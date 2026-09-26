import CryptoKit
import Foundation

/// Version of the JSON contract between coop and this binary. Bump on any
/// incompatible change to a command's arguments or output.
public let protocolVersion = 1
public let runtimeVersion = "0.1.0"
public let containerizationVersion = "0.45.0"

/// On-disk layout of one runtime state root. Everything the runtime owns
/// lives under `root`; nothing is read from or written to Apple Container's
/// stores.
public struct SandboxRoot: Sendable {
    public let root: URL

    /// `path` must be absolute. An existing root is canonicalized with
    /// realpath(3), so paths the runtime reports (e.g. the rootfs source in
    /// the effective config) compare exactly with the caller's canonical form.
    public init(_ path: String) throws {
        guard path.hasPrefix("/") else { throw SandboxError("--root must be an absolute path") }
        root = URL(fileURLWithPath: Self.canonical(path), isDirectory: true)
    }

    /// realpath(3) of `path`, or of its parent plus the last component when
    /// `path` does not exist yet, so a root reads the same before and after
    /// it is created.
    static func canonical(_ path: String) -> String {
        if let real = realpath(path, nil) {
            defer { free(real) }
            return String(cString: real)
        }
        let url = URL(fileURLWithPath: path)
        let parent = url.deletingLastPathComponent().path
        guard parent != path, parent != "/" || url.lastPathComponent != "" else { return path }
        return (canonical(parent) as NSString).appendingPathComponent(url.lastPathComponent)
    }

    public var imageStore: URL { root.appendingPathComponent("store", isDirectory: true) }
    public var kernel: URL { root.appendingPathComponent("vmlinux") }
    public var initfs: URL { root.appendingPathComponent("initfs.ext4") }
    public var sandboxes: URL { root.appendingPathComponent("sandboxes", isDirectory: true) }
    /// Unpacked image root filesystems, cloned into new sandboxes.
    public var bases: URL { root.appendingPathComponent("bases", isDirectory: true) }
    /// Disks saved by `commit`, cloned by `create --from-disk` and `restore`.
    public var disks: URL { root.appendingPathComponent("disks", isDirectory: true) }
    public var subnetState: URL { root.appendingPathComponent("subnets.json") }
    public var allocationLock: URL { root.appendingPathComponent("subnets.lock") }
    public var operationLock: URL { root.appendingPathComponent("operations.lock") }

    public func sandbox(_ id: SandboxID) -> SandboxPaths {
        SandboxPaths(dir: sandboxes.appendingPathComponent(id.rawValue, isDirectory: true))
    }

    public func disk(_ name: SandboxID) -> URL {
        disks.appendingPathComponent("\(name.rawValue).ext4")
    }

    public func requireInitialized() throws {
        for url in [kernel, initfs, imageStore] where !FileManager.default.fileExists(atPath: url.path) {
            throw SandboxError("state root \(root.path) is not initialized; run `coop-sandbox init`")
        }
    }

    /// Every committed sandbox. A directory without a record is an
    /// uncommitted create and is skipped; a record that exists but cannot be
    /// read is an error, so listings and subnet allocation fail closed rather
    /// than forget a sandbox.
    public func allRecords() throws -> [SandboxRecord] {
        guard FileManager.default.fileExists(atPath: sandboxes.path) else { return [] }
        return try FileManager.default.contentsOfDirectory(atPath: sandboxes.path).sorted().compactMap { name in
            guard let id = try? SandboxID(name) else { return nil }
            let paths = sandbox(id)
            guard FileManager.default.fileExists(atPath: paths.record.path) else { return nil }
            return try paths.loadRecord()
        }
    }

    public func createDirectories() throws {
        for dir in [root, sandboxes, bases, disks] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
    }
}

public struct SandboxPaths: Sendable {
    public let dir: URL
    public var record: URL { dir.appendingPathComponent("record.json") }
    public var live: URL { dir.appendingPathComponent("live.json") }
    public var rootfs: URL { dir.appendingPathComponent("rootfs.ext4") }
    public var bootLog: URL { dir.appendingPathComponent("boot.log") }
    public var ownerLog: URL { dir.appendingPathComponent("owner.log") }
    public var lock: URL { dir.appendingPathComponent("owner.lock") }
    public var launchdPlist: URL { dir.appendingPathComponent("launchd.plist") }
    /// Written by an owner that failed before its VM ran; read by `start`.
    public var ownerFailed: URL { dir.appendingPathComponent("owner.failed") }
    /// Unix socket paths are limited to 104 bytes on macOS, so the control
    /// socket lives in a short per-user directory keyed by a hash of `dir`.
    public var control: URL {
        Self.controlDirectory.appendingPathComponent("\(Self.stableHash(dir.path)).sock")
    }

    /// `coop-sbx` in the per-user temporary directory, which is private to
    /// the user from boot: in shared `/tmp`, another user could pre-create
    /// the directory and block every sandbox. Read with confstr(3) because
    /// launchd jobs may not inherit `TMPDIR`.
    public static let controlDirectory: URL = {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let n = confstr(_CS_DARWIN_USER_TEMP_DIR, &buf, buf.count)
        let tmp = n > 0 && n <= buf.count ? String(cString: buf) : NSTemporaryDirectory()
        return URL(fileURLWithPath: tmp, isDirectory: true).appendingPathComponent("coop-sbx", isDirectory: true)
    }()
    /// launchd label, unique per state root and sandbox.
    public var launchdLabel: String { "dev.coop.sandbox.\(Self.stableHash(dir.path))" }

    static func stableHash(_ s: String) -> String {
        let h = s.utf8.reduce(UInt64(14_695_981_039_346_656_037)) { ($0 ^ UInt64($1)) &* 1_099_511_628_211 }
        return String(h, radix: 16)
    }

    public func loadRecord() throws -> SandboxRecord {
        settlePendingRestore()
        return try JSONDecoder.iso.decode(SandboxRecord.self, from: Data(contentsOf: record))
    }

    /// The record a restore will commit, written before its disk swap.
    public var pendingRestore: URL { dir.appendingPathComponent("restore.pending.json") }
    /// The restore's prepared disk, swapped in by rename.
    public var restoreWork: URL { dir.appendingPathComponent(".restore-rootfs.ext4") }

    struct PendingRestore: Codable {
        var inode: UInt64
        var record: SandboxRecord
    }

    static func inode(_ url: URL) -> UInt64? {
        var st = stat()
        return lstat(url.path, &st) == 0 ? UInt64(st.st_ino) : nil
    }

    /// Finishes a restore interrupted between its disk swap and its record
    /// write, so the disk and its generation never disagree: the swap moved
    /// the prepared disk (same inode) into place, or it never happened.
    func settlePendingRestore() {
        guard let data = try? Data(contentsOf: pendingRestore),
            let pending = try? JSONDecoder.iso.decode(PendingRestore.self, from: data)
        else { return }
        if Self.inode(rootfs) == pending.inode {
            guard (try? save(pending.record)) != nil else { return }
        } else if FileManager.default.fileExists(atPath: restoreWork.path) {
            return  // the swap may still happen
        }
        try? FileManager.default.removeItem(at: pendingRestore)
    }

    func writePendingRestore(_ record: SandboxRecord, disk: URL) throws {
        guard let inode = Self.inode(disk) else { throw SandboxError("stat \(disk.path): errno \(errno)") }
        try JSONEncoder.pretty.encode(PendingRestore(inode: inode, record: record)).write(to: pendingRestore, options: .atomic)
    }

    public func save(_ record: SandboxRecord) throws {
        try JSONEncoder.pretty.encode(record).write(to: self.record, options: .atomic)
    }

    public func loadLive() -> LiveState? {
        guard let data = try? Data(contentsOf: live) else { return nil }
        return try? JSONDecoder.iso.decode(LiveState.self, from: data)
    }
}

/// A sandbox or disk identifier: always a safe single path component and a
/// valid container ID.
public struct SandboxID: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    public let rawValue: String
    public init?(rawValue: String) { try? self.init(rawValue) }
    public init(_ raw: String) throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-")
        let ok = !raw.isEmpty && raw.count <= 48 && raw.first != "-"
            && raw.unicodeScalars.allSatisfy { allowed.contains($0) }
        guard ok else { throw SandboxError("invalid identifier \(raw.debugDescription)") }
        rawValue = raw
    }
    public init(from decoder: Decoder) throws {
        try self.init(try decoder.singleValueContainer().decode(String.self))
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
    public var description: String { rawValue }
}

/// Durable description of a persistent sandbox. Deliberately has no field
/// for host mounts, socket relays, published ports, or agent forwarding:
/// those states are not expressible.
public struct SandboxRecord: Codable, Sendable {
    public var id: SandboxID
    /// Caller-chosen ownership tag; `delete` refuses a mismatch.
    public var owner: String
    public var imageReference: String
    public var imageDigest: String
    /// Committed disk this sandbox was cloned from, if any.
    public var baseDisk: String?
    /// Init process environment, captured from the image config at create
    /// time so a start never depends on the image store.
    public var environment: [String]
    public var cpus: Int
    public var memoryBytes: UInt64
    public var diskBytes: UInt64
    public var subnetIndex: Int
    public var createdAt: Date
    /// Incremented each time `restore` replaces the disk, so a caller that
    /// crashed mid-restore can tell whether it applied.
    public var diskGeneration: Int = 0

    public var subnet: String { Self.subnet(subnetIndex) }
    public static func subnet(_ index: Int) -> String { "10.231.\(index).0/24" }

    public init(
        id: SandboxID, owner: String, imageReference: String, imageDigest: String, baseDisk: String?,
        environment: [String], cpus: Int, memoryBytes: UInt64, diskBytes: UInt64, subnetIndex: Int, createdAt: Date
    ) {
        self.id = id
        self.owner = owner
        self.imageReference = imageReference
        self.imageDigest = imageDigest
        self.baseDisk = baseDisk
        self.environment = environment
        self.cpus = cpus
        self.memoryBytes = memoryBytes
        self.diskBytes = diskBytes
        self.subnetIndex = subnetIndex
        self.createdAt = createdAt
    }
}

/// Written by the owner process while the VM runs; removed on clean stop.
public struct LiveState: Codable, Sendable {
    public var pid: Int32
    public var startedAt: Date
    public var ipv4: String?
    public var ipv6: String?
}

public enum SandboxStatus: String, Codable, Sendable {
    case running, booting, stopped, crashed
}

public struct SandboxError: Error, CustomStringConvertible {
    public let description: String
    public init(_ message: String) { description = message }
}

/// Kernels this runtime has been validated with (sha256 of the vmlinux).
/// `init` refuses any other kernel; there is no override.
public enum KernelPin {
    public static let allowed: Set<String> = [
        // vmlinux-6.18.15-186, installed by Apple `container` 1.4.1 (Kata static build).
        "2fe4a58d2885d623bcb4d705900ac8c1d4f02371152da8126b3b00c8c47fc3a1"
    ]

    /// The kernel for `root`, validated against `allowed`. A root keeps a
    /// kernel it was initialized with while that kernel is still pinned, so a
    /// newer kernel installed elsewhere later does not break re-running init;
    /// otherwise `requested` replaces it. `install` is true when the kernel
    /// must be written.
    public static func select(
        root: SandboxRoot, requested: String, allowed: Set<String> = allowed
    ) throws -> (data: Data, sha256: String, install: Bool) {
        func pinned(_ path: String) throws -> (Data, String) {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            guard allowed.contains(sha) else {
                throw SandboxError("kernel \(path) (sha256 \(sha)) is not a validated kernel")
            }
            return (data, sha)
        }
        if let (data, sha) = try? pinned(root.kernel.path) { return (data, sha, false) }
        let (data, sha) = try pinned(requested)
        return (data, sha, true)
    }
}

/// Serializes offline disk operations against `reconcile`'s sweep of scratch
/// files and uncommitted creates. Operations hold it shared (they run
/// concurrently with each other); the sweep needs it exclusively.
public final class OperationLock {
    private let fd: Int32

    private init(fd: Int32) { self.fd = fd }

    /// Blocks until no sweep is running.
    public static func shared(_ root: SandboxRoot) throws -> OperationLock {
        let fd = open(root.operationLock.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw SandboxError("open \(root.operationLock.path): errno \(errno)") }
        guard flock(fd, LOCK_SH) == 0 else {
            close(fd)
            throw SandboxError("flock: errno \(errno)")
        }
        return OperationLock(fd: fd)
    }

    /// `nil` while any operation is in progress.
    public static func tryExclusive(_ root: SandboxRoot) -> OperationLock? {
        let fd = open(root.operationLock.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return nil }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            return nil
        }
        return OperationLock(fd: fd)
    }

    deinit { close(fd) }
}

public func clone(_ from: URL, to: URL) throws {
    guard clonefile(from.path, to.path, 0) == 0 else {
        throw SandboxError("clonefile \(from.lastPathComponent) -> \(to.lastPathComponent): errno \(errno)")
    }
}

public func printJSON<T: Encodable>(_ value: T) throws {
    FileHandle.standardOutput.write(try JSONEncoder.pretty.encode(value))
    FileHandle.standardOutput.write(Data("\n".utf8))
}

extension JSONEncoder {
    public static var pretty: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        e.dateEncodingStrategy = .iso8601
        return e
    }
}

extension JSONDecoder {
    public static var iso: JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }
}
