import Containerization
import Foundation

/// What `create` clones a new sandbox from.
public enum SandboxSource: Sendable {
    case image(String)
    case disk(SandboxID)
}

/// Metadata saved beside a committed disk; a sandbox created from it
/// inherits these fields.
public struct DiskMetadata: Codable, Sendable {
    public var imageReference: String
    public var imageDigest: String
    public var environment: [String]
    public var diskBytes: UInt64
    public var committedFrom: SandboxID
    public var createdAt: Date
}

public struct InspectOutput: Encodable, Sendable {
    public var record: SandboxRecord
    public var status: SandboxStatus
    public var live: LiveState?
    public var effective: EffectiveConfig?
    public var disk: DiskSummary
}

public struct ReconcileAction: Codable, Sendable {
    public var id: String
    public var status: String
    public var action: String
}

/// Sandbox lifecycle operations. Every mutation of a sandbox's disk or
/// record requires it to be stopped with no live owner.
public enum Sandboxes {
    // MARK: status

    public static func status(_ paths: SandboxPaths) -> SandboxStatus {
        guard let live = paths.loadLive() else {
            return ownerHoldsLock(paths) ? .booting : .stopped
        }
        // The owner holds its lock for its whole life, so the lock (not the
        // recorded PID, which the system may reuse) proves it is alive.
        guard ownerHoldsLock(paths) else { return .crashed }
        return (try? ControlSocket.call(paths.control, .init(op: .ping), timeout: 5))?.ok == true ? .running : .booting
    }

    /// Whether some process holds the owner lock (an owner between launch
    /// and writing live.json, or a wedged one).
    static func ownerHoldsLock(_ paths: SandboxPaths) -> Bool {
        let fd = open(paths.lock.path, O_RDWR)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        if flock(fd, LOCK_EX | LOCK_NB) == 0 {
            flock(fd, LOCK_UN)
            return false
        }
        return true
    }

    public static func requireStopped(_ paths: SandboxPaths, _ id: SandboxID) throws {
        let s = status(paths)
        guard s == .stopped else { throw SandboxError("\(id) is \(s.rawValue); stop it first") }
    }

    // MARK: create

    public static func create(
        root: SandboxRoot, id: SandboxID, owner: String, source: SandboxSource, cpus: Int, memoryBytes: UInt64, diskBytes: UInt64
    ) async throws -> SandboxRecord {
        let operation = try OperationLock.shared(root)
        defer { withExtendedLifetime(operation) {} }
        try root.requireInitialized()
        guard cpus >= 1, memoryBytes >= 256 * 1024 * 1024, diskBytes >= 1024 * 1024 * 1024 else {
            throw SandboxError("cpus must be >= 1, memory >= 256 MiB, disk >= 1 GiB")
        }
        let paths = root.sandbox(id)
        // No record yet means an uncommitted create; reconcile removes those.
        try FileManager.default.createDirectory(at: paths.dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            return try await populate(root: root, paths: paths, id: id, owner: owner, source: source, cpus: cpus, memoryBytes: memoryBytes, diskBytes: diskBytes)
        } catch {
            try? FileManager.default.removeItem(at: paths.dir)
            throw error
        }
    }

    static func populate(
        root: SandboxRoot, paths: SandboxPaths, id: SandboxID, owner: String, source: SandboxSource, cpus: Int, memoryBytes: UInt64,
        diskBytes: UInt64
    ) async throws -> SandboxRecord {

        let imageReference: String
        let imageDigest: String
        let environment: [String]
        var baseDisk: String?
        switch source {
        case .image(let reference):
            let store = try ImageStore(path: root.imageStore)
            let image = try await store.get(reference: reference)
            let base = try await Disks.base(root: root, image: image, bytes: diskBytes)
            try clone(base, to: paths.rootfs)
            imageReference = reference
            imageDigest = image.digest
            environment = try await image.config(for: .current).config?.env ?? ["PATH=\(LinuxProcessConfiguration.defaultPath)"]
        case .disk(let name):
            let meta = try loadDiskMetadata(root: root, name: name)
            guard diskBytes >= meta.diskBytes else {
                throw SandboxError("disk \(name) is \(meta.diskBytes) bytes; cannot create a smaller sandbox from it")
            }
            try clone(root.disk(name), to: paths.rootfs)
            if diskBytes > meta.diskBytes {
                try await growInPlace(root: root, paths: paths, to: diskBytes)
            }
            imageReference = meta.imageReference
            imageDigest = meta.imageDigest
            environment = meta.environment
            baseDisk = name.rawValue
        }

        var record: SandboxRecord?
        try SubnetAllocator(root: root).allocate(for: id) { index in
            let r = SandboxRecord(
                id: id, owner: owner, imageReference: imageReference, imageDigest: imageDigest, baseDisk: baseDisk,
                environment: environment, cpus: cpus, memoryBytes: memoryBytes, diskBytes: diskBytes, subnetIndex: index,
                createdAt: Date())
            // Writing the record commits the create.
            try paths.save(r)
            record = r
        }
        guard let record else { throw SandboxError("allocation did not commit") }
        return record
    }

    // MARK: start / stop

    public static func start(root: SandboxRoot, id: SandboxID, executable: String, wait: TimeInterval) async throws -> LiveState {
        try root.requireInitialized()
        let paths = root.sandbox(id)
        _ = try paths.loadRecord()
        if status(paths) == .crashed {
            // Take the job back from launchd before starting it fresh.
            Launchd.bootout(paths.launchdLabel)
            try? FileManager.default.removeItem(at: paths.live)
        }
        try requireStopped(paths, id)
        Launchd.bootout(paths.launchdLabel)
        let domain = Launchd.domain()
        let plist = Launchd.plist(
            label: paths.launchdLabel, executable: executable,
            arguments: ["run", id.rawValue, "--root", root.root.path], log: paths.ownerLog)
        try Launchd.write(plist, to: paths.launchdPlist)
        try? FileManager.default.removeItem(at: paths.ownerFailed)
        try Launchd.bootstrap(plist: paths.launchdPlist, domain: domain)

        let deadline = Date().addingTimeInterval(wait)
        while Date() < deadline {
            if let live = paths.loadLive(), (try? ControlSocket.call(paths.control, .init(op: .ping), timeout: 5))?.ok == true {
                return live
            }
            if let failure = try? String(contentsOf: paths.ownerFailed, encoding: .utf8) {
                Launchd.bootout(paths.launchdLabel)
                throw SandboxError("\(id) failed to start: \(failure)")
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        let tail = logTail(paths.ownerLog, lines: 20)
        Launchd.bootout(paths.launchdLabel)
        throw SandboxError("\(id) did not become ready within \(Int(wait))s; owner log:\n\(tail)")
    }

    /// Halt systemd cleanly, wait for the owner to exit, and unload its job.
    /// Idempotent: stopping a stopped sandbox succeeds.
    public static func stop(root: SandboxRoot, id: SandboxID, timeout: TimeInterval) async throws {
        let paths = root.sandbox(id)
        _ = try paths.loadRecord()
        if status(paths) == .running {
            _ = try? ControlSocket.call(paths.control, .init(op: .stop), timeout: timeout)
        }
        let deadline = Date().addingTimeInterval(timeout)
        while ownerHoldsLock(paths), Date() < deadline {
            try await Task.sleep(for: .milliseconds(100))
        }
        // bootout also covers an owner that ignored the request: launchd
        // sends SIGTERM (a graceful halt) and SIGKILL after ExitTimeOut.
        Launchd.bootout(paths.launchdLabel)
        let hard = Date().addingTimeInterval(100)
        while ownerHoldsLock(paths), Date() < hard { try await Task.sleep(for: .milliseconds(100)) }
        guard !ownerHoldsLock(paths) else { throw SandboxError("\(id) owner did not exit") }
        try? FileManager.default.removeItem(at: paths.live)
    }

    // MARK: inspect

    public static func inspect(root: SandboxRoot, id: SandboxID) throws -> InspectOutput {
        let paths = root.sandbox(id)
        let record = try paths.loadRecord()
        let s = status(paths)
        let effective = s == .running ? try? ControlSocket.call(paths.control, .init(op: .inspect), timeout: 10).inspect : nil
        let (logical, allocated) = Disks.sizes(paths.rootfs)
        return InspectOutput(
            record: record, status: s, live: s == .stopped ? nil : paths.loadLive(), effective: effective,
            disk: DiskSummary(name: "rootfs", logicalBytes: logical, allocatedBytes: allocated))
    }

    // MARK: resources and disks

    public static func setResources(root: SandboxRoot, id: SandboxID, cpus: Int?, memoryBytes: UInt64?) throws -> SandboxRecord {
        let paths = root.sandbox(id)
        try requireStopped(paths, id)
        var record = try paths.loadRecord()
        if let cpus {
            guard cpus >= 1 else { throw SandboxError("cpus must be >= 1") }
            record.cpus = cpus
        }
        if let memoryBytes {
            guard memoryBytes >= 256 * 1024 * 1024 else { throw SandboxError("memory must be >= 256 MiB") }
            record.memoryBytes = memoryBytes
        }
        try paths.save(record)
        return record
    }

    public static func grow(root: SandboxRoot, id: SandboxID, diskBytes: UInt64) async throws -> SandboxRecord {
        let operation = try OperationLock.shared(root)
        defer { withExtendedLifetime(operation) {} }
        let paths = root.sandbox(id)
        try requireStopped(paths, id)
        var record = try paths.loadRecord()
        guard diskBytes > record.diskBytes else { throw SandboxError("shrinking a disk is not supported") }
        try await growInPlace(root: root, paths: paths, to: diskBytes)
        record.diskBytes = diskBytes
        try paths.save(record)
        return record
    }

    static func growInPlace(root: SandboxRoot, paths: SandboxPaths, to bytes: UInt64) async throws {
        let digest = try? paths.loadRecord().imageDigest
        try await grow(root: root, scratch: paths.dir, disk: paths.rootfs, to: bytes, imageDigest: digest)
    }

    /// Grow `disk` via a clone that is swapped in only once the resize
    /// succeeded, so a failure leaves `disk` untouched.
    static func grow(root: SandboxRoot, scratch: URL, disk: URL, to bytes: UInt64, imageDigest: String?) async throws {
        let work = scratch.appendingPathComponent(".grow-\(disk.lastPathComponent)")
        try? FileManager.default.removeItem(at: work)
        defer { try? FileManager.default.removeItem(at: work) }
        try clone(disk, to: work)
        guard truncate(work.path, off_t(bytes)) == 0 else { throw SandboxError("truncate: errno \(errno)") }
        let tools = try await Disks.toolsDisk(root: root, preferring: imageDigest)
        let log = try await Maintenance.growFilesystem(root: root, scratch: scratch, tools: tools, disk: work)
        Owner.log("grew \(disk.lastPathComponent) to \(bytes) bytes: \(log.split(separator: "\n").last ?? "")")
        guard rename(work.path, disk.path) == 0 else { throw SandboxError("rename: errno \(errno)") }
    }

    /// Save a stopped sandbox's disk as `name`, with its identity removed.
    public static func commit(root: SandboxRoot, id: SandboxID, name: SandboxID, replace: Bool) async throws -> DiskSummary {
        let operation = try OperationLock.shared(root)
        defer { withExtendedLifetime(operation) {} }
        let paths = root.sandbox(id)
        try requireStopped(paths, id)
        let record = try paths.loadRecord()
        let target = root.disk(name)
        if FileManager.default.fileExists(atPath: target.path), !replace {
            throw SandboxError("disk \(name) exists")
        }
        let tmp = root.disks.appendingPathComponent(".tmp-\(name.rawValue)-\(UUID().uuidString.prefix(8)).ext4")
        defer { try? FileManager.default.removeItem(at: tmp) }
        try clone(paths.rootfs, to: tmp)
        // The reset runs coop-built tools against the disk as data, so the
        // guest's own binaries cannot interfere with it. It removes only the
        // identity left on disk: a guest that authored the disk can still
        // re-create its old identity when a clone boots.
        let tools = try await Disks.toolsDisk(root: root, preferring: record.imageDigest)
        _ = try await Maintenance.resetIdentity(root: root, scratch: root.disks, tools: tools, disk: tmp)
        let meta = DiskMetadata(
            imageReference: record.imageReference, imageDigest: record.imageDigest, environment: record.environment,
            diskBytes: record.diskBytes, committedFrom: id, createdAt: Date())
        // Disk first, then its metadata: a disk without metadata is unusable
        // (and reconcile removes it), never paired with another disk's metadata.
        try? FileManager.default.removeItem(at: metadataURL(root: root, name: name))
        guard rename(tmp.path, target.path) == 0 else { throw SandboxError("rename: errno \(errno)") }
        try JSONEncoder.pretty.encode(meta).write(to: metadataURL(root: root, name: name), options: .atomic)
        let (logical, allocated) = Disks.sizes(target)
        return DiskSummary(name: name.rawValue, logicalBytes: logical, allocatedBytes: allocated)
    }

    /// Replace a stopped sandbox's disk with a clone of committed disk `name`
    /// or a fresh copy of an image, grown back to the sandbox's size if that
    /// is larger. The new disk has no host keys, so the next boot generates
    /// new ones.
    public static func restore(root: SandboxRoot, id: SandboxID, source: SandboxSource) async throws -> SandboxRecord {
        let operation = try OperationLock.shared(root)
        defer { withExtendedLifetime(operation) {} }
        let paths = root.sandbox(id)
        try requireStopped(paths, id)
        var record = try paths.loadRecord()
        let sourceURL: URL
        let sourceBytes: UInt64
        switch source {
        case .disk(let name):
            let meta = try loadDiskMetadata(root: root, name: name)
            sourceURL = root.disk(name)
            sourceBytes = meta.diskBytes
            record.imageReference = meta.imageReference
            record.imageDigest = meta.imageDigest
            record.environment = meta.environment
            record.baseDisk = name.rawValue
        case .image(let reference):
            let store = try ImageStore(path: root.imageStore)
            let image = try await store.get(reference: reference)
            sourceURL = try await Disks.base(root: root, image: image, bytes: record.diskBytes)
            sourceBytes = record.diskBytes
            record.imageReference = reference
            record.imageDigest = image.digest
            record.environment = try await image.config(for: .current).config?.env ?? ["PATH=\(LinuxProcessConfiguration.defaultPath)"]
            record.baseDisk = nil
        }
        // Everything that can fail happens on a scratch copy; the swap is the
        // last step. The new record is staged first, so a crash right after
        // the swap still commits the new generation (see settlePendingRestore).
        let work = paths.restoreWork
        try? FileManager.default.removeItem(at: work)
        defer { try? FileManager.default.removeItem(at: work) }
        try clone(sourceURL, to: work)
        if record.diskBytes > sourceBytes {
            try await grow(root: root, scratch: paths.dir, disk: work, to: record.diskBytes, imageDigest: record.imageDigest)
        } else {
            record.diskBytes = sourceBytes
        }
        record.diskGeneration += 1
        try paths.writePendingRestore(record, disk: work)
        guard rename(work.path, paths.rootfs.path) == 0 else {
            try? FileManager.default.removeItem(at: paths.pendingRestore)
            throw SandboxError("rename: errno \(errno)")
        }
        try paths.save(record)
        try? FileManager.default.removeItem(at: paths.pendingRestore)
        return record
    }

    public static func deleteDisk(root: SandboxRoot, name: SandboxID) throws {
        try FileManager.default.removeItem(at: root.disk(name))
        try? FileManager.default.removeItem(at: metadataURL(root: root, name: name))
    }

    static func metadataURL(root: SandboxRoot, name: SandboxID) -> URL {
        root.disks.appendingPathComponent("\(name.rawValue).json")
    }

    static func loadDiskMetadata(root: SandboxRoot, name: SandboxID) throws -> DiskMetadata {
        guard FileManager.default.fileExists(atPath: root.disk(name).path) else { throw SandboxError("no disk named \(name)") }
        return try JSONDecoder.iso.decode(DiskMetadata.self, from: Data(contentsOf: metadataURL(root: root, name: name)))
    }

    // MARK: delete / reconcile

    public static func delete(root: SandboxRoot, id: SandboxID, owner: String) throws {
        let paths = root.sandbox(id)
        try requireStopped(paths, id)
        let record = try paths.loadRecord()
        guard record.owner == owner else { throw SandboxError("\(id) belongs to owner \(record.owner), not \(owner)") }
        Launchd.bootout(paths.launchdLabel)
        // Rename first so an interrupted delete never leaves a half-removed
        // sandbox that still looks valid; reconcile finishes the removal.
        let tomb = root.sandboxes.appendingPathComponent(".deleting-\(id.rawValue)-\(UUID().uuidString.prefix(8))")
        guard rename(paths.dir.path, tomb.path) == 0 else { throw SandboxError("rename: errno \(errno)") }
        try FileManager.default.removeItem(at: tomb)
    }

    /// Clear crashed owners' state, finish interrupted deletes, and remove
    /// uncommitted creates and leftover scratch files.
    public static func reconcile(root: SandboxRoot) throws -> [ReconcileAction] {
        var out: [ReconcileAction] = []
        // The sweep below must not race an in-flight create, grow, commit, or
        // restore; when one is running, only crashed owners are cleared.
        let sweep = OperationLock.tryExclusive(root)
        defer { withExtendedLifetime(sweep) {} }
        for record in try root.allRecords() {
            let paths = root.sandbox(record.id)
            let s = status(paths)
            var action = "none"
            if s == .crashed {
                Launchd.bootout(paths.launchdLabel)
                try? FileManager.default.removeItem(at: paths.live)
                unlink(paths.control.path)
                action = "cleared-crashed-owner"
            }
            out.append(.init(id: record.id.rawValue, status: s.rawValue, action: action))
        }
        guard sweep != nil else {
            out.append(.init(id: "-", status: "busy", action: "sweep-skipped-operation-in-progress"))
            return out
        }
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root.sandboxes.path)) ?? []
        for name in names.sorted() {
            let dir = root.sandboxes.appendingPathComponent(name)
            if name.hasPrefix(".deleting-") {
                try FileManager.default.removeItem(at: dir)
                out.append(.init(id: name, status: "deleting", action: "finished-delete"))
            } else if let id = try? SandboxID(name), !FileManager.default.fileExists(atPath: root.sandbox(id).record.path),
                !ownerHoldsLock(root.sandbox(id))
            {
                try FileManager.default.removeItem(at: dir)
                out.append(.init(id: name, status: "incomplete", action: "removed-uncommitted-create"))
            }
        }
        var scratchDirs = [root.bases, root.disks]
        scratchDirs += try root.allRecords().map { root.sandbox($0.id).dir }
        for dir in scratchDirs {
            // Scratch files come only from offline operations on a stopped
            // sandbox; any other sandbox is left for a later sweep.
            if dir.deletingLastPathComponent() == root.sandboxes,
                let id = try? SandboxID(dir.lastPathComponent), status(root.sandbox(id)) != .stopped
            {
                continue
            }
            for name in (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
            where isScratch(name) {
                try? FileManager.default.removeItem(at: dir.appendingPathComponent(name))
            }
        }
        for name in (try? FileManager.default.contentsOfDirectory(atPath: root.disks.path)) ?? []
        where name.hasSuffix(".ext4") && !name.hasPrefix(".") {
            let disk = root.disks.appendingPathComponent(name)
            if !FileManager.default.fileExists(atPath: disk.deletingPathExtension().appendingPathExtension("json").path) {
                try? FileManager.default.removeItem(at: disk)
                out.append(.init(id: name, status: "incomplete", action: "removed-uncommitted-disk"))
            }
        }
        return out
    }

    /// Scratch files left by an interrupted offline operation.
    static func isScratch(_ name: String) -> Bool {
        [".tmp-", ".grow-", ".restore-", ".maintenance-"].contains { name.hasPrefix($0) }
    }

    // MARK: logs

    /// The last `lines` lines of `url`. Splits on bytes: the serial console
    /// writes CRLF, which Swift's `String` treats as a single character.
    public static func logTail(_ url: URL, lines: Int) -> String {
        String(decoding: tailData(url, lines: lines), as: UTF8.self)
    }

    /// The last `lines` lines of `url`, reading at most its last 256 KiB.
    public static func tailData(_ url: URL, lines: Int, window: UInt64 = 256 * 1024) -> Data {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return Data() }
        defer { try? handle.close() }
        guard let end = try? handle.seekToEnd() else { return Data() }
        try? handle.seek(toOffset: end > window ? end - window : 0)
        var data = (try? handle.readToEnd()) ?? Data()
        // A window that starts mid-line would return a fragment as a line.
        if end > window, let nl = data.firstIndex(of: 0x0A) { data = data[(nl + 1)...] }
        return tailLines(Data(data), lines)
    }

    public static func tailLines(_ data: Data, _ lines: Int) -> Data {
        var parts = data.split(separator: 0x0A, omittingEmptySubsequences: false)
        if parts.last?.isEmpty == true { parts.removeLast() }
        let kept = parts.suffix(lines)
        guard !kept.isEmpty else { return Data() }
        return Data(kept.joined(separator: [0x0A])) + [0x0A]
    }
}
