import Foundation
import Testing

@testable import CoopSandboxCore

/// Disk-update recovery and same-sandbox exclusion, without a VM.
@Suite struct TransactionTests {
    func root() throws -> SandboxRoot {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("csb-\(UUID().uuidString)")
        let r = try SandboxRoot(dir.path)
        try r.createDirectories()
        return r
    }

    /// An initialized root (placeholder kernel and init filesystem), for
    /// commands that require one.
    func initializedRoot() throws -> SandboxRoot {
        let r = try root()
        try Data().write(to: r.kernel)
        try Data().write(to: r.initfs)
        try FileManager.default.createDirectory(at: r.imageStore, withIntermediateDirectories: true)
        return r
    }

    @discardableResult
    func stoppedSandbox(_ root: SandboxRoot, _ name: String, disk: UInt64 = 8 << 30, content: String = "old") throws -> SandboxPaths {
        let id = try SandboxID(name)
        let paths = root.sandbox(id)
        try FileManager.default.createDirectory(at: paths.dir, withIntermediateDirectories: true)
        try paths.save(
            SandboxRecord(
                id: id, owner: "o", imageReference: "i", imageDigest: "d", baseDisk: nil, environment: [], cpus: 1,
                memoryBytes: 1 << 30, diskBytes: disk, subnetIndex: 1, createdAt: Date()))
        try Data(content.utf8).write(to: paths.rootfs)
        return paths
    }

    /// A committed disk `name` of `bytes` capacity holding `content`.
    func committedDisk(_ root: SandboxRoot, _ name: String, bytes: UInt64 = 8 << 30, content: String = "snap") throws {
        let id = try SandboxID(name)
        try Data(content.utf8).write(to: root.disk(id))
        let meta = DiskMetadata(
            imageReference: "snap-image", imageDigest: "snap-digest", environment: ["A=1"], diskBytes: bytes,
            committedFrom: try SandboxID("src"), createdAt: Date())
        try JSONEncoder.pretty.encode(meta).write(to: Sandboxes.metadataURL(root: root, name: id))
    }

    func rootfs(_ paths: SandboxPaths) throws -> String {
        String(decoding: try Data(contentsOf: paths.rootfs), as: UTF8.self)
    }

    /// Interrupt a grow's publication at each boundary. Reopening (a read,
    /// then the next guarded operation's settle, twice) always yields the old
    /// disk with the old record or the new disk with the new record.
    @Test(arguments: DiskUpdate.Fault.allCases)
    func interruptedPublicationRecoversToOneSide(_ fault: DiskUpdate.Fault) throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let op = OperationID.random()
        let work = DiskUpdate.workDisk(paths, op)
        try Data("new".utf8).write(to: work)
        var next = try paths.loadRecord()
        next.diskBytes = 16 << 30
        next.lastOperation = op

        #expect(throws: DiskUpdate.InjectedFault.self) {
            try DiskUpdate.publish(paths, kind: .grow, operation: op, work: work, record: next, fault: fault)
        }
        let applied = fault == .afterRename || fault == .afterRecord
        func consistent() throws {
            let record = try paths.loadRecord()
            if applied {
                #expect(try rootfs(paths) == "new" && record.diskBytes == 16 << 30 && record.lastOperation == op, "\(fault)")
            } else {
                #expect(try rootfs(paths) == "old" && record.diskBytes == 8 << 30 && record.lastOperation == nil, "\(fault)")
            }
        }
        try consistent()
        _ = try DiskUpdate.settle(paths)
        try consistent()
        #expect(try paths.readRecordFile().diskBytes == (applied ? 16 << 30 : 8 << 30), "settled into record.json")
        #expect(try !DiskUpdate.settle(paths), "recovery is idempotent")
        try consistent()
        #expect(!FileManager.default.fileExists(atPath: paths.pendingDiskUpdate.path))
        // Interrupted before staging, the scratch disk is plain scratch.
        #expect(FileManager.default.fileExists(atPath: work.path) == (fault == .beforeStaging))
        _ = try Sandboxes.reconcile(root: r)
        #expect(!FileManager.default.fileExists(atPath: work.path))
        try consistent()
    }

    /// Commit's metadata comes from the settled record, so a disk committed
    /// after an interrupted grow records the grown size.
    @Test func interruptedGrowSettlesBeforeTheNextOperationReadsTheRecord() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let op = OperationID.random()
        let work = DiskUpdate.workDisk(paths, op)
        try Data("grown".utf8).write(to: work)
        var next = try paths.loadRecord()
        next.diskBytes = 16 << 30
        #expect(throws: DiskUpdate.InjectedFault.self) {
            try DiskUpdate.publish(paths, kind: .grow, operation: op, work: work, record: next, fault: .afterRename)
        }
        let seen = try await Sandboxes.mutating(paths) { try paths.readRecordFile().diskBytes }
        #expect(seen == 16 << 30)
    }

    @Test func unreadableStagedStateIsAnErrorButDeleteStillWorks() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        try Data("{".utf8).write(to: paths.pendingDiskUpdate)
        #expect(throws: SandboxError.self) { try paths.loadRecord() }
        await #expect(throws: SandboxError.self) {
            try await Sandboxes.setResources(root: r, id: try SandboxID("a"), cpus: 2, memoryBytes: nil)
        }
        let actions = try Sandboxes.reconcile(root: r).map(\.action)
        #expect(actions.contains { $0.hasPrefix("unresolved-disk-update") }, "\(actions)")
        try await Sandboxes.delete(root: r, id: try SandboxID("a"), owner: "o")
        #expect(!FileManager.default.fileExists(atPath: paths.dir.path))
    }

    /// A staged update whose scratch disk is not the one it names contradicts
    /// itself: neither side is guessed.
    @Test func contradictoryStagedStateIsAnError() throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let op = OperationID.random()
        let work = DiskUpdate.workDisk(paths, op)
        try Data("new".utf8).write(to: work)
        #expect(throws: DiskUpdate.InjectedFault.self) {
            try DiskUpdate.publish(paths, kind: .grow, operation: op, work: work, record: try paths.loadRecord(), fault: .afterStaging)
        }
        try FileManager.default.removeItem(at: work)
        try Data("other".utf8).write(to: work)
        #expect(throws: SandboxError.self) { try paths.loadRecord() }
        #expect(throws: SandboxError.self) { try DiskUpdate.settle(paths) }
    }

    @Test func restoresOfOneSandboxSerialize() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        try committedDisk(r, "snap")
        let id = try SandboxID("a")
        let snap = try SandboxID("snap")
        try await withThrowingTaskGroup(of: SandboxRecord.self) { group in
            for _ in 0..<4 {
                group.addTask { try await Sandboxes.restore(root: r, id: id, source: .disk(snap)) }
            }
            var generations: [Int] = []
            for try await record in group { generations.append(record.diskGeneration) }
            #expect(generations.sorted() == [1, 2, 3, 4], "no lost update")
        }
        let record = try paths.loadRecord()
        #expect(record.diskGeneration == 4)
        #expect(record.imageReference == "snap-image")
        #expect(try rootfs(paths) == "snap")
        let left = try FileManager.default.contentsOfDirectory(atPath: paths.dir.path)
        #expect(!left.contains { Sandboxes.isScratch($0) || $0.hasSuffix(".pending.json") }, "\(left)")
    }

    @Test func guardsExcludeOneSandboxButNotOthers() throws {
        let r = try root()
        let a = try stoppedSandbox(r, "a")
        let b = try stoppedSandbox(r, "b")
        var held: FileLock? = try FileLock.acquire(a.mutationLock, .exclusive)
        #expect(try FileLock.attempt(a.mutationLock, .exclusive) == nil)
        #expect(try FileLock.attempt(b.mutationLock, .exclusive) != nil)
        held = nil
        #expect(held == nil)
        let again = try FileLock.attempt(a.mutationLock, .exclusive)
        #expect(again != nil)
    }

    /// Operations on different sandboxes proceed while one is held.
    @Test func otherSandboxesStayMutable() async throws {
        let r = try root()
        let a = try stoppedSandbox(r, "a")
        try stoppedSandbox(r, "b")
        let held = try FileLock.acquire(a.mutationLock, .exclusive)
        let record = try await Sandboxes.setResources(root: r, id: try SandboxID("b"), cpus: 3, memoryBytes: nil)
        #expect(record.cpus == 3)
        withExtendedLifetime(held) {}
    }

    /// An owner (from `start` or a launchd respawn) cannot claim a sandbox
    /// while an operation holds its guard; once it has, operations refuse.
    @Test func ownerClaimWaitsForTheGuardAndBlocksLaterMutations() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let id = try SandboxID("a")
        var held: FileLock? = try FileLock.acquire(paths.mutationLock, .exclusive)
        let claim = Task { try await Owner.claim(root: r, id: id) }
        try await Task.sleep(for: .milliseconds(300))
        #expect(!Sandboxes.ownerHoldsLock(paths), "the owner claimed a guarded sandbox")
        held = nil
        let fd = try await claim.value
        defer { close(fd) }
        #expect(held == nil)
        #expect(Sandboxes.ownerHoldsLock(paths))
        try committedDisk(r, "snap")
        await #expect(throws: SandboxError.self) {
            try await Sandboxes.restore(root: r, id: id, source: .disk(try SandboxID("snap")))
        }
        #expect(try paths.loadRecord().diskGeneration == 0)
    }

    /// The claiming owner finishes an interrupted disk update before its VM
    /// reads the disk.
    @Test func ownerClaimSettlesAnInterruptedUpdate() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let op = OperationID.random()
        let work = DiskUpdate.workDisk(paths, op)
        try Data("new".utf8).write(to: work)
        var next = try paths.loadRecord()
        next.diskGeneration = 5
        #expect(throws: DiskUpdate.InjectedFault.self) {
            try DiskUpdate.publish(paths, kind: .restore, operation: op, work: work, record: next, fault: .afterRename)
        }
        let fd = try await Owner.claim(root: r, id: try SandboxID("a"))
        defer { close(fd) }
        #expect(try paths.readRecordFile().diskGeneration == 5)
        #expect(!FileManager.default.fileExists(atPath: paths.pendingDiskUpdate.path))
    }

    /// A guard held by a process that dies is released by the kernel.
    @Test func aDeadHoldersGuardIsReleased() throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let holder = Process()
        holder.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
        holder.arguments = [
            "-MFcntl=:flock", "-e", #"open(my $f, ">>", $ARGV[0]) or die; flock($f, LOCK_EX) or die; $| = 1; print "held\n"; sleep 60"#,
            paths.mutationLock.path,
        ]
        let out = Pipe()
        holder.standardOutput = out
        try holder.run()
        #expect(out.fileHandleForReading.availableData == Data("held\n".utf8))
        #expect(try FileLock.attempt(paths.mutationLock, .exclusive) == nil)
        kill(holder.processIdentifier, SIGKILL)
        holder.waitUntilExit()
        #expect(try FileLock.attempt(paths.mutationLock, .exclusive) != nil)
    }

    @Test func deleteWaitsForAnInFlightMutation() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        var held: FileLock? = try FileLock.acquire(paths.mutationLock, .exclusive)
        let delete = Task { try await Sandboxes.delete(root: r, id: try SandboxID("a"), owner: "o") }
        try await Task.sleep(for: .milliseconds(200))
        #expect(FileManager.default.fileExists(atPath: paths.record.path))
        held = nil
        try await delete.value
        #expect(held == nil)
        #expect(!FileManager.default.fileExists(atPath: paths.dir.path))
        // A mutation queued behind the delete finds nothing to act on.
        await #expect(throws: (any Error).self) {
            try await Sandboxes.setResources(root: r, id: try SandboxID("a"), cpus: 2, memoryBytes: nil)
        }
    }

    /// A clone of a committed disk waits for a replacement being published
    /// under that name, then sees the new disk with its own metadata.
    @Test func cloningWaitsForACommittedDiskPublication() async throws {
        let r = try initializedRoot()
        try committedDisk(r, "snap", content: "v1")
        let snap = try SandboxID("snap")
        var publishing: FileLock? = try FileLock.acquire(r.diskLock(snap), .exclusive)
        let create = Task {
            try await Sandboxes.create(
                root: r, id: try SandboxID("c"), owner: "o", source: .disk(snap), cpus: 1, memoryBytes: 1 << 30, diskBytes: 8 << 30)
        }
        try await Task.sleep(for: .milliseconds(200))
        #expect(!FileManager.default.fileExists(atPath: r.sandbox(try SandboxID("c")).rootfs.path))
        try committedDisk(r, "snap", content: "v2")
        publishing = nil
        let record = try await create.value
        #expect(publishing == nil)
        #expect(record.baseDisk == "snap")
        #expect(try rootfs(r.sandbox(try SandboxID("c"))) == "v2")
    }

    /// Undoing an operation refuses once another has committed since.
    @Test func expectedOperationGuardsAgainstOverwritingANewerChange() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        let id = try SandboxID("a")
        let first = OperationID.random()
        let second = OperationID.random()
        _ = try await Sandboxes.setResources(root: r, id: id, cpus: 4, memoryBytes: nil, operation: first)
        _ = try await Sandboxes.setResources(root: r, id: id, cpus: 6, memoryBytes: nil, operation: second)
        await #expect(throws: SandboxError.self) {
            try await Sandboxes.setResources(root: r, id: id, cpus: 1, memoryBytes: nil, expect: first)
        }
        #expect(try paths.loadRecord().cpus == 6)
        let undone = try await Sandboxes.setResources(root: r, id: id, cpus: 4, memoryBytes: nil, expect: second)
        #expect(undone.cpus == 4 && undone.lastOperation != second)
    }

    /// Without a maintenance artifact, growth fails before publication and
    /// leaves disk, record, and scratch space as they were.
    @Test func growWithoutMaintenanceFailsBeforePublication() async throws {
        let r = try root()
        let paths = try stoppedSandbox(r, "a")
        do {
            _ = try await Sandboxes.grow(root: r, id: try SandboxID("a"), diskBytes: 16 << 30)
            Issue.record("grow succeeded without a maintenance image")
        } catch let error as SandboxError {
            #expect(error.description.contains("no maintenance image is installed"), "\(error)")
        }
        #expect(try paths.loadRecord().diskBytes == 8 << 30)
        #expect(try rootfs(paths) == "old")
        let left = try FileManager.default.contentsOfDirectory(atPath: paths.dir.path)
        #expect(!left.contains { Sandboxes.isScratch($0) || $0.hasSuffix(".pending.json") }, "\(left)")
    }

    @Test func maintenanceCapacityFollowsTheArtifact() throws {
        let mib: UInt64 = 1024 * 1024
        #expect(try Maintenance.capacity(packedBytes: 30 * mib) == 640 * mib)
        #expect(try Maintenance.capacity(packedBytes: 0) == 512 * mib)
        #expect(try Maintenance.capacity(packedBytes: 100 * mib) % (64 * mib) == 0)
        #expect(throws: SandboxError.self) { try Maintenance.capacity(packedBytes: Maintenance.maxPackedBytes + 1) }
    }

    @Test func maintenanceArtifactSurvivesImageDeletionAndIsReadBack() throws {
        let r = try root()
        #expect(try Maintenance.installed(root: r) == nil)
        let artifact = MaintenanceArtifact(
            version: "1", reference: "local/coop-maintenance:1", digest: "sha256:ab", capacityBytes: 1 << 30, installedAt: Date(),
            disk: "tools-ab-1073741824.ext4")
        try JSONEncoder.pretty.encode(artifact).write(to: Maintenance.artifactURL(r))
        try Data("tools".utf8).write(to: r.maintenance.appendingPathComponent(artifact.disk))
        #expect(try Maintenance.installed(root: r)?.version == "1")
        let clone = r.root.appendingPathComponent("clone.ext4")
        try Maintenance.cloneTools(root: r, to: clone)
        #expect(try Data(contentsOf: clone) == Data("tools".utf8))
        // The image store is not consulted: the artifact lives outside it.
        #expect(!r.maintenance.path.hasPrefix(r.imageStore.path))
    }

    @Test func operationIDsAreSafeTokens() throws {
        #expect(try OperationID("0123abcd-ef").rawValue == "0123abcd-ef")
        for bad in ["", "A", "a b", "../x", String(repeating: "a", count: 65)] {
            #expect(throws: SandboxError.self) { try OperationID(bad) }
        }
        #expect(try OperationID(OperationID.random().rawValue).rawValue.count == 36)
    }
}
