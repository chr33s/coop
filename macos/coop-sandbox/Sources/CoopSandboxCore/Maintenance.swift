import Containerization
import Foundation

/// Offline disk maintenance in a short-lived VM.
///
/// The VM boots from a throwaway APFS clone of a coop-built image
/// (`Disks.toolsDisk`, which carries e2fsprogs), with no network, and the
/// target disk attached either as a raw device or mounted at `/coopdisk`. The
/// target is data only: none of its programs run.
public enum Maintenance {
    enum Attach {
        /// The device node itself, for fsck/resize of an unmounted filesystem.
        case raw
        /// The filesystem, mounted read-write.
        case mounted
    }

    /// Grow `disk`'s ext4 to fill its (already enlarged) file. The formatter's
    /// ext4 uses sparse_super2, which the guest kernel cannot resize online.
    public static func growFilesystem(root: SandboxRoot, scratch: URL, tools: URL, disk: URL) async throws -> String {
        try await run(
            root: root, scratch: scratch, tools: tools, target: disk, attach: .raw,
            script: "e2fsck -fy /coopdisk; rc=$?; [ $rc -le 1 ] || exit $rc; resize2fs /coopdisk")
    }

    /// Remove per-machine identity from `disk` so every sandbox cloned from it
    /// generates its own SSH host keys and machine-id on first boot.
    public static func resetIdentity(root: SandboxRoot, scratch: URL, tools: URL, disk: URL) async throws -> String {
        try await run(
            root: root, scratch: scratch, tools: tools, target: disk, attach: .mounted,
            script: resetIdentityScript)
    }

    /// Guest-controlled paths are never followed: a symlinked `/etc` or
    /// `/etc/ssh` would redirect the deletions, so it fails the reset instead,
    /// and `rm` removes a symlinked key or machine-id itself, not its target.
    static let resetIdentityScript = """
        set -e
        for d in /coopdisk/etc /coopdisk/etc/ssh; do
            if [ -L "$d" ] || [ ! -d "$d" ]; then echo "refusing: $d is not a directory" >&2; exit 3; fi
        done
        rm -f /coopdisk/etc/ssh/ssh_host_*_key /coopdisk/etc/ssh/ssh_host_*_key.pub
        rm -f /coopdisk/etc/machine-id
        : > /coopdisk/etc/machine-id
        sync
        """

    static func run(root: SandboxRoot, scratch: URL, tools: URL, target: URL, attach: Attach, script: String) async throws -> String {
        let toolsClone = scratch.appendingPathComponent(".maintenance-\(UUID().uuidString.prefix(8)).ext4")
        try clone(tools, to: toolsClone)
        defer { try? FileManager.default.removeItem(at: toolsClone) }

        let vmm = VZVirtualMachineManager(
            kernel: Kernel(path: root.kernel, platform: .linuxArm),
            initialFilesystem: .block(format: "ext4", source: root.initfs.path, destination: "/", options: ["ro"])
        )
        let out = BufferWriter()
        var config = LinuxContainer.Configuration()
        config.process.arguments = ["/bin/sh", "-c", script]
        config.process.capabilities = .allCapabilities
        config.process.stdout = out
        config.process.stderr = out
        config.cpus = 1
        config.memoryInBytes = 1024 * 1024 * 1024
        config.interfaces = []
        let attached: Containerization.Mount =
            switch attach {
            case .raw: .block(format: "none", source: target.path, destination: "/coopdisk", options: ["bind"])
            case .mounted: .block(format: "ext4", source: target.path, destination: "/coopdisk", options: ["nosuid", "nodev", "noexec"])
            }
        config.mounts = LinuxContainer.defaultMounts() + [attached]
        let rootfs = Containerization.Mount.block(format: "ext4", source: toolsClone.path, destination: "/", options: [])
        let container = try LinuxContainer("m-\(UUID().uuidString.prefix(12).lowercased())", rootfs: rootfs, vmm: vmm, configuration: config)
        try await container.create()
        try await container.start()
        let status = try await container.wait(timeoutInSeconds: 600)
        try? await container.stop()
        let log = String(decoding: out.data, as: UTF8.self)
        guard status.exitCode == 0 else { throw SandboxError("maintenance failed (exit \(status.exitCode)):\n\(log)") }
        return log
    }
}
