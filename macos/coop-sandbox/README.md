# coop-sandbox

The macOS VM runtime behind coop's opt-in `apple-container` build: persistent
Linux sandboxes on [`apple/containerization`](https://github.com/apple/containerization)
0.45.0 (pinned exactly in `Package.swift`). coop drives it through the JSON CLI
below; see [`docs/backends.md`](../../docs/backends.md) for the coop side and
[`docs/trust-model.md`](../../docs/trust-model.md) for the isolation contract.

Each sandbox is one Linux VM running systemd from its own ext4 disk, on its own
vmnet network, with no host mounts, socket relays, published ports, or SSH-agent
forwarding. The sandbox record has no field for any of those, so they cannot be
configured. A running sandbox is owned by one `coop-sandbox run` process, which
holds the VM (Virtualization.framework runs it in-process) and serves a
peer-UID-checked 0600 Unix socket for exec/stop/inspect. `start` loads that
owner as a launchd job from a plist in the sandbox directory. launchd respawns
it if it is killed, and nothing starts at login.

## Build

```bash
scripts/build-coop-sandbox.sh [PREFIX]    # default ~/.local/opt/coop-sandbox
swift test --package-path macos/coop-sandbox
./tests/integration-apple-sandbox.sh      # boots real VMs; ~10 min
```

The binary needs only the `com.apple.security.virtualization` entitlement and is
signed ad hoc. Requires Xcode (Swift 6.2+) and macOS 26+ on Apple Silicon.

## CLI (protocol 1)

Every command except `version` takes `--root <absolute path>`, the state root.
It is canonicalized with realpath(3), and every path the runtime reports lies
under it. Commands that report state print JSON on stdout; `exec` and `logs`
pass output through.

```text
version                                   {name, version, protocol, containerization}
init --kernel K                           pinned kernel (sha256 allowlist) + vminit 0.45.0 initfs
image import --oci-tar T | image list | image delete REF
create ID (--image REF | --from-disk NAME) --cpus N --memory-mib M --disk-gib G --owner O
start ID [--wait-seconds S]               launchd job; returns once the owner answers
stop ID [--timeout-seconds S]             systemd halt (SIGRTMIN+3), then unload the job
exec [-i] [--timeout S] ID -- ARGV        root, over vsock; exit code is passed through
inspect ID                                {record, status, live, effective, disk}
list                                      [{id, status, owner}]
set ID [--cpus N] [--memory-mib M]        stopped only; applied at the next start
grow ID --disk-gib G                      stopped only; offline e2fsck + resize2fs
commit ID NAME [--replace]                save the disk with host keys and machine-id removed
restore ID (NAME | --image REF)           replace the disk; bumps record.diskGeneration
disk list | disk delete NAME
logs ID [-n N] [--follow]                 serial console
delete ID --owner O                       refuses another owner's sandbox
reconcile                                 clear crashed owners, finish interrupted creates/deletes
                                          (the sweep is skipped while a create/grow/commit/restore runs)
```

Status is `running`, `booting` (owner up, control channel not yet answering),
`stopped`, or `crashed` (owner died; `start` recovers).

## Behaviour worth knowing

- **Subnets.** Each sandbox gets `10.231.N.0/24` from an allocator shared by
  every sandbox in the root. vmnet keeps a subnet reserved for hours after its
  owning process dies uncleanly and refuses to recreate it. The owner then
  quarantines that subnet (24 h, at most 64 entries) and moves the sandbox to
  another. The address changes; the identity does not.
- **Disks.** Images are unpacked once per (image, size) into a journaled ext4
  and APFS-cloned per sandbox, so creating from a cached base takes
  milliseconds. The formatter uses `sparse_super2`, which the guest kernel
  cannot resize online, so `grow` runs `e2fsck`/`resize2fs` in a short,
  network-less maintenance VM booted from a coop-built tools image; the
  sandbox's disk is attached as data and none of its programs run. The grown
  copy is swapped in only on success. `commit` uses the same VM to strip host
  keys and machine-id.
- **Console log.** The serial console is copied to `boot.log`, capped at
  8 MiB: past the cap the file restarts with a marker line, so a guest
  flooding its console cannot fill the host disk. `logs -n` reads only the
  file's last 256 KiB.
- **Stop.** `stop` asks systemd to halt and forces the VM down after 60 s.
  Killing the owner powers the VM off: journaled ext4 recovers, but unsynced
  guest writes can be lost.
