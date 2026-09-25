# Platform Backends

coop selects its VM backend at compile time. macOS builds use Lima. Linux builds use Firecracker. A macOS build with the opt-in `apple-container` feature uses Apple Container machines instead of Lima (see [macOS / Apple Container](#macos--apple-container-opt-in)). The binary determines the backend; there is no runtime override.

Both backends expose the same CLI commands and produce the same guest environment: Ubuntu with Docker, GitHub CLI, Claude Code, and Codex pre-installed. The backends differ in how they create and manage the VM underneath.

## macOS / Lima

The Lima backend runs VMs through [Lima](https://lima-vm.io/), which wraps Apple's Virtualization.framework. Lima manages disk images, networking, and SSH port forwarding, so coop delegates most operations to `limactl`.

### Prerequisites

Install Lima before running `coop setup`:

```
brew install lima
```

Setup verifies that `limactl --version` is reachable. If it is not, setup fails with an install hint.

### Setup process

`coop setup` builds a golden disk image that all instances clone from:

1. Generates an ed25519 SSH key pair, stored in the coop data directory.
2. Creates a temporary builder VM from an Ubuntu 24.04 cloud image. The Lima YAML template includes a cloud-init provision script.
3. The provision script installs all packages (Docker, GitHub CLI, Claude Code, Codex, and any profile packages), creates the `ubuntu` user with SSH access, and enables services.
4. After provisioning completes, cleans cloud-init state so it re-runs on cloned instances.
5. Stops the builder VM and extracts its disk as the golden image.
6. Generates a fast-start Lima template that references the golden image directly. No cloud-init provisioning runs on instance start.

The builder VM is deleted after extraction, whether the build succeeds or fails.

### How instances work

Each instance is a Lima VM created with `limactl start` using the fast-start template. Lima names are prefixed with `coop-` (e.g., `coop-my-instance`). The instance gets its own disk, a copy-on-write layer over the golden image. Lima handles SSH port allocation automatically; coop reads the assigned port from `limactl list --json`.

The Lima template configures:
- `vmType: "vz"` (Virtualization.framework, not QEMU)
- Rosetta enabled for x86_64 binary translation on Apple Silicon
- `mountType: "virtiofs"` with no host mounts (empty `mounts: []`). When `coop up --mount` is used, Lima adds virtiofs mount entries for the specified host directories, providing live mounts where changes are visible immediately on both sides.
- Lima's built-in containerd disabled (Docker is installed in the guest instead)

### Resize (disk, memory, vCPUs)

Resizing a stopped instance's disk truncates the Lima disk to the new size. Cloud-init's `growpart` module expands the partition and filesystem on next boot. Shrinking is not supported.

Memory and vCPU changes rewrite the `cpus`/`memory` fields in the instance's `lima.yaml`, which Lima re-reads on `limactl start`. The edit is written atomically, then coop starts the instance to validate and apply the new spec — if `limactl` rejects it (e.g. a spec larger than the host), the previous `lima.yaml` is restored. Without `--start` the instance is stopped again after the validating boot. The `lima.yaml` is authoritative: the global `[vm]` `cpus`/`memory` settings only seed *new* instances.

### Resource ownership

Lima runs as the current user. No `sudo` is required for any Lima operation: setup, start, stop, or destroy.

## macOS / Apple Container (opt-in)

Build with `cargo build --release --features apple-container` to replace Lima with Apple's [`container machine`](https://github.com/apple/container/blob/1.4.1/docs/container-machine.md) runtime. Selecting the feature on a non-macOS target is a compile error. The default macOS build never calls, requires, or modifies Apple Container.

> **Status: blocked on a runtime extension.** Stock Apple Container 1.4.1 attaches every machine to one shared built-in network and forwards the host SSH agent into it, and its machine CLI has no switch for either. coop requires a runtime build whose `container machine create` accepts `--network <id>` and `--no-ssh-agent`, and whose `machine inspect` reports `network` and `sshAgentForwarding`. On a runtime without them, `coop setup`, `up`, `start`, `shell`, and every other command that needs a guest fail with `APPLE_RUNTIME_UNQUALIFIED` before any credential, workspace, agent, or project hook reaches a guest. There is no override. Listing, stopping, and destroying already-owned resources still work.

### Prerequisites

- Apple Silicon, macOS 26 or later.
- A qualified `container` runtime with its service already running (`container system start`). coop never starts, stops, or restarts the global service.
- The runtime binary is taken from `[apple_container] binary`, or else `/usr/local/bin/container` or `/opt/homebrew/bin/container`. `PATH` and project files are never consulted, and a binary that is group/world-writable or owned by another user is rejected.

Neither Lima nor host Docker is needed. Docker still runs *inside* the guest.

### Configuration

```toml
[apple_container]
# binary = "/absolute/path/to/container"
probe_timeout_seconds = 10    # version, help, inspect, list
operation_timeout_seconds = 60 # network create/delete, machine set, image delete
create_timeout_seconds = 600  # machine create (unpacks the image)
boot_timeout_seconds = 120    # boot to SSH-ready
stop_timeout_seconds = 30     # stop confirmation
build_timeout_seconds = 3600  # image build; `setup --builder-timeout` overrides
```

Each timeout must be between 1 and 86400 seconds. Unknown keys are rejected, and there is no key to mount the home directory, forward the SSH agent, share a network, or skip qualification. The existing `[vm]` CPU/memory, image, guest-user, profile, and workspace settings apply unchanged.

### State

The feature build defaults to `~/.coop-apple` for its config file and data directory, so neither build's `uninstall --purge` can reach the other's state. `coop setup` refuses a `data_dir` that already holds a default build's `images/`, `instances/`, `vm_key`, or Firecracker/Lima artifacts, because that build's purge removes its whole `data_dir`. Whatever `data_dir` is configured, this backend keeps everything under `<data_dir>/backends/apple-container-v1/`: `owner.json` (installation owner ID), `vm_key`, `images/<name>/` (`template-config.json`, `apple-image.json`, `build.log`), and `instances/<name>/` (`apple-machine.json`, `known_hosts`, `operation.json` while a mutation is pending, plus the shared sidecars). Control files are `0600`, directories `0700`. `uninstall --purge` removes all of `~/.coop-apple` when that is the data directory, and otherwise only `backends/apple-container-v1/`. Workspace copies always skip `.coop-apple/`. Editor `~/.ssh/config` entries use `coop-apple-<name>` aliases inside `# coop-apple START/END` markers, so the two builds never touch each other's entries. Because a default-build instance named `apple-<x>` has the same alias as this build's `<x>`, each build refuses to write an alias the other already manages. The data directory path may contain spaces (SSH options are quoted) but not quote or control characters.

`coop update` is disabled in this build (`APPLE_UPDATE_VARIANT_UNSUPPORTED`): release artifacts carry only the Lima backend. Rebuild from source instead.

### Setup process

`coop setup`:

1. Checks the platform, resolves and qualifies the runtime, and confirms the service is running.
2. Creates `owner.json` and the VM-access key pair.
3. Renders a minimal build context in a private temporary directory: a Dockerfile `FROM ubuntu:24.04`, the same provisioning script Lima uses (packages, profiles, OCI features, guest user, Claude Code, Codex, Docker), a machine-setup script, and `/etc/machine/create-user.sh`. The context contains the coop **public** key only. There are no build arguments and no secrets.
4. Runs `container build --platform linux/arm64 -t local/coop-<owner>:<hash>-<nonce>`, with output in `images/<name>/build.log`. Every build gets a fresh tag, so a rebuild never retags the image the current manifest or an existing instance uses.
5. Boots the image in a disposable machine on its own network, with no credentials, passing the same isolation gate an instance does. It checks the required guest binaries and waits (up to `boot_timeout_seconds`) for `ssh` and `docker` to become active, then deletes the machine and network.
6. Records the image digest and input hash in `apple-image.json` and `template-config.json`. A failed build or verification deletes its new tag and leaves the previous manifest and image in place. After a successful rebuild, the superseded tag is deleted once no instance records it.

The image carries no SSH host keys and an empty `/etc/machine-id`. Each machine generates its own on first boot and keeps them across restarts. `sshd` refuses passwords and root logins and disables agent forwarding.

Marketplaces and plugins are not baked into the image. The first boot installs them through the shared bootstrap.

### How instances work

`coop up` creates, for each instance, one network and one machine, both named `coop-<owner8>-<random16>`. The order:

1. Validate requested capabilities (an explicit `--disk` is rejected here) and write `operation.json`.
2. `container network create` for a dedicated network.
3. `container machine create --no-boot --home-mount none --network <net> --no-ssh-agent` with explicit CPU and memory (`<MiB>mb`).
4. Inspect and verify: home mount `none`, agent forwarding off, dedicated network, requested resources.
5. Boot with `container machine run --root -n <machine> -- /usr/bin/true`.
6. The isolation gate: the backing container belongs to this machine (`<machine>-<suffix>`), is attached to the dedicated network only, has SSH-agent forwarding off, publishes no ports or sockets, and mounts nothing but the runtime's read-only helper directory (`/sbin.machine`) and its first-boot marker (`/etc/.machine.initialized`). Both mounts must come from `…/machines/<machine>/` in the runtime's own state.
7. Read `/etc/ssh/ssh_host_ed25519_key.pub` through `machine run --root` and pin it in the instance's `known_hosts`.
8. Connect over SSH with `StrictHostKeyChecking=yes` against that pin, then hand off to the shared lifecycle: forwards, credentials, agent bootstrap, workspace copy, hooks.

Every later `ssh_target` (shell, exec, agent launch, push/pull, editor) re-inspects the machine and re-runs the gate before it returns a target. On restart the machine gets a new address and backing container. coop re-runs the gate and compares the host key with the pin. A changed or missing key fails with `APPLE_HOST_KEY_CHANGED`: coop never re-enrolls on its own. To recover, recreate the instance.

Workspaces are always copied. `--mount` directories are synced once, as on Firecracker; use `coop push`/`coop pull`.

Local model servers on host loopback reach the guest over a per-instance `ssh -R 127.0.0.1:<guest-port>:<host-addr>:<host-port>` tunnel. The forward goes to the exact loopback address the URL names. The guest port is the same as the host port, except that a privileged port (below 1024) moves to port + 40000, so `https://localhost` becomes `https://localhost:40443` in the guest. `localhost` and `127.0.0.1` URLs keep their host, so TLS names still verify. Other `127.x` addresses are rewritten to `127.0.0.1` for plain HTTP only. IPv6-loopback endpoints are rejected. Each bootstrap reconciles the tunnels for both agents: live tunnels are kept, tunnels the config no longer needs are closed, and two endpoints that need the same guest port with different destinations are an error.

### Resize, commit, restore

`coop resize --mem/--vcpus` runs `container machine set` on the stopped machine, reads the values back, and records them. With `--start`, if the boot fails, the previous values are restored once the machine is confirmed stopped. If the restore fails too, the error says so. Disk sizing (`up --disk`, `resize --disk`) and `commit`/`restore` fail with `CAPABILITY_UNSUPPORTED` before anything is stopped or written.

### Stop, destroy, recovery

`stop` confirms that the machine reached `stopped`. A stop that is not confirmed in time is reported as `APPLE_OPERATION_UNCERTAIN`, and nothing is deleted. `coop stop` never reports success when it could not prove the instance's state. When the normal liveness check fails — an unqualified runtime, a machine that fails the gate, or an unfinished journal — it stops the owned machine through the runtime's control plane alone (no SSH, no qualification needed) and keeps its disk. `coop status` lists such an instance as `unknown` instead of failing. A boot that fails or times out during `coop start` stops the machine again. Ctrl-C interrupts only image builds, machine creation, and boots; stop, delete, and cleanup commands always run to completion. `destroy` acts only on resources whose names and local records match this installation's owner ID. It stops and deletes the machine, confirms it is gone, deletes the network, and then removes local state. If an operation was interrupted (`operation.json` exists), `destroy` checks what the runtime actually has and cleans up only what the journal says coop created. Image deletion removes only this installation's `local/coop-<owner>:` tags.

### Diagnostics

| Identifier | Meaning |
|---|---|
| `APPLE_RUNTIME_UNAVAILABLE` | No usable binary, service not running, or unsupported platform. |
| `APPLE_RUNTIME_UNQUALIFIED` | Unknown CLI/schema or missing isolation extension. |
| `APPLE_NETWORK_ISOLATION` | Wrong, extra, or missing network. |
| `APPLE_HOST_EXPOSURE` | Home mount, agent forwarding, published port, or unexpected host mount. |
| `APPLE_IDENTITY_CONFLICT` | Ownership, name, image, or container identity mismatch. |
| `APPLE_HOST_KEY_CHANGED` | Missing or changed pinned host key. |
| `APPLE_BOOT_TIMEOUT` | Boot or readiness failed or exceeded its deadline, or no valid host key appeared in time; the error includes the last lines of the machine's boot log. Disk and journal are kept. |
| `APPLE_OPERATION_UNCERTAIN` | Timed-out or cancelled runtime call, or unconfirmed stop; reconciled on retry. |
| `CAPABILITY_UNSUPPORTED` | Disk sizing or snapshots requested. |

`coop logs` (snapshot and `--follow`) replaces control characters in the guest's console output before printing it.

Runtime commands run with a cleared environment: only `HOME`, `USER`, `LOGNAME`, `TMPDIR`, locale, and a fixed `PATH` pass through. `SSH_AUTH_SOCK`, API and GitHub tokens, `DYLD_*`, and `CONTAINER_*` overrides are dropped.

### Not yet validated

Nothing in this section has been exercised against a qualified runtime, because none exists yet. The machine/network/SSH-agent extension still has to be implemented and reviewed in Apple Container. After that, the real-hardware acceptance suite still needs to run: cross-network IPv4/IPv6 isolation, the host-exposure and agent canaries, first-boot identity, restart, crash recovery, and endurance. Until then, the stock-runtime refusal is the only runtime behaviour this backend has been tested for.

## Linux / Firecracker

The Firecracker backend runs [Firecracker microVMs](https://firecracker-microvm.github.io/) with KVM hardware virtualization. Each instance is a lightweight VM with its own rootfs, TAP network device, and Firecracker process.

### Prerequisites

- **KVM access**: `/dev/kvm` must exist and be readable/writable by the current user. Setup checks this and offers to fix permissions via `setfacl` or by adding the user to the `kvm` group.
- **x86_64 or arm64 architecture**: The Firecracker backend supports both. x86_64 is the primary test target; arm64 builds are produced but less exercised.
- **curl**: Required for downloading the Firecracker binary and kernel.
- **System packages**: Setup checks for `setfacl`, `unsquashfs`, `mkfs.ext4`, `ssh`, and `rsync`. If tools are missing, it offers to install their Debian/Ubuntu packages (`acl`, `squashfs-tools`, `e2fsprogs`, `openssh-client`, and `rsync`) using `apt-get`. If `apt-get` is unavailable, setup lists the missing tools; install the packages providing them with your host's package manager and rerun `coop setup`. No package manager is needed for this check when all these tools are already on `PATH`. The guest remains Ubuntu regardless of the host distribution.

### Setup process

`coop setup` prepares three artifacts:

1. **Firecracker binary**: Downloaded from the latest GitHub release and stored in the data directory. The jailer binary is extracted alongside it.
2. **Guest kernel**: Fetched from Firecracker's CI S3 bucket. This is a minimal `vmlinux` image matching the Firecracker release version.
3. **Template rootfs**: Built by downloading the Firecracker CI squashfs rootfs (Ubuntu-based), unpacking it, creating an ext4 image at the configured template size, and running an install script inside a chroot. The script installs Docker, GitHub CLI, Claude Code, Codex, and profile packages. It configures the `ubuntu` user with SSH keys and sets up systemd-networkd.

All three steps are idempotent. If the artifact already exists and is up to date, setup skips it.

### How instances work

Creating an instance (`coop up`) follows this sequence:

1. Copies the template rootfs to the instance directory using `cp --reflink=auto` for copy-on-write on supported filesystems.
2. Mounts the copy and patches the guest network config with the instance's unique IP address, plus `/etc/hostname` and the matching `/etc/hosts` alias so the guest can resolve its own name.
3. Optionally resizes the rootfs if a larger disk was requested (truncate + e2fsck + resize2fs).
4. Writes a Firecracker JSON config specifying the kernel, rootfs drive, vCPU/memory allocation, network interface, and vsock device.
5. Creates and attaches a TAP device to the bridge (see TAP networking below).
6. Starts the Firecracker process with `sudo`. Firecracker requires root for KVM and TAP access.
7. Records the Firecracker PID and waits for SSH to become reachable.
8. If `--mount` was specified, rsyncs the host directory into the guest. This is a one-time copy, not a live mount. Use `coop push` and `coop pull` to re-sync.

The code uses a typestate pattern (`Configured` then `Running`) to enforce valid lifecycle transitions at compile time.

Stopping a VM sends `SendCtrlAltDel` via the Firecracker API socket for graceful shutdown, falls back to `SIGTERM`, then `SIGKILL` if the process does not exit.

### TAP networking

Each Firecracker instance gets a dedicated TAP device (`tap0`, `tap1`, ...) derived from its instance index.

The network is configured as follows:

- A Linux bridge (`br0`) is created if it does not already exist, with the configured host IP (default `172.16.0.1/24`).
- IP forwarding is enabled via `sysctl`.
- iptables NAT masquerade and forwarding rules route guest traffic through the host's default network interface. The interface is auto-detected from the default route, or set explicitly via `network.host_iface` in the config.
- A `FORWARD -i br0 -o br0 -j DROP` rule is inserted at the head of the chain. If an existing rule has lost that precedence, startup fails until the host firewall configuration places it first.
- Each instance's TAP device is created, attached to the bridge, marked as an isolated bridge port, and brought up.
- Guest IPs are assigned statically: `172.16.0.{index + 2}`. Instance 0 gets `172.16.0.2`.

**Instances cannot reach each other by IP.** Two controls enforce that and both are required: the isolated bridge-port flag blocks the direct L2 path, and the `FORWARD` rule blocks the L3 path a guest could otherwise take by routing through the host's bridge address. Each guest still reaches the host and the internet. The flag is read back after being set, so a host that cannot apply it fails the VM start rather than booting an unisolated guest; this needs Linux ≥ 4.18 and iproute2 ≥ 4.19.

Isolation is applied per start. Because the kernel drops a frame only when both ports are isolated, a VM still running from before the upgrade leaves the *whole bridge* unisolated until it is stopped and started — not just itself.

[`docs/trust-model.md`](trust-model.md) carries the full invariant and its known residuals (ARP/IP impersonation, IPv6, firewall reloads).

On teardown, the TAP device is removed. If no TAP devices remain on the bridge, the bridge and all associated iptables rules are also removed.

### Network configuration

The `network` section in `config.toml` controls Firecracker networking:

| Field | Default | Description |
|---|---|---|
| `host_ip` | `172.16.0.1` | IP address assigned to the bridge on the host side |
| `subnet_mask` | `/24` | CIDR subnet mask for the bridge network |
| `host_iface` | `auto` | Host interface for NAT. `auto` detects the default route interface. Set explicitly if auto-detection fails. |

These settings are ignored on macOS. Lima handles its own networking. coop's generated Lima templates declare no `networks:` stanza, so each macOS guest gets its own user-mode NAT: instances are isolated from each other by construction there, with no shared bridge and nothing to enforce.

### Resize (disk, memory, vCPUs)

Resizing a stopped Firecracker instance's disk runs `truncate` to extend the rootfs image, then `e2fsck -fy` and `resize2fs` to grow the filesystem in place. Shrinking is not supported.

Memory and vCPU changes edit the `machine-config` block of the instance's per-instance JSON (`vm_config.json`), written atomically so a crash mid-write leaves the prior values intact. This JSON is authoritative: on every restart `configure()` regenerates the infra fields (kernel path, boot args, drive, network) from the global config so they roll forward, but preserves the on-disk `mem_size_mib`/`vcpu_count` rather than resetting them to the global `[vm]` defaults. Those defaults therefore only seed *new* instances. Firecracker does not boot the VM to apply the change; it takes effect on the next `coop start` (or immediately with `--start`).

### Resource ownership

Firecracker requires `sudo` for several operations:

- Starting the VM (KVM device access, TAP device creation)
- Stopping the VM (the Firecracker process runs as root)
- Creating and manipulating TAP devices and bridge interfaces
- Managing iptables rules
- Rootfs operations during setup (chroot, mount, filesystem tools)
- Destroying instance directories (files owned by the root-owned Firecracker process)

## Cross-compilation

coop supports cross-compiling from macOS (arm64) to Linux (x86_64) for the Firecracker backend. The project includes a Cargo config that sets the linker for `x86_64-unknown-linux-musl` to `x86_64-linux-musl-gcc`, provided by the `musl-cross` Homebrew package.

The integration test runner (`tests/run-integration.sh --remote`) automates this workflow: it cross-compiles a release build, copies the binary to the remote Linux host via scp, and runs the test suite there.

## Feature parity

Lima and Firecracker support the same CLI commands and guest capabilities (the Apple Container differences are listed in its section above):

| Capability | Lima (macOS) | Firecracker (Linux) |
|---|---|---|
| `coop setup` | Builds golden image via builder VM | Installs binary + kernel, builds rootfs via chroot |
| `coop up` | Creates or reconnects/restarts a project VM; `--profile` builds/starts a derived image | Copies rootfs, configures TAP, starts Firecracker; `--profile` builds/starts a derived image |
| `coop start` | Restarts a stopped Lima VM | Restarts a stopped Firecracker VM |
| `coop stop` | `limactl stop` | API socket shutdown, SIGTERM, SIGKILL |
| `coop destroy` | `limactl delete --force` | Kill process, remove TAP, delete instance dir |
| `coop status` | Queries `limactl list --json` | Reads PID file, queries guest via SSH |
| `coop logs` | Reads Lima's `serial.log` | Reads Firecracker log file |
| `coop shell` | SSH to localhost on Lima-assigned port | SSH to guest IP on configured port |
| `coop resize` | Disk: truncates Lima disk. Mem/vCPU: edits `lima.yaml`, validated via start | Disk: truncates + resize2fs on rootfs. Mem/vCPU: edits per-instance JSON |
| Resource monitoring | SSH query to guest | SSH query to guest |
| Docker in guest | Works (full kernel) | Works (with iptables-legacy workaround) |
| `--mount` host mounts | Live virtiofs (changes visible immediately) | One-time rsync sync (use `push`/`pull` to re-sync) |
| Needs sudo | No | Yes (VM start, stop, networking, rootfs ops) |
