# Coop Apple Container Backend — Implementation Specification

**Document ID:** COOP-APPLE-001  
**Version:** 0.1.0  
**Date:** 2026-09-25  
**Status:** Implemented; qualified on `1.4.1+coop.83b256f` / macOS 27 (§17.3). Firecracker default-backend regression pending  
**Target repository:** `trailofbits/coop`  
**Coop source baseline:** `338228c44977ed4c408ae7c83d79f2e03f60693c`  
**Apple source baseline:** `apple/container` tag `1.4.1`  
**Delivery model:** Opt-in, compile-time macOS backend; Lima remains the default

## 1. Decision and implementation boundary

Implement `AppleContainerBackend` behind a Cargo feature named `apple-container`. Use Apple's **`container machine`** lifecycle and OCI machine images, retain Coop's SSH-based guest operations, and use copied workspaces rather than host-directory sharing in version 1.

This replaces **Lima as the macOS VM orchestrator**. It does not initially remove Docker from the Linux guest. Current Coop selects Lima on macOS and Firecracker on Linux through a compile-time `PlatformBackend` alias; Docker is part of the guest toolchain and required-binary checks. Removing guest Docker is a separate, optional follow-on deliverable. [C1], [C2], [C3]

### Critical prerequisite

**An unmodified Apple Container 1.4.1 installation is sufficient for a restricted backend prototype, but is not sufficient to ship the isolation-preserving backend specified here.** Its machine implementation selects the built-in network and sets `config.ssh = true`; its machine CLI does not offer the ordinary container command's arbitrary mount/network selection. The boot helper also forwards `SSH_AUTH_SOCK` when inherited. [A2], [A3], [A6], [A7]

The shipping path therefore requires a narrowly scoped, reviewed Apple-side extension, preferably upstreamed, that supports a selected per-machine network and explicitly disables SSH-agent forwarding. Section 7 specifies this dependency. Equivalent externally enforced isolation may replace that extension only through a reviewed amendment with the same acceptance tests—not through an undocumented fallback.

The implementation MUST NOT silently treat a stock runtime as meeting these requirements. It MUST NOT launch agents, inject credentials, synchronize private workspaces, or run project hooks before the security gate passes.

### Normative language

**MUST**, **MUST NOT**, **SHOULD**, and **MAY** describe implementation requirements. All proposed Rust interfaces, configuration additions, sidecars, and Apple CLI extensions below are design requirements, not claims that those interfaces already exist. Source references distinguish current behavior from proposed behavior.

## 2. Goals, non-goals, and success criteria

### 2.1 Goals

| ID | Requirement |
|---|---|
| G-01 | Support Apple Silicon hosts running macOS 26 or later, with an explicitly qualified Apple Container build. |
| G-02 | Preserve the existing `VmBackend` architecture, lifecycle proof types, agent bootstrap, secret handling, and public Coop command semantics where supported. |
| G-03 | Run a persistent Ubuntu-based, Linux/arm64 machine with systemd, SSH, the configured Coop guest account, and existing development profiles. |
| G-04 | Require neither Lima nor host Docker/Docker Desktop for the Apple backend. Retain guest Docker for initial compatibility. |
| G-05 | Keep the macOS home directory and SSH agent inaccessible to the guest; expose no host runtime-management socket. |
| G-06 | Enforce inter-instance network isolation outside the untrusted guest, with fresh validation on every start. |
| G-07 | Support create, restart, shell/exec, agent launch, copied workspace workflows, stop, destroy, status, logs, and CPU/memory changes. |
| G-08 | Fail explicitly for unsupported operations; keep existing Lima and Firecracker behavior unchanged. |
| G-09 | Persist ownership, backend identity, image identity, and recovery state without leaking secrets. |

### 2.2 Non-goals for version 1

Version 1 does not include runtime backend switching within one binary, conversion of existing Lima disks, selective live workspace mounts, guest disk resizing, filesystem commit/restore, Intel Mac support, Rosetta/amd64 guests, nested KVM, or exposing the host's Container control plane to the agent. Full egress allowlisting is also outside scope: preserving isolation does not mean preventing an agent from sending its permitted workspace contents to the internet.

Docker Compose/API compatibility inside the guest remains whatever the existing guest toolchain provides; the Apple host runtime is not a replacement Docker API endpoint.

### 2.3 Definition of success

The backend is releasable when the requirements in this document are implemented, the acceptance suite passes on real Apple Silicon, an unchanged default build still uses Lima, the Linux build still uses Firecracker, and the external network/SSH-agent prerequisite is satisfied by the exact runtime build under test. A successful `container machine create` or agent launch alone is not completion.

## 3. Verified baseline and corrections to earlier investigation

| Current fact | Implementation consequence | Evidence |
|---|---|---|
| Coop uses `VmBackend` plus a compile-time `PlatformBackend` alias, not a runtime VM-backend enum. | Add a feature-selected implementation; do not introduce runtime backend dispatch. | [C1], [C2] |
| Shared operations already use `SshTarget`, `RunningInstance`, and `StoppedInstance`. | Reuse those abstractions; do not rewrite agent operations around native machine exec. | [C1], [C2] |
| Coop normally uses a configured UID-1000 guest account and `/home/<guest-user>` paths. | Override Apple's host-matching account setup. | [C3], [A1] |
| Apple machines boot the image's init system and support a custom first-boot user script. | Build a machine-specific OCI image with systemd and `/etc/machine/create-user.sh`. | [A1] |
| The default machine home mount is read-write. | Pass `--home-mount none` at creation; inspect and enforce it before every boot. | [A2] |
| Machine creation has neither ordinary container mount flags nor a network selector in 1.4.1. | Copy workspaces; implement the network extension in Section 7. | [A2], [A3] |
| Machine conversion hard-codes the built-in network and enables SSH-agent support. | Network selection and explicit agent disablement are shipping prerequisites. | [A7] |
| Even with home mounting disabled, Apple mounts runtime bootstrap resources, including a read-only helper directory and a writable initialization marker. | Do not claim that the guest has zero host-backed mounts. Audit and allow only these narrowly scoped runtime-owned mounts. | [A7] |
| Machine inspection emits a JSON array, including `id`, `status`, `containerId`, `ipAddress`, `homeMount`, `cpus`, and byte-valued `memory`. | Parse the actual machine schema, not Docker's inspect schema. | [A4] |
| Each machine boot creates a new underlying container ID; an IP may be unavailable during boot. | Persist the machine ID, not the underlying container ID or IP as permanent identity. | [A7] |
| Current Coop disk-size code reads a backend disk path. | Gate unsupported disk operations before that path is requested. | [C5] |

Upstream issue #291 reports successful machine/SSH/nested-Docker experiments on Container 1.0.0. Treat that as historical feasibility evidence, not as a current conformance report. Its native-exec observations and claims about mount parity must be rechecked against the pinned runtime. The 1.4.1 native machine runner has explicit process, interactive, and root options; do not copy older limitations into code as universal facts. [C6], [A5]

## 4. Architecture and code boundaries

### 4.1 Target arrangement

```text
Trusted macOS host
  Coop CLI + existing credential proxy
    AppleContainerBackend
      typed, bounded CLI adapter
        qualified Apple Container service
          one dedicated network per Coop instance
          one persistent Linux machine per instance
            systemd + sshd
            configured Coop guest user
            Claude/Codex + profiles + guest Docker

Host -> guest operations: existing SSH/SCP/rsync/tar paths
Guest -> model proxy: per-instance loopback SSH reverse tunnel
Workspace: explicit copies; no host-home mount
Guest -> host Container API / SSH agent: prohibited
```

The VM remains the trust boundary. Passwordless sudo inside the guest remains deliberate; consequently, guest firewall rules and guest file permissions are not controls against a compromised agent. [C4]

### 4.2 Compile-time selection

Add the feature to the root package's existing feature table, without replacing other entries:

```toml
[features]
apple-container = []
```

Proposed backend selection:

```rust
#[cfg(all(target_os = "macos", feature = "apple-container"))]
pub type PlatformBackend = crate::apple_container::AppleContainerBackend;

#[cfg(all(target_os = "macos", not(feature = "apple-container")))]
pub type PlatformBackend = LimaBackend;

// Retain the existing non-macOS Firecracker alias.
```

Selecting `apple-container` on a non-macOS target MUST fail clearly at compile time rather than silently selecting Firecracker. Existing Linux CI MUST NOT start using `--all-features` without accounting for this expected negative build. Pure parsing and state-machine unit tests SHOULD remain runnable on Linux without selecting the macOS backend.

The default macOS build MUST NOT invoke, require, or modify Apple Container. Audit all macOS-specific `#[cfg]` branches: operating-system selection is no longer equivalent to Lima selection.

### 4.3 Proposed modules

```text
src/apple_container/
  mod.rs          # AppleContainerBackend and VmBackend implementation
  cli.rs          # Commands, sanitized environment, deadlines, output bounds
  protocol.rs     # Versioned inspect DTOs and parsing
  state.rs        # Ownership, journals, atomic manifests, recovery
  image.rs        # Minimal OCI build context and image verification
  security.rs     # Runtime qualification, network and mount verification
  ssh.rs          # First-boot host-key enrollment and SSH target construction
```

Split modules only where responsibilities justify them. Use Coop's existing `Cmd`, path/newtype validation, atomic-write helpers, cancellation, and error conventions. A test command executor MAY be injected below the adapter so unit tests do not invoke a real runtime.

### 4.4 Shared interface changes

Introduce a small `BackendCapabilities` value returned by `VmBackend::capabilities()`. This is capability reporting, not runtime backend selection. At minimum it describes live mounts, disk resizing, disk snapshots, host-visible disk paths, CPU/memory changes, and whether local-model endpoints require reverse forwarding.

Lima and Firecracker capabilities MUST preserve existing behavior. Apple capabilities MUST gate unsupported handlers before those handlers stop a VM, create an image record, or call `disk_path()`.

Extend `SshTarget` with an explicit trust policy: the current policy for existing backends, and per-instance pinned host keys for Apple. This change MUST cover SSH, SCP, rsync, generated editor SSH configuration, and multiplexed connections. Do not change existing backends' trust policies incidentally.

A persisted `BackendKind` tag is allowed; it identifies artifacts and is not a dispatch enum.

## 5. Compatibility, configuration, and feature availability

### 5.1 Runtime qualification

The initial qualification baseline is Apple Container 1.4.1 plus the reviewed Section 7 extension. Record the exact Apple and Containerization revisions, runtime/kernel identity, macOS version, and test results. Apple 1.4.1 is the latest release returned by the repository API when this specification was prepared; that is not a promise of future compatibility. [A0]

Preflight MUST verify:

1. macOS, arm64, and the supported OS floor.
2. A host-owned executable resolved to an absolute path—not a `container` executable inside the project directory.
3. Service availability without automatically restarting or stopping the global service.
4. Recognized CLI/schema behavior and the required security capabilities, not just a semver comparison.
5. Valid configuration, sufficient reported host resources, and backend-owned state permissions.

Unknown schema variants, missing security fields, or older runtime behavior MUST fail closed. Future versions enter the supported set only after qualification. Version strings alone are not proof of network isolation.

### 5.2 Proposed configuration

Reuse existing Coop CPU, memory, image, guest-user, profile, and workspace settings. Add only backend-specific settings that are necessary:

```toml
# Proposed additions; not current upstream configuration.
[apple_container]
# Optional absolute path to a qualified runtime binary.
# binary = "/absolute/path/to/container"
probe_timeout_seconds = 10
boot_timeout_seconds = 120
stop_timeout_seconds = 60
```

Timeout values above are proposed defaults, not measured performance. Validate positive bounded values. Image builds need a separate, substantially longer cancellation-aware deadline; do not apply the boot timeout to package installation.

There is no production `allow_insecure`, whole-home mount, or forwarded-host-agent setting. The isolated-network policy is mandatory, not a user-selectable downgrade. Configuration is trusted host input, but project/devcontainer content MUST NOT be able to override the runtime executable, host security policy, or host command environment.

### 5.3 Version-1 capability matrix

| Capability | Version 1 behavior |
|---|---|
| OCI image setup and existing guest profiles | Supported after image verification. |
| Create/start/restart/stop/destroy | Supported, ownership-scoped and recoverable. |
| SSH shell, exec, agent bootstrap, editor SSH access | Supported after security and host-key gates. |
| Workspace copy, push/pull, repository clone | Supported using existing safe copy paths. |
| Live bind mounts | Unsupported; `mounts_are_live()` returns `false`. Existing sync-style mounts retain documented copy semantics. |
| Host-home sharing / host SSH-agent forwarding | Prohibited. |
| Credential proxy and loopback port forwards | Supported via existing SSH tunnel mechanisms. |
| Local model on the host loopback interface | Supported through an explicit per-instance reverse-tunnel endpoint plan; see Section 11. |
| CPU/memory reconfiguration | Supported while stopped, preserving rollback semantics. |
| Explicit disk-size allocation or resizing | Unsupported; reject the request before lifecycle mutation. |
| Commit/restore filesystem snapshots | Unsupported; reject before creating destination metadata. |
| Guest Docker | Retained and tested. |
| Host Docker daemon or Docker socket | Neither required nor exposed. |
| Automatic self-update | Disabled for the feature build until release selection preserves the backend variant. |

An inherited generic disk default MUST NOT make every ordinary `up` fail. Preserve the distinction between an implicit legacy default and an explicit user disk-size request; do not silently discard an explicit request. Do not present sparse host storage growth as unlimited guest disk capacity.

## 6. CLI adapter and runtime protocol

### 6.1 Command construction

All calls MUST use argument vectors through `Cmd`, never an interpolated host shell. Use an explicit machine ID for every command; never rely on the user's default machine. Resource names are generated validated identifiers, not raw workspace names.

Use a sanitized child environment. Explicitly remove `SSH_AUTH_SOCK`, provider/GitHub tokens, agent authentication variables, unintended runtime overrides, and dynamic-loader injection variables. Preserve only required host-service/session variables, a controlled executable search path, locale, and explicitly authorized registry authentication behavior. Audit retained `HOME`, temporary-directory, and XPC-related variables; do not blindly erase values the runtime needs to locate its own service.

Do not use production secrets for image builds. Do not add secrets to command arguments, Dockerfile build arguments, logs, or image layers. Native runtime commands MUST NOT receive the `EnvForward` intended for an SSH guest session. [C4], [A6]

Every command has cancellation behavior, a deadline appropriate to the operation, and bounded captured output. Suggested starting limits are 1 MiB for a single-machine JSON response and 16 KiB for public-key enrollment; tune only with tests. Stream large build/log output to restricted log files rather than buffering it without bounds.

### 6.2 Command mapping

The following commands exist in the inspected baseline, except security extension arguments explicitly described in Section 7. [A1], [A2], [A4], [A5]

| Operation | Adapter behavior |
|---|---|
| Build image | `container build --platform linux/arm64 -t <owned-tag> <minimal-context>` |
| Create, without boot | `container machine create --no-boot --name <machine-id> --cpus <n> --memory <size> --home-mount none <image-ref>`, plus required security extension flags. |
| Trigger boot | `container machine run --root -n <machine-id> -- /usr/bin/true` |
| Inspect | `container machine inspect <machine-id>` |
| List | A version-qualified machine-list JSON mode; capture its exact schema in fixtures. |
| Stop | `container machine stop <machine-id>` |
| Delete | `container machine delete <machine-id>`, only after confirmed stop. |
| Change resources | `container machine set -n <machine-id> cpus=<n> memory=<size>`; omit unchanged fields. |
| Read host public key | `container machine run --root -n <machine-id> -- /bin/cat /etc/ssh/ssh_host_ed25519_key.pub` |
| Diagnostics | Machine logs with version-qualified follow options; guest service logs through SSH when available. |

No normal operation may invoke `container system stop`, broad prune/clean commands, global deletion, or `machine set-default`. Runtime behavior may itself choose the first machine as a default when none exists; do not depend on that behavior and do not overwrite an existing user default to compensate. [A7]

### 6.3 Inspection parsing

The current machine inspect command serializes an array containing a machine-specific output structure. It is not the internal `MachineSnapshot` serialization and not ordinary container inspect. Parse an array of exactly one matching record for a targeted inspection. Validate `id`, status, optional underlying `containerId`, optional `ipAddress`, `homeMount`, CPU count, and memory units. [A4]

Unknown non-security fields MAY be ignored for forward compatibility. Unknown status values, missing security-extension fields, malformed addresses, duplicate records, mismatched IDs, or an unexpected home-mount mode MUST be errors. A running machine with no address is a bounded boot-readiness condition, not a successful SSH target.

Use fixture-derived parsers for network/image descriptions. Do not invent JSON paths such as Docker's `NetworkSettings.IPAddress`. Persist normalized internal data, not an unvalidated arbitrary runtime JSON object.

### 6.4 Liveness semantics

`as_running()` returns `Ok(None)` only when a successful inspection establishes that the machine is not running. Inspection failure returns `Err`. `as_stopped()` must prove a stopped state; it must not treat a timeout or unknown state as stopped.

If the existing boolean `is_running()` API must remain, errors must never grant permission for destructive or stopped-only operations. Audit callers and route state-changing operations through the fallible proof methods. All boot entry points retain `boot_preflight()`. [C2]

## 7. Required Apple runtime extension and isolation gate

### 7.1 Explicit dependency

Implement and qualify the following small extension in an upstream contribution or a pinned fork of Apple Container. The flags and fields in this section are not available in stock 1.4.1. They are implemented in the pinned fork [chr33s/container](https://github.com/chr33s/container), vendored as the `vendor/container` submodule (commit `83b256f`); installation is described in `docs/backends.md`.

| Surface | Required change |
|---|---|
| Machine creation | Accept `--network <network-id>` and `--no-ssh-agent`. |
| Persisted `MachineConfig` | Store the selected network and SSH-agent policy; validate and preserve both across stop/start and service restart. |
| Machine-to-container conversion | Resolve the specified network rather than always selecting the built-in network; set `config.ssh = false` when forwarding is disabled. |
| Boot processing | Ignore/reject `SSH_AUTH_SOCK` in dynamic boot environment when SSH-agent forwarding is disabled, even if a caller supplies it. |
| Machine inspection | Report the configured network and SSH-agent policy in explicit fields; preserve existing output compatibility. |
| Effective-runtime inspection | Permit verification that the backing container actually has the selected network, no additional attachment, and no SSH-agent forwarding. |

For non-Coop callers, missing fields in legacy machine records MAY retain Apple's existing defaults. Coop MUST always supply explicit values and reject records that cannot demonstrate them. Missing or deleted requested networks MUST cause boot failure; there must be no fallback to the built-in network.

Use the existing `MachineCreate`, `MachineConfig`, `MachineInspect`, and `MachinesService` code paths rather than a second parallel VM implementation. Add upstream unit and integration tests for serialization, legacy defaults, explicit disablement, failed network resolution, and restart persistence. The relevant existing conversion and boot behavior is in `MachinesService.swift`. [A2], [A4], [A7]

### 7.2 One private network per instance

Before creating the machine, create an owned network with a generated ID. Use the runtime's supported network-management command, not host shell/firewall edits. Persist network ownership before side effects and use exactly one machine attachment. Never place all Coop machines on one shared “coop” network.

Verify that automatically allocated networks/subnets are host-reachable as intended and do not introduce ambiguous routes. Do not hard-code a subnet or a guest address. Reject an unexpected additional endpoint/attachment in an owned network. Build and image-verification machines receive their own networks as well.

Separate network objects are a mechanism, **not by themselves proof of isolation**. The runtime qualification suite MUST establish the following on the target macOS/runtime combination:

- Guest A cannot connect to Guest B or an unrelated container by IPv4 or IPv6, either directly or by routing through the host gateway.
- A guest changing its own address/routes or attempting neighbor impersonation cannot establish peer connectivity or intercept host-to-peer SSH.
- The host can reach each owned guest's SSH endpoint; required outbound DNS/HTTPS and guest Docker networking work.
- Guest-accessible services, forwarded ports, and the capability-token proxy do not become reachable by a different guest.

Where the platform permits traffic between the selected networks, an additional reviewed host/runtime enforcement mechanism is required. Guest iptables/nftables rules are not an acceptable substitute. The security gate stays closed until the mechanism passes both positive and negative tests. Apple's current general networking documentation explicitly describes same-network reachability; Coop must not inherit that topology unnoticed. [A8], [C4]

### 7.3 Host filesystem and socket exposure

`--home-mount none` is mandatory before first boot and on every restart. Inspect the effective backing-container mounts against a narrow allowlist: the Apple runtime's read-only machine helper directory and its runtime-owned initialization marker may be present; arbitrary host directories, workspaces, credential directories, and control-plane sockets may not. [A7]

The writable initialization marker is an existing runtime-managed guest-to-host surface, not a workspace feature. Include it in security review and pin the responsible runtime code. Do not interpret marker contents as a host command or extend its sharing to a parent directory.

The adapter removes `SSH_AUTH_SOCK` even with the explicit runtime disable flag. These are complementary defenses. Tests must show that an agent cannot use the host agent with a fake or real host agent present, and that an already-running Container service cannot reintroduce a service-inherited agent socket.

### 7.4 Gate placement and test-only prototype

Required network, mount, and forwarding configuration MUST be checked before boot. After boot, inspect effective attachments/mounts again before enrolling trust or transferring any sensitive data. Obtain a private, short-lived `SecurityReady` proof tied to the machine ID and current underlying container ID. Recreate it after every restart; a persisted boolean is not a security proof.

Stock-runtime development is limited to dedicated test harnesses using disposable data, no tokens, no host SSH agent, no private workspace, and no agent or project-hook execution. Such harnesses are not a public insecure mode and are not a release artifact. On stock 1.4.1, production `setup`/`up` fails with an actionable capability error.

If the Apple extension is not accepted upstream, deliver the Coop backend foundation and the pinned runtime patch separately. Do not label the stock runtime as supported to meet a milestone.

## 8. Persistent state, ownership, and recovery

### 8.1 Storage layout

Introduce an effective backend-owned data root beneath the configured Coop data directory:

```text
<data_dir>/backends/apple-container-v1/
  owner.json
  vm_key                      # reuse Coop key handling within this backend root
  vm_key.pub
  images/<image-name>/
    template-config.json      # existing logical template contract
    apple-image.json
  instances/<instance-name>/
    instance.json             # existing logical instance contract, backend-tagged
    apple-machine.json
    operation.json            # only while mutation/recovery is pending
    known_hosts
    workspace.json            # existing shared sidecars, where applicable
    forwards.json
    guest_env.json
    model.json
    proxy.json
    logs/
```

The feature build's default configured data directory MUST use a distinct application identity from an existing Coop installation. During rollout, do not place Apple state under a data root that an unmodified older Coop binary may recursively purge. An explicit shared root is supported only when every binary using it has ownership-aware cleanup.

Resolve the effective root once before loading image/instance state; do not append the backend suffix in scattered call sites. Preserve existing config semantics for default backends. Existing Lima/Firecracker artifacts are not migrated, reused, or deleted. An Apple build encountering a foreign backend tag MUST refuse the operation.

Directories containing sensitive state use `0700`; keys, sidecars, pins, and logs use `0600` unless an existing stricter rule applies. Use atomic writes with preserved permissions, no symlink-following for managed control files, and existing filesystem locks. Do not claim that the entire pre-existing Coop state model has become secret-free; preserve existing secret-bearing sidecar protections.

### 8.2 Names and ownership

Generate machine/network names from a persisted owner ID plus random instance ID, for example `coop-<owner8>-<instance16>`. Validate against the pinned runtime's actual name limits. Do not pass raw project names, usernames, or filesystem paths as machine names. Check for collisions and generate a new identifier; do not adopt a colliding object.

Ownership is established by restricted local metadata written before creation, the unpredictable generated ID, and matching runtime identity/image/network information. A `coop-` prefix alone is never sufficient authority to delete an object. Revalidate identity before every destructive operation.

The host user is trusted; this does not attempt to defend against an attacker who already controls the macOS account and can replace both runtime state and Coop metadata.

### 8.3 Required sidecar fields

Define versioned serde types rather than free-form JSON. `apple-machine.json` includes:

| Field | Meaning |
|---|---|
| `schema_version` | Parser/migration version. Unknown future versions are rejected. |
| `backend` | Literal `apple-container`. |
| `owner_id`, `instance_id`, `machine_id` | Stable ownership and logical identity. |
| `network_id` | Owned dedicated network identity. |
| `image_digest`, `image_manifest_id` | Exact template identity used at creation. |
| `guest_user` | Persisted validated guest account. |
| `requested_cpus`, `requested_memory_bytes` | Last committed resource intent, reconciled with runtime configuration. |
| `host_key_fingerprint` | Enrolled public host-key fingerprint, not a private key. |
| `last_observed_container_id`, `last_observed_ip` | Diagnostic observations only; always refreshed before use. |
| `creation_state`, `created_at` | Recovery information; not live-state authority. |
| `runtime_identity` | Qualified runtime/schema/patch identity for diagnostics. |

Do not store API tokens, agent sockets, raw environment dumps, private guest host keys, or a persisted security-ready assertion in these new records. Redact sensitive existing state in diagnostics.

### 8.4 Mutation journal and locks

Use a per-instance mutation lock and a short-lived image/ownership lock where needed. Establish a documented lock ordering. Reads may report a transition in progress; they must not launch competing repairs. An image rebuild must not change the digest under an existing instance.

Write an operation journal before each mutating runtime call. It records the intended operation, prior committed state, created resource IDs, and completed stages. Recovery re-inspects the runtime before acting; a command timeout does not mean that creation/deletion failed.

| Interrupted operation | Required recovery |
|---|---|
| Network created, machine absent | Remove only the journal-owned network after confirming it has no foreign attachment. |
| Machine create timed out | Inspect exact ID; reconcile matching ownership and immutable inputs, or stop with a conflict. Never issue a blind second create. |
| Boot/readiness failed | Stop the owned machine when possible; retain its disk, journal, and diagnostic logs. Do not automatically delete user data. |
| Resource update interrupted | Read authoritative values; complete or revert the journaled change without overwriting unrelated state. |
| Stop timed out | Preserve “unknown/stopping”; no disk mutation or deletion until stop is confirmed. |
| Delete interrupted | Re-inspect, then complete machine/network/local-metadata cleanup in order. |
| Runtime service unavailable | Preserve all state and report a retriable error; do not reinterpret absence of a response as absence of a machine. |

## 9. OCI image and guest provisioning

### 9.1 Image contract

Build a Linux/arm64 OCI image based on Ubuntu 24.04, following Apple's systemd machine requirements and Coop's reusable guest provisioning contract. [A1], [C3]

The image MUST contain systemd, SSH, the configured UID-1000 guest account, passwordless sudo consistent with Coop, required copy tools, existing agent launchers/authentication dependencies, selected language profiles, and guest Docker. Verify required binaries using the shared source of truth in `guest.rs`, not a second divergent list.

Use `/etc/machine/create-user.sh` to preserve Coop's guest identity. It must be an executable root-owned script that idempotently creates/verifies the configured account and does not create a home-mount alias or host-matching account merely because `CONTAINER_USER`/`CONTAINER_HOME` were supplied. Normal guest interaction subsequently uses SSH; native machine commands used by Coop specify `--root` and fixed paths, so they do not depend on Apple's host-matching account. [A1], [A5], [C3]

### 9.2 Reuse and separate provisioning

Reuse architecture-independent profile/tool installers. Audit each shared script before reuse: Firecracker networking/kernel workarounds, chroot mount logic, Lima cloud-init behavior, and direct disk mutations must not be copied into an OCI build wholesale.

Use Apple's documented machine/systemd adaptations as the starting point, then explicitly test SSH, D-Bus/account-auth services, Docker, clean shutdown, and the guest username. Do not add nested-virtualization flags merely to run Docker inside Linux; nested KVM is not part of this backend.

Image setup MUST verify both installed executables and essential service readiness. Exit status or a stale “provisioning complete” marker alone is insufficient.

### 9.3 Build context and identity

Generate the smallest possible build context in a private temporary directory. It includes only the rendered Dockerfile, reviewed provisioning scripts, validated profile inputs, and the Coop VM-access **public** key when creating a local personalized image. Never use the whole repository, current directory, or macOS home as the build context by default.

A public access key may be baked into a local derivative; the host private key and all provider credentials MUST remain outside the image. Include the public-key fingerprint in the local image cache key. A distributable base image must not contain a user's authorized keys; build a local derivative before it becomes a Coop template.

Compute a manifest identity from the base-image digest, platform, provisioning-script content hashes, selected profiles and resolved inputs, guest user, public-key fingerprint, and schema version. Resolve tags to a digest and persist that digest. Dependency install versions/digests SHOULD be pinned; where an upstream installer cannot be fully pinned, record the resolved version and document that the build is repeatable only to that extent.

`image_is_built()` succeeds only when the local manifest is complete and the referenced OCI content still exists with the expected platform/digest. A tag name alone or an old build directory is insufficient.

### 9.4 First-boot identity and verification

Remove machine IDs and SSH server private keys from the reusable image. Generate them per instance on first boot, and **preserve them on subsequent restarts**. Verify that two instances have different host-key fingerprints and machine IDs.

Configure SSH for the Coop public key, no password authentication, no root login over SSH, no agent forwarding, and the required explicit environment allowlist. Preserve remote/local TCP forwarding only as needed for Coop's existing tunnels; test its scope rather than enabling unrelated forwarding features.

Verify a candidate image in a disposable, owned, isolated machine with no real provider credentials. Only publish `apple-image.json` as ready after verification succeeds. Delete the verification machine and its network through ownership-scoped cleanup. A failed rebuild must not remove the previously working image manifest/digest.

## 10. Lifecycle implementation and SSH trust

### 10.1 `setup`

Run `boot_preflight`, qualify the runtime, initialize the backend root and VM-access key using existing helpers, render/build the OCI image, verify it in isolation, and atomically publish the template manifest. Do not install or restart global host services implicitly. On failure retain bounded logs and remove only temporary owned resources.

### 10.2 `create_and_start`

The required order is:

1. Validate configuration and supported capabilities before creating resources. Acquire the mutation lock and reserve stable ownership IDs.
2. Verify the selected image digest and persist a creation journal.
3. Create the owned network; verify its intended isolation configuration.
4. Create the machine with `--no-boot`, explicit resource limits, `--home-mount none`, the selected network, and disabled SSH-agent forwarding.
5. Inspect persisted configuration. Abort before boot on any mismatch.
6. Trigger boot using the fixed native command; retry only bounded readiness probes, not arbitrary failed project commands.
7. Inspect the current underlying container and effective network/mount/agent policy. Establish `SecurityReady`.
8. Wait for first-boot SSH host-key creation. Read the public key through the explicit native machine control channel, validate it, and enroll it as described below.
9. Build a fresh `SshTarget` and run the existing SSH readiness probe.
10. Persist committed machine metadata. Return into the existing shared lifecycle for forwards, credentials, agent bootstrap, workspace transfer, and hooks, preserving their existing ordering contracts.

Steps 1–9 do not transmit provider credentials or private workspace data. Ensure no newly introduced first-boot service launches an agent or project hook before this gate. The backend need not duplicate shared bootstrap functions; the command handler must wait until the backend's secure readiness contract is satisfied.

### 10.3 Host-key enrollment and transport

The existing local-VM no-host-key-checking policy must not simply be extended to the Apple backend. [C4]

Read the guest's Ed25519 host **public** key over `machine run --root`, addressing the exact owned machine; never use network `ssh-keyscan` as the trust root. Parse one bounded, valid key. Enrollment is allowed only for a newly created machine with no previous pin and after effective security checks.

Write a per-instance known-hosts file under `0600`, using a stable host-key alias tied to the instance ID. Construct Apple SSH options from one policy branch:

```text
StrictHostKeyChecking=yes
UserKnownHostsFile=<instance-owned-known-hosts>
GlobalKnownHostsFile=/dev/null
HostKeyAlias=<stable-instance-alias>
UpdateHostKeys=no
ForwardAgent=no
IdentitiesOnly=yes
```

Do not append these after the existing contradictory `StrictHostKeyChecking=no` options; construct the intended options once. Apply the pin to every transport and generated editor configuration. Multiplexing identities must include instance/trust identity, not only an IP that can be reassigned.

On restart, keep the existing pin and refresh only the endpoint. A missing pin on an already-created instance or a changed host key is a hard error, not permission to auto-enroll. Recovery requires an explicit operator-reviewed action or instance recreation. A guest may change its own key because it has sudo; that must cause loss of access, not loss of host authentication.

### 10.4 `start_existing` and liveness

Revalidate ownership, runtime qualification, home/agent/network settings, and pending journal state. Respect the machine's persisted CPU/memory configuration rather than resetting it from global defaults. Boot, re-inspect its new underlying container/IP, re-establish `SecurityReady`, and connect with the existing pin.

Never reuse a diagnostic cached address. Recreate SSH forwards/proxy tunnels against the fresh target and keep the existing first-boot-versus-restart bootstrap distinction. A persisted `RunningInstance` or `SecurityReady` is prohibited; proofs are process-local and tied to current observations.

### 10.5 `stop`, destroy, and cleanup

`stop` consumes `RunningInstance`, stops associated Coop-owned tunnels/proxies according to existing lifecycle cleanup, requests machine stop, and verifies the result. Forced termination may be attempted only through a documented, qualified per-machine operation and explicit existing force semantics; never kill a global runtime service.

Destroy requires a confirmed stopped machine. Delete the exact owned machine, confirm absence, remove its owned network only if no other endpoint exists, then remove local metadata and pins. If an earlier step fails, retain enough state to retry. A missing runtime object with intact ownership metadata may be reconciled; an unowned existing object must not be deleted.

`destroy_shared` and image deletion operate only on this backend's manifests, derivative tags, and owned resources. Never prune the global image store or delete shared base images as a shortcut. Audit shared `uninstall`/purge handlers so neither updated build recursively removes a foreign backend namespace; an Apple build cannot remove Lima or unrelated Container data.

### 10.6 CPU/memory and unsupported storage operations

Resource changes require `StoppedInstance`. Journal previous authoritative CPU/memory values, apply only requested fields, read back byte-valued memory and CPU count, and atomically commit the change. Use explicit units and test conversion; do not confuse decimal megabytes and binary mebibytes.

When `start_after` is requested, use the same secure start path. If boot fails, restore prior resource configuration only after stopped state can be established; otherwise report incomplete rollback and preserve the journal. Do not hide rollback failure.

Apple `resize_disk`, `commit_disk`, `restore_disk`, and host `disk_path` return typed unsupported-capability errors. Handlers must reject these operations before stopping a VM or creating/deleting an image. Do not reach into Apple's private EXT4/snapshot files. Runtime-reported disk usage, guest filesystem capacity, and sparse file allocation are distinct metrics; expose them only with accurate labels.

## 11. Shared workspace, agent, proxy, and editor integration

### 11.1 Workspaces and devcontainers

Set `mounts_are_live()` to `false`. Reuse Coop's existing rsync/tar workspace machinery, path validation, symlink/traversal defenses, and explicit pull semantics. Do not implement an independent copy-back mechanism. [C1], [C4]

The guest workspace must be independent of the macOS source directory. A guest edit must not change the host until an explicit supported pull/sync operation occurs. Preserve intended permissions and ownership, validate paths containing spaces and Unicode, and make symlink behavior match the existing safe copy contract.

Reject features that require an actual live bind mount rather than pretending a one-time copy is equivalent. Keep sync-style mounts clearly labeled in status and documentation. Exclude host credentials from implicit copies; explicitly requested workspace files remain within the user's selected data boundary.

Devcontainer/profile content must run in the Linux build/guest context, never as a new host shell hook. Audit image/path/feature handling so project input cannot choose the host runtime binary, enable an agent socket, or widen the network policy. Version-1 unsupported devcontainer features produce a precise error before boot where possible.

### 11.2 Agent bootstrap and credential proxy

Continue using shared `bootstrap_agents` and environment/secret resolution. Credentials are supplied only after secure readiness. Preserve opt-in GitHub-token behavior and existing API-key suppression in credential-proxy mode. Do not copy a whole host agent configuration directory as a substitute for Coop's allowlisted staging. [C1], [C4]

Retain host-loopback `coop-proxy` listeners and per-instance capability tokens delivered through the existing SSH reverse tunnel. Never expose the proxy using a wildcard host listener or the Apple default network. Preserve failure-closed proxy readiness and current proxy confinement. [C4]

### 11.3 Port forwards and local-model endpoints

Keep existing local forwards bound to `127.0.0.1`, including collision detection. Do not introduce Apple `--publish` as a second competing forwarding mechanism.

For host-loopback local-model servers, add a resolved `LocalEndpointPlan` to shared endpoint setup. It records the host destination, guest loopback listener, tunnel identity, and rewritten guest URL. Apple uses a per-instance `ssh -R` tunnel; legacy backends may keep their existing direct host-address rewriting.

A representative forwarding argument is:

```text
-R 127.0.0.1:<guest-port>:127.0.0.1:<host-model-port>
```

Use `ExitOnForwardFailure=yes`, validate collisions, and verify readiness before publishing the guest URL. Resolve each instance's endpoint independently, including multiple providers or local endpoints. Preserve URL scheme/path and TLS verification; unsupported hostname/certificate transformations must fail rather than disable verification. Handle IPv6-loopback destinations explicitly when supported.

Do not return Lima's `host.lima.internal` or invent an Apple hostname in `guest_host_address()`. Refactor endpoint resolution to consume `LocalEndpointPlan` when the backend requires it. An Apple guest-loopback address is valid only together with an established tunnel and matching port; returning `127.0.0.1` alone is not an implementation.

On stop, crash detection, or failed startup, remove only the instance's tunnels and associated state. Recreate them against the new SSH endpoint on restart.

### 11.4 Status, logs, and editor configuration

Status combines authoritative runtime state with existing guest probes only when a valid running/security context exists. Include backend, qualified-runtime identity, copied-workspace mode, CPU/memory, and unsupported capability indicators. Unavailable guest metrics are reported as unavailable, not zero.

Machine boot logs remain available through ownership-checked diagnostic paths after SSH readiness failure. Continuous logs are streamed without unbounded accumulation. Sanitize guest-controlled terminal output in structured/human diagnostic contexts where appropriate; never evaluate it.

Generated editor SSH entries must include the per-instance host-key policy and current endpoint. Regenerate stale address information on restart, and remove only entries owned by the deleted instance. A changed guest IP must not force disabling host-key checks.

## 12. Errors, observability, and release behavior

### 12.1 Error classification

Use typed backend errors wrapped according to existing Coop conventions. Proposed stable diagnostic identifiers:

| Identifier | Condition and required response |
|---|---|
| `APPLE_RUNTIME_UNAVAILABLE` | Executable/service missing; provide the failing prerequisite without restarting unrelated services. |
| `APPLE_RUNTIME_UNQUALIFIED` | Unknown build/schema or missing required runtime extension; stop before sensitive work. |
| `APPLE_NETWORK_ISOLATION` | Wrong topology, missing network, or unmet isolation mechanism; fail closed. |
| `APPLE_HOST_EXPOSURE` | Home/agent/forbidden mount or socket exposure; refuse boot or stop the newly booted owned machine. |
| `APPLE_IDENTITY_CONFLICT` | Ownership/runtime/image mismatch; do not adopt or delete the object. |
| `APPLE_HOST_KEY_CHANGED` | Missing or mismatched existing pin; do not auto-enroll. |
| `APPLE_BOOT_TIMEOUT` | Boot/readiness deadline exceeded; preserve disk/journal and include bounded diagnostics. |
| `APPLE_OPERATION_UNCERTAIN` | Runtime result is ambiguous; reconcile before further mutation. |
| `APPLE_CAPABILITY_UNSUPPORTED` | Disk/live-mount/snapshot operation not implemented; reject without side effects. |
| `APPLE_UPDATE_VARIANT_UNSUPPORTED` | Stock self-updater would replace the feature build; leave binaries unchanged. |

Use the repository's established process-exit conventions; do not introduce arbitrary numeric exit codes without a broader CLI decision. Machine-readable output may add versioned fields, but must not silently remove existing fields or repurpose their meanings.

### 12.2 Diagnostics and performance evidence

Record operation durations, image cache decisions, readiness attempts, schema/build identity, and cleanup outcomes without secrets. Diagnostic snapshots must not include unrestricted host environment variables or agent-auth files.

Measure cold image setup, cached create-to-SSH readiness, warm restart, workspace transfer, and stop/destroy timings on stated hardware. Also record host and guest storage metrics with their actual meanings. Performance numbers are evidence to collect, not guarantees in this spec. Security gates cannot be bypassed to improve a benchmark.

### 12.3 Installation, update, and fallback

During development, install the feature build under a distinct name such as `coop-apple`, with its matching `coop-proxy`, or run the built binary directly. Display the active backend in version/diagnostic output.

Disable stock self-update and automatic update suggestions for the Apple feature build until release artifact selection preserves the backend feature, companion binary, and runtime compatibility requirements. Test that an update attempt cannot silently replace the Apple build with a Lima build. Default-build update behavior remains unchanged.

Fallback means using the ordinary Lima build and creating/using its own instances; there is no automatic disk conversion or backend switching for an existing Apple instance. Keep a rollback path that preserves Apple data while the default build remains usable.

## 13. File-level change map

All new file names below are proposed. Existing file paths are anchored to the Coop baseline in this document. Reconcile nearby refactors before implementation rather than applying line-number patches blindly. [C1], [C2], [C3], [C5]

| Area | Required changes |
|---|---|
| `Cargo.toml` | Add feature; preserve workspace/default feature behavior. |
| `src/lib.rs` | Feature-gated module wiring, unsupported-target compile error, backend-aware diagnostics, and dispatch/capability checks where necessary. |
| `src/backend.rs` | Select alias; add capability reporting and explicit SSH trust policy; retain proof-type/boot invariants. |
| `src/apple_container/*` | Implement lifecycle, adapter, protocol, state, image, security, and enrollment responsibilities. |
| `src/config.rs` | Add optional Apple settings, effective data-root resolution, backend tags, and explicit-versus-default disk request provenance. |
| `src/cmd.rs` | Extend the existing command wrapper as needed for environment sanitization, deadlines, cancellation, and bounded output, preserving redaction. |
| `src/guest.rs`, `scripts/guest/*` | Reuse tool/profile sources; add machine-specific user/SSH/systemd provisioning without changing default-backend behavior. |
| `src/commands/lifecycle.rs` | Fail unsupported operations before mutation/disk-path lookup; integrate secure readiness, recovery, endpoint planning, and resource semantics. |
| `src/commands/profiles.rs`, `quickstart.rs` | Recognize digest-backed OCI templates rather than assuming Lima/Firecracker disk artifacts. |
| `src/workspace.rs`, `ssh.rs` | Preserve copy behavior; apply host-key policy consistently to transport/editor configuration. |
| `src/proxy.rs`, `port_forward.rs`, `model_state.rs` | Reuse scoped tunnels; persist resolved local endpoint plans and remove stale target state. |
| `src/commands/json.rs` | Add backend/capability diagnostics compatibly. |
| `src/commands/admin.rs`, `src/commands/mod.rs` | Audit uninstall and purge for strict backend ownership. |
| `src/update.rs` | Protect feature-build identity; disable incompatible updater/notifier paths. |
| `tests/fixtures/apple-container/*` | Add source-version-labeled CLI fixtures with synthetic/sanitized identifiers. |
| `tests/apple-container-*.sh` | Add contract, lifecycle, integration, security, and crash-recovery suites. |
| `docs/backends.md`, `getting-started.md`, `ARCHITECTURE.md`, `trust-model.md` | Document capability boundary, runtime dependency, copy semantics, and new security surfaces. |
| Apple runtime patch | Add the Section 7 flags, persisted fields, conversion logic, inspection, and regression tests. |

Audit direct `limactl`, `crate::lima`, `inst.rootfs_path`, disk-file metadata, and macOS-only assumptions throughout the tree, not just the listed files. No shared user command should escape the intended backend boundary through one of these shortcuts.

## 14. Implementation work packages

These are dependency-ordered deliverables, not calendar estimates. Mark completion only with the specified evidence.

### WP-0 — Baseline and contract harness

**Dependencies:** None.  
**Deliverables:** Pin source revisions; capture real 1.4.1 machine create/run/inspect/list/log/resource behavior; document JSON fixtures, name constraints, units, timeout/error behavior, and required extension fields.

- [ ] Build and test the unchanged Coop baseline on macOS and Linux.
- [x] Run a restricted, credential-free stock-runtime prototype on real Apple Silicon.
- [x] Confirm home disabled, native fixed-command execution, image requirements, and restart identity behavior.
- [x] Capture the expected production refusal on the unmodified runtime.

**Exit:** Fixtures are checked in and baseline assumptions are reproducible. Historical issue comments are not accepted as test evidence.

### WP-1 — Apple security prerequisite

**Dependencies:** WP-0.  
**Deliverables:** Reviewed runtime patch, exact build identity, serialization/API tests, dedicated-network and agent-disable support.

- [x] Implement all Section 7 extension points without changing unrelated default behavior.
- [x] Validate persistence after machine restart and service restart.
- [x] Demonstrate cross-network IPv4/IPv6 and route/neighbor negative tests.
- [x] Demonstrate absence of host-agent exposure even with inherited/service-side agent state.

**Exit:** Security qualification succeeds. Otherwise retain an explicitly blocked shipping gate; do not downgrade it to a warning.

### WP-2 — Backend skeleton, ownership, and capabilities

**Dependencies:** WP-0; may proceed while WP-1 is under review.  
**Deliverables:** Cargo selection, CLI adapter, parsers, capability errors, backend data namespace, typed manifests/journals, ownership-safe cleanup.

- [x] Default macOS/Linux builds remain unchanged.
- [x] Feature build advertises Apple backend and rejects unsupported targets.
- [x] Unit tests cover malformed output, command injection, timeout ambiguity, backend mismatch, and resource collisions.
- [x] Unsupported operations fail before side effects.

**Exit:** Mock-runtime lifecycle and failure paths pass; stock-runtime production guard remains enforced.

### WP-3 — Image and secure lifecycle

**Dependencies:** WP-1 and WP-2 for real-runtime secure tests.  
**Deliverables:** OCI builder, image manifests, configured guest account, secure creation/restart, host-key enrollment, stop/destroy, resource changes.

- [x] Required binaries/services verified in a disposable machine.
- [x] Distinct first-boot machine IDs/host keys; stable keys on restart.
- [x] Security checks precede credentials/workspace transfer.
- [x] Crash-injected lifecycle operations recover without data loss or foreign-resource deletion.

**Exit:** Core acceptance tests T-01 through T-15 below pass on the qualified runtime.

### WP-4 — Shared product integration

**Dependencies:** WP-3.  
**Deliverables:** Workspaces, agents, proxy, editor SSH, local-model endpoint plans, status/logs, profile/quickstart compatibility, updater protection.

- [x] No whole-home mount or unrestricted agent-config copy is introduced.
- [x] Proxy credentials remain host-side in proxy mode; port listeners remain loopback-only.
- [x] Copy/pull and devcontainer cases preserve existing trust boundaries.
- [x] Feature build cannot update itself into a different backend.

**Exit:** Full functional suite passes with synthetic credentials and controlled endpoints; optional live-provider tests require separate authorization.

### WP-5 — Qualification and release

**Dependencies:** WP-1 through WP-4.  
**Deliverables:** Security review, real-hardware CI, source/build provenance, support matrix, operational docs, rollback evidence, benchmark report.

- [ ] Run the complete acceptance suite and all default-backend regression checks.
- [x] Run at least 30 consecutive lifecycle cycles and a concurrent multi-instance scenario; investigate every leaked resource or unexpected result.
- [x] Re-run security checks after service restart and simulated failure.
- [x] Publish exact supported runtime/macOS combinations and unresolved non-goals.

**Exit:** All release gates in Section 17 are met. A skeleton, prototype, or patched-runtime proposal alone is not a release.

## 15. Acceptance test matrix

Tests must exercise both a fake command executor for deterministic errors and real Apple Silicon hardware for virtualization/network behavior. A generic hosted runner label does not prove that the required virtualization facilities are available.

| ID | Test | Acceptance criterion |
|---|---|---|
| T-01 | Build selection | Ordinary macOS binary selects Lima; Apple feature selects Apple; ordinary Linux selects Firecracker; Apple feature on Linux fails clearly. |
| T-02 | Stock-runtime rejection | Missing network/agent extension prevents production setup/start before sensitive state is transferred. |
| T-03 | Command safety | Names/paths with shell metacharacters cannot execute host commands; all arguments are separate and validated. |
| T-04 | Environment safety | Canary API/GitHub credentials and SSH agent variables are absent from runtime child environment, logs, build args, and image layers. |
| T-05 | Inspect schema | Correct array parsed; malformed, empty, duplicated, mismatched, unknown-status, missing-policy, and oversized responses fail appropriately. |
| T-06 | Ownership/data isolation | Foreign backend records, colliding names, and unrelated machines/images/networks cannot be adopted or deleted. |
| T-07 | Guest image contract | Configured UID-1000 user, sudo, copy tools, agent launchers, account-auth dependencies, and guest Docker pass verification. |
| T-08 | First-boot identity | Two instances have different machine IDs and host keys; neither reusable image nor host logs contains guest private host keys. |
| T-09 | Persistent restart | Guest files and enrolled host key survive stop/start; underlying container ID/address is refreshed without breaking SSH. |
| T-10 | SSH pin enforcement | A wrong key or missing existing pin fails SSH/SCP/rsync/editor access; no transport downgrades checking. |
| T-11 | Liveness ambiguity | Probe errors never mint stopped/running proofs that authorize unsafe mutation; boot without an IP waits within its deadline. |
| T-12 | CPU/memory | Settings round-trip with correct byte units; restart preserves them; failed boot performs safe rollback or reports incomplete rollback. |
| T-13 | Unsupported operations | Explicit disk sizing, resize, commit/restore, and mandatory live mounts fail before state-changing work. |
| T-14 | Failure recovery | Inject failure after each journaled side effect; retry reconciles resources and preserves user disks. |
| T-15 | Scoped destroy | Removing one instance leaves other instances and an unrelated user's test container/network/image intact. |
| T-16 | Host mount exposure | Home is disabled before boot and on restart; only the reviewed runtime bootstrap mounts exist; host canary files remain inaccessible. |
| T-17 | SSH-agent exposure | No usable host agent is available from the guest, including when the CLI or already-running service has an agent in its environment. |
| T-18 | Peer isolation | Owned and unrelated peers cannot connect across instance networks over IPv4/IPv6, including route/address/neighbor manipulation cases. |
| T-19 | Required connectivity | Host SSH, permitted external DNS/HTTPS, image pulls, and guest Docker network operations work without opening peer access. |
| T-20 | Workspace independence | Guest writes do not immediately alter the host; explicit pull works; traversal, escaping symlink, and permission cases preserve existing safeguards. |
| T-21 | Agent/proxy integration | Bootstrap and launcher configuration pass; synthetic secrets are redacted; proxy mode does not stage real model API credentials in the guest. |
| T-22 | Tunnel scope | Forwarded ports and reverse proxy/model tunnels bind loopback, detect collisions, clean up, and cannot be used by another guest. |
| T-23 | Local models | Resolved endpoint reaches the intended host-loopback server; scheme/path and verification remain correct; no hard-coded Lima hostname is used. |
| T-24 | Editor/interactive I/O | Generated SSH entries use pins; terminal resize, stdin, exit codes, cancellation, and noninteractive exec behave correctly. |
| T-25 | Logs/diagnostics | Boot failure is diagnosable without a functioning SSH service; output is bounded, restricted, and secret-redacted. |
| T-26 | Runtime drift | Deleted network, altered home/agent policy, unknown schema, or changed effective attachment closes the gate on subsequent operations. |
| T-27 | Service restart | Machine state/identity/policy is reconciled; stale sessions are not reused; no policy defaults silently reappear. |
| T-28 | Update/uninstall | Feature build cannot update to a Lima artifact; uninstall/purge never deletes foreign backend/runtime resources. |
| T-29 | Concurrency/endurance | Parallel create/start/stop operations use correct locks; repeated cycles leave no unintended networks, machines, or proxy processes. |
| T-30 | Default-backend regression | Existing Lima/Firecracker CLI behavior, profiles, state, SSH options, and integration suites remain unchanged. |

Use a loopback test service and synthetic canary credentials for transport/proxy tests. Production upstream-host restrictions must not be relaxed merely to enable a mock; introduce any test-only dependency injection below the policy boundary. Do not require paid agent API calls for the default test suite.

### Build checks

Run on macOS, after the feature implementation exists:

```bash
cargo fmt --all -- --check
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

cargo build --workspace --release --features apple-container
cargo test --workspace --features apple-container
cargo clippy --workspace --all-targets --features apple-container -- -D warnings
```

Run the existing default Linux checks separately, plus the expected-negative feature build test. Add proposed integration scripts for runtime contract, secure lifecycle, and security qualification; those scripts do not exist merely because they are named here.

## 16. Optional follow-on: remove guest Docker

This is a separate capability/profile change, not part of the Apple backend's definition of done. Current `required_guest_binaries()` includes `/usr/bin/docker`, and guest provisioning exposes Docker-specific installation support. [C3]

A Docker-free guest mode would:

1. Make Docker installation and required-binary/service validation explicitly profile/capability-dependent across both existing backends and Apple.
2. Audit profile scripts, devcontainer support, agent instructions, and integration tests for unconditional Docker use.
3. Reject Docker-dependent workflows clearly in that mode while keeping a compatibility profile available.
4. Prove that image setup, basic agents, workspace operations, and selected development tools work without any guest Docker binary or daemon.

It MUST NOT replace guest Docker with unrestricted remote access to the host Container daemon, XPC service, or a privileged host command proxy. A future restricted host execution service would require its own API and threat-model specification.

## 17. Release gates and unresolved validation items

### 17.1 Release gates

The following are all mandatory:

- [x] The exact runtime build supports and enforces dedicated machine networks and disabled SSH-agent forwarding.
- [ ] Real-hardware isolation, host-exposure, SSH pin, failure-recovery, and default-backend regression tests pass.
- [x] Credentials and project data cannot cross before secure readiness.
- [x] Explicitly unsupported capabilities fail without side effects and are documented.
- [x] Image provenance, backend-owned state, feature-preserving installation, and rollback are documented.
- [x] No code relies on undocumented Apple disk paths, a Docker-compatible API, or unqualified future CLI behavior.

### 17.2 Items requiring implementation-time evidence

| Item | Decision already fixed | Evidence still required |
|---|---|---|
| Network enforcement | Must be outside the guest; one network per instance is the selected design. | Actual cross-network L2/L3/IPv6 behavior on the target OS/runtime; additional enforcement if needed. |
| Runtime extension | Required for shipping; stock runtime is not silently accepted. | Upstream acceptance or a reviewed, distributable pinned build and support process. |
| SSH-agent disablement | Explicit runtime disable plus sanitized child environment. | No usable socket after normal boot, service restart, or adverse inherited environment. |
| Native bootstrap commands | Fixed root commands only, bounded and ownership-addressed. | First-boot timing, exit-code, stdout, and retry behavior in real fixtures. |
| Systemd/guest Docker | Retain existing guest functionality. | Service readiness and Docker networking with the qualified kernel. |
| Resource/disk reporting | CPU/memory supported; disk resize/snapshots unsupported. | Unit conversion and honest distinctions among guest capacity and runtime storage metrics. |
| Performance | Measure without weakening security. | Published results with hardware, OS, runtime, workload, and cache state. |

These items are validation work, not evidence that testing has already occurred. The implementation must preserve the blocked state when evidence is missing rather than infer success from the architecture.

### 17.3 Qualification evidence (2026-09-25)

Runtime `1.4.1+coop.83b256f` (fork `vendor/container`; the full coop checks ran on the preceding `707eb44`), macOS 27.0, Apple Silicon. Results are recorded in `docs/backends.md` ("Supported combinations", "Validation status"): fork machine and cross-network isolation tests, coop end-to-end lifecycle, credential/proxy/host-exposure checks with synthetic credentials, service restart, SIGKILL at every journaled stage, and 30 sequential plus concurrent lifecycles without leaks. The stock-runtime contract (`tests/apple-container-contract.sh`) passes against Homebrew 1.4.1. The default Lima backend's integration suite passes on macOS except three `ssh <alias>` checks, which fail because the run used a scratch `HOME` that OpenSSH ignores when locating `~/.ssh/config`; the same alias connects with `ssh -F <scratch config>`. Still open: the Firecracker integration suite on Linux, which requires a remote Linux/KVM host.

## 18. Source registry

Sources were inspected on 2026-09-25. Coop code references are pinned to the source baseline; Apple code/documentation references use tag `1.4.1`. Issue #291 is historical, mutable context. The release API check identified 1.4.1 when preparing this document. Revalidate sources and capture executable fixtures before coding against a different revision.

| Reference | Source and relevance |
|---|---|
| [C1] | Coop architecture: compile-time backend selection, shared operations, lifecycle dispatch, and file layout. |
| [C2] | Coop backend source: `VmBackend`, capabilities requiring adaptation, proof types, and SSH transport construction. |
| [C3] | Coop guest source: configured guest identity, required tools, and guest provisioning constants. |
| [C4] | Coop trust model: VM boundary, guest sudo, host/guest secrets, network isolation, proxy and forwarding rules. |
| [C5] | Coop lifecycle source: disk-path coupling and lifecycle/storage command behavior. |
| [C6] | Coop issue #291: earlier Apple machine feasibility investigation and reported prototype results. |
| [A0] | Apple Container 1.4.1 release; baseline runtime version. |
| [A1] | Apple machine guide: OCI/systemd image pattern and custom first-boot account hook. |
| [A2] | Apple `MachineCreate.swift`: current creation flags and configuration handling. |
| [A3] | Apple machine management flags: platform options, not ordinary-container network/mount options. |
| [A4] | Apple `MachineInspect.swift`: actual JSON array/output fields. |
| [A5] | Apple `MachineRun.swift`: root/native execution and process-I/O options. |
| [A6] | Apple `MachineHelpers.swift`: boot helper and inherited `SSH_AUTH_SOCK`. |
| [A7] | Apple `MachinesService.swift`: lifecycle, fresh underlying IDs, effective mounts, default network, and SSH-agent enablement. |
| [A8] | Apple networking guide: default network reachability and separate network support. |

[C1]: https://github.com/trailofbits/coop/blob/338228c44977ed4c408ae7c83d79f2e03f60693c/docs/ARCHITECTURE.md
[C2]: https://github.com/trailofbits/coop/blob/338228c44977ed4c408ae7c83d79f2e03f60693c/src/backend.rs
[C3]: https://github.com/trailofbits/coop/blob/338228c44977ed4c408ae7c83d79f2e03f60693c/src/guest.rs
[C4]: https://github.com/trailofbits/coop/blob/338228c44977ed4c408ae7c83d79f2e03f60693c/docs/trust-model.md
[C5]: https://github.com/trailofbits/coop/blob/338228c44977ed4c408ae7c83d79f2e03f60693c/src/commands/lifecycle.rs
[C6]: https://github.com/trailofbits/coop/issues/291
[A0]: https://github.com/apple/container/releases/tag/1.4.1
[A1]: https://github.com/apple/container/blob/1.4.1/docs/container-machine.md
[A2]: https://github.com/apple/container/blob/1.4.1/Sources/ContainerCommands/Machine/MachineCreate.swift
[A3]: https://github.com/apple/container/blob/1.4.1/Sources/Services/MachineAPIService/Client/Flags.swift
[A4]: https://github.com/apple/container/blob/1.4.1/Sources/ContainerCommands/Machine/MachineInspect.swift
[A5]: https://github.com/apple/container/blob/1.4.1/Sources/ContainerCommands/Machine/MachineRun.swift
[A6]: https://github.com/apple/container/blob/1.4.1/Sources/ContainerCommands/Machine/MachineHelpers.swift
[A7]: https://github.com/apple/container/blob/1.4.1/Sources/Services/MachineAPIService/Server/MachinesService.swift
[A8]: https://github.com/apple/container/blob/1.4.1/docs/networking.md
