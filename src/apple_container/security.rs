//! Runtime qualification and the isolation gate.
//!
//! Stock Apple Container 1.4.1 attaches every machine to the built-in shared
//! network and forwards the caller's SSH agent into it. coop therefore
//! requires a runtime extension (a per-machine `--network` and
//! `--no-ssh-agent`, reported back by `machine inspect`), provided by the
//! fork vendored at `vendor/container`, and fails closed without it. No flag or config key relaxes these checks.

use anyhow::{Result, bail};

use super::AppleError;
use super::protocol::{ContainerRecord, HomeMount, MachineRecord, MachineStatus};
use super::state::{MachineName, NetworkName};

/// Mounts the runtime itself adds to every machine and that are allowed to
/// exist, as (guest destination, file name inside the machine's own runtime
/// bundle, required mode): a read-only helper directory holding the machine
/// init binary, and a writable first-boot marker file. The source must be
/// exactly `…/machines/<machine-id>/<file name>`, so a host directory mounted
/// at an allowed destination still fails. Anything else — the host home, a
/// workspace, a socket — fails the gate.
const RUNTIME_BOOTSTRAP_MOUNTS: &[(&str, &str, &str)] = &[
    ("/sbin.machine", "sbin.machine", "ro"),
    ("/etc/.machine.initialized", "machine.initialized", "rw"),
];

/// Whether `source` is `<abs>/machines/<machine>/<file>` with no `.`/`..`
/// components.
fn is_bundle_path(source: &str, machine: &MachineName, file: &str) -> bool {
    use std::path::Component;
    let path = std::path::Path::new(source);
    let normal = path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
    let tail: Vec<&str> = source.rsplitn(4, '/').collect();
    normal
        && tail.len() == 4
        && tail[0] == file
        && tail[1] == machine.as_str()
        && tail[2] == "machines"
}

/// What `qualify` learned about the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QualifiedRuntime {
    /// Full `container --version` line, recorded for diagnostics.
    pub(crate) identity: String,
}

/// Oldest runtime whose machine CLI and JSON schema the parsers were written
/// against.
const MIN_VERSION: semver::Version = semver::Version::new(1, 4, 1);

/// Decide from `container --version` and `container machine create --help`
/// output whether the runtime can run coop machines safely. Version alone is
/// not proof: the required isolation flags must be advertised too.
pub(crate) fn qualify(version_text: &str, create_help: &str) -> Result<QualifiedRuntime> {
    let (identity, version) = super::protocol::parse_version(version_text)?;
    if version < MIN_VERSION {
        bail!(AppleError::RuntimeUnqualified(format!(
            "{identity} is older than the minimum supported {MIN_VERSION}"
        )));
    }
    let missing: Vec<&str> = ["--network", "--no-ssh-agent", "--home-mount", "--no-boot"]
        .into_iter()
        .filter(|flag| !super::protocol::help_lists_flag(create_help, flag))
        .collect();
    if !missing.is_empty() {
        bail!(AppleError::RuntimeUnqualified(format!(
            "{identity} lacks the per-machine isolation controls coop requires \
             (`container machine create` has no {}). Stock Apple Container attaches \
             every machine to one shared network and forwards the host SSH agent, \
             so coop will not start agents, copy workspaces, or pass credentials on \
             it. A runtime build with the machine network/SSH-agent extension is \
             required; see docs/backends.md.",
            missing.join(", ")
        )));
    }
    Ok(QualifiedRuntime { identity })
}

/// Pre-boot check of a machine's persisted configuration.
pub(crate) fn verify_machine_config(record: &MachineRecord, network: &NetworkName) -> Result<()> {
    if record.home_mount != HomeMount::None {
        bail!(AppleError::HostExposure(format!(
            "machine {} would mount the host home directory",
            record.id
        )));
    }
    let Some(policy) = &record.policy else {
        bail!(AppleError::RuntimeUnqualified(format!(
            "machine {} does not report its network/SSH-agent policy",
            record.id
        )));
    };
    if policy.ssh_agent_forwarding {
        bail!(AppleError::HostExposure(format!(
            "machine {} has host SSH-agent forwarding enabled",
            record.id
        )));
    }
    if policy.network.as_deref() != Some(network.as_str()) {
        let configured = policy.network.as_deref().map_or_else(
            || "the built-in network".to_owned(),
            |n| format!("network {n:?}"),
        );
        bail!(AppleError::NetworkIsolation(format!(
            "machine {} is configured for {configured}, expected its dedicated network {network}",
            record.id
        )));
    }
    Ok(())
}

/// Process-local proof that a machine's *current* backing container passed the
/// isolation gate: dedicated network only, no SSH-agent forwarding, and only
/// the runtime's own bootstrap mounts. Fields are private and it is neither
/// serializable nor cloneable, so it cannot be persisted or forged; it is
/// re-established after every boot and before every SSH target is handed out.
#[derive(Debug)]
pub(crate) struct SecurityReady {
    machine: MachineName,
    container_id: String,
}

impl SecurityReady {
    pub(crate) fn machine(&self) -> &MachineName {
        &self.machine
    }

    pub(crate) fn container_id(&self) -> &str {
        &self.container_id
    }
}

/// Post-boot check of the effective runtime state. `record` must be a fresh
/// inspection showing the machine running on `container.id`.
pub(crate) fn verify_effective(
    record: &MachineRecord,
    container: &ContainerRecord,
    network: &NetworkName,
) -> Result<SecurityReady> {
    verify_machine_config(record, network)?;
    if record.status != MachineStatus::Running {
        bail!(AppleError::OperationUncertain(format!(
            "machine {} is {}, not running",
            record.id,
            record.status.label()
        )));
    }
    // The runtime names each boot's container `<machine>-<suffix>`.
    let owned_container = container
        .id
        .strip_prefix(record.id.as_str())
        .is_some_and(|rest| rest.starts_with('-'));
    if !owned_container || record.container_id.as_deref() != Some(container.id.as_str()) {
        bail!(AppleError::IdentityConflict(format!(
            "machine {} is backed by {:?}, but the inspected container is {}",
            record.id, record.container_id, container.id
        )));
    }
    if container.ssh_agent_forwarding {
        bail!(AppleError::HostExposure(format!(
            "backing container {} forwards the host SSH agent",
            container.id
        )));
    }
    let only_dedicated =
        |nets: &[String]| nets.len() == 1 && nets.first().is_some_and(|n| n == network.as_str());
    if !only_dedicated(&container.configured_networks)
        || !only_dedicated(&container.attached_networks)
    {
        bail!(AppleError::NetworkIsolation(format!(
            "backing container {} is attached to {:?} (configured {:?}); expected only {network}",
            container.id, container.attached_networks, container.configured_networks
        )));
    }
    for mount in &container.mounts {
        let allowed = RUNTIME_BOOTSTRAP_MOUNTS.iter().any(|(dest, file, mode)| {
            mount.destination == *dest
                && is_bundle_path(&mount.source, &record.id, file)
                && mount.options.iter().any(|o| o == mode)
                && (*mode == "rw" || !mount.options.iter().any(|o| o == "rw"))
        });
        if !allowed {
            bail!(AppleError::HostExposure(format!(
                "backing container {} mounts host path at {} ({:?}); only the runtime's \
                 bootstrap mounts are allowed",
                container.id,
                super::cli::sanitize_for_display(&mount.destination),
                mount.options
            )));
        }
    }
    Ok(SecurityReady {
        machine: record.id.clone(),
        container_id: container.id.clone(),
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::apple_container::protocol::{MachinePolicy, MountRecord};

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/apple-container"
    );

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
    }

    fn net() -> NetworkName {
        NetworkName::new("coop-0a1b2c3d-00112233445566ff").unwrap()
    }

    fn record() -> MachineRecord {
        MachineRecord {
            id: net(),
            status: MachineStatus::Running,
            container_id: Some("coop-0a1b2c3d-00112233445566ff-abc123".into()),
            ip: Some(std::net::Ipv4Addr::new(192, 168, 70, 2)),
            home_mount: HomeMount::None,
            cpus: 2,
            memory_bytes: 1 << 32,
            policy: Some(MachinePolicy {
                network: Some(net().to_string()),
                ssh_agent_forwarding: false,
            }),
        }
    }

    fn container() -> ContainerRecord {
        ContainerRecord {
            id: "coop-0a1b2c3d-00112233445566ff-abc123".into(),
            mounts: vec![
                MountRecord {
                    source: "/Users/u/Library/Application Support/com.apple.container/machines/coop-0a1b2c3d-00112233445566ff/sbin.machine".into(),
                    destination: "/sbin.machine".into(),
                    options: vec!["ro".into()],
                },
                MountRecord {
                    source: "/Users/u/Library/Application Support/com.apple.container/machines/coop-0a1b2c3d-00112233445566ff/machine.initialized".into(),
                    destination: "/etc/.machine.initialized".into(),
                    options: vec!["rw".into()],
                },
            ],
            configured_networks: vec![net().to_string()],
            attached_networks: vec![net().to_string()],
            ssh_agent_forwarding: false,
        }
    }

    fn kind(err: &anyhow::Error) -> &AppleError {
        err.downcast_ref::<AppleError>().unwrap()
    }

    #[test]
    fn stock_runtime_is_unqualified() {
        let err = qualify(
            &fixture("version-1.4.1.txt"),
            &fixture("machine-create-help-1.4.1.txt"),
        )
        .unwrap_err();
        assert!(matches!(kind(&err), AppleError::RuntimeUnqualified(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("--network") && msg.contains("--no-ssh-agent"),
            "{msg}"
        );
    }

    #[test]
    fn extended_runtime_qualifies() {
        let q = qualify(
            &fixture("version-coop-fdddb59.txt"),
            &fixture("machine-create-help-coop-fdddb59.txt"),
        )
        .unwrap();
        assert!(q.identity.contains("1.4.1+coop.fdddb59"));
        let help = fixture("machine-create-help-coop-fdddb59.txt");
        assert!(qualify("container CLI version 1.3.0 (build: release)", &help).is_err());
    }

    #[test]
    fn gate_accepts_only_the_expected_shape() {
        let ready = verify_effective(&record(), &container(), &net()).unwrap();
        assert_eq!(
            ready.container_id(),
            "coop-0a1b2c3d-00112233445566ff-abc123"
        );
        assert_eq!(ready.machine(), &net());
    }

    #[test]
    fn gate_rejects_home_agent_network_and_mount_exposure() {
        let mut r = record();
        r.home_mount = HomeMount::ReadOnly;
        assert!(matches!(
            kind(&verify_machine_config(&r, &net()).unwrap_err()),
            AppleError::HostExposure(_)
        ));

        let mut r = record();
        r.policy = None;
        assert!(matches!(
            kind(&verify_machine_config(&r, &net()).unwrap_err()),
            AppleError::RuntimeUnqualified(_)
        ));

        for network in [Some("default".to_owned()), None] {
            let mut r = record();
            r.policy = Some(MachinePolicy {
                network,
                ssh_agent_forwarding: false,
            });
            assert!(matches!(
                kind(&verify_machine_config(&r, &net()).unwrap_err()),
                AppleError::NetworkIsolation(_)
            ));
        }

        let mut c = container();
        c.ssh_agent_forwarding = true;
        assert!(matches!(
            kind(&verify_effective(&record(), &c, &net()).unwrap_err()),
            AppleError::HostExposure(_)
        ));

        let mut c = container();
        c.attached_networks.push("default".into());
        assert!(matches!(
            kind(&verify_effective(&record(), &c, &net()).unwrap_err()),
            AppleError::NetworkIsolation(_)
        ));

        let mut c = container();
        c.mounts.push(MountRecord {
            source: "/Users/me".into(),
            destination: "/Users/me".into(),
            options: vec!["ro".into()],
        });
        assert!(matches!(
            kind(&verify_effective(&record(), &c, &net()).unwrap_err()),
            AppleError::HostExposure(_)
        ));

        // A host directory at an allowed destination is still exposure.
        for bad_source in [
            "/Users/me",
            "/Users/u/machines/other-machine/machine.initialized",
            "/x/machines/coop-0a1b2c3d-00112233445566ff/../../../Users/me/machine.initialized",
            "machines/coop-0a1b2c3d-00112233445566ff/machine.initialized",
        ] {
            let mut c = container();
            c.mounts[1].source = bad_source.into();
            assert!(
                matches!(
                    kind(&verify_effective(&record(), &c, &net()).unwrap_err()),
                    AppleError::HostExposure(_)
                ),
                "{bad_source}"
            );
        }

        // A container that is not this machine's boot is not trusted.
        let mut r = record();
        let mut c = container();
        r.container_id = Some("foreign-container".into());
        c.id = "foreign-container".into();
        assert!(verify_effective(&r, &c, &net()).is_err());

        // The helper directory must stay read-only.
        let mut c = container();
        c.mounts[0].options = vec!["rw".into()];
        assert!(verify_effective(&record(), &c, &net()).is_err());

        // A stale container id (restart raced the inspection) is not ready.
        let mut c = container();
        c.id = "coop-0a1b2c3d-00112233445566ff-000000".into();
        assert!(matches!(
            kind(&verify_effective(&record(), &c, &net()).unwrap_err()),
            AppleError::IdentityConflict(_)
        ));

        let mut r = record();
        r.status = MachineStatus::Stopping;
        assert!(verify_effective(&r, &container(), &net()).is_err());
    }

    #[test]
    fn stock_default_machine_fails_every_gate() {
        let c = crate::apple_container::protocol::parse_container_inspect(
            &fixture("container-inspect-1.4.1.json"),
            "a1b2c3d4-e5f6",
        )
        .unwrap();
        let mut r = record();
        r.container_id = Some(c.id.clone());
        assert!(verify_effective(&r, &c, &net()).is_err());
    }
}
