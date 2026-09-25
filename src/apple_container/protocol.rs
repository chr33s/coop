//! Versioned parsers for Apple `container` CLI output.
//!
//! Shapes come from the pinned runtime source (tag `1.4.1`): `machine inspect`
//! prints a JSON array of `InspectOutput`, `machine list --format json` an
//! array of `PrintableMachine`, and `inspect <container>` an array of
//! `ManagedContainer`. Unknown non-security fields are ignored; unknown status
//! values, missing security fields, malformed addresses, and ID mismatches are
//! errors. Parsed values are normalized into the records below — raw runtime
//! JSON is never persisted.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::AppleError;
use super::state::MachineName;

/// `RuntimeStatus` from the runtime. Any other string is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachineStatus {
    Unknown,
    Stopped,
    Running,
    Stopping,
}

impl MachineStatus {
    fn parse(raw: &str) -> Result<Self> {
        Ok(match raw {
            "unknown" => Self::Unknown,
            "stopped" => Self::Stopped,
            "running" => Self::Running,
            "stopping" => Self::Stopping,
            other => bail!(AppleError::RuntimeUnqualified(format!(
                "unrecognised machine status {other:?}"
            ))),
        })
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Stopping => "stopping",
        }
    }
}

/// `MachineConfig.HomeMountOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HomeMount {
    ReadOnly,
    ReadWrite,
    None,
}

impl HomeMount {
    fn parse(raw: &str) -> Result<Self> {
        Ok(match raw {
            "ro" => Self::ReadOnly,
            "rw" => Self::ReadWrite,
            "none" => Self::None,
            other => bail!(AppleError::RuntimeUnqualified(format!(
                "unrecognised homeMount value {other:?}"
            ))),
        })
    }
}

/// Isolation policy a qualified runtime reports for a machine. These fields
/// come from the runtime extension coop requires (a per-machine network and an
/// explicit SSH-agent switch); stock 1.4.1 does not emit them, so their
/// absence is how an unqualified runtime is detected per machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachinePolicy {
    /// Selected network; `None` is the runtime's built-in shared network,
    /// which the extension reports by omitting `network`.
    pub(crate) network: Option<String>,
    pub(crate) ssh_agent_forwarding: bool,
}

/// A validated `machine inspect` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MachineRecord {
    pub(crate) id: MachineName,
    pub(crate) status: MachineStatus,
    pub(crate) container_id: Option<String>,
    pub(crate) ip: Option<Ipv4Addr>,
    pub(crate) home_mount: HomeMount,
    pub(crate) cpus: u32,
    pub(crate) memory_bytes: u64,
    pub(crate) policy: Option<MachinePolicy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMachine {
    id: String,
    status: String,
    container_id: Option<String>,
    ip_address: Option<String>,
    home_mount: String,
    cpus: i64,
    memory: u64,
    // Runtime-extension fields (see [`MachinePolicy`]).
    network: Option<String>,
    ssh_agent_forwarding: Option<bool>,
}

/// Parse `container machine inspect <expected>` output: an array holding
/// exactly one record whose `id` is `expected`.
pub(crate) fn parse_machine_inspect(json: &str, expected: &MachineName) -> Result<MachineRecord> {
    let raw: Vec<RawMachine> = serde_json::from_str(json)
        .map_err(|e| AppleError::RuntimeUnqualified(format!("machine inspect output: {e}")))?;
    let [only] = <[RawMachine; 1]>::try_from(raw).map_err(|v| {
        AppleError::RuntimeUnqualified(format!(
            "machine inspect returned {} records, expected exactly 1",
            v.len()
        ))
    })?;
    if only.id != expected.as_str() {
        bail!(AppleError::IdentityConflict(format!(
            "machine inspect for {expected} returned record {:?}",
            only.id
        )));
    }
    let ip = only
        .ip_address
        .as_deref()
        .map(|addr| {
            addr.parse::<Ipv4Addr>().map_err(|_| {
                AppleError::RuntimeUnqualified(format!("malformed machine ipAddress {addr:?}"))
            })
        })
        .transpose()?;
    let cpus = u32::try_from(only.cpus)
        .ok()
        .filter(|&c| c > 0)
        .with_context(|| format!("invalid machine cpu count {}", only.cpus))?;
    if only.memory == 0 {
        bail!("machine reports zero memory");
    }
    // `sshAgentForwarding` marks an extended runtime; `network` is then
    // omitted only for the built-in network.
    let policy = match (only.network, only.ssh_agent_forwarding) {
        (network, Some(ssh_agent_forwarding)) => Some(MachinePolicy {
            network,
            ssh_agent_forwarding,
        }),
        (None, None) => None,
        (Some(_), None) => bail!(AppleError::RuntimeUnqualified(
            "machine inspect reports only part of the network/SSH-agent policy".into()
        )),
    };
    if let Some(cid) = &only.container_id {
        validate_runtime_id(cid)?;
    }
    Ok(MachineRecord {
        id: expected.clone(),
        status: MachineStatus::parse(&only.status)?,
        container_id: only.container_id,
        ip,
        home_mount: HomeMount::parse(&only.home_mount)?,
        cpus,
        memory_bytes: only.memory,
        policy,
    })
}

#[derive(Deserialize)]
struct RawListed {
    id: String,
    status: String,
}

/// One row of `container machine list --format json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedMachine {
    pub(crate) id: String,
    pub(crate) status: MachineStatus,
}

pub(crate) fn parse_machine_list(json: &str) -> Result<Vec<ListedMachine>> {
    let raw: Vec<RawListed> = serde_json::from_str(json)
        .map_err(|e| AppleError::RuntimeUnqualified(format!("machine list output: {e}")))?;
    let mut seen = std::collections::HashSet::new();
    raw.into_iter()
        .map(|r| {
            if !seen.insert(r.id.clone()) {
                bail!(AppleError::RuntimeUnqualified(format!(
                    "machine list reports {:?} twice",
                    r.id
                )));
            }
            Ok(ListedMachine {
                status: MachineStatus::parse(&r.status)?,
                id: r.id,
            })
        })
        .collect()
}

/// A mount on a machine's backing container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountRecord {
    pub(crate) source: String,
    pub(crate) destination: String,
    pub(crate) options: Vec<String>,
}

/// The effective configuration of a machine's current backing container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerRecord {
    pub(crate) id: String,
    pub(crate) mounts: Vec<MountRecord>,
    /// Networks the container was configured to join.
    pub(crate) configured_networks: Vec<String>,
    /// Networks the running sandbox is actually attached to.
    pub(crate) attached_networks: Vec<String>,
    /// Whether host SSH-agent socket forwarding is enabled.
    pub(crate) ssh_agent_forwarding: bool,
}

#[derive(Deserialize)]
struct RawContainer {
    configuration: RawContainerConfig,
    status: RawContainerStatus,
}

#[derive(Deserialize)]
struct RawContainerConfig {
    id: String,
    #[serde(default)]
    mounts: Vec<RawMount>,
    #[serde(default)]
    networks: Vec<RawNetworkRef>,
    ssh: bool,
    #[serde(default, rename = "publishedPorts")]
    published_ports: Vec<serde_json::Value>,
    #[serde(default, rename = "publishedSockets")]
    published_sockets: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawMount {
    source: String,
    destination: String,
    #[serde(default)]
    options: Vec<String>,
}

#[derive(Deserialize)]
struct RawNetworkRef {
    network: String,
}

#[derive(Deserialize)]
struct RawContainerStatus {
    #[serde(default)]
    networks: Vec<RawNetworkRef>,
}

/// Parse `container inspect <expected>` output for a machine's backing
/// container. Published ports or sockets are rejected outright: coop never
/// requests them, and each would be a host-side listener the guest controls.
pub(crate) fn parse_container_inspect(json: &str, expected: &str) -> Result<ContainerRecord> {
    let raw: Vec<RawContainer> = serde_json::from_str(json)
        .map_err(|e| AppleError::RuntimeUnqualified(format!("container inspect output: {e}")))?;
    let [only] = <[RawContainer; 1]>::try_from(raw).map_err(|v| {
        AppleError::RuntimeUnqualified(format!(
            "container inspect returned {} records, expected exactly 1",
            v.len()
        ))
    })?;
    if only.configuration.id != expected {
        bail!(AppleError::IdentityConflict(format!(
            "container inspect for {expected} returned {:?}",
            only.configuration.id
        )));
    }
    if !only.configuration.published_ports.is_empty()
        || !only.configuration.published_sockets.is_empty()
    {
        bail!(AppleError::HostExposure(format!(
            "backing container {expected} publishes host ports or sockets"
        )));
    }
    Ok(ContainerRecord {
        id: only.configuration.id,
        mounts: only
            .configuration
            .mounts
            .into_iter()
            .map(|m| MountRecord {
                source: m.source,
                destination: m.destination,
                options: m.options,
            })
            .collect(),
        configured_networks: only
            .configuration
            .networks
            .into_iter()
            .map(|n| n.network)
            .collect(),
        attached_networks: only
            .status
            .networks
            .into_iter()
            .map(|n| n.network)
            .collect(),
        ssh_agent_forwarding: only.configuration.ssh,
    })
}

#[derive(Deserialize)]
struct RawNetwork {
    id: String,
}

/// IDs from `container network list --format json`, rejecting duplicates.
pub(crate) fn parse_network_list(json: &str) -> Result<Vec<String>> {
    let raw: Vec<RawNetwork> = serde_json::from_str(json)
        .map_err(|e| AppleError::RuntimeUnqualified(format!("network list output: {e}")))?;
    let mut seen = std::collections::HashSet::new();
    raw.into_iter()
        .map(|n| {
            if !seen.insert(n.id.clone()) {
                bail!(AppleError::RuntimeUnqualified(format!(
                    "network list reports {:?} twice",
                    n.id
                )));
            }
            Ok(n.id)
        })
        .collect()
}

/// Runtime-generated identifiers (container IDs) are lowercase UUID-ish
/// tokens. Reject anything else before it is used as an argument.
fn validate_runtime_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.'
        });
    if !ok {
        bail!(AppleError::RuntimeUnqualified(format!(
            "malformed runtime identifier {id:?}"
        )));
    }
    Ok(())
}

/// `container --version` → the full identity line and the semantic version.
pub(crate) fn parse_version(text: &str) -> Result<(String, semver::Version)> {
    let line = text.lines().next().unwrap_or_default().trim();
    let version = line
        .strip_prefix("container CLI version ")
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|v| semver::Version::parse(v).ok())
        .ok_or_else(|| {
            AppleError::RuntimeUnqualified(format!("unrecognised version output {line:?}"))
        })?;
    Ok((line.to_string(), version))
}

/// Flags advertised by `container machine create --help`.
pub(crate) fn help_lists_flag(help: &str, flag: &str) -> bool {
    help.lines().any(|line| {
        line.split(|c: char| c.is_whitespace() || c == ',')
            .any(|token| token == flag)
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/apple-container"
    );

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
    }

    fn machine() -> MachineName {
        MachineName::new("coop-0a1b2c3d-00112233445566ff").unwrap()
    }

    #[test]
    fn stock_inspect_parses_without_policy() {
        let rec =
            parse_machine_inspect(&fixture("machine-inspect-1.4.1.json"), &machine()).unwrap();
        assert_eq!(rec.status, MachineStatus::Running);
        assert_eq!(rec.ip, Some(Ipv4Addr::new(192, 168, 64, 3)));
        assert_eq!(rec.home_mount, HomeMount::None);
        assert_eq!(rec.cpus, 4);
        assert_eq!(rec.memory_bytes, 4096 * 1024 * 1024);
        assert_eq!(rec.policy, None);
    }

    #[test]
    fn extended_inspect_reports_policy() {
        let rec =
            parse_machine_inspect(&fixture("machine-inspect-extended.json"), &machine()).unwrap();
        assert_eq!(
            rec.policy,
            Some(MachinePolicy {
                network: Some("coop-0a1b2c3d-00112233445566ff".into()),
                ssh_agent_forwarding: false,
            })
        );
        assert_eq!(rec.status, MachineStatus::Stopped);
        assert_eq!(rec.ip, None);
    }

    #[test]
    fn inspect_rejects_malformed_shapes() {
        let good = fixture("machine-inspect-1.4.1.json");
        let m = machine();
        assert!(parse_machine_inspect("[]", &m).is_err());
        assert!(parse_machine_inspect("{}", &m).is_err());
        let dup = format!(
            "[{0},{0}]",
            good.trim().trim_start_matches('[').trim_end_matches(']')
        );
        assert!(parse_machine_inspect(&dup, &m).is_err());
        let other = MachineName::new("coop-0a1b2c3d-ffffffffffffffff").unwrap();
        let err = parse_machine_inspect(&good, &other).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::IdentityConflict(_))
        ));
        for (from, to) in [
            ("\"running\"", "\"paused\""),
            ("\"192.168.64.3\"", "\"192.168.64.3/24\""),
            ("\"homeMount\" : \"none\"", "\"homeMount\" : \"everything\""),
            (
                "\"containerId\" : \"a1b2c3d4-e5f6\"",
                "\"containerId\" : \"$(reboot)\"",
            ),
        ] {
            assert!(good.contains(from), "fixture lacks {from}");
            let bad = good.replace(from, to);
            assert!(parse_machine_inspect(&bad, &m).is_err(), "accepted {to}");
        }
        let partial =
            fixture("machine-inspect-extended.json").replace("\"sshAgentForwarding\" : false,", "");
        assert!(parse_machine_inspect(&partial, &m).is_err());
    }

    #[test]
    fn extended_inspect_without_network_is_the_builtin_network() {
        let json = fixture("machine-inspect-extended.json")
            .replace("\"network\" : \"coop-0a1b2c3d-00112233445566ff\",", "");
        let rec = parse_machine_inspect(&json, &machine()).unwrap();
        assert_eq!(
            rec.policy,
            Some(MachinePolicy {
                network: None,
                ssh_agent_forwarding: false,
            })
        );
    }

    #[test]
    fn list_rejects_duplicates_and_unknown_status() {
        let listed = parse_machine_list(&fixture("machine-list-1.4.1.json")).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(
            parse_machine_list(r#"[{"id":"a","status":"running"},{"id":"a","status":"stopped"}]"#)
                .is_err()
        );
        assert!(parse_machine_list(r#"[{"id":"a","status":"exploded"}]"#).is_err());
    }

    #[test]
    fn container_inspect_extracts_mounts_networks_and_agent() {
        let rec =
            parse_container_inspect(&fixture("container-inspect-1.4.1.json"), "a1b2c3d4-e5f6")
                .unwrap();
        assert!(rec.ssh_agent_forwarding);
        assert_eq!(rec.configured_networks, ["default"]);
        assert_eq!(rec.attached_networks, ["default"]);
        assert_eq!(rec.mounts.len(), 3);
        assert!(
            parse_container_inspect(&fixture("container-inspect-1.4.1.json"), "other").is_err()
        );
    }

    #[test]
    fn container_inspect_rejects_published_ports() {
        let json = fixture("container-inspect-1.4.1.json").replace(
            "\"publishedPorts\" : [ ]",
            "\"publishedPorts\" : [ {\"hostPort\": 22} ]",
        );
        let err = parse_container_inspect(&json, "a1b2c3d4-e5f6").unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::HostExposure(_))
        ));
    }

    #[test]
    fn version_and_help_parsing() {
        let (line, v) = parse_version(&fixture("version-1.4.1.txt")).unwrap();
        assert_eq!(v, semver::Version::new(1, 4, 1));
        assert!(line.starts_with("container CLI version 1.4.1"));
        assert!(parse_version("docker version 27").is_err());
        let help = fixture("machine-create-help-1.4.1.txt");
        assert!(help_lists_flag(&help, "--home-mount"));
        assert!(help_lists_flag(&help, "--no-boot"));
        assert!(!help_lists_flag(&help, "--network"));
        assert!(!help_lists_flag(&help, "--no-ssh-agent"));

        let (line, v) = parse_version(&fixture("version-coop-fdddb59.txt")).unwrap();
        assert_eq!(v, "1.4.1+coop.fdddb59".parse::<semver::Version>().unwrap());
        assert!(line.contains("commit: fdddb59"));
        let help = fixture("machine-create-help-coop-fdddb59.txt");
        for flag in [
            "--network",
            "--no-ssh-agent",
            "--home-mount",
            "--no-boot",
            "--progress",
        ] {
            assert!(help_lists_flag(&help, flag), "{flag}");
        }
    }

    #[test]
    fn network_list_parses_ids_and_rejects_duplicates() {
        let ids =
            parse_network_list(r#"[{"id":"default","state":"running"},{"id":"coop-x"}]"#).unwrap();
        assert_eq!(ids, ["default", "coop-x"]);
        assert!(parse_network_list("[]").unwrap().is_empty());
        assert!(parse_network_list(r#"[{"id":"a"},{"id":"a"}]"#).is_err());
        assert!(parse_network_list("not json").is_err());
    }
}
