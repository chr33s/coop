//! Backend-owned persistent state: ownership, per-instance machine records,
//! and the mutation journal.
//!
//! Everything here is versioned serde data written atomically with owner-only
//! permissions. Records hold identities and observations only — never tokens,
//! agent sockets, environment dumps, private host keys, or a "security ready"
//! flag (that proof is process-local; see `security::SecurityReady`).

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::AppleError;
use crate::config::{CoopConfig, Instance};

/// Literal backend tag stored in every record.
pub(crate) const BACKEND_TAG: &str = "apple-container";
/// Schema of the instance record, journal, and image manifest. Version 1 was
/// the `container machine` backend; its records are refused (see
/// [`legacy_machine`]).
pub(crate) const SCHEMA_VERSION: u32 = 2;
/// Schema of `owner.json`, unchanged since version 1.
const OWNER_SCHEMA_VERSION: u32 = 1;

const OWNER_FILE: &str = "owner.json";
const MACHINE_FILE: &str = "apple-machine.json";
const JOURNAL_FILE: &str = "operation.json";
const KNOWN_HOSTS_FILE: &str = "known_hosts";

/// Entries a default (Lima/Firecracker) build creates directly in its
/// `data_dir`. Their presence means the configured root is shared.
const FOREIGN_BACKEND_ARTIFACTS: &[&str] = &[
    "images",
    "instances",
    "vm_key",
    "lima-builder.yaml",
    "vmlinux",
    "firecracker",
];

/// Longest sandbox id `coop-sandbox` accepts.
const MAX_MACHINE_NAME: usize = 48;

// ── Names ─────────────────────────────────────────────────────

/// A runtime object name coop generated: `[a-z0-9]([a-z0-9-]*[a-z0-9])?`,
/// at most [`MAX_MACHINE_NAME`] characters. Never derived from project names,
/// usernames, or paths.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct MachineName(String);

impl MachineName {
    pub(crate) fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let bytes = name.as_bytes();
        let charset_ok = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        let ends_ok = matches!(bytes.first(), Some(b) if *b != b'-')
            && matches!(bytes.last(), Some(b) if *b != b'-');
        if !charset_ok || !ends_ok || name.len() > MAX_MACHINE_NAME {
            bail!("invalid runtime object name {name:?}");
        }
        Ok(Self(name))
    }

    /// `coop-<owner8>-<instance16>`.
    pub(crate) fn generate(owner: &OwnerId) -> Result<Self> {
        Self::new(format!(
            "coop-{}-{}",
            owner.short(),
            crate::fs_util::random_hex(8)?
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this name was generated for `owner`. Necessary but never
    /// sufficient for deletion: callers also require matching local metadata.
    pub(crate) fn belongs_to(&self, owner: &OwnerId) -> bool {
        self.0
            .strip_prefix("coop-")
            .and_then(|rest| rest.strip_prefix(owner.short()))
            .is_some_and(|rest| rest.starts_with('-'))
    }
}

impl TryFrom<String> for MachineName {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<MachineName> for String {
    fn from(value: MachineName) -> Self {
        value.0
    }
}

impl std::fmt::Display for MachineName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// 32 lowercase hex characters identifying one installation's resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct OwnerId(String);

impl OwnerId {
    fn generate() -> Result<Self> {
        Ok(Self(crate::fs_util::random_hex(16)?))
    }

    /// The 8-character prefix embedded in generated names.
    pub(crate) fn short(&self) -> &str {
        &self.0[..8]
    }

    /// The full id, passed to the runtime as each sandbox's owner tag.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OwnerId {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            bail!("invalid owner id {value:?}");
        }
        Ok(Self(value))
    }
}

impl From<OwnerId> for String {
    fn from(value: OwnerId) -> Self {
        value.0
    }
}

// ── File helpers ──────────────────────────────────────────────

/// Read a managed control file without following a symlink at its path.
fn read_control_file(path: &Path) -> Result<Option<String>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    let mut file = match file {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to open {}", path.display()));
        }
    };
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    Ok(Some(content))
}

fn write_control_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value).context("Failed to serialize state")?;
    crate::fs_util::atomic_write_with_mode(path, &format!("{json}\n"), 0o600)
}

/// Create `dir` (and parents) and restrict it to the owner.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::create_dir_all(dir).with_context(|| format!("Failed to create {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to restrict {}", dir.display()))
}

fn check_header(schema_version: u32, backend: &str, path: &Path, want: u32) -> Result<()> {
    if backend != BACKEND_TAG {
        bail!(AppleError::IdentityConflict(format!(
            "{} belongs to backend {backend:?}, not {BACKEND_TAG}; refusing to use it",
            path.display()
        )));
    }
    if schema_version == 1 && want == SCHEMA_VERSION {
        bail!(AppleError::IdentityConflict(format!(
            "{} was written by the retired `container machine` backend; `coop destroy` \
             removes the instance's local state (its machine and network stay in the Apple \
             Container runtime until you delete them there)",
            path.display()
        )));
    }
    if schema_version != want {
        bail!(AppleError::IdentityConflict(format!(
            "{} has schema version {schema_version}; this build understands {want}",
            path.display()
        )));
    }
    Ok(())
}

// ── Owner ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Owner {
    pub(crate) schema_version: u32,
    pub(crate) backend: String,
    #[serde(rename = "owner_id")]
    pub(crate) id: OwnerId,
}

impl Owner {
    fn path(cfg: &CoopConfig) -> PathBuf {
        cfg.state_root().join(OWNER_FILE)
    }

    /// Load the installation's owner record, refusing a foreign backend's.
    pub(crate) fn load(cfg: &CoopConfig) -> Result<Self> {
        let path = Self::path(cfg);
        let content = read_control_file(&path)?.ok_or_else(|| {
            anyhow::anyhow!(
                "No Apple sandbox backend state at {}. Run `coop setup` first.",
                cfg.state_root().display()
            )
        })?;
        let owner: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        check_header(
            owner.schema_version,
            &owner.backend,
            &path,
            OWNER_SCHEMA_VERSION,
        )?;
        Ok(owner)
    }

    /// Load, or create on first setup.
    ///
    /// Refuses to initialise under a configured `data_dir` that a default
    /// (Lima/Firecracker) build also uses: that build's `uninstall --purge`
    /// removes its whole `data_dir`, which would delete this backend's
    /// ownership records and orphan its runtime objects.
    pub(crate) fn load_or_init(cfg: &CoopConfig) -> Result<Self> {
        if read_control_file(&Self::path(cfg))?.is_some() {
            return Self::load(cfg);
        }
        if let Some(foreign) = FOREIGN_BACKEND_ARTIFACTS
            .iter()
            .find(|name| cfg.data_dir.join(name).exists())
        {
            bail!(AppleError::IdentityConflict(format!(
                "data_dir {} already holds {foreign} from a default coop build; refusing to \
                 share it. Use a separate data_dir (the default is ~/.coop-apple).",
                cfg.data_dir.display()
            )));
        }
        ensure_private_dir(&cfg.state_root())?;
        let _lock = crate::fs_util::lock_sibling(&Self::path(cfg))?;
        if read_control_file(&Self::path(cfg))?.is_some() {
            return Self::load(cfg);
        }
        let owner = Self {
            schema_version: OWNER_SCHEMA_VERSION,
            backend: BACKEND_TAG.into(),
            id: OwnerId::generate()?,
        };
        write_control_file(&Self::path(cfg), &owner)?;
        Ok(owner)
    }
}

// ── Machine record ────────────────────────────────────────────

/// Where a machine is in its creation lifecycle. The record is only written
/// once creation has completed (an in-progress creation lives in the
/// journal), so `Ready` is the one value today; the field exists so a later
/// schema can add states without a migration. Recovery information only; live
/// state always comes from the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CreationState {
    /// Created and first-boot trust enrolled.
    Ready,
}

/// `apple-machine.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MachineSidecar {
    pub(crate) schema_version: u32,
    pub(crate) backend: String,
    pub(crate) owner_id: OwnerId,
    pub(crate) instance_id: String,
    /// `coop-sandbox` id; its vmnet network is internal to the sandbox.
    pub(crate) machine_id: MachineName,
    pub(crate) image_ref: String,
    pub(crate) image_digest: String,
    pub(crate) image_manifest_id: String,
    pub(crate) guest_user: crate::guest::GuestUser,
    pub(crate) requested_cpus: u32,
    pub(crate) requested_memory_bytes: u64,
    pub(crate) host_key_fingerprint: String,
    pub(crate) last_observed_owner_pid: Option<i32>,
    pub(crate) last_observed_ip: Option<std::net::Ipv4Addr>,
    /// Set once coop itself replaced the disk (`restore`): the next start
    /// enrolls the new host key instead of requiring the old pin. Never set
    /// in response to anything the guest did.
    pub(crate) reenroll_host_key: bool,
    pub(crate) creation_state: CreationState,
    pub(crate) created_at: String,
    pub(crate) runtime_identity: String,
}

impl MachineSidecar {
    pub(crate) fn path(inst: &Instance) -> PathBuf {
        inst.dir.join(MACHINE_FILE)
    }

    pub(crate) fn try_load(inst: &Instance) -> Result<Option<Self>> {
        let path = Self::path(inst);
        let Some(content) = read_control_file(&path)? else {
            return Ok(None);
        };
        check_raw_header(&content, &path)?;
        let rec: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(Some(rec))
    }

    pub(crate) fn load(inst: &Instance) -> Result<Self> {
        Self::try_load(inst)?.ok_or_else(|| {
            anyhow::anyhow!(
                "Instance '{}' has no Apple sandbox record at {}",
                inst.name,
                Self::path(inst).display()
            )
        })
    }

    pub(crate) fn save(&self, inst: &Instance) -> Result<()> {
        write_control_file(&Self::path(inst), self)
    }

    /// Refuse to act on a record that is not this installation's, or whose
    /// runtime names were not generated for it.
    pub(crate) fn check_owner(&self, owner: &Owner) -> Result<()> {
        if self.owner_id != owner.id || !self.machine_id.belongs_to(&owner.id) {
            bail!(AppleError::IdentityConflict(format!(
                "machine {} is not owned by this installation",
                self.machine_id
            )));
        }
        Ok(())
    }
}

// ── Journal ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Operation {
    Create,
    SetResources,
    /// Disk replaced by `coop restore`.
    RestoreDisk,
    Destroy,
}

/// A journaled operation with what reconciling it needs, so an operation
/// cannot be recorded without its prior state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalOp {
    Create,
    /// CPU count and memory committed before the change, read when
    /// reconciling an interrupted resize.
    SetResources {
        prior: (u32, u64),
    },
    /// The runtime's disk generation before the restore: a higher value
    /// afterwards proves the disk was replaced.
    RestoreDisk {
        prior_generation: u64,
    },
    Destroy,
}

impl JournalOp {
    pub(crate) fn kind(self) -> Operation {
        match self {
            Self::Create => Operation::Create,
            Self::SetResources { .. } => Operation::SetResources,
            Self::RestoreDisk { .. } => Operation::RestoreDisk,
            Self::Destroy => Operation::Destroy,
        }
    }
}

/// Completed side effects of a journaled operation, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Stage {
    /// Name reserved; nothing exists in the runtime yet.
    Reserved,
    /// About to create the sandbox (outcome may be unknown after a crash).
    CreatingMachine,
    MachineCreated,
    /// About to change resources or replace the disk.
    Applying,
    /// About to delete the sandbox.
    DeletingMachine,
    MachineDeleted,
}

/// `operation.json` — present only while a mutation or its recovery is
/// pending. Written before each mutating runtime call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "JournalRecord", into = "JournalRecord")]
pub(crate) struct Journal {
    pub(crate) schema_version: u32,
    pub(crate) backend: String,
    pub(crate) owner_id: OwnerId,
    pub(crate) op: JournalOp,
    pub(crate) stage: Stage,
    pub(crate) machine_id: MachineName,
}

/// The on-disk layout of [`Journal`]: the operation's prior state is stored
/// in optional fields beside it.
#[derive(Serialize, Deserialize)]
struct JournalRecord {
    schema_version: u32,
    backend: String,
    owner_id: OwnerId,
    operation: Operation,
    stage: Stage,
    machine_id: MachineName,
    prior_resources: Option<(u32, u64)>,
    prior_disk_generation: Option<u64>,
}

impl TryFrom<JournalRecord> for Journal {
    type Error = String;

    fn try_from(r: JournalRecord) -> std::result::Result<Self, String> {
        let op = match (r.operation, r.prior_resources, r.prior_disk_generation) {
            (Operation::Create, None, None) => JournalOp::Create,
            (Operation::Destroy, None, None) => JournalOp::Destroy,
            (Operation::SetResources, Some(prior), None) => JournalOp::SetResources { prior },
            (Operation::RestoreDisk, None, Some(prior_generation)) => {
                JournalOp::RestoreDisk { prior_generation }
            }
            (op, ..) => return Err(format!("{op:?} journal has mismatched prior state")),
        };
        Ok(Self {
            schema_version: r.schema_version,
            backend: r.backend,
            owner_id: r.owner_id,
            op,
            stage: r.stage,
            machine_id: r.machine_id,
        })
    }
}

impl From<Journal> for JournalRecord {
    fn from(j: Journal) -> Self {
        let (prior_resources, prior_disk_generation) = match j.op {
            JournalOp::SetResources { prior } => (Some(prior), None),
            JournalOp::RestoreDisk { prior_generation } => (None, Some(prior_generation)),
            JournalOp::Create | JournalOp::Destroy => (None, None),
        };
        Self {
            schema_version: j.schema_version,
            backend: j.backend,
            owner_id: j.owner_id,
            operation: j.op.kind(),
            stage: j.stage,
            machine_id: j.machine_id,
            prior_resources,
            prior_disk_generation,
        }
    }
}

impl Journal {
    fn path(inst: &Instance) -> PathBuf {
        inst.dir.join(JOURNAL_FILE)
    }

    pub(crate) fn begin(
        inst: &Instance,
        owner: &Owner,
        op: JournalOp,
        machine_id: MachineName,
    ) -> Result<Self> {
        let journal = Self {
            schema_version: SCHEMA_VERSION,
            backend: BACKEND_TAG.into(),
            owner_id: owner.id.clone(),
            op,
            stage: Stage::Reserved,
            machine_id,
        };
        journal.save(inst)?;
        Ok(journal)
    }

    pub(crate) fn try_load(inst: &Instance) -> Result<Option<Self>> {
        let path = Self::path(inst);
        let Some(content) = read_control_file(&path)? else {
            return Ok(None);
        };
        check_raw_header(&content, &path)?;
        let journal: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(Some(journal))
    }

    pub(crate) fn advance(&mut self, inst: &Instance, stage: Stage) -> Result<()> {
        self.stage = stage;
        self.save(inst)
    }

    fn save(&self, inst: &Instance) -> Result<()> {
        write_control_file(&Self::path(inst), self)
    }

    pub(crate) fn complete(inst: &Instance) -> Result<()> {
        match fs::remove_file(Self::path(inst)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("Failed to clear operation journal"),
        }
    }
}

/// Check a record's header before parsing the rest, so a record from
/// another schema fails with its own explanation rather than a field error.
fn check_raw_header(content: &str, path: &Path) -> Result<()> {
    #[derive(Deserialize)]
    struct Header {
        schema_version: u32,
        backend: String,
    }
    let header: Header = serde_json::from_str(content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    check_header(header.schema_version, &header.backend, path, SCHEMA_VERSION)
}

/// A schema-1 instance record or journal from the retired `container
/// machine` backend: its machine and network names, so `destroy` can name
/// what it leaves in that runtime.
pub(crate) fn legacy_machine(inst: &Instance) -> Result<Option<(String, String)>> {
    #[derive(Deserialize)]
    struct Legacy {
        schema_version: u32,
        backend: String,
        machine_id: String,
        network_id: String,
    }
    for path in [MachineSidecar::path(inst), Journal::path(inst)] {
        let Some(content) = read_control_file(&path)? else {
            continue;
        };
        if let Some(l) = serde_json::from_str::<Legacy>(&content)
            .ok()
            .filter(|l| l.schema_version == 1 && l.backend == BACKEND_TAG)
        {
            return Ok(Some((l.machine_id, l.network_id)));
        }
    }
    Ok(None)
}

/// Per-instance known-hosts file for the pinned guest host key.
pub(crate) fn known_hosts_path(inst: &Instance) -> PathBuf {
    inst.dir.join(KNOWN_HOSTS_FILE)
}

/// Serialize mutations of one instance.
pub(crate) fn lock_instance(inst: &Instance) -> Result<crate::fs_util::FileLock> {
    crate::fs_util::lock_sibling(&MachineSidecar::path(inst))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn owner() -> OwnerId {
        OwnerId::try_from("0a1b2c3d00112233445566778899aabb".to_string()).unwrap()
    }

    #[test]
    fn machine_names_follow_runtime_rule() {
        assert!(MachineName::new("coop-0a1b2c3d-00112233445566ff").is_ok());
        for bad in [
            "",
            "-lead",
            "trail-",
            "Upper",
            "has_underscore",
            "semi;colon",
            "a b",
            "../x",
            &"a".repeat(49),
        ] {
            assert!(MachineName::new(bad).is_err(), "accepted {bad:?}");
        }
        assert!(MachineName::new("a".repeat(48)).is_ok());
    }

    #[test]
    fn generated_names_are_owned_and_unique() {
        let o = owner();
        let a = MachineName::generate(&o).unwrap();
        let b = MachineName::generate(&o).unwrap();
        assert_ne!(a, b);
        assert!(a.belongs_to(&o));
        assert_eq!(a.as_str().len(), "coop-0a1b2c3d-".len() + 16);
        let other = OwnerId::try_from("ffffffff00112233445566778899aabb".to_string()).unwrap();
        assert!(!a.belongs_to(&other));
        // A name that merely shares the prefix is not owned.
        assert!(!MachineName::new("coop-0a1b2c3dx-1").unwrap().belongs_to(&o));
        assert!(!MachineName::new("users-machine").unwrap().belongs_to(&o));
    }

    #[test]
    fn owner_id_rejects_malformed() {
        assert!(OwnerId::try_from("short".to_string()).is_err());
        assert!(OwnerId::try_from("0A1B2C3D00112233445566778899AABB".to_string()).is_err());
    }

    fn test_cfg(dir: &Path) -> CoopConfig {
        CoopConfig {
            data_dir: crate::config::ConfigPath::new(dir),
            ..CoopConfig::default()
        }
    }

    #[test]
    fn owner_init_is_stable_and_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(&tmp.path().join("root"));
        let a = Owner::load_or_init(&cfg).unwrap();
        let b = Owner::load_or_init(&cfg).unwrap();
        assert_eq!(a.id, b.id);
        let mode = fs::metadata(cfg.state_root().join(OWNER_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(cfg.state_root()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[test]
    fn owner_refuses_foreign_backend_and_root() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        fs::create_dir_all(cfg.state_root()).unwrap();
        fs::write(
            cfg.state_root().join(OWNER_FILE),
            r#"{"schema_version":1,"backend":"lima","owner_id":"0a1b2c3d00112233445566778899aabb"}"#,
        )
        .unwrap();
        let err = Owner::load(&cfg).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::IdentityConflict(_))
        ));

        // A data_dir shared with a default build (its images/instances/key
        // live at the top level) is refused, and nothing is created in it.
        for foreign in ["lima-builder.yaml", "vm_key", "instances"] {
            let tmp = tempfile::tempdir().unwrap();
            fs::write(tmp.path().join(foreign), "").unwrap();
            let cfg = test_cfg(tmp.path());
            assert!(Owner::load_or_init(&cfg).is_err(), "{foreign}");
            assert!(!cfg.state_root().exists(), "{foreign}");
        }
    }

    #[test]
    fn control_files_do_not_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("elsewhere.json");
        fs::write(&target, "{}").unwrap();
        let link = tmp.path().join(OWNER_FILE);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_control_file(&link).is_err());
    }

    #[test]
    fn stages_are_ordered() {
        assert!(Stage::Reserved < Stage::CreatingMachine);
        assert!(Stage::CreatingMachine < Stage::MachineCreated);
        assert!(Stage::DeletingMachine < Stage::MachineDeleted);
    }

    fn test_inst(cfg: &CoopConfig) -> Instance {
        let dir = cfg.instances_dir().join("t");
        fs::create_dir_all(&dir).unwrap();
        Instance {
            name: crate::config::InstanceName::new("t").unwrap(),
            index: crate::config::InstanceIndex::new(0).unwrap(),
            dir,
            image: crate::config::ImageName::new("default").unwrap(),
        }
    }

    fn sidecar(owner_id: OwnerId, machine_id: MachineName) -> MachineSidecar {
        MachineSidecar {
            schema_version: SCHEMA_VERSION,
            backend: BACKEND_TAG.into(),
            owner_id,
            instance_id: "00112233445566ff".into(),
            machine_id,
            image_ref: "local/coop-0a1b2c3d:x".into(),
            image_digest: "sha256:x".into(),
            image_manifest_id: "m".into(),
            guest_user: crate::guest::GuestUser::default(),
            requested_cpus: 2,
            requested_memory_bytes: 1 << 30,
            host_key_fingerprint: "SHA256:x".into(),
            last_observed_owner_pid: None,
            last_observed_ip: None,
            reenroll_host_key: false,
            creation_state: CreationState::Ready,
            created_at: "now".into(),
            runtime_identity: "test".into(),
        }
    }

    /// A record is acted on only when both its owner field and its machine
    /// name belong to this installation.
    #[test]
    fn check_owner_requires_owner_and_name() {
        let me = Owner {
            schema_version: OWNER_SCHEMA_VERSION,
            backend: BACKEND_TAG.into(),
            id: owner(),
        };
        let other = OwnerId::try_from("ffffffff00112233445566778899aabb".to_string()).unwrap();
        let mine = MachineName::generate(&me.id).unwrap();
        let theirs = MachineName::generate(&other).unwrap();
        assert!(sidecar(owner(), mine.clone()).check_owner(&me).is_ok());
        for record in [
            sidecar(other.clone(), mine),
            sidecar(owner(), theirs.clone()),
            sidecar(other, theirs),
        ] {
            let err = record.check_owner(&me).unwrap_err();
            assert!(matches!(
                err.downcast_ref::<AppleError>(),
                Some(AppleError::IdentityConflict(_))
            ));
        }
        assert_eq!(me.id.as_str(), "0a1b2c3d00112233445566778899aabb");
    }

    #[test]
    fn journal_complete_is_idempotent_but_reports_real_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let inst = test_inst(&cfg);
        let me = Owner {
            schema_version: OWNER_SCHEMA_VERSION,
            backend: BACKEND_TAG.into(),
            id: owner(),
        };
        let name = MachineName::generate(&me.id).unwrap();
        Journal::begin(&inst, &me, JournalOp::Create, name).unwrap();
        Journal::complete(&inst).unwrap();
        assert!(Journal::try_load(&inst).unwrap().is_none());
        Journal::complete(&inst).unwrap();

        // Something that cannot be removed as a file is not "already gone".
        fs::create_dir(Journal::path(&inst)).unwrap();
        assert!(Journal::complete(&inst).is_err());
    }

    /// The journal keeps its flat on-disk layout, and an operation stored
    /// without its prior state (or with another operation's) is refused.
    #[test]
    fn journal_prior_state_matches_its_operation() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let inst = test_inst(&cfg);
        let me = Owner {
            schema_version: OWNER_SCHEMA_VERSION,
            backend: BACKEND_TAG.into(),
            id: owner(),
        };
        let name = MachineName::generate(&me.id).unwrap();
        let op = JournalOp::RestoreDisk {
            prior_generation: 7,
        };
        Journal::begin(&inst, &me, op, name.clone()).unwrap();
        let raw: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(Journal::path(&inst)).unwrap()).unwrap();
        assert_eq!(raw["operation"], "restore-disk");
        assert_eq!(raw["prior_disk_generation"], 7);
        assert!(raw["prior_resources"].is_null());
        assert_eq!(Journal::try_load(&inst).unwrap().unwrap().op, op);

        for (operation, resources, generation) in [
            ("set-resources", "null", "null"),
            ("restore-disk", "null", "null"),
            ("create", "[1,2]", "null"),
            ("set-resources", "[1,2]", "3"),
        ] {
            fs::write(
                Journal::path(&inst),
                format!(
                    r#"{{"schema_version":2,"backend":"apple-container","owner_id":"{}","operation":"{operation}","stage":"applying","machine_id":"{name}","prior_resources":{resources},"prior_disk_generation":{generation}}}"#,
                    me.id.as_str()
                ),
            )
            .unwrap();
            assert!(
                Journal::try_load(&inst).is_err(),
                "{operation} {resources} {generation}"
            );
        }
    }

    /// Only a schema-1 record from this backend is legacy; a current record
    /// or another backend's schema-1 record is not.
    #[test]
    fn legacy_machine_needs_old_schema_and_this_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let inst = test_inst(&cfg);
        for record in [
            r#"{"schema_version":2,"backend":"apple-container","machine_id":"a","network_id":"b"}"#,
            r#"{"schema_version":1,"backend":"lima","machine_id":"a","network_id":"b"}"#,
        ] {
            fs::write(MachineSidecar::path(&inst), record).unwrap();
            assert_eq!(legacy_machine(&inst).unwrap(), None, "{record}");
        }
    }

    /// Records from the retired `container machine` backend are refused with
    /// an explanation, and `legacy_machine` names what they point at.
    #[test]
    fn schema_one_records_are_legacy() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let inst = test_inst(&cfg);
        fs::write(
            MachineSidecar::path(&inst),
            r#"{"schema_version":1,"backend":"apple-container","machine_id":"coop-0a1b2c3d-1","network_id":"coop-0a1b2c3d-1"}"#,
        )
        .unwrap();
        let err = MachineSidecar::try_load(&inst).unwrap_err();
        assert!(
            format!("{err:#}").contains("retired `container machine` backend"),
            "{err:#}"
        );
        assert_eq!(
            legacy_machine(&inst).unwrap(),
            Some(("coop-0a1b2c3d-1".into(), "coop-0a1b2c3d-1".into()))
        );
    }
}
