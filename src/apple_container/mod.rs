//! Apple Container backend (`apple-container` feature, macOS only).
//!
//! Runs each coop instance as a persistent Apple `container machine` with its
//! own dedicated network, no host-home mount, and no host SSH-agent
//! forwarding, then reuses coop's SSH-based guest operations with a pinned
//! per-instance host key. Workspaces are copied, never live-mounted.
//!
//! The isolation this backend promises depends on a runtime extension that
//! stock Apple Container 1.4.1 lacks (see `security::qualify`). On a runtime
//! without it, `setup`, `up`, `start`, and every SSH target fail closed before
//! any credential, workspace, or agent reaches a guest. Read-only queries and
//! cleanup of already-owned resources still work.

mod cli;
mod image;
mod protocol;
mod security;
mod ssh;
mod state;

use std::cell::OnceCell;
use std::net::Ipv4Addr;
use std::num::NonZeroU8;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::backend::{
    BackendCapabilities, Capability, LocalEndpointRoute, LogMode, RunningInstance, SshTarget,
    StoppedInstance, VmBackend, boot_preflight,
};
use crate::config::{
    AppleContainerConfig, CoopConfig, GiB, ImageName, Instance, Mount, NetworkConfig, VmMemory,
};
use crate::setup::SetupOptions;
use cli::{Exec, MAX_JSON_OUTPUT, MAX_PUBKEY_OUTPUT, MAX_TEXT_OUTPUT, RealExec, Request};
use image::{BuildContext, BuildInputs, ImageManifest};
use protocol::{MachineRecord, MachineStatus};
use security::{QualifiedRuntime, SecurityReady};
use state::{
    CreationState, Journal, MachineName, MachineSidecar, NetworkName, Operation, Owner, Stage,
};

/// Stable diagnostic classes. The prefix of each message is the identifier
/// documented in `docs/backends.md`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AppleError {
    #[error("APPLE_RUNTIME_UNAVAILABLE: {0}")]
    RuntimeUnavailable(String),
    #[error("APPLE_RUNTIME_UNQUALIFIED: {0}")]
    RuntimeUnqualified(String),
    #[error("APPLE_NETWORK_ISOLATION: {0}")]
    NetworkIsolation(String),
    #[error("APPLE_HOST_EXPOSURE: {0}")]
    HostExposure(String),
    #[error("APPLE_IDENTITY_CONFLICT: {0}")]
    IdentityConflict(String),
    #[error("APPLE_HOST_KEY_CHANGED: {0}")]
    HostKeyChanged(String),
    #[error("APPLE_BOOT_TIMEOUT: {0}")]
    BootTimeout(String),
    #[error("APPLE_OPERATION_UNCERTAIN: {0}")]
    OperationUncertain(String),
}

/// Install locations searched when `[apple_container] binary` is unset.
const DEFAULT_BINARIES: &[&str] = &["/usr/local/bin/container", "/opt/homebrew/bin/container"];

/// Oldest macOS release Apple Container machines support.
const MIN_MACOS_MAJOR: u32 = 26;

/// Deadlines from `[apple_container]`.
#[derive(Debug, Clone)]
struct Settings {
    binary: Option<PathBuf>,
    probe: Duration,
    operation: Duration,
    create: Duration,
    boot: Duration,
    stop: Duration,
    build: Duration,
}

impl From<&AppleContainerConfig> for Settings {
    fn from(cfg: &AppleContainerConfig) -> Self {
        Self {
            binary: cfg.binary.as_ref().map(|p| p.to_path_buf()),
            probe: cfg.probe_timeout_seconds.duration(),
            operation: cfg.operation_timeout_seconds.duration(),
            create: cfg.create_timeout_seconds.duration(),
            boot: cfg.boot_timeout_seconds.duration(),
            stop: cfg.stop_timeout_seconds.duration(),
            build: cfg.build_timeout_seconds.duration(),
        }
    }
}

/// A resolved runtime binary plus what qualification found. Qualification
/// failure is kept (not raised) so cleanup of owned resources still works on
/// an unqualified runtime; every path that boots or hands out a guest calls
/// [`Runtime::qualified`] first.
struct Runtime {
    exec: Box<dyn Exec>,
    settings: Settings,
    qualification: std::result::Result<QualifiedRuntime, AppleError>,
    /// Set once `system status` succeeded; the service is probed once per
    /// process, not once per SSH target.
    service_ready: std::cell::Cell<bool>,
}

pub struct AppleContainerBackend {
    settings: Settings,
    runtime: OnceCell<Runtime>,
    injected: std::cell::RefCell<Option<Box<dyn Exec>>>,
}

impl AppleContainerBackend {
    /// Backend with default `[apple_container]` settings.
    pub fn new() -> Self {
        Self::for_config(&CoopConfig::default())
    }

    /// Backend honouring the configured runtime binary and deadlines.
    pub fn for_config(cfg: &CoopConfig) -> Self {
        Self {
            settings: Settings::from(&cfg.apple_container),
            runtime: OnceCell::new(),
            injected: std::cell::RefCell::new(None),
        }
    }

    #[cfg(test)]
    fn with_exec(exec: Box<dyn Exec>) -> Self {
        let be = Self::new();
        *be.injected.borrow_mut() = Some(exec);
        be
    }

    /// The runtime, resolved and probed once per process.
    fn runtime(&self) -> Result<&Runtime> {
        if let Some(rt) = self.runtime.get() {
            return Ok(rt);
        }
        let exec: Box<dyn Exec> = match self.injected.borrow_mut().take() {
            Some(exec) => exec,
            None => Box::new(RealExec::new(resolve_binary(
                self.settings.binary.as_deref(),
            )?)),
        };
        let mut rt = Runtime {
            exec,
            settings: self.settings.clone(),
            qualification: Err(AppleError::RuntimeUnavailable(String::new())),
            service_ready: std::cell::Cell::new(false),
        };
        rt.qualification = rt
            .probe_qualification()
            .map_err(|e| match e.downcast::<AppleError>() {
                Ok(apple) => apple,
                Err(other) => AppleError::RuntimeUnavailable(format!("{other:#}")),
            });
        Ok(self.runtime.get_or_init(|| rt))
    }

    /// Runtime that passed qualification, with its service running.
    fn qualified_runtime(&self) -> Result<(&Runtime, &QualifiedRuntime)> {
        let rt = self.runtime()?;
        let q = rt.qualified()?;
        rt.require_service()?;
        Ok((rt, q))
    }
}

impl Default for AppleContainerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AppleContainerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("apple-container")
    }
}

// ── Preflight ─────────────────────────────────────────────────

/// Resolve the runtime to an absolute, host-owned executable. Only the
/// user's own config or the fixed install paths are consulted — never `PATH`
/// or anything a project supplies — so a project cannot choose the runtime.
fn resolve_binary(configured: Option<&Path>) -> Result<PathBuf> {
    let candidates: Vec<PathBuf> = match configured {
        Some(p) => vec![p.to_path_buf()],
        None => DEFAULT_BINARIES.iter().map(PathBuf::from).collect(),
    };
    let mut last_err = None;
    for candidate in candidates {
        match check_binary(&candidate) {
            Ok(resolved) => return Ok(resolved),
            Err(e) => last_err = Some(e),
        }
    }
    let detail = last_err.map(|e| format!(" ({e:#})")).unwrap_or_default();
    Err(AppleError::RuntimeUnavailable(format!(
        "no usable Apple `container` runtime found{detail}. Install a qualified build or set \
         `[apple_container] binary` to its absolute path."
    ))
    .into())
}

fn check_binary(path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;
    if !path.is_absolute() {
        bail!("{} is not an absolute path", path.display());
    }
    let resolved = path
        .canonicalize()
        .with_context(|| format!("{} does not exist", path.display()))?;
    let meta = std::fs::metadata(&resolved)?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    if !meta.is_file() || meta.mode() & 0o111 == 0 {
        bail!("{} is not an executable file", resolved.display());
    }
    if meta.uid() != 0 && meta.uid() != uid {
        bail!("{} is owned by another user", resolved.display());
    }
    if meta.mode() & 0o022 != 0 {
        bail!("{} is group- or world-writable", resolved.display());
    }
    Ok(resolved)
}

/// Apple Silicon and a supported macOS release.
fn check_platform() -> Result<()> {
    if !cfg!(target_arch = "aarch64") {
        bail!(AppleError::RuntimeUnavailable(
            "the Apple Container backend requires an Apple Silicon Mac".into()
        ));
    }
    let out = std::process::Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .context("Failed to run sw_vers")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let major = text
        .trim()
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
        .context("Unrecognised sw_vers output")?;
    if major < MIN_MACOS_MAJOR {
        bail!(AppleError::RuntimeUnavailable(format!(
            "the Apple Container backend requires macOS {MIN_MACOS_MAJOR} or later (found {})",
            text.trim()
        )));
    }
    Ok(())
}

// ── Runtime operations ────────────────────────────────────────

impl Runtime {
    fn qualified(&self) -> Result<&QualifiedRuntime> {
        self.qualification.as_ref().map_err(|e| e.clone().into())
    }

    fn probe_qualification(&self) -> Result<QualifiedRuntime> {
        let version = self.text(["--version"], self.settings.probe, MAX_TEXT_OUTPUT)?;
        let help = self.text(
            ["machine", "create", "--help"],
            self.settings.probe,
            MAX_TEXT_OUTPUT,
        )?;
        security::qualify(&version, &help)
    }

    /// Run a command that must succeed; return its stdout.
    fn text<I, S>(&self, args: I, timeout: Duration, max: usize) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.checked(&Request::new(args, timeout, max))
    }

    /// The service must already be running; coop never starts, stops, or
    /// restarts the global service itself.
    fn require_service(&self) -> Result<()> {
        if self.service_ready.get() {
            return Ok(());
        }
        let req = Request::new(["system", "status"], self.settings.probe, MAX_TEXT_OUTPUT);
        let out = self.exec.run(&req)?;
        if !out.success() {
            bail!(AppleError::RuntimeUnavailable(format!(
                "the Apple Container service is not running ({}). Start it with \
                 `container system start`, then retry.",
                out.stderr_summary()
            )));
        }
        self.service_ready.set(true);
        Ok(())
    }

    fn inspect_machine(&self, name: &MachineName) -> Result<MachineRecord> {
        let json = self.text(
            ["machine", "inspect", name.as_str()],
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        protocol::parse_machine_inspect(&json, name)
    }

    /// Whether the runtime lists `name`. A failed listing is an error, never
    /// "absent".
    fn machine_exists(&self, name: &MachineName) -> Result<bool> {
        let json = self.text(
            ["machine", "list", "--format", "json"],
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        Ok(protocol::parse_machine_list(&json)?
            .iter()
            .any(|m| m.id == name.as_str()))
    }

    /// Whether the runtime lists network `name`. Decided from the full
    /// listing rather than from `network inspect` error text, so a missing
    /// network is never confused with a failed query.
    fn network_exists(&self, name: &NetworkName) -> Result<bool> {
        let json = self.text(
            ["network", "list", "--format", "json"],
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        Ok(protocol::parse_network_list(&json)?
            .iter()
            .any(|id| id == name.as_str()))
    }

    fn require_network(&self, name: &NetworkName) -> Result<()> {
        if !self.network_exists(name)? {
            bail!(AppleError::NetworkIsolation(format!(
                "dedicated network {name} is missing; refusing to boot on any other network"
            )));
        }
        Ok(())
    }

    fn create_network(&self, name: &NetworkName, owner: &Owner) -> Result<()> {
        let label = format!("coop.owner={}", owner.id.short());
        let created = self.text(
            ["network", "create", "--label", &label, name.as_str()],
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        )?;
        if created.trim() != name.as_str() {
            bail!(AppleError::IdentityConflict(format!(
                "network create for {name} reported {:?}",
                cli::sanitize_for_display(&created)
            )));
        }
        Ok(())
    }

    fn create_machine(
        &self,
        name: &MachineName,
        network: &NetworkName,
        cpus: NonZeroU8,
        memory_mib: u32,
        image_ref: &str,
    ) -> Result<()> {
        // Creation unpacks the image into a new machine disk, so it gets its
        // own (longer) deadline rather than the boot deadline.
        let req = Request::new(
            create_machine_args(name, network, cpus, memory_mib, image_ref),
            self.settings.create,
            MAX_TEXT_OUTPUT,
        )
        .cancellable();
        self.checked(&req)?;
        Ok(())
    }

    /// Run `req`, which must succeed; return its stdout.
    fn checked(&self, req: &Request) -> Result<String> {
        let out = self.exec.run(req)?;
        if !out.success() {
            bail!(
                "`container {}` failed: {}",
                req.describe(),
                out.stderr_summary()
            );
        }
        Ok(out.stdout_str()?.to_string())
    }

    /// Last lines of the machine's boot log, for boot-failure errors: the
    /// only diagnostic available when SSH never came up. Best effort;
    /// control characters from the guest are replaced.
    fn boot_log_tail(&self, name: &MachineName) -> String {
        let req = Request::new(
            ["machine", "logs", "--boot", "-n", "40", name.as_str()],
            self.settings.probe,
            MAX_JSON_OUTPUT,
        );
        match self.checked(&req) {
            Ok(text) if !text.trim().is_empty() => {
                format!(
                    "\nLast boot log lines:\n{}",
                    cli::sanitize_for_display(&text)
                )
            }
            _ => format!("\n(Boot log unavailable; try `container machine logs --boot {name}`.)"),
        }
    }

    /// Boot `name` with a fixed no-op command; `machine run` boots on demand.
    fn boot(&self, name: &MachineName) -> Result<()> {
        let req = Request::new(
            machine_run_args(name, &["/usr/bin/true"]),
            self.settings.boot,
            MAX_TEXT_OUTPUT,
        )
        .cancellable();
        self.checked(&req).map_err(|e| {
            AppleError::BootTimeout(format!(
                "machine {name} failed to boot: {e:#}{}",
                self.boot_log_tail(name)
            ))
        })?;
        Ok(())
    }

    /// Wait until `name` runs with an address and a backing container, then
    /// run the post-boot isolation gate.
    fn wait_ready(
        &self,
        name: &MachineName,
        network: &NetworkName,
        deadline: Instant,
    ) -> Result<(SecurityReady, MachineRecord)> {
        loop {
            crate::signal::check_shutdown()?;
            let rec = self.inspect_machine(name)?;
            if rec.status == MachineStatus::Stopped {
                bail!(AppleError::BootTimeout(format!(
                    "machine {name} stopped during boot{}",
                    self.boot_log_tail(name)
                )));
            }
            if rec.status == MachineStatus::Running
                && rec.ip.is_some()
                && rec.container_id.is_some()
            {
                return self.gate(rec, network);
            }
            if Instant::now() >= deadline {
                bail!(AppleError::BootTimeout(format!(
                    "machine {name} did not report a running address in time{}",
                    self.boot_log_tail(name)
                )));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Inspect `rec`'s current backing container and run the isolation gate.
    fn gate(
        &self,
        rec: MachineRecord,
        network: &NetworkName,
    ) -> Result<(SecurityReady, MachineRecord)> {
        let cid = rec
            .container_id
            .clone()
            .context("running machine reports no backing container")?;
        let json = self.text(["inspect", &cid], self.settings.probe, MAX_JSON_OUTPUT)?;
        let container = protocol::parse_container_inspect(&json, &cid)?;
        let ready = security::verify_effective(&rec, &container, network)?;
        Ok((ready, rec))
    }

    /// Re-run the gate on an already-inspected running machine, without
    /// booting it.
    fn establish_ready(
        &self,
        sidecar: &MachineSidecar,
        rec: MachineRecord,
    ) -> Result<(SecurityReady, Ipv4Addr)> {
        if rec.status != MachineStatus::Running {
            bail!(
                "Instance machine {} is {}, not running",
                sidecar.machine_id,
                rec.status.label()
            );
        }
        let (ready, rec) = self.gate(rec, &sidecar.network_id)?;
        let ip = rec.ip.context("running machine reports no address")?;
        Ok((ready, ip))
    }

    /// Read the guest host public key over the native control channel,
    /// retrying until first-boot key generation finishes.
    fn read_host_key(
        &self,
        ready: &SecurityReady,
        deadline: Instant,
    ) -> Result<ssh::HostPublicKey> {
        let name = ready.machine();
        loop {
            crate::signal::check_shutdown()?;
            let req = Request::new(
                machine_run_args(name, &["/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"]),
                self.settings.probe,
                MAX_PUBKEY_OUTPUT,
            );
            let out = self.exec.run(&req)?;
            // A missing file and a file caught mid-write (empty or partial)
            // both mean key generation has not finished: poll again. Only a
            // key that still does not parse at the deadline is an error.
            let attempt = if out.success() {
                out.stdout_str()
                    .map(String::from)
                    .and_then(|text| ssh::HostPublicKey::parse(&text))
            } else {
                Err(anyhow::anyhow!("{}", out.stderr_summary()))
            };
            match attempt {
                Ok(key) => {
                    // The key must come from the boot the gate approved.
                    let rec = self.inspect_machine(name)?;
                    if rec.container_id.as_deref() != Some(ready.container_id()) {
                        bail!(AppleError::IdentityConflict(format!(
                            "machine {name} restarted while its host key was read"
                        )));
                    }
                    return Ok(key);
                }
                Err(e) if Instant::now() >= deadline => {
                    bail!(AppleError::BootTimeout(format!(
                        "machine {name} did not produce a valid SSH host key in time: {e:#}"
                    )));
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Request a stop and confirm it. A stop that cannot be confirmed leaves
    /// the machine in an unknown state; nothing may mutate its disk then.
    fn stop_and_confirm(&self, name: &MachineName) -> Result<()> {
        let req = Request::new(
            ["machine", "stop", name.as_str()],
            self.settings.stop,
            MAX_TEXT_OUTPUT,
        );
        let out = self.exec.run(&req)?;
        let deadline = Instant::now() + self.settings.stop;
        loop {
            let rec = self.inspect_machine(name)?;
            if rec.status == MachineStatus::Stopped {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(AppleError::OperationUncertain(format!(
                    "machine {name} did not confirm it stopped ({}); leaving it untouched",
                    out.stderr_summary()
                )));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn delete_machine(&self, name: &MachineName) -> Result<()> {
        self.text(
            ["machine", "delete", name.as_str()],
            self.settings.stop,
            MAX_TEXT_OUTPUT,
        )?;
        if self.machine_exists(name)? {
            bail!(AppleError::OperationUncertain(format!(
                "machine {name} still exists after delete"
            )));
        }
        Ok(())
    }

    fn delete_network(&self, name: &NetworkName) -> Result<()> {
        self.text(
            ["network", "delete", name.as_str()],
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        )?;
        Ok(())
    }

    fn image_digest(&self, image_ref: &str) -> Result<String> {
        let json = self.text(
            ["image", "inspect", image_ref],
            self.settings.probe,
            MAX_JSON_OUTPUT * 4,
        )?;
        image::parse_image_digest(&json)
    }

    fn verify_image(&self, manifest: &ImageManifest) -> Result<()> {
        let digest = self.image_digest(&manifest.image_ref)?;
        if digest != manifest.digest {
            bail!(AppleError::IdentityConflict(format!(
                "image {} now resolves to {digest}, but the template was verified as {}; \
                 run `coop setup --rebuild`",
                manifest.image_ref, manifest.digest
            )));
        }
        Ok(())
    }

    /// Poll until every unit in `services` is active. Units start after the
    /// SSH host key appears (docker well after), so "activating" is retried;
    /// a unit still inactive at `deadline` fails verification.
    fn wait_for_services(
        &self,
        name: &MachineName,
        services: &[&str],
        deadline: Instant,
    ) -> Result<()> {
        loop {
            let mut args = vec!["/usr/bin/systemctl", "is-active", "--quiet"];
            args.extend_from_slice(services);
            if self.run_root_ok(name, &args) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let mut states = vec!["/usr/bin/systemctl", "is-active"];
                states.extend_from_slice(services);
                let detail = self
                    .exec
                    .run(&Request::new(
                        machine_run_args(name, &states),
                        self.settings.probe,
                        MAX_TEXT_OUTPUT,
                    ))
                    .map(|o| cli::sanitize_for_display(&String::from_utf8_lossy(&o.stdout)))
                    .unwrap_or_default();
                bail!(
                    "Image verification failed: services {} not active in time ({})",
                    services.join(", "),
                    detail.replace('\n', ", ")
                );
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Which of `paths` are not executable in the machine, from one
    /// `machine run`. Paths reach the script as positional parameters, each
    /// escaped once by [`machine_run_args`], never as script text.
    fn missing_executables(&self, name: &MachineName, paths: &[String]) -> Result<Vec<String>> {
        let mut command = vec![
            "/bin/sh",
            "-c",
            r#"for p; do test -x "$p" || printf '%s\n' "$p"; done"#,
            "sh",
        ];
        command.extend(paths.iter().map(String::as_str));
        let out = self.checked(&Request::new(
            machine_run_args(name, &command),
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        ))?;
        Ok(out.lines().map(String::from).collect())
    }

    /// Run a fixed root command in the machine; `true` on exit 0.
    fn run_root_ok(&self, name: &MachineName, command: &[&str]) -> bool {
        self.exec
            .run(&Request::new(
                machine_run_args(name, command),
                self.settings.operation,
                MAX_TEXT_OUTPUT,
            ))
            .is_ok_and(|o| o.success())
    }

    fn delete_image_best_effort(&self, image_ref: &str) {
        if let Err(e) = self.text(
            ["image", "delete", image_ref],
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        ) {
            tracing::warn!("Failed to delete image {image_ref}: {e:#}");
        }
    }

    /// Best-effort stop after a failed boot, keeping the disk for diagnosis.
    fn stop_after_failure(&self, name: &MachineName) {
        if let Err(e) = self.stop_and_confirm(name) {
            tracing::warn!("Failed to stop machine {name} after a failed start: {e:#}");
        }
    }
}

/// Argument vector for `machine create`, including the required isolation
/// extension flags.
/// `container machine run --root -n <name> -- <command>`. The runtime joins
/// everything after `--` with spaces and runs it through the guest shell
/// (`$SHELL -c "$*"` in the machine init script), so `command` is sent as a
/// single shell string with every word escaped exactly once.
fn machine_run_args(name: &MachineName, command: &[&str]) -> Vec<String> {
    let mut rendered = crate::remote_command::RemoteCommand::new();
    for (i, word) in command.iter().enumerate() {
        if i > 0 {
            rendered = rendered.literal(" ");
        }
        rendered = rendered.arg(word);
    }
    ["machine", "run", "--root", "-n", name.as_str(), "--"]
        .into_iter()
        .map(String::from)
        .chain([rendered.into_string()])
        .collect()
}

fn create_machine_args(
    name: &MachineName,
    network: &NetworkName,
    cpus: NonZeroU8,
    memory_mib: u32,
    image_ref: &str,
) -> Vec<String> {
    vec![
        "machine".into(),
        "create".into(),
        "--no-boot".into(),
        "--name".into(),
        name.to_string(),
        "--cpus".into(),
        cpus.to_string(),
        "--memory".into(),
        memory_arg(memory_mib),
        "--home-mount".into(),
        "none".into(),
        "--network".into(),
        network.to_string(),
        "--no-ssh-agent".into(),
        "--progress".into(),
        "none".into(),
        image_ref.into(),
    ]
}

/// The runtime parses `mb` as mebibytes.
fn memory_arg(mib: u32) -> String {
    format!("{mib}mb")
}

fn mib_to_bytes(mib: u32) -> u64 {
    u64::from(mib) * 1024 * 1024
}

// ── Lifecycle ─────────────────────────────────────────────────

impl AppleContainerBackend {
    fn provision_machine(
        cfg: &CoopConfig,
        rt: &Runtime,
        q: &QualifiedRuntime,
        inst: &Instance,
        owner: &Owner,
        manifest: &ImageManifest,
        journal: &mut Journal,
    ) -> Result<()> {
        let machine = journal.machine_id.clone();
        let network = journal.network_id.clone();
        let cpus = cfg.vm.vcpu_count;
        let memory_mib = cfg.vm.mem_size_mib.get().as_u32();

        journal.advance(inst, Stage::CreatingNetwork)?;
        rt.create_network(&network, owner)?;
        journal.advance(inst, Stage::NetworkCreated)?;
        rt.require_network(&network)?;

        journal.advance(inst, Stage::CreatingMachine)?;
        rt.create_machine(&machine, &network, cpus, memory_mib, &manifest.image_ref)?;
        journal.advance(inst, Stage::MachineCreated)?;

        let rec = rt.inspect_machine(&machine)?;
        security::verify_machine_config(&rec, &network)?;
        if rec.cpus != u32::from(cpus.get()) || rec.memory_bytes != mib_to_bytes(memory_mib) {
            bail!(AppleError::IdentityConflict(format!(
                "machine {machine} was created with {} vCPUs / {} bytes, expected {cpus} / {}",
                rec.cpus,
                rec.memory_bytes,
                mib_to_bytes(memory_mib)
            )));
        }

        let deadline = Instant::now() + rt.settings.boot;
        rt.boot(&machine)?;
        let (ready, rec) = rt.wait_ready(&machine, &network, deadline)?;
        let key = rt.read_host_key(&ready, deadline)?;
        ssh::enroll(inst, &machine, &key)?;
        let ip = rec.ip.context("running machine reports no address")?;
        let target = ssh::pinned_target(cfg, inst, &machine, ip, &manifest.guest_user)?;
        target
            .wait_until_ready(
                deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_secs(5)),
            )
            .context("Guest booted but SSH is not accepting connections")?;

        MachineSidecar {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            owner_id: owner.id.clone(),
            instance_id: machine
                .as_str()
                .rsplit('-')
                .next()
                .unwrap_or_default()
                .to_string(),
            machine_id: machine,
            network_id: network,
            image_ref: manifest.image_ref.clone(),
            image_digest: manifest.digest.clone(),
            image_manifest_id: manifest.manifest_id.clone(),
            guest_user: manifest.guest_user.clone(),
            requested_cpus: u32::from(cpus.get()),
            requested_memory_bytes: mib_to_bytes(memory_mib),
            host_key_fingerprint: key.fingerprint(),
            last_observed_container_id: Some(ready.container_id().to_string()),
            last_observed_ip: Some(ip),
            creation_state: CreationState::Ready,
            created_at: crate::setup::utc_timestamp(),
            runtime_identity: q.identity.clone(),
        }
        .save(inst)
    }

    /// Load and ownership-check an instance's machine record.
    fn owned_sidecar(cfg: &CoopConfig, inst: &Instance) -> Result<MachineSidecar> {
        let owner = Owner::load(cfg)?;
        if let Some(journal) = Journal::try_load(inst)? {
            bail!(AppleError::OperationUncertain(format!(
                "instance '{}' has an unfinished {:?} operation (stage {:?}); run \
                 `coop start {}` (resize) or `coop destroy {}` (create/destroy) to reconcile it",
                inst.name, journal.operation, journal.stage, inst.name, inst.name
            )));
        }
        let sidecar = MachineSidecar::load(inst)?;
        sidecar.check_owner(&owner)?;
        Ok(sidecar)
    }

    /// Finish an interrupted `resize`: once the machine is confirmed stopped,
    /// the runtime's current CPU/memory are authoritative, so record them and
    /// clear the journal. Other journaled operations are left for `destroy`.
    /// Caller holds the instance lock.
    fn recover_resources(rt: &Runtime, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let Some(journal) = Journal::try_load(inst)? else {
            return Ok(());
        };
        if journal.operation != Operation::SetResources {
            return Ok(());
        }
        let owner = Owner::load(cfg)?;
        let mut sidecar = MachineSidecar::load(inst)?;
        sidecar.check_owner(&owner)?;
        if journal.machine_id != sidecar.machine_id {
            bail!(AppleError::IdentityConflict(format!(
                "resize journal names {}, but the instance records {}",
                journal.machine_id, sidecar.machine_id
            )));
        }
        let rec = rt.inspect_machine(&sidecar.machine_id)?;
        if rec.status != MachineStatus::Stopped {
            bail!(AppleError::OperationUncertain(format!(
                "an interrupted resize of '{}' cannot be reconciled while the machine is {}",
                inst.name,
                rec.status.label()
            )));
        }
        let (prior_cpus, prior_bytes) = journal
            .prior_resources
            .unwrap_or((sidecar.requested_cpus, sidecar.requested_memory_bytes));
        let outcome = if (rec.cpus, rec.memory_bytes) == (prior_cpus, prior_bytes) {
            "the change did not apply"
        } else {
            "the change applied"
        };
        tracing::warn!(
            "Reconciling an interrupted resize of '{}' ({outcome}): was {prior_cpus} vCPUs / \
             {} MiB, runtime reports {} vCPUs / {} MiB",
            inst.name,
            prior_bytes / (1024 * 1024),
            rec.cpus,
            rec.memory_bytes / (1024 * 1024)
        );
        sidecar.requested_cpus = rec.cpus;
        sidecar.requested_memory_bytes = rec.memory_bytes;
        sidecar.save(inst)?;
        Journal::complete(inst)
    }

    fn start_owned(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let (rt, q) = self.qualified_runtime()?;
        let _lock = state::lock_instance(inst)?;
        Self::recover_resources(rt, cfg, inst)?;
        let mut sidecar = Self::owned_sidecar(cfg, inst)?;
        let machine = sidecar.machine_id.clone();
        let rec = rt.inspect_machine(&machine)?;
        match rec.status {
            MachineStatus::Stopped => {}
            MachineStatus::Running => bail!("Instance '{}' is already running", inst.name),
            other => bail!(AppleError::OperationUncertain(format!(
                "machine {machine} is {}; wait for it to settle",
                other.label()
            ))),
        }
        security::verify_machine_config(&rec, &sidecar.network_id)?;
        rt.require_network(&sidecar.network_id)?;

        let deadline = Instant::now() + rt.settings.boot;
        let booted = (|| -> Result<(SecurityReady, Ipv4Addr)> {
            // Inside the guard: a boot that errors or times out may still
            // have started the machine, and it must not be left running.
            rt.boot(&machine)?;
            let (ready, rec) = rt.wait_ready(&machine, &sidecar.network_id, deadline)?;
            let key = rt.read_host_key(&ready, deadline)?;
            ssh::check_pin(inst, &machine, &key)?;
            let ip = rec.ip.context("running machine reports no address")?;
            let target = ssh::pinned_target(cfg, inst, &machine, ip, &sidecar.guest_user)?;
            target
                .wait_until_ready(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_secs(5)),
                )
                .context("Guest booted but SSH is not accepting connections")?;
            Ok((ready, ip))
        })();
        let (ready, ip) = match booted {
            Ok(v) => v,
            Err(e) => {
                rt.stop_after_failure(&machine);
                return Err(e);
            }
        };
        sidecar.last_observed_container_id = Some(ready.container_id().to_string());
        sidecar.last_observed_ip = Some(ip);
        sidecar.runtime_identity.clone_from(&q.identity);
        sidecar.save(inst)
    }

    /// Qualify, gate, and build the pinned target from an inspection the
    /// caller already made.
    fn target_for(
        &self,
        cfg: &CoopConfig,
        inst: &Instance,
        sidecar: &MachineSidecar,
        rec: MachineRecord,
    ) -> Result<SshTarget> {
        let (rt, _) = self.qualified_runtime()?;
        let (ready, ip) = rt.establish_ready(sidecar, rec)?;
        ssh::pinned_target(cfg, inst, ready.machine(), ip, &sidecar.guest_user)
    }

    fn apply_resources(
        rt: &Runtime,
        machine: &MachineName,
        cpus: Option<u32>,
        memory_mib: Option<u32>,
    ) -> Result<()> {
        let mut args = vec![
            "machine".to_string(),
            "set".into(),
            "-n".into(),
            machine.to_string(),
        ];
        if let Some(c) = cpus {
            args.push(format!("cpus={c}"));
        }
        if let Some(m) = memory_mib {
            args.push(format!("memory={}", memory_arg(m)));
        }
        rt.text(args, rt.settings.operation, MAX_TEXT_OUTPUT)?;
        Ok(())
    }
}

impl VmBackend for AppleContainerBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::new(&[Capability::MachineResources])
    }

    fn setup(&self, cfg: &CoopConfig, opts: &SetupOptions) -> Result<()> {
        boot_preflight(cfg)?;
        check_platform()?;
        let (rt, q) = self.qualified_runtime()?;
        tracing::info!("Apple Container runtime: {}", q.identity);
        let owner = Owner::load_or_init(cfg)?;
        ensure_ssh_key(cfg)?;

        let pubkey_path = cfg.ssh_key_path().with_extension("pub");
        let pubkey = std::fs::read_to_string(&pubkey_path)
            .with_context(|| format!("Failed to read {}", pubkey_path.display()))?;
        let pubkey = pubkey.trim();
        let pubkey_fingerprint = ssh::HostPublicKey::parse(pubkey)?.fingerprint();
        let ctx = BuildContext::render(&BuildInputs {
            pubkey,
            profiles: &opts.profiles,
            oci_features: &opts.oci_features,
            guest_user: &opts.guest_user,
        });
        let manifest_id = ctx.manifest_id(&opts.guest_user, &pubkey_fingerprint);
        let image = &opts.image;

        // An unreadable manifest must not block the rebuild that replaces it.
        let previous = ImageManifest::load_lenient(cfg, image);
        if !opts.rebuild
            && let Some(existing) = &previous
            && existing.manifest_id == manifest_id
            && rt.verify_image(existing).is_ok()
        {
            tracing::info!("Image '{image}' is up to date ({})", existing.image_ref);
            return Ok(());
        }

        let image_ref = image::image_ref(&owner, &manifest_id, &crate::fs_util::random_hex(4)?);
        state::ensure_private_dir(&cfg.image_dir(image))?;
        let log = cfg.image_dir(image).join("build.log");
        crate::fs_util::atomic_write_with_mode(&log, "", 0o600)?;
        let context = ctx.materialize()?;
        tracing::info!(
            "Building image '{image}' as {image_ref} (log: {})",
            log.display()
        );
        let built = build_and_verify_image(
            rt,
            &owner,
            &image_ref,
            &context,
            &log,
            // `coop setup --builder-timeout` overrides the configured deadline.
            opts.builder_timeout.unwrap_or(rt.settings.build),
            &opts.guest_user,
        );
        let digest = match built {
            Ok(digest) => digest,
            Err(e) => {
                // The new tag is unpublished; the previous manifest and its
                // image are untouched.
                rt.delete_image_best_effort(&image_ref);
                return Err(e);
            }
        };

        ImageManifest {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            image_ref: image_ref.clone(),
            digest,
            manifest_id: manifest_id.clone(),
            base_image: image::BASE_IMAGE.into(),
            platform: image::PLATFORM.into(),
            guest_user: opts.guest_user.clone(),
            pubkey_fingerprint,
            created: crate::setup::utc_timestamp(),
        }
        .save(cfg, image)?;
        crate::setup::TemplateConfig {
            version: crate::setup::TEMPLATE_VERSION,
            created: crate::setup::utc_timestamp(),
            install_script_hash: crate::sha256_hash::Sha256Hash::of(&manifest_id),
            profiles: opts.profiles.iter().map(|p| p.name.clone()).collect(),
            extra_packages: Vec::new(),
            post_install_hash: None,
            // Nothing is baked: the first boot installs every marketplace,
            // plugin, and MCP server through the shared bootstrap.
            marketplaces: Vec::new(),
            plugins: Vec::new(),
            codex_marketplaces: Vec::new(),
            codex_plugins: Vec::new(),
            guest_user: opts.guest_user.clone(),
            oci_features: crate::devcontainer_oci::installed_features(&opts.oci_features),
        }
        .save_for(cfg, image)?;
        if let Some(old) = previous
            && old.image_ref != image_ref
        {
            prune_superseded_image(rt, cfg, &owner, &old.image_ref);
        }
        tracing::info!("Setup complete. Run `coop up` in a project directory to launch a VM.");
        Ok(())
    }

    fn create_and_start(
        &self,
        cfg: &CoopConfig,
        inst: &Instance,
        disk_gib: Option<GiB>,
        _mounts: &[Mount],
    ) -> Result<()> {
        boot_preflight(cfg)?;
        if disk_gib.is_some() {
            self.capabilities().require(self, Capability::DiskResize)?;
        }
        let (rt, q) = self.qualified_runtime()?;
        let owner = Owner::load(cfg)?;
        let manifest = ImageManifest::load(cfg, &inst.image)?;
        rt.verify_image(&manifest)?;

        let _lock = state::lock_instance(inst)?;
        if MachineSidecar::try_load(inst)?.is_some() || Journal::try_load(inst)?.is_some() {
            bail!(AppleError::OperationUncertain(format!(
                "instance '{}' already has machine state; destroy it before recreating",
                inst.name
            )));
        }
        let machine = MachineName::generate(&owner.id)?;
        if rt.machine_exists(&machine)? || rt.network_exists(&machine)? {
            bail!(AppleError::IdentityConflict(format!(
                "generated name {machine} is already in use; retry"
            )));
        }
        let mut journal = Journal::begin(
            inst,
            &owner,
            Operation::Create,
            machine.clone(),
            machine.clone(),
        )?;
        if let Err(e) = Self::provision_machine(cfg, rt, q, inst, &owner, &manifest, &mut journal) {
            if journal.stage >= Stage::CreatingMachine {
                rt.stop_after_failure(&machine);
            }
            return Err(e);
        }
        Journal::complete(inst)
    }

    fn start_existing(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        boot_preflight(cfg)?;
        self.start_owned(cfg, inst)
    }

    fn stop(&self, cfg: &CoopConfig, running: RunningInstance) -> Result<()> {
        let (inst, _target) = running.into_parts();
        let rt = self.runtime()?;
        let _lock = state::lock_instance(&inst)?;
        let sidecar = Self::owned_sidecar(cfg, &inst)?;
        rt.stop_and_confirm(&sidecar.machine_id)
    }

    /// Stop through the runtime's control plane alone. Needs neither a
    /// qualified runtime nor a passing gate nor SSH, so a machine that can no
    /// longer be reached safely can still be stopped (its disk is kept).
    /// Ownership is still required; an unfinished journal does not block it.
    fn stop_unproven(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let owner = Owner::load(cfg)?;
        let sidecar = MachineSidecar::load(inst)?;
        sidecar.check_owner(&owner)?;
        let rt = self.runtime()?;
        let _lock = state::lock_instance(inst)?;
        let rec = rt.inspect_machine(&sidecar.machine_id)?;
        if rec.status != MachineStatus::Stopped {
            rt.stop_and_confirm(&sidecar.machine_id)?;
        }
        tracing::info!("Instance '{}' stopped", inst.name);
        Ok(())
    }

    fn destroy_instance(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let sidecar = MachineSidecar::try_load(inst)?;
        let journal = Journal::try_load(inst)?;
        let ids = match (&sidecar, &journal) {
            (_, Some(j)) => Some((
                j.owner_id.clone(),
                j.machine_id.clone(),
                j.network_id.clone(),
            )),
            (Some(s), None) => Some((
                s.owner_id.clone(),
                s.machine_id.clone(),
                s.network_id.clone(),
            )),
            (None, None) => None,
        };
        if let Some((owner_id, machine, network)) = ids {
            let owner = Owner::load(cfg)?;
            if owner_id != owner.id
                || !machine.belongs_to(&owner.id)
                || !network.belongs_to(&owner.id)
            {
                bail!(AppleError::IdentityConflict(format!(
                    "instance '{}' records machine {machine}, which this installation does not own; \
                     leaving it untouched",
                    inst.name
                )));
            }
            let rt = self.runtime()?;
            let _lock = state::lock_instance(inst)?;
            if rt.machine_exists(&machine)? {
                let rec = rt.inspect_machine(&machine)?;
                if rec.status != MachineStatus::Stopped {
                    rt.stop_and_confirm(&machine)?;
                }
                let mut j = match journal {
                    Some(j) => j,
                    None => Journal::begin(
                        inst,
                        &owner,
                        Operation::Destroy,
                        machine.clone(),
                        network.clone(),
                    )?,
                };
                j.advance(inst, Stage::DeletingMachine)?;
                rt.delete_machine(&machine)?;
                j.advance(inst, Stage::MachineDeleted)?;
            }
            if rt.network_exists(&network)? {
                rt.delete_network(&network).with_context(|| {
                    format!("Failed to delete network {network}; it may still have an attachment")
                })?;
            }
        }
        if inst.dir.exists() {
            std::fs::remove_dir_all(&inst.dir)
                .with_context(|| format!("Failed to remove {}", inst.dir.display()))?;
        }
        // An instance created before a rebuild pins the superseded tag;
        // release it once the last such instance is gone.
        if let Some(s) = sidecar
            && ImageManifest::try_load(cfg, &inst.image)
                .ok()
                .flatten()
                .is_none_or(|m| m.image_ref != s.image_ref)
            && let (Ok(owner), Ok(rt)) = (Owner::load(cfg), self.runtime())
        {
            prune_superseded_image(rt, cfg, &owner, &s.image_ref);
        }
        Ok(())
    }

    fn destroy_shared(&self, cfg: &CoopConfig) {
        let Ok(images) = cfg.list_images() else {
            return;
        };
        for info in images {
            if let Err(e) = self.destroy_image(cfg, &info.name) {
                tracing::warn!("Failed to remove image '{}': {e:#}", info.name);
            }
        }
    }

    fn destroy_image(&self, cfg: &CoopConfig, image: &ImageName) -> Result<()> {
        let dir = cfg.image_dir(image);
        if !dir.exists() {
            bail!("Image '{image}' does not exist");
        }
        // Deleting the runtime tag is best effort: an unreadable manifest,
        // missing owner record, or unavailable runtime must not leave the
        // image name stuck.
        if let Some(manifest) = ImageManifest::load_lenient(cfg, image)
            && let Ok(owner) = Owner::load(cfg)
            && manifest
                .image_ref
                .starts_with(&format!("local/coop-{}:", owner.id.short()))
        {
            match self.runtime() {
                Ok(rt) => rt.delete_image_best_effort(&manifest.image_ref),
                Err(e) => tracing::warn!(
                    "Could not delete image {} from the runtime: {e:#}",
                    manifest.image_ref
                ),
            }
        }
        std::fs::remove_dir_all(&dir)
            .with_context(|| format!("Failed to remove image dir {}", dir.display()))?;
        tracing::info!("Removed image '{image}'");
        Ok(())
    }

    fn resize_disk(
        &self,
        _cfg: &CoopConfig,
        _stopped: &StoppedInstance,
        _new_size: GiB,
    ) -> Result<()> {
        self.capabilities().require(self, Capability::DiskResize)
    }

    fn set_machine_resources(
        &self,
        cfg: &CoopConfig,
        stopped: &StoppedInstance,
        mem: Option<VmMemory>,
        vcpus: Option<NonZeroU8>,
        start_after: bool,
    ) -> Result<()> {
        let inst = stopped.instance();
        let (rt, _) = self.qualified_runtime()?;
        let owner = Owner::load(cfg)?;
        let mut sidecar;
        let prior;
        {
            let _lock = state::lock_instance(inst)?;
            Self::recover_resources(rt, cfg, inst)?;
            sidecar = Self::owned_sidecar(cfg, inst)?;
            let machine = sidecar.machine_id.clone();
            let rec = rt.inspect_machine(&machine)?;
            if rec.status != MachineStatus::Stopped {
                bail!("Instance '{}' is not stopped", inst.name);
            }
            prior = (rec.cpus, rec.memory_bytes);
            let mut journal = Journal::begin(
                inst,
                &owner,
                Operation::SetResources,
                machine.clone(),
                sidecar.network_id.clone(),
            )?;
            journal.prior_resources = Some(prior);
            journal.advance(inst, Stage::Applying)?;

            let cpus = vcpus.map(|v| u32::from(v.get()));
            let memory_mib = mem.map(|m| m.get().as_u32());
            Self::apply_resources(rt, &machine, cpus, memory_mib)?;
            let after = rt.inspect_machine(&machine)?;
            let want_cpus = cpus.unwrap_or(prior.0);
            let want_mem = memory_mib.map_or(prior.1, mib_to_bytes);
            if after.cpus != want_cpus || after.memory_bytes != want_mem {
                bail!(AppleError::OperationUncertain(format!(
                    "machine {machine} reports {} vCPUs / {} bytes after update, expected {want_cpus} / {want_mem}",
                    after.cpus, after.memory_bytes
                )));
            }
            sidecar.requested_cpus = want_cpus;
            sidecar.requested_memory_bytes = want_mem;
            sidecar.save(inst)?;
            Journal::complete(inst)?;
        }
        if !start_after {
            return Ok(());
        }
        let Err(start_err) = self.start_existing(cfg, inst) else {
            return Ok(());
        };
        // Roll back only once the machine is provably stopped again.
        let machine = sidecar.machine_id.clone();
        let rolled_back = (|| -> Result<()> {
            let rec = rt.inspect_machine(&machine)?;
            if rec.status != MachineStatus::Stopped {
                bail!("machine is {}", rec.status.label());
            }
            let prior_mib = u32::try_from(prior.1 / (1024 * 1024)).context("prior memory")?;
            Self::apply_resources(rt, &machine, Some(prior.0), Some(prior_mib))?;
            sidecar.requested_cpus = prior.0;
            sidecar.requested_memory_bytes = prior.1;
            sidecar.save(inst)
        })();
        match rolled_back {
            Ok(()) => Err(start_err.context(
                "Instance failed to start with the new resources; previous CPU/memory restored",
            )),
            Err(rb) => Err(start_err.context(format!(
                "Instance failed to start with the new resources, and restoring the previous \
                 {} vCPUs / {} bytes did not complete: {rb:#}",
                prior.0, prior.1
            ))),
        }
    }

    fn commit_disk(
        &self,
        _cfg: &CoopConfig,
        _stopped: &StoppedInstance,
        _image: &ImageName,
    ) -> Result<()> {
        self.capabilities().require(self, Capability::DiskSnapshots)
    }

    fn restore_disk(
        &self,
        _cfg: &CoopConfig,
        _stopped: &StoppedInstance,
        _image: &ImageName,
    ) -> Result<()> {
        self.capabilities().require(self, Capability::DiskSnapshots)
    }

    fn is_running(&self, inst: &Instance) -> bool {
        let Ok(Some(sidecar)) = MachineSidecar::try_load(inst) else {
            return false;
        };
        self.runtime()
            .and_then(|rt| rt.inspect_machine(&sidecar.machine_id))
            .is_ok_and(|rec| rec.status == MachineStatus::Running)
    }

    fn as_running(&self, cfg: &CoopConfig, inst: Instance) -> Result<Option<RunningInstance>> {
        let sidecar = Self::owned_sidecar(cfg, &inst)?;
        let rt = self.runtime()?;
        let rec = rt.inspect_machine(&sidecar.machine_id)?;
        match rec.status {
            MachineStatus::Stopped => Ok(None),
            MachineStatus::Running => {
                // A running machine that cannot be handed out (unqualified
                // runtime, failed gate) is an error, never "not running":
                // callers must not report it stopped.
                let target = self
                    .target_for(cfg, &inst, &sidecar, rec)
                    .with_context(|| {
                        format!(
                            "Instance '{}' is running but cannot be reached safely; \
                             `coop stop {}` stops it without connecting to the guest",
                            inst.name, inst.name
                        )
                    })?;
                Ok(Some(RunningInstance::new(inst, target)))
            }
            other => bail!(AppleError::OperationUncertain(format!(
                "machine {} is {}",
                sidecar.machine_id,
                other.label()
            ))),
        }
    }

    fn as_stopped(&self, inst: Instance) -> Result<StoppedInstance> {
        let sidecar = MachineSidecar::load(&inst)?;
        let rec = self.runtime()?.inspect_machine(&sidecar.machine_id)?;
        match rec.status {
            MachineStatus::Stopped => Ok(StoppedInstance::new(inst)),
            MachineStatus::Running => bail!(
                "Instance '{}' is running — stop it first with `coop stop {}`",
                inst.name,
                inst.name,
            ),
            other => bail!(AppleError::OperationUncertain(format!(
                "machine {} is {}",
                sidecar.machine_id,
                other.label()
            ))),
        }
    }

    fn status(&self, cfg: &CoopConfig, running: &RunningInstance) -> Result<String> {
        use std::fmt::Write as _;
        let inst = running.instance();
        let sidecar = Self::owned_sidecar(cfg, inst)?;
        let rt = self.runtime()?;
        let rec = rt.inspect_machine(&sidecar.machine_id)?;
        let runtime = rt
            .qualification
            .as_ref()
            .map_or_else(|e| format!("unqualified ({e})"), |q| q.identity.clone());
        let ip = rec
            .ip
            .map_or_else(|| "unavailable".to_string(), |ip| ip.to_string());
        let mut out = format!(
            "Instance '{}' ({})\n\
             \x20 Backend: apple-container\n\
             \x20 Runtime: {runtime}\n\
             \x20 Machine: {}\n\
             \x20 Network: {} (dedicated)\n\
             \x20 vCPUs: {}\n\
             \x20 Memory: {} MiB\n\
             \x20 Address: {ip} (host key {})\n\
             \x20 Workspace: copied (no live mounts)\n\
             \x20 Unsupported: disk resize, commit/restore snapshots",
            inst.name,
            rec.status.label(),
            sidecar.machine_id,
            sidecar.network_id,
            rec.cpus,
            rec.memory_bytes / (1024 * 1024),
            sidecar.host_key_fingerprint,
        );
        match crate::backend::query_resource_usage(running.target()) {
            Some(usage) => {
                let _ = write!(out, "\n  {usage}");
            }
            None => out.push_str("\n  Guest usage: unavailable"),
        }
        Ok(out)
    }

    fn stream_logs(
        &self,
        cfg: &CoopConfig,
        running: &RunningInstance,
        mode: LogMode,
    ) -> Result<()> {
        use std::io::Write as _;
        let sidecar = Self::owned_sidecar(cfg, running.instance())?;
        let rt = self.runtime()?;
        let name = sidecar.machine_id.to_string();
        match mode {
            LogMode::Follow => {
                // Guest-controlled console output: replace control bytes on
                // every line before it reaches the operator's terminal.
                let args: Vec<String> = ["machine", "logs", "--follow", &name]
                    .into_iter()
                    .map(String::from)
                    .collect();
                let mut stdout = std::io::stdout().lock();
                let out = rt.exec.run_streaming(&args, &mut |line| {
                    writeln!(
                        stdout,
                        "{}",
                        cli::sanitize_for_display(&String::from_utf8_lossy(line))
                    )
                    .context("Failed to write logs")
                })?;
                if !out.success() {
                    bail!("`container machine logs` exited with {:?}", out.code);
                }
            }
            LogMode::Snapshot => {
                // Spool to a private file rather than memory, then print it
                // line by line with guest-controlled control bytes replaced.
                let spool = tempfile::NamedTempFile::new().context("Failed to create log spool")?;
                let req = Request::new(["machine", "logs", name.as_str()], rt.settings.boot, 0);
                let out = rt.exec.run_logged(&req, spool.path())?;
                if !out.success() {
                    bail!(
                        "`container machine logs` failed: {}",
                        cli::log_tail(spool.path(), 2048)
                    );
                }
                let reader = std::io::BufReader::new(
                    std::fs::File::open(spool.path()).context("Failed to read log spool")?,
                );
                let mut stdout = std::io::stdout().lock();
                for line in std::io::BufRead::split(reader, b'\n') {
                    let line = line.context("Failed to read log spool")?;
                    writeln!(
                        stdout,
                        "{}",
                        cli::sanitize_for_display(&String::from_utf8_lossy(&line))
                    )
                    .context("Failed to write logs")?;
                }
            }
        }
        Ok(())
    }

    fn ssh_target(&self, cfg: &CoopConfig, inst: &Instance) -> Result<SshTarget> {
        let sidecar = Self::owned_sidecar(cfg, inst)?;
        let rec = self.runtime()?.inspect_machine(&sidecar.machine_id)?;
        self.target_for(cfg, inst, &sidecar, rec)
    }

    fn disk_path(&self, _inst: &Instance) -> Result<PathBuf> {
        self.capabilities()
            .require(self, Capability::DiskResize)
            .map(|()| PathBuf::new())
    }

    fn local_endpoint_route(&self, _network: &NetworkConfig) -> LocalEndpointRoute {
        LocalEndpointRoute::ReverseTunnel
    }

    fn image_is_built(&self, cfg: &CoopConfig, image: &ImageName) -> bool {
        let Ok(Some(manifest)) = ImageManifest::try_load(cfg, image) else {
            return false;
        };
        self.runtime()
            .and_then(|rt| rt.verify_image(&manifest))
            .is_ok()
    }
}

/// Generate the VM-access keypair under the backend root if missing.
fn ensure_ssh_key(cfg: &CoopConfig) -> Result<()> {
    let key_path = cfg.ssh_key_path();
    if key_path.exists() {
        return Ok(());
    }
    crate::cmd::Cmd::new("/usr/bin/ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-C", "coop-apple", "-f"])
        .arg(&key_path)
        .run()
        .context("Failed to generate the VM access key")
}

/// Build `image_ref` from `context` (output to `log`), then verify it in a
/// disposable machine. Returns the built digest.
fn build_and_verify_image(
    rt: &Runtime,
    owner: &Owner,
    image_ref: &str,
    context: &tempfile::TempDir,
    log: &Path,
    timeout: Duration,
    guest_user: &crate::guest::GuestUser,
) -> Result<String> {
    let build = Request::new(
        [
            "build".to_string(),
            "--platform".into(),
            image::PLATFORM.into(),
            "--progress".into(),
            "plain".into(),
            "-t".into(),
            image_ref.to_string(),
            context.path().display().to_string(),
        ],
        timeout,
        0,
    )
    .cancellable();
    let out = rt.exec.run_logged(&build, log)?;
    if !out.success() {
        bail!(
            "Image build failed. Last lines of {}:\n{}",
            log.display(),
            cli::log_tail(log, 4096)
        );
    }
    let digest = rt.image_digest(image_ref)?;
    verify_image_in_machine(rt, owner, image_ref, guest_user)?;
    Ok(digest)
}

/// Delete a superseded owned image tag unless an instance still records it.
fn prune_superseded_image(rt: &Runtime, cfg: &CoopConfig, owner: &Owner, image_ref: &str) {
    if !image_ref.starts_with(&format!("local/coop-{}:", owner.id.short())) {
        return;
    }
    let in_use = cfg.list_instances().map_or(true, |instances| {
        instances.iter().any(|inst| {
            MachineSidecar::try_load(inst)
                .map_or(true, |s| s.is_some_and(|s| s.image_ref == image_ref))
        })
    });
    if in_use {
        tracing::debug!("Keeping superseded image {image_ref}: an instance may still use it");
        return;
    }
    rt.delete_image_best_effort(image_ref);
}

/// Boot the candidate image in a disposable, owned, isolated machine with no
/// credentials, check the guest contract, and always clean up.
fn verify_image_in_machine(
    rt: &Runtime,
    owner: &Owner,
    image_ref: &str,
    guest_user: &crate::guest::GuestUser,
) -> Result<()> {
    let machine = MachineName::generate(&owner.id)?;
    tracing::info!("Verifying image in disposable machine {machine}");
    let result = (|| -> Result<()> {
        rt.create_network(&machine, owner)?;
        rt.create_machine(
            &machine,
            &machine,
            NonZeroU8::new(2).context("2 vCPUs")?,
            2048,
            image_ref,
        )?;
        let rec = rt.inspect_machine(&machine)?;
        security::verify_machine_config(&rec, &machine)?;
        let deadline = Instant::now() + rt.settings.boot;
        rt.boot(&machine)?;
        let (ready, _) = rt.wait_ready(&machine, &machine, deadline)?;
        rt.read_host_key(&ready, deadline)?;
        let wanted: Vec<String> = crate::guest::required_guest_binaries(guest_user)
            .iter()
            .map(ToString::to_string)
            .collect();
        let missing = rt.missing_executables(&machine, &wanted)?;
        crate::guest::verify_required_binaries(
            guest_user,
            "image build",
            |path| !missing.iter().any(|m| m == path.as_ref()),
            String::new,
        )?;
        // Services get their own window: docker is often still starting
        // when the boot deadline's readiness checks have finished.
        rt.wait_for_services(
            &machine,
            &["ssh", "docker"],
            Instant::now() + rt.settings.boot,
        )?;
        Ok(())
    })();
    let cleanup = (|| -> Result<()> {
        if rt.machine_exists(&machine)? {
            let rec = rt.inspect_machine(&machine)?;
            if rec.status != MachineStatus::Stopped {
                rt.stop_and_confirm(&machine)?;
            }
            rt.delete_machine(&machine)?;
        }
        if rt.network_exists(&machine)? {
            rt.delete_network(&machine)?;
        }
        Ok(())
    })();
    if let Err(e) = &cleanup {
        tracing::warn!("Failed to clean up verification machine {machine}: {e:#}");
    }
    result
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    //! Backend tests against a scripted runtime.

    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;

    use super::cli::{Exec, Output, Request};
    use super::*;
    use crate::config::{ConfigPath, ImageName, InstanceIndex, InstanceName};

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/apple-container"
    );

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
    }

    type Responder = Box<dyn Fn(&[String]) -> Output>;

    /// Records every argument vector and answers from a responder.
    struct FakeExec {
        calls: Rc<RefCell<Vec<Vec<String>>>>,
        respond: Responder,
    }

    impl Exec for FakeExec {
        fn run(&self, req: &Request) -> Result<Output> {
            self.calls.borrow_mut().push(req.args.clone());
            Ok((self.respond)(&req.args))
        }

        fn run_logged(&self, req: &Request, _log: &Path) -> Result<Output> {
            self.run(req)
        }

        fn run_streaming(
            &self,
            args: &[String],
            on_line: &mut dyn FnMut(&[u8]) -> Result<()>,
        ) -> Result<Output> {
            self.calls.borrow_mut().push(args.to_vec());
            let out = (self.respond)(args);
            for line in out.stdout.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                on_line(line)?;
            }
            Ok(out)
        }
    }

    fn ok(stdout: &str) -> Output {
        Output {
            code: Some(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn fail(stderr: &str) -> Output {
        Output {
            code: Some(1),
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn starts(args: &[String], prefix: &[&str]) -> bool {
        args.len() >= prefix.len() && args.iter().zip(prefix).all(|(a, p)| a == p)
    }

    /// Responses shared by every scenario: version, help, service status.
    fn base_response(args: &[String], extended: bool) -> Option<Output> {
        if starts(args, &["--version"]) {
            return Some(ok(&fixture("version-1.4.1.txt")));
        }
        if starts(args, &["machine", "create", "--help"]) {
            let help = fixture("machine-create-help-1.4.1.txt");
            let help = if extended {
                help.replace(
                    "  --home-mount <home-mount>",
                    "  --network <network>     Network\n  --no-ssh-agent          No agent\n  --home-mount <home-mount>",
                )
            } else {
                help
            };
            return Some(ok(&help));
        }
        if starts(args, &["system", "status"]) {
            return Some(ok("apiserver is running"));
        }
        None
    }

    fn backend(respond: Responder) -> (AppleContainerBackend, Rc<RefCell<Vec<Vec<String>>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let exec = FakeExec {
            calls: Rc::clone(&calls),
            respond,
        };
        (AppleContainerBackend::with_exec(Box::new(exec)), calls)
    }

    fn test_cfg(dir: &Path) -> CoopConfig {
        CoopConfig {
            data_dir: ConfigPath::new(dir),
            ..CoopConfig::default()
        }
    }

    fn test_inst(cfg: &CoopConfig) -> Instance {
        let dir = cfg.instances_dir().join("t");
        std::fs::create_dir_all(&dir).unwrap();
        Instance {
            name: InstanceName::new("t").unwrap(),
            index: InstanceIndex::new(0).unwrap(),
            dir,
            image: ImageName::new("default").unwrap(),
        }
    }

    /// The machine init script runs `$SHELL -c "$*"` over the words after
    /// `--`; the rendered command must reach the guest with its argv intact.
    #[test]
    fn machine_run_args_survive_the_guest_shell() {
        let name = MachineName::new("coop-0a1b2c3d-00112233445566ff").unwrap();
        let words = [
            "/usr/bin/printf",
            "%s\\n",
            "a b",
            "it's",
            "$(id)",
            "; true",
            "",
        ];
        let args = machine_run_args(&name, &words);
        let (fixed, rest) = args.split_at(6);
        assert_eq!(
            fixed,
            ["machine", "run", "--root", "-n", name.as_str(), "--"]
        );
        assert_eq!(rest.len(), 1, "command must be a single word: {rest:?}");
        let command = rest.first().unwrap();
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", r#"exec /bin/sh -c "$*""#, "init"])
            .arg(command)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "a b\nit's\n$(id)\n; true\n\n"
        );
    }

    /// Commands that change runtime state. None may run before the gate passes.
    fn is_mutating(args: &[String]) -> bool {
        [
            &["network", "create"][..],
            &["network", "delete"],
            &["machine", "create", "--no-boot"],
            &["machine", "run"],
            &["machine", "set"],
            &["machine", "stop"],
            &["machine", "delete"],
            &["build"],
            &["image", "delete"],
            &["system", "start"],
            &["system", "stop"],
        ]
        .iter()
        .any(|p| starts(args, p))
    }

    #[test]
    fn stock_runtime_refuses_create_before_any_side_effect() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let (be, calls) = backend(Box::new(|args| {
            base_response(args, false).unwrap_or_else(|| ok("[]"))
        }));
        let err = be.create_and_start(&cfg, &inst, None, &[]).unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<AppleError>(),
                Some(AppleError::RuntimeUnqualified(_))
            ),
            "{err:#}"
        );
        let calls = calls.borrow();
        assert!(calls.iter().all(|c| !is_mutating(c)), "{calls:?}");
        assert!(!MachineSidecar::path(&inst).exists());
        assert!(Journal::try_load(&inst).unwrap().is_none());
    }

    #[test]
    fn stock_runtime_refuses_ssh_target_and_start() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let (be, calls) = backend(Box::new(|args| {
            base_response(args, false).unwrap_or_else(|| ok(&fixture("machine-inspect-1.4.1.json")))
        }));
        assert!(be.ssh_target(&cfg, &inst).is_err());
        assert!(be.start_existing(&cfg, &inst).is_err());
        assert!(calls.borrow().iter().all(|c| !is_mutating(c)));
    }

    #[test]
    fn explicit_disk_request_is_rejected_first() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let inst = test_inst(&cfg);
        let (be, calls) = backend(Box::new(|_| ok("")));
        let err = be
            .create_and_start(&cfg, &inst, Some(GiB::new(50).unwrap()), &[])
            .unwrap_err();
        assert!(
            err.downcast_ref::<crate::backend::UnsupportedCapability>()
                .is_some()
        );
        assert!(calls.borrow().is_empty());
        assert!(be.disk_path(&inst).is_err());
    }

    fn machine_name(owner: &Owner) -> MachineName {
        MachineName::new(format!("coop-{}-00112233445566ff", owner.id.short())).unwrap()
    }

    fn write_sidecar(inst: &Instance, owner: &Owner) -> MachineSidecar {
        let name = machine_name(owner);
        let sidecar = MachineSidecar {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            owner_id: owner.id.clone(),
            instance_id: "00112233445566ff".into(),
            machine_id: name.clone(),
            network_id: name,
            image_ref: "local/coop-x:0".into(),
            image_digest: format!("sha256:{}", "0".repeat(64)),
            image_manifest_id: "m".into(),
            guest_user: crate::guest::GuestUser::default(),
            requested_cpus: 2,
            requested_memory_bytes: 1 << 32,
            host_key_fingerprint: "SHA256:x".into(),
            last_observed_container_id: None,
            last_observed_ip: None,
            creation_state: CreationState::Ready,
            created_at: "now".into(),
            runtime_identity: "test".into(),
        };
        sidecar.save(inst).unwrap();
        sidecar
    }

    /// An inspect record for `name` in `status`, with the extension policy.
    fn inspect_json(name: &MachineName, status: &str) -> String {
        fixture("machine-inspect-extended.json")
            .replace("coop-0a1b2c3d-00112233445566ff", name.as_str())
            .replace("\"stopped\"", &format!("\"{status}\""))
    }

    #[test]
    fn liveness_probe_errors_are_not_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);

        let (be, _) = backend(Box::new(|args| {
            base_response(args, true).unwrap_or_else(|| fail("XPC connection interrupted"))
        }));
        assert!(be.as_stopped(inst.clone()).is_err());
        assert!(be.as_running(&cfg, inst.clone()).is_err());
        assert!(!be.is_running(&inst));

        let name = machine_name(&owner);
        for (status, stopped_ok) in [("stopping", false), ("unknown", false), ("stopped", true)] {
            let json = inspect_json(&name, status);
            let (be, _) = backend(Box::new(move |args| {
                base_response(args, true).unwrap_or_else(|| ok(&json))
            }));
            assert_eq!(be.as_stopped(inst.clone()).is_ok(), stopped_ok, "{status}");
        }
    }

    #[test]
    fn destroy_refuses_unowned_machine() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let mut sidecar = write_sidecar(&inst, &owner);
        sidecar.machine_id = MachineName::new("users-own-machine").unwrap();
        sidecar.save(&inst).unwrap();
        let (be, calls) = backend(Box::new(|args| {
            base_response(args, true).unwrap_or_else(|| ok("[]"))
        }));
        let err = be.destroy_instance(&cfg, &inst).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::IdentityConflict(_))
        ));
        assert!(calls.borrow().iter().all(|c| !is_mutating(c)));
        assert!(inst.dir.exists(), "metadata must survive a refused destroy");
    }

    #[test]
    fn destroy_reconciles_interrupted_create() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let name = machine_name(&owner);
        let mut journal =
            Journal::begin(&inst, &owner, Operation::Create, name.clone(), name.clone()).unwrap();
        journal.advance(&inst, Stage::CreatingMachine).unwrap();

        let net = name.to_string();
        let (be, calls) = backend(Box::new(move |args| {
            if let Some(o) = base_response(args, true) {
                return o;
            }
            if starts(args, &["machine", "list"]) {
                // The machine create never landed; an unrelated machine exists.
                return ok(&fixture("machine-list-1.4.1.json"));
            }
            if starts(args, &["network", "list"]) {
                return ok(&format!(r#"[{{"id":"default"}},{{"id":"{net}"}}]"#));
            }
            if starts(args, &["network", "delete"]) {
                return ok("");
            }
            fail("unexpected")
        }));
        be.destroy_instance(&cfg, &inst).unwrap();
        let calls = calls.borrow();
        let mutating: Vec<&Vec<String>> = calls.iter().filter(|c| is_mutating(c)).collect();
        assert_eq!(
            mutating,
            [&vec![
                "network".to_string(),
                "delete".into(),
                name.to_string()
            ]]
        );
        assert!(!inst.dir.exists());
    }

    #[test]
    fn destroy_stops_then_deletes_owned_machine() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let name = machine_name(&owner);
        let stopped = Rc::new(RefCell::new(false));
        let deleted = Rc::new(RefCell::new(false));
        let (s2, d2, n2) = (Rc::clone(&stopped), Rc::clone(&deleted), name.clone());
        let (be, calls) = backend(Box::new(move |args| {
            if let Some(o) = base_response(args, true) {
                return o;
            }
            if starts(args, &["machine", "list"]) {
                let rows = if *d2.borrow() {
                    "[]".to_string()
                } else {
                    format!(r#"[{{"id":"{n2}","status":"running"}}]"#)
                };
                return ok(&rows);
            }
            if starts(args, &["machine", "inspect"]) {
                let status = if *s2.borrow() { "stopped" } else { "running" };
                return ok(&inspect_json(&n2, status));
            }
            if starts(args, &["machine", "stop"]) {
                *s2.borrow_mut() = true;
                return ok("");
            }
            if starts(args, &["machine", "delete"]) {
                *d2.borrow_mut() = true;
                return ok("");
            }
            if starts(args, &["network", "list"]) {
                return ok(r#"[{"id":"default"}]"#);
            }
            fail("unexpected")
        }));
        be.destroy_instance(&cfg, &inst).unwrap();
        let order: Vec<String> = calls
            .borrow()
            .iter()
            .filter(|c| is_mutating(c))
            .map(|c| c[..2].join(" "))
            .collect();
        assert_eq!(order, ["machine stop", "machine delete"]);
        assert!(!inst.dir.exists());
    }

    #[test]
    fn stop_timeout_is_uncertain_not_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let name = machine_name(&owner);
        let json = inspect_json(&name, "stopping");
        let (be, _) = backend(Box::new(move |args| {
            base_response(args, true).unwrap_or_else(|| ok(&json))
        }));
        let rt = be.runtime().unwrap();
        let rt = Runtime {
            exec: Box::new(FakeExec {
                calls: Rc::new(RefCell::new(Vec::new())),
                respond: Box::new({
                    let json = inspect_json(&name, "stopping");
                    move |_| ok(&json)
                }),
            }),
            settings: Settings {
                stop: Duration::from_millis(300),
                ..rt.settings.clone()
            },
            qualification: Err(AppleError::RuntimeUnavailable(String::new())),
            service_ready: std::cell::Cell::new(false),
        };
        let err = rt.stop_and_confirm(&name).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::OperationUncertain(_))
        ));
    }

    #[test]
    fn create_args_request_isolation_and_exact_units() {
        let name = MachineName::new("coop-0a1b2c3d-00112233445566ff").unwrap();
        let args = create_machine_args(
            &name,
            &name,
            NonZeroU8::new(4).unwrap(),
            4096,
            "local/coop-0a1b2c3d:00",
        );
        let joined = args.join(" ");
        assert!(joined.contains("--no-boot"));
        assert!(joined.contains("--home-mount none"));
        assert!(joined.contains(&format!("--network {name}")));
        assert!(joined.contains("--no-ssh-agent"));
        assert!(joined.contains("--memory 4096mb"));
        assert!(!joined.contains("--set-default"));
        assert_eq!(mib_to_bytes(4096), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn capabilities_block_disk_operations() {
        let be = AppleContainerBackend::new();
        let caps = be.capabilities();
        for cap in [
            Capability::LiveMounts,
            Capability::DiskResize,
            Capability::DiskSnapshots,
        ] {
            assert!(!caps.has(cap), "{cap:?}");
        }
        assert!(caps.has(Capability::MachineResources));
        assert!(!be.mounts_are_live());
        assert_eq!(
            be.local_endpoint_route(&NetworkConfig::default()),
            LocalEndpointRoute::ReverseTunnel
        );
    }

    #[test]
    fn resolve_binary_rejects_relative_and_missing() {
        assert!(resolve_binary(Some(Path::new("container"))).is_err());
        assert!(resolve_binary(Some(Path::new("/nonexistent/container"))).is_err());
        let tmp = tempfile::tempdir().unwrap();
        let writable = tmp.path().join("container");
        std::fs::write(&writable, "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let err = resolve_binary(Some(&writable)).unwrap_err();
        assert!(format!("{err:#}").contains("writable"), "{err:#}");
    }

    #[test]
    fn interrupted_resize_is_reconciled_from_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let sidecar = write_sidecar(&inst, &owner);
        let name = machine_name(&owner);
        let mut journal = Journal::begin(
            &inst,
            &owner,
            Operation::SetResources,
            name.clone(),
            name.clone(),
        )
        .unwrap();
        journal.advance(&inst, Stage::Applying).unwrap();

        let json = inspect_json(&name, "stopped");
        let (be, calls) = backend(Box::new(move |args| {
            base_response(args, true).unwrap_or_else(|| ok(&json))
        }));
        let rt = be.runtime().unwrap();
        AppleContainerBackend::recover_resources(rt, &cfg, &inst).unwrap();
        assert!(Journal::try_load(&inst).unwrap().is_none());
        let after = MachineSidecar::load(&inst).unwrap();
        // The extended fixture reports 2 vCPUs / 4 GiB.
        assert_eq!(after.requested_cpus, 2);
        assert_eq!(after.requested_memory_bytes, 4 * 1024 * 1024 * 1024);
        assert_eq!(after.machine_id, sidecar.machine_id);
        assert!(calls.borrow().iter().all(|c| !is_mutating(c)));

        // A running machine is not reconciled.
        let mut journal = Journal::begin(
            &inst,
            &owner,
            Operation::SetResources,
            name.clone(),
            name.clone(),
        )
        .unwrap();
        journal.advance(&inst, Stage::Applying).unwrap();
        let json = inspect_json(&name, "running");
        let (be, _) = backend(Box::new(move |args| {
            base_response(args, true).unwrap_or_else(|| ok(&json))
        }));
        let rt = be.runtime().unwrap();
        assert!(AppleContainerBackend::recover_resources(rt, &cfg, &inst).is_err());
        assert!(Journal::try_load(&inst).unwrap().is_some());
    }

    #[test]
    fn failed_restart_boot_stops_the_machine_and_reports_the_boot_log() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let name = machine_name(&owner);
        let json = inspect_json(&name, "stopped");
        let net = name.to_string();
        let (be, calls) = backend(Box::new(move |args| {
            if let Some(o) = base_response(args, true) {
                return o;
            }
            if starts(args, &["machine", "inspect"]) {
                return ok(&json);
            }
            if starts(args, &["network", "list"]) {
                return ok(&format!(r#"[{{"id":"{net}"}}]"#));
            }
            if starts(args, &["machine", "run"]) {
                return fail("boot failed: vminitd exited");
            }
            if starts(args, &["machine", "logs", "--boot"]) {
                return ok("kernel panic \x1b[31m- not syncing\n");
            }
            if starts(args, &["machine", "stop"]) {
                return ok("");
            }
            fail("unexpected")
        }));
        let err = be.start_existing(&cfg, &inst).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("APPLE_BOOT_TIMEOUT"), "{msg}");
        assert!(msg.contains("kernel panic ?[31m- not syncing"), "{msg}");
        let order: Vec<String> = calls
            .borrow()
            .iter()
            .filter(|c| is_mutating(c))
            .map(|c| c[..2].join(" "))
            .collect();
        assert_eq!(order, ["machine run", "machine stop"]);
    }

    #[test]
    #[expect(clippy::panic, reason = "test assertion")]
    fn unqualified_running_machine_is_an_error_not_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let json = inspect_json(&machine_name(&owner), "running");
        let (be, _) = backend(Box::new(move |args| {
            base_response(args, false).unwrap_or_else(|| ok(&json))
        }));
        let Err(err) = be.as_running(&cfg, inst.clone()) else {
            panic!("a running machine on an unqualified runtime must not yield a target");
        };
        assert!(format!("{err:#}").contains("coop stop t"), "{err:#}");
    }

    #[test]
    fn stop_unproven_stops_without_qualification_or_ssh() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let name = machine_name(&owner);
        let stopped = Rc::new(RefCell::new(false));
        let (s2, n2) = (Rc::clone(&stopped), name.clone());
        // Stock (unqualified) runtime: only control-plane calls are made.
        let (be, calls) = backend(Box::new(move |args| {
            if let Some(o) = base_response(args, false) {
                return o;
            }
            if starts(args, &["machine", "inspect"]) {
                let status = if *s2.borrow() { "stopped" } else { "running" };
                return ok(&inspect_json(&n2, status));
            }
            if starts(args, &["machine", "stop"]) {
                *s2.borrow_mut() = true;
                return ok("");
            }
            fail("unexpected")
        }));
        be.stop_unproven(&cfg, &inst).unwrap();
        assert!(*stopped.borrow());
        let mutating: Vec<String> = calls
            .borrow()
            .iter()
            .filter(|c| is_mutating(c))
            .map(|c| c[..2].join(" "))
            .collect();
        assert_eq!(mutating, ["machine stop"]);
    }

    #[test]
    fn follow_logs_replace_guest_control_bytes() {
        // `stream_logs` needs a RunningInstance, which cannot be minted without
        // SSH here, so this drives the same streaming call and sanitizer it uses.
        let (be, _) = backend(Box::new(|args| {
            if starts(args, &["machine", "logs"]) {
                return ok("ok\n\x1b]52;c;ZXZpbA==\x07pwned\n");
            }
            fail("unexpected")
        }));
        let rt = be.runtime().unwrap();
        let mut lines = Vec::new();
        rt.exec
            .run_streaming(
                &[
                    "machine".into(),
                    "logs".into(),
                    "--follow".into(),
                    "m".into(),
                ],
                &mut |line| {
                    lines.push(cli::sanitize_for_display(&String::from_utf8_lossy(line)));
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(lines, ["ok", "?]52;c;ZXZpbA==?pwned"]);
    }

    #[test]
    fn host_key_read_retries_a_half_written_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let name = machine_name(&owner);
        let reads = Rc::new(RefCell::new(0));
        let (r2, n2) = (Rc::clone(&reads), name.clone());
        let cid = format!("{name}-abc123");
        let cid2 = cid.clone();
        let (be, _) = backend(Box::new(move |args| {
            if let Some(o) = base_response(args, true) {
                return o;
            }
            if starts(args, &["machine", "run"]) {
                *r2.borrow_mut() += 1;
                // First read catches the file mid-write.
                return if *r2.borrow() == 1 {
                    ok("ssh-ed25519 AAAAC3Nza")
                } else {
                    ok(
                        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINiqkOnkRV06x+SuorkF+O3KdBTVFznIV0+b58cidW1N root@guest\n",
                    )
                };
            }
            if starts(args, &["machine", "inspect"]) {
                return ok(&inspect_json(&n2, "running").replace(
                    "\"cpus\"",
                    &format!("\"containerId\" : \"{cid2}\",\n    \"cpus\""),
                ));
            }
            fail("unexpected")
        }));
        let rt = be.runtime().unwrap();
        let json = inspect_json(&name, "running").replace(
            "\"cpus\"",
            &format!("\"containerId\" : \"{cid}\",\n    \"cpus\""),
        );
        let rec = protocol::parse_machine_inspect(&json, &name).unwrap();
        let container = protocol::ContainerRecord {
            id: cid.clone(),
            mounts: Vec::new(),
            configured_networks: vec![name.to_string()],
            attached_networks: vec![name.to_string()],
            ssh_agent_forwarding: false,
        };
        let ready = security::verify_effective(&rec, &container, &name).unwrap();
        let key = rt
            .read_host_key(&ready, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(key.fingerprint().starts_with("SHA256:"));
        assert_eq!(*reads.borrow(), 2);
    }
}
