//! Apple sandbox backend (`apple-container` feature, macOS only).
//!
//! Runs each coop instance as a persistent `coop-sandbox` VM
//! (`macos/coop-sandbox`, built on `apple/containerization`): one VM per
//! instance, each on its own vmnet network, with no host mounts, socket
//! relays, published ports, or SSH-agent forwarding. coop reuses its SSH-based
//! guest operations over a pinned per-instance host key. Workspaces are
//! copied, never live-mounted.
//!
//! Images are built from a generated Dockerfile by the stock Apple
//! `container` CLI (`container build`) and imported into the runtime's
//! private store. Every path that boots a guest or hands one out first
//! qualifies the runtime and passes the isolation gate (`security`); cleanup
//! of owned resources works without either.

mod cli;
mod image;
mod protocol;
mod security;
mod ssh;
mod state;

use std::cell::OnceCell;
use std::collections::HashSet;
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
use image::{BuildContext, BuildInputs, CommittedDisk, ImageManifest};
use protocol::{Inspect, SandboxStatus};
use security::{Expected, QualifiedRuntime, SecurityReady};
use state::{
    CreationState, Journal, JournalOp, MachineName, MachineSidecar, Operation, Owner, Stage,
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

/// Install locations searched for `coop-sandbox` when `[apple_container]
/// binary` is unset; the first is `scripts/build-coop-sandbox.sh`'s default.
fn default_runtimes() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        v.push(PathBuf::from(home).join(".local/opt/coop-sandbox/bin/coop-sandbox"));
    }
    v.push("/usr/local/bin/coop-sandbox".into());
    v.push("/opt/homebrew/bin/coop-sandbox".into());
    v
}

/// Install locations searched for the stock image builder.
const DEFAULT_BUILDERS: &[&str] = &["/usr/local/bin/container", "/opt/homebrew/bin/container"];

/// Where stock Apple `container` installs its default guest kernel.
fn default_kernel() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library/Application Support/com.apple.container/kernels/default.kernel-arm64")
    })
}

/// Oldest macOS release `apple/containerization`'s vmnet networks support.
const MIN_MACOS_MAJOR: u32 = 26;

/// Name of the runtime state root under the backend's state directory.
const RUNTIME_DIR: &str = "runtime";

/// Settings from `[apple_container]`, plus the runtime state root.
#[derive(Debug, Clone)]
struct Settings {
    binary: Option<PathBuf>,
    builder: Option<PathBuf>,
    kernel: Option<PathBuf>,
    runtime_root: PathBuf,
    probe: Duration,
    operation: Duration,
    create: Duration,
    boot: Duration,
    stop: Duration,
    build: Duration,
}

impl Settings {
    fn new(cfg: &AppleContainerConfig, state_root: &Path) -> Self {
        Self {
            binary: cfg.binary.as_ref().map(|p| p.to_path_buf()),
            builder: cfg.builder.as_ref().map(|p| p.to_path_buf()),
            kernel: cfg.kernel.as_ref().map(|p| p.to_path_buf()),
            runtime_root: state_root.join(RUNTIME_DIR),
            probe: cfg.probe_timeout_seconds.duration(),
            operation: cfg.operation_timeout_seconds.duration(),
            create: cfg.create_timeout_seconds.duration(),
            boot: cfg.boot_timeout_seconds.duration(),
            stop: cfg.stop_timeout_seconds.duration(),
            build: cfg.build_timeout_seconds.duration(),
        }
    }
}

/// A resolved `coop-sandbox` plus what qualification found. Qualification
/// failure is kept (not raised) so cleanup of owned resources still works on
/// an unqualified runtime; every path that boots or hands out a guest calls
/// [`Runtime::qualified`] first.
struct Runtime {
    exec: Box<dyn Exec>,
    settings: Settings,
    /// Canonical runtime state root, passed as `--root` on every call. The
    /// runtime reports paths under it, and the gate compares them exactly.
    root: PathBuf,
    qualification: std::result::Result<QualifiedRuntime, AppleError>,
}

/// The stock `container` CLI, used only to build images.
struct Builder {
    exec: Box<dyn Exec>,
}

pub struct AppleContainerBackend {
    settings: Settings,
    runtime: OnceCell<Runtime>,
    builder: OnceCell<Builder>,
    /// Runtime executor substituted by tests, taken on first use.
    #[cfg(test)]
    injected: std::cell::RefCell<Option<Box<dyn Exec>>>,
}

impl AppleContainerBackend {
    /// Backend with default `[apple_container]` settings.
    pub fn new() -> Self {
        Self::for_config(&CoopConfig::default())
    }

    /// Backend honouring the configured binaries, state root, and deadlines.
    pub fn for_config(cfg: &CoopConfig) -> Self {
        Self {
            settings: Settings::new(&cfg.apple_container, &cfg.state_root()),
            runtime: OnceCell::new(),
            builder: OnceCell::new(),
            #[cfg(test)]
            injected: std::cell::RefCell::new(None),
        }
    }

    #[cfg(test)]
    fn with_exec(cfg: &CoopConfig, runtime: Box<dyn Exec>, builder: Box<dyn Exec>) -> Self {
        let be = Self::for_config(cfg);
        *be.injected.borrow_mut() = Some(runtime);
        let _ = be.builder.set(Builder { exec: builder });
        be
    }

    /// The runtime, resolved and probed once per process.
    fn runtime(&self) -> Result<&Runtime> {
        if let Some(rt) = self.runtime.get() {
            return Ok(rt);
        }
        #[cfg(test)]
        let injected = self.injected.borrow_mut().take();
        #[cfg(not(test))]
        let injected: Option<Box<dyn Exec>> = None;
        let exec = match injected {
            Some(exec) => exec,
            None => Box::new(RealExec::new(resolve_binary(
                self.settings.binary.as_deref(),
                &default_runtimes(),
                Tool::Runtime,
            )?)),
        };
        let mut rt = Runtime {
            exec,
            settings: self.settings.clone(),
            root: canonical_path(&self.settings.runtime_root),
            qualification: Err(AppleError::RuntimeUnavailable(String::new())),
        };
        rt.qualification = rt
            .probe_qualification()
            .map_err(|e| match e.downcast::<AppleError>() {
                Ok(apple) => apple,
                Err(other) => AppleError::RuntimeUnavailable(format!("{other:#}")),
            });
        Ok(self.runtime.get_or_init(|| rt))
    }

    /// Runtime that passed qualification.
    fn qualified_runtime(&self) -> Result<(&Runtime, &QualifiedRuntime)> {
        let rt = self.runtime()?;
        let q = rt.qualified()?;
        Ok((rt, q))
    }

    /// The stock image builder, with its service running.
    fn builder(&self) -> Result<&Builder> {
        if let Some(b) = self.builder.get() {
            return Ok(b);
        }
        let binary = resolve_binary(
            self.settings.builder.as_deref(),
            &DEFAULT_BUILDERS
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>(),
            Tool::Builder,
        )?;
        Ok(self.builder.get_or_init(|| Builder {
            exec: Box::new(RealExec::new(binary)),
        }))
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

/// The two binaries the backend runs.
#[derive(Debug, Clone, Copy)]
enum Tool {
    /// `coop-sandbox`.
    Runtime,
    /// Stock Apple `container`, for image builds.
    Builder,
}

impl Tool {
    fn name(self) -> &'static str {
        match self {
            Self::Runtime => "coop-sandbox",
            Self::Builder => "container",
        }
    }

    fn install_hint(self) -> &'static str {
        match self {
            Self::Runtime => {
                "Build it with scripts/build-coop-sandbox.sh, or set `[apple_container] binary`."
            }
            Self::Builder => {
                "Install Apple `container` 1.4.1 or later, or set `[apple_container] builder`."
            }
        }
    }
}

/// Resolve a binary to an absolute, host-owned executable. Only the user's
/// own config or fixed install paths are consulted — never `PATH` or anything
/// a project supplies — so a project cannot choose the runtime.
fn resolve_binary(configured: Option<&Path>, defaults: &[PathBuf], tool: Tool) -> Result<PathBuf> {
    let candidates: Vec<PathBuf> = match configured {
        Some(p) => vec![p.to_path_buf()],
        None => defaults.to_vec(),
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
        "no usable `{}` found{detail}. {}",
        tool.name(),
        tool.install_hint()
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

/// `path` with its longest existing ancestor canonicalized, so it reads the
/// same before and after the missing tail is created (matching
/// `coop-sandbox`, which canonicalizes its root the same way).
fn canonical_path(path: &Path) -> PathBuf {
    if let Ok(real) = path.canonicalize() {
        return real;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonical_path(parent).join(name),
        _ => path.to_path_buf(),
    }
}

/// Apple Silicon and a supported macOS release.
fn check_platform() -> Result<()> {
    if !cfg!(target_arch = "aarch64") {
        bail!(AppleError::RuntimeUnavailable(
            "the Apple sandbox backend requires an Apple Silicon Mac".into()
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
            "the Apple sandbox backend requires macOS {MIN_MACOS_MAJOR} or later (found {})",
            text.trim()
        )));
    }
    Ok(())
}

// ── Runtime operations ────────────────────────────────────────

/// What a new sandbox clones.
enum Source<'a> {
    Image(&'a str),
    Disk(&'a MachineName),
}

impl Runtime {
    fn qualified(&self) -> Result<&QualifiedRuntime> {
        self.qualification.as_ref().map_err(|e| e.clone().into())
    }

    fn probe_qualification(&self) -> Result<QualifiedRuntime> {
        let json = self.text(["version"], self.settings.probe, MAX_TEXT_OUTPUT)?;
        security::qualify(&protocol::parse_version(&json)?)
    }

    /// `<subcommand...> --root <root> <rest...>`.
    fn args(&self, sub: &[&str], rest: &[&str]) -> Vec<String> {
        sub.iter()
            .map(|s| (*s).to_string())
            .chain(["--root".to_string(), self.root.display().to_string()])
            .chain(rest.iter().map(|s| (*s).to_string()))
            .collect()
    }

    /// Run a command that must succeed; return its stdout.
    fn text<I, S>(&self, args: I, timeout: Duration, max: usize) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.checked(&Request::new(args, timeout, max))
    }

    /// Run `req`, which must succeed; return its stdout.
    fn checked(&self, req: &Request) -> Result<String> {
        let out = self.exec.run(req)?;
        if !out.success() {
            bail!(
                "`coop-sandbox {}` failed: {}",
                req.describe(),
                out.stderr_summary()
            );
        }
        Ok(out.stdout_str()?.to_string())
    }

    fn expected<'a>(&'a self, sidecar: &'a MachineSidecar) -> Expected<'a> {
        Expected {
            sandbox: &sidecar.machine_id,
            owner: sidecar.owner_id.as_str(),
            runtime_root: &self.root,
            cpus: sidecar.requested_cpus,
            memory_bytes: sidecar.requested_memory_bytes,
        }
    }

    fn init(&self, kernel: &Path) -> Result<()> {
        state::ensure_private_dir(&self.root)?;
        let kernel = kernel.display().to_string();
        // The first init pulls the pinned init image; later ones are no-ops.
        self.text(
            self.args(&["init"], &["--kernel", &kernel]),
            self.settings.create,
            MAX_TEXT_OUTPUT,
        )?;
        Ok(())
    }

    fn inspect(&self, name: &MachineName) -> Result<Inspect> {
        let json = self.text(
            self.args(&["inspect"], &[name.as_str()]),
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        protocol::parse_inspect(&json, name)
    }

    /// Whether the runtime lists `name`. A failed listing is an error, never
    /// "absent".
    fn exists(&self, name: &MachineName) -> Result<bool> {
        let json = self.text(
            self.args(&["list"], &[]),
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        Ok(protocol::parse_list(&json)?
            .iter()
            .any(|s| s.id == name.as_str()))
    }

    fn create(
        &self,
        name: &MachineName,
        source: &Source<'_>,
        cpus: NonZeroU8,
        memory_mib: u32,
        disk: GiB,
        owner: &Owner,
    ) -> Result<()> {
        let req = Request::new(
            create_args(self, name, source, cpus, memory_mib, disk, owner),
            self.settings.create,
            MAX_JSON_OUTPUT,
        )
        .cancellable();
        self.checked(&req)?;
        Ok(())
    }

    /// Last lines of the sandbox's console log, for boot-failure errors: the
    /// only diagnostic available when SSH never came up. Best effort;
    /// control characters from the guest are replaced.
    fn boot_log_tail(&self, name: &MachineName) -> String {
        let req = Request::new(
            self.args(&["logs"], &[name.as_str(), "-n", "40"]),
            self.settings.probe,
            MAX_JSON_OUTPUT,
        );
        match self.checked(&req) {
            Ok(text) if !text.trim().is_empty() => {
                format!(
                    "\nLast console log lines:\n{}",
                    cli::sanitize_for_display(&text)
                )
            }
            _ => format!("\n(Console log unavailable; try `coop logs`.) [{name}]"),
        }
    }

    /// Boot `name` under launchd; returns once its owner answers.
    fn boot(&self, name: &MachineName) -> Result<()> {
        let wait = self.settings.boot.as_secs().to_string();
        let req = Request::new(
            self.args(&["start"], &[name.as_str(), "--wait-seconds", &wait]),
            self.settings.boot + Duration::from_secs(10),
            MAX_JSON_OUTPUT,
        )
        .cancellable();
        self.checked(&req).map_err(|e| {
            AppleError::BootTimeout(format!(
                "sandbox {name} failed to boot: {e:#}{}",
                self.boot_log_tail(name)
            ))
        })?;
        Ok(())
    }

    /// Wait until `name` runs with its effective configuration, then run the
    /// isolation gate.
    fn wait_ready(&self, expected: &Expected<'_>, deadline: Instant) -> Result<SecurityReady> {
        let name = expected.sandbox;
        loop {
            crate::signal::check_shutdown()?;
            let rec = self.inspect(name)?;
            match rec.status {
                SandboxStatus::Running if rec.effective.is_some() => {
                    return security::verify_effective(&rec, expected);
                }
                SandboxStatus::Stopped | SandboxStatus::Crashed => {
                    bail!(AppleError::BootTimeout(format!(
                        "sandbox {name} {} during boot{}",
                        rec.status.label(),
                        self.boot_log_tail(name)
                    )));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                bail!(AppleError::BootTimeout(format!(
                    "sandbox {name} did not report a running configuration in time{}",
                    self.boot_log_tail(name)
                )));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Run a fixed command as root in the guest over the native control
    /// channel (vsock). Arguments reach the guest as an argv, never a shell
    /// string.
    fn guest(
        &self,
        name: &MachineName,
        argv: &[&str],
        timeout: Duration,
        max: usize,
    ) -> Result<cli::Output> {
        let secs = timeout.as_secs().max(1).to_string();
        let mut rest = vec!["--timeout", secs.as_str(), name.as_str(), "--"];
        rest.extend_from_slice(argv);
        self.exec.run(&Request::new(
            self.args(&["exec"], &rest),
            timeout + Duration::from_secs(30),
            max,
        ))
    }

    /// Read the guest host public key over the native control channel,
    /// retrying until first-boot key generation finishes.
    fn read_host_key(
        &self,
        ready: &SecurityReady,
        deadline: Instant,
    ) -> Result<ssh::HostPublicKey> {
        let name = ready.sandbox();
        loop {
            crate::signal::check_shutdown()?;
            let out = self.guest(
                name,
                &["/bin/cat", "/etc/ssh/ssh_host_ed25519_key.pub"],
                self.settings.probe,
                MAX_PUBKEY_OUTPUT,
            )?;
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
                    let rec = self.inspect(name)?;
                    if rec.live.as_ref().map(|l| l.pid) != Some(ready.owner_pid()) {
                        bail!(AppleError::IdentityConflict(format!(
                            "sandbox {name} restarted while its host key was read"
                        )));
                    }
                    return Ok(key);
                }
                Err(e) if Instant::now() >= deadline => {
                    bail!(AppleError::BootTimeout(format!(
                        "sandbox {name} did not produce a valid SSH host key in time: {e:#}"
                    )));
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Request a clean stop and confirm it. A stop that cannot be confirmed
    /// leaves the sandbox in an unknown state; nothing may mutate its disk.
    fn stop_and_confirm(&self, name: &MachineName) -> Result<()> {
        let secs = self.settings.stop.as_secs().to_string();
        let req = Request::new(
            self.args(&["stop"], &[name.as_str(), "--timeout-seconds", &secs]),
            self.settings.stop + Duration::from_secs(120),
            MAX_TEXT_OUTPUT,
        );
        let out = self.exec.run(&req)?;
        let rec = self.inspect(name)?;
        if rec.status != SandboxStatus::Stopped {
            bail!(AppleError::OperationUncertain(format!(
                "sandbox {name} did not confirm it stopped (now {}; {}); leaving it untouched",
                rec.status.label(),
                out.stderr_summary()
            )));
        }
        Ok(())
    }

    fn delete(&self, name: &MachineName, owner: &Owner) -> Result<()> {
        self.text(
            self.args(&["delete"], &[name.as_str(), "--owner", owner.id.as_str()]),
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        )?;
        if self.exists(name)? {
            bail!(AppleError::OperationUncertain(format!(
                "sandbox {name} still exists after delete"
            )));
        }
        Ok(())
    }

    fn images(&self) -> Result<Vec<protocol::ImageEntry>> {
        let json = self.text(
            self.args(&["image", "list"], &[]),
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        protocol::parse_images(&json)
    }

    fn disks(&self) -> Result<Vec<protocol::DiskEntry>> {
        let json = self.text(
            self.args(&["disk", "list"], &[]),
            self.settings.probe,
            MAX_JSON_OUTPUT,
        )?;
        protocol::parse_disks(&json)
    }

    /// The manifest's image (or committed disk) must still be in the store
    /// with the verified content.
    fn verify_image(&self, manifest: &ImageManifest) -> Result<()> {
        if let Some(disk) = &manifest.disk {
            if !self.disks()?.iter().any(|d| d.name == disk.name.as_str()) {
                bail!(AppleError::IdentityConflict(format!(
                    "committed disk {} for image {} is missing from the runtime",
                    disk.name, manifest.image_ref
                )));
            }
            return Ok(());
        }
        let images = self.images()?;
        let Some(found) = images.iter().find(|i| i.reference == manifest.image_ref) else {
            bail!(AppleError::IdentityConflict(format!(
                "image {} is missing from the runtime; run `coop setup --rebuild`",
                manifest.image_ref
            )));
        };
        if found.digest != manifest.digest {
            bail!(AppleError::IdentityConflict(format!(
                "image {} now resolves to {}, but the template was verified as {}; \
                 run `coop setup --rebuild`",
                manifest.image_ref, found.digest, manifest.digest
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
                    .guest(name, &states, self.settings.probe, MAX_TEXT_OUTPUT)
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

    /// Which of `paths` are not executable in the guest, from one exec.
    /// Paths reach the script as positional parameters, never as script text.
    fn missing_executables(&self, name: &MachineName, paths: &[String]) -> Result<Vec<String>> {
        let mut command = vec![
            "/bin/sh",
            "-c",
            r#"for p; do test -x "$p" || printf '%s\n' "$p"; done"#,
            "sh",
        ];
        command.extend(paths.iter().map(String::as_str));
        let out = self.guest(name, &command, self.settings.operation, MAX_TEXT_OUTPUT)?;
        if !out.success() {
            bail!("guest check failed: {}", out.stderr_summary());
        }
        Ok(out.stdout_str()?.lines().map(String::from).collect())
    }

    /// Run a fixed root command in the guest; `true` on exit 0.
    fn run_root_ok(&self, name: &MachineName, command: &[&str]) -> bool {
        self.guest(name, command, self.settings.operation, MAX_TEXT_OUTPUT)
            .is_ok_and(|o| o.success())
    }

    fn delete_image_best_effort(&self, image_ref: &str) {
        if let Err(e) = self.text(
            self.args(&["image", "delete"], &[image_ref]),
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        ) {
            tracing::warn!("Failed to delete image {image_ref}: {e:#}");
        }
    }

    fn delete_disk_best_effort(&self, disk: &MachineName) {
        if let Err(e) = self.text(
            self.args(&["disk", "delete"], &[disk.as_str()]),
            self.settings.operation,
            MAX_TEXT_OUTPUT,
        ) {
            tracing::warn!("Failed to delete committed disk {disk}: {e:#}");
        }
    }

    /// Remove uncommitted creates, interrupted deletes, and scratch files.
    fn reconcile_best_effort(&self) {
        if let Err(e) = self.text(
            self.args(&["reconcile"], &[]),
            self.settings.operation,
            MAX_JSON_OUTPUT,
        ) {
            tracing::warn!("Failed to reconcile the sandbox runtime: {e:#}");
        }
    }

    /// Best-effort stop after a failed boot, keeping the disk for diagnosis.
    fn stop_after_failure(&self, name: &MachineName) {
        if let Err(e) = self.stop_and_confirm(name) {
            tracing::warn!("Failed to stop sandbox {name} after a failed start: {e:#}");
        }
    }
}

impl Builder {
    fn text(&self, args: &[&str], timeout: Duration) -> Result<String> {
        let req = Request::new(args.iter().copied(), timeout, MAX_TEXT_OUTPUT);
        let out = self.exec.run(&req)?;
        if !out.success() {
            bail!(
                "`container {}` failed: {}",
                req.describe(),
                out.stderr_summary()
            );
        }
        Ok(out.stdout_str()?.to_string())
    }

    /// The builder needs its service; coop never starts or stops it.
    fn require_service(&self, timeout: Duration) -> Result<()> {
        self.text(&["system", "status"], timeout)
            .map(|_| ())
            .map_err(|e| {
                AppleError::RuntimeUnavailable(format!(
                    "the Apple `container` service (used to build images) is not running ({e:#}). \
                 Start it with `container system start`, then retry."
                ))
                .into()
            })
    }
}

/// The one command that reconciles an unfinished `operation`: `start`
/// finishes an interrupted resize or restore; `destroy` removes or finishes
/// the rest.
fn recovery_hint(operation: Operation, name: &crate::config::InstanceName) -> String {
    match operation {
        Operation::SetResources | Operation::RestoreDisk => {
            format!("run `coop start {name}` to finish it")
        }
        Operation::Create => {
            format!("run `coop destroy {name}` to remove what it created, then `coop up` again")
        }
        Operation::Destroy => format!("run `coop destroy {name}` to finish it"),
    }
}

/// Argument vector for `coop-sandbox create`. There is no argument for a
/// host mount, socket, port, network, or agent: the runtime cannot express them.
fn create_args(
    rt: &Runtime,
    name: &MachineName,
    source: &Source<'_>,
    cpus: NonZeroU8,
    memory_mib: u32,
    disk: GiB,
    owner: &Owner,
) -> Vec<String> {
    let (flag, value) = match source {
        Source::Image(r) => ("--image", (*r).to_string()),
        Source::Disk(d) => ("--from-disk", d.to_string()),
    };
    let cpus = cpus.to_string();
    let mem = memory_mib.to_string();
    let disk = disk.to_string();
    rt.args(
        &["create"],
        &[
            name.as_str(),
            flag,
            &value,
            "--cpus",
            &cpus,
            "--memory-mib",
            &mem,
            "--disk-gib",
            &disk,
            "--owner",
            owner.id.as_str(),
        ],
    )
}

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

fn mib_to_bytes(mib: u32) -> u64 {
    u64::from(mib) * MIB
}

/// Whole GiB covering `bytes` (committed disks are always whole GiB).
fn covering_gib(bytes: u64) -> Result<GiB> {
    let gib = u32::try_from(bytes.div_ceil(GIB)).context("disk size")?;
    GiB::new(gib).context("disk size is zero")
}

// ── Lifecycle ─────────────────────────────────────────────────

impl AppleContainerBackend {
    #[expect(clippy::too_many_arguments, reason = "one create, all inputs explicit")]
    fn provision_sandbox(
        cfg: &CoopConfig,
        rt: &Runtime,
        q: &QualifiedRuntime,
        inst: &Instance,
        owner: &Owner,
        manifest: &ImageManifest,
        disk: GiB,
        journal: &mut Journal,
    ) -> Result<()> {
        let machine = journal.machine_id.clone();
        let cpus = cfg.vm.vcpu_count;
        let memory_mib = cfg.vm.mem_size_mib.get().as_u32();
        let source = match &manifest.disk {
            Some(d) => Source::Disk(&d.name),
            None => Source::Image(&manifest.image_ref),
        };

        journal.advance(inst, Stage::CreatingMachine)?;
        rt.create(&machine, &source, cpus, memory_mib, disk, owner)?;
        journal.advance(inst, Stage::MachineCreated)?;

        let mut sidecar = MachineSidecar {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            owner_id: owner.id.clone(),
            instance_id: machine
                .as_str()
                .rsplit('-')
                .next()
                .unwrap_or_default()
                .to_string(),
            machine_id: machine.clone(),
            image_ref: manifest.image_ref.clone(),
            image_digest: manifest.digest.clone(),
            image_manifest_id: manifest.manifest_id.clone(),
            guest_user: manifest.guest_user.clone(),
            requested_cpus: u32::from(cpus.get()),
            requested_memory_bytes: mib_to_bytes(memory_mib),
            host_key_fingerprint: String::new(),
            last_observed_owner_pid: None,
            last_observed_ip: None,
            reenroll_host_key: false,
            creation_state: CreationState::Ready,
            created_at: crate::setup::utc_timestamp(),
            runtime_identity: q.identity.clone(),
        };
        security::verify_record(&rt.inspect(&machine)?, &rt.expected(&sidecar))?;

        let deadline = Instant::now() + rt.settings.boot;
        rt.boot(&machine)?;
        let ready = rt.wait_ready(&rt.expected(&sidecar), deadline)?;
        let key = rt.read_host_key(&ready, deadline)?;
        ssh::enroll(inst, &machine, &key)?;
        let target = ssh::pinned_target(cfg, inst, &machine, ready.ip(), &manifest.guest_user)?;
        target
            .wait_until_ready(
                deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_secs(5)),
            )
            .context("Guest booted but SSH is not accepting connections")?;

        sidecar.host_key_fingerprint = key.fingerprint();
        sidecar.last_observed_owner_pid = Some(ready.owner_pid());
        sidecar.last_observed_ip = Some(ready.ip());
        sidecar.save(inst)
    }

    /// Load and ownership-check an instance's record.
    fn owned_sidecar(cfg: &CoopConfig, inst: &Instance) -> Result<MachineSidecar> {
        let owner = Owner::load(cfg)?;
        if let Some(journal) = Journal::try_load(inst)? {
            bail!(AppleError::OperationUncertain(format!(
                "instance '{}' has an unfinished {:?} operation (stage {:?}); {}",
                inst.name,
                journal.op.kind(),
                journal.stage,
                recovery_hint(journal.op.kind(), &inst.name)
            )));
        }
        let sidecar = MachineSidecar::load(inst)?;
        sidecar.check_owner(&owner)?;
        Ok(sidecar)
    }

    /// Finish an interrupted `resize` or `restore` once the sandbox is
    /// confirmed stopped: the runtime's record is authoritative. Other
    /// journaled operations are left for `destroy`. Caller holds the lock.
    fn recover_journal(rt: &Runtime, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let Some(journal) = Journal::try_load(inst)? else {
            return Ok(());
        };
        if !matches!(
            journal.op,
            JournalOp::SetResources { .. } | JournalOp::RestoreDisk { .. }
        ) {
            return Ok(());
        }
        let owner = Owner::load(cfg)?;
        let mut sidecar = MachineSidecar::load(inst)?;
        sidecar.check_owner(&owner)?;
        if journal.machine_id != sidecar.machine_id {
            bail!(AppleError::IdentityConflict(format!(
                "journal names {}, but the instance records {}",
                journal.machine_id, sidecar.machine_id
            )));
        }
        let rec = rt.inspect(&sidecar.machine_id)?;
        if rec.status != SandboxStatus::Stopped {
            bail!(AppleError::OperationUncertain(format!(
                "an interrupted {:?} of '{}' cannot be reconciled while the sandbox is {}",
                journal.op.kind(),
                inst.name,
                rec.status.label()
            )));
        }
        match journal.op {
            JournalOp::SetResources {
                prior: (prior_cpus, prior_bytes),
            } => {
                let outcome =
                    if (rec.record.cpus, rec.record.memory_bytes) == (prior_cpus, prior_bytes) {
                        "the change did not apply"
                    } else {
                        "the change applied"
                    };
                tracing::warn!(
                    "Reconciling an interrupted resize of '{}' ({outcome}): runtime reports {} vCPUs / {} MiB",
                    inst.name,
                    rec.record.cpus,
                    rec.record.memory_bytes / MIB
                );
                sidecar.requested_cpus = rec.record.cpus;
                sidecar.requested_memory_bytes = rec.record.memory_bytes;
            }
            JournalOp::RestoreDisk { prior_generation } => {
                // Only a higher disk generation proves coop's restore replaced
                // the disk; anything else keeps the existing pin.
                let applied = rec.record.disk_generation > prior_generation;
                tracing::warn!(
                    "Reconciling an interrupted restore of '{}': {}",
                    inst.name,
                    if applied {
                        "the disk was replaced"
                    } else {
                        "the disk was not replaced"
                    }
                );
                if applied {
                    sidecar.image_ref.clone_from(&rec.record.image_reference);
                    sidecar.image_digest.clone_from(&rec.record.image_digest);
                    sidecar.reenroll_host_key = true;
                }
            }
            JournalOp::Create | JournalOp::Destroy => {}
        }
        sidecar.save(inst)?;
        Journal::complete(inst)
    }

    fn start_owned(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let (rt, q) = self.qualified_runtime()?;
        let _lock = state::lock_instance(inst)?;
        Self::recover_journal(rt, cfg, inst)?;
        let mut sidecar = Self::owned_sidecar(cfg, inst)?;
        let machine = sidecar.machine_id.clone();
        let rec = rt.inspect(&machine)?;
        match rec.status {
            // A crashed owner left no VM; `coop-sandbox start` clears it.
            SandboxStatus::Stopped | SandboxStatus::Crashed => {}
            SandboxStatus::Running => bail!("Instance '{}' is already running", inst.name),
            SandboxStatus::Booting => bail!(AppleError::OperationUncertain(format!(
                "sandbox {machine} is booting; wait for it to settle"
            ))),
        }
        security::verify_record(&rec, &rt.expected(&sidecar))?;

        let deadline = Instant::now() + rt.settings.boot;
        let booted = (|| -> Result<SecurityReady> {
            // Inside the guard: a boot that errors or times out may still
            // have started the sandbox, and it must not be left running.
            rt.boot(&machine)?;
            let ready = rt.wait_ready(&rt.expected(&sidecar), deadline)?;
            let key = rt.read_host_key(&ready, deadline)?;
            if sidecar.reenroll_host_key {
                ssh::reenroll_after_disk_replacement(inst, &machine, &key)?;
                // Close the window at once: a later start, even after this
                // one fails, must enforce the new pin.
                tracing::info!(
                    "Pinned the new host key of '{}' after its disk was restored ({})",
                    inst.name,
                    key.fingerprint()
                );
                sidecar.reenroll_host_key = false;
                sidecar.host_key_fingerprint = key.fingerprint();
                sidecar.save(inst)?;
            } else {
                ssh::check_pin(inst, &machine, &key)?;
            }
            let target = ssh::pinned_target(cfg, inst, &machine, ready.ip(), &sidecar.guest_user)?;
            target
                .wait_until_ready(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .max(Duration::from_secs(5)),
                )
                .context("Guest booted but SSH is not accepting connections")?;
            Ok(ready)
        })();
        let ready = match booted {
            Ok(ready) => ready,
            Err(e) => {
                rt.stop_after_failure(&machine);
                return Err(e);
            }
        };
        sidecar.last_observed_owner_pid = Some(ready.owner_pid());
        sidecar.last_observed_ip = Some(ready.ip());
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
        rec: &Inspect,
    ) -> Result<SshTarget> {
        let (rt, _) = self.qualified_runtime()?;
        let ready = security::verify_effective(rec, &rt.expected(sidecar))?;
        ssh::pinned_target(cfg, inst, ready.sandbox(), ready.ip(), &sidecar.guest_user)
    }

    /// Create the runtime state root with the pinned kernel and init image.
    fn init_runtime(&self, rt: &Runtime) -> Result<()> {
        let kernel = self
            .settings
            .kernel
            .clone()
            .or_else(default_kernel)
            .context("no kernel path: set `[apple_container] kernel`")?;
        rt.init(&kernel).map_err(|e| {
            AppleError::RuntimeUnavailable(format!(
                "failed to initialize the sandbox runtime with kernel {}: {e:#}. The kernel is \
                 installed by Apple `container` (`container system start`), or set \
                 `[apple_container] kernel` to a validated kernel.",
                kernel.display()
            ))
            .into()
        })
    }

    /// Inspect a sandbox that must be stopped for a disk or resource change.
    fn require_stopped(rt: &Runtime, inst: &Instance, machine: &MachineName) -> Result<Inspect> {
        let rec = rt.inspect(machine)?;
        if rec.status != SandboxStatus::Stopped {
            bail!(
                "Instance '{}' is not stopped (sandbox is {})",
                inst.name,
                rec.status.label()
            );
        }
        Ok(rec)
    }

    fn apply_resources(
        rt: &Runtime,
        machine: &MachineName,
        cpus: Option<u32>,
        memory_mib: Option<u32>,
    ) -> Result<()> {
        let cpus = cpus.map(|c| c.to_string());
        let mem = memory_mib.map(|m| m.to_string());
        let mut rest = vec![machine.as_str()];
        if let Some(c) = &cpus {
            rest.extend(["--cpus", c.as_str()]);
        }
        if let Some(m) = &mem {
            rest.extend(["--memory-mib", m.as_str()]);
        }
        rt.text(
            rt.args(&["set"], &rest),
            rt.settings.operation,
            MAX_JSON_OUTPUT,
        )?;
        Ok(())
    }
}

impl VmBackend for AppleContainerBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::new(&[
            Capability::DiskResize,
            Capability::DiskSnapshots,
            Capability::MachineResources,
        ])
    }

    fn setup(&self, cfg: &CoopConfig, opts: &SetupOptions) -> Result<()> {
        boot_preflight(cfg)?;
        check_platform()?;
        let (rt, q) = self.qualified_runtime()?;
        tracing::info!("Sandbox runtime: {}", q.identity);
        let owner = Owner::load_or_init(cfg)?;
        ensure_ssh_key(cfg)?;
        self.init_runtime(rt)?;

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

        let builder = self.builder()?;
        builder.require_service(rt.settings.probe)?;
        let image_ref = image::image_ref(&owner, &manifest_id, &crate::fs_util::random_hex(4)?);
        state::ensure_private_dir(&cfg.image_dir(image))?;
        let log = cfg.image_dir(image).join("build.log");
        crate::fs_util::atomic_write_with_mode(&log, "", 0o600)?;
        let context = ctx.materialize()?;
        tracing::info!(
            "Building image '{image}' as {image_ref} (log: {})",
            log.display()
        );
        let built = build_import_and_verify(
            rt,
            builder,
            cfg,
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
            disk: None,
            manifest_id: manifest_id.clone(),
            base_image: image::BASE_IMAGE.into(),
            platform: image::PLATFORM.into(),
            guest_user: opts.guest_user.clone(),
            pubkey_fingerprint,
            created: crate::setup::utc_timestamp(),
        }
        .save(cfg, image)?;
        save_template_config(cfg, opts, &manifest_id)?;
        if let Some(old) = previous {
            release_manifest(rt, cfg, &owner, &old, None);
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
        let (rt, q) = self.qualified_runtime()?;
        let owner = Owner::load(cfg)?;
        let manifest = ImageManifest::load(cfg, &inst.image)?;
        rt.verify_image(&manifest)?;
        let disk = match (disk_gib, &manifest.disk) {
            (Some(d), _) => d,
            (None, Some(committed)) => covering_gib(committed.bytes)?,
            (None, None) => cfg.vm.template_size_gib,
        };

        let _lock = state::lock_instance(inst)?;
        if MachineSidecar::try_load(inst)?.is_some() || Journal::try_load(inst)?.is_some() {
            bail!(AppleError::OperationUncertain(format!(
                "instance '{}' already has sandbox state; destroy it before recreating",
                inst.name
            )));
        }
        let machine = MachineName::generate(&owner.id)?;
        if rt.exists(&machine)? {
            bail!(AppleError::IdentityConflict(format!(
                "generated name {machine} is already in use; retry"
            )));
        }
        let mut journal = Journal::begin(inst, &owner, JournalOp::Create, machine.clone())?;
        if let Err(e) =
            Self::provision_sandbox(cfg, rt, q, inst, &owner, &manifest, disk, &mut journal)
        {
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
    /// qualified runtime nor a passing gate nor SSH, so a sandbox that can
    /// no longer be reached safely can still be stopped (its disk is kept).
    /// Ownership is still required; an unfinished journal does not block it.
    fn stop_unproven(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        let owner = Owner::load(cfg)?;
        let sidecar = MachineSidecar::load(inst)?;
        sidecar.check_owner(&owner)?;
        let rt = self.runtime()?;
        let _lock = state::lock_instance(inst)?;
        let rec = rt.inspect(&sidecar.machine_id)?;
        if rec.status != SandboxStatus::Stopped {
            rt.stop_and_confirm(&sidecar.machine_id)?;
        }
        tracing::info!("Instance '{}' stopped", inst.name);
        Ok(())
    }

    fn destroy_instance(&self, cfg: &CoopConfig, inst: &Instance) -> Result<()> {
        if let Some((machine, network)) = state::legacy_machine(inst)? {
            tracing::warn!(
                "Instance '{}' was created by the retired `container machine` backend. Removing \
                 its local state; its machine and network remain in the Apple Container runtime. \
                 Delete them there with `container machine delete {machine}` and \
                 `container network delete {network}`.",
                inst.name
            );
            return remove_instance_dir(inst);
        }
        let sidecar = MachineSidecar::try_load(inst)?;
        let journal = Journal::try_load(inst)?;
        let ids = match (&sidecar, &journal) {
            (_, Some(j)) => Some((j.owner_id.clone(), j.machine_id.clone())),
            (Some(s), None) => Some((s.owner_id.clone(), s.machine_id.clone())),
            (None, None) => None,
        };
        if let Some((owner_id, machine)) = ids {
            let owner = Owner::load(cfg)?;
            if owner_id != owner.id || !machine.belongs_to(&owner.id) {
                bail!(AppleError::IdentityConflict(format!(
                    "instance '{}' records sandbox {machine}, which this installation does not own; \
                     leaving it untouched",
                    inst.name
                )));
            }
            let rt = self.runtime()?;
            let _lock = state::lock_instance(inst)?;
            if rt.exists(&machine)? {
                let rec = rt.inspect(&machine)?;
                if rec.status != SandboxStatus::Stopped {
                    rt.stop_and_confirm(&machine)?;
                }
                let mut j = match journal {
                    Some(j) => j,
                    None => Journal::begin(inst, &owner, JournalOp::Destroy, machine.clone())?,
                };
                j.advance(inst, Stage::DeletingMachine)?;
                rt.delete(&machine, &owner)?;
                j.advance(inst, Stage::MachineDeleted)?;
            }
            // A create or delete interrupted inside the runtime leaves an
            // unlisted directory there; reconcile removes it.
            rt.reconcile_best_effort();
        }
        remove_instance_dir(inst)
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
        // Deleting the runtime content is best effort: an unreadable
        // manifest, missing owner record, or unavailable runtime must not
        // leave the image name stuck. Instances never depend on it: each has
        // its own disk and captured environment.
        if let Some(manifest) = ImageManifest::load_lenient(cfg, image)
            && let Ok(owner) = Owner::load(cfg)
        {
            match self.runtime() {
                Ok(rt) => release_manifest(rt, cfg, &owner, &manifest, Some(image)),
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
        cfg: &CoopConfig,
        stopped: &StoppedInstance,
        new_size: GiB,
    ) -> Result<()> {
        let inst = stopped.instance();
        let (rt, _) = self.qualified_runtime()?;
        let _lock = state::lock_instance(inst)?;
        let sidecar = Self::owned_sidecar(cfg, inst)?;
        let machine = &sidecar.machine_id;
        let before = Self::require_stopped(rt, inst, machine)?;
        let wanted = u64::from(new_size.as_u32()) * GIB;
        if wanted <= before.record.disk_bytes {
            if wanted == before.record.disk_bytes {
                return Ok(());
            }
            bail!(
                "Instance '{}' has a {} GiB disk; shrinking is not supported",
                inst.name,
                before.record.disk_bytes / GIB
            );
        }
        // The runtime grows a clone offline and swaps it in only on success,
        // so a failure leaves the disk unchanged; no journal is needed.
        let gib = new_size.to_string();
        let req = Request::new(
            rt.args(&["grow"], &[machine.as_str(), "--disk-gib", &gib]),
            rt.settings.create,
            MAX_JSON_OUTPUT,
        );
        rt.checked(&req)?;
        let after = rt.inspect(machine)?;
        if after.record.disk_bytes != wanted {
            bail!(AppleError::OperationUncertain(format!(
                "sandbox {machine} reports a {} byte disk after growing to {wanted}",
                after.record.disk_bytes
            )));
        }
        tracing::info!("Grew instance '{}' disk to {new_size} GiB", inst.name);
        Ok(())
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
            Self::recover_journal(rt, cfg, inst)?;
            sidecar = Self::owned_sidecar(cfg, inst)?;
            let machine = sidecar.machine_id.clone();
            let rec = Self::require_stopped(rt, inst, &machine)?;
            prior = (rec.record.cpus, rec.record.memory_bytes);
            let mut journal = Journal::begin(
                inst,
                &owner,
                JournalOp::SetResources { prior },
                machine.clone(),
            )?;
            journal.advance(inst, Stage::Applying)?;

            let cpus = vcpus.map(|v| u32::from(v.get()));
            let memory_mib = mem.map(|m| m.get().as_u32());
            Self::apply_resources(rt, &machine, cpus, memory_mib)?;
            let after = rt.inspect(&machine)?;
            let want_cpus = cpus.unwrap_or(prior.0);
            let want_mem = memory_mib.map_or(prior.1, mib_to_bytes);
            if after.record.cpus != want_cpus || after.record.memory_bytes != want_mem {
                bail!(AppleError::OperationUncertain(format!(
                    "sandbox {machine} reports {} vCPUs / {} bytes after update, expected {want_cpus} / {want_mem}",
                    after.record.cpus, after.record.memory_bytes
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
        // Roll back only once the sandbox is provably stopped again.
        let machine = sidecar.machine_id.clone();
        let rolled_back = (|| -> Result<()> {
            Self::require_stopped(rt, inst, &machine)?;
            let prior_mib = u32::try_from(prior.1 / MIB).context("prior memory")?;
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

    /// Save the stopped instance's disk (identity removed) as image `image`.
    fn commit_disk(
        &self,
        cfg: &CoopConfig,
        stopped: &StoppedInstance,
        image: &ImageName,
    ) -> Result<()> {
        let inst = stopped.instance();
        let (rt, _) = self.qualified_runtime()?;
        let owner = Owner::load(cfg)?;
        let _lock = state::lock_instance(inst)?;
        let sidecar = Self::owned_sidecar(cfg, inst)?;
        let rec = Self::require_stopped(rt, inst, &sidecar.machine_id)?;
        let disk = MachineName::generate(&owner.id)?;
        let req = Request::new(
            rt.args(&["commit"], &[sidecar.machine_id.as_str(), disk.as_str()]),
            rt.settings.create,
            MAX_JSON_OUTPUT,
        );
        let out = rt.checked(&req)?;
        let source = ImageManifest::load_lenient(cfg, &inst.image);
        let previous = ImageManifest::load_lenient(cfg, image);
        let saved = protocol::parse_disk(&out).and_then(|committed| {
            ImageManifest {
                schema_version: state::SCHEMA_VERSION,
                backend: state::BACKEND_TAG.into(),
                image_ref: rec.record.image_reference.clone(),
                digest: rec.record.image_digest.clone(),
                disk: Some(CommittedDisk {
                    name: disk.clone(),
                    bytes: committed.logical_bytes,
                }),
                manifest_id: format!("commit-{disk}"),
                base_image: image::BASE_IMAGE.into(),
                platform: image::PLATFORM.into(),
                guest_user: sidecar.guest_user.clone(),
                pubkey_fingerprint: source.map(|m| m.pubkey_fingerprint).unwrap_or_default(),
                created: crate::setup::utc_timestamp(),
            }
            .save(cfg, image)
        });
        if let Err(e) = saved {
            // Nothing refers to the new disk yet; do not leave it behind.
            rt.delete_disk_best_effort(&disk);
            return Err(e);
        }
        if let Some(old) = previous {
            release_manifest(rt, cfg, &owner, &old, None);
        }
        Ok(())
    }

    /// Replace the stopped instance's disk with image `image`'s. The new disk
    /// has no host keys; the next start pins the one it generates.
    fn restore_disk(
        &self,
        cfg: &CoopConfig,
        stopped: &StoppedInstance,
        image: &ImageName,
    ) -> Result<()> {
        let inst = stopped.instance();
        let (rt, _) = self.qualified_runtime()?;
        let owner = Owner::load(cfg)?;
        let manifest = ImageManifest::load(cfg, image)?;
        rt.verify_image(&manifest)?;
        let _lock = state::lock_instance(inst)?;
        Self::recover_journal(rt, cfg, inst)?;
        let mut sidecar = Self::owned_sidecar(cfg, inst)?;
        let machine = sidecar.machine_id.clone();
        let rec = Self::require_stopped(rt, inst, &machine)?;
        // SSH logs in as the instance's recorded user; a disk built for
        // another user would leave the instance unable to start.
        if manifest.guest_user != sidecar.guest_user {
            bail!(
                "Image '{image}' was built for guest user '{}', but instance '{}' uses '{}'; \
                 create a new instance from it instead",
                manifest.guest_user,
                inst.name,
                sidecar.guest_user
            );
        }
        let mut journal = Journal::begin(
            inst,
            &owner,
            JournalOp::RestoreDisk {
                prior_generation: rec.record.disk_generation,
            },
            machine.clone(),
        )?;
        journal.advance(inst, Stage::Applying)?;
        let rest: Vec<&str> = match &manifest.disk {
            Some(d) => vec![machine.as_str(), d.name.as_str()],
            None => vec![machine.as_str(), "--image", manifest.image_ref.as_str()],
        };
        let req = Request::new(
            rt.args(&["restore"], &rest),
            rt.settings.create,
            MAX_JSON_OUTPUT,
        );
        rt.checked(&req)?;
        let after = rt.inspect(&machine)?;
        if after.record.disk_generation <= rec.record.disk_generation {
            bail!(AppleError::OperationUncertain(format!(
                "sandbox {machine} did not report a replaced disk; {}",
                recovery_hint(Operation::RestoreDisk, &inst.name)
            )));
        }
        sidecar.image_ref.clone_from(&after.record.image_reference);
        sidecar.image_digest.clone_from(&after.record.image_digest);
        sidecar.image_manifest_id.clone_from(&manifest.manifest_id);
        sidecar.reenroll_host_key = true;
        sidecar.save(inst)?;
        Journal::complete(inst)
    }

    fn is_running(&self, inst: &Instance) -> bool {
        let Ok(Some(sidecar)) = MachineSidecar::try_load(inst) else {
            return false;
        };
        self.runtime()
            .and_then(|rt| rt.inspect(&sidecar.machine_id))
            .is_ok_and(|rec| rec.status == SandboxStatus::Running)
    }

    fn images_in_data_dir(&self) -> bool {
        false
    }

    fn probe_running(&self, inst: &Instance) -> Result<bool> {
        if let Some(journal) = Journal::try_load(inst)? {
            bail!(AppleError::OperationUncertain(format!(
                "instance '{}' has an unfinished {:?} operation",
                inst.name,
                journal.op.kind()
            )));
        }
        let Some(sidecar) = MachineSidecar::try_load(inst)? else {
            return Ok(false);
        };
        let rec = self.runtime()?.inspect(&sidecar.machine_id)?;
        match rec.status {
            SandboxStatus::Running => Ok(true),
            SandboxStatus::Stopped => Ok(false),
            other => bail!(AppleError::OperationUncertain(format!(
                "sandbox {} is {}",
                sidecar.machine_id,
                other.label()
            ))),
        }
    }

    fn as_running(&self, cfg: &CoopConfig, inst: Instance) -> Result<Option<RunningInstance>> {
        let sidecar = Self::owned_sidecar(cfg, &inst)?;
        let rt = self.runtime()?;
        let rec = rt.inspect(&sidecar.machine_id)?;
        match rec.status {
            SandboxStatus::Stopped => Ok(None),
            SandboxStatus::Running => {
                // A running sandbox that cannot be handed out (unqualified
                // runtime, failed gate) is an error, never "not running":
                // callers must not report it stopped.
                let target = self
                    .target_for(cfg, &inst, &sidecar, &rec)
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
                "sandbox {} is {}",
                sidecar.machine_id,
                other.label()
            ))),
        }
    }

    fn as_stopped(&self, inst: Instance) -> Result<StoppedInstance> {
        let sidecar = MachineSidecar::load(&inst)?;
        let rec = self.runtime()?.inspect(&sidecar.machine_id)?;
        match rec.status {
            SandboxStatus::Stopped => Ok(StoppedInstance::new(inst)),
            SandboxStatus::Running => bail!(
                "Instance '{}' is running — stop it first with `coop stop {}`",
                inst.name,
                inst.name,
            ),
            other => bail!(AppleError::OperationUncertain(format!(
                "sandbox {} is {}",
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
        let rec = rt.inspect(&sidecar.machine_id)?;
        let runtime = rt
            .qualification
            .as_ref()
            .map_or_else(|e| format!("unqualified ({e})"), |q| q.identity.clone());
        let mut out = describe_sandbox(inst, &sidecar, &rec, &runtime);
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
        let name = sidecar.machine_id.as_str();
        match mode {
            LogMode::Follow => {
                // Guest-controlled console output: replace control bytes on
                // every line before it reaches the operator's terminal.
                let args = rt.args(&["logs"], &[name, "--follow"]);
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
                    bail!("`coop-sandbox logs` exited with {:?}", out.code);
                }
            }
            LogMode::Snapshot => {
                // Spool to a private file rather than memory, then print it
                // line by line with guest-controlled control bytes replaced.
                let spool = tempfile::NamedTempFile::new().context("Failed to create log spool")?;
                let req = Request::new(rt.args(&["logs"], &[name]), rt.settings.boot, 0);
                let out = rt.exec.run_logged(&req, spool.path())?;
                if !out.success() {
                    bail!(
                        "`coop-sandbox logs` failed: {}",
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
        let rec = self.runtime()?.inspect(&sidecar.machine_id)?;
        self.target_for(cfg, inst, &sidecar, &rec)
    }

    /// The sandbox's disk file; its size is the instance's disk size.
    fn disk_path(&self, inst: &Instance) -> Result<PathBuf> {
        let sidecar = MachineSidecar::load(inst)?;
        Ok(security::rootfs_path(
            &canonical_path(&self.settings.runtime_root),
            &sidecar.machine_id,
        ))
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

/// `coop status` text for a sandbox, from the runtime's record.
fn describe_sandbox(
    inst: &Instance,
    sidecar: &MachineSidecar,
    rec: &Inspect,
    runtime: &str,
) -> String {
    let ip = rec
        .ip()
        .map_or_else(|| "unavailable".to_string(), |ip| ip.to_string());
    let network = rec
        .effective
        .as_ref()
        .and_then(|e| e.interfaces.first())
        .map_or_else(
            || "unavailable".to_string(),
            |i| cli::sanitize_for_display(&i.network),
        );
    let gib = |b: u64| {
        let tenths = b * 10 / GIB;
        format!("{}.{}", tenths / 10, tenths % 10)
    };
    format!(
        "Instance '{}' ({})\n\
         \x20 Backend: apple-container (coop-sandbox)\n\
         \x20 Runtime: {runtime}\n\
         \x20 Sandbox: {}\n\
         \x20 Network: {network} (dedicated)\n\
         \x20 vCPUs: {}\n\
         \x20 Memory: {} MiB\n\
         \x20 Disk: {} GiB ({} GiB allocated)\n\
         \x20 Address: {ip} (host key {})\n\
         \x20 Workspace: copied (no live mounts)",
        inst.name,
        rec.status.label(),
        sidecar.machine_id,
        rec.record.cpus,
        rec.record.memory_bytes / MIB,
        gib(rec.disk.logical_bytes),
        gib(rec.disk.allocated_bytes),
        sidecar.host_key_fingerprint,
    )
}

/// The backend-agnostic half of a freshly built image.
fn save_template_config(cfg: &CoopConfig, opts: &SetupOptions, manifest_id: &str) -> Result<()> {
    crate::setup::TemplateConfig {
        version: crate::setup::TEMPLATE_VERSION,
        created: crate::setup::utc_timestamp(),
        install_script_hash: crate::sha256_hash::Sha256Hash::of(manifest_id),
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
    .save_for(cfg, &opts.image)
}

fn remove_instance_dir(inst: &Instance) -> Result<()> {
    if inst.dir.exists() {
        std::fs::remove_dir_all(&inst.dir)
            .with_context(|| format!("Failed to remove {}", inst.dir.display()))?;
    }
    Ok(())
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

/// Build `image_ref` from `context` with the stock builder (output to `log`),
/// move it into the runtime's store, then verify it in a disposable sandbox.
/// Returns the digest.
#[expect(clippy::too_many_arguments, reason = "one build, all inputs explicit")]
fn build_import_and_verify(
    rt: &Runtime,
    builder: &Builder,
    cfg: &CoopConfig,
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
    let out = builder.exec.run_logged(&build, log)?;
    if !out.success() {
        bail!(
            "Image build failed. Last lines of {}:\n{}",
            log.display(),
            cli::log_tail(log, 4096)
        );
    }
    // The OCI archive holds only the image just built from the private context.
    let archive = tempfile::Builder::new()
        .prefix("coop-apple-image-")
        .tempdir()
        .context("Failed to create image export directory")?;
    let tar = archive.path().join("image.tar");
    let tar_arg = tar.display().to_string();
    let saved = builder.text(
        &[
            "image",
            "save",
            "--platform",
            image::PLATFORM,
            "-o",
            &tar_arg,
            image_ref,
        ],
        rt.settings.create,
    );
    // The builder's copy is not used again, whatever happens next.
    let _ = builder.text(&["image", "delete", image_ref], rt.settings.operation);
    saved?;
    let imported = protocol::parse_images(&rt.text(
        rt.args(&["image", "import"], &["--oci-tar", &tar_arg]),
        rt.settings.create,
        MAX_JSON_OUTPUT,
    )?)?;
    let Some(entry) = imported.iter().find(|i| i.reference == image_ref) else {
        bail!(AppleError::IdentityConflict(format!(
            "importing {image_ref} into the runtime produced {:?}",
            imported.iter().map(|i| &i.reference).collect::<Vec<_>>()
        )));
    };
    verify_image_in_sandbox(rt, cfg, owner, image_ref, guest_user)?;
    Ok(entry.digest.clone())
}

/// The image tags and committed disks the saved manifests (other than
/// `except`) still use, or `None` when one cannot be read: nothing is
/// released then, since it might be in use.
fn manifest_references(
    cfg: &CoopConfig,
    except: Option<&ImageName>,
) -> Option<(HashSet<String>, HashSet<String>)> {
    let images = cfg
        .list_images()
        .map_err(|e| tracing::warn!("Keeping image content: cannot list images: {e:#}"))
        .ok()?;
    let (mut refs, mut disks) = (HashSet::new(), HashSet::new());
    for info in images.iter().filter(|i| Some(&i.name) != except) {
        match ImageManifest::try_load(cfg, &info.name) {
            Ok(Some(m)) => {
                if let Some(d) = &m.disk {
                    disks.insert(d.name.to_string());
                }
                refs.insert(m.image_ref);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Keeping image content: manifest for '{}' is unreadable: {e:#}",
                    info.name
                );
                return None;
            }
        }
    }
    Some((refs, disks))
}

/// Delete an owned manifest's runtime content (its committed disk and its
/// image tag) unless a saved manifest other than `except` still uses it.
/// Instances never depend on either after creation.
fn release_manifest(
    rt: &Runtime,
    cfg: &CoopConfig,
    owner: &Owner,
    manifest: &ImageManifest,
    except: Option<&ImageName>,
) {
    let Some((refs, disks)) = manifest_references(cfg, except) else {
        return;
    };
    if let Some(disk) = &manifest.disk
        && disk.name.belongs_to(&owner.id)
        && !disks.contains(disk.name.as_str())
    {
        rt.delete_disk_best_effort(&disk.name);
    }
    if manifest
        .image_ref
        .starts_with(&format!("local/coop-{}:", owner.id.short()))
        && !refs.contains(&manifest.image_ref)
    {
        rt.delete_image_best_effort(&manifest.image_ref);
    }
}

/// Boot the candidate image in a disposable, owned sandbox with no
/// credentials, check the guest contract, and always clean up.
fn verify_image_in_sandbox(
    rt: &Runtime,
    cfg: &CoopConfig,
    owner: &Owner,
    image_ref: &str,
    guest_user: &crate::guest::GuestUser,
) -> Result<()> {
    let machine = MachineName::generate(&owner.id)?;
    tracing::info!("Verifying image in disposable sandbox {machine}");
    // Small and fixed: the check needs a boot, not the instance's resources.
    let (cpus, memory_mib) = (2u8, 2048u32);
    let expected = security::Expected {
        sandbox: &machine,
        owner: owner.id.as_str(),
        runtime_root: &rt.root,
        cpus: u32::from(cpus),
        memory_bytes: mib_to_bytes(memory_mib),
    };
    let result = (|| -> Result<()> {
        // The instance default disk size, so the unpacked base is cached for
        // the first `coop up`.
        rt.create(
            &machine,
            &Source::Image(image_ref),
            NonZeroU8::new(cpus).context("verification vCPUs")?,
            memory_mib,
            cfg.vm.template_size_gib,
            owner,
        )?;
        security::verify_record(&rt.inspect(&machine)?, &expected)?;
        let deadline = Instant::now() + rt.settings.boot;
        rt.boot(&machine)?;
        let ready = rt.wait_ready(&expected, deadline)?;
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
        // The guest user is baked into the image; coop's forwards assume uid 1000.
        let uid = rt.guest(
            &machine,
            &["/usr/bin/id", "-u", guest_user.as_str()],
            rt.settings.probe,
            MAX_TEXT_OUTPUT,
        )?;
        if uid.stdout_str().map(str::trim).ok() != Some("1000") {
            bail!("Image verification failed: guest user {guest_user} is not uid 1000");
        }
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
        if rt.exists(&machine)? {
            let rec = rt.inspect(&machine)?;
            if rec.status != SandboxStatus::Stopped {
                rt.stop_and_confirm(&machine)?;
            }
            rt.delete(&machine, owner)?;
        }
        Ok(())
    })();
    if let Err(e) = &cleanup {
        tracing::warn!("Failed to clean up verification sandbox {machine}: {e:#}");
    }
    result
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    //! Backend tests against a scripted runtime and builder.

    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;

    use super::cli::{Exec, Output, Request};
    use super::*;
    use crate::config::{ConfigPath, ImageName, InstanceIndex, InstanceName};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/coop-sandbox");
    const FIXTURE_ID: &str = "coop-0a1b2c3d-00112233445566ff";
    const FIXTURE_OWNER: &str = "0a1b2c3d00112233445566778899aabb";
    const FIXTURE_ROOT: &str = "/Users/me/.coop-apple/backends/apple-container-v1/runtime";
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINiqkOnkRV06x+SuorkF+O3KdBTVFznIV0+b58cidW1N root@guest\n";

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{name}")).unwrap()
    }

    type Responder = Box<dyn Fn(&[String]) -> Output>;
    type Calls = Rc<RefCell<Vec<Vec<String>>>>;

    /// Records every argument vector and answers from a shared responder.
    #[derive(Clone)]
    struct FakeExec {
        calls: Calls,
        respond: Rc<Responder>,
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

    /// The runtime's `version`, qualified or not.
    fn version(args: &[String], qualified: bool) -> Option<Output> {
        starts(args, &["version"]).then(|| {
            let v = fixture("version.json");
            ok(&if qualified {
                v
            } else {
                v.replace("\"protocol\" : 1", "\"protocol\" : 99")
            })
        })
    }

    /// Runtime and builder backed by one responder (they are told apart by
    /// their argument vectors).
    fn backend(cfg: &CoopConfig, respond: Responder) -> (AppleContainerBackend, Calls) {
        let calls: Calls = Rc::new(RefCell::new(Vec::new()));
        let exec = FakeExec {
            calls: Rc::clone(&calls),
            respond: Rc::new(respond),
        };
        (
            AppleContainerBackend::with_exec(cfg, Box::new(exec.clone()), Box::new(exec)),
            calls,
        )
    }

    /// Short deadlines: nothing in these tests really boots.
    fn test_cfg(dir: &Path) -> CoopConfig {
        let mut cfg = CoopConfig {
            data_dir: ConfigPath::new(dir),
            ..CoopConfig::default()
        };
        cfg.apple_container.boot_timeout_seconds = crate::config::TimeoutSecs::new(2).unwrap();
        cfg
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

    fn sandbox_name(owner: &Owner) -> MachineName {
        MachineName::new(format!("coop-{}-00112233445566ff", owner.id.short())).unwrap()
    }

    fn write_sidecar(inst: &Instance, owner: &Owner) -> MachineSidecar {
        let sidecar = MachineSidecar {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            owner_id: owner.id.clone(),
            instance_id: "00112233445566ff".into(),
            machine_id: sandbox_name(owner),
            image_ref: "local/coop-exp:fx".into(),
            image_digest: "sha256:3c8ada4041838a362f1d3c0805e487beff8ef85383044efeb07844cdd7c1e0b3"
                .into(),
            image_manifest_id: "m".into(),
            guest_user: crate::guest::GuestUser::default(),
            requested_cpus: 2,
            requested_memory_bytes: 2048 * 1024 * 1024,
            host_key_fingerprint: "SHA256:x".into(),
            last_observed_owner_pid: None,
            last_observed_ip: None,
            reenroll_host_key: false,
            creation_state: CreationState::Ready,
            created_at: "now".into(),
            runtime_identity: "test".into(),
        };
        sidecar.save(inst).unwrap();
        sidecar
    }

    /// A real inspect record rewritten for this test's owner, sandbox, and
    /// runtime root, in `status`.
    fn inspect_json(cfg: &CoopConfig, owner: &Owner, status: &str) -> String {
        let base = if status == "running" {
            fixture("inspect-running.json")
        } else {
            fixture("inspect-stopped.json")
        };
        let root = canonical_path(&cfg.state_root().join(RUNTIME_DIR));
        base.replace(FIXTURE_ID, sandbox_name(owner).as_str())
            .replace(FIXTURE_OWNER, owner.id.as_str())
            .replace(FIXTURE_ROOT, &root.display().to_string())
            .replace(
                "\"status\" : \"stopped\"",
                &format!("\"status\" : \"{status}\""),
            )
    }

    fn with_generation(json: &str, generation: u64) -> String {
        json.replace(
            "\"diskGeneration\" : 0",
            &format!("\"diskGeneration\" : {generation}"),
        )
    }

    /// Commands that change runtime state. None may run before the gate passes.
    fn is_mutating(args: &[String]) -> bool {
        [
            &["create"][..],
            &["start"],
            &["stop"],
            &["exec"],
            &["set"],
            &["grow"],
            &["commit"],
            &["restore"],
            &["delete"],
            &["init"],
            &["image", "import"],
            &["image", "delete"],
            &["image", "save"],
            &["disk", "delete"],
            &["build"],
            &["system", "start"],
            &["system", "stop"],
        ]
        .iter()
        .any(|p| starts(args, p))
    }

    fn mutations(calls: &Calls) -> Vec<String> {
        calls
            .borrow()
            .iter()
            .filter(|c| is_mutating(c))
            .map(|c| c.first().cloned().unwrap_or_default())
            .collect()
    }

    fn kind(err: &anyhow::Error) -> &AppleError {
        err.downcast_ref::<AppleError>().unwrap()
    }

    #[test]
    fn unqualified_runtime_refuses_create_before_any_side_effect() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let (be, calls) = backend(
            &cfg,
            Box::new(|args| version(args, false).unwrap_or_else(|| ok("[]"))),
        );
        let err = be.create_and_start(&cfg, &inst, None, &[]).unwrap_err();
        assert!(
            matches!(kind(&err), AppleError::RuntimeUnqualified(_)),
            "{err:#}"
        );
        assert!(mutations(&calls).is_empty(), "{:?}", calls.borrow());
        assert!(!MachineSidecar::path(&inst).exists());
        assert!(Journal::try_load(&inst).unwrap().is_none());
    }

    #[test]
    fn unqualified_runtime_refuses_ssh_target_and_start() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let json = inspect_json(&cfg, &owner, "running");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| version(args, false).unwrap_or_else(|| ok(&json))),
        );
        for err in [
            be.ssh_target(&cfg, &inst).unwrap_err(),
            be.start_existing(&cfg, &inst).unwrap_err(),
        ] {
            assert!(
                matches!(kind(&err), AppleError::RuntimeUnqualified(_)),
                "{err:#}"
            );
        }
        assert!(mutations(&calls).is_empty());
    }

    #[test]
    fn recovery_hint_names_the_command_for_each_operation() {
        let name = InstanceName::new("vm1").unwrap();
        assert!(recovery_hint(Operation::SetResources, &name).contains("`coop start vm1`"));
        assert!(recovery_hint(Operation::RestoreDisk, &name).contains("`coop start vm1`"));
        let create = recovery_hint(Operation::Create, &name);
        assert!(
            create.contains("`coop destroy vm1`") && create.contains("`coop up`"),
            "{create}"
        );
        let destroy = recovery_hint(Operation::Destroy, &name);
        assert!(
            destroy.contains("`coop destroy vm1`") && !destroy.contains("coop up"),
            "{destroy}"
        );
    }

    /// Listings report `unknown` (an error here) instead of `stopped` when
    /// the state cannot be read, is transitional, or an operation is unfinished.
    #[test]
    fn probe_running_distinguishes_unknown_from_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);

        for (status, expected) in [
            ("running", Some(true)),
            ("stopped", Some(false)),
            ("booting", None),
            ("crashed", None),
        ] {
            let json = inspect_json(&cfg, &owner, status);
            let (be, _) = backend(
                &cfg,
                Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
            );
            let probe = be.probe_running(&inst);
            assert_eq!(probe.as_ref().ok().copied(), expected, "{status}");
            if let Err(e) = probe {
                assert!(matches!(kind(&e), AppleError::OperationUncertain(_)));
            }
        }

        // No record yet: nothing exists to be running.
        let bare = Instance {
            name: InstanceName::new("fresh").unwrap(),
            dir: cfg.instances_dir().join("fresh"),
            ..inst.clone()
        };
        std::fs::create_dir_all(&bare.dir).unwrap();
        let (be, _) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| fail("unexpected"))),
        );
        assert_eq!(be.probe_running(&bare).ok(), Some(false));

        let (be, _) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| fail("owner unreachable"))),
        );
        assert!(be.probe_running(&inst).is_err());

        Journal::begin(&inst, &owner, JournalOp::Create, sandbox_name(&owner)).unwrap();
        let json = inspect_json(&cfg, &owner, "stopped");
        let (be, _) = backend(
            &cfg,
            Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
        );
        let err = be.probe_running(&inst).unwrap_err();
        assert!(matches!(kind(&err), AppleError::OperationUncertain(_)));
    }

    #[test]
    fn liveness_probe_errors_are_not_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);

        let (be, _) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| fail("interrupted"))),
        );
        assert!(be.as_stopped(inst.clone()).is_err());
        assert!(be.as_running(&cfg, inst.clone()).is_err());
        assert!(!be.is_running(&inst));

        for (status, stopped_ok) in [("booting", false), ("crashed", false), ("stopped", true)] {
            let json = inspect_json(&cfg, &owner, status);
            let (be, _) = backend(
                &cfg,
                Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
            );
            assert_eq!(be.as_stopped(inst.clone()).is_ok(), stopped_ok, "{status}");
        }
    }

    #[test]
    fn destroy_refuses_unowned_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let mut sidecar = write_sidecar(&inst, &owner);
        sidecar.machine_id = MachineName::new("users-own-sandbox").unwrap();
        sidecar.save(&inst).unwrap();
        let (be, calls) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| ok("[]"))),
        );
        let err = be.destroy_instance(&cfg, &inst).unwrap_err();
        assert!(matches!(kind(&err), AppleError::IdentityConflict(_)));
        assert!(mutations(&calls).is_empty());
        assert!(inst.dir.exists(), "metadata must survive a refused destroy");
    }

    #[test]
    fn destroy_reconciles_interrupted_create() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let mut journal =
            Journal::begin(&inst, &owner, JournalOp::Create, sandbox_name(&owner)).unwrap();
        journal.advance(&inst, Stage::CreatingMachine).unwrap();
        // The create never landed; an unrelated sandbox exists.
        let (be, calls) = backend(
            &cfg,
            Box::new(|args| {
                version(args, true).unwrap_or_else(|| {
                    if starts(args, &["list"]) {
                        return ok(r#"[{"id":"someone-else","status":"running","owner":"x"}]"#);
                    }
                    if starts(args, &["reconcile"]) {
                        return ok("{}");
                    }
                    fail("unexpected")
                })
            }),
        );
        be.destroy_instance(&cfg, &inst).unwrap();
        assert!(mutations(&calls).is_empty());
        // The runtime sweeps what the interrupted create left inside it.
        assert!(calls.borrow().iter().any(|c| starts(c, &["reconcile"])));
        assert!(!inst.dir.exists());
    }

    #[test]
    fn destroy_stops_then_deletes_owned_sandbox() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let name = sandbox_name(&owner);
        let state = Rc::new(RefCell::new((false, false))); // (stopped, deleted)
        let (s, n) = (Rc::clone(&state), name.clone());
        let (running, stopped) = (
            inspect_json(&cfg, &owner, "running"),
            inspect_json(&cfg, &owner, "stopped"),
        );
        let owner_id = owner.id.as_str().to_string();
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["list"]) {
                    return ok(&if s.borrow().1 {
                        "[]".into()
                    } else {
                        format!(r#"[{{"id":"{n}","status":"running","owner":"{owner_id}"}}]"#)
                    });
                }
                if starts(args, &["inspect"]) {
                    return ok(if s.borrow().0 { &stopped } else { &running });
                }
                if starts(args, &["stop"]) {
                    s.borrow_mut().0 = true;
                    return ok("");
                }
                if starts(args, &["delete"]) {
                    assert!(
                        args.windows(2)
                            .any(|w| w[0] == "--owner" && w[1] == owner_id)
                    );
                    s.borrow_mut().1 = true;
                    return ok("");
                }
                fail("unexpected")
            }),
        );
        be.destroy_instance(&cfg, &inst).unwrap();
        assert_eq!(mutations(&calls), ["stop", "delete"]);
        assert!(!inst.dir.exists());
    }

    #[test]
    fn unconfirmed_stop_is_uncertain_not_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let json = inspect_json(&cfg, &owner, "running");
        let (be, _) = backend(
            &cfg,
            Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
        );
        let err = be
            .runtime()
            .unwrap()
            .stop_and_confirm(&sandbox_name(&owner))
            .unwrap_err();
        assert!(matches!(kind(&err), AppleError::OperationUncertain(_)));
    }

    #[test]
    fn create_args_carry_exact_values_and_no_host_surfaces() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let (be, _) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| ok(""))),
        );
        let rt = be.runtime().unwrap();
        let name = sandbox_name(&owner);
        let args = create_args(
            rt,
            &name,
            &Source::Image("local/coop-0a1b2c3d:00"),
            NonZeroU8::new(4).unwrap(),
            4096,
            GiB::new(32).unwrap(),
            &owner,
        );
        let joined = args.join(" ");
        assert!(joined.starts_with("create --root /"), "{joined}");
        for want in [
            name.as_str(),
            "--image local/coop-0a1b2c3d:00",
            "--cpus 4",
            "--memory-mib 4096",
            "--disk-gib 32",
            &format!("--owner {}", owner.id.as_str()),
        ] {
            assert!(joined.contains(want), "{want}: {joined}");
        }
        for never in ["mount", "volume", "publish", "socket", "ssh", "network"] {
            assert!(!joined.contains(never), "{never}: {joined}");
        }
        let disk = MachineName::generate(&owner.id).unwrap();
        let joined = create_args(
            rt,
            &name,
            &Source::Disk(&disk),
            NonZeroU8::new(1).unwrap(),
            512,
            GiB::new(8).unwrap(),
            &owner,
        )
        .join(" ");
        assert!(joined.contains(&format!("--from-disk {disk}")) && !joined.contains("--image"));
        assert_eq!(mib_to_bytes(4096), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn guest_commands_are_argv_not_shell_text() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let (be, calls) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| ok(""))),
        );
        let rt = be.runtime().unwrap();
        let words = [
            "/usr/bin/printf",
            "%s\\n",
            "a b",
            "it's",
            "$(id)",
            "; true",
            "",
        ];
        rt.guest(
            &sandbox_name(&owner),
            &words,
            Duration::from_secs(5),
            MAX_TEXT_OUTPUT,
        )
        .unwrap();
        let call = calls.borrow().last().cloned().unwrap();
        let dashdash = call.iter().position(|a| a == "--").unwrap();
        assert_eq!(&call[dashdash + 1..], words);
    }

    #[test]
    fn capabilities_include_disk_operations() {
        let be = AppleContainerBackend::new();
        let caps = be.capabilities();
        for cap in [
            Capability::DiskResize,
            Capability::DiskSnapshots,
            Capability::MachineResources,
        ] {
            assert!(caps.has(cap), "{cap:?}");
        }
        assert!(!caps.has(Capability::LiveMounts));
        assert!(!be.mounts_are_live());
        assert_eq!(
            be.local_endpoint_route(&NetworkConfig::default()),
            LocalEndpointRoute::ReverseTunnel
        );
    }

    #[test]
    fn resolve_binary_rejects_relative_missing_and_writable() {
        assert!(resolve_binary(Some(Path::new("coop-sandbox")), &[], Tool::Runtime).is_err());
        assert!(
            resolve_binary(
                Some(Path::new("/nonexistent/coop-sandbox")),
                &[],
                Tool::Runtime
            )
            .is_err()
        );
        let tmp = tempfile::tempdir().unwrap();
        let writable = tmp.path().join("coop-sandbox");
        std::fs::write(&writable, "#!/bin/sh\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        let err = resolve_binary(Some(&writable), &[], Tool::Runtime).unwrap_err();
        assert!(format!("{err:#}").contains("writable"), "{err:#}");
        // A configured path is the only candidate: defaults are not a fallback.
        let err = resolve_binary(
            Some(Path::new("/nonexistent/x")),
            &[writable],
            Tool::Runtime,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("/nonexistent/x"), "{err:#}");
    }

    /// Only a regular, executable, user- or root-owned file that no group or
    /// other user can write is accepted.
    #[test]
    fn check_binary_accepts_only_private_executables() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("tool");
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        let set = |mode| std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(mode));

        set(0o755).unwrap();
        assert_eq!(check_binary(&bin).unwrap(), bin.canonicalize().unwrap());
        for (mode, why) in [
            (0o644, "not an executable"),
            (0o775, "writable"),
            (0o757, "writable"),
        ] {
            set(mode).unwrap();
            let err = check_binary(&bin).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{mode:o}: {err:#}");
        }
        let dir = tmp.path().join("dir");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(format!("{:#}", check_binary(&dir).unwrap_err()).contains("not an executable"));

        // Root-owned system binaries are trusted.
        assert!(check_binary(Path::new("/bin/sh")).is_ok());
    }

    #[test]
    fn missing_binary_names_the_tool_and_how_to_get_it() {
        for (tool, name, hint) in [
            (Tool::Runtime, "`coop-sandbox`", "build-coop-sandbox.sh"),
            (Tool::Builder, "`container`", "[apple_container] builder"),
        ] {
            let err = resolve_binary(None, &[], tool).unwrap_err();
            let text = format!("{err:#}");
            assert!(text.contains(name) && text.contains(hint), "{text}");
        }
        assert_eq!(AppleContainerBackend::new().to_string(), "apple-container");
    }

    #[test]
    fn interrupted_resize_is_reconciled_from_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let mut sidecar = write_sidecar(&inst, &owner);
        sidecar.requested_cpus = 8;
        sidecar.requested_memory_bytes = 1 << 30;
        sidecar.save(&inst).unwrap();
        let mut journal = Journal::begin(
            &inst,
            &owner,
            JournalOp::SetResources {
                prior: (8, 1 << 30),
            },
            sandbox_name(&owner),
        )
        .unwrap();
        journal.advance(&inst, Stage::Applying).unwrap();

        let json = inspect_json(&cfg, &owner, "stopped");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
        );
        AppleContainerBackend::recover_journal(be.runtime().unwrap(), &cfg, &inst).unwrap();
        assert!(Journal::try_load(&inst).unwrap().is_none());
        let after = MachineSidecar::load(&inst).unwrap();
        // The runtime record (2 vCPUs / 2 GiB) is authoritative.
        assert_eq!(after.requested_cpus, 2);
        assert_eq!(after.requested_memory_bytes, 2048 * 1024 * 1024);
        assert!(mutations(&calls).is_empty());

        // A running sandbox is not reconciled.
        let mut journal = Journal::begin(
            &inst,
            &owner,
            JournalOp::SetResources {
                prior: (8, 1 << 30),
            },
            sandbox_name(&owner),
        )
        .unwrap();
        journal.advance(&inst, Stage::Applying).unwrap();
        let json = inspect_json(&cfg, &owner, "running");
        let (be, _) = backend(
            &cfg,
            Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
        );
        assert!(
            AppleContainerBackend::recover_journal(be.runtime().unwrap(), &cfg, &inst).is_err()
        );
        assert!(Journal::try_load(&inst).unwrap().is_some());
    }

    /// Only a higher disk generation lets the next start pin a new host key.
    #[test]
    fn interrupted_restore_reenrolls_only_when_the_disk_was_replaced() {
        for (generation, reenroll) in [(3, false), (4, true)] {
            let tmp = tempfile::tempdir().unwrap();
            let cfg = test_cfg(tmp.path());
            let owner = Owner::load_or_init(&cfg).unwrap();
            let inst = test_inst(&cfg);
            write_sidecar(&inst, &owner);
            let mut journal = Journal::begin(
                &inst,
                &owner,
                JournalOp::RestoreDisk {
                    prior_generation: 3,
                },
                sandbox_name(&owner),
            )
            .unwrap();
            journal.advance(&inst, Stage::Applying).unwrap();
            let json = with_generation(&inspect_json(&cfg, &owner, "stopped"), generation);
            let (be, _) = backend(
                &cfg,
                Box::new(move |args| version(args, true).unwrap_or_else(|| ok(&json))),
            );
            AppleContainerBackend::recover_journal(be.runtime().unwrap(), &cfg, &inst).unwrap();
            assert!(Journal::try_load(&inst).unwrap().is_none());
            assert_eq!(
                MachineSidecar::load(&inst).unwrap().reenroll_host_key,
                reenroll,
                "{generation}"
            );
        }
    }

    #[test]
    fn restore_journals_the_generation_and_marks_reenrollment() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let image = ImageName::new("default").unwrap();
        ImageManifest {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            image_ref: "local/coop-exp:fx".into(),
            digest: "sha256:3c8ada4041838a362f1d3c0805e487beff8ef85383044efeb07844cdd7c1e0b3"
                .into(),
            disk: None,
            manifest_id: "m2".into(),
            base_image: image::BASE_IMAGE.into(),
            platform: image::PLATFORM.into(),
            guest_user: crate::guest::GuestUser::default(),
            pubkey_fingerprint: String::new(),
            created: "now".into(),
        }
        .save(&cfg, &image)
        .unwrap();
        let restored = Rc::new(RefCell::new(false));
        let r = Rc::clone(&restored);
        let stopped = inspect_json(&cfg, &owner, "stopped");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["image", "list"]) {
                    return ok(
                        r#"[{"reference":"local/coop-exp:fx","digest":"sha256:3c8ada4041838a362f1d3c0805e487beff8ef85383044efeb07844cdd7c1e0b3"}]"#,
                    );
                }
                if starts(args, &["inspect"]) {
                    return ok(&with_generation(&stopped, u64::from(*r.borrow())));
                }
                if starts(args, &["restore"]) {
                    assert!(
                        args.windows(2)
                            .any(|w| w[0] == "--image" && w[1] == "local/coop-exp:fx")
                    );
                    *r.borrow_mut() = true;
                    return ok("{}");
                }
                fail("unexpected")
            }),
        );
        // A disk built for another guest user is refused before any change.
        let other = ImageName::new("other").unwrap();
        let mut foreign = ImageManifest::load(&cfg, &image).unwrap();
        foreign.guest_user = crate::guest::GuestUser::new("dev").unwrap();
        foreign.save(&cfg, &other).unwrap();
        let err = be
            .restore_disk(&cfg, &StoppedInstance::new(inst.clone()), &other)
            .unwrap_err();
        assert!(format!("{err:#}").contains("guest user 'dev'"), "{err:#}");
        assert!(mutations(&calls).is_empty());
        assert!(Journal::try_load(&inst).unwrap().is_none());

        be.restore_disk(&cfg, &StoppedInstance::new(inst.clone()), &image)
            .unwrap();
        assert_eq!(mutations(&calls), ["restore"]);
        let after = MachineSidecar::load(&inst).unwrap();
        assert!(after.reenroll_host_key);
        assert_eq!(after.image_manifest_id, "m2");
        assert!(Journal::try_load(&inst).unwrap().is_none());
    }

    #[test]
    fn resize_grows_but_never_shrinks() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        // The fixture disk is 8 GiB.
        let grown = Rc::new(RefCell::new(false));
        let g = Rc::clone(&grown);
        let stopped = inspect_json(&cfg, &owner, "stopped");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["inspect"]) {
                    let bytes = if *g.borrow() { 32u64 << 30 } else { 8u64 << 30 };
                    return ok(&stopped.replace(
                        "\"diskBytes\" : 8589934592",
                        &format!("\"diskBytes\" : {bytes}"),
                    ));
                }
                if starts(args, &["grow"]) {
                    assert!(
                        args.windows(2)
                            .any(|w| w[0] == "--disk-gib" && w[1] == "32")
                    );
                    *g.borrow_mut() = true;
                    return ok("{}");
                }
                fail("unexpected")
            }),
        );
        let stopped_inst = StoppedInstance::new(inst.clone());
        let err = be
            .resize_disk(&cfg, &stopped_inst, GiB::new(4).unwrap())
            .unwrap_err();
        assert!(format!("{err:#}").contains("shrinking"), "{err:#}");
        be.resize_disk(&cfg, &stopped_inst, GiB::new(8).unwrap())
            .unwrap();
        assert!(mutations(&calls).is_empty());
        be.resize_disk(&cfg, &stopped_inst, GiB::new(32).unwrap())
            .unwrap();
        assert_eq!(mutations(&calls), ["grow"]);
        assert!(be.disk_path(&inst).unwrap().ends_with(format!(
            "runtime/sandboxes/{}/rootfs.ext4",
            sandbox_name(&owner)
        )));
    }

    #[test]
    fn failed_restart_boot_stops_the_sandbox_and_reports_the_console_log() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let json = inspect_json(&cfg, &owner, "stopped");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["inspect"]) {
                    return ok(&json);
                }
                if starts(args, &["start"]) {
                    return fail("owner failed: vmnet refused");
                }
                if starts(args, &["logs"]) {
                    return ok("kernel panic \x1b[31m- not syncing\n");
                }
                if starts(args, &["stop"]) {
                    return ok("");
                }
                fail("unexpected")
            }),
        );
        let err = be.start_existing(&cfg, &inst).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("APPLE_BOOT_TIMEOUT"), "{msg}");
        assert!(msg.contains("kernel panic ?[31m- not syncing"), "{msg}");
        assert_eq!(mutations(&calls), ["start", "stop"]);
    }

    /// A normal start must reject a changed host key; only a coop restore
    /// lets the next start pin a new one.
    #[test]
    fn start_enforces_the_pin_unless_coop_replaced_the_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let mut sidecar = write_sidecar(&inst, &owner);
        std::fs::write(state::known_hosts_path(&inst), "old-pin\n").unwrap();
        let respond = |cfg: &CoopConfig, owner: &Owner| -> Responder {
            let booted = Rc::new(RefCell::new(false));
            let (stopped, running) = (
                inspect_json(cfg, owner, "stopped"),
                inspect_json(cfg, owner, "running"),
            );
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["inspect"]) {
                    return ok(if *booted.borrow() { &running } else { &stopped });
                }
                if starts(args, &["start"]) {
                    *booted.borrow_mut() = true;
                    return ok("{}");
                }
                if starts(args, &["exec"]) {
                    return ok(KEY);
                }
                if starts(args, &["stop"]) {
                    *booted.borrow_mut() = false;
                    return ok("");
                }
                fail("unexpected")
            })
        };
        let (be, _) = backend(&cfg, respond(&cfg, &owner));
        let err = be.start_existing(&cfg, &inst).unwrap_err();
        assert!(
            matches!(kind(&err), AppleError::HostKeyChanged(_)),
            "{err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(state::known_hosts_path(&inst)).unwrap(),
            "old-pin\n"
        );

        sidecar.reenroll_host_key = true;
        sidecar.save(&inst).unwrap();
        let (be, _) = backend(&cfg, respond(&cfg, &owner));
        // SSH never answers here, so this start fails after pinning; the
        // re-enroll window must close anyway.
        assert!(be.start_existing(&cfg, &inst).is_err());
        assert!(!MachineSidecar::load(&inst).unwrap().reenroll_host_key);
        let pinned = std::fs::read_to_string(state::known_hosts_path(&inst)).unwrap();
        assert!(
            pinned.contains("AAAAC3NzaC1lZDI1NTE5AAAAINiqkOnkRV06x"),
            "{pinned}"
        );
    }

    #[test]
    #[expect(clippy::panic, reason = "test assertion")]
    fn unqualified_running_sandbox_is_an_error_not_stopped() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let json = inspect_json(&cfg, &owner, "running");
        let (be, _) = backend(
            &cfg,
            Box::new(move |args| version(args, false).unwrap_or_else(|| ok(&json))),
        );
        let Err(err) = be.as_running(&cfg, inst.clone()) else {
            panic!("a running sandbox on an unqualified runtime must not yield a target");
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
        let stopped = Rc::new(RefCell::new(false));
        let s = Rc::clone(&stopped);
        let (on, off) = (
            inspect_json(&cfg, &owner, "running"),
            inspect_json(&cfg, &owner, "stopped"),
        );
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, false) {
                    return o;
                }
                if starts(args, &["inspect"]) {
                    return ok(if *s.borrow() { &off } else { &on });
                }
                if starts(args, &["stop"]) {
                    *s.borrow_mut() = true;
                    return ok("");
                }
                fail("unexpected")
            }),
        );
        be.stop_unproven(&cfg, &inst).unwrap();
        assert!(*stopped.borrow());
        assert_eq!(mutations(&calls), ["stop"]);
    }

    #[test]
    fn follow_logs_replace_guest_control_bytes() {
        // `stream_logs` needs a RunningInstance, which cannot be minted without
        // SSH here, so this drives the same streaming call and sanitizer it uses.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let (be, _) = backend(
            &cfg,
            Box::new(|args| {
                version(args, true).unwrap_or_else(|| {
                    if starts(args, &["logs"]) {
                        return ok("ok\n\x1b]52;c;ZXZpbA==\x07pwned\n");
                    }
                    fail("unexpected")
                })
            }),
        );
        let rt = be.runtime().unwrap();
        let mut lines = Vec::new();
        rt.exec
            .run_streaming(&rt.args(&["logs"], &["m", "--follow"]), &mut |line| {
                lines.push(cli::sanitize_for_display(&String::from_utf8_lossy(line)));
                Ok(())
            })
            .unwrap();
        assert_eq!(lines, ["ok", "?]52;c;ZXZpbA==?pwned"]);
    }

    #[test]
    fn host_key_read_retries_a_half_written_file_and_detects_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let sidecar = write_sidecar(&test_inst(&cfg), &owner);
        let running = inspect_json(&cfg, &owner, "running");
        for restarted in [false, true] {
            let reads = Rc::new(RefCell::new(0));
            let r = Rc::clone(&reads);
            let now = if restarted {
                let pid =
                    serde_json::from_str::<serde_json::Value>(&running).unwrap()["live"]["pid"]
                        .as_i64()
                        .unwrap();
                running.replace(
                    &format!("\"pid\" : {pid}"),
                    &format!("\"pid\" : {}", pid + 1),
                )
            } else {
                running.clone()
            };
            let (be, _) = backend(
                &cfg,
                Box::new(move |args| {
                    if let Some(o) = version(args, true) {
                        return o;
                    }
                    if starts(args, &["exec"]) {
                        *r.borrow_mut() += 1;
                        // First read catches the file mid-write.
                        return ok(if *r.borrow() == 1 {
                            "ssh-ed25519 AAAAC3Nza"
                        } else {
                            KEY
                        });
                    }
                    if starts(args, &["inspect"]) {
                        return ok(&now);
                    }
                    fail("unexpected")
                }),
            );
            let rt = be.runtime().unwrap();
            let inspect = protocol::parse_inspect(&running, &sidecar.machine_id).unwrap();
            let ready = security::verify_effective(&inspect, &rt.expected(&sidecar)).unwrap();
            let got = rt.read_host_key(&ready, Instant::now() + Duration::from_secs(5));
            assert_eq!(*reads.borrow(), 2);
            if restarted {
                assert!(matches!(
                    kind(&got.unwrap_err()),
                    AppleError::IdentityConflict(_)
                ));
            } else {
                assert!(got.unwrap().fingerprint().starts_with("SHA256:"));
            }
        }
    }

    #[test]
    fn legacy_instance_destroy_removes_local_state_only() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        std::fs::write(
            MachineSidecar::path(&inst),
            r#"{"schema_version":1,"backend":"apple-container","machine_id":"coop-0a1b2c3d-1","network_id":"coop-0a1b2c3d-1"}"#,
        )
        .unwrap();
        let (be, calls) = backend(&cfg, Box::new(|_| fail("no runtime call expected")));
        be.destroy_instance(&cfg, &inst).unwrap();
        assert!(calls.borrow().is_empty());
        assert!(!inst.dir.exists());
    }

    fn manifest(image_ref: &str, disk: Option<CommittedDisk>) -> ImageManifest {
        ImageManifest {
            schema_version: state::SCHEMA_VERSION,
            backend: state::BACKEND_TAG.into(),
            image_ref: image_ref.into(),
            digest: format!("sha256:{}", "a".repeat(64)),
            disk,
            manifest_id: "m".into(),
            base_image: image::BASE_IMAGE.into(),
            platform: image::PLATFORM.into(),
            guest_user: crate::guest::GuestUser::default(),
            pubkey_fingerprint: String::new(),
            created: "now".into(),
        }
    }

    /// Only this installation's images and disks are deleted, and only once
    /// no saved manifest still uses them; an unreadable manifest keeps all.
    #[test]
    fn release_deletes_only_owned_and_unreferenced_content() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let (be, calls) = backend(
            &cfg,
            Box::new(|args| version(args, true).unwrap_or_else(|| ok(""))),
        );
        let rt = be.runtime().unwrap();
        let owned_ref = format!("local/coop-{}:abc", owner.id.short());
        let owned_disk = MachineName::generate(&owner.id).unwrap();
        let foreign_disk = MachineName::new("coop-ffffffff-0011223344556677").unwrap();
        let committed = |name: &MachineName| {
            manifest(
                &owned_ref,
                Some(CommittedDisk {
                    name: name.clone(),
                    bytes: 1,
                }),
            )
        };
        let deleted = || -> Vec<Vec<String>> {
            calls
                .borrow()
                .iter()
                .filter(|c| is_mutating(c))
                .cloned()
                .collect()
        };
        let base = ImageName::new("default").unwrap();
        manifest(&owned_ref, None).save(&cfg, &base).unwrap();

        // Foreign content is never touched.
        release_manifest(
            rt,
            &cfg,
            &owner,
            &manifest("local/someone-else:1", None),
            None,
        );
        release_manifest(rt, &cfg, &owner, &committed(&foreign_disk), None);
        // The image tag is still used by `default`; the owned disk is not.
        release_manifest(rt, &cfg, &owner, &committed(&owned_disk), None);
        let got = deleted();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(
            starts(&got[0], &["disk", "delete"]) && got[0].last() == Some(&owned_disk.to_string())
        );

        // A disk another manifest uses is kept.
        calls.borrow_mut().clear();
        committed(&owned_disk)
            .save(&cfg, &ImageName::new("snap").unwrap())
            .unwrap();
        release_manifest(rt, &cfg, &owner, &committed(&owned_disk), Some(&base));
        let got = deleted();
        assert!(
            got.iter().all(|c| !starts(c, &["disk", "delete"])),
            "{got:?}"
        );

        // Once nothing else uses the tag, it goes with the last manifest.
        calls.borrow_mut().clear();
        std::fs::remove_dir_all(cfg.image_dir(&ImageName::new("snap").unwrap())).unwrap();
        release_manifest(rt, &cfg, &owner, &manifest(&owned_ref, None), Some(&base));
        let got = deleted();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(starts(&got[0], &["image", "delete"]) && got[0].last() == Some(&owned_ref));

        // An unreadable manifest might reference anything: keep everything.
        calls.borrow_mut().clear();
        let broken = ImageName::new("broken").unwrap();
        std::fs::create_dir_all(cfg.image_dir(&broken)).unwrap();
        std::fs::write(cfg.image_dir(&broken).join("apple-image.json"), "{").unwrap();
        release_manifest(rt, &cfg, &owner, &committed(&owned_disk), Some(&base));
        assert!(deleted().is_empty());
    }

    #[test]
    fn verify_image_checks_presence_and_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let listed = format!(r#"[{{"reference":"local/x:1","digest":"{digest}"}}]"#);
        let (be, _) = backend(
            &cfg,
            Box::new(move |args| {
                version(args, true).unwrap_or_else(|| {
                    if starts(args, &["image", "list"]) {
                        return ok(&listed);
                    }
                    if starts(args, &["disk", "list"]) {
                        return ok(
                            r#"[{"name":"coop-0a1b2c3d-1","logicalBytes":1,"allocatedBytes":1}]"#,
                        );
                    }
                    fail("unexpected")
                })
            }),
        );
        let rt = be.runtime().unwrap();
        rt.verify_image(&manifest("local/x:1", None)).unwrap();
        let mut stale = manifest("local/x:1", None);
        stale.digest = format!("sha256:{}", "b".repeat(64));
        for bad in [
            manifest("local/missing:1", None),
            stale,
            manifest(
                "local/x:1",
                Some(CommittedDisk {
                    name: MachineName::generate(&owner.id).unwrap(),
                    bytes: 1,
                }),
            ),
        ] {
            let err = rt.verify_image(&bad).unwrap_err();
            assert!(
                matches!(kind(&err), AppleError::IdentityConflict(_)),
                "{err:#}"
            );
        }
        let present = MachineName::new("coop-0a1b2c3d-1").unwrap();
        rt.verify_image(&manifest(
            "local/gone:1",
            Some(CommittedDisk {
                name: present,
                bytes: 1,
            }),
        ))
        .unwrap();
    }

    #[test]
    fn commit_saves_a_disk_manifest_from_the_runtime_record() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let sidecar = write_sidecar(&inst, &owner);
        let stopped = inspect_json(&cfg, &owner, "stopped");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["inspect"]) {
                    return ok(&stopped);
                }
                if starts(args, &["commit"]) {
                    let name = args.last().unwrap();
                    return ok(&format!(
                        r#"{{"name":"{name}","logicalBytes":8589934592,"allocatedBytes":1}}"#
                    ));
                }
                fail("unexpected")
            }),
        );
        let image = ImageName::new("snap").unwrap();
        be.commit_disk(&cfg, &StoppedInstance::new(inst.clone()), &image)
            .unwrap();
        let call = calls
            .borrow()
            .iter()
            .find(|c| starts(c, &["commit"]))
            .cloned()
            .unwrap();
        let disk = call.last().unwrap().clone();
        assert!(call.contains(&sidecar.machine_id.to_string()));
        assert!(
            MachineName::new(disk.clone())
                .unwrap()
                .belongs_to(&owner.id)
        );
        let saved = ImageManifest::load(&cfg, &image).unwrap();
        let committed = saved.disk.unwrap();
        assert_eq!(committed.name.as_str(), disk);
        assert_eq!(committed.bytes, 8 << 30);
        // Image identity comes from the runtime record, not the instance.
        assert_eq!(saved.image_ref, "local/coop-exp:fx");
        assert_eq!(covering_gib(committed.bytes).unwrap(), GiB::new(8).unwrap());
    }

    #[test]
    fn disk_bytes_round_up_to_whole_gib() {
        assert_eq!(covering_gib(1).unwrap(), GiB::new(1).unwrap());
        assert_eq!(covering_gib((8 << 30) + 1).unwrap(), GiB::new(9).unwrap());
        assert!(covering_gib(0).is_err());
    }

    /// A readback that does not match the request is uncertain, and the
    /// journal stays for `start` to reconcile.
    #[test]
    fn resource_change_that_does_not_apply_is_uncertain() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let stopped = inspect_json(&cfg, &owner, "stopped");
        let (be, calls) = backend(
            &cfg,
            Box::new(move |args| {
                if let Some(o) = version(args, true) {
                    return o;
                }
                if starts(args, &["inspect"]) {
                    return ok(&stopped);
                }
                if starts(args, &["set"]) {
                    return ok("{}");
                }
                fail("unexpected")
            }),
        );
        let err = be
            .set_machine_resources(
                &cfg,
                &StoppedInstance::new(inst.clone()),
                None,
                NonZeroU8::new(6),
                false,
            )
            .unwrap_err();
        assert!(
            matches!(kind(&err), AppleError::OperationUncertain(_)),
            "{err:#}"
        );
        let set = calls
            .borrow()
            .iter()
            .find(|c| starts(c, &["set"]))
            .cloned()
            .unwrap();
        assert!(set.windows(2).any(|w| w[0] == "--cpus" && w[1] == "6"));
        assert!(!set.contains(&"--memory-mib".to_string()));
        // The journal carries the resources the runtime had before the change.
        assert_eq!(
            Journal::try_load(&inst).unwrap().unwrap().op,
            JournalOp::SetResources {
                prior: (2, 2048 * 1024 * 1024)
            }
        );
    }

    #[test]
    fn legacy_journal_only_instance_can_be_destroyed() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        std::fs::write(
            inst.dir.join("operation.json"),
            r#"{"schema_version":1,"backend":"apple-container","machine_id":"coop-0a1b2c3d-2","network_id":"coop-0a1b2c3d-2"}"#,
        )
        .unwrap();
        let (be, calls) = backend(&cfg, Box::new(|_| fail("no runtime call expected")));
        be.destroy_instance(&cfg, &inst).unwrap();
        assert!(calls.borrow().is_empty());
        assert!(!inst.dir.exists());
    }

    // ── Simulated runtime ─────────────────────────────────────

    struct SimBox {
        status: SandboxStatus,
        image: String,
        digest: String,
        cpus: u32,
        memory_bytes: u64,
        /// Inspects left before a started sandbox reports its effective
        /// configuration.
        settling: u32,
    }

    /// A stateful stand-in for `coop-sandbox` and the stock builder, for
    /// driving whole operations (setup, image verification) end to end.
    struct Sim {
        root: String,
        owner: String,
        sandboxes: std::collections::BTreeMap<String, SimBox>,
        images: Vec<(String, String)>,
        saved: Option<String>,
        builder_images: Vec<String>,
        /// Status a started sandbox settles into (`running`, or `stopped`
        /// for a guest that powers off during boot).
        boots_to: SandboxStatus,
        settle_inspects: u32,
        host_key: Option<&'static str>,
        missing: Vec<String>,
        uid: &'static str,
        console: &'static str,
        faults: Vec<Fault>,
    }

    /// Ways the simulated runtime or builder misbehaves.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        BuilderDown,
        BuildFails,
        CreateFails,
        ServicesInactive,
        SetIgnoresMemory,
        LogsFail,
    }

    const SIM_DIGEST: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    impl Sim {
        fn new(cfg: &CoopConfig, owner: &Owner) -> Rc<RefCell<Self>> {
            Rc::new(RefCell::new(Self {
                root: canonical_path(&cfg.state_root().join(RUNTIME_DIR))
                    .display()
                    .to_string(),
                owner: owner.id.as_str().to_string(),
                sandboxes: std::collections::BTreeMap::new(),
                images: Vec::new(),
                saved: None,
                builder_images: Vec::new(),
                boots_to: SandboxStatus::Running,
                settle_inspects: 0,
                host_key: Some(KEY),
                missing: Vec::new(),
                uid: "1000\n",
                console: "[    0.000000] Booting Linux\n",
                faults: Vec::new(),
            }))
        }

        fn has(&self, fault: Fault) -> bool {
            self.faults.contains(&fault)
        }

        fn inspect(&mut self, id: &str) -> Output {
            let Some(b) = self.sandboxes.get_mut(id) else {
                return fail("no such sandbox");
            };
            let settling = b.status == SandboxStatus::Running && b.settling > 0;
            b.settling = b.settling.saturating_sub(1);
            let fixture_name = if b.status == SandboxStatus::Running {
                "inspect-running.json"
            } else {
                "inspect-stopped.json"
            };
            let mut v: serde_json::Value = serde_json::from_str(&fixture(fixture_name)).unwrap();
            v["status"] = b.status.label().into();
            for key in ["record", "effective"] {
                let Some(o) = v.get_mut(key).filter(|o| o.is_object()) else {
                    continue;
                };
                o["id"] = id.into();
                o["imageReference"] = b.image.clone().into();
                o["imageDigest"] = b.digest.clone().into();
                o["cpus"] = b.cpus.into();
                o["memoryBytes"] = b.memory_bytes.into();
            }
            v["record"]["owner"] = self.owner.clone().into();
            if let Some(rootfs) = v.pointer_mut("/effective/rootfs/source") {
                *rootfs = format!("{}/sandboxes/{id}/rootfs.ext4", self.root).into();
            }
            if settling {
                v["effective"] = serde_json::Value::Null;
            }
            ok(&v.to_string())
        }

        fn guest(&self, argv: &[String]) -> Output {
            match argv.first().map(String::as_str) {
                Some("/bin/cat") => self.host_key.map_or_else(|| fail("No such file"), ok),
                Some("/bin/sh") => ok(&self
                    .missing
                    .iter()
                    .filter(|m| argv.contains(m))
                    .fold(String::new(), |out, m| out + m + "\n")),
                Some("/usr/bin/id") => ok(self.uid),
                Some("/usr/bin/systemctl") if argv.iter().any(|a| a == "--quiet") => {
                    if self.has(Fault::ServicesInactive) {
                        fail("")
                    } else {
                        ok("")
                    }
                }
                Some("/usr/bin/systemctl") => ok("active\nactivating\n"),
                _ => fail("unexpected guest command"),
            }
        }

        fn respond(&mut self, args: &[String]) -> Output {
            let flag = |name: &str| {
                args.windows(2)
                    .find(|w| w[0] == name)
                    .map(|w| w[1].clone())
                    .unwrap_or_default()
            };
            if !args.iter().any(|a| a == "--root") {
                // The stock builder.
                if starts(args, &["system", "status"]) {
                    return if self.has(Fault::BuilderDown) {
                        fail("not running")
                    } else {
                        ok("")
                    };
                }
                if starts(args, &["build"]) {
                    if self.has(Fault::BuildFails) {
                        return fail("build failed");
                    }
                    self.builder_images.push(flag("-t"));
                    return ok("");
                }
                if starts(args, &["image", "save"]) {
                    self.saved = args.last().cloned();
                    return ok("");
                }
                if starts(args, &["image", "delete"]) {
                    self.builder_images.retain(|i| Some(i) != args.last());
                    return ok("");
                }
                return fail("unexpected builder command");
            }
            let id = args.get(3).cloned().unwrap_or_default();
            match (args[0].as_str(), args.get(1).map(String::as_str)) {
                ("init" | "reconcile", _) => ok("{}"),
                ("image", Some("import")) => {
                    let reference = self.saved.clone().unwrap_or_default();
                    self.images.push((reference.clone(), SIM_DIGEST.into()));
                    ok(&format!(r#"[{{"reference":"{reference}","digest":"{SIM_DIGEST}"}}]"#))
                }
                ("image", Some("list")) => ok(&serde_json::to_string(
                    &self
                        .images
                        .iter()
                        .map(|(r, d)| serde_json::json!({"reference": r, "digest": d}))
                        .collect::<Vec<_>>(),
                )
                .unwrap()),
                ("image", Some("delete")) => {
                    self.images.retain(|(r, _)| Some(r) != args.last());
                    ok("")
                }
                ("disk", Some("list")) => ok("[]"),
                ("list", _) => ok(&serde_json::to_string(
                    &self
                        .sandboxes
                        .iter()
                        .map(|(id, b)| {
                            serde_json::json!({"id": id, "status": b.status.label(), "owner": self.owner})
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap()),
                _ => self.respond_sandbox(args, &id, &flag),
            }
        }

        fn respond_sandbox(
            &mut self,
            args: &[String],
            id: &str,
            flag: &dyn Fn(&str) -> String,
        ) -> Output {
            match args[0].as_str() {
                "create" => {
                    if self.has(Fault::CreateFails) {
                        return fail("create failed");
                    }
                    let image = flag("--image");
                    let Some((_, digest)) = self.images.iter().find(|(r, _)| *r == image) else {
                        return fail("no such image");
                    };
                    let memory_mib: u64 = flag("--memory-mib").parse().unwrap();
                    self.sandboxes.insert(
                        id.to_string(),
                        SimBox {
                            status: SandboxStatus::Stopped,
                            image,
                            digest: digest.clone(),
                            cpus: flag("--cpus").parse().unwrap(),
                            memory_bytes: memory_mib * 1024 * 1024,
                            settling: 0,
                        },
                    );
                    ok("{}")
                }
                "inspect" => self.inspect(id),
                "start" => {
                    let (to, settle) = (self.boots_to, self.settle_inspects);
                    let Some(b) = self.sandboxes.get_mut(id) else {
                        return fail("no such sandbox");
                    };
                    b.status = to;
                    b.settling = settle;
                    ok("{}")
                }
                "stop" => {
                    if let Some(b) = self.sandboxes.get_mut(id) {
                        b.status = SandboxStatus::Stopped;
                    }
                    ok("")
                }
                "delete" => {
                    self.sandboxes.remove(id);
                    ok("")
                }
                "logs" if self.has(Fault::LogsFail) => fail("no console log"),
                "logs" => ok(self.console),
                "set" => {
                    let ignores_memory = self.has(Fault::SetIgnoresMemory);
                    let Some(b) = self.sandboxes.get_mut(id) else {
                        return fail("no such sandbox");
                    };
                    if let Ok(cpus) = flag("--cpus").parse() {
                        b.cpus = cpus;
                    }
                    if let Ok(mib) = flag("--memory-mib").parse::<u64>()
                        && !ignores_memory
                    {
                        b.memory_bytes = mib * 1024 * 1024;
                    }
                    ok("{}")
                }
                "exec" => {
                    // exec --root R --timeout S ID -- ARGV
                    let dashes = args.iter().position(|a| a == "--").unwrap();
                    self.guest(&args[dashes + 1..])
                }
                _ => fail("unexpected runtime command"),
            }
        }
    }

    fn sim_backend(cfg: &CoopConfig, sim: &Rc<RefCell<Sim>>) -> (AppleContainerBackend, Calls) {
        let sim = Rc::clone(sim);
        backend(
            cfg,
            Box::new(move |args| {
                version(args, true).unwrap_or_else(|| sim.borrow_mut().respond(args))
            }),
        )
    }

    /// A test config whose kernel path exists, with a fresh owner.
    fn setup_env(dir: &Path) -> (CoopConfig, Owner, SetupOptions) {
        let mut cfg = test_cfg(&dir.join("data"));
        let kernel = dir.join("vmlinux");
        std::fs::write(&kernel, "").unwrap();
        cfg.apple_container.kernel = Some(ConfigPath::new(&kernel));
        let owner = Owner::load_or_init(&cfg).unwrap();
        let opts = SetupOptions {
            skip_confirm: true,
            rebuild: false,
            profiles: Vec::new(),
            oci_features: Vec::new(),
            extra_packages: Vec::new(),
            post_install: None,
            image: ImageName::new("default").unwrap(),
            guest_user: crate::guest::GuestUser::default(),
            builder_timeout: None,
        };
        (cfg, owner, opts)
    }

    /// Setup builds with the stock builder, moves the image into the runtime,
    /// proves it boots and meets the guest contract in a disposable sandbox,
    /// then publishes the manifest. A second setup with the same inputs
    /// reuses it; `--rebuild` replaces it and releases the old tag.
    #[test]
    fn setup_verifies_in_a_disposable_sandbox_then_publishes() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, owner, mut opts) = setup_env(tmp.path());
        let sim = Sim::new(&cfg, &owner);
        sim.borrow_mut().settle_inspects = 2;
        let (be, calls) = sim_backend(&cfg, &sim);
        assert!(!be.image_is_built(&cfg, &opts.image));

        be.setup(&cfg, &opts).unwrap();
        let manifest = ImageManifest::load(&cfg, &opts.image).unwrap();
        assert!(
            manifest
                .image_ref
                .starts_with(&format!("local/coop-{}:", owner.id.short()))
        );
        assert_eq!(manifest.digest, SIM_DIGEST);
        assert!(be.image_is_built(&cfg, &opts.image));
        assert!(crate::setup::TemplateConfig::load_for(&cfg, &opts.image).is_ok());
        {
            let s = sim.borrow();
            assert!(s.sandboxes.is_empty(), "verification sandbox left behind");
            assert!(s.builder_images.is_empty(), "builder copy left behind");
            assert_eq!(s.images.len(), 1);
        }
        assert_eq!(
            mutations(&calls),
            [
                "init", "build", "image", "image", "image", "create", "start", "exec", "exec",
                "exec", "exec", "stop", "delete"
            ]
        );

        calls.borrow_mut().clear();
        be.setup(&cfg, &opts).unwrap();
        assert_eq!(mutations(&calls), ["init"], "an up-to-date image is reused");

        opts.rebuild = true;
        be.setup(&cfg, &opts).unwrap();
        let rebuilt = ImageManifest::load(&cfg, &opts.image).unwrap();
        assert_ne!(rebuilt.image_ref, manifest.image_ref);
        let s = sim.borrow();
        assert_eq!(s.images.len(), 1, "superseded tag released");
        assert_eq!(s.images[0].0, rebuilt.image_ref);
    }

    /// Every failed check fails setup, removes the verification sandbox and
    /// the candidate image, and publishes nothing.
    #[test]
    fn setup_rejects_an_image_that_fails_verification() {
        type Break = fn(&mut Sim);
        let cases: [(&str, Break); 7] = [
            ("service", |s| s.faults.push(Fault::BuilderDown)),
            ("Image build failed", |s| s.faults.push(Fault::BuildFails)),
            ("stopped during boot", |s| {
                s.boots_to = SandboxStatus::Stopped;
            }),
            ("SSH host key", |s| s.host_key = None),
            ("/usr/bin/docker", |s| {
                s.missing = vec!["/usr/bin/docker".into()];
            }),
            ("uid 1000", |s| s.uid = "1001\n"),
            ("services ssh, docker not active", |s| {
                s.faults.push(Fault::ServicesInactive);
            }),
        ];
        for (why, breaks) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let (cfg, owner, opts) = setup_env(tmp.path());
            let sim = Sim::new(&cfg, &owner);
            breaks(&mut sim.borrow_mut());
            let (be, _) = sim_backend(&cfg, &sim);
            let err = be.setup(&cfg, &opts).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{why}: {err:#}");
            assert!(
                ImageManifest::try_load(&cfg, &opts.image)
                    .unwrap()
                    .is_none(),
                "{why}"
            );
            assert!(!be.image_is_built(&cfg, &opts.image), "{why}");
            let s = sim.borrow();
            assert!(
                s.sandboxes.is_empty() && s.images.is_empty(),
                "{why}: left state behind"
            );
        }
    }

    /// A sandbox that never reports a running configuration fails at the
    /// boot deadline, not before; the console log explains what it can.
    #[test]
    fn readiness_waits_for_the_deadline_then_reports_the_console() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, owner, opts) = setup_env(tmp.path());
        let sim = Sim::new(&cfg, &owner);
        sim.borrow_mut().settle_inspects = u32::MAX;
        let (be, _) = sim_backend(&cfg, &sim);
        let started = Instant::now();
        let err = be.setup(&cfg, &opts).unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(1), "gave up early");
        let text = format!("{err:#}");
        assert!(
            text.contains("did not report a running configuration"),
            "{text}"
        );
        assert!(text.contains("Booting Linux"), "{text}");
    }

    /// A sandbox matching `write_sidecar`, in `status`.
    fn sim_sandbox(sim: &Rc<RefCell<Sim>>, owner: &Owner, status: SandboxStatus) {
        sim.borrow_mut().sandboxes.insert(
            sandbox_name(owner).to_string(),
            SimBox {
                status,
                image: "local/coop-exp:fx".into(),
                digest: SIM_DIGEST.into(),
                cpus: 2,
                memory_bytes: 2048 * 1024 * 1024,
                settling: 0,
            },
        );
    }

    fn running(inst: &Instance) -> RunningInstance {
        let target = SshTarget {
            host: crate::backend::Hostname::from(std::net::Ipv4Addr::new(10, 231, 2, 2)),
            port: std::num::NonZeroU16::new(22).unwrap(),
            user: crate::backend::SshUser::new("coop").unwrap(),
            key_path: PathBuf::from("/nonexistent/key"),
            host_keys: crate::backend::HostKeyPolicy::Unverified,
        };
        RunningInstance::new(inst.clone(), target)
    }

    /// `up` refuses to overwrite existing state, and a failed boot stops the
    /// sandbox it created and keeps the journal for `destroy`.
    #[test]
    fn create_refuses_existing_state_and_stops_a_failed_boot() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, owner, opts) = setup_env(tmp.path());
        let sim = Sim::new(&cfg, &owner);
        let (be, calls) = sim_backend(&cfg, &sim);
        be.setup(&cfg, &opts).unwrap();
        let inst = test_inst(&cfg);

        Journal::begin(&inst, &owner, JournalOp::Create, sandbox_name(&owner)).unwrap();
        calls.borrow_mut().clear();
        let err = be.create_and_start(&cfg, &inst, None, &[]).unwrap_err();
        assert!(
            matches!(kind(&err), AppleError::OperationUncertain(_)),
            "{err:#}"
        );
        assert!(mutations(&calls).is_empty());
        Journal::complete(&inst).unwrap();

        sim.borrow_mut().faults = vec![Fault::CreateFails];
        let err = be.create_and_start(&cfg, &inst, None, &[]).unwrap_err();
        assert!(format!("{err:#}").contains("create failed"), "{err:#}");
        Journal::complete(&inst).unwrap();

        {
            let mut s = sim.borrow_mut();
            s.faults.clear();
            s.settle_inspects = u32::MAX;
        }
        calls.borrow_mut().clear();
        let started = Instant::now();
        let err = be.create_and_start(&cfg, &inst, None, &[]).unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(1), "gave up early");
        assert!(matches!(kind(&err), AppleError::BootTimeout(_)), "{err:#}");
        assert_eq!(mutations(&calls), ["create", "start", "stop"]);
        assert!(
            sim.borrow()
                .sandboxes
                .values()
                .all(|b| b.status == SandboxStatus::Stopped)
        );
        assert!(MachineSidecar::try_load(&inst).unwrap().is_none());
        assert_eq!(
            Journal::try_load(&inst).unwrap().unwrap().stage,
            Stage::MachineCreated
        );
    }

    #[test]
    fn stop_and_is_running_follow_the_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let sim = Sim::new(&cfg, &owner);
        let (be, calls) = sim_backend(&cfg, &sim);
        assert!(!be.is_running(&inst), "no record");
        write_sidecar(&inst, &owner);
        sim_sandbox(&sim, &owner, SandboxStatus::Running);
        assert!(be.is_running(&inst));
        be.stop(&cfg, running(&inst)).unwrap();
        assert_eq!(mutations(&calls), ["stop"]);
        assert!(!be.is_running(&inst));
        assert!(!be.images_in_data_dir());
    }

    #[test]
    fn status_reports_the_runtime_record() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        let sidecar = write_sidecar(&inst, &owner);
        let rec =
            protocol::parse_inspect(&inspect_json(&cfg, &owner, "running"), &sidecar.machine_id)
                .unwrap();
        let text = describe_sandbox(&inst, &sidecar, &rec, "coop-sandbox 0.1.0");
        for want in [
            "Instance 't' (running)",
            "Runtime: coop-sandbox 0.1.0",
            "Network: vmnet-shared:10.231.2.0/24 (dedicated)",
            "vCPUs: 2",
            "Memory: 2048 MiB",
            // 8724152320 and 752058368 bytes.
            "Disk: 8.1 GiB (0.7 GiB allocated)",
            "Address: 10.231.2.2 (host key SHA256:x)",
        ] {
            assert!(text.contains(want), "{want:?} not in:\n{text}");
        }
        let stopped =
            protocol::parse_inspect(&inspect_json(&cfg, &owner, "stopped"), &sidecar.machine_id)
                .unwrap();
        let text = describe_sandbox(&inst, &sidecar, &stopped, "r");
        assert!(text.contains("Network: unavailable"), "{text}");
        assert!(text.contains("Address: unavailable"), "{text}");
    }

    #[test]
    fn logs_stream_or_fail_with_the_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let sim = Sim::new(&cfg, &owner);
        sim_sandbox(&sim, &owner, SandboxStatus::Running);
        let (be, calls) = sim_backend(&cfg, &sim);
        for mode in [LogMode::Snapshot, LogMode::Follow] {
            be.stream_logs(&cfg, &running(&inst), mode).unwrap();
        }
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|c| starts(c, &["logs"]))
                .count(),
            2
        );
        sim.borrow_mut().faults = vec![Fault::LogsFail];
        for mode in [LogMode::Snapshot, LogMode::Follow] {
            assert!(be.stream_logs(&cfg, &running(&inst), mode).is_err());
        }
    }

    /// Memory that does not change is caught as well as CPUs; a restart that
    /// fails with new resources restores the previous ones.
    #[test]
    fn resource_changes_are_verified_and_rolled_back() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let sim = Sim::new(&cfg, &owner);
        sim_sandbox(&sim, &owner, SandboxStatus::Stopped);
        let (be, _) = sim_backend(&cfg, &sim);
        let stopped = StoppedInstance::new(inst.clone());
        let mem = Some(VmMemory::new(crate::config::MiB::new(4096).unwrap()).unwrap());

        sim.borrow_mut().faults = vec![Fault::SetIgnoresMemory];
        let err = be
            .set_machine_resources(&cfg, &stopped, mem, NonZeroU8::new(4), false)
            .unwrap_err();
        assert!(
            matches!(kind(&err), AppleError::OperationUncertain(_)),
            "{err:#}"
        );
        Journal::complete(&inst).unwrap();
        sim.borrow_mut().faults.clear();

        be.set_machine_resources(&cfg, &stopped, mem, NonZeroU8::new(4), false)
            .unwrap();
        let sidecar = MachineSidecar::load(&inst).unwrap();
        assert_eq!(
            (sidecar.requested_cpus, sidecar.requested_memory_bytes),
            (4, 4096 * 1024 * 1024)
        );

        sim.borrow_mut().boots_to = SandboxStatus::Stopped;
        let mem = Some(VmMemory::new(crate::config::MiB::new(6144).unwrap()).unwrap());
        let err = be
            .set_machine_resources(&cfg, &stopped, mem, NonZeroU8::new(6), true)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("previous CPU/memory restored"),
            "{err:#}"
        );
        let sidecar = MachineSidecar::load(&inst).unwrap();
        let prior = (4, 4096 * 1024 * 1024);
        assert_eq!(
            (sidecar.requested_cpus, sidecar.requested_memory_bytes),
            prior
        );
        let s = sim.borrow();
        let b = s.sandboxes.values().next().unwrap();
        assert_eq!((b.cpus, b.memory_bytes), prior);
    }

    #[test]
    fn destroying_images_releases_owned_content() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, owner, opts) = setup_env(tmp.path());
        let sim = Sim::new(&cfg, &owner);
        let (be, _) = sim_backend(&cfg, &sim);
        let missing = ImageName::new("missing").unwrap();
        assert!(be.destroy_image(&cfg, &missing).is_err());

        be.setup(&cfg, &opts).unwrap();
        be.destroy_image(&cfg, &opts.image).unwrap();
        assert!(!cfg.image_dir(&opts.image).exists());
        assert!(sim.borrow().images.is_empty());

        be.setup(&cfg, &opts).unwrap();
        be.destroy_shared(&cfg);
        assert!(!cfg.image_dir(&opts.image).exists());
        assert!(sim.borrow().images.is_empty());
    }

    /// Without console output (unreadable or blank), a boot failure says
    /// where to look instead.
    #[test]
    fn boot_failure_without_a_console_log_says_so() {
        type Blank = fn(&mut Sim);
        let cases: [Blank; 2] = [|s| s.faults.push(Fault::LogsFail), |s| s.console = "  \n"];
        for blank in cases {
            let tmp = tempfile::tempdir().unwrap();
            let (cfg, owner, opts) = setup_env(tmp.path());
            let sim = Sim::new(&cfg, &owner);
            sim.borrow_mut().boots_to = SandboxStatus::Stopped;
            blank(&mut sim.borrow_mut());
            let (be, _) = sim_backend(&cfg, &sim);
            let err = be.setup(&cfg, &opts).unwrap_err();
            assert!(
                format!("{err:#}").contains("Console log unavailable"),
                "{err:#}"
            );
        }
    }

    /// A restart that never reports a running configuration fails at the
    /// boot deadline, not before, and leaves the sandbox stopped.
    #[test]
    fn start_waits_for_the_boot_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = test_cfg(tmp.path());
        let owner = Owner::load_or_init(&cfg).unwrap();
        let inst = test_inst(&cfg);
        write_sidecar(&inst, &owner);
        let sim = Sim::new(&cfg, &owner);
        sim_sandbox(&sim, &owner, SandboxStatus::Stopped);
        sim.borrow_mut().settle_inspects = u32::MAX;
        let (be, calls) = sim_backend(&cfg, &sim);
        let started = Instant::now();
        let err = be.start_existing(&cfg, &inst).unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(1), "gave up early");
        assert!(matches!(kind(&err), AppleError::BootTimeout(_)), "{err:#}");
        assert_eq!(mutations(&calls), ["start", "stop"]);
    }

    /// Services get their own window after boot; setup waits it out.
    #[test]
    fn inactive_services_fail_only_after_their_window() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, owner, opts) = setup_env(tmp.path());
        let sim = Sim::new(&cfg, &owner);
        sim.borrow_mut().faults = vec![Fault::ServicesInactive];
        let (be, _) = sim_backend(&cfg, &sim);
        let started = Instant::now();
        let err = be.setup(&cfg, &opts).unwrap_err();
        assert!(started.elapsed() >= Duration::from_secs(1), "gave up early");
        let text = format!("{err:#}");
        assert!(text.contains("(active, activating)"), "{text}");
    }

    #[test]
    fn canonical_path_resolves_through_the_existing_ancestor() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().canonicalize().unwrap();
        assert_eq!(canonical_path(&tmp.path().join("a/b")), real.join("a/b"));
    }
}
