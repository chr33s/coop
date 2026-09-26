//! Typed, bounded adapter over the `coop-sandbox` runtime CLI (and the stock
//! `container` CLI, used only to build images).
//!
//! Every runtime call goes through [`Exec`], so it gets an argument vector
//! (never a host shell), an explicit deadline, bounded captured output, and a
//! sanitized environment. [`RealExec`] runs the real binary; tests substitute a
//! scripted executor.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::AppleError;

/// Largest single-machine JSON response accepted from the runtime.
pub(crate) const MAX_JSON_OUTPUT: usize = 1024 * 1024;
/// Largest host public-key response accepted during enrollment.
pub(crate) const MAX_PUBKEY_OUTPUT: usize = 16 * 1024;
/// Largest help/version text accepted during qualification.
pub(crate) const MAX_TEXT_OUTPUT: usize = 256 * 1024;

/// The only variables a runtime child inherits. `HOME`, `USER`, `LOGNAME`
/// and `TMPDIR` let the CLI find its per-user launchd service and state;
/// locale keeps its output parseable. Everything else — `SSH_AUTH_SOCK`,
/// provider and GitHub tokens, `DYLD_*`, `CONTAINER_*` overrides — is dropped.
const INHERITED_ENV: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "__CF_USER_TEXT_ENCODING",
];

/// Fixed executable search path for runtime children, so a project-local
/// directory on the caller's `PATH` can never shadow a helper.
const CHILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// One runtime invocation.
#[derive(Debug, Clone)]
pub(crate) struct Request {
    pub(crate) args: Vec<String>,
    pub(crate) timeout: Duration,
    pub(crate) max_output: usize,
    /// Whether Ctrl-C aborts the call. Only long operations that create or
    /// boot something are cancellable; stop, delete, and read-only probes are
    /// not, so cleanup after an interrupt still runs to completion (the
    /// shutdown flag is sticky for the rest of the process).
    pub(crate) cancellable: bool,
}

impl Request {
    pub(crate) fn new<I, S>(args: I, timeout: Duration, max_output: usize) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            args: args.into_iter().map(Into::into).collect(),
            timeout,
            max_output,
            cancellable: false,
        }
    }

    /// Let Ctrl-C abort this call; see [`Request::cancellable`].
    pub(crate) fn cancellable(mut self) -> Self {
        self.cancellable = true;
        self
    }

    /// The argument vector joined for diagnostics. Arguments are generated
    /// identifiers and fixed flags, never secrets.
    pub(crate) fn describe(&self) -> String {
        self.args.join(" ")
    }
}

/// A completed invocation.
#[derive(Debug, Clone, Default)]
pub(crate) struct Output {
    /// Exit code; `None` when the process was killed by a signal.
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl Output {
    pub(crate) fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub(crate) fn stdout_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.stdout).context("runtime output is not valid UTF-8")
    }

    /// Stderr, lossily decoded and trimmed, for error messages. Runtime error
    /// text is host-controlled, but it can echo guest-influenced names, so it
    /// is stripped of control characters before display.
    pub(crate) fn stderr_summary(&self) -> String {
        sanitize_for_display(&String::from_utf8_lossy(&self.stderr))
    }
}

/// Replace control characters (other than newline/tab) so text echoed from
/// the runtime or guest cannot drive the operator's terminal.
pub(crate) fn sanitize_for_display(text: &str) -> String {
    text.trim()
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// Runs runtime commands. Object-safe so the backend can hold `Box<dyn Exec>`
/// and tests can script responses.
pub(crate) trait Exec {
    /// Run `req`, returning its output whatever the exit status. `Err` means
    /// the result is unknown (spawn failure, deadline, oversized output,
    /// cancellation) — never that the operation failed.
    fn run(&self, req: &Request) -> Result<Output>;

    /// Run `req` with stdout and stderr appended to `log` instead of captured,
    /// for long, chatty operations (image builds).
    fn run_logged(&self, req: &Request, log: &Path) -> Result<Output>;

    /// Run `args` with no deadline (log streaming), passing each stdout line
    /// to `on_line` as it arrives; stderr lines are sanitized and forwarded
    /// to the caller's stderr. Returns when the child exits.
    fn run_streaming(
        &self,
        args: &[String],
        on_line: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Output>;
}

/// Executes a real runtime binary.
pub(crate) struct RealExec {
    binary: PathBuf,
}

impl RealExec {
    pub(crate) fn new(binary: PathBuf) -> Self {
        Self { binary }
    }

    /// The binary's file name, for diagnostics.
    fn program(&self) -> String {
        self.binary
            .file_name()
            .map_or_else(|| "runtime".into(), |n| n.to_string_lossy().into_owned())
    }

    fn command(&self, args: &[String]) -> Command {
        let mut cmd = crate::cmd::Cmd::new(&self.binary).args(args).build();
        apply_sanitized_env(&mut cmd, std::env::vars_os());
        cmd.stdin(Stdio::null());
        cmd
    }
}

/// Clear `cmd`'s environment and re-add only [`INHERITED_ENV`] from `vars`,
/// plus the fixed [`CHILD_PATH`].
pub(crate) fn apply_sanitized_env(
    cmd: &mut Command,
    vars: impl IntoIterator<Item = (OsString, OsString)>,
) {
    cmd.env_clear();
    for (key, value) in vars {
        if key.to_str().is_some_and(|k| INHERITED_ENV.contains(&k)) {
            cmd.env(key, value);
        }
    }
    cmd.env("PATH", CHILD_PATH);
}

impl Exec for RealExec {
    fn run(&self, req: &Request) -> Result<Output> {
        let mut cmd = self.command(&req.args);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        tracing::debug!("{} {}", self.program(), req.describe());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to run {}", self.binary.display()))?;
        let stdout = child.stdout.take().context("runtime stdout unavailable")?;
        let stderr = child.stderr.take().context("runtime stderr unavailable")?;
        let limit = req.max_output;
        let out_reader = std::thread::spawn(move || read_bounded(stdout, limit));
        let err_reader = std::thread::spawn(move || read_bounded(stderr, MAX_TEXT_OUTPUT));

        let status = wait_with_deadline(&mut child, req, &self.program())?;
        let (stdout, out_overflow) = join_reader(out_reader)?;
        let (stderr, _) = join_reader(err_reader)?;
        if out_overflow {
            return Err(AppleError::OperationUncertain(format!(
                "`{} {}` produced more than {limit} bytes of output",
                self.program(),
                req.describe()
            ))
            .into());
        }
        Ok(Output {
            code: status.code(),
            stdout,
            stderr,
        })
    }

    fn run_logged(&self, req: &Request, log: &Path) -> Result<Output> {
        let file = File::options()
            .create(true)
            .append(true)
            .open(log)
            .with_context(|| format!("Failed to open {}", log.display()))?;
        let err_file = file.try_clone().context("Failed to clone build log")?;
        let mut cmd = self.command(&req.args);
        cmd.stdout(Stdio::from(file)).stderr(Stdio::from(err_file));
        tracing::debug!(
            "{} {} (logged to {})",
            self.program(),
            req.describe(),
            log.display()
        );
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to run {}", self.binary.display()))?;
        let status = wait_with_deadline(&mut child, req, &self.program())?;
        Ok(Output {
            code: status.code(),
            ..Output::default()
        })
    }

    fn run_streaming(
        &self,
        args: &[String],
        on_line: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Output> {
        use std::io::{BufRead as _, Write as _};
        let mut cmd = self.command(args);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to run {}", self.binary.display()))?;
        let stdout = child.stdout.take().context("runtime stdout unavailable")?;
        let stderr = child.stderr.take().context("runtime stderr unavailable")?;
        let err_forwarder = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr)
                .split(b'\n')
                .map_while(Result::ok)
            {
                let _ = writeln!(
                    std::io::stderr(),
                    "{}",
                    sanitize_for_display(&String::from_utf8_lossy(&line))
                );
            }
        });
        let mut streamed = Ok(());
        for line in std::io::BufReader::new(stdout).split(b'\n') {
            match line
                .context("Failed to read runtime output")
                .and_then(|l| on_line(&l))
            {
                Ok(()) => {}
                Err(e) => {
                    let _ = child.kill();
                    streamed = Err(e);
                    break;
                }
            }
        }
        let status = child.wait().context("Failed to wait for runtime command")?;
        let _ = err_forwarder.join();
        streamed?;
        Ok(Output {
            code: status.code(),
            ..Output::default()
        })
    }
}

/// Poll `child` until it exits, the deadline passes, or the user cancels.
/// Killing the CLI does not cancel work the runtime service already accepted,
/// so both of the latter are reported as an uncertain outcome.
fn wait_with_deadline(
    child: &mut std::process::Child,
    req: &Request,
    program: &str,
) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + req.timeout;
    loop {
        if let Some(status) = child.try_wait().context("Failed to poll runtime command")? {
            return Ok(status);
        }
        let cancelled = req.cancellable && crate::signal::check_shutdown().is_err();
        if cancelled || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let why = if cancelled {
                "was cancelled".to_string()
            } else {
                format!("did not finish within {:?}", req.timeout)
            };
            return Err(AppleError::OperationUncertain(format!(
                "`{program} {}` {why}; its effect is unknown and will be reconciled on retry",
                req.describe()
            ))
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Read up to `limit` bytes, then keep draining (so the child never blocks on
/// a full pipe) while recording that the limit was exceeded.
fn read_bounded(mut reader: impl std::io::Read, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut overflow = false;
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok((kept, overflow));
        }
        let room = limit.saturating_sub(kept.len());
        if n > room {
            overflow = true;
        }
        kept.extend_from_slice(&buf[..n.min(room)]);
    }
}

type ReaderHandle = std::thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>;

fn join_reader(handle: ReaderHandle) -> Result<(Vec<u8>, bool)> {
    match handle.join() {
        Ok(result) => result.context("Failed to read runtime output"),
        Err(_) => bail!("runtime output reader panicked"),
    }
}

/// Read at most the last `max` bytes of a log file, for failure diagnostics.
pub(crate) fn log_tail(path: &Path, max: usize) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let mut content = Vec::new();
    if file.read_to_end(&mut content).is_err() {
        return String::new();
    }
    let start = content.len().saturating_sub(max);
    sanitize_for_display(&String::from_utf8_lossy(&content[start..]))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn sanitized_env_drops_agent_and_tokens() {
        let mut cmd = Command::new("/usr/bin/true");
        let vars = [
            ("HOME", "/Users/me"),
            ("SSH_AUTH_SOCK", "/tmp/agent.sock"),
            ("ANTHROPIC_API_KEY", "sk-canary"),
            ("GITHUB_TOKEN", "ghp_canary"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
            ("CONTAINER_DEBUG", "1"),
            ("PATH", "/project/bin:/usr/bin"),
            ("LANG", "en_US.UTF-8"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        apply_sanitized_env(&mut cmd, vars);
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let get = |name: &str| {
            envs.iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| v.clone())
        };
        assert_eq!(get("HOME").as_deref(), Some("/Users/me"));
        assert_eq!(get("LANG").as_deref(), Some("en_US.UTF-8"));
        assert_eq!(get("PATH").as_deref(), Some(CHILD_PATH));
        for dropped in [
            "SSH_AUTH_SOCK",
            "ANTHROPIC_API_KEY",
            "GITHUB_TOKEN",
            "DYLD_INSERT_LIBRARIES",
            "CONTAINER_DEBUG",
        ] {
            assert_eq!(get(dropped), None, "{dropped} leaked into runtime env");
        }
    }

    #[test]
    fn requests_are_not_cancellable_unless_asked() {
        let req = Request::new(["machine", "stop", "m"], Duration::from_secs(1), 1);
        assert!(!req.cancellable, "cleanup must survive a Ctrl-C");
        assert!(req.cancellable().cancellable);
    }

    #[test]
    fn read_bounded_flags_overflow_but_drains() {
        let data = [b'x'; 100];
        let (kept, overflow) = read_bounded(&data[..], 10).unwrap();
        assert_eq!(kept.len(), 10);
        assert!(overflow);
        let (kept, overflow) = read_bounded(&data[..], 100).unwrap();
        assert_eq!(kept.len(), 100);
        assert!(!overflow);
    }

    /// Each bound admits the largest legitimate response of its kind and
    /// stays small enough to hold in memory.
    #[test]
    fn output_bounds_fit_real_responses() {
        let bounds = [
            (MAX_JSON_OUTPUT, 512 * 1024, 4 * 1024 * 1024),
            (MAX_PUBKEY_OUTPUT, 8 * 1024, 64 * 1024),
            (MAX_TEXT_OUTPUT, 128 * 1024, 1024 * 1024),
        ];
        for (bound, fits, ceiling) in bounds {
            let data = vec![b'x'; fits];
            assert!(
                !read_bounded(&data[..], bound).unwrap().1,
                "{bound} < {fits}"
            );
            assert!(bound <= ceiling, "{bound} > {ceiling}");
        }
    }

    #[test]
    fn output_reports_success_and_sanitized_stderr() {
        let out = Output {
            code: Some(0),
            stdout: Vec::new(),
            stderr: b"  bad\x1b[2J name \n".to_vec(),
        };
        assert!(out.success());
        assert_eq!(out.stderr_summary(), "bad?[2J name");
        for code in [Some(1), None] {
            assert!(
                !Output {
                    code,
                    ..out.clone()
                }
                .success()
            );
        }
        let req = Request::new(["image", "delete", "x"], Duration::from_secs(1), 1);
        assert_eq!(req.describe(), "image delete x");
    }

    #[test]
    fn sanitize_strips_terminal_controls() {
        assert_eq!(sanitize_for_display("ok\x1b[2Jdone\n"), "ok?[2Jdone");
    }

    #[test]
    fn real_exec_streams_stdout_lines() {
        let exec = RealExec::new(PathBuf::from("/bin/sh"));
        let mut lines = Vec::new();
        let out = exec
            .run_streaming(&["-c".into(), "printf 'a\\nb\\n'".into()], &mut |l| {
                lines.push(String::from_utf8_lossy(l).into_owned());
                Ok(())
            })
            .unwrap();
        assert!(out.success());
        assert_eq!(lines, ["a", "b"]);
    }

    /// Logged runs append both streams to the log and report the exit code.
    #[test]
    fn real_exec_logs_both_streams_and_the_exit_code() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("build.log");
        std::fs::write(&log, "earlier\n").unwrap();
        let exec = RealExec::new(PathBuf::from("/bin/sh"));
        let req = Request::new(
            ["-c", "echo out; echo err >&2; exit 3"],
            Duration::from_secs(10),
            0,
        );
        let out = exec.run_logged(&req, &log).unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "earlier\nout\nerr\n"
        );
    }

    #[test]
    fn real_exec_times_out_as_uncertain() {
        let exec = RealExec::new(PathBuf::from("/bin/sleep"));
        let req = Request::new(["5"], Duration::from_millis(100), 1024);
        let err = exec.run(&req).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::OperationUncertain(_))
        ));
    }

    #[test]
    fn real_exec_rejects_oversized_output() {
        let exec = RealExec::new(PathBuf::from("/bin/echo"));
        let req = Request::new(["0123456789"], Duration::from_secs(5), 4);
        assert!(exec.run(&req).is_err());
        let req = Request::new(["hi"], Duration::from_secs(5), 64);
        let out = exec.run(&req).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout_str().unwrap(), "hi\n");
    }
}
