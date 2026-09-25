//! OCI machine image: minimal build context, manifest identity, and the
//! digest-backed `apple-image.json` template record.
//!
//! The context is generated in a private temporary directory and holds only
//! the rendered Dockerfile and reviewed provisioning scripts, including the
//! coop VM-access **public** key. It is never the repository, the working
//! directory, or the macOS home, and it never carries a secret.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::AppleError;
use super::state::{BACKEND_TAG, Owner, SCHEMA_VERSION};
use crate::config::{CoopConfig, ImageName};
use crate::devcontainer_oci::ResolvedFeature;
use crate::guest::{GuestUser, ProfileDef};

/// Base image for every coop machine image.
pub(crate) const BASE_IMAGE: &str = "docker.io/library/ubuntu:24.04";
/// The only guest platform version 1 supports.
pub(crate) const PLATFORM: &str = "linux/arm64";
/// Where the build context is copied inside the image during the build. Not
/// under `/tmp`, which the shared provisioning script wipes.
const CONTEXT_DIR: &str = "/opt/coop-build";

const MANIFEST_FILE: &str = "apple-image.json";

/// `images/<name>/apple-image.json` — published only after the image passed
/// verification in a disposable machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ImageManifest {
    pub(crate) schema_version: u32,
    pub(crate) backend: String,
    /// Owned local tag, e.g. `local/coop-0a1b2c3d:0011223344556677`.
    pub(crate) image_ref: String,
    /// Content digest the tag resolved to after the build.
    pub(crate) digest: String,
    /// Hash of every build input; see [`manifest_id`].
    pub(crate) manifest_id: String,
    pub(crate) base_image: String,
    pub(crate) platform: String,
    pub(crate) guest_user: GuestUser,
    pub(crate) pubkey_fingerprint: String,
    pub(crate) created: String,
}

impl ImageManifest {
    fn path(cfg: &CoopConfig, image: &ImageName) -> std::path::PathBuf {
        cfg.image_dir(image).join(MANIFEST_FILE)
    }

    pub(crate) fn try_load(cfg: &CoopConfig, image: &ImageName) -> Result<Option<Self>> {
        let path = Self::path(cfg, image);
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("Failed to read {}", path.display())),
        };
        let manifest: Self = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        if manifest.backend != BACKEND_TAG || manifest.schema_version != SCHEMA_VERSION {
            bail!(AppleError::IdentityConflict(format!(
                "{} is not a {BACKEND_TAG} v{SCHEMA_VERSION} image manifest",
                path.display()
            )));
        }
        Ok(Some(manifest))
    }

    /// [`Self::try_load`], treating an unreadable or foreign manifest as
    /// absent (with a warning). For paths that replace or remove it.
    pub(crate) fn load_lenient(cfg: &CoopConfig, image: &ImageName) -> Option<Self> {
        Self::try_load(cfg, image).unwrap_or_else(|e| {
            tracing::warn!("Ignoring unreadable image manifest for '{image}': {e:#}");
            None
        })
    }

    pub(crate) fn load(cfg: &CoopConfig, image: &ImageName) -> Result<Self> {
        Self::try_load(cfg, image)?.ok_or_else(|| {
            anyhow::anyhow!("No image '{image}' found.\nRun `coop setup --image {image}` first.")
        })
    }

    pub(crate) fn save(&self, cfg: &CoopConfig, image: &ImageName) -> Result<()> {
        super::state::ensure_private_dir(&cfg.image_dir(image))?;
        let json = serde_json::to_string_pretty(self).context("Failed to serialize manifest")?;
        crate::fs_util::atomic_write_with_mode(&Self::path(cfg, image), &format!("{json}\n"), 0o600)
    }
}

/// Everything that goes into the build context, rendered in memory.
pub(crate) struct BuildContext {
    files: Vec<(&'static str, String, u32)>,
}

/// Inputs that determine an image's content.
pub(crate) struct BuildInputs<'a> {
    pub(crate) pubkey: &'a str,
    pub(crate) profiles: &'a [ProfileDef],
    pub(crate) oci_features: &'a [ResolvedFeature],
    pub(crate) guest_user: &'a GuestUser,
}

impl BuildContext {
    pub(crate) fn render(inputs: &BuildInputs<'_>) -> Self {
        let provision = crate::lima::compose_provision_script(
            inputs.pubkey,
            inputs.profiles,
            inputs.oci_features,
            inputs.guest_user,
        );
        Self {
            files: vec![
                ("Dockerfile", dockerfile(), 0o644),
                ("provision.sh", provision, 0o644),
                ("machine-setup.sh", machine_setup_script(), 0o644),
                (
                    "create-user.sh",
                    create_user_script(inputs.guest_user),
                    0o755,
                ),
                ("coop-ssh-hostkeys.service", HOSTKEY_UNIT.to_string(), 0o644),
                ("10-coop.conf", SSHD_DROPIN.to_string(), 0o644),
            ],
        }
    }

    /// Stable hash of the context plus the identity inputs that are not in
    /// file contents.
    pub(crate) fn manifest_id(&self, guest_user: &GuestUser, pubkey_fingerprint: &str) -> String {
        let mut h = sha2::Sha256::new();
        for part in [
            format!("schema={SCHEMA_VERSION}"),
            format!("base={BASE_IMAGE}"),
            format!("platform={PLATFORM}"),
            format!("user={guest_user}"),
            format!("pubkey={pubkey_fingerprint}"),
        ] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        for (name, content, mode) in &self.files {
            h.update(name.as_bytes());
            h.update([0]);
            h.update(mode.to_be_bytes());
            h.update(content.as_bytes());
            h.update([0]);
        }
        hex::encode(h.finalize())
    }

    /// Write the context into a fresh private directory.
    pub(crate) fn materialize(&self) -> Result<tempfile::TempDir> {
        let dir = tempfile::Builder::new()
            .prefix("coop-apple-build-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .context("Failed to create build context directory")?;
        for (name, content, mode) in &self.files {
            write_mode(&dir.path().join(name), content, *mode)?;
        }
        Ok(dir)
    }
}

fn write_mode(path: &Path, content: &str, mode: u32) -> Result<()> {
    fs::write(path, content).with_context(|| format!("Failed to write {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("Failed to chmod {}", path.display()))
}

/// Owned tag for one build: repository scoped to this installation, tag from
/// the content hash plus a per-build nonce. Every build gets a fresh tag, so
/// a rebuild (even of identical inputs) never retags the image a published
/// manifest or an existing instance points at.
pub(crate) fn image_ref(owner: &Owner, manifest_id: &str, build_id: &str) -> String {
    format!(
        "local/coop-{}:{}-{build_id}",
        owner.id.short(),
        &manifest_id[..16.min(manifest_id.len())]
    )
}

/// Extract the content digest from `container image inspect <ref>` output.
pub(crate) fn parse_image_digest(json: &str) -> Result<String> {
    let raw: Vec<serde_json::Value> = serde_json::from_str(json)
        .map_err(|e| AppleError::RuntimeUnqualified(format!("image inspect output: {e}")))?;
    let [only] = <[serde_json::Value; 1]>::try_from(raw).map_err(|v| {
        AppleError::RuntimeUnqualified(format!(
            "image inspect returned {} records, expected 1",
            v.len()
        ))
    })?;
    let digest = only
        .pointer("/descriptor/digest")
        .or_else(|| only.get("digest"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let valid = digest
        .strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if !valid {
        bail!(AppleError::RuntimeUnqualified(format!(
            "image inspect reported no valid digest ({digest:?})"
        )));
    }
    Ok(digest.to_string())
}

fn dockerfile() -> String {
    format!(
        r"# Generated by coop — Apple Container machine image.
FROM {BASE_IMAGE}
ENV container=container
COPY . {CONTEXT_DIR}/
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update -qq; \
    apt-get install -y -qq --no-install-recommends \
        ca-certificates curl gnupg systemd systemd-sysv dbus openssh-server sudo \
        iproute2 iputils-ping; \
    bash {CONTEXT_DIR}/provision.sh; \
    bash {CONTEXT_DIR}/machine-setup.sh; \
    rm -rf {CONTEXT_DIR}
"
    )
}

/// Adaptations from Apple's machine guide plus per-instance identity: the
/// reusable image carries no SSH host keys and an empty machine-id, so each
/// machine generates its own on first boot and keeps them across restarts.
fn machine_setup_script() -> String {
    format!(
        r"#!/bin/bash
set -euo pipefail

systemctl set-default multi-user.target
systemctl mask \
    dev-hugepages.mount \
    sys-fs-fuse-connections.mount \
    systemd-update-utmp.service \
    systemd-tmpfiles-setup.service \
    console-getty.service
systemctl disable networkd-dispatcher.service 2>/dev/null || true

install -m 0644 {CONTEXT_DIR}/coop-ssh-hostkeys.service /etc/systemd/system/coop-ssh-hostkeys.service
install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 {CONTEXT_DIR}/10-coop.conf /etc/ssh/sshd_config.d/10-coop.conf
systemctl disable ssh.socket 2>/dev/null || true
systemctl enable coop-ssh-hostkeys.service ssh.service docker.service

rm -f /etc/ssh/ssh_host_*
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id

install -d -m 0755 -o root -g root /etc/machine
install -m 0755 -o root -g root {CONTEXT_DIR}/create-user.sh /etc/machine/create-user.sh
"
    )
}

/// Runs once as root on first boot. The runtime passes the *host* account in
/// `CONTAINER_USER`/`CONTAINER_HOME`; coop ignores them — the guest account is
/// baked into the image — and only verifies it, so no host-matching account
/// or home alias is created.
fn create_user_script(guest_user: &GuestUser) -> String {
    // GuestUser is validated to a POSIX-portable name, safe to interpolate.
    format!(
        r#"#!/bin/sh
set -eu
uid=$(id -u '{guest_user}' 2>/dev/null) || {{ echo "coop: guest user {guest_user} is missing" >&2; exit 1; }}
if [ "$uid" != 1000 ]; then
    echo "coop: guest user {guest_user} has uid $uid, expected 1000" >&2
    exit 1
fi
"#
    )
}

const HOSTKEY_UNIT: &str = "\
[Unit]
Description=Generate this machine's SSH host keys
Before=ssh.service
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=multi-user.target
";

/// Included before the main `sshd_config`, so these values win. TCP
/// forwarding stays on for coop's own `-L`/`-R` tunnels; remote forwards bind
/// the guest loopback only.
const SSHD_DROPIN: &str = "\
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowAgentForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
AllowTcpForwarding yes
";

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn inputs(user: &GuestUser) -> BuildInputs<'_> {
        BuildInputs {
            pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINiqkOnkRV06x+SuorkF+O3KdBTVFznIV0+b58cidW1N coop",
            profiles: &[],
            oci_features: &[],
            guest_user: user,
        }
    }

    #[test]
    fn manifest_id_tracks_inputs() {
        let user = GuestUser::default();
        let ctx = BuildContext::render(&inputs(&user));
        let a = ctx.manifest_id(&user, "SHA256:a");
        assert_eq!(a, ctx.manifest_id(&user, "SHA256:a"));
        assert_ne!(a, ctx.manifest_id(&user, "SHA256:b"));
        let other = GuestUser::new("coop").unwrap();
        let ctx2 = BuildContext::render(&inputs(&other));
        assert_ne!(a, ctx2.manifest_id(&other, "SHA256:a"));
    }

    #[test]
    fn context_is_private_and_minimal() {
        let user = GuestUser::default();
        let ctx = BuildContext::render(&inputs(&user));
        let dir = ctx.materialize().unwrap();
        let mode = fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "10-coop.conf",
                "Dockerfile",
                "coop-ssh-hostkeys.service",
                "create-user.sh",
                "machine-setup.sh",
                "provision.sh"
            ]
        );
        let all: String = ctx.files.iter().map(|(_, c, _)| c.as_str()).collect();
        assert!(!all.contains("PRIVATE KEY"));
        assert!(!all.contains("ARG "), "build args could leak into layers");
    }

    #[test]
    fn image_strips_host_identity_and_hardens_sshd() {
        let setup = machine_setup_script();
        assert!(setup.contains("rm -f /etc/ssh/ssh_host_*"));
        assert!(setup.contains(": > /etc/machine-id"));
        assert!(SSHD_DROPIN.contains("AllowAgentForwarding no"));
        assert!(SSHD_DROPIN.contains("PasswordAuthentication no"));
        assert!(SSHD_DROPIN.contains("PermitRootLogin no"));
        let create = create_user_script(&GuestUser::default());
        assert!(!create.contains("CONTAINER_USER"));
        assert!(!create.contains("useradd"));
    }

    #[test]
    fn digest_parsing_is_strict() {
        let good = format!(
            r#"[{{"name":"x","descriptor":{{"digest":"sha256:{}"}}}}]"#,
            "a".repeat(64)
        );
        assert!(parse_image_digest(&good).unwrap().starts_with("sha256:"));
        assert!(parse_image_digest("[]").is_err());
        assert!(parse_image_digest(r#"[{"descriptor":{"digest":"md5:1"}}]"#).is_err());
    }
}
