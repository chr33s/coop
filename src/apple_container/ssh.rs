//! First-boot host-key enrollment and pinned SSH targets.
//!
//! The guest's Ed25519 host public key is read over the runtime's native
//! control channel (`machine run --root`, addressed to the exact owned
//! machine) — never over the network with `ssh-keyscan` — and written to a
//! per-instance known-hosts file under a stable alias. Every later connection
//! verifies against that pin; a missing or changed key is a hard error.

use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use anyhow::{Context, Result, bail};
use sha2::Digest as _;

use super::AppleError;
use super::state::MachineName;
use crate::backend::{HostKeyPolicy, Hostname, PinnedHostKey, SshTarget, SshUser};
use crate::config::{CoopConfig, Instance};

const ED25519_PREFIX: &str = "ssh-ed25519";
/// Base64 of the ed25519 wire blob: `u32 len || "ssh-ed25519" || u32 len || 32 bytes`.
const ED25519_BLOB_LEN: usize = 4 + 11 + 4 + 32;

/// A validated guest host public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostPublicKey {
    base64: String,
    blob: Vec<u8>,
}

impl HostPublicKey {
    /// Parse exactly one `ssh-ed25519 <base64> [comment]` line. The comment is
    /// guest-controlled and dropped.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let (Some(line), None) = (lines.next(), lines.next()) else {
            bail!(AppleError::HostKeyChanged(
                "guest host public key must be exactly one line".into()
            ));
        };
        let mut fields = line.split_whitespace();
        let (Some(kind), Some(b64)) = (fields.next(), fields.next()) else {
            bail!(AppleError::HostKeyChanged(
                "malformed guest host public key".into()
            ));
        };
        if kind != ED25519_PREFIX {
            bail!(AppleError::HostKeyChanged(format!(
                "guest host key type {:?} is not ssh-ed25519",
                super::cli::sanitize_for_display(kind)
            )));
        }
        let blob = decode_base64(b64).ok_or_else(|| {
            AppleError::HostKeyChanged("guest host key is not valid base64".into())
        })?;
        let well_formed = blob.len() == ED25519_BLOB_LEN
            && blob[..4] == [0, 0, 0, 11]
            && &blob[4..15] == ED25519_PREFIX.as_bytes()
            && blob[15..19] == [0, 0, 0, 32];
        if !well_formed {
            bail!(AppleError::HostKeyChanged(
                "guest host key blob is not an ed25519 public key".into()
            ));
        }
        Ok(Self {
            base64: b64.to_string(),
            blob,
        })
    }

    /// OpenSSH-style `SHA256:<base64>` fingerprint.
    pub(crate) fn fingerprint(&self) -> String {
        let digest = sha2::Sha256::digest(&self.blob);
        format!(
            "SHA256:{}",
            crate::devcontainer_oci::base64_encode(&digest).trim_end_matches('=')
        )
    }

    fn known_hosts_line(&self, alias: &Hostname) -> String {
        format!("{alias} {ED25519_PREFIX} {}\n", self.base64)
    }
}

/// Stable per-instance `HostKeyAlias`, independent of the (reassignable) IP.
pub(crate) fn host_key_alias(machine: &MachineName) -> Result<Hostname> {
    Hostname::new(format!("{machine}.coop-apple"))
}

/// Record the first-boot key for a newly created machine. Refuses to replace
/// an existing pin: re-enrollment is an explicit operator action.
pub(crate) fn enroll(inst: &Instance, machine: &MachineName, key: &HostPublicKey) -> Result<()> {
    let path = super::state::known_hosts_path(inst);
    if path.exists() {
        bail!(AppleError::HostKeyChanged(format!(
            "instance '{}' already has a pinned host key at {}; refusing to re-enroll",
            inst.name,
            path.display()
        )));
    }
    crate::fs_util::atomic_write_with_mode(
        &path,
        &key.known_hosts_line(&host_key_alias(machine)?),
        0o600,
    )
    .context("Failed to write pinned host key")
}

/// Compare a freshly read key against the pin recorded at enrollment.
pub(crate) fn check_pin(inst: &Instance, machine: &MachineName, key: &HostPublicKey) -> Result<()> {
    let path = super::state::known_hosts_path(inst);
    let pinned = std::fs::read_to_string(&path).map_err(|_| {
        AppleError::HostKeyChanged(format!(
            "instance '{}' has no pinned host key; recreate the instance",
            inst.name
        ))
    })?;
    if pinned != key.known_hosts_line(&host_key_alias(machine)?) {
        bail!(AppleError::HostKeyChanged(format!(
            "the SSH host key of instance '{}' changed (now {}); refusing to connect. \
             Recreate the instance, or re-enroll deliberately after review.",
            inst.name,
            key.fingerprint()
        )));
    }
    Ok(())
}

/// Build the pinned SSH target for `machine` at its current address.
pub(crate) fn pinned_target(
    cfg: &CoopConfig,
    inst: &Instance,
    machine: &MachineName,
    ip: Ipv4Addr,
    user: &crate::guest::GuestUser,
) -> Result<SshTarget> {
    let known_hosts = super::state::known_hosts_path(inst);
    // The path is passed to ssh as a (possibly quoted) option value and
    // written into `~/.ssh/config`; a quote or control character there
    // could change how ssh parses it.
    if known_hosts
        .to_string_lossy()
        .chars()
        .any(|c| c == '"' || c == '\'' || c.is_control())
    {
        bail!(
            "data directory path {} contains a quote or control character; SSH \
             options cannot carry it safely",
            known_hosts.display()
        );
    }
    if !known_hosts.exists() {
        bail!(AppleError::HostKeyChanged(format!(
            "instance '{}' has no pinned host key at {}; recreate the instance",
            inst.name,
            known_hosts.display()
        )));
    }
    Ok(SshTarget {
        host: Hostname::from(ip),
        port: NonZeroU16::new(22).context("port 22")?,
        user: SshUser::new(user.as_str())?,
        key_path: cfg.ssh_key_path(),
        host_keys: HostKeyPolicy::Pinned(PinnedHostKey {
            known_hosts,
            alias: host_key_alias(machine)?,
        }),
    })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = u32::try_from(B64.iter().position(|&b| b == c)?).ok()?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    // Throwaway keys generated with `ssh-keygen -t ed25519` for these tests.
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINiqkOnkRV06x+SuorkF+O3KdBTVFznIV0+b58cidW1N root@guest";
    const OTHER_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKB2Bohi4Rqvfx9oW+/9UovsYrOdYeFuWqvUuZpjig+1 x";

    fn machine() -> MachineName {
        MachineName::new("coop-0a1b2c3d-00112233445566ff").unwrap()
    }

    fn inst(dir: &std::path::Path) -> Instance {
        Instance {
            name: crate::config::InstanceName::new("t").unwrap(),
            index: crate::config::InstanceIndex::new(0).unwrap(),
            dir: dir.to_path_buf(),
            image: crate::config::ImageName::new("default").unwrap(),
        }
    }

    #[test]
    fn parses_one_ed25519_key_and_fingerprints_it() {
        let key = HostPublicKey::parse(KEY).unwrap();
        // Matches `ssh-keygen -lf` for the same key.
        assert_eq!(
            key.fingerprint(),
            "SHA256:10O2vYbKkmA/sBuRrfwbSNiR5pAFM/qtkqldbUJESvk"
        );
    }

    #[test]
    fn rejects_other_types_multiple_lines_and_garbage() {
        assert!(HostPublicKey::parse("").is_err());
        assert!(HostPublicKey::parse(&format!("{KEY}\n{KEY}")).is_err());
        assert!(HostPublicKey::parse("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x").is_err());
        assert!(HostPublicKey::parse("ssh-ed25519 not*base64").is_err());
        assert!(HostPublicKey::parse("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5").is_err());
    }

    #[test]
    fn enroll_once_then_pin_is_enforced() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let inst = inst(tmp.path());
        let key = HostPublicKey::parse(KEY).unwrap();
        enroll(&inst, &machine(), &key).unwrap();
        let mode = std::fs::metadata(super::super::state::known_hosts_path(&inst))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        check_pin(&inst, &machine(), &key).unwrap();

        // Re-enrollment is refused.
        assert!(enroll(&inst, &machine(), &key).is_err());

        // A different key is a hard error.
        let other = HostPublicKey::parse(OTHER_KEY).unwrap();
        let err = check_pin(&inst, &machine(), &other).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<AppleError>(),
            Some(AppleError::HostKeyChanged(_))
        ));
    }

    #[test]
    fn missing_pin_blocks_target() {
        let tmp = tempfile::tempdir().unwrap();
        let inst = inst(tmp.path());
        let cfg = CoopConfig::default();
        let user = crate::guest::GuestUser::default();
        let key = HostPublicKey::parse(KEY).unwrap();
        assert!(check_pin(&inst, &machine(), &key).is_err());
        assert!(pinned_target(&cfg, &inst, &machine(), Ipv4Addr::new(10, 0, 0, 2), &user).is_err());
        enroll(&inst, &machine(), &key).unwrap();
        let target =
            pinned_target(&cfg, &inst, &machine(), Ipv4Addr::new(10, 0, 0, 2), &user).unwrap();
        assert!(matches!(target.host_keys, HostKeyPolicy::Pinned(_)));
        assert!(
            target
                .ssh_opts()
                .iter()
                .any(|o| o == "StrictHostKeyChecking=yes")
        );
    }

    #[test]
    fn base64_decodes_known_vectors() {
        for (enc, dec) in [
            ("", &b""[..]),
            ("Zg==", b"f"),
            ("Zm8", b"fo"),
            ("Zm9vYmFy", b"foobar"),
        ] {
            assert_eq!(decode_base64(enc).unwrap(), dec);
        }
        assert!(decode_base64("Zm9v*").is_none());
    }
}
