//! THE RECOVERY KIT on the desktop — a printable paper key that is an ordinary
//! member device.
//!
//! # STATUS: PRE-AUDIT — UNAUDITED — DEV / LOCALHOST / PLAIN HTTP
//!
//! [ADR 0042](../../../docs/decisions/0042-recovery-kit.md) built the kit and
//! shipped it in the `sigil` CLI only, with limitation 9 saying so in as many
//! words: *"the desktop has no recovery commands"*. That mattered because
//! **`restore` runs on a NEW INSTALL** — precisely the situation of a person who
//! has lost every device — so a customer whose only client was this app held a
//! printed sheet they could not use here.
//!
//! # Reuse, not reimplementation (the rule for this directory)
//!
//! There is **no kit codec, no HKDF derivation, no safety-number digest and no
//! HTTP request** in this file. Every one of them already exists twice (Rust in
//! `cli/src/lib.rs`, JavaScript in `sigil-wasm/recovery.mjs`) and a third copy
//! would be a liability, not a feature. This module calls the `sigil-cli`
//! LIBRARY functions the `sigil recovery …` subcommands call:
//!
//! | what | reused from `sigil_cli` |
//! |---|---|
//! | generate a kit, enroll it, cover vaults, verify before printing | [`recovery_generate`] |
//! | extend a kit to one more vault | [`recovery_cover`] |
//! | what a kit can still reach | [`recovery_check`] |
//! | decode + checksum a typed code, OFFLINE | [`recovery_verify`] |
//! | rebuild identity, keyring and vaults on a NEW machine | [`recovery_restore`] |
//! | retire a sheet and take back its envelopes | [`recovery_revoke`] |
//! | render the printed grouping | [`sigil_core::format_recovery_kit`] |
//!
//! ⭐ **The wrap gate comes with them.** `recovery_generate` and
//! `recovery_cover` reach the one wrap→deposit→grant path through
//! `verify_recipient_for_wrap`, whose `VerifiedRecipient` has private fields and
//! no other constructor — so nothing here *can* wrap a vault key to a kit whose
//! key was not verified, and a first-sight kit with no safety number is refused
//! with nothing wrapped and the pin store unmutated.
//!
//! # ⚠️ THE CODE IS THE WHOLE CREDENTIAL
//!
//! Whoever holds the 56 printed characters can read every covered vault and
//! revoke every device. It is **stronger than a stolen locked phone**: there is
//! no OS lock, no biometric and no vault password in front of it.
//!
//! So: [`RecoveryKitSheet::code`] is returned **exactly once**, is never written
//! to a file by this crate, never logged, never placed in a request, and is
//! redacted from `Debug`. Everything else on the sheet is public.

use std::path::{Path, PathBuf};

use sigil_cli::{
    recovery_check, recovery_cover, recovery_generate, recovery_restore, recovery_revoke,
    recovery_verify, RECOVERY_DEVICE_LABEL,
};
use sigil_core::format_recovery_kit;

use crate::net::net_error;
use crate::{DesktopError, DeviceConfig, Result};

// ---------------------------------------------------------------------------
// View models — public material only, except the one field that is the point
// ---------------------------------------------------------------------------

/// One vault a kit covers, as of the print date.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredVault {
    /// The op-log vault id.
    pub vault_id: String,
    /// 16-hex SHA-256 fingerprint of the vault key wrapped to the kit. Never the
    /// key.
    pub key_fingerprint: String,
}

/// What the mandatory pre-print round-trip proved: the kit was re-derived from
/// the exact text about to be printed, authenticated as itself, landed in THIS
/// account, and unwrapped a real envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProof {
    /// The account the kit resolved to when it authenticated as itself.
    pub account_id: String,
    /// How many vaults the kit's own envelope index reported.
    pub indexed_vaults: usize,
    /// The vault whose envelope was unwrapped end to end (`""` if none).
    pub unwrapped_vault: String,
    /// Fingerprint of the key that came back out. Never the key.
    pub key_fingerprint: String,
}

/// A freshly generated recovery kit: the printed sheet.
///
/// ⚠️ [`RecoveryKitSheet::code`] is **THE SECRET**, handed back exactly once so
/// the human can write it down. Show it, then drop it. Do not persist it, do not
/// log it, do not put it in a URL.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKitSheet {
    /// ⚠️ THE SECRET — the 56 characters, in the printed grouping.
    pub code: String,
    /// The kit's server-assigned device id. PUBLIC, and needed at restore time.
    pub device_id: String,
    /// The account it joined. PUBLIC.
    pub account_id: String,
    /// The server it was enrolled against. PUBLIC.
    pub server: String,
    /// The kit's SAFETY NUMBER — printed on the sheet so a sibling device can
    /// verify the kit's key before wrapping anything to it.
    pub safety_number: String,
    /// Unix seconds the kit was printed.
    pub created_at: u64,
    /// The vaults covered AS OF NOW. Coverage drifts: a vault created later
    /// needs [`DeviceConfig::recovery_cover`], and nothing reminds anyone.
    pub covered: Vec<CoveredVault>,
    /// Active devices in the account after the kit joined — it consumes a seat.
    pub seats_used: usize,
    /// The server's per-account device cap.
    pub seat_limit: usize,
    /// What the pre-print verification proved.
    pub proof: RecoveryProof,
}

/// REDACTED on purpose: a stray `{:?}` must not put the credential in a log.
impl std::fmt::Debug for RecoveryKitSheet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKitSheet")
            .field("code", &"<redacted>")
            .field("device_id", &self.device_id)
            .field("account_id", &self.account_id)
            .field("safety_number", &self.safety_number)
            .field("covered", &self.covered)
            .finish_non_exhaustive()
    }
}

/// One vault's coverage, **as observed from this device**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageView {
    /// The vault.
    pub vault_id: String,
    /// Whether the kit currently holds an envelope for it.
    pub covered: bool,
    /// RFC 3339 timestamp of that envelope, when covered.
    pub covered_at: String,
    /// Whether the vault's sealed container has EVER been pushed.
    /// ⚠️ A kit recovers KEYS, not DATA: an unsynced vault is unrecoverable even
    /// when it is "covered".
    pub synced: bool,
}

/// What a restore actually recovered, on a machine that had nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreView {
    /// The kit's device id.
    pub device_id: String,
    /// The account it belongs to.
    pub account_id: String,
    /// The vaults written out.
    pub vaults: Vec<RestoredVault>,
    /// Vaults the index listed but that could not be recovered, with a reason —
    /// most importantly a covered-but-never-synced vault, where the KEY came
    /// back and the DATA was never on the server.
    pub skipped: Vec<(String, String)>,
    /// Whether the kit's own secrets were persisted on this machine.
    /// ⚠️ `true` means this machine is now a second copy of the paper.
    pub adopted: bool,
}

/// One vault a restore rebuilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredVault {
    /// The vault id.
    pub vault_id: String,
    /// Where the sealed container was written (`0600`, in a `0700` directory).
    pub path: PathBuf,
    /// Fingerprint of the recovered vault key. Never the key.
    pub key_fingerprint: String,
    /// How many accounts the recovered vault holds.
    pub entries: usize,
}

/// What a revocation did, and what is still on the user to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeView {
    /// The kit that was revoked.
    pub device_id: String,
    /// Vaults whose envelope for the kit was deleted.
    pub envelopes_removed: Vec<String>,
    /// Vaults where there was nothing to remove.
    pub already_clear: Vec<String>,
}

/// A recovery kit this device can see in its own account listing.
///
/// ⚠️ Resolved by device LABEL ([`RECOVERY_DEVICE_LABEL`]) from a listing the
/// **server** serves, so it answers *"is recovery set up, as far as this server
/// admits"* — see ADR 0042 §5. It is a display aid; no trust decision is taken
/// on it here (the wrap gate makes those, and is not weakened by the label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KitView {
    /// The kit's device id — what `restore` and `check` are addressed to.
    pub device_id: String,
    /// `"active"` or `"revoked"`.
    pub status: String,
    /// RFC 3339 enrollment time.
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Offline: verify a typed code before anything is sent anywhere
// ---------------------------------------------------------------------------

/// VERIFY a printed recovery code **offline**: decode + checksum only.
///
/// ⭐ Zero network I/O, which is the property that lets a UI tell *"you mistyped
/// it"* apart from *"this server does not know that kit"* without ever having
/// sent the credential to a wrong server first.
///
/// The code is **not** echoed back — only whether it is well-formed.
///
/// # Errors
/// - [`DesktopError::Recovery`] naming the codec failure (wrong length, a
///   character outside the Crockford alphabet, or a bad checksum — which is what
///   a mistyped character produces).
pub fn verify_recovery_code(code: &str) -> Result<()> {
    // The decoded seed is dropped immediately; nothing but the verdict escapes.
    recovery_verify(code.trim()).map(|_| ()).map_err(|e| {
        DesktopError::Recovery(format!(
            "{e}\n  -> Check the sheet character by character. The alphabet has no I, L, O or U: \
             read 1 for I/L, 0 for O, and there is no U at all."
        ))
    })
}

/// Render a code in the printed grouping (7 groups of 8). ⚠️ Input and output
/// are both the SECRET.
#[must_use]
pub fn format_code(code: &str) -> String {
    format_recovery_kit(code)
}

// ---------------------------------------------------------------------------
// The kit lifecycle, on this device
// ---------------------------------------------------------------------------

impl DeviceConfig {
    /// GENERATE a recovery kit covering `vault_ids` (or, when empty, every
    /// shared vault this device currently holds a key for).
    ///
    /// The whole flow — draw 32 CSPRNG bytes, derive the kit's Ed25519 + hybrid
    /// identity, mint a PINNED single-use invite for exactly that public key,
    /// enroll as the kit, publish its hybrid key, pin the DERIVED key locally
    /// (so no covering wrap ever fetches a key there is anything to substitute),
    /// wrap each vault key to it, and then **verify before printing** by
    /// re-parsing the printed text, re-deriving, authenticating as the kit and
    /// unwrapping one envelope end to end — is [`recovery_generate`]'s. A kit
    /// that was generated but never worked is structurally impossible: any
    /// failure revokes the partial kit and returns the original error.
    ///
    /// ⚠️ A PASSWORD-sealed vault cannot be covered (it has no vault key to
    /// wrap). Convert it first — that is a one-way door.
    ///
    /// ⚠️ The returned [`RecoveryKitSheet::code`] is the whole credential and is
    /// returned once. See the module note.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::NotShared`] when a named vault has no key here.
    /// - [`DesktopError::Recovery`] when the pre-print verification failed (the
    ///   kit is revoked first).
    /// - [`DesktopError::Unauthenticated`] / [`DesktopError::Forbidden`] /
    ///   [`DesktopError::NotEnabled`] / [`DesktopError::Unreachable`] /
    ///   [`DesktopError::Server`] with `409` when the account is at its device
    ///   limit (a kit consumes a seat).
    pub fn recovery_generate(&self, vault_ids: &[String]) -> Result<RecoveryKitSheet> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();

        let vaults: Vec<String> = if vault_ids.is_empty() {
            self.status()?
                .vaults
                .into_iter()
                .map(|v| v.vault_id)
                .collect()
        } else {
            vault_ids
                .iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        };
        // Fail with the ACTIONABLE error rather than the library's generic one:
        // "this vault is still password-sealed" is what the user has to fix.
        for vault_id in &vaults {
            if self.vault_key(vault_id)?.is_none() {
                return Err(DesktopError::NotShared(vault_id.clone()));
            }
        }

        let kit = recovery_generate(
            self.server(),
            &auth,
            &vaults,
            &self.keyring_path(),
            &self.pins_path(),
            None,
        )
        .map_err(|e| net_error(e, self.server(), "generating the recovery kit"))?;

        Ok(RecoveryKitSheet {
            // The printed grouping is the ONLY form handed out: it decodes just
            // as well as the ungrouped one, so there is no reason to make a
            // second copy of the credential.
            code: format_recovery_kit(&kit.code),
            device_id: kit.public.device_id,
            account_id: kit.public.account_id,
            server: kit.public.server,
            safety_number: kit.public.safety_number,
            created_at: kit.public.created_at,
            covered: kit
                .covered
                .into_iter()
                .map(|(vault_id, key_fingerprint)| CoveredVault {
                    vault_id,
                    key_fingerprint,
                })
                .collect(),
            seats_used: kit.seats_used,
            seat_limit: kit.seat_limit,
            proof: RecoveryProof {
                account_id: kit.verification.account_id,
                indexed_vaults: kit.verification.indexed_vaults,
                unwrapped_vault: kit.verification.unwrapped_vault,
                key_fingerprint: kit.verification.key_fingerprint,
            },
        })
    }

    /// COVER one more vault with an EXISTING kit: wrap this vault's key to the
    /// kit and grant it `read`.
    ///
    /// ⭐ **Two paths, and the difference is the point.** On the device that
    /// generated the kit, the kit's key is pinned locally with
    /// `origin = "recovery-kit"`, so the derived identity is used and nothing is
    /// fetched — there is no substitution window at all. On any OTHER device the
    /// key must come from the server, and `safety_number` (the digits printed on
    /// the sheet) is **REQUIRED**: the wrap gate refuses a first-sight kit
    /// without it, before anything is wrapped or uploaded.
    ///
    /// Returns `(key fingerprint, was the key derived locally)`.
    ///
    /// # Errors
    /// - [`DesktopError::KeyUnverified`] when no (or a wrong) safety number was
    ///   given for a kit this device has not pinned.
    /// - [`DesktopError::KeyPinMismatch`] when the kit's published key CHANGED.
    /// - [`DesktopError::NotShared`] when the vault is still password-sealed.
    /// - [`DesktopError::NotEnrolled`] and the transport errors.
    pub fn recovery_cover(
        &self,
        kit_device_id: &str,
        vault_id: &str,
        safety_number: Option<&str>,
    ) -> Result<(String, bool)> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();
        let vault_id = vault_id.trim();
        if self.vault_key(vault_id)?.is_none() {
            return Err(DesktopError::NotShared(vault_id.to_string()));
        }
        recovery_cover(
            self.server(),
            &auth,
            kit_device_id.trim(),
            vault_id,
            &self.keyring_path(),
            &self.pins_path(),
            safety_number,
        )
        .map_err(|e| net_error(e, self.server(), "covering a vault with the recovery kit"))
    }

    /// CHECK, from this device, which of its vaults the kit still covers — and
    /// whether each has ever been pushed.
    ///
    /// ⚠️ Render it as *"checked from this device"*, never as *"you are
    /// covered"*: a vault created on a sibling device that never heard of the
    /// kit is invisible here. That is honest coverage drift, not a bug.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`], plus the transport errors (listing a
    ///   vault's envelope holders needs WRITE on that vault).
    pub fn recovery_check(&self, kit_device_id: &str) -> Result<Vec<CoverageView>> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();
        let rows = recovery_check(
            self.server(),
            &auth,
            kit_device_id.trim(),
            &self.keyring_path(),
        )
        .map_err(|e| net_error(e, self.server(), "checking what the recovery kit covers"))?;
        Ok(rows
            .into_iter()
            .map(|c| CoverageView {
                vault_id: c.vault_id,
                covered: c.covered,
                covered_at: c.covered_at,
                synced: c.synced,
            })
            .collect())
    }

    /// RESTORE from a printed kit — **the flow that runs on a machine which has
    /// nothing**, which is the situation the sheet exists for.
    ///
    /// The code is decoded and checksummed **offline first**, so a mistyped code
    /// never reaches a server. Then: derive → authenticate as the kit → read the
    /// kit's own (self-only) envelope index → per vault, collect the envelope,
    /// unwrap the vault key, pull the op-log, **open the container before
    /// writing it**, and only then write `0600` into a `0700` directory via a
    /// temp file and a rename.
    ///
    /// ⭐ **`adopt` defaults to false and should stay false unless the user is
    /// told what it means.** With `adopt = true` the kit's own Ed25519 seed and
    /// hybrid identity are written to this machine, which becomes a **second
    /// copy of the paper** — full account control, with no OS lock in front of
    /// it. With `adopt = false` the vaults and their keys are recovered and the
    /// kit's identity is dropped when this returns.
    ///
    /// Vaults land in `out_dir` (default: this config's state directory).
    ///
    /// # Errors
    /// - [`DesktopError::Recovery`] for an undecodable code (offline, nothing
    ///   sent) or a kit whose index is empty.
    /// - [`DesktopError::Unauthenticated`] (`401`) — a well-formed code that
    ///   this server has no device for: wrong server, wrong kit id, or revoked.
    ///   The server deliberately will not say which.
    pub fn recovery_restore(
        &self,
        code: &str,
        kit_device_id: &str,
        out_dir: Option<&Path>,
        adopt: bool,
    ) -> Result<RestoreView> {
        // OFFLINE FIRST, with the actionable message, before any network I/O.
        verify_recovery_code(code)?;
        let dir = out_dir.map_or_else(|| self.state_dir().to_path_buf(), Path::to_path_buf);
        let report = recovery_restore(
            code.trim(),
            self.server(),
            kit_device_id.trim(),
            &dir,
            adopt,
        )
        .map_err(|e| net_error(e, self.server(), "restoring from the recovery kit"))?;
        Ok(RestoreView {
            device_id: report.device_id,
            account_id: report.account_id,
            vaults: report
                .vaults
                .into_iter()
                .map(|(vault_id, path, key_fingerprint, entries)| RestoredVault {
                    vault_id,
                    path,
                    key_fingerprint,
                    entries,
                })
                .collect(),
            skipped: report.skipped,
            adopted: report.adopted,
        })
    }

    /// REVOKE a kit: refuse it at the door and delete its envelopes for
    /// `vault_ids` (or, when empty, every vault this device holds a key for).
    ///
    /// ⚠️ It does **not** rotate, and revocation **cannot un-learn** a key the
    /// kit already unwrapped. Rotating each vault is the remediation, and it
    /// protects FUTURE content only — so this returns the vaults it touched and
    /// leaves that decision explicit.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`], plus the transport errors.
    pub fn recovery_revoke(&self, kit_device_id: &str, vault_ids: &[String]) -> Result<RevokeView> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();
        let vaults: Vec<String> = if vault_ids.is_empty() {
            self.status()?
                .vaults
                .into_iter()
                .map(|v| v.vault_id)
                .collect()
        } else {
            vault_ids
                .iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        };
        let report = recovery_revoke(self.server(), &auth, kit_device_id.trim(), &vaults)
            .map_err(|e| net_error(e, self.server(), "revoking the recovery kit"))?;
        Ok(RevokeView {
            device_id: report.device_id,
            envelopes_removed: report.envelopes_removed,
            already_clear: report.already_clear,
        })
    }

    /// The recovery kits in this device's own account, as the SERVER lists them.
    ///
    /// ⚠️ Label-based (ADR 0042 §5): a server that renames the label makes a kit
    /// invisible here. It is a display aid for *"Recovery: not set up"* — no
    /// trust decision is taken on it.
    ///
    /// # Errors
    /// - As [`DeviceConfig::account`].
    pub fn recovery_kits(&self) -> Result<Vec<KitView>> {
        Ok(self
            .account()?
            .members
            .into_iter()
            .filter(|m| m.label == RECOVERY_DEVICE_LABEL)
            .map(|m| KitView {
                device_id: m.device_id,
                status: m.status,
                created_at: m.created_at,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Tests — the OFFLINE half. The networked proof (a real sigild + the real
// `sigil` binary, a device destroyed and a vault recovered from the paper
// alone) is `tests/server_interop.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sigil-desktop-recovery-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// ⭐ The offline gate. A mistyped sheet must be rejected HERE, with a
    /// message about typing, before the credential is ever sent to a server —
    /// including a server that has no business seeing it.
    #[test]
    fn a_mistyped_code_is_rejected_offline_and_never_echoed() {
        // The known-answer vector from `sigil-core` (seed = 0x42 * 32), which is
        // the same string the CLI and the JS client pin.
        const GOOD: &str = "05144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89145G6W";
        verify_recovery_code(GOOD).expect("the KAT code must verify");
        // Presentation is forgiving; content is not.
        verify_recovery_code(&GOOD.replace('-', "")).expect("ungrouped");
        verify_recovery_code(&GOOD.to_ascii_lowercase()).expect("case-insensitive");

        // One flipped character -> a checksum failure, not a version complaint.
        let mut typo: Vec<char> = GOOD.chars().collect();
        typo[2] = if typo[2] == '1' { '2' } else { '1' };
        let err = verify_recovery_code(&typo.iter().collect::<String>()).unwrap_err();
        assert!(matches!(err, DesktopError::Recovery(_)), "got {err:?}");
        let text = err.to_string();
        assert!(text.contains("check"), "{text}");
        // ⚠️ THE CREDENTIAL MUST NOT BE IN THE ERROR.
        assert!(
            !text.contains("144GJ2"),
            "the error echoed part of the code: {text}"
        );

        for bad in ["", "too short", "U0144GJ2"] {
            assert!(verify_recovery_code(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// Every kit operation that needs a server must refuse CLEARLY before it
    /// opens a socket, so a user with no identity gets a message, not a hang.
    #[test]
    fn kit_operations_without_an_identity_report_not_enrolled() {
        let c = DeviceConfig::new("http://127.0.0.1:1", scratch("notenrolled"));
        for e in [
            c.recovery_generate(&[]).unwrap_err(),
            c.recovery_cover("dev_kit", "v", Some("1")).unwrap_err(),
            c.recovery_check("dev_kit").unwrap_err(),
            c.recovery_revoke("dev_kit", &[]).unwrap_err(),
            c.recovery_kits().unwrap_err(),
        ] {
            assert!(matches!(e, DesktopError::NotEnrolled(_)), "got {e:?}");
        }
        // ...and a restore with a bad code fails OFFLINE, before the identity is
        // even consulted — there is no identity here and no server listening.
        assert!(matches!(
            c.recovery_restore("nonsense", "dev_kit", None, false),
            Err(DesktopError::Recovery(_))
        ));
        assert!(
            !c.state_dir().exists(),
            "a failed kit operation must not create state"
        );
    }

    /// The sheet is a credential: `Debug` must never print it.
    #[test]
    fn the_printed_code_is_redacted_from_debug() {
        let sheet = RecoveryKitSheet {
            code: "05144GJ2-89144GJ2".to_string(),
            device_id: "dev_kit".to_string(),
            account_id: "acct_1".to_string(),
            server: "http://127.0.0.1:1".to_string(),
            safety_number: "11111 22222 33333 44444 55555 66666".to_string(),
            created_at: 0,
            covered: vec![CoveredVault {
                vault_id: "v".to_string(),
                key_fingerprint: "0123456789abcdef".to_string(),
            }],
            seats_used: 2,
            seat_limit: 10,
            proof: RecoveryProof {
                account_id: "acct_1".to_string(),
                indexed_vaults: 1,
                unwrapped_vault: "v".to_string(),
                key_fingerprint: "0123456789abcdef".to_string(),
            },
        };
        let rendered = format!("{sheet:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains("05144GJ2"),
            "Debug leaked the recovery code: {rendered}"
        );
        // The public half is still renderable, which is what makes redaction
        // usable rather than merely safe.
        assert!(rendered.contains("dev_kit") && rendered.contains("11111"));
    }

    /// The grouping is the CLI's renderer, not a desktop copy of it.
    #[test]
    fn formatting_is_the_shared_renderer_and_is_idempotent() {
        const GOOD: &str = "05144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89145G6W";
        assert_eq!(format_code(&GOOD.replace('-', "")), GOOD);
        assert_eq!(format_code(GOOD), GOOD);
    }
}
