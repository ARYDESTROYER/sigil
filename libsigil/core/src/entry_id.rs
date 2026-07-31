//! Content-derived TOTP-entry identity (Phase 61).
//!
//! STATUS: pre-audit, UNAUDITED. This module adds **no new cryptography**: it is
//! one domain-separated, length-prefixed SHA-256 transcript formatted as an
//! RFC 9562 version-8 UUID. It reads no clock and draws no randomness, so it is
//! `no_std` and wasm-pure like the rest of the crate (ADR 0007).
//!
//! ## Why this exists, and why it lives HERE
//!
//! A TOTP entry has a stable `uuid` ([ADR 0047]) that is drawn at random when an
//! entry is created. Entries written **before** that field existed have none, and
//! a vault that syncs between devices must give those legacy entries an id that
//! **every device independently agrees on** — otherwise the first merge of a
//! pre-existing vault duplicates every account in it, and a delete performed on
//! one device can never suppress the other device's copy.
//!
//! That agreement has to be exact, and a **drift in this function is invisible**:
//! it produces a vault that opens correctly everywhere and merely duplicates or
//! mis-suppresses entries. So it is deliberately **not** a mirrored Rust/JS pair
//! like the vault schema — it lives in `sigil-core`, the CLI and the desktop call
//! it directly, and the browsers reach the *same bytes* through a one-line
//! `wasm_bindgen` shell.
//!
//! ## The transcript
//!
//! ```text
//! digest = SHA-256( "sigil-totp-entry-id-v1\n"
//!                 ‖ u32_be(len(issuer))    ‖ issuer      // "" when absent
//!                 ‖ u32_be(len(label))     ‖ label
//!                 ‖ u32_be(len(secret))    ‖ secret      // DECODED key bytes
//!                 ‖ u32_be(len(algorithm)) ‖ algorithm   // lowercase
//!                 ‖ u32_be(4) ‖ u32_be(digits)
//!                 ‖ u32_be(4) ‖ u32_be(period)
//!                 ‖ u32_be(4) ‖ u32_be(disambiguator) )
//! id     = uuid_v8(digest[0..16])
//! ```
//!
//! Every field is length-prefixed, so `issuer="ab", label="c"` cannot collide
//! with `issuer="a", label="bc"` — the same framing discipline as
//! [`crate::hybrid_auth`]'s context AAD and the safety-number digest.
//!
//! `disambiguator` is `0` for every ordinary call. It exists only so that a vault
//! that already contains two byte-identical legacy entries (which nothing in this
//! repo writes — `TotpVault::add` has always rejected duplicates — but which a
//! hand-edited or hand-merged file can contain) can be given distinct **and still
//! deterministic** ids, instead of collapsing two entries into one at merge time.
//!
//! ## Why version 8 and not version 5
//!
//! RFC 9562 §5.5 defines version 5 as *"name-based, SHA-1"*. This is SHA-256, so
//! calling it a v5 would be a false statement encoded in a wire format. Version 8
//! is the standard's "custom / implementation-defined" version, which is exactly
//! what this is.
//!
//! ## What it is NOT
//!
//! ⚠️ It is an **identifier, not a secret and not a key** — but note that it *is*
//! computed over the secret, so an id derived this way is a commitment to the
//! entry's full content. That is why it is used **only** to bootstrap an id for a
//! legacy entry (and to answer "do I already have this exact account?" at import
//! time), and never as the id of a newly created entry, which stays random.
//!
//! [ADR 0047]: ../../../docs/decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md

use alloc::string::String;
use sha2::{Digest, Sha256};

/// Domain separator for the entry-id transcript. Ends with a newline, matching
/// the other domain strings in this crate.
const ENTRY_ID_DOMAIN: &[u8] = b"sigil-totp-entry-id-v1\n";

/// Number of bytes of the digest that become the UUID.
const UUID_BYTES: usize = 16;

/// Absorb one length-prefixed field into `h`.
fn absorb(h: &mut Sha256, field: &[u8]) {
    // `as u32` cannot truncate meaningfully here: a TOTP label/issuer/secret that
    // exceeded 4 GiB could not be held by any caller in this workspace, and the
    // prefix is framing, not a length check.
    h.update((field.len() as u32).to_be_bytes());
    h.update(field);
}

/// Absorb one length-prefixed `u32`.
fn absorb_u32(h: &mut Sha256, v: u32) {
    h.update(4u32.to_be_bytes());
    h.update(v.to_be_bytes());
}

/// Format 16 bytes as a lowercase RFC 9562 **version 8** UUID string.
///
/// The version nibble and the variant bits are fixed, so the output is a
/// well-formed UUID and not merely hex.
#[must_use]
pub fn format_entry_uuid_v8(bytes: &[u8; UUID_BYTES]) -> String {
    let mut b = *bytes;
    b[6] = (b[6] & 0x0f) | 0x80; // version 8 (custom)
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 / 9562 variant
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            out.push('-');
        }
        // Lowercase hex, without pulling in `format!`'s machinery per byte.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Derive the deterministic, content-derived id of a TOTP entry.
///
/// `secret` is the **decoded** key bytes (not the base64 the vault stores), and
/// `algorithm` is the lowercase name (`"sha1"` / `"sha256"` / `"sha512"`). Pass
/// `disambiguator = 0` unless an earlier entry in the same vault already claimed
/// the resulting id.
///
/// The output is stable across every client, every platform and every build — it
/// is a pure function of its arguments.
#[must_use]
pub fn entry_id(
    issuer: &str,
    label: &str,
    secret: &[u8],
    algorithm: &str,
    digits: u32,
    period: u32,
    disambiguator: u32,
) -> String {
    let mut h = Sha256::new();
    h.update(ENTRY_ID_DOMAIN);
    absorb(&mut h, issuer.as_bytes());
    absorb(&mut h, label.as_bytes());
    absorb(&mut h, secret);
    absorb(&mut h, algorithm.as_bytes());
    absorb_u32(&mut h, digits);
    absorb_u32(&mut h, period);
    absorb_u32(&mut h, disambiguator);
    let digest = h.finalize();
    let mut first16 = [0u8; UUID_BYTES];
    first16.copy_from_slice(&digest[..UUID_BYTES]);
    format_entry_uuid_v8(&first16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString as _;

    // ⭐ THE KNOWN-ANSWER VECTOR. It is asserted here, in `cli/src/lib.rs`, in
    // `sigil-wasm/src/lib.rs` and in `sigil-wasm/test/merge-interop.mjs`, so a
    // change to the transcript cannot be made quietly on one side.
    const KAT_ISSUER: &str = "GitHub";
    const KAT_LABEL: &str = "alice@example.com";
    const KAT_SECRET: &[u8] = b"12345678901234567890";
    // Computed independently in Python from the transcript above, not copied out
    // of this implementation's output.
    const KAT_ID: &str = "41828256-7397-80c1-bf67-e6b85ff84173";

    #[test]
    fn known_answer_vector() {
        assert_eq!(
            entry_id(KAT_ISSUER, KAT_LABEL, KAT_SECRET, "sha1", 6, 30, 0),
            KAT_ID
        );
    }

    #[test]
    fn it_is_a_well_formed_version_8_uuid() {
        let id = entry_id("", "x", b"k", "sha1", 6, 30, 0);
        assert_eq!(id.len(), 36);
        let bytes = id.as_bytes();
        assert_eq!(bytes[8], b'-');
        assert_eq!(bytes[13], b'-');
        assert_eq!(bytes[14], b'8', "version nibble must be 8, not 4 or 5");
        assert_eq!(bytes[18], b'-');
        assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'), "variant");
        assert_eq!(bytes[23], b'-');
        assert!(id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
    }

    #[test]
    fn it_is_deterministic() {
        let a = entry_id("iss", "lab", b"secret", "sha256", 8, 60, 0);
        let b = entry_id("iss", "lab", b"secret", "sha256", 8, 60, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn every_field_changes_the_id() {
        let base = entry_id("iss", "lab", b"secret", "sha1", 6, 30, 0);
        for other in [
            entry_id("ISS", "lab", b"secret", "sha1", 6, 30, 0),
            entry_id("iss", "LAB", b"secret", "sha1", 6, 30, 0),
            entry_id("iss", "lab", b"SECRET", "sha1", 6, 30, 0),
            entry_id("iss", "lab", b"secret", "sha256", 6, 30, 0),
            entry_id("iss", "lab", b"secret", "sha1", 8, 30, 0),
            entry_id("iss", "lab", b"secret", "sha1", 6, 60, 0),
            entry_id("iss", "lab", b"secret", "sha1", 6, 30, 1),
        ] {
            assert_ne!(base, other);
        }
    }

    #[test]
    fn length_prefixes_defeat_the_boundary_collision() {
        // Without length prefixes, "ab"+"c" and "a"+"bc" hash identically.
        assert_ne!(
            entry_id("ab", "c", b"", "sha1", 6, 30, 0),
            entry_id("a", "bc", b"", "sha1", 6, 30, 0)
        );
    }

    #[test]
    fn an_absent_issuer_is_the_empty_string() {
        // Callers map `None` to `""`; that must be a stable, documented choice.
        assert_eq!(
            entry_id("", "lab", b"s", "sha1", 6, 30, 0),
            entry_id("", "lab", b"s", "sha1", 6, 30, 0).to_string()
        );
    }
}
