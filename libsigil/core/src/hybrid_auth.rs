//! **AUTHENTICATED** hybrid public-key encryption — the sender proves, to the
//! AEAD itself, that it holds a specific long-term X25519 secret.
//!
//! STATUS: pre-audit, UNAUDITED. Like [`mod@crate::hybrid`] and
//! [`mod@crate::hybrid_seal`] this module writes **no new low-level
//! cryptography**: it composes X25519 ([`mod@crate::kx`]), ML-KEM-768
//! ([`mod@crate::mlkem`]), HKDF-SHA256 and the AEAD/envelope layers that are
//! already here. It adds **no dependency**, draws **no randomness**, and reads
//! **no clock**.
//!
//! # Why this module exists — the hole it closes
//!
//! [`crate::hybrid_seal`] is an **ephemeral-static** KEM: the sender's only key
//! is a per-message ephemeral X25519 secret, so *anybody* holding the
//! recipient's PUBLIC key can produce a well-formed ciphertext that the
//! recipient will happily open. That is the right shape for anonymous
//! file-to-a-pubkey encryption (HPKE `mode_base`), and it is a **catastrophic**
//! shape for delivering a **key** — the recipient cannot tell a key its peer
//! chose from a key an attacker chose. In the vault-sharing flow the practical
//! consequence was that anyone who could read a device's published hybrid public
//! key (which the server serves to every authenticated device) and deposit an
//! envelope could install a vault key **of their own choosing**; everything the
//! victim wrote afterwards was readable by the attacker.
//!
//! This module is the fix, and it is HPKE's `mode_auth` shape: the sender ALSO
//! holds a long-term ("static") X25519 key pair, and a third Diffie–Hellman
//! between the sender's static secret and the recipient's static public key is
//! mixed into the KDF. An attacker who knows only public keys cannot compute
//! that third secret, so it cannot produce a ciphertext this module will open.
//!
//! # The construction
//!
//! ```text
//!   ss_e = X25519(eph_secret,            recipient_x25519_pub)   -- ephemeral-static
//!   ss_s = X25519(sender_static_secret,  recipient_x25519_pub)   -- static-static  <-- THE AUTHENTICATION
//!  (mlkem_ct, ss_kem) = ML-KEM-768.Encaps(recipient_encaps_key, coin)
//!
//!   transcript = SHA-256( "sigil-hybrid-auth-v1\n"
//!                       ‖ u32_be(32)   ‖ eph_x25519_pub
//!                       ‖ u32_be(1088) ‖ mlkem_ct
//!                       ‖ u32_be(32)   ‖ sender_static_x25519_pub
//!                       ‖ u32_be(32)   ‖ recipient_x25519_pub )
//!
//!   ss = HKDF-SHA256( ikm  = ss_e ‖ ss_kem ‖ ss_s ‖ transcript,
//!                     salt = none,
//!                     info = "sigil-hybrid-auth-v1" )            [32 bytes]
//! ```
//!
//! Every field in the transcript is length-prefixed, so no two distinct field
//! sets can produce the same byte stream. The transcript binds the ephemeral
//! public key, the ML-KEM ciphertext, **the sender's identity** and **the
//! recipient's identity**, so a capture cannot be re-attributed to a different
//! sender or re-aimed at a different recipient without changing the key.
//!
//! ## What each half buys, honestly
//!
//! * `ss_e` gives forward secrecy against later compromise of the sender's
//!   static secret (the ephemeral secret is thrown away).
//! * `ss_kem` is the post-quantum half; as in [`mod@crate::hybrid`], breaking
//!   the combined secret is designed to require breaking **both** X25519 and
//!   ML-KEM-768.
//! * `ss_s` is the **authentication**. ⚠️ It is *implicit*, key-confirmed
//!   authentication, not a signature: it proves the ciphertext was produced by
//!   **someone holding the sender's static X25519 secret**, and it is **not
//!   transferable** — the recipient cannot show a third party that the sender
//!   made it, because the recipient could have made it too (it knows `ss_s`).
//!   For our purpose — "did MY peer choose this vault key, or did somebody
//!   else?" — that is exactly the property required, and it is deliberately
//!   *weaker* than non-repudiation.
//!
//! ⚠️ **The post-quantum half is NOT authenticated.** `ss_s` is classical X25519
//! only. A quantum adversary that can break X25519 could forge a ciphertext,
//! even though it still could not *read* one (that needs ML-KEM too). Making
//! authentication post-quantum needs an ML-KEM static-static encapsulation or an
//! ML-DSA signature; neither is wired in here, and this module does not claim
//! post-quantum authentication.
//!
//! ## Entropy, as everywhere in this crate
//!
//! The ephemeral X25519 secret, the ML-KEM coin and the AEAD nonce are the
//! CALLER's to supply, fresh per message, from a CSPRNG — `sigil-core` compiles
//! to `wasm32-unknown-unknown` and never generates randomness
//! ([ADR 0007](../../../docs/decisions/0007-caller-supplied-entropy-in-core.md)).
//!
//! ## Pre-audit caveats
//!
//! - UNAUDITED, and a **custom** composition: this is HPKE `mode_auth`'s *shape*
//!   but it is **NOT RFC 9180 HPKE** and shares none of its test vectors.
//! - A non-contributory (all-zero / low-order) recipient public key is rejected
//!   for **both** DH computations, exactly as [`mod@crate::kx`] does.
//! - No zeroization of the component secrets beyond what the dependencies do.

use crate::{
    ml_kem768_decapsulate, ml_kem768_encapsulate, open, seal, x25519_public_key,
    x25519_shared_secret, Envelope, HybridError, HybridSealError, HybridSealed,
    ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN,
    ML_KEM768_ENCAPS_KEY_LEN, ML_KEM768_SHARED_SECRET_LEN, NONCE_LEN, X25519_PUBLIC_KEY_LEN,
    X25519_SECRET_KEY_LEN, X25519_SHARED_SECRET_LEN,
};
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Length, in bytes, of the combined AUTHENTICATED hybrid shared secret.
pub const HYBRID_AUTH_SHARED_SECRET_LEN: usize = 32;

/// HKDF `info` label domain-separating the authenticated combiner from the
/// anonymous one (`"sigil-hybrid-v1"`). The two derivations can therefore never
/// produce the same key from the same material.
pub const HYBRID_AUTH_INFO: &[u8] = b"sigil-hybrid-auth-v1";

/// Domain-separation prefix of the authenticated transcript hash. The trailing
/// newline is part of the constant.
pub const HYBRID_AUTH_TRANSCRIPT_PREFIX: &[u8] = b"sigil-hybrid-auth-v1\n";

/// Domain-separation prefix of the vault-key-wrap AAD ([`vault_key_wrap_aad`]).
///
/// ⚠️ The `-v1` is **this AAD layout's own version**, not the container's: the
/// layout is carried inside `SIGILhyb` container **version 2**. Changing these
/// bytes invalidates every existing wrapped vault key and MUST be a version bump.
pub const VAULT_KEY_WRAP_AAD_PREFIX: &[u8] = b"sigil-vault-key-wrap-v1\n";

/// Length-prefix a field into a transcript so that no two different field sets
/// can serialise to the same bytes (`"ab"+"c"` must not collide with `"a"+"bc"`).
fn absorb(h: &mut Sha256, field: &[u8]) {
    h.update((field.len() as u32).to_be_bytes());
    h.update(field);
}

/// Length-prefix a field into a byte buffer, same rule as [`absorb`].
fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

/// ⭐ The CONTEXT-BOUND additional authenticated data for a **vault-key wrap**.
///
/// ```text
///   "sigil-vault-key-wrap-v1\n"
///   ‖ u32_be(len(vault_id))            ‖ vault_id
///   ‖ u32_be(len(recipient_device_id)) ‖ recipient_device_id
///   ‖ u32_be(len(sender_device_id))    ‖ sender_device_id
/// ```
///
/// # Why an AAD at all, when the KEM is already authenticated
///
/// Authentication says *who made this ciphertext*. It does not say *what it was
/// meant for*. Before this existed, every hybrid container in the system was
/// sealed under one fixed tag (`"sigil-hybrid-cli/1"`), which bound the
/// ciphertext to **no vault, no recipient, no sender and NO PURPOSE** — which is
/// precisely why the output of the general-purpose file-encryption command was a
/// structurally valid *vault-key envelope*. Binding the purpose and the three
/// identifiers means:
///
/// * a **file** envelope can never be replayed as a **vault-key** envelope, and
///   vice versa (different domain string);
/// * an envelope for vault A cannot be moved to vault B;
/// * an envelope addressed to device X cannot be re-filed under device Y;
/// * an envelope from sender S cannot be re-attributed to sender T.
///
/// Each of those would otherwise be a re-filing attack the AEAD could not see,
/// because the ciphertext itself is unchanged. The AAD travels in the clear
/// inside the envelope and is authenticated by the AEAD tag, so a mismatch is an
/// authentication failure — never a silent success.
///
/// The identifiers are opaque strings to this crate; the caller supplies them
/// and MUST use the same three values on both sides.
///
/// MIRRORED in `sigil-wasm/sharing.mjs`; the bytes MUST stay identical or a
/// browser-wrapped key will not open in the CLI (and vice versa).
pub fn vault_key_wrap_aad(
    vault_id: &str,
    recipient_device_id: &str,
    sender_device_id: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        VAULT_KEY_WRAP_AAD_PREFIX.len()
            + 12
            + vault_id.len()
            + recipient_device_id.len()
            + sender_device_id.len(),
    );
    out.extend_from_slice(VAULT_KEY_WRAP_AAD_PREFIX);
    push_field(&mut out, vault_id.as_bytes());
    push_field(&mut out, recipient_device_id.as_bytes());
    push_field(&mut out, sender_device_id.as_bytes());
    out
}

/// The output of [`hybrid_auth_encapsulate`]: `(eph_x25519_pub, mlkem_ct,
/// combined_secret)`.
pub type HybridAuthEncapsulation = (
    [u8; X25519_PUBLIC_KEY_LEN],
    [u8; ML_KEM768_CIPHERTEXT_LEN],
    [u8; HYBRID_AUTH_SHARED_SECRET_LEN],
);

/// Combine the three raw component secrets, binding the full transcript.
///
/// See the module docs for the exact layout. Both DH halves and the ML-KEM half
/// feed the HKDF input keying material, so the output depends on all three.
#[allow(clippy::too_many_arguments)]
fn combine_auth(
    ss_e: &[u8; X25519_SHARED_SECRET_LEN],
    ss_kem: &[u8; ML_KEM768_SHARED_SECRET_LEN],
    ss_s: &[u8; X25519_SHARED_SECRET_LEN],
    eph_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    mlkem_ct: &[u8; ML_KEM768_CIPHERTEXT_LEN],
    sender_static_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
) -> [u8; HYBRID_AUTH_SHARED_SECRET_LEN] {
    let mut h = Sha256::new();
    h.update(HYBRID_AUTH_TRANSCRIPT_PREFIX);
    absorb(&mut h, eph_x25519_pub);
    absorb(&mut h, mlkem_ct);
    absorb(&mut h, sender_static_x25519_pub);
    absorb(&mut h, recipient_x25519_pub);
    let transcript = h.finalize();

    // ikm = ss_e (32) ‖ ss_kem (32) ‖ ss_s (32) ‖ transcript (32) = 128 bytes.
    let mut ikm = [0u8; 128];
    ikm[..32].copy_from_slice(ss_e);
    ikm[32..64].copy_from_slice(ss_kem);
    ikm[64..96].copy_from_slice(ss_s);
    ikm[96..].copy_from_slice(&transcript);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; HYBRID_AUTH_SHARED_SECRET_LEN];
    hk.expand(HYBRID_AUTH_INFO, &mut okm)
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    okm
}

/// AUTHENTICATED hybrid encapsulation: establish a shared secret with a
/// recipient **as** the holder of `sender_static_x25519_secret`.
///
/// Returns `(eph_x25519_pub, mlkem_ciphertext, combined_secret)`. The recipient
/// recovers the same secret via [`hybrid_auth_decapsulate`] — but ONLY if it is
/// told which sender to expect, because the sender's static public key is an
/// input to the derivation and is deliberately **not** carried in the output.
///
/// `ephemeral_x25519_secret` and `mlkem_coin` MUST be fresh per call.
///
/// # Errors
/// - [`HybridError::Kx`] if either Diffie–Hellman is non-contributory, i.e.
///   `recipient_x25519_pub` is an all-zero / low-order point (RFC 7748 §6.1).
/// - [`HybridError::MlKem`] if the encapsulation key does not parse
///   (unreachable for the fixed-size array here).
pub fn hybrid_auth_encapsulate(
    sender_static_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_mlkem_encaps_key: &[u8; ML_KEM768_ENCAPS_KEY_LEN],
    ephemeral_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    mlkem_coin: &[u8; ML_KEM768_ENCAPS_COIN_LEN],
) -> Result<HybridAuthEncapsulation, HybridError> {
    // Both DH halves reject a non-contributory peer point.
    let ss_e = x25519_shared_secret(ephemeral_x25519_secret, recipient_x25519_pub)?;
    let ss_s = x25519_shared_secret(sender_static_x25519_secret, recipient_x25519_pub)?;
    let eph_pub = x25519_public_key(ephemeral_x25519_secret);
    let sender_pub = x25519_public_key(sender_static_x25519_secret);
    let (mlkem_ct, ss_kem) = ml_kem768_encapsulate(recipient_mlkem_encaps_key, mlkem_coin)?;
    let combined = combine_auth(
        &ss_e,
        &ss_kem,
        &ss_s,
        &eph_pub,
        &mlkem_ct,
        &sender_pub,
        recipient_x25519_pub,
    );
    Ok((eph_pub, mlkem_ct, combined))
}

/// AUTHENTICATED hybrid decapsulation: recover the secret established by
/// [`hybrid_auth_encapsulate`], **for a named sender**.
///
/// ⭐ `sender_static_x25519_pub` is an INPUT, not something read out of the
/// ciphertext. Passing the wrong sender yields a different secret and therefore
/// an AEAD authentication failure downstream — the caller learns "this did not
/// come from who I expected" without any string comparison being trusted.
///
/// # Errors
/// - [`HybridError::Kx`] if `sender_eph_x25519_pub` is non-contributory.
/// - [`HybridError::MlKem`] if a fixed-size input does not parse (unreachable
///   here).
pub fn hybrid_auth_decapsulate(
    recipient_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient_mlkem_decaps_key: &[u8; ML_KEM768_DECAPS_KEY_LEN],
    sender_static_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    sender_eph_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    mlkem_ct: &[u8; ML_KEM768_CIPHERTEXT_LEN],
) -> Result<[u8; HYBRID_AUTH_SHARED_SECRET_LEN], HybridError> {
    let ss_e = x25519_shared_secret(recipient_x25519_secret, sender_eph_x25519_pub)?;
    let ss_s = x25519_shared_secret(recipient_x25519_secret, sender_static_x25519_pub)?;
    let ss_kem = ml_kem768_decapsulate(recipient_mlkem_decaps_key, mlkem_ct)?;
    let recipient_pub = x25519_public_key(recipient_x25519_secret);
    Ok(combine_auth(
        &ss_e,
        &ss_kem,
        &ss_s,
        sender_eph_x25519_pub,
        mlkem_ct,
        sender_static_x25519_pub,
        &recipient_pub,
    ))
}

/// AUTHENTICATED hybrid seal: encrypt `plaintext` TO a recipient's hybrid public
/// key, AS the holder of `sender_static_x25519_secret`, under `aad`.
///
/// This is [`crate::hybrid_seal`] with the sender's identity folded into the KEM.
/// Returns `(eph_x25519_pub, mlkem_ciphertext, envelope_bytes)`.
///
/// ⭐ **Use [`vault_key_wrap_aad`] for a vault-key wrap.** The AAD is what stops
/// a valid envelope being re-filed under another vault, recipient, sender or
/// purpose.
///
/// # Errors
/// - [`HybridSealError::Hybrid`] if the KEM rejects an input.
#[allow(clippy::too_many_arguments)]
pub fn hybrid_auth_seal(
    sender_static_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_mlkem_encaps_key: &[u8; ML_KEM768_ENCAPS_KEY_LEN],
    ephemeral_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    mlkem_coin: &[u8; ML_KEM768_ENCAPS_COIN_LEN],
    aead_nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HybridSealed, HybridSealError> {
    let (eph_pub, mlkem_ct, combined) = hybrid_auth_encapsulate(
        sender_static_x25519_secret,
        recipient_x25519_pub,
        recipient_mlkem_encaps_key,
        ephemeral_x25519_secret,
        mlkem_coin,
    )?;
    let envelope = seal(&combined, aead_nonce, aad, plaintext);
    Ok((eph_pub, mlkem_ct, envelope.encode()))
}

/// AUTHENTICATED hybrid open: decrypt a record produced by [`hybrid_auth_seal`]
/// **and assert it came from `sender_static_x25519_pub`**.
///
/// `expected_aad` is checked BEFORE the AEAD is entered: the envelope carries
/// its AAD in the clear, and an envelope whose AAD is not byte-identical to what
/// the caller expected is rejected as an authentication failure rather than
/// opened. (The AEAD tag would reject it too — this just makes the refusal
/// explicit and keeps the caller from having to trust an attacker-supplied
/// context string.)
///
/// # Errors
/// - [`HybridSealError::Envelope`] if `envelope_bytes` is malformed.
/// - [`HybridSealError::Hybrid`] if the KEM rejects an input.
/// - [`HybridSealError::Aead`] on ANY authentication failure — a wrong
///   recipient, a wrong SENDER, a tampered ciphertext, or a mismatched AAD. No
///   plaintext is ever returned in that case.
pub fn hybrid_auth_open(
    recipient_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient_mlkem_decaps_key: &[u8; ML_KEM768_DECAPS_KEY_LEN],
    sender_static_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    sender_eph_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    mlkem_ct: &[u8; ML_KEM768_CIPHERTEXT_LEN],
    expected_aad: &[u8],
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, HybridSealError> {
    let envelope = Envelope::decode(envelope_bytes)?;
    if envelope.aad != expected_aad {
        return Err(HybridSealError::Aead(crate::AeadError::Authentication));
    }
    let combined = hybrid_auth_decapsulate(
        recipient_x25519_secret,
        recipient_mlkem_decaps_key,
        sender_static_x25519_pub,
        sender_eph_x25519_pub,
        mlkem_ct,
    )?;
    Ok(open(&combined, &envelope)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hybrid_open, hybrid_seal, ml_kem768_keygen, AeadError, KxError, ML_KEM768_KEYGEN_SEED_LEN,
    };

    fn arr32(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        a
    }

    fn arr64(seed: u8) -> [u8; ML_KEM768_KEYGEN_SEED_LEN] {
        let mut a = [0u8; ML_KEM768_KEYGEN_SEED_LEN];
        for (i, b) in a.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        a
    }

    struct Setup {
        s_secret: [u8; X25519_SECRET_KEY_LEN],
        s_pub: [u8; X25519_PUBLIC_KEY_LEN],
        r_secret: [u8; X25519_SECRET_KEY_LEN],
        r_pub: [u8; X25519_PUBLIC_KEY_LEN],
        ek: [u8; ML_KEM768_ENCAPS_KEY_LEN],
        dk: [u8; ML_KEM768_DECAPS_KEY_LEN],
        eph: [u8; X25519_SECRET_KEY_LEN],
        coin: [u8; ML_KEM768_ENCAPS_COIN_LEN],
        nonce: [u8; NONCE_LEN],
    }

    fn setup() -> Setup {
        let s_secret = arr32(0x01);
        let r_secret = arr32(0x11);
        let (ek, dk) = ml_kem768_keygen(&arr64(0x20));
        Setup {
            s_pub: x25519_public_key(&s_secret),
            s_secret,
            r_pub: x25519_public_key(&r_secret),
            r_secret,
            ek,
            dk,
            eph: arr32(0x30),
            coin: arr32(0x40),
            nonce: [0x5a; NONCE_LEN],
        }
    }

    fn hex(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write as _;
        let mut s = alloc::string::String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// THE CAPSTONE: the authenticated KEM agrees, and both sides derive the
    /// same 32-byte secret.
    #[test]
    fn authenticated_kem_round_trip_agrees() {
        let s = setup();
        let (eph_pub, ct, k_send) =
            hybrid_auth_encapsulate(&s.s_secret, &s.r_pub, &s.ek, &s.eph, &s.coin)
                .expect("encapsulate");
        let k_recv = hybrid_auth_decapsulate(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct)
            .expect("decapsulate");
        assert_eq!(k_send, k_recv);
    }

    /// ⭐ THE VULNERABILITY, AS A TEST. An attacker who holds ONLY the
    /// recipient's public key mints an anonymous `hybrid_seal` container — the
    /// exact bytes the shipped `sigil hybrid-seal` produced — and the
    /// authenticated open REFUSES it. Before this module, the anonymous form was
    /// what the vault-key path used, and this forgery opened cleanly.
    #[test]
    fn forgery_from_recipient_public_key_alone_is_refused() {
        let s = setup();
        let attacker_chosen_key = [0xABu8; 32];
        let aad = vault_key_wrap_aad("demo", "dev_victim", "dev_peer");

        // The attacker needs no secret of anyone's.
        let (eph_pub, ct, env) = hybrid_seal(
            &s.r_pub,
            &s.ek,
            &arr32(0x77),
            &arr32(0x88),
            &s.nonce,
            &aad,
            &attacker_chosen_key,
        )
        .expect("the anonymous form seals for anybody — that IS the bug");

        // The anonymous form still opens anonymously (unchanged behaviour)...
        assert_eq!(
            hybrid_open(&s.r_secret, &s.dk, &eph_pub, &ct, &env).expect("anonymous open"),
            attacker_chosen_key.to_vec()
        );

        // ...but it is NOT accepted as an authenticated record from the peer.
        assert!(matches!(
            hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &aad, &env),
            Err(HybridSealError::Aead(AeadError::Authentication))
        ));
    }

    /// A genuine record from the WRONG sender fails at the AEAD, never in a
    /// comparison and never by returning plaintext.
    #[test]
    fn wrong_sender_fails_with_aead_error() {
        let s = setup();
        let aad = vault_key_wrap_aad("demo", "dev_r", "dev_s");
        let (eph_pub, ct, env) = hybrid_auth_seal(
            &s.s_secret,
            &s.r_pub,
            &s.ek,
            &s.eph,
            &s.coin,
            &s.nonce,
            &aad,
            b"a 32-byte-ish vault key here!!!!",
        )
        .expect("seal");

        let other_sender_pub = x25519_public_key(&arr32(0x99));
        assert!(matches!(
            hybrid_auth_open(
                &s.r_secret,
                &s.dk,
                &other_sender_pub,
                &eph_pub,
                &ct,
                &aad,
                &env
            ),
            Err(HybridSealError::Aead(AeadError::Authentication))
        ));
        // The right sender still works.
        assert!(hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &aad, &env).is_ok());
    }

    /// ⭐⭐ THE AUTHENTICATION PROPERTY ITSELF, and the reason this test exists
    /// SEPARATELY from `wrong_sender_fails_with_aead_error`.
    ///
    /// That test passes even with the static-static DH removed, because the
    /// transcript alone binds the sender's public key — which stops an honest
    /// envelope being RE-LABELLED but stops no forgery, since the label is
    /// public. So: give a forger EVERYTHING public — the recipient's hybrid
    /// public key, the sender's static X25519 public key, a chosen ephemeral
    /// secret, a chosen ML-KEM coin, the exact transcript — and withhold only
    /// `ss_s`. It must still be unable to produce an acceptable record.
    ///
    /// ⚠️ Mutation-checked: zeroing `ss_s` in `combine_auth` makes this FAIL.
    #[test]
    fn public_material_alone_cannot_forge_an_authenticated_record() {
        let s = setup();
        let aad = vault_key_wrap_aad("demo", "dev_victim", "dev_peer");
        let payload = b"an attacker-chosen 32-byte key!!";

        // Everything the forger CAN compute from public material.
        let eph = arr32(0x71);
        let eph_pub = x25519_public_key(&eph);
        let ss_e = x25519_shared_secret(&eph, &s.r_pub).expect("ss_e");
        let (ct, ss_kem) = ml_kem768_encapsulate(&s.ek, &arr32(0x72)).expect("encaps");

        // Every guess at the one value it cannot compute.
        for guess in [[0u8; 32], arr32(0xEE), [0xFFu8; 32]] {
            let k = combine_auth(&ss_e, &ss_kem, &guess, &eph_pub, &ct, &s.s_pub, &s.r_pub);
            let env = seal(&k, &s.nonce, &aad, payload).encode();
            assert!(
                matches!(
                    hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &aad, &env),
                    Err(HybridSealError::Aead(AeadError::Authentication))
                ),
                "a forgery built from public material alone must be refused"
            );
        }

        // CONTROL: the identical construction with the REAL ss_s DOES open, so
        // the refusals above are not an artefact of some unrelated mismatch.
        let ss_s = x25519_shared_secret(&s.s_secret, &s.r_pub).expect("ss_s");
        let k = combine_auth(&ss_e, &ss_kem, &ss_s, &eph_pub, &ct, &s.s_pub, &s.r_pub);
        let env = seal(&k, &s.nonce, &aad, payload).encode();
        assert_eq!(
            hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &aad, &env)
                .expect("the genuine sender opens"),
            payload.to_vec()
        );
    }

    /// The wrong RECIPIENT fails too (the ordinary confidentiality property).
    #[test]
    fn wrong_recipient_fails_with_aead_error() {
        let s = setup();
        let aad = vault_key_wrap_aad("demo", "dev_r", "dev_s");
        let (eph_pub, ct, env) = hybrid_auth_seal(
            &s.s_secret,
            &s.r_pub,
            &s.ek,
            &s.eph,
            &s.coin,
            &s.nonce,
            &aad,
            b"payload",
        )
        .expect("seal");
        let other_secret = arr32(0xC0);
        let (_ek2, dk2) = ml_kem768_keygen(&arr64(0xD0));
        assert!(matches!(
            hybrid_auth_open(&other_secret, &dk2, &s.s_pub, &eph_pub, &ct, &aad, &env),
            Err(HybridSealError::Aead(AeadError::Authentication))
        ));
    }

    /// ⭐ CONTEXT BINDING. The SAME authenticated ciphertext presented under a
    /// different vault / recipient / sender / purpose is refused. Every one of
    /// these is a re-filing attack the ciphertext bytes cannot reveal.
    #[test]
    fn aad_context_binding_refuses_every_re_filing() {
        let s = setup();
        let aad = vault_key_wrap_aad("vault-a", "dev_recipient", "dev_sender");
        let (eph_pub, ct, env) = hybrid_auth_seal(
            &s.s_secret,
            &s.r_pub,
            &s.ek,
            &s.eph,
            &s.coin,
            &s.nonce,
            &aad,
            b"the vault key",
        )
        .expect("seal");

        for wrong in [
            vault_key_wrap_aad("vault-b", "dev_recipient", "dev_sender"),
            vault_key_wrap_aad("vault-a", "dev_other", "dev_sender"),
            vault_key_wrap_aad("vault-a", "dev_recipient", "dev_other"),
            b"sigil-hybrid-cli/1".to_vec(),
        ] {
            assert!(
                matches!(
                    hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &wrong, &env),
                    Err(HybridSealError::Aead(AeadError::Authentication))
                ),
                "a re-filed envelope must be refused"
            );
        }
        assert!(hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &aad, &env).is_ok());
    }

    /// The AAD is length-prefixed, so no two distinct triples collide.
    #[test]
    fn aad_fields_cannot_be_confused_by_concatenation() {
        assert_ne!(
            vault_key_wrap_aad("ab", "c", "d"),
            vault_key_wrap_aad("a", "bc", "d")
        );
        assert_ne!(
            vault_key_wrap_aad("a", "bc", "d"),
            vault_key_wrap_aad("a", "b", "cd")
        );
        // And it is domain-separated from the anonymous file tag.
        assert!(!vault_key_wrap_aad("v", "r", "s").starts_with(b"sigil-hybrid-cli/1"));
    }

    /// All three component secrets feed the combiner, and so does every
    /// transcript field.
    #[test]
    fn every_input_feeds_the_combined_secret() {
        let ss_e = arr32(0x01);
        let ss_kem: [u8; ML_KEM768_SHARED_SECRET_LEN] = arr32(0x02);
        let ss_s = arr32(0x03);
        let eph = arr32(0x04);
        let ct = [0x05u8; ML_KEM768_CIPHERTEXT_LEN];
        let sp = arr32(0x06);
        let rp = arr32(0x07);
        let base = combine_auth(&ss_e, &ss_kem, &ss_s, &eph, &ct, &sp, &rp);

        let mut v = ss_e;
        v[0] ^= 0xff;
        assert_ne!(base, combine_auth(&v, &ss_kem, &ss_s, &eph, &ct, &sp, &rp));
        let mut v = ss_kem;
        v[0] ^= 0xff;
        assert_ne!(base, combine_auth(&ss_e, &v, &ss_s, &eph, &ct, &sp, &rp));
        let mut v = ss_s;
        v[0] ^= 0xff;
        assert_ne!(base, combine_auth(&ss_e, &ss_kem, &v, &eph, &ct, &sp, &rp));
        let mut v = eph;
        v[0] ^= 0xff;
        assert_ne!(base, combine_auth(&ss_e, &ss_kem, &ss_s, &v, &ct, &sp, &rp));
        let mut v = ct;
        v[0] ^= 0xff;
        assert_ne!(
            base,
            combine_auth(&ss_e, &ss_kem, &ss_s, &eph, &v, &sp, &rp)
        );
        let mut v = sp;
        v[0] ^= 0xff;
        assert_ne!(
            base,
            combine_auth(&ss_e, &ss_kem, &ss_s, &eph, &ct, &v, &rp)
        );
        let mut v = rp;
        v[0] ^= 0xff;
        assert_ne!(
            base,
            combine_auth(&ss_e, &ss_kem, &ss_s, &eph, &ct, &sp, &v)
        );
    }

    /// The authenticated combiner is domain-separated from the anonymous one:
    /// the same material can never yield the same key through both.
    #[test]
    fn authenticated_and_anonymous_derivations_differ() {
        let s = setup();
        let (_e1, _c1, k_anon) =
            crate::hybrid_encapsulate(&s.r_pub, &s.ek, &s.eph, &s.coin).expect("anon");
        let (_e2, _c2, k_auth) =
            hybrid_auth_encapsulate(&s.s_secret, &s.r_pub, &s.ek, &s.eph, &s.coin).expect("auth");
        assert_ne!(k_anon, k_auth);
    }

    /// A non-contributory recipient key is rejected — for BOTH DH halves.
    #[test]
    fn non_contributory_recipient_is_rejected() {
        let s = setup();
        let zero = [0u8; X25519_PUBLIC_KEY_LEN];
        assert_eq!(
            hybrid_auth_encapsulate(&s.s_secret, &zero, &s.ek, &s.eph, &s.coin),
            Err(HybridError::Kx(KxError::NonContributory))
        );
        assert_eq!(
            hybrid_auth_decapsulate(&s.r_secret, &s.dk, &zero, &s.s_pub, &[0u8; 1088]),
            Err(HybridError::Kx(KxError::NonContributory))
        );
    }

    /// Determinism: this module draws no randomness.
    #[test]
    fn encapsulation_is_deterministic() {
        let s = setup();
        let a = hybrid_auth_encapsulate(&s.s_secret, &s.r_pub, &s.ek, &s.eph, &s.coin).unwrap();
        let b = hybrid_auth_encapsulate(&s.s_secret, &s.r_pub, &s.ek, &s.eph, &s.coin).unwrap();
        assert_eq!(a.2, b.2);
    }

    /// ⭐ GOLDEN KNOWN-ANSWER VECTOR over fixed seeds. Mirrored by the JS side;
    /// if either implementation drifts, a browser-wrapped vault key stops
    /// opening in the CLI and this test says so first.
    ///
    /// sender static secret = 0x01,0x02,…  recipient static secret = 0x11,0x12,…
    /// ML-KEM keygen seed = 0x20,0x21,…    ephemeral = 0x30,…  coin = 0x40,…
    #[test]
    fn golden_known_answer_vector() {
        let s = setup();
        let (eph_pub, ct, k) =
            hybrid_auth_encapsulate(&s.s_secret, &s.r_pub, &s.ek, &s.eph, &s.coin).unwrap();
        assert_eq!(
            hex(&k),
            "7d5cda4ae644faeb3fe30d492886bcd7961ed08c196b990c34bc9760be8c42b0",
            "AUTHENTICATED HYBRID KEM KAT drifted"
        );
        // Decapsulation reproduces it from the wire material alone.
        let k2 = hybrid_auth_decapsulate(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct).unwrap();
        assert_eq!(k, k2);

        // And the AAD layout, byte for byte.
        assert_eq!(
            hex(&vault_key_wrap_aad("demo", "dev_bob", "dev_alice")),
            "736967696c2d7661756c742d6b65792d777261702d76310a0000000464656d6f\
             000000076465765f626f62000000096465765f616c696365"
        );
    }

    /// Empty plaintext round-trips (a 0-byte payload is still authenticated).
    #[test]
    fn empty_plaintext_round_trips() {
        let s = setup();
        let aad = vault_key_wrap_aad("v", "r", "s");
        let (eph_pub, ct, env) = hybrid_auth_seal(
            &s.s_secret,
            &s.r_pub,
            &s.ek,
            &s.eph,
            &s.coin,
            &s.nonce,
            &aad,
            b"",
        )
        .unwrap();
        assert!(
            hybrid_auth_open(&s.r_secret, &s.dk, &s.s_pub, &eph_pub, &ct, &aad, &env)
                .unwrap()
                .is_empty()
        );
    }
}
