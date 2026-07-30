//! `sigil` — a pre-audit demonstration CLI that seals/opens one file with the
//! real-but-UNAUDITED libsigil `sigil-core` record API.
//!
//! STATUS: pre-audit. UNAUDITED cryptography. Demonstration of the libsigil
//! building block only. Do NOT use it to protect real secrets.
//!
//! Arg parsing is hand-rolled on `std::env` (no clap). See [`HELP`] for usage.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use sigil_cli::{
    base32_decode, cursor_key, decode_migration_uri, encode_migration_uri, enroll_device,
    entry_to_migration_otp, entry_to_otpauth_uri, fetch_hybrid_key, generate_hybrid_identity,
    generate_key, generate_vault_key, get_key_envelope, grant_vault_access, hybrid_open_container,
    hybrid_seal_to_container, keyring_get, keyring_put, list_devices, load_hybrid_public,
    load_hybrid_secret, load_identity, load_key_file, load_keyring, migration_otp_to_entry,
    new_totp_entry, open_container, open_vault, parse_otpauth_uri, publish_hybrid_key,
    pull_ops_auth, push_op_auth, put_key_envelope, read_cursor, revoke_device, save_hybrid_public,
    save_hybrid_secret, save_key, seal_to_container, seal_vault, share_vault_to_known_key,
    totp_algorithm_from_str, vault_key_fingerprint, wrap_vault_key, write_cursor, CliError,
    DeviceIdentity, ImportedOtp, RequestAuth, TotpEntry, TotpVault, PULL_STATE_FILE,
    TOTP_DEFAULT_DIGITS, TOTP_DEFAULT_PERIOD, VAULT_KEYRING_FILE,
};
// Phase 50 — key verification (safety numbers + pinning) and vault key rotation.
// All of it lives in the sigil-cli LIBRARY so the native desktop app gets the
// same semantics by calling the same functions (ADR 0037).
use sigil_cli::{
    hybrid_safety_number, list_key_envelopes, load_pins, pairwise_safety_number, repin_hybrid_key,
    rotate_vault_key, verify_recipient_for_wrap, HybridPublicIdentity, HYBRID_PIN_FILE,
};
// Phase 52 — the ACCOUNT model. Membership is what entitlement and vault
// ownership key off, so a second device inherits both. Every call rides the
// EXISTING contract v3 request path: no new signed message, no new header.
use sigil_cli::{create_account_invite, get_account, list_account_invites, revoke_account_invite};
// Phase 60 — the AUTHENTICATED vault-key envelope. A wrap now needs the SENDING
// device's hybrid SECRET (it authenticates the envelope), and an unwrap needs
// the sending device's PUBLIC key through the `VerifiedSender` gate.
use sigil_cli::{accept_vault_key, SenderIdentity, VaultKeyWrapContext};
use sigil_core::Argon2Params;
// Phase 54 — THE RECOVERY KIT. All of it lives in the sigil-cli LIBRARY so the
// desktop app gets the same semantics by calling the same functions (ADR 0037),
// and so the code that talks to the server has exactly ONE implementation.
use sigil_cli::{
    derive_recovery_identity, recovery_check, recovery_cover, recovery_generate, recovery_restore,
    recovery_revoke, recovery_verify,
};
use sigil_core::format_recovery_kit;

/// Environment variable the password is read from. Empty/unset is a hard error.
const PASSWORD_ENV: &str = "SIGIL_PASSWORD";

/// Environment variable for the dev sigild base URL (overridden by --server).
const SERVER_ENV: &str = "SIGIL_SERVER";

/// Default dev sigild base URL when neither --server nor SIGIL_SERVER is set.
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// Environment variable giving the path to the device key / identity file used to
/// SIGN op-log requests (overridden by `--key`).
const DEVICE_KEY_ENV: &str = "SIGIL_DEVICE_KEY";

/// Environment variable that supplies (or overrides) the enrolled DEVICE ID.
/// Setting it forces contract v3 signing even for an identity file that has no
/// `device_id` yet. Unset/empty means "use whatever the identity file says".
const DEVICE_ID_ENV: &str = "SIGIL_DEVICE_ID";

/// Environment variable for the operator ADMIN token used by
/// `sigil device list` / `sigil device revoke` (overridden by `--admin-token`).
/// It is a BEARER SECRET and is never printed.
const ADMIN_TOKEN_ENV: &str = "SIGIL_ADMIN_TOKEN";

/// Environment variable for the single-use device ENROLLMENT token (overridden by
/// `--token`). It is a BEARER SECRET and is never printed.
const ENROLL_TOKEN_ENV: &str = "SIGIL_ENROLL_TOKEN";

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
sigil — pre-audit demonstration CLI over the libsigil core

  !!  WARNING — PRE-AUDIT, UNAUDITED CRYPTOGRAPHY  !!
  This tool uses the REAL but UNAUDITED sigil-core building block
  (Argon2id + XChaCha20-Poly1305). It is a DEMONSTRATION of the libsigil
  core only. It has NOT been audited and makes NO security guarantees.
  Do NOT use it to protect real secrets.

USAGE:
  sigil seal --in <file> --out <file>    Seal <in> into a password-encrypted container at <out>
  sigil open --in <file> --out <file>    Open a password-encrypted container <in> into <out>
  sigil totp add <label> --secret <BASE32> [--issuer X] [--algorithm sha1|sha256|sha512]
                         [--digits 6] [--period 30] [--vault <file>]
                                         Add a TOTP secret to the encrypted vault
  sigil totp add --uri \"otpauth://totp/...\" [--vault <file>]
                                         Import a TOTP secret from an otpauth:// URI
  sigil totp list [--vault <file>]       List vault entries (label/issuer/algorithm/digits/period)
  sigil totp code <label> [--vault <file>] [--at <unix>]
                                         Print the CURRENT code for <label> (system clock, or --at)
  sigil totp remove <label> [--vault <file>]
                                         Delete an entry from the vault
  sigil totp import <ARG> [--vault <file>]
                                         Import 2FA secrets: <ARG> is an
                                         otpauth-migration:// URI (Google Authenticator bulk
                                         export), an otpauth:// URI, or a file with one URI per line
  sigil totp export [<label>] [--vault <file>] [--migration] [--skip-unsupported] [--out <file>]
                                         Export entries as otpauth:// URIs (or ONE
                                         otpauth-migration:// URI with --migration). PRINTS SECRETS.
                                         --migration REFUSES entries the Google format cannot
                                         express (e.g. a 60 s period); --skip-unsupported exports
                                         the rest and names each one it left out.
  sigil keygen --out <file>              Generate a DEV device key (0600) and print its public key
  sigil device enroll --token <t> [--label <name>] [--key <file>] [--server <url>] [--reuse-key]
                                         Enroll this device with sigild; writes the identity (0600)
  sigil device list --admin-token <t> [--server <url>]
                                         List enrolled devices (operator admin token)
  sigil device revoke <deviceID> [--admin-token <t>] [--key <file>] [--server <url>]
                                         Revoke a device (self, v3-signed, or operator admin token)
  sigil device grant <deviceID> --vault <id> --permission read|write [--key <file>] [--server <url>]
                                         Grant another device access to YOUR vault (owner only)
  sigil device hybrid-publish [--key <file>] [--hybrid-key <file>] [--regenerate] [--server <url>]
                                         Generate (if absent) this device's HYBRID identity and
                                         publish only its PUBLIC half, so others can share to it
  sigil vault rekey --vault <id> [--file <vaultfile>] [--publish] [--keyring <f>] [--key <f>]
                                         Re-seal a PASSWORD vault under a fresh random VAULT KEY
                                         (--publish also wraps it to THIS device and uploads it)
  sigil vault share --vault <id> --to <deviceID> [--permission read|write] [--keyring <f>]
                    [--safety-number \"<digits>\"] [--key <f>] [--pins <f>] [--server <url>]
                    [--envelope-out <f>]
                                         Wrap the vault key to that device's hybrid public key,
                                         upload the opaque envelope, and grant it access. Prints
                                         the safety number BEFORE wrapping. REFUSES if that
                                         device's key CHANGED since it was pinned, if a supplied
                                         --safety-number does not match, or if the recipient is a
                                         RECOVERY KIT this client has never pinned and no
                                         --safety-number was given
  sigil vault rotate --vault <id> --to <deviceID> [--to <deviceID> ...] [--drop <deviceID> ...]
                     [--drop-all-others] [--safety-number \"<deviceID>=<digits>\" ...]
                     [--file <vaultfile>] [--keyring <f>] [--pins <f>] [--key <f>] [--server <url>]
                                         Draw a FRESH vault key, re-seal the vault under it, re-wrap
                                         it to EXACTLY those devices, and delete the envelope of
                                         every device named by --drop. Every recipient goes through
                                         the SAME wrap gate as share. REFUSES if some device holds
                                         an envelope and is in neither list (it would lose access
                                         silently — including your RECOVERY KIT).
                                         Protects FUTURE content only
  sigil recovery generate [--vault <id> ...] [--keyring <f>] [--pins <f>] [--key <f>]
                          [--server <url>] [--out <sheet>]
                                         Print a RECOVERY KIT: 56 characters of paper that are a
                                         full member device. Verifies itself end to end BEFORE
                                         printing. ⚠️ whoever holds the paper holds the account
  sigil recovery verify [--code \"<56 chars>\" | --code-stdin]
                                         Check a printed code OFFLINE (checksum only, no network).
                                         With no --code it PROMPTS (echo off) or reads one line
                                         from stdin. ⚠️ --code puts the SECRET in argv (readable
                                         via /proc on Linux) and in your shell history
  sigil recovery check --device-id <kitID> [--keyring <f>] [--key <f>] [--server <url>]
                                         Which of THIS device's vaults the kit still covers
  sigil recovery cover --device-id <kitID> --vault <id> [--safety-number \"<digits>\"]
                       [--keyring <f>] [--pins <f>] [--key <f>] [--server <url>]
                                         Cover one more vault. From a device that did NOT generate
                                         the kit, --safety-number is REQUIRED and must match
  sigil recovery restore --device-id <kitID> [--code \"<56 chars>\" | --code-stdin]
                         [--out-dir <dir>] [--adopt] [--server <url>]
                                         Recover every covered vault on a machine with NO local
                                         state. The code is PROMPTED for (echo off) or read from
                                         stdin; --code still works for scripts but exposes the
                                         SECRET in argv and shell history. --adopt ALSO persists
                                         the kit's secrets here, making this machine a second
                                         copy of the paper
  sigil recovery revoke --device-id <kitID> [--vault <id> ...] [--keyring <f>] [--key <f>]
                        [--server <url>]
                                         Revoke the kit and take back its envelopes (then rotate)
  sigil device safety-number [<deviceID>] [--pair <deviceID>] [--key <f>] [--server <url>]
                                         Print the human-comparable SAFETY NUMBER of a hybrid public
                                         key — read it aloud over a TRUSTED channel to verify a key
                                         BEFORE the first share (--pair is order-independent)
  sigil device pins [--pins <file>]      List the hybrid public keys this client TRUSTS
  sigil device repin <deviceID> --yes [--safety-number <digits>] [--pins <f>] [--server <url>]
                                         DANGEROUS. Accept a CHANGED hybrid key for a device. Only
                                         after verifying the NEW safety number out of band — a
                                         changed key may be a KEY-SUBSTITUTION ATTACK
  sigil vault accept --vault <id> [--from <deviceID>] [--safety-number <digits>] [--replace]
                     [--keyring <f>] [--pins <f>] [--key <f>] [--hybrid-key <f>]
                     [--server <url>] [--envelope-out <f>]
                                         Collect the envelope addressed to THIS device, verify it
                                         came from the SENDING device (--from, else this device's
                                         own envelope index), unwrap it, prove the key opens the
                                         vault's newest op, and store it locally (0600).
                                         --replace is required to overwrite a DIFFERENT key
  sigil vault list [--keyring <file>]    List vaults this device holds a key for (fingerprints only)
  sigil hybrid-keygen --out <file>       Generate a hybrid identity: secret <file> (0600) + shareable <file>.pub
  sigil hybrid-seal --recipient-pub <pubfile> --in <file> --out <file>
                                         Encrypt <in> TO a recipient's hybrid public identity (no password)
  sigil hybrid-open --key <file> --in <file> --out <file>
                                         Decrypt a hybrid container <in> with your secret identity <file>
  sigil push --vault <id> --in <file> [--server <url>] [--key <file>]
                                         Upload an opaque container to the dev op-log
  sigil pull --vault <id> --out-dir <dir> [--since <N>] [--server <url>] [--key <file>]
                                         Download NEW opaque containers from the dev op-log
  sigil --help                           Show this help
  sigil --version                        Show the version

PASSWORD (seal/open only):
  The password is read from the SIGIL_PASSWORD environment variable. If it is
  unset or empty, the command fails immediately (it never prompts and never
  hangs). push/pull move OPAQUE sealed containers and do NOT need a password.
  Example:

    SIGIL_PASSWORD='correct horse battery staple' sigil seal --in secret.txt --out secret.sigil
    SIGIL_PASSWORD='correct horse battery staple' sigil open --in secret.sigil --out secret.txt

TOTP VAULT (totp add/list/code/remove) — the authenticator feature:
  A TOTP vault is an encrypted list of 2FA secrets, sealed AT REST with the SAME
  password container as seal/open (SIGIL_PASSWORD provides the password). Codes
  are generated with the real RFC 4226/6238 primitive in sigil-core.

  The vault path is --vault <file>, else the default $HOME/.sigil/totp-vault.sigil
  (the .sigil dir is created 0700; the vault file is written 0600). Example:

    export SIGIL_PASSWORD='correct horse battery staple'
    sigil totp add work --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --issuer Acme --digits 6
    sigil totp add --uri \"otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQ&period=30\"
    sigil totp list
    sigil totp code work
    sigil totp remove work

  !! PRE-AUDIT / UNAUDITED / DEV-ONLY !! The OTP math is standard and RFC-vector
  checked, but the build is unaudited. Do NOT store real 2FA secrets yet.

TOTP IMPORT / EXPORT (totp import/export) — migrate 2FA in and out:
  import ingests either a Google Authenticator bulk-export migration URI
  (otpauth-migration://offline?data=<BASE64>, hand-rolled protobuf decode), a
  single otpauth:// URI, or a text file with one such URI per line. HOTP entries
  and duplicate labels are SKIPPED; the vault is re-sealed with any new TOTP
  entries. export is the inverse: it prints each entry as an otpauth:// URI, or —
  with --migration — one otpauth-migration:// URI holding them all.

    sigil totp import \"otpauth-migration://offline?data=CjUK...AB\"
    sigil totp import ./exported-uris.txt
    sigil totp export                     # every entry as otpauth:// URIs
    sigil totp export work                # just the 'work' entry
    sigil totp export --migration         # ONE migration URI for all entries
    sigil totp export --migration --out backup.txt   # write to a 0600 file
    sigil totp export --migration --skip-unsupported # skip what the format cannot express

  !! export prints your SECRETS IN THE CLEAR (that is what a 2FA export is). It
  warns on stderr; treat the output like a password. !!

HYBRID PUBLIC-KEY ENCRYPTION (hybrid-keygen / hybrid-seal / hybrid-open) — NO password:
  This is the PUBLIC-KEY path, distinct from the password-based seal/open above.
  You encrypt a file TO another device's HYBRID IDENTITY (an X25519 public key +
  an ML-KEM-768 encapsulation key); only the holder of the matching SECRET
  identity can decrypt it. There is NO shared password.

  !! PRE-AUDIT / UNAUDITED / DEV-ONLY !! The construction is a CUSTOM
  KEM-then-AEAD composition (X25519 + ML-KEM-768 -> shared secret ->
  XChaCha20-Poly1305). It is NOT RFC 9180 HPKE and NOT a standardised scheme; the
  SYSTEM is NOT post-quantum secure. It has NOT been audited and makes NO security
  guarantees. Do NOT use it to protect real secrets.

  Flow (device B receives; device A sends):

    # Device B: generate a hybrid identity. Writes the SECRET id to b.key (0600)
    # and the shareable PUBLIC id to b.key.pub. Share ONLY b.key.pub with senders.
    sigil hybrid-keygen --out b.key

    # Device A: encrypt a file TO B's public identity (no password).
    sigil hybrid-seal --recipient-pub b.key.pub --in secret.txt --out msg.hyb

    # Device B: decrypt with its secret identity.
    sigil hybrid-open --key b.key --in msg.hyb --out secret.txt

SYNC (push/pull) — !! DEV / LOCALHOST / PLAIN HTTP ONLY !!
  push/pull talk PLAIN, UNENCRYPTED HTTP to a sigild DEV op-log that is itself
  dev-gated (sigild must run with SIGILD_ENABLE_DEV_OPS=1) and UNAUTHENTICATED.
  There is NO TLS and NO auth on this path. They only shuttle already-sealed,
  OPAQUE container bytes — they never see your password or plaintext. This is a
  local development demo, NOT a production sync service. Do NOT point it at a
  remote host or use it for real secrets.

  The server base URL is chosen as: --server flag, else the SIGIL_SERVER
  environment variable, else the default http://127.0.0.1:8080. Example:

    sigil push --vault demo --in secret.sigil
    SIGIL_SERVER=http://127.0.0.1:8080 sigil pull --vault demo --out-dir ./inbox

DEVICE-KEY SIGNING (push/pull) — DEV-ONLY, single device key:
  If the dev sigild is configured with SIGILD_OPLOG_PUBKEY (standard-base64 of a
  32-byte Ed25519 public key), it REQUIRES every op-log request to be SIGNED by
  the matching device key — unsigned or invalid requests get HTTP 401. Otherwise
  signing is OFF and the op-log stays unauthenticated (unchanged).

  Generate a device key once, then point sigild at its public key:

    sigil keygen --out device.key       # writes device.key (mode 0600), prints the public key
    # -> device public key (set sigild SIGILD_OPLOG_PUBKEY to this): <base64>

  Then pass the key on push/pull with --key <file>, or set SIGIL_DEVICE_KEY to
  the key-file path (--key takes precedence over SIGIL_DEVICE_KEY):

    sigil push --vault demo --in secret.sigil --key device.key
    SIGIL_DEVICE_KEY=device.key sigil pull --vault demo --out-dir ./inbox

  HONEST SCOPE: this is a SINGLE device key, DEV-ONLY, over plain HTTP. Requests
  are signed under the CONTRACT v2 message, which binds the method, path, query, a
  unix-seconds timestamp, a FRESH per-request nonce, and the body; sigild rejects
  timestamps skewed more than 300s AND, when it tracks seen nonces, rejects a
  replayed nonce within that window — so a captured request is replay-resistant.
  That replay cache is per-process/in-memory on the server (a multi-instance deploy
  would need a shared store). The signing primitive (Ed25519) is REAL but UNAUDITED.

MULTI-DEVICE AUTH (sigil device ...) — CONTRACT v3, DEV-ONLY:
  A sigild started with SIGILD_DEVICE_AUTH=1 (plus SIGILD_ENABLE_DEV_OPS=1 and
  SIGILD_ENROLL_TOKENS=<...>) runs a real device registry instead of the single
  v2 key: each device ENROLLS, gets a device ID, signs every request under the
  CONTRACT v3 message (which additionally binds that device ID and is sent with
  X-Sigil-Device), and is authorized PER VAULT. The first device to WRITE an
  unclaimed vault becomes its owner; any other device gets 403 until granted.

  CONTRACT SELECTION is automatic and additive:
    no --key/SIGIL_DEVICE_KEY        -> unsigned      (unchanged legacy behaviour)
    identity file WITHOUT device_id  -> contract v2   (unchanged legacy behaviour)
    identity file WITH device_id     -> contract v3   (after `device enroll`)
  Setting SIGIL_DEVICE_ID=<id> forces v3 with that ID even for an older key file.

  The identity file is the SAME 0600 JSON as `sigil keygen` writes, EXTENDED with
  an optional \"device_id\" that `device enroll` fills in — an old key file still
  works untouched. The default identity path is $HOME/.sigil/device.key. The seed
  is never printed; enrollment/admin tokens are never printed or logged.

    # operator: sigild with SIGILD_DEVICE_AUTH=1 SIGILD_ENROLL_TOKENS=tokA,tokB
    sigil device enroll --token tokA --label laptop --key ./a.key
    # -> enrolled device dev_XXXX (identity written to ./a.key, mode 0600)

    sigil push --vault demo --in secret.sigil --key ./a.key   # A claims 'demo'
    sigil pull --vault demo --out-dir ./inbox --key ./a.key

    # a second device is 403 on A's vault until A grants it:
    sigil device enroll --token tokB --label phone --key ./b.key
    sigil device grant <B_ID> --vault demo --permission read --key ./a.key
    sigil pull --vault demo --out-dir ./inbox-b --key ./b.key

    # revoke: the device itself (v3-signed) or the operator admin token
    sigil device revoke <B_ID> --key ./b.key
    sigil device revoke <B_ID> --admin-token \"$SIGIL_ADMIN_TOKEN\"
    sigil device list --admin-token \"$SIGIL_ADMIN_TOKEN\"

  Enrollment tokens are SINGLE-USE (a failed attempt burns one) and are bound into
  the signed enrollment challenge only as their SHA-256 digest. Enrollment proves
  possession of the device private key. HONEST SCOPE: dev/localhost/plain HTTP,
  UNAUDITED; no account model, no key rotation, no recovery.

ACCOUNTS (sigil account ...) — WHO OWNS THE VAULT AND WHO IS ENTITLED, DEV-ONLY:
  An ACCOUNT is a group of your own devices. It is what a subscription and a
  vault's ownership belong to — so paying on one device entitles the others, and
  revoking one device does not orphan its vaults. An account is AUTH METADATA
  ONLY: no email, no password, no session. The server never sees a vault key.

  A second device joins with a SINGLE-USE INVITE minted by a device already in
  the account. There is no separate \"join\" command — an invite IS an enrollment
  token, so the enrollment path is completely unchanged:

    sigil account status                          # which account am I in?
    sigil account invite                          # prints ONE invite secret
    sigil account invite --ttl 300                # ...shorter-lived
    sigil account invite --pin-key \"<b64 pubkey>\"  # ...redeemable by ONE key only
    sigil account invites                         # open invites (metadata only)
    sigil account revoke-invite <inviteID>        # kill one before it is used

    # on the joining device — the ORDINARY enroll command:
    sigil device enroll --token <the invite> --label phone --key ./b.key

  No request ever names an account: the server reads yours off the signature it
  just verified, which is why there is no --account flag anywhere.

  !! HONEST SCOPE: dev-gated, plain HTTP, UNAUDITED.
  * NO RECOVERY UNLESS YOU PRINTED A KIT FIRST. An account is reachable only
    through a member device's private key. Lose or revoke every device and the
    account, its vaults and its subscription are permanently unreachable — by
    you and by us — UNLESS `sigil recovery generate` was run in advance and the
    sheet survived. A kit CANNOT be made after the loss, and it only opens the
    vaults it was told to cover (`sigil recovery cover`). Keep two devices
    enrolled AND print a kit.
  * Joining grants AUTHORIZATION, never DECRYPTION. A new device reads nothing
    until a member wraps the vault key to it (`sigil vault share`).
  * Membership is FLAT: any member may invite, revoke every other member, and
    run checkout. Revoking a compromised device does NOT revoke the devices it
    invited — the audit log names the inviter, but nothing prevents it.
  * An UNPINNED invite is a bearer secret over plain HTTP for its whole life.
  * Membership is immutable: no transfer, no merge, no account deletion. A
    device enrolled into the wrong account can only be revoked and re-enrolled.
  * Devices enrolled before the account model each got their OWN account, so an
    existing phone + laptop are TWO accounts with TWO subscriptions. !!

DEVICE-TO-DEVICE VAULT SHARING (sigil vault ...) — DEV-ONLY, UNAUDITED:
  This is how a SECOND device gets into the SAME vault. The key hierarchy:

    human password  -> seals your PERSONAL vault. It is NEVER shared, NEVER
                       wrapped, and never leaves your machine.
    vault key       -> 32 random bytes that seal a SHARED vault (the same
                       SIGILcli container: it takes arbitrary password BYTES, so
                       a random key needs no format change).
    wrapped key     -> the vault key encrypted TO one device's HYBRID public key
                       (X25519 + ML-KEM-768). sigild RELAYS that opaque envelope
                       and cannot read it: it has no decapsulation key, sees only
                       ciphertext, device ids, and a vault id.

  Flow (device A owns the vault; device B joins). Both devices must already be
  enrolled (`sigil device enroll`), and sigild must run with device auth on:

    # Both devices, once: create + publish a hybrid identity. The SECRET half is
    # written 0600 next to the device identity and is never uploaded.
    sigil device hybrid-publish --key ./a.key
    sigil device hybrid-publish --key ./b.key

    # A: turn its password vault into a SHARED vault (fresh random vault key),
    # wrap that key to itself, and push the sealed vault to the op-log.
    SIGIL_PASSWORD=... sigil vault rekey --vault demo --file ./a-vault.sigil --publish --key ./a.key
    sigil push --vault demo --in ./a-vault.sigil --key ./a.key

    # BEFORE the first share: verify B's key out of band. Pinning cannot protect
    # first contact — only a human comparing these digits can.
    sigil device safety-number <B_ID> --key ./a.key     # A reads the digits...
    sigil device safety-number --key ./b.key            # ...B reads its own; they must match

    # A: share to B — fetches B's hybrid PUBLIC key, PINS it on first sight (and
    # REFUSES loudly if it ever changes), wraps the vault key to it with fresh
    # ephemeral entropy, uploads the envelope, and grants B access.
    sigil vault share --vault demo --to <B_ID> --permission read --key ./a.key

    # B: accept — collects the envelope addressed to B, unwraps it with B's
    # hybrid SECRET identity, stores the vault key 0600.
    sigil vault accept --vault demo --key ./b.key
    sigil pull --vault demo --out-dir ./inbox --key ./b.key
    sigil totp code work --vault ./inbox/demo/op-1.sigil --vault-id demo

    # Later: B is lost/revoked. Revocation alone does not protect content sealed
    # under the key B already has — ROTATE, naming everyone who KEEPS access.
    sigil device revoke <B_ID> --admin-token ... --server ...
    sigil vault rotate --vault demo --to <A_ID> --to <C_ID> --file ./a-vault.sigil --key ./a.key
    sigil push --vault demo --in ./a-vault.sigil --key ./a.key
    # Everything added AFTER this is unreadable to B. Anything B already read,
    # B still has — rotation protects FUTURE content only.

  --vault-id <id> is what tells the totp commands to open a file with the VAULT
  KEY for <id> instead of SIGIL_PASSWORD. Without it, nothing changes: existing
  password vaults keep working exactly as before.

  The vault key is NEVER printed — commands show only a SHA-256 fingerprint, so
  two devices can confirm they hold the same key without revealing it. The local
  keyring is $HOME/.sigil/vault-keys.json (mode 0600, never synced).

  !! HONEST SCOPE: dev/localhost/plain HTTP, UNAUDITED. The hybrid construction
  is a CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE; the SYSTEM is NOT post-quantum
  secure. Revoking a device stops FUTURE access — it cannot make a device forget
  a vault key it already accepted (that needs a re-key and a re-share). No key
  rotation schedule, no recovery. Do NOT store real 2FA secrets. !!

INCREMENTAL PULL (pull only):
  Pulled ops are written to <out-dir>/<vault>/op-<seq>.sigil — a PER-VAULT subdir,
  so multiple vaults can safely share one --out-dir without their op-<seq>.sigil
  filenames colliding. The shared cursor state file is <out-dir>/.sigil-pull-state.json
  (at the out-dir root, NOT inside the per-vault subdir).

  pull is INCREMENTAL. It remembers the last pulled op sequence per (server,
  vault) in that LOCAL state file. The first pull for a (server, vault) gets
  every op; later pulls fetch only ops newer than the saved cursor. The cursor
  is MONOTONIC: it only ever advances.

    --since <N> overrides the start for ONE pull (fetch ops with seq > N), e.g.
    --since 0 re-fetches everything. It does NOT rewind the saved cursor: after
    an explicit --since, the cursor still only moves forward.

  The state file is LOCAL, per-device state — it is NOT secret and is NOT synced
  (it holds only server URLs, vault ids, and integers, never crypto material).
  Delete it to reset the cursor and re-pull from scratch.

ON-DISK CONTAINER FORMAT (all integers little-endian):
  Password container (seal/open):
    magic[8]=\"SIGILcli\" | version:u8=1 | m_cost:u32 | t_cost:u32 | p_cost:u32 |
    salt_len:u8 | salt[salt_len] | envelope[..]
    The Argon2id salt and params are stored in the header (the AEAD nonce travels
    inside the envelope). The salt/params header is unprotected metadata; tampering
    with it makes the record fail to open.

  Hybrid container (hybrid-seal/hybrid-open):
    magic[8]=\"SIGILhyb\" | version:u8=1 | eph_x25519_pub[32] | mlkem_ct[1088] |
    envelope[..]
    The sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext precede
    the seal envelope; the recipient re-derives the shared secret from them plus its
    secret identity. Tampering with any of it makes the record fail to open.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("sigil: error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Parsed `--in` / `--out` pair for the seal/open subcommands.
struct IoArgs {
    input: String,
    output: String,
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        // No subcommand: print help to stderr and fail (so scripts notice).
        return Err(format!("no command given\n\n{HELP}"));
    };

    match command.as_str() {
        "--help" | "-h" | "help" => {
            print!("{HELP}");
            Ok(())
        }
        "--version" | "-V" => {
            println!("sigil {VERSION} (pre-audit, unaudited)");
            Ok(())
        }
        "seal" => {
            let io = parse_io(args)?;
            cmd_seal(&io)
        }
        "open" => {
            let io = parse_io(args)?;
            cmd_open(&io)
        }
        "keygen" => {
            let out = parse_keygen(args)?;
            cmd_keygen(&out)
        }
        "hybrid-keygen" => {
            let out = parse_keygen(args)?;
            cmd_hybrid_keygen(&out)
        }
        "hybrid-seal" => {
            let a = parse_hybrid_seal(args)?;
            cmd_hybrid_seal(&a)
        }
        "hybrid-open" => {
            let a = parse_hybrid_open(args)?;
            cmd_hybrid_open(&a)
        }
        "totp" => cmd_totp(args),
        "device" => cmd_device(args),
        "account" => cmd_account(args),
        "vault" => cmd_vault(args),
        "recovery" => cmd_recovery(args),
        "push" => {
            let p = parse_push(args)?;
            cmd_push(&p)
        }
        "pull" => {
            let p = parse_pull(args)?;
            cmd_pull(&p)
        }
        other => Err(format!(
            "unknown command {other:?}; try `sigil --help`\n\n{HELP}"
        )),
    }
}

/// Resolve the dev sigild base URL: explicit `--server`, else `SIGIL_SERVER`,
/// else the localhost default.
fn resolve_server(flag: Option<String>) -> String {
    flag.or_else(|| std::env::var(SERVER_ENV).ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

/// Parsed args for `sigil push`.
struct PushArgs {
    vault: String,
    input: String,
    server: String,
    /// Path to the device key file to SIGN the request with: `--key`, else the
    /// `SIGIL_DEVICE_KEY` env var, else `None` (send unsigned).
    key: Option<String>,
}

/// Parsed args for `sigil pull`.
struct PullArgs {
    vault: String,
    /// The start seq override. `Some(n)` means `--since n` was given explicitly
    /// (a one-off re-fetch start); `None` means use the saved incremental cursor.
    since: Option<u64>,
    out_dir: String,
    server: String,
    /// Path to the device key file to SIGN the request with: `--key`, else the
    /// `SIGIL_DEVICE_KEY` env var, else `None` (send unsigned).
    key: Option<String>,
}

/// Resolve the device key-file path: explicit `--key` wins, else the
/// `SIGIL_DEVICE_KEY` env var (empty treated as unset), else `None` (unsigned).
fn resolve_key(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var(DEVICE_KEY_ENV).ok())
        .filter(|s| !s.is_empty())
}

fn parse_push(mut args: impl Iterator<Item = String>) -> Result<PushArgs, String> {
    let mut vault: Option<String> = None;
    let mut input: Option<String> = None;
    let mut server: Option<String> = None;
    let mut key: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut vault, &mut args, "--vault")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--server" => set_once(&mut server, &mut args, "--server")?,
            "--key" => set_once(&mut key, &mut args, "--key")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(PushArgs {
        vault: vault.ok_or_else(|| "missing required --vault <id>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        server: resolve_server(server),
        key: resolve_key(key),
    })
}

fn parse_pull(mut args: impl Iterator<Item = String>) -> Result<PullArgs, String> {
    let mut vault: Option<String> = None;
    let mut since_raw: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut server: Option<String> = None;
    let mut key: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut vault, &mut args, "--vault")?,
            "--since" => set_once(&mut since_raw, &mut args, "--since")?,
            "--out-dir" => set_once(&mut out_dir, &mut args, "--out-dir")?,
            "--server" => set_once(&mut server, &mut args, "--server")?,
            "--key" => set_once(&mut key, &mut args, "--key")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    // Parse `--since` only when it was actually provided; `None` lets cmd_pull
    // fall back to the saved incremental cursor instead of forcing a start.
    let since = match since_raw {
        Some(raw) => Some(
            raw.parse::<u64>()
                .map_err(|_| format!("--since must be a non-negative integer, got {raw:?}"))?,
        ),
        None => None,
    };

    Ok(PullArgs {
        vault: vault.ok_or_else(|| "missing required --vault <id>".to_string())?,
        since,
        out_dir: out_dir.ok_or_else(|| "missing required --out-dir <dir>".to_string())?,
        server: resolve_server(server),
        key: resolve_key(key),
    })
}

/// Parse `sigil keygen --out <file>` from the remaining args. Also used by
/// `hybrid-keygen`, which takes the same single `--out <file>` argument.
fn parse_keygen(mut args: impl Iterator<Item = String>) -> Result<String, String> {
    let mut out: Option<String> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--out" => set_once(&mut out, &mut args, "--out")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    out.ok_or_else(|| "missing required --out <file>".to_string())
}

/// Parsed args for `sigil hybrid-seal`: encrypt `--in` TO the recipient public
/// identity at `--recipient-pub`, writing the hybrid container to `--out`.
struct HybridSealArgs {
    recipient_pub: String,
    input: String,
    output: String,
}

/// Parsed args for `sigil hybrid-open`: decrypt the hybrid container at `--in`
/// with the secret identity at `--key`, writing the plaintext to `--out`.
struct HybridOpenArgs {
    key: String,
    input: String,
    output: String,
}

fn parse_hybrid_seal(mut args: impl Iterator<Item = String>) -> Result<HybridSealArgs, String> {
    let mut recipient_pub: Option<String> = None;
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--recipient-pub" => set_once(&mut recipient_pub, &mut args, "--recipient-pub")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--out" => set_once(&mut output, &mut args, "--out")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(HybridSealArgs {
        recipient_pub: recipient_pub
            .ok_or_else(|| "missing required --recipient-pub <file>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        output: output.ok_or_else(|| "missing required --out <file>".to_string())?,
    })
}

fn parse_hybrid_open(mut args: impl Iterator<Item = String>) -> Result<HybridOpenArgs, String> {
    let mut key: Option<String> = None;
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--key" => set_once(&mut key, &mut args, "--key")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--out" => set_once(&mut output, &mut args, "--out")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(HybridOpenArgs {
        key: key.ok_or_else(|| "missing required --key <file>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        output: output.ok_or_else(|| "missing required --out <file>".to_string())?,
    })
}

/// Store a value into `slot` exactly once, erroring on a missing value or a
/// repeated flag.
fn set_once(
    slot: &mut Option<String>,
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<(), String> {
    let v = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    if slot.replace(v).is_some() {
        return Err(format!("{flag} given more than once"));
    }
    Ok(())
}

/// Parse exactly `--in <file> --out <file>` (order-independent) from the
/// remaining args.
fn parse_io(mut args: impl Iterator<Item = String>) -> Result<IoArgs, String> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--in" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--in requires a file path".to_string())?;
                if input.replace(v).is_some() {
                    return Err("--in given more than once".to_string());
                }
            }
            "--out" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--out requires a file path".to_string())?;
                if output.replace(v).is_some() {
                    return Err("--out given more than once".to_string());
                }
            }
            other => {
                return Err(format!("unexpected argument {other:?}; try `sigil --help`"));
            }
        }
    }

    let input = input.ok_or_else(|| "missing required --in <file>".to_string())?;
    let output = output.ok_or_else(|| "missing required --out <file>".to_string())?;
    Ok(IoArgs { input, output })
}

/// Read the password from the environment, erroring if unset or empty.
fn password_from_env() -> Result<Vec<u8>, String> {
    match std::env::var_os(PASSWORD_ENV) {
        Some(v) if !v.is_empty() => Ok(v.into_encoded_bytes()),
        _ => Err(format!(
            "{PASSWORD_ENV} is unset or empty; set it to the password, e.g. \
             `{PASSWORD_ENV}=... sigil seal --in f --out f.sigil`"
        )),
    }
}

fn cmd_seal(io: &IoArgs) -> Result<(), String> {
    let password = password_from_env()?;
    let plaintext = std::fs::read(&io.input)
        .map_err(|e| format!("could not read input {:?}: {e}", io.input))?;

    let container = seal_to_container(&password, &plaintext, Argon2Params::RECOMMENDED)
        .map_err(|e| e.to_string())?;

    std::fs::write(&io.output, &container)
        .map_err(|e| format!("could not write output {:?}: {e}", io.output))?;
    Ok(())
}

fn cmd_open(io: &IoArgs) -> Result<(), String> {
    let password = password_from_env()?;
    let container = std::fs::read(&io.input)
        .map_err(|e| format!("could not read input {:?}: {e}", io.input))?;

    // open_container never returns plaintext on error, so this message is safe.
    let plaintext = open_container(&password, &container).map_err(|e| e.to_string())?;

    std::fs::write(&io.output, &plaintext)
        .map_err(|e| format!("could not write output {:?}: {e}", io.output))?;
    Ok(())
}

/// Generate a fresh DEV device key, write it to `out` (mode `0600`), and print
/// its public key so the user can set `SIGILD_OPLOG_PUBKEY` to it.
fn cmd_keygen(out: &str) -> Result<(), String> {
    let kf = generate_key().map_err(|e| e.to_string())?;
    let path = std::path::Path::new(out);
    save_key(path, &kf).map_err(|e| e.to_string())?;
    // Echo the public key (base64) for the user to paste into sigild's config.
    println!(
        "wrote device key to {out} (mode 0600)\n\
         device public key (set sigild SIGILD_OPLOG_PUBKEY to this): {}",
        kf.public_key
    );
    Ok(())
}

/// Generate a fresh hybrid identity, writing the SECRET identity to `out` (mode
/// `0600`) and the shareable PUBLIC identity to `<out>.pub`. Prints the `.pub`
/// path and a note to SHARE it with senders.
fn cmd_hybrid_keygen(out: &str) -> Result<(), String> {
    let (secret, public) = generate_hybrid_identity().map_err(|e| e.to_string())?;
    let pub_out = format!("{out}.pub");

    save_hybrid_secret(std::path::Path::new(out), &secret).map_err(|e| e.to_string())?;
    save_hybrid_public(std::path::Path::new(&pub_out), &public).map_err(|e| e.to_string())?;

    println!(
        "wrote hybrid SECRET identity to {out} (mode 0600) — keep it local, it decrypts your messages\n\
         wrote shareable PUBLIC identity to {pub_out}\n\
         SHARE {pub_out} with senders so they can `hybrid-seal --recipient-pub {pub_out}` TO this device"
    );
    Ok(())
}

/// Encrypt `--in` TO the recipient's PUBLIC hybrid identity and write the hybrid
/// container to `--out`. No password (this is the public-key path).
fn cmd_hybrid_seal(a: &HybridSealArgs) -> Result<(), String> {
    let public =
        load_hybrid_public(std::path::Path::new(&a.recipient_pub)).map_err(|e| e.to_string())?;
    let recipient = public.decode().map_err(|e| e.to_string())?;

    let plaintext =
        std::fs::read(&a.input).map_err(|e| format!("could not read input {:?}: {e}", a.input))?;

    let container = hybrid_seal_to_container(&recipient, &plaintext).map_err(|e| e.to_string())?;

    std::fs::write(&a.output, &container)
        .map_err(|e| format!("could not write output {:?}: {e}", a.output))?;
    Ok(())
}

/// Decrypt the hybrid container at `--in` with the SECRET identity at `--key` and
/// write the plaintext to `--out`. No password (this is the public-key path).
fn cmd_hybrid_open(a: &HybridOpenArgs) -> Result<(), String> {
    let secret = load_hybrid_secret(std::path::Path::new(&a.key)).map_err(|e| e.to_string())?;
    let identity = secret.decode().map_err(|e| e.to_string())?;

    let container =
        std::fs::read(&a.input).map_err(|e| format!("could not read input {:?}: {e}", a.input))?;

    // hybrid_open_container never returns plaintext on error, so this is safe.
    let plaintext = hybrid_open_container(&identity, &container).map_err(|e| e.to_string())?;

    std::fs::write(&a.output, &plaintext)
        .map_err(|e| format!("could not write output {:?}: {e}", a.output))?;
    Ok(())
}

/// Load the device IDENTITY from an optional key-file path.
///
/// `None` -> `Ok(None)` (send unsigned — the EXACT legacy behaviour when neither
/// `--key` nor `SIGIL_DEVICE_KEY` is set). `Some(path)` -> decode the identity;
/// its `device_id` (or `SIGIL_DEVICE_ID`, which overrides it) is what later
/// selects contract v3 over the legacy v2.
fn load_identity_opt(key: &Option<String>) -> Result<Option<DeviceIdentity>, String> {
    let Some(path) = key else { return Ok(None) };
    let mut id = load_identity(std::path::Path::new(path)).map_err(|e| e.to_string())?;
    if let Some(env_id) = std::env::var(DEVICE_ID_ENV).ok().filter(|s| !s.is_empty()) {
        id.device_id = Some(env_id);
    }
    Ok(Some(id))
}

/// The [`RequestAuth`] for an optional identity: no identity -> unsigned;
/// identity without a device ID -> legacy v2; with one -> contract v3.
fn auth_for(identity: &Option<DeviceIdentity>) -> RequestAuth<'_> {
    match identity {
        Some(id) => id.auth(),
        None => RequestAuth::None,
    }
}

/// ⭐ HTTP 402 — a BILLING state, and NOTHING ELSE.
///
/// sigild's entitlement gate (ADR 0043) runs strictly AFTER authentication and
/// authorization have BOTH succeeded, and it is called from exactly three WRITE
/// handlers: op-log append, key-envelope deposit and vault grant. No read handler
/// contains one line of entitlement code, and a key deposit (plus the grant that
/// accompanies it) to a device of YOUR OWN account is exempt even past grace.
///
/// So a 402 must never be rendered as `401` (your key is wrong) or `403` (you may
/// not touch this) — those send a paying customer to debug the wrong thing — and
/// it must never suggest that any code has been lost. Nothing has.
fn explain_payment_required(e: &CliError, what: &str) -> String {
    format!(
        "{e}\n  -> HTTP 402: this is a BILLING state, not an authentication or permission failure.\n     \
         The server authenticated AND authorized this device, then asked for payment: the\n     \
         subscription lapsed and its grace period has ended, so it refused {what}.\n     \
         ⭐ NOTHING YOU ALREADY HAVE IS AFFECTED. Reads are NEVER refused: `sigil pull`, opening\n     \
         a vault and printing codes (`sigil totp code`) all still work — codes are computed\n     \
         locally and need no server at all. Collecting your key envelopes, enumerating what a\n     \
         device can decrypt, publishing a hybrid key, enrolling, revoking, minting an invite and\n     \
         reading your account are all still served, and so is giving another device OF YOUR OWN\n     \
         ACCOUNT the key to a vault — which is why `sigil recovery generate` and `sigil recovery\n     \
         cover` still work while lapsed. Nothing is deleted and nothing expires.\n     \
         What stops is uploading NEW changes (`sigil push`) and sharing a vault to a device of a\n     \
         DIFFERENT account. Pay via the server's checkout route to resume."
    )
}

/// Turn a sync error into an actionable message, distinguishing the two auth
/// verdicts sigild can return: `401` = the request was not authenticated at all
/// (missing/invalid/replayed signature, unknown or revoked device), `403` = it WAS
/// authenticated but this device holds no sufficient grant on that vault.
fn explain_sync_error(e: CliError, vault: &str, contract: &str) -> String {
    match &e {
        CliError::Server { status: 402, .. } => {
            explain_payment_required(&e, &format!("this write to vault {vault:?}"))
        }
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> HTTP 401: sigild did not accept this request's credentials (contract {contract}).\n     \
             Check that the device is enrolled and not revoked, that --key/SIGIL_DEVICE_KEY points at the\n     \
             enrolled identity, and that the clock is within 300s of the server."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: this device IS authenticated but is NOT authorized for vault {vault:?}.\n     \
             The vault is owned by another device. Ask its owner to run:\n       \
             sigil device grant <THIS_DEVICE_ID> --vault {vault} --permission read|write"
        ),
        _ => e.to_string(),
    }
}

fn cmd_push(p: &PushArgs) -> Result<(), String> {
    let container =
        std::fs::read(&p.input).map_err(|e| format!("could not read input {:?}: {e}", p.input))?;

    // When a device identity is configured, SIGN the request: contract v3 if the
    // identity is enrolled (has a device ID), else the LEGACY v2 contract. With no
    // identity the request is unsigned, exactly as before. Either way push moves
    // OPAQUE bytes; no password, no plaintext.
    let identity = load_identity_opt(&p.key)?;
    let auth = auth_for(&identity);
    let seq = push_op_auth(&p.server, &p.vault, &container, &auth)
        .map_err(|e| explain_sync_error(e, &p.vault, auth.contract()))?;
    println!("pushed vault {} seq {}", p.vault, seq);
    Ok(())
}

fn cmd_pull(p: &PullArgs) -> Result<(), String> {
    // The state file lives at the out-dir ROOT (NOT inside the per-vault subdir),
    // shared across vaults and keyed by (server, vault).
    let state_path = std::path::Path::new(&p.out_dir).join(PULL_STATE_FILE);
    let key = cursor_key(&p.server, &p.vault);

    // Read the saved incremental cursor first; we need it both to choose the
    // default start AND to keep the new cursor monotonic on an explicit --since.
    let saved = read_cursor(&state_path, &key).map_err(|e| e.to_string())?;

    // Explicit `--since N` overrides the start for this one-off pull; otherwise
    // resume from the saved cursor.
    let start = p.since.unwrap_or(saved);

    // When a device identity is configured, SIGN the request: contract v3 if the
    // identity is enrolled, else the LEGACY v2 contract; unsigned with no identity.
    let identity = load_identity_opt(&p.key)?;
    let auth = auth_for(&identity);
    let ops = pull_ops_auth(&p.server, &p.vault, start, &auth)
        .map_err(|e| explain_sync_error(e, &p.vault, auth.contract()))?;

    if ops.is_empty() {
        println!("no new ops since {start}");
        return Ok(());
    }

    // Write each op into a PER-VAULT subdir so multiple vaults can safely share
    // one --out-dir without their flat `op-<seq>.sigil` filenames colliding. The
    // vault id was validated in pull_ops (check_vault rejects empty / '/' /
    // whitespace), so it is a safe single path segment. We create the subdir only
    // now that pull_ops returned a non-empty result, so "no new ops" leaves no
    // empty dirs behind.
    let vault_dir = std::path::Path::new(&p.out_dir).join(&p.vault);
    std::fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("could not create out dir {:?}: {e}", vault_dir))?;

    let mut max_seq = 0u64;
    for op in &ops {
        let path = vault_dir.join(format!("op-{}.sigil", op.seq));
        std::fs::write(&path, &op.blob).map_err(|e| format!("could not write {:?}: {e}", path))?;
        println!("pulled seq {} -> {}", op.seq, path.display());
        max_seq = max_seq.max(op.seq);
    }

    // Advance the cursor MONOTONICALLY: never below the saved value, even when an
    // explicit `--since 0` re-fetched older ops.
    let new_cursor = saved.max(max_seq);
    write_cursor(&state_path, &key, new_cursor).map_err(|e| e.to_string())?;
    println!("cursor for {} now at {}", p.vault, new_cursor);
    Ok(())
}

// ---------------------------------------------------------------------------
// `sigil device` — the CLIENT side of sigild's MULTI-DEVICE auth model
// (contract v3): enroll / list / revoke / grant.
//
// DEV-ONLY, UNAUDITED, plain HTTP. Every secret here (the device seed, the
// enrollment token, the admin token) is kept out of stdout/stderr: we print
// device IDs, labels and statuses only.
// ---------------------------------------------------------------------------

/// Resolve the device identity path: `--key <file>`, else `SIGIL_DEVICE_KEY`,
/// else the default `$HOME/.sigil/device.key` (falling back to the CWD if `$HOME`
/// is unset).
///
/// NOTE: this default applies ONLY to the `device` subcommands. push/pull keep
/// their existing rule (no `--key` and no `SIGIL_DEVICE_KEY` => send UNSIGNED),
/// so their legacy behaviour is untouched.
fn resolve_identity_path(flag: Option<String>) -> std::path::PathBuf {
    if let Some(p) = resolve_key(flag) {
        return std::path::PathBuf::from(p);
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home)
            .join(".sigil")
            .join("device.key"),
        _ => std::path::PathBuf::from("device.key"),
    }
}

/// Read a token from an explicit flag, else the given environment variable.
/// Tokens are BEARER SECRETS: this never echoes the value.
fn resolve_token(flag: Option<String>, env: &str) -> Option<String> {
    flag.or_else(|| std::env::var(env).ok())
        .filter(|s| !s.is_empty())
}

/// Resolve this device's HYBRID identity path (the secret half). Explicit
/// `--hybrid-key <file>` wins; otherwise it sits ALONGSIDE the device identity
/// with a `.hybrid` extension (so `$HOME/.sigil/device.key` pairs with
/// `$HOME/.sigil/device.hybrid`). The shareable PUBLIC half is always that path
/// plus `.pub`.
fn resolve_hybrid_path(
    flag: Option<String>,
    identity_path: &std::path::Path,
) -> std::path::PathBuf {
    match flag {
        Some(f) => std::path::PathBuf::from(f),
        None => identity_path.with_extension("hybrid"),
    }
}

/// The shareable PUBLIC half that sits next to a secret hybrid identity file.
fn hybrid_public_path(secret_path: &std::path::Path) -> std::path::PathBuf {
    let mut s = secret_path.as_os_str().to_os_string();
    s.push(".pub");
    std::path::PathBuf::from(s)
}

/// Parsed flags shared by the `device` subcommands. Unknown flags are rejected by
/// the caller, so each subcommand validates the combination it needs.
#[derive(Default)]
struct DeviceFlags {
    server: Option<String>,
    key: Option<String>,
    token: Option<String>,
    admin_token: Option<String>,
    label: Option<String>,
    vault: Option<String>,
    permission: Option<String>,
    reuse_key: bool,
    /// Path to this device's SECRET hybrid identity (`device hybrid-publish`).
    hybrid_key: Option<String>,
    /// Force a NEW hybrid identity even if one already exists on disk.
    regenerate: bool,
    /// `device safety-number` only: compute the ORDER-INDEPENDENT pairwise
    /// number between this device and `--pair <deviceID>`.
    pair: Option<String>,
    /// `device repin` only: the safety number the human claims to have verified
    /// out of band. When given it MUST match the presented key, or the re-pin is
    /// refused — so a typo cannot silently bless an attacker's key.
    safety_number: Option<String>,
    /// `device repin` only: the explicit acknowledgement that re-pinning
    /// accepts a NEW key for a device.
    yes: bool,
    /// Override the LOCAL hybrid-key pin store path.
    pins: Option<String>,
}

/// Parse the `device` subcommand flags (order-independent), rejecting anything
/// unknown or repeated.
fn parse_device_flags(args: Vec<String>) -> Result<DeviceFlags, String> {
    let mut f = DeviceFlags::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--server" => set_once(&mut f.server, &mut it, "--server")?,
            "--key" => set_once(&mut f.key, &mut it, "--key")?,
            "--token" => set_once(&mut f.token, &mut it, "--token")?,
            "--admin-token" => set_once(&mut f.admin_token, &mut it, "--admin-token")?,
            "--label" => set_once(&mut f.label, &mut it, "--label")?,
            "--vault" => set_once(&mut f.vault, &mut it, "--vault")?,
            "--permission" => set_once(&mut f.permission, &mut it, "--permission")?,
            "--hybrid-key" => set_once(&mut f.hybrid_key, &mut it, "--hybrid-key")?,
            "--pair" => set_once(&mut f.pair, &mut it, "--pair")?,
            "--pins" => set_once(&mut f.pins, &mut it, "--pins")?,
            "--safety-number" => set_once(&mut f.safety_number, &mut it, "--safety-number")?,
            "--reuse-key" => f.reuse_key = true,
            "--regenerate" => f.regenerate = true,
            "--yes" => f.yes = true,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    Ok(f)
}

/// Dispatch `sigil device <sub> ...`.
fn cmd_device(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err(
            "missing device subcommand: enroll | list | revoke | grant | hybrid-publish | \
             safety-number | pins | repin"
                .to_string(),
        );
    };
    let rest: Vec<String> = args.collect();
    let (positional, flags) = take_positional(&rest);
    let f = parse_device_flags(flags.to_vec())?;

    match sub.as_str() {
        "enroll" => cmd_device_enroll(&f),
        "list" => cmd_device_list(&f),
        "revoke" => cmd_device_revoke(positional, &f),
        "grant" => cmd_device_grant(positional, &f),
        "hybrid-publish" => cmd_device_hybrid_publish(&f),
        "safety-number" => cmd_device_safety_number(positional, &f),
        "pins" => cmd_device_pins(&f),
        "repin" => cmd_device_repin(positional, &f),
        other => Err(format!(
            "unknown device subcommand {other:?}; try enroll | list | revoke | grant | \
             hybrid-publish | safety-number | pins | repin"
        )),
    }
}

/// Explain a device-route HTTP failure in terms of what the operator can do.
/// Never echoes a token.
fn explain_device_error(e: CliError, what: &str) -> String {
    match &e {
        CliError::Server { status: 402, .. } => explain_payment_required(&e, what),
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> HTTP 401: sigild rejected the credentials for {what}. Enrollment tokens are\n     \
             SINGLE-USE and time-limited, the admin token must match SIGILD_ADMIN_TOKEN exactly, and the\n     \
             clock must be within 300s of the server."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: authenticated, but not permitted to {what}. A device may revoke ITSELF or\n     \
             a SIBLING in its own account (an unknown device looks the same as a foreign one — that is\n     \
             deliberate), and only a device of the vault's OWNING ACCOUNT may grant access to it."
        ),
        CliError::Server { status: 409, .. } => format!(
            "{e}\n  -> HTTP 409: that public key is already enrolled. Use the existing identity file, or\n     \
             enroll a FRESH key (drop --reuse-key / choose a new --key path)."
        ),
        CliError::Server { status: 501, .. } => format!(
            "{e}\n  -> HTTP 501: this sigild does not have the device model enabled. Start it with\n     \
             SIGILD_ENABLE_DEV_OPS=1 SIGILD_DEVICE_AUTH=1 SIGILD_ENROLL_TOKENS=<token,...>."
        ),
        _ => e.to_string(),
    }
}

/// `sigil device enroll --token <t> [--label <name>] [--key <file>] [--reuse-key]`
///
/// Generates a FRESH Ed25519 key pair (or reuses the existing identity file with
/// `--reuse-key`), proves possession of it against the enrollment challenge, and
/// on success writes the identity file (mode 0600) INCLUDING the server-assigned
/// device ID. Prints the device ID; never the seed and never the token.
fn cmd_device_enroll(f: &DeviceFlags) -> Result<(), String> {
    if f.vault.is_some() || f.permission.is_some() || f.admin_token.is_some() {
        return Err("device enroll takes --token/--label/--key/--server/--reuse-key only".into());
    }
    let token = resolve_token(f.token.clone(), ENROLL_TOKEN_ENV).ok_or_else(|| {
        format!("missing required --token <enrollment-token> (or set {ENROLL_TOKEN_ENV})")
    })?;
    let server = resolve_server(f.server.clone());
    let path = resolve_identity_path(f.key.clone());
    let label = f.label.clone().unwrap_or_default();

    // Choose the key: reuse the existing identity file on request, else generate a
    // fresh pair. We NEVER silently overwrite an existing identity — that would
    // destroy a device's only credential.
    let key_file = if f.reuse_key {
        load_key_file(&path).map_err(|e| e.to_string())?
    } else {
        if path.exists() {
            return Err(format!(
                "identity file {} already exists; pass --reuse-key to enroll that key, \
                 or --key <other-file> to enroll a fresh one",
                path.display()
            ));
        }
        generate_key().map_err(|e| e.to_string())?
    };

    let identity = key_file.decode().map_err(|e| e.to_string())?;

    let dev = enroll_device(
        &server,
        &token,
        &label,
        &identity.public_key,
        &identity.seed,
    )
    .map_err(|e| explain_device_error(e, "device enrollment"))?;

    // Persist the assigned device ID alongside the key (mode 0600). Creating the
    // parent dir 0700 mirrors the TOTP vault's handling of $HOME/.sigil.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("could not create identity dir {:?}: {e}", parent))?;
        }
    }
    let mut stored = key_file;
    stored.device_id = Some(dev.device_id.clone());
    save_key(&path, &stored).map_err(|e| e.to_string())?;

    println!(
        "enrolled device {id} (label {label:?}, status {status})\n\
         identity written to {path} (mode 0600) — push/pull with this --key now sign under contract v3",
        id = dev.device_id,
        status = dev.status,
        path = path.display(),
    );
    Ok(())
}

/// `sigil device list --admin-token <t>` — operator-only listing.
fn cmd_device_list(f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.vault.is_some() || f.permission.is_some() {
        return Err("device list takes --admin-token/--server only".into());
    }
    let admin = resolve_token(f.admin_token.clone(), ADMIN_TOKEN_ENV).ok_or_else(|| {
        format!("missing required --admin-token <token> (or set {ADMIN_TOKEN_ENV}); listing devices is operator-only")
    })?;
    let server = resolve_server(f.server.clone());

    let devices =
        list_devices(&server, &admin).map_err(|e| explain_device_error(e, "listing devices"))?;
    if devices.is_empty() {
        println!("no devices enrolled");
        return Ok(());
    }
    println!("{} device(s):", devices.len());
    for d in &devices {
        let revoked = d.revoked_at.as_deref().unwrap_or("-");
        // account is ADDITIVE: a server without the account model omits it, and
        // the line then reads exactly as it always did.
        let account = match d.account_id.as_deref() {
            Some(a) if !a.is_empty() => format!("  account={a}"),
            _ => String::new(),
        };
        println!(
            "  {id}  status={status}  label={label:?}  created={created}  revoked={revoked}{account}",
            id = d.device_id,
            status = d.status,
            label = d.label,
            created = d.created_at,
        );
    }
    Ok(())
}

/// `sigil device revoke <deviceID> [--admin-token <t>] [--key <file>]`
///
/// THREE authorized paths, matching the server: the operator admin token (may
/// revoke ANY device), SELF-revocation, and — since the account model (Phase 52)
/// — a SIBLING in the same account. The client therefore no longer refuses to
/// send a revocation for another device: whether it is a sibling is a fact only
/// the server's registry knows, so it decides and answers 403 if not.
fn cmd_device_revoke(target: Option<String>, f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.vault.is_some() || f.permission.is_some() {
        return Err("device revoke takes <deviceID> plus --admin-token/--key/--server only".into());
    }
    let target = target.ok_or_else(|| "missing <deviceID> to revoke".to_string())?;
    let server = resolve_server(f.server.clone());
    let admin = resolve_token(f.admin_token.clone(), ADMIN_TOKEN_ENV);

    // Self-revocation needs the device's own identity; with an admin token the
    // identity is optional.
    let identity = match (&admin, resolve_key(f.key.clone())) {
        (_, Some(path)) => {
            Some(load_identity(std::path::Path::new(&path)).map_err(|e| e.to_string())?)
        }
        (Some(_), None) => None,
        (None, None) => {
            return Err(format!(
                "revoking needs a credential: either --admin-token <t> (or {ADMIN_TOKEN_ENV}) \
                 or --key <identity-file> for SELF-revocation"
            ))
        }
    };
    // A signing identity that is not the target is NO LONGER refused here: a
    // device may revoke a SIBLING in its own account (Phase 52), and only the
    // server's registry knows whether the target is one. We do still insist the
    // identity be enrolled, because an unsigned request could only ever be 401.
    if let (None, Some(id)) = (&admin, &identity) {
        if id.device_id.is_none() {
            return Err(format!(
                "identity for {target:?} has no device_id: run `sigil device enroll` first, or pass \
                 --admin-token to revoke as the operator"
            ));
        }
    }
    let auth = auth_for(&identity);

    let dev = revoke_device(&server, &target, &auth, admin.as_deref())
        .map_err(|e| explain_device_error(e, "revoking a device"))?;
    println!("revoked device {} (status {})", dev.device_id, dev.status);
    Ok(())
}

/// `sigil device grant <deviceID> --vault <id> --permission read|write`
///
/// OWNER-ONLY: signed under contract v3 by the identity that owns `--vault`.
fn cmd_device_grant(target: Option<String>, f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.admin_token.is_some() {
        return Err(
            "device grant takes <deviceID> plus --vault/--permission/--key/--server only".into(),
        );
    }
    let target = target.ok_or_else(|| "missing <deviceID> to grant access to".to_string())?;
    let vault = f
        .vault
        .clone()
        .ok_or_else(|| "missing required --vault <id>".to_string())?;
    let permission = f
        .permission
        .clone()
        .ok_or_else(|| "missing required --permission read|write".to_string())?;
    let server = resolve_server(f.server.clone());

    let path = resolve_identity_path(f.key.clone());
    let identity = load_identity(&path).map_err(|e| e.to_string())?;
    if identity.device_id.is_none() {
        return Err(format!(
            "identity {} has no device_id: run `sigil device enroll` first (granting is a \
             contract v3, owner-only operation)",
            path.display()
        ));
    }
    let identity = Some(identity);
    let auth = auth_for(&identity);

    grant_vault_access(&server, &vault, &target, &permission, &auth)
        .map_err(|e| explain_device_error(e, "granting vault access"))?;
    println!("granted {target} {permission} access to vault {vault}");
    Ok(())
}

/// `sigil device hybrid-publish [--hybrid-key <file>] [--regenerate]`
///
/// Generate (if absent) this device's HYBRID identity and publish only its
/// PUBLIC half to sigild, so other devices can wrap a vault key to it.
///
/// The SECRET half is written 0600 alongside the device identity and NEVER
/// leaves this machine; the shareable public half is written next to it as
/// `<file>.pub` and is what is uploaded. Publishing is an upsert: re-running it
/// (or `--regenerate`) replaces the server's copy. Re-generating does NOT
/// re-wrap envelopes already deposited for this device — those were sealed to
/// the OLD key and must be re-shared.
fn cmd_device_hybrid_publish(f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.admin_token.is_some() || f.vault.is_some() || f.permission.is_some() {
        return Err(
            "device hybrid-publish takes --key/--hybrid-key/--server/--regenerate only".to_string(),
        );
    }
    let server = resolve_server(f.server.clone());
    let identity_path = resolve_identity_path(f.key.clone());
    let identity = load_identity(&identity_path).map_err(|e| e.to_string())?;
    let Some(device_id) = identity.device_id.clone() else {
        return Err(format!(
            "identity {} has no device_id: run `sigil device enroll` first (publishing a hybrid \
             key is a contract v3, self-only operation)",
            identity_path.display()
        ));
    };

    let secret_path = resolve_hybrid_path(f.hybrid_key.clone(), &identity_path);
    let public_path = hybrid_public_path(&secret_path);

    // Reuse the existing identity unless asked to regenerate. We never silently
    // overwrite a hybrid secret: it is the ONLY thing that can open envelopes
    // already addressed to this device.
    let public = if secret_path.exists() && !f.regenerate {
        if public_path.exists() {
            load_hybrid_public(&public_path).map_err(|e| e.to_string())?
        } else {
            // The secret is present but the public half was lost: re-derive it
            // by regenerating is NOT acceptable (it would orphan envelopes), so
            // ask for it explicitly.
            return Err(format!(
                "hybrid secret {} exists but its public half {} is missing; restore it, or pass \
                 --regenerate to create a NEW hybrid identity (which orphans any envelope already \
                 addressed to this device)",
                secret_path.display(),
                public_path.display()
            ));
        }
    } else {
        let (secret, public) = generate_hybrid_identity().map_err(|e| e.to_string())?;
        if let Some(parent) = secret_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| format!("could not create identity dir {:?}: {e}", parent))?;
            }
        }
        save_hybrid_secret(&secret_path, &secret).map_err(|e| e.to_string())?;
        save_hybrid_public(&public_path, &public).map_err(|e| e.to_string())?;
        public
    };

    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);
    publish_hybrid_key(&server, &device_id, &public, &auth)
        .map_err(|e| explain_device_error(e, "publishing this device's hybrid public key"))?;

    println!(
        "published hybrid public key for device {device_id}\n  \
         secret identity: {secret} (mode 0600, never uploaded)\n  \
         public identity: {public_file}",
        secret = secret_path.display(),
        public_file = public_path.display(),
    );
    Ok(())
}

/// Load THIS device's own hybrid PUBLIC identity from disk (no network).
fn own_hybrid_public(f: &DeviceFlags) -> Result<(String, HybridPublicIdentity), String> {
    let identity_path = resolve_identity_path(f.key.clone());
    let identity = load_identity(&identity_path).map_err(|e| e.to_string())?;
    let device_id = identity.device_id.clone().ok_or_else(|| {
        format!(
            "identity {} has no device_id: run `sigil device enroll` first",
            identity_path.display()
        )
    })?;
    let secret_path = resolve_hybrid_path(f.hybrid_key.clone(), &identity_path);
    let public = load_hybrid_public(&hybrid_public_path(&secret_path)).map_err(|e| {
        format!("{e}\n  -> run `sigil device hybrid-publish` first so this device has a hybrid identity")
    })?;
    Ok((device_id, public))
}

/// `sigil device safety-number [<deviceID>] [--pair <deviceID>]`
///
/// Print a SAFETY NUMBER: a short, deterministic fingerprint of a device's FULL
/// hybrid public key (X25519 public key + ML-KEM-768 encapsulation key) bound to
/// its device id, rendered as six 5-digit groups.
///
/// ⭐ THIS IS THE THING YOU READ ALOUD. Pinning cannot protect the FIRST time you
/// see a device's key — if the server lied then, the lie is what got pinned. The
/// only fix is to compare this number with the other person over a channel the
/// server does not control (a phone call, in person). If the digits match, the
/// key you are about to wrap a vault key to is really theirs.
///
///   * no argument  -> THIS device's own number, read from local files only.
///   * `<deviceID>` -> that device's number, fetched from the server, plus how it
///     compares to what this client has pinned. This is READ-ONLY: it never pins
///     and never re-pins.
///   * `--pair <deviceID>` -> the ORDER-INDEPENDENT pairwise number for this
///     device and that one. Both people see the SAME digits regardless of who
///     runs it, which is what makes it easy to read to each other.
fn cmd_device_safety_number(target: Option<String>, f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.admin_token.is_some() || f.yes || f.safety_number.is_some() {
        return Err(
            "device safety-number takes [<deviceID>] [--pair <deviceID>] [--key/--hybrid-key/--pins/--server] only"
                .to_string(),
        );
    }
    let (my_id, my_public) = own_hybrid_public(f)?;

    // Pairwise: mix BOTH devices' digests in a canonical sorted order.
    if let Some(other) = &f.pair {
        let server = resolve_server(f.server.clone());
        let identity_path = resolve_identity_path(f.key.clone());
        let identity = load_identity(&identity_path).map_err(|e| e.to_string())?;
        let identity_opt = Some(identity);
        let auth = auth_for(&identity_opt);
        let theirs = fetch_hybrid_key(&server, other, &auth)
            .map_err(|e| explain_sharing_error(e, "fetching that device's hybrid public key"))?;
        let pair = pairwise_safety_number(&my_id, &my_public, other, &theirs)
            .map_err(|e| e.to_string())?;
        println!(
            "PAIRWISE SAFETY NUMBER\n  \
             {my_id}  <->  {other}\n\n    {pair}\n\n  \
             Read this to the other person over a TRUSTED channel (a phone call, in person).\n  \
             It is ORDER-INDEPENDENT: they will see the SAME digits when they run\n  \
             `sigil device safety-number --pair {my_id}`. If the digits differ, DO NOT SHARE —\n  \
             something between you is substituting keys."
        );
        return Ok(());
    }

    // Someone else's key, fetched from the registry. Read-only: no pinning here.
    if let Some(device_id) = target {
        let server = resolve_server(f.server.clone());
        let identity_path = resolve_identity_path(f.key.clone());
        let identity = load_identity(&identity_path).map_err(|e| e.to_string())?;
        let identity_opt = Some(identity);
        let auth = auth_for(&identity_opt);
        let theirs = fetch_hybrid_key(&server, &device_id, &auth)
            .map_err(|e| explain_sharing_error(e, "fetching that device's hybrid public key"))?;
        let presented = hybrid_safety_number(&device_id, &theirs).map_err(|e| e.to_string())?;
        let pins_path = resolve_pins_path(f.pins.clone(), None);
        let store = load_pins(&pins_path).map_err(|e| e.to_string())?;
        let pin_line = match store.pins.get(&device_id) {
            None => "not pinned yet (it will be pinned the first time you share)".to_string(),
            Some(p) if p.safety_number == presented => {
                format!("MATCHES the pinned key (pinned at unix {})", p.pinned_at)
            }
            Some(p) => format!(
                "⚠️ DIFFERS from the pinned key ({}) — sharing will REFUSE until you re-pin",
                p.safety_number
            ),
        };
        println!(
            "SAFETY NUMBER for device {device_id}\n\n    {presented}\n\n  \
             pin status: {pin_line}\n  \
             Confirm these digits with that device's owner over a TRUSTED channel before you\n  \
             share a vault with them for the FIRST time."
        );
        return Ok(());
    }

    // This device's own number — local files only, works offline.
    let mine = hybrid_safety_number(&my_id, &my_public).map_err(|e| e.to_string())?;
    println!(
        "SAFETY NUMBER for THIS device ({my_id})\n\n    {mine}\n\n  \
         Read these digits to anyone who is about to share a vault with you, over a channel\n  \
         the server does not control. Derived from this device's FULL hybrid public key\n  \
         (X25519 + ML-KEM-768) and its device id — no secret is involved and nothing was\n  \
         sent anywhere."
    );
    Ok(())
}

/// `sigil device pins [--pins <file>]` — the hybrid public keys this client
/// TRUSTS, and their safety numbers.
///
/// This is the local record the server cannot rewrite. If a device shows a
/// non-zero re-pin count, a human accepted a key change for it at some point.
fn cmd_device_pins(f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.admin_token.is_some() || f.yes || f.pair.is_some() {
        return Err("device pins takes --pins <file> only".to_string());
    }
    let pins_path = resolve_pins_path(f.pins.clone(), None);
    let store = load_pins(&pins_path).map_err(|e| e.to_string())?;
    if store.pins.is_empty() {
        println!(
            "no pinned hybrid keys in {}\n  \
             A key is pinned the FIRST time this client fetches it (trust on first use).",
            pins_path.display()
        );
        return Ok(());
    }
    println!(
        "{} pinned key(s) in {}:",
        store.pins.len(),
        pins_path.display()
    );
    for (device_id, pin) in &store.pins {
        println!(
            "  {device_id}\n    safety number: {sn}\n    pinned at:     unix {at}{repin}",
            sn = pin.safety_number,
            at = pin.pinned_at,
            repin = if pin.repins == 0 {
                String::new()
            } else {
                format!(
                    "\n    ⚠️ re-pinned {} time(s) by explicit request",
                    pin.repins
                )
            },
        );
    }
    Ok(())
}

/// `sigil device repin <deviceID> --yes [--safety-number \"<digits>\"]`
///
/// ⚠️⚠️ DANGEROUS — READ THIS BEFORE USING IT. ⚠️⚠️
///
/// Re-pinning tells this client to TRUST A NEW hybrid public key for a device
/// whose key has CHANGED. There are exactly two reasons a key changes:
///
///   1. that device legitimately re-enrolled or regenerated its hybrid identity; or
///   2. someone — a hostile or compromised server, or anything between you and it
///      — SUBSTITUTED a key they can decrypt with, so that the next vault key you
///      share is wrapped to THEM.
///
/// Nothing this client can see tells those two apart. Only a human can, by
/// reading the NEW safety number aloud to the device's owner over a channel the
/// server does not control. Do that FIRST.
///
/// This is the ONLY operation that ever replaces a pin; no share, rotate or fetch
/// path will do it for you, and none of them will ever accept a changed key.
///
/// `--yes` is required. If you pass `--safety-number \"<digits>\"` it must match
/// the number of the key the server is presenting, so a mistyped or stale value
/// refuses rather than blessing the wrong key.
fn cmd_device_repin(target: Option<String>, f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.admin_token.is_some() || f.pair.is_some() {
        return Err(
            "device repin takes <deviceID> --yes [--safety-number <digits>] [--key/--pins/--server] only"
                .to_string(),
        );
    }
    let device_id = target.ok_or_else(|| {
        "missing required <deviceID>: `sigil device repin <deviceID> --yes`".to_string()
    })?;
    if !f.yes {
        return Err(format!(
            "refusing to re-pin {device_id} without --yes.\n  \
             Re-pinning accepts a DIFFERENT hybrid public key for that device. If the change was\n  \
             not a deliberate re-enrolment on their side, it is a KEY-SUBSTITUTION ATTACK and\n  \
             re-pinning would hand the next shared vault key to the attacker.\n  \
             Verify the new safety number with the device's owner over a TRUSTED out-of-band\n  \
             channel first (`sigil device safety-number {device_id}`), then re-run with --yes."
        ));
    }

    let server = resolve_server(f.server.clone());
    let identity_path = resolve_identity_path(f.key.clone());
    let identity = load_identity(&identity_path).map_err(|e| e.to_string())?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);
    let presented = fetch_hybrid_key(&server, &device_id, &auth)
        .map_err(|e| explain_sharing_error(e, "fetching that device's hybrid public key"))?;
    let presented_number =
        hybrid_safety_number(&device_id, &presented).map_err(|e| e.to_string())?;

    // If the human typed the number they verified, it MUST match what the server
    // is serving right now — otherwise they verified something else.
    if let Some(claimed) = &f.safety_number {
        let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        if norm(claimed) != norm(&presented_number) {
            return Err(format!(
                "refusing to re-pin {device_id}: the --safety-number you supplied does not match\n  \
                 the key this server is presenting.\n    \
                 you verified: {claimed}\n    \
                 server shows: {presented_number}\n  \
                 Do NOT re-pin. Either you verified a stale value, or the key changed again\n  \
                 between your call and this command."
            ));
        }
    }

    let pins_path = resolve_pins_path(f.pins.clone(), None);
    let (previous, new_number) =
        repin_hybrid_key(&pins_path, &device_id, &presented).map_err(|e| e.to_string())?;
    match previous {
        Some(old) => println!(
            "RE-PINNED device {device_id}\n  \
             was: {old}\n  \
             now: {new_number}\n  \
             store: {store} (0600)\n  \
             Future shares to {device_id} will now succeed and will use this key.",
            store = pins_path.display()
        ),
        None => println!(
            "pinned device {device_id} (nothing was pinned before)\n  \
             safety number: {new_number}\n  \
             store: {store} (0600)",
            store = pins_path.display()
        ),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `sigil vault` — DEVICE-TO-DEVICE VAULT SHARING (Phase 46).
//
// The key hierarchy, stated once more where the user meets it:
//
//   * A PERSONAL vault stays sealed under the human password (SIGIL_PASSWORD).
//     Nothing here changes that, and the password is NEVER shared or wrapped.
//   * A SHARED vault is sealed under a random 32-byte VAULT KEY. `vault rekey`
//     is the one-way door from the first to the second.
//   * The vault key is WRAPPED to each recipient device with the hybrid
//     (X25519 + ML-KEM-768) public-key path. The server relays that opaque
//     envelope and cannot read it.
//
// DEV-ONLY, UNAUDITED, plain HTTP. The vault key is never printed — only its
// SHA-256 fingerprint, so two devices can prove they hold the same key.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `sigil account ...` — the ACCOUNT model (Phase 52).
//
// WHY IT EXISTS: before this, a subscription was bought by a DEVICE and a vault
// was owned by a DEVICE, so paying on your phone did not entitle your laptop and
// revoking a vault's owner orphaned the vault. An account is a server-assigned
// id on the device row that entitlement and vault ownership key off instead.
//
// HOW A SECOND DEVICE JOINS: a member mints a single-use INVITE, and the joining
// device presents it as its ordinary enrollment token —
//
//     sigil account invite --key ./a.key          # on a device already in the account
//     sigil device enroll --token join_… --key ./b.key
//
// There is NO new subcommand for joining and no new wire format: the enrollment
// challenge already binds the token DIGEST, so an invite rides the existing
// X-Sigil-Enroll-Token header on the unchanged enrollment path.
//
// NO REQUEST HERE NAMES AN ACCOUNT. The server always reads it off the device row
// of the signature it just verified, which is what makes a cross-account request
// unconstructible rather than merely rejected.
//
// HONEST SCOPE: dev-gated, plain HTTP, UNAUDITED. Membership confers
// AUTHORIZATION, never DECRYPTION — a joined device still reads nothing until a
// member wraps the vault key to its hybrid public key (`sigil vault share`).
// Membership is FLAT (any member may invite, revoke any sibling and run
// checkout) and there is NO RECOVERY: lose every device in an account and the
// account is permanently unreachable.
// ---------------------------------------------------------------------------

/// Parsed flags for the `account` subcommands.
#[derive(Default)]
struct AccountFlags {
    server: Option<String>,
    key: Option<String>,
    /// `account invite` only: shorten the invite's life (seconds). The server
    /// clamps it to its own ceiling — a client may never LENGTHEN it.
    ttl: Option<String>,
    /// `account invite` only: PIN the invite to one Ed25519 public key
    /// (standard base64 of 32 bytes), so an intercepted invite is useless to
    /// anyone else.
    pin_key: Option<String>,
}

fn parse_account_flags(args: Vec<String>) -> Result<AccountFlags, String> {
    let mut f = AccountFlags::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--server" => set_once(&mut f.server, &mut it, "--server")?,
            "--key" => set_once(&mut f.key, &mut it, "--key")?,
            "--ttl" => set_once(&mut f.ttl, &mut it, "--ttl")?,
            "--pin-key" => set_once(&mut f.pin_key, &mut it, "--pin-key")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    Ok(f)
}

/// Dispatch `sigil account <sub> ...`.
fn cmd_account(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err("missing account subcommand: status | invite | invites | revoke-invite".into());
    };
    let rest: Vec<String> = args.collect();
    let (positional, flags) = take_positional(&rest);
    let f = parse_account_flags(flags.to_vec())?;

    match sub.as_str() {
        "status" => cmd_account_status(&f),
        "invite" => cmd_account_invite(&f),
        "invites" => cmd_account_invites(&f),
        "revoke-invite" => cmd_account_revoke_invite(positional, &f),
        other => Err(format!(
            "unknown account subcommand {other:?}; try status | invite | invites | revoke-invite"
        )),
    }
}

/// Explain an account-route HTTP failure. Never echoes an invite secret.
fn explain_account_error(e: CliError, what: &str) -> String {
    match &e {
        CliError::Server { status: 402, .. } => explain_payment_required(&e, what),
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> HTTP 401: sigild did not authenticate this device for {what}. The identity must be\n     \
             ENROLLED (contract v3), not revoked, and the clock within 300s of the server."
        ),
        CliError::Server { status: 404, .. } => format!(
            "{e}\n  -> HTTP 404: no such OPEN invite in YOUR account. An invite that belongs to another\n     \
             account is indistinguishable from one that does not exist — that is deliberate, so the\n     \
             route cannot be used to enumerate invites."
        ),
        CliError::Server { status: 409, .. } => format!(
            "{e}\n  -> HTTP 409: refused. Either the account already has the maximum number of OPEN invites\n     \
             (revoke one with `sigil account revoke-invite <inviteID>`), or it is at its device limit."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: refused. Either this device is not authorized for that account/vault, or —\n     \
             if it was enrolled by a PRE-ACCOUNT-MODEL sigild against an already-migrated database — it\n     \
             carries NO ACCOUNT at all, which the server refuses everywhere. The bodies are deliberately\n     \
             identical (no oracle); the operator can tell them apart in the audit log, and repairs the\n     \
             second with `sigild migrate adopt`."
        ),
        CliError::Server { status: 500, .. } => format!(
            "{e}\n  -> HTTP 500: a server-side fault (the device registry could not be read or written).\n     \
             This is NOT a verdict on this device — retry, and check the server's logs."
        ),
        CliError::Server { status: 501, .. } => format!(
            "{e}\n  -> HTTP 501: this sigild does not have the account model enabled. Start it with\n     \
             SIGILD_ENABLE_DEV_OPS=1 SIGILD_DEVICE_AUTH=1."
        ),
        _ => e.to_string(),
    }
}

/// Load the enrolled identity every account command needs. Accounts are resolved
/// from the SIGNATURE, so an unenrolled (or unsigned) identity cannot name one —
/// we say that here rather than letting the server answer a bare 401.
fn account_identity(key: Option<String>) -> Result<(std::path::PathBuf, DeviceIdentity), String> {
    let path = resolve_identity_path(key);
    let identity = load_identity(&path).map_err(|e| e.to_string())?;
    if identity.device_id.is_none() {
        return Err(format!(
            "identity {} has no device_id: run `sigil device enroll` first (the account routes are \
             contract v3 — the server reads your account off the signature, so an unenrolled key \
             cannot name one)",
            path.display()
        ));
    }
    Ok((path, identity))
}

/// `sigil account status [--key <file>] [--server <url>]`
///
/// Show THIS device's account and its members. There is no way to ask about
/// another account: the server derives it from the verified signature.
fn cmd_account_status(f: &AccountFlags) -> Result<(), String> {
    if f.ttl.is_some() || f.pin_key.is_some() {
        return Err("account status takes --key/--server only".into());
    }
    let server = resolve_server(f.server.clone());
    let (path, identity) = account_identity(f.key.clone())?;
    let me = identity.device_id.clone().unwrap_or_default();
    let auth = identity.auth();

    let acct = get_account(&server, &auth)
        .map_err(|e| explain_account_error(e, "reading your account"))?;

    println!(
        "account {id}{created}\n  devices: {count}/{limit} active{revoked}\n  identity: {path}",
        id = acct.account_id,
        created = if acct.created_at.is_empty() {
            String::new()
        } else {
            format!(" (created {})", acct.created_at)
        },
        count = acct.device_count,
        limit = acct.device_limit,
        // Say it out loud: the cap counts ACTIVE devices, so a revoked device is
        // listed below but does not hold a seat.
        revoked = if acct.revoked_device_count == 0 {
            String::new()
        } else {
            format!(
                "  ({} revoked — a revoked device does not use a seat)",
                acct.revoked_device_count
            )
        },
        path = path.display(),
    );
    for d in &acct.devices {
        let marker = if d.device_id == me {
            " <- this device"
        } else {
            ""
        };
        println!(
            "  {id}  status={status}  label={label:?}  created={created}{marker}",
            id = d.device_id,
            status = d.status,
            label = d.label,
            created = d.created_at,
        );
    }
    if acct.devices.len() < 2 {
        // Not a nag: the only remedy for a lost account is another device that
        // is already in it, and there is no recovery path of any kind.
        println!(
            "\n  NOTE: this account has one device. There is NO RECOVERY — if you lose it, the\n  \
             account and its vaults are permanently unreachable. Enroll a second device:\n    \
             sigil account invite            # here\n    \
             sigil device enroll --token <invite>   # on the other device"
        );
    }
    Ok(())
}

/// `sigil account invite [--ttl <seconds>] [--pin-key <b64>]`
///
/// Mint a SINGLE-USE invite that lets one more device join this account. The
/// secret is printed ONCE, to stdout, and is never written to a file or a log.
fn cmd_account_invite(f: &AccountFlags) -> Result<(), String> {
    let server = resolve_server(f.server.clone());
    let (_, identity) = account_identity(f.key.clone())?;
    let auth = identity.auth();

    let ttl = match &f.ttl {
        None => None,
        Some(s) => Some(
            s.parse::<u64>()
                .map_err(|_| format!("--ttl {s:?} must be a positive whole number of seconds"))
                .and_then(|v| {
                    if v == 0 {
                        Err("--ttl must be greater than 0".to_string())
                    } else {
                        Ok(v)
                    }
                })?,
        ),
    };
    let pin = match &f.pin_key {
        None => None,
        Some(b64) => {
            use base64::Engine as _;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| format!("--pin-key must be standard base64: {e}"))?;
            let arr: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                format!(
                    "--pin-key must decode to exactly 32 bytes (an Ed25519 public key), got {}",
                    raw.len()
                )
            })?;
            Some(arr)
        }
    };

    let inv = create_account_invite(&server, &auth, ttl, pin.as_ref())
        .map_err(|e| explain_account_error(e, "minting an invite"))?;

    // The secret is shown exactly once. Warn BEFORE printing it, on stderr, so a
    // piped stdout still carries only the value.
    if inv.pinned {
        eprintln!(
            "!! This invite is PINNED to one public key: only that key can redeem it. It is still\n\
             !! single-use and expires at {}. It is shown ONCE and is not recoverable.",
            inv.expires_at
        );
    } else {
        eprintln!(
            "!! This invite is a BEARER SECRET: anyone who reads it before {} can join your account\n\
             !! and inherit its subscription. The dev transport is PLAIN HTTP. Pass --pin-key <b64>\n\
             !! (the joining device's public key) to bind it to one device. Shown ONCE.",
            inv.expires_at
        );
    }
    println!("{}", inv.invite);
    println!(
        "  invite_id: {id}  (public handle — revoke with `sigil account revoke-invite {id}`)\n  \
         account:   {acct}\n  expires:   {exp}\n  redeem on the other device with:\n    \
         sigil device enroll --token <the invite above> --label <name>",
        id = inv.invite_id,
        acct = inv.account_id,
        exp = inv.expires_at,
    );
    println!(
        "  NOTE: joining grants AUTHORIZATION only. The new device reads nothing until you share a\n  \
         vault key to it: `sigil vault share --vault <id> --to <its device id>`."
    );
    Ok(())
}

/// `sigil account invites` — list this account's OPEN invites (metadata only).
fn cmd_account_invites(f: &AccountFlags) -> Result<(), String> {
    if f.ttl.is_some() || f.pin_key.is_some() {
        return Err("account invites takes --key/--server only".into());
    }
    let server = resolve_server(f.server.clone());
    let (_, identity) = account_identity(f.key.clone())?;
    let auth = identity.auth();

    let invites = list_account_invites(&server, &auth)
        .map_err(|e| explain_account_error(e, "listing invites"))?;
    if invites.is_empty() {
        println!("no open invites");
        return Ok(());
    }
    println!("{} open invite(s):", invites.len());
    for i in &invites {
        println!(
            "  {id}  created_by={by}  created={created}  expires={exp}  pinned={pinned}",
            id = i.invite_id,
            by = i.created_by_device_id,
            created = i.created_at,
            exp = i.expires_at,
            pinned = i.pinned,
        );
    }
    println!(
        "  (metadata only — the server cannot re-serve an invite secret, and neither can this CLI)"
    );
    Ok(())
}

/// `sigil account revoke-invite <inviteID>` — kill an unredeemed invite.
fn cmd_account_revoke_invite(target: Option<String>, f: &AccountFlags) -> Result<(), String> {
    if f.ttl.is_some() || f.pin_key.is_some() {
        return Err("account revoke-invite takes <inviteID> plus --key/--server only".into());
    }
    let target = target.ok_or_else(|| "missing <inviteID> to revoke".to_string())?;
    let server = resolve_server(f.server.clone());
    let (_, identity) = account_identity(f.key.clone())?;
    let auth = identity.auth();

    revoke_account_invite(&server, &auth, &target)
        .map_err(|e| explain_account_error(e, "revoking an invite"))?;
    println!("revoked invite {target}");
    Ok(())
}

/// Parsed flags for the `vault` subcommands.
#[derive(Default)]
struct VaultFlags {
    /// The shared VAULT ID (the op-log vault, not a local file).
    vault: Option<String>,
    /// Recipient device IDs. `share` takes exactly one; `rotate` takes one or
    /// more (`--to` repeated), naming the devices that KEEP access.
    to: Vec<String>,
    /// Diagnostic addressee for `accept` (see cmd_vault_accept).
    addressee: Option<String>,
    /// The local sealed vault FILE for `rekey`.
    file: Option<String>,
    keyring: Option<String>,
    /// Override the LOCAL hybrid-key pin store path.
    pins: Option<String>,
    key: Option<String>,
    hybrid_key: Option<String>,
    server: Option<String>,
    permission: Option<String>,
    /// Write the opaque envelope bytes to this file (0600) as well as
    /// uploading/consuming them. Diagnostic: it is what makes "the server
    /// relayed exactly these bytes" checkable.
    envelope_out: Option<String>,
    /// `rekey` only: also wrap the new vault key to THIS device and upload it,
    /// so the owner's own key is recoverable from the server.
    publish: bool,
    /// `rotate` only (Phase 54): devices whose envelope may be DELETED. A device
    /// that holds an envelope and is named by neither `--to` nor `--drop` aborts
    /// the rotation, so destroying access is an explicit act rather than the
    /// silent default it used to be.
    drop: Vec<String>,
    /// `rotate` only: shorthand for "drop every current holder not in `--to`".
    /// Still explicit — you have to type it.
    drop_all_others: bool,
    /// ⭐ Out-of-band verification of a recipient's hybrid key, checked by the
    /// WRAP GATE before anything is wrapped (`sigil_cli::verify_recipient_for_wrap`).
    ///
    /// Two accepted forms, so `share` (one recipient) stays as simple as it was
    /// and `rotate` (many) is still expressible:
    ///
    ///   --safety-number "83791 28129 ..."                (applies to the single --to)
    ///   --safety-number "dev_abc=83791 28129 ..."        (repeatable, per device)
    ///
    /// REQUIRED when the recipient is a RECOVERY KIT this client has never
    /// pinned: the digits are printed on the sheet, so the channel exists and
    /// trusting the registry instead is not acceptable for the one credential
    /// that reconstructs the whole account.
    safety_number: Vec<String>,
    /// `accept` only (Phase 60): the device that DEPOSITED the envelope, whose
    /// hybrid public key authenticates it. Omitted, it is read from this
    /// device's own (self-only) envelope index — a server-supplied hint that
    /// cannot be abused, because naming the wrong device just makes the AEAD
    /// refuse.
    from: Option<String>,
    /// `accept` only (Phase 60): permit REPLACING a different vault key this
    /// client already holds. Off by default, because a silent replacement is
    /// how a hostile deposit takes a vault away from a device that had it.
    replace: bool,
}

fn parse_vault_flags(args: Vec<String>) -> Result<VaultFlags, String> {
    let mut f = VaultFlags::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut f.vault, &mut it, "--vault")?,
            "--to" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--to requires a value".to_string())?;
                if f.to.contains(&v) {
                    return Err(format!("--to {v:?} given more than once"));
                }
                f.to.push(v);
            }
            "--for" => set_once(&mut f.addressee, &mut it, "--for")?,
            "--file" => set_once(&mut f.file, &mut it, "--file")?,
            "--keyring" => set_once(&mut f.keyring, &mut it, "--keyring")?,
            "--pins" => set_once(&mut f.pins, &mut it, "--pins")?,
            "--key" => set_once(&mut f.key, &mut it, "--key")?,
            "--hybrid-key" => set_once(&mut f.hybrid_key, &mut it, "--hybrid-key")?,
            "--server" => set_once(&mut f.server, &mut it, "--server")?,
            "--permission" => set_once(&mut f.permission, &mut it, "--permission")?,
            "--envelope-out" => set_once(&mut f.envelope_out, &mut it, "--envelope-out")?,
            "--drop" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--drop requires a value".to_string())?;
                if f.drop.contains(&v) {
                    return Err(format!("--drop {v:?} given more than once"));
                }
                f.drop.push(v);
            }
            "--safety-number" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--safety-number requires a value".to_string())?;
                f.safety_number.push(v);
            }
            "--from" => set_once(&mut f.from, &mut it, "--from")?,
            "--publish" => f.publish = true,
            "--replace" => f.replace = true,
            "--drop-all-others" => f.drop_all_others = true,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    Ok(f)
}

/// Resolve `--safety-number` values into `(device id, digits)` pairs.
///
/// Bare digits are allowed only when there is exactly ONE recipient, because
/// silently applying them to a set would let a human verify one device and
/// believe they had verified all of them.
fn resolve_safety_numbers(
    raw: &[String],
    recipients: &[String],
) -> Result<Vec<(String, String)>, String> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(raw.len());
    for entry in raw {
        let (device, digits) = match entry.split_once('=') {
            Some((d, n)) => (d.trim().to_string(), n.trim().to_string()),
            None => {
                if recipients.len() != 1 {
                    return Err(
                        "--safety-number without a device needs exactly one --to; with several \
                         recipients use --safety-number \"<deviceID>=<the six 5-digit groups>\""
                            .to_string(),
                    );
                }
                (recipients[0].clone(), entry.trim().to_string())
            }
        };
        if !recipients.contains(&device) {
            return Err(format!(
                "--safety-number names {device:?}, which is not one of the --to recipients"
            ));
        }
        if out.iter().any(|(d, _)| d == &device) {
            return Err(format!("--safety-number given twice for {device:?}"));
        }
        if digits.chars().filter(|c| c.is_ascii_digit()).count() == 0 {
            return Err(format!(
                "--safety-number for {device:?} contains no digits; it should be the six 5-digit \
                 groups printed on the sheet"
            ));
        }
        out.push((device, digits));
    }
    Ok(out)
}

/// Dispatch `sigil vault <sub> ...`.
fn cmd_vault(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err("missing vault subcommand: rekey | share | rotate | accept | list".to_string());
    };
    let rest: Vec<String> = args.collect();
    let f = parse_vault_flags(rest)?;
    match sub.as_str() {
        "rekey" => cmd_vault_rekey(&f),
        "share" => cmd_vault_share(&f),
        "rotate" => cmd_vault_rotate(&f),
        "accept" => cmd_vault_accept(&f),
        "list" => cmd_vault_list(&f),
        other => Err(format!(
            "unknown vault subcommand {other:?}; try rekey | share | rotate | accept | list"
        )),
    }
}

/// Load the enrolled device identity for a sharing command, requiring contract
/// v3 (every sharing route is device-authenticated).
fn sharing_identity(key: Option<String>) -> Result<(std::path::PathBuf, DeviceIdentity), String> {
    let path = resolve_identity_path(key);
    let identity = load_identity(&path).map_err(|e| e.to_string())?;
    if identity.device_id.is_none() {
        return Err(format!(
            "identity {} has no device_id: run `sigil device enroll` first (vault sharing is a \
             contract v3, device-authenticated operation)",
            path.display()
        ));
    }
    Ok((path, identity))
}

/// ⭐ Build the SENDER identity that every vault-key wrap now requires: this
/// device's id plus its hybrid SECRET identity.
///
/// Since Phase 60 a vault-key envelope is AUTHENTICATED — the sender mixes its
/// long-term X25519 secret into the KEM — so wrapping is no longer something a
/// device can do with public material alone. A device that has never run
/// `sigil device hybrid-publish` therefore cannot share, and is told so.
fn sender_identity(
    identity: &DeviceIdentity,
    identity_path: &std::path::Path,
    hybrid_key: Option<String>,
) -> Result<SenderIdentity, String> {
    let device_id = identity.device_id.clone().ok_or_else(|| {
        "this identity has no device_id: run `sigil device enroll` first".to_string()
    })?;
    let secret_path = resolve_hybrid_path(hybrid_key, identity_path);
    let secret = load_hybrid_secret(&secret_path).map_err(|e| {
        format!(
            "{e}\n  -> run `sigil device hybrid-publish` first: a vault-key envelope is \
             AUTHENTICATED to the sending device, so this device must have a hybrid identity \
             before it can wrap a key to anyone"
        )
    })?;
    SenderIdentity::new(&device_id, secret).map_err(|e| e.to_string())
}

/// Write opaque envelope bytes to a 0600 file. They are ciphertext, but they are
/// still key-shaped material, so the file is owner-only.
fn write_envelope_file(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let p = std::path::Path::new(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(p)
        .map_err(|e| format!("could not create envelope file {path:?}: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("could not write envelope file {path:?}: {e}"))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not set envelope permissions {path:?}: {e}"))
}

/// Explain a sharing HTTP failure in terms of what the user can do. Never
/// echoes a key, an envelope, or a token.
fn explain_sharing_error(e: CliError, what: &str) -> String {
    match &e {
        CliError::Server { status: 402, .. } => explain_payment_required(&e, what),
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> HTTP 401: sigild did not accept this request's credentials while {what}.\n     \
             Check the device is enrolled and NOT REVOKED, that --key points at its identity, and\n     \
             that the clock is within 300s of the server."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: authenticated, but not permitted while {what}. Only a device with\n     \
             WRITE access may deposit a key envelope, and only the ADDRESSEE may collect one."
        ),
        CliError::Server { status: 404, .. } => format!(
            "{e}\n  -> HTTP 404: nothing there while {what}. The recipient may not have run\n     \
             `sigil device hybrid-publish`, or no envelope has been shared to this device yet."
        ),
        _ => e.to_string(),
    }
}

/// `sigil vault rekey --vault <id> [--file <vaultfile>] [--publish]`
///
/// Convert a PASSWORD-sealed vault into a SHARED vault: open it with
/// `SIGIL_PASSWORD`, draw a fresh random 32-byte VAULT KEY, re-seal the SAME
/// file under that key, and record the key in the local 0600 keyring.
///
/// This is the ONLY thing that changes how a vault is sealed, and it is
/// explicit: existing password vaults keep working untouched until you run it.
/// After a rekey, that file is opened with `--vault-id <id>`, not the password.
///
/// With `--publish` it ALSO wraps the new key to THIS device's own hybrid public
/// key and uploads the envelope, so the owner can recover its own vault key from
/// the server (and, as a side effect, claims the vault ID for this device).
fn cmd_vault_rekey(f: &VaultFlags) -> Result<(), String> {
    if !f.to.is_empty() || f.addressee.is_some() || !f.drop.is_empty() || f.drop_all_others {
        return Err("vault rekey takes --vault/--file/--keyring/--publish (plus --key/--hybrid-key/--server) only".to_string());
    }
    let vault_id = f
        .vault
        .clone()
        .ok_or_else(|| "missing required --vault <id>".to_string())?;
    let file = resolve_vault_path(f.file.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());

    // Open the EXISTING password-sealed vault. This fails loudly if the file is
    // already key-sealed (wrong secret), which is the right outcome: rekey is
    // for the password -> vault-key transition.
    let password = password_from_env()?;
    let vault = load_vault_required(&file, &password)?;

    let key = generate_vault_key().map_err(|e| e.to_string())?;
    save_vault(&file, &key, &vault)?;
    keyring_put(&keyring, &vault_id, &key).map_err(|e| e.to_string())?;

    println!(
        "vault {vault_id} re-sealed under a fresh random vault key\n  \
         file:        {file} (mode 0600, now opened with --vault-id {vault_id})\n  \
         keyring:     {keyring} (mode 0600)\n  \
         key sha256:  {fp} (fingerprint only — the key is never printed)",
        file = file.display(),
        keyring = keyring.display(),
        fp = vault_key_fingerprint(&key),
    );

    if f.publish {
        let server = resolve_server(f.server.clone());
        let (identity_path, identity) = sharing_identity(f.key.clone())?;
        let device_id = identity.device_id.clone().expect("checked above");
        let secret_path = resolve_hybrid_path(f.hybrid_key.clone(), &identity_path);
        let public_path = hybrid_public_path(&secret_path);
        let public = load_hybrid_public(&public_path).map_err(|e| {
            format!("{e}\n  -> run `sigil device hybrid-publish` first so this device has a hybrid identity")
        })?;

        // ⭐ THE ONE WRAP THAT DOES NOT GO THROUGH verify_recipient_for_wrap, and
        // why that is correct: the recipient is THIS DEVICE, and its hybrid
        // PUBLIC key was just read off the LOCAL 0600 file — the server was
        // never asked, so there is no fetched answer to verify. Every wrap whose
        // recipient key came from the server goes through the gate (share,
        // rotate, cover, recovery generate); this one has no such input.
        //
        // It is still AUTHENTICATED and CONTEXT-BOUND: this device is both the
        // sender and the recipient, so the envelope it deposits for itself is
        // one only it could have produced.
        let sender = sender_identity(&identity, &identity_path, f.hybrid_key.clone())?;
        let ctx = VaultKeyWrapContext::new(&vault_id, &device_id, &device_id)
            .map_err(|e| e.to_string())?;
        let envelope = wrap_vault_key(&sender, &public, &ctx, &key).map_err(|e| e.to_string())?;
        let identity_opt = Some(identity);
        let auth = auth_for(&identity_opt);
        put_key_envelope(&server, &vault_id, &device_id, &envelope, &auth)
            .map_err(|e| explain_sharing_error(e, "depositing this vault's key for this device"))?;
        println!("  wrapped the vault key to this device ({device_id}) and uploaded the envelope ({} bytes)", envelope.len());
    }
    Ok(())
}

/// `sigil vault share --vault <id> --to <deviceID> [--permission read|write]`
///
/// Share a vault with another device: fetch that device's published hybrid
/// PUBLIC key, WRAP this vault's key to it with fresh ephemeral entropy, upload
/// the opaque envelope, and grant the device access through the EXISTING grant
/// API — so authorization and key distribution never drift apart.
///
/// The vault key itself is never printed and never leaves this machine
/// unwrapped.
fn cmd_vault_share(f: &VaultFlags) -> Result<(), String> {
    if f.file.is_some()
        || f.addressee.is_some()
        || f.publish
        || !f.drop.is_empty()
        || f.drop_all_others
    {
        return Err(
            "vault share takes --vault/--to/--permission/--keyring/--key/--server/--envelope-out only"
                .to_string(),
        );
    }
    let vault_id = f
        .vault
        .clone()
        .ok_or_else(|| "missing required --vault <id>".to_string())?;
    if f.to.len() > 1 {
        return Err(
            "vault share takes ONE --to <deviceID>; to re-wrap to several devices at once use \
             `sigil vault rotate --to A --to B`"
                .to_string(),
        );
    }
    let to =
        f.to.first()
            .cloned()
            .ok_or_else(|| "missing required --to <deviceID>".to_string())?;
    let permission = f.permission.clone().unwrap_or_else(|| "read".to_string());
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());

    let (identity_path, identity) = sharing_identity(f.key.clone())?;
    // ⭐ The SENDER identity. A vault-key envelope is authenticated to the device
    // that deposits it, so this is resolved BEFORE any network call: a device
    // without a hybrid identity must be told it cannot share, not discover it
    // after a grant has already been made.
    let sender = sender_identity(&identity, &identity_path, f.hybrid_key.clone())?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    let key = keyring_get(&keyring, &vault_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!(
                "no vault key for {vault_id:?} in {}; run `sigil vault rekey --vault {vault_id}` \
                 first (a shared vault is sealed under a random vault key, never your password)",
                keyring.display()
            )
        })?;

    // 1) ⭐ THE WRAP GATE. Resolve the recipient's PUBLIC hybrid key AND settle
    //    trust in it in ONE call, before anything can be wrapped. A changed key
    //    (PinMismatch), a wrong --safety-number, or an unverified RECOVERY KIT
    //    all stop HERE: nothing is wrapped, nothing is uploaded, and the pin
    //    store is not mutated. This is the same gate `vault rotate`,
    //    `recovery cover` and `recovery generate` use — the point of ADR 0038.
    let pins = resolve_pins_path(f.pins.clone(), f.keyring.clone());
    let safety_numbers = resolve_safety_numbers(&f.safety_number, std::slice::from_ref(&to))?;
    let expected = safety_numbers.first().map(|(_, n)| n.as_str());
    let recipient = verify_recipient_for_wrap(&server, &to, &auth, &pins, expected, false)
        .map_err(|e| explain_sharing_error(e, "verifying the recipient's hybrid public key"))?;

    // ⭐ SHOW THE TRUST DECISION BEFORE ACTING ON IT. The previous version
    // printed the safety number AFTER the wrap, the deposit and the grant had
    // all completed, which is exactly backwards: by then the vault key was
    // already in the server's hands and no human decision could undo it.
    println!(
        "about to wrap vault {vault_id} to device {to}\n  \
         key trust:   {trust}\n  \
         safety no.:  {safety}",
        trust = recipient.trust().label(),
        safety = recipient.safety_number(),
    );
    if recipient.trust().needs_out_of_band_check() {
        eprintln!(
            "warning: this is the FIRST time this client has seen {to}'s hybrid key, and nothing \n  \
             out of band has confirmed it. Pinning cannot protect first contact. Confirm the safety\n  \
             number above with {to}'s owner over a channel the server does NOT control (a phone\n  \
             call, in person); re-run with --safety-number \"<digits>\" to have it checked here."
        );
    }

    // 2-4) ⭐ THE ONE wrap -> deposit -> grant path. It takes the VerifiedRecipient
    //      produced above, and `VerifiedRecipient` has no other constructor — so
    //      this call is unreachable with an unchecked key.
    let envelope = share_vault_to_known_key(
        &server,
        &vault_id,
        &recipient,
        &permission,
        &key,
        &auth,
        &sender,
    )
    .map_err(|e| explain_sharing_error(e, "sharing the vault (wrap, grant, deposit)"))?;

    if let Some(path) = &f.envelope_out {
        write_envelope_file(path, &envelope)?;
    }
    println!(
        "shared vault {vault_id} with device {to}\n  \
         wrapped the vault key to that device's hybrid public key (X25519 + ML-KEM-768)\n  \
         envelope:    {} bytes, opaque to the server\n  \
         permission:  {permission}\n  \
         key sha256:  {fp} (fingerprint only)",
        envelope.len(),
        fp = vault_key_fingerprint(&key),
    );
    Ok(())
}

/// `sigil vault accept --vault <id>`
///
/// Collect the envelope addressed to THIS device, unwrap it with this device's
/// hybrid SECRET identity, and record the recovered vault key in the local 0600
/// keyring. Afterwards `sigil totp ... --vault-id <id>` opens the shared vault.
///
/// `--for <deviceID>` is a DIAGNOSTIC that asks for the envelope addressed to
/// ANOTHER device. The server must refuse it with 403 — the flag exists so that
/// rule is testable from the outside. It never attempts to unwrap.
fn cmd_vault_accept(f: &VaultFlags) -> Result<(), String> {
    if f.file.is_some()
        || !f.to.is_empty()
        || f.publish
        || f.permission.is_some()
        || !f.drop.is_empty()
        || f.drop_all_others
    {
        return Err(
            "vault accept takes --vault/--keyring/--pins/--key/--hybrid-key/--server/--envelope-out/--for/--from/--safety-number/--replace only"
                .to_string(),
        );
    }
    if f.safety_number.len() > 1 {
        return Err("vault accept takes at most one --safety-number (the SENDER's)".to_string());
    }
    let vault_id = f
        .vault
        .clone()
        .ok_or_else(|| "missing required --vault <id>".to_string())?;
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());
    let pins = resolve_pins_path(f.pins.clone(), f.keyring.clone());

    let (identity_path, identity) = sharing_identity(f.key.clone())?;
    let device_id = identity.device_id.clone().expect("checked above");
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    // The `--for` DIAGNOSTIC still short-circuits: it asks for someone else's
    // envelope purely so the server's 403 is testable from outside, and it never
    // unwraps anything.
    if let Some(addressee) = f.addressee.clone() {
        let envelope = get_key_envelope(&server, &vault_id, &addressee, &auth)
            .map_err(|e| explain_sharing_error(e, "collecting the key envelope"))?;
        if let Some(path) = &f.envelope_out {
            write_envelope_file(path, &envelope)?;
        }
        if addressee != device_id {
            return Err(format!(
                "fetched {} bytes addressed to {addressee} — but this device is {device_id}, so \
                 the server should have refused with 403",
                envelope.len()
            ));
        }
    }

    let secret_path = resolve_hybrid_path(f.hybrid_key.clone(), &identity_path);
    let secret = load_hybrid_secret(&secret_path).map_err(|e| {
        format!("{e}\n  -> run `sigil device hybrid-publish` first so this device has a hybrid identity")
    })?;

    // ⭐ THE UNWRAP GATE + OPEN-BEFORE-WRITING + the no-silent-replace rule, all
    // inside one library call so the desktop app gets the identical semantics.
    let report = accept_vault_key(
        &server,
        &vault_id,
        &device_id,
        &secret,
        &keyring,
        &pins,
        &auth,
        f.from.as_deref(),
        f.safety_number.first().map(String::as_str),
        f.replace,
    )
    .map_err(|e| explain_sharing_error(e, "accepting the vault key"))?;

    if let Some(path) = &f.envelope_out {
        write_envelope_file(path, &report.envelope)?;
    }

    println!(
        "accepted vault {vault_id}\n  \
         from device: {from}\n  \
         key trust:   {trust}\n  \
         safety no.:  {safety}\n  \
         opened tip:  {tip}\n  \
         keyring:     {keyring} (mode 0600)\n  \
         key sha256:  {fp} (fingerprint only — the key is never printed)\n  \
         open it with: sigil totp list --vault <file> --vault-id {vault_id}",
        from = report.sender_device_id,
        trust = report.sender_trust.label(),
        safety = report.sender_safety_number,
        tip = if report.verified_against_tip {
            "yes — the recovered key opens this vault's newest op"
        } else {
            "n/a — this vault has never been pushed, so there was nothing to open"
        },
        keyring = keyring.display(),
        fp = report.key_fingerprint,
    );
    if let Some(old) = &report.replaced {
        println!("  REPLACED a different key this client held (sha256 {old})");
    }
    if report.sender_trust.needs_out_of_band_check() {
        eprintln!(
            "warning: this is the FIRST time this client has seen {}'s hybrid key. The envelope\n  \
             IS authenticated to that key — but on first contact a hostile server could have\n  \
             served its own key AND forged the envelope under it. Confirm the safety number above\n  \
             with that device's owner over a channel the server does NOT control, and re-run with\n  \
             --safety-number \"<digits>\" to have it checked here.",
            report.sender_device_id
        );
    }
    Ok(())
}

/// Resolve the LOCAL hybrid-key PIN STORE path.
///
/// Explicit `--pins <file>` wins. Otherwise the pin store sits BESIDE the vault
/// keyring, so a client pointed at a non-default state directory keeps all of its
/// local state together (`--keyring /tmp/a/vault-keys.json` implies
/// `/tmp/a/hybrid-pins.json`). With neither, it is `$HOME/.sigil/hybrid-pins.json`.
///
/// The pin store holds only PUBLIC keys, but it is still security-critical: an
/// attacker who can rewrite it can silence the substitution alarm. It is written
/// 0600 inside a 0700 directory like every other piece of local state.
fn resolve_pins_path(
    pins_flag: Option<String>,
    keyring_flag: Option<String>,
) -> std::path::PathBuf {
    if let Some(p) = pins_flag {
        return std::path::PathBuf::from(p);
    }
    if let Some(k) = keyring_flag {
        let kp = std::path::PathBuf::from(k);
        return match kp.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.join(HYBRID_PIN_FILE),
            _ => std::path::PathBuf::from(HYBRID_PIN_FILE),
        };
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home)
            .join(".sigil")
            .join(HYBRID_PIN_FILE),
        _ => std::path::PathBuf::from(HYBRID_PIN_FILE),
    }
}

/// `sigil vault rotate --vault <id> --to <deviceID> [--to <deviceID> ...]`
///
/// ROTATE a shared vault's key and RE-WRAP it to exactly the devices named by
/// `--to`, replacing their envelopes and DELETING the envelope of every other
/// device that still holds one.
///
/// Use it after revoking a device: revocation stops that device talking to the
/// server, but everything already sealed under the old key stays readable to
/// anyone who has that key. Rotation is what makes FUTURE content unreadable to
/// it.
///
/// ⚠️ Be clear about what this buys. It protects FUTURE content ONLY. A device
/// that already unwrapped the previous key keeps that key and whatever it has
/// already copied — nothing can retract a secret that has already been read.
///
/// Every recipient's hybrid key goes through the WRAP GATE
/// (`sigil_cli::verify_recipient_for_wrap`) first, and a pin mismatch, a wrong
/// `--safety-number` or an unverified RECOVERY KIT recipient aborts the WHOLE
/// rotation before anything local or remote is modified.
fn cmd_vault_rotate(f: &VaultFlags) -> Result<(), String> {
    if f.addressee.is_some() || f.publish || f.permission.is_some() {
        return Err(
            "vault rotate takes --vault/--to (repeatable)/--drop (repeatable)/--drop-all-others/\
             --file/--keyring/--pins/--key/--server only"
                .to_string(),
        );
    }
    let vault_id = f
        .vault
        .clone()
        .ok_or_else(|| "missing required --vault <id>".to_string())?;
    if f.to.is_empty() {
        return Err(
            "missing required --to <deviceID>: name EVERY device that should keep access \
             (usually including THIS device, so the owner can still recover its own key)"
                .to_string(),
        );
    }
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());
    let pins = resolve_pins_path(f.pins.clone(), f.keyring.clone());
    let file = resolve_vault_path(f.file.clone());

    let (identity_path, identity) = sharing_identity(f.key.clone())?;
    // Re-wrapping is a wrap: it needs this device's hybrid SECRET to authenticate
    // every envelope it re-issues. Resolved before any state is touched.
    let sender = sender_identity(&identity, &identity_path, f.hybrid_key.clone())?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    // `--drop-all-others` is resolved HERE, into an explicit list, so the
    // library still receives named devices and the report can name every one it
    // removed. The rotation itself refuses any holder named by neither list.
    let mut drop = f.drop.clone();
    if f.drop_all_others {
        for holder in list_key_envelopes(&server, &vault_id, &auth)
            .map_err(|e| explain_sharing_error(e, "listing this vault's key envelopes"))?
        {
            if !f.to.contains(&holder.device_id) && !drop.contains(&holder.device_id) {
                drop.push(holder.device_id);
            }
        }
    }

    let safety_numbers = resolve_safety_numbers(&f.safety_number, &f.to)?;
    let report = rotate_vault_key(
        &server,
        &vault_id,
        &file,
        &keyring,
        &pins,
        &f.to,
        &drop,
        &safety_numbers,
        &auth,
        Argon2Params::RECOMMENDED,
        &sender,
    )
    .map_err(|e| explain_sharing_error(e, "rotating the vault key"))?;

    println!(
        "rotated vault {vault_id}\n  \
         file:        {file} (re-sealed 0600 under a FRESH random vault key)\n  \
         old key:     sha256 {old} (retired)\n  \
         new key:     sha256 {new}",
        file = file.display(),
        old = report.old_key_fingerprint,
        new = report.new_key_fingerprint,
    );
    for (device, trust) in &report.rewrapped {
        println!("  re-wrapped:  {device} ({})", trust.label());
    }
    if report.removed.is_empty() {
        println!("  removed:     (no stale envelopes)");
    } else {
        for device in &report.removed {
            println!("  removed:     {device} (its envelope was deleted from the server)");
        }
    }
    println!(
        "  NOTE: this protects FUTURE content only. A device that already unwrapped the OLD key\n  \
         still holds it and whatever it had already copied. Push the re-sealed vault so the\n  \
         remaining devices get the new content: sigil push --vault {vault_id} --in {file}",
        file = file.display()
    );
    Ok(())
}

/// `sigil vault list [--keyring <file>]` — which shared vaults this device holds
/// a key for. Prints the vault ID and a SHA-256 FINGERPRINT of the key, never
/// the key.
fn cmd_vault_list(f: &VaultFlags) -> Result<(), String> {
    let keyring = resolve_keyring_path(f.keyring.clone());
    let kr = load_keyring(&keyring).map_err(|e| e.to_string())?;
    if kr.keys.is_empty() {
        println!("no vault keys in {}", keyring.display());
        return Ok(());
    }
    println!("{} vault key(s) in {}:", kr.keys.len(), keyring.display());
    for id in kr.keys.keys() {
        // Re-read through keyring_get so a malformed entry is reported, not
        // silently rendered.
        let fp = match keyring_get(&keyring, id).map_err(|e| e.to_string())? {
            Some(key) => vault_key_fingerprint(&key),
            None => "<unreadable>".to_string(),
        };
        println!("  {id}  key_sha256={fp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `sigil totp` — the encrypted TOTP-secret vault (the first product feature).
// ---------------------------------------------------------------------------

/// Resolve the vault path: `--vault <file>` if given, else the default
/// `$HOME/.sigil/totp-vault.sigil` (falling back to the CWD if `$HOME` is unset).
fn resolve_vault_path(flag: Option<String>) -> std::path::PathBuf {
    if let Some(f) = flag {
        return std::path::PathBuf::from(f);
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home)
            .join(".sigil")
            .join("totp-vault.sigil"),
        _ => std::path::PathBuf::from("totp-vault.sigil"),
    }
}

/// Read+decrypt the vault at `path`. If the file does not exist, returns an empty
/// vault (used by `add`, so the first add creates the vault).
fn load_vault_or_empty(path: &std::path::Path, password: &[u8]) -> Result<TotpVault, String> {
    match std::fs::read(path) {
        Ok(bytes) => open_vault(password, &bytes).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TotpVault::default()),
        Err(e) => Err(format!("could not read vault {:?}: {e}", path)),
    }
}

/// Read+decrypt the vault at `path`, erroring if it does not exist (used by
/// `list`/`code`/`remove`, which need an existing vault).
fn load_vault_required(path: &std::path::Path, password: &[u8]) -> Result<TotpVault, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "no vault at {:?}; add an entry first with `sigil totp add`",
                path
            )
        } else {
            format!("could not read vault {:?}: {e}", path)
        }
    })?;
    open_vault(password, &bytes).map_err(|e| e.to_string())
}

/// Seal `vault` under `password` and write it to `path` with mode 0600, creating
/// the parent directory (mode 0700) if needed.
fn save_vault(path: &std::path::Path, password: &[u8], vault: &TotpVault) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("could not create vault dir {:?}: {e}", parent))?;
        }
    }

    let sealed =
        seal_vault(password, vault, Argon2Params::RECOMMENDED).map_err(|e| e.to_string())?;

    // Create with 0600 up front so the sealed vault is never briefly world-readable.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("could not create vault {:?}: {e}", path))?;
    use std::io::Write as _;
    f.write_all(&sealed)
        .map_err(|e| format!("could not write vault {:?}: {e}", path))?;
    // Re-assert 0600 in case the file pre-existed with looser permissions.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not set vault permissions {:?}: {e}", path))
}

/// The current wall-clock time as Unix seconds. Native-only; the core reads no
/// clock, so the binary supplies the time.
fn now_unix_secs() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before the Unix epoch: {e}"))
}

/// Dispatch `sigil totp <sub> ...`.
fn cmd_totp(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err("missing totp subcommand: add | list | code | remove".to_string());
    };
    let rest: Vec<String> = args.collect();
    match sub.as_str() {
        "add" => cmd_totp_add(rest),
        "list" => cmd_totp_list(rest),
        "code" => cmd_totp_code(rest),
        "remove" => cmd_totp_remove(rest),
        "import" => cmd_totp_import(rest),
        "export" => cmd_totp_export(rest),
        other => Err(format!(
            "unknown totp subcommand {other:?}; try add | list | code | remove | import | export"
        )),
    }
}

/// Split the args into an optional leading positional (the `<label>`) plus the
/// flag map. A positional is any leading token that does not start with `--`.
fn take_positional(args: &[String]) -> (Option<String>, &[String]) {
    match args.first() {
        Some(first) if !first.starts_with("--") => (Some(first.clone()), &args[1..]),
        _ => (None, args),
    }
}

/// Resolve the LOCAL vault-keyring path: `--keyring <file>` if given, else the
/// default `$HOME/.sigil/vault-keys.json` (falling back to the CWD if `$HOME` is
/// unset). The keyring holds SECRET vault keys and is always written 0600.
fn resolve_keyring_path(flag: Option<String>) -> std::path::PathBuf {
    if let Some(f) = flag {
        return std::path::PathBuf::from(f);
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home)
            .join(".sigil")
            .join(VAULT_KEYRING_FILE),
        _ => std::path::PathBuf::from(VAULT_KEYRING_FILE),
    }
}

/// How a local vault FILE is sealed/opened: which file, and which SECRET.
///
/// This is the one place the key hierarchy shows up in the totp commands:
///
///   * no `--vault-id`  -> the vault is a PERSONAL, password-sealed vault and
///     the secret is `SIGIL_PASSWORD`. This is the EXISTING behaviour, byte for
///     byte — nothing about an existing password vault changes.
///   * `--vault-id <id>` -> the vault is a SHARED vault sealed under the random
///     32-byte VAULT KEY held for `<id>` in the local keyring. The human
///     password is not involved and is never shared.
struct VaultAccess {
    /// The local sealed-container file.
    path: std::path::PathBuf,
    /// The shared-vault id, when this vault is key-sealed rather than
    /// password-sealed.
    vault_id: Option<String>,
    /// Where to look the vault key up.
    keyring: std::path::PathBuf,
}

impl VaultAccess {
    /// The bytes that seal/open this vault: the vault key for `--vault-id`, else
    /// the `SIGIL_PASSWORD` password. Never printed, never logged.
    fn secret(&self) -> Result<Vec<u8>, String> {
        match &self.vault_id {
            Some(id) => {
                let key = keyring_get(&self.keyring, id)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| {
                        format!(
                            "no vault key for {id:?} in {}; run `sigil vault rekey --vault {id}` \
                             (owner) or `sigil vault accept --vault {id}` (recipient) first",
                            self.keyring.display()
                        )
                    })?;
                Ok(key.to_vec())
            }
            None => password_from_env(),
        }
    }
}

/// Pull the vault-selection flags (`--vault <file>`, `--vault-id <id>`,
/// `--keyring <file>`) out of a flag list, returning the resolved access and the
/// remaining flags.
///
/// `--vault` keeps its existing meaning (the local FILE), so every existing
/// invocation behaves exactly as before; `--vault-id`/`--keyring` are new and
/// purely additive.
fn extract_vault_access(mut flags: Vec<String>) -> Result<(VaultAccess, Vec<String>), String> {
    let mut vault: Option<String> = None;
    let mut vault_id: Option<String> = None;
    let mut keyring: Option<String> = None;
    let mut rest = Vec::new();
    let mut it = flags.drain(..);
    while let Some(f) = it.next() {
        match f.as_str() {
            "--vault" => set_once(&mut vault, &mut it, "--vault")?,
            "--vault-id" => set_once(&mut vault_id, &mut it, "--vault-id")?,
            "--keyring" => set_once(&mut keyring, &mut it, "--keyring")?,
            _ => rest.push(f),
        }
    }
    Ok((
        VaultAccess {
            path: resolve_vault_path(vault),
            vault_id,
            keyring: resolve_keyring_path(keyring),
        },
        rest,
    ))
}

fn cmd_totp_add(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (access, flags) = extract_vault_access(flags.to_vec())?;
    let vault_path = access.path.clone();

    // Parse the add flags.
    let mut uri: Option<String> = None;
    let mut secret: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut digits: Option<u32> = None;
    let mut period: Option<u32> = None;

    let mut it = flags.into_iter();
    while let Some(f) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("{f} requires a value"));
        match f.as_str() {
            "--uri" => uri = Some(next()?),
            "--secret" => secret = Some(next()?),
            "--issuer" => issuer = Some(next()?),
            "--algorithm" => algorithm = Some(next()?),
            "--digits" => {
                digits = Some(
                    next()?
                        .parse()
                        .map_err(|_| "--digits must be an integer".to_string())?,
                )
            }
            "--period" => {
                period = Some(
                    next()?
                        .parse()
                        .map_err(|_| "--period must be an integer".to_string())?,
                )
            }
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    let password = access.secret()?;
    let mut vault = load_vault_or_empty(&vault_path, &password)?;

    let entry = if let Some(uri) = uri {
        // --uri import path: a leading positional label / other flags are ignored
        // in favor of the URI's own fields.
        if secret.is_some() {
            return Err("--uri and --secret are mutually exclusive".to_string());
        }
        parse_otpauth_uri(&uri).map_err(|e| e.to_string())?
    } else {
        let label =
            label.ok_or_else(|| "missing <label> (or use --uri \"otpauth://...\")".to_string())?;
        let secret_b32 = secret.ok_or_else(|| {
            "missing --secret <BASE32> (or use --uri \"otpauth://...\")".to_string()
        })?;
        let secret_bytes = base32_decode(&secret_b32).map_err(|e| e.to_string())?;
        let algo = totp_algorithm_from_str(algorithm.as_deref().unwrap_or("sha1"))
            .map_err(|e| e.to_string())?;
        new_totp_entry(
            &label,
            issuer,
            &secret_bytes,
            algo,
            digits.unwrap_or(TOTP_DEFAULT_DIGITS),
            period.unwrap_or(TOTP_DEFAULT_PERIOD),
        )
        .map_err(|e| e.to_string())?
    };

    let label = entry.label.clone();
    vault.add(entry).map_err(|e| e.to_string())?;
    save_vault(&vault_path, &password, &vault)?;
    println!("added {label:?} to vault {}", vault_path.display());
    Ok(())
}

fn cmd_totp_list(args: Vec<String>) -> Result<(), String> {
    let (access, rest) = extract_vault_access(args)?;
    let vault_path = access.path.clone();
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }
    let password = access.secret()?;
    let vault = load_vault_required(&vault_path, &password)?;

    if vault.entries.is_empty() {
        println!("vault {} is empty", vault_path.display());
        return Ok(());
    }
    println!(
        "vault {} ({} entries):",
        vault_path.display(),
        vault.entries.len()
    );
    for e in &vault.entries {
        let issuer = e.issuer.as_deref().unwrap_or("-");
        // Never print the secret.
        println!(
            "  {label}  issuer={issuer}  algorithm={algo}  digits={digits}  period={period}s",
            label = e.label,
            algo = e.algorithm,
            digits = e.digits,
            period = e.period,
        );
    }
    Ok(())
}

fn cmd_totp_code(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (access, rest) = extract_vault_access(flags.to_vec())?;
    let vault_path = access.path.clone();

    // `--at <unix-seconds>` pins the instant instead of reading the system
    // clock. It is a TEST/DEBUG hook (the wasm client has the same `?t=`), which
    // is what makes a code reproducible across two machines in a proof; it
    // changes nothing about how the code is computed.
    let mut at: Option<u64> = None;
    let mut it = rest.into_iter();
    while let Some(f) = it.next() {
        match f.as_str() {
            "--at" => {
                let raw = it
                    .next()
                    .ok_or_else(|| "--at requires a value".to_string())?;
                at =
                    Some(raw.parse::<u64>().map_err(|_| {
                        format!("--at must be non-negative unix seconds, got {raw:?}")
                    })?);
            }
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    let label = label.ok_or_else(|| "missing <label>".to_string())?;

    let password = access.secret()?;
    let vault = load_vault_required(&vault_path, &password)?;
    let entry = vault
        .find(&label)
        .ok_or_else(|| format!("no entry labelled {label:?} in the vault"))?;

    let now = match at {
        Some(t) => t,
        None => now_unix_secs()?,
    };
    let (code, remaining) = entry.code_at(now).map_err(|e| e.to_string())?;
    println!("{code}  (valid for {remaining}s)");
    Ok(())
}

fn cmd_totp_remove(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (access, rest) = extract_vault_access(flags.to_vec())?;
    let vault_path = access.path.clone();
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }
    let label = label.ok_or_else(|| "missing <label>".to_string())?;

    let password = access.secret()?;
    let mut vault = load_vault_required(&vault_path, &password)?;
    vault.remove(&label).map_err(|e| e.to_string())?;
    save_vault(&vault_path, &password, &vault)?;
    println!("removed {label:?} from vault {}", vault_path.display());
    Ok(())
}

/// One decoded multi-QR batch note, plus whether anything is still OUTSTANDING.
///
/// ⛔ The bool is not cosmetic: it is what stops `sigil totp import` telling a
/// user who has just scanned the last QR of an export that their import is
/// incomplete. `batch_note()` alone cannot carry that, because a caller has to
/// choose a HEADER for the whole run, across several URIs.
struct BatchNote {
    /// True while more QR codes remain; false on the final batch.
    outstanding: bool,
    /// The human-readable sentence from `MigrationBatch::batch_note`.
    note: String,
}

/// Collect the TOTP entries carried by a single `otpauth-migration://` or
/// `otpauth://` URI, appending to `entries` and bumping the skip counters.
/// A malformed migration/otpauth URI is counted as invalid (not fatal), so a
/// bulk import of many URIs keeps going.
fn collect_from_uri(
    uri: &str,
    entries: &mut Vec<TotpEntry>,
    skipped_hotp: &mut usize,
    skipped_invalid: &mut usize,
    batch_notes: &mut Vec<BatchNote>,
) -> Result<(), String> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration://") {
        // Bulk export: one URI, many accounts. A bad payload is fatal for THIS
        // URI (we cannot parse further), but per-account mapping errors are not.
        let batch = decode_migration_uri(uri).map_err(|e| e.to_string())?;
        // ⛔ MULTI-QR EXPORTS. Google Authenticator splits a large export across
        // several QR codes; this URI is ONE of them. Say so and remember it, so
        // the final line cannot claim a partial import was the whole transfer.
        //
        // ⭐ `outstanding` is the difference between "there is more to scan" and
        // "that was the last one". Both are worth saying; only the first is a
        // warning. Shouting INCOMPLETE at someone who has just finished is how a
        // warning becomes noise the next user skips past when it is real.
        if let Some(note) = batch.batch_note() {
            let outstanding = !batch.is_final_batch();
            if outstanding {
                eprintln!("sigil: ⚠️  {note}");
            } else {
                eprintln!("sigil: {note}");
            }
            batch_notes.push(BatchNote { outstanding, note });
        }
        for p in &batch.otps {
            match migration_otp_to_entry(p) {
                Ok(ImportedOtp::Totp(e)) => entries.push(*e),
                Ok(ImportedOtp::SkippedHotp) => {
                    eprintln!(
                        "sigil: skipping HOTP entry {:?} (the vault stores TOTP only)",
                        p.name
                    );
                    *skipped_hotp += 1;
                }
                Err(e) => {
                    eprintln!("sigil: skipping invalid entry {:?}: {e}", p.name);
                    *skipped_invalid += 1;
                }
            }
        }
        Ok(())
    } else if lower.starts_with("otpauth://") {
        match parse_otpauth_uri(uri) {
            Ok(e) => {
                entries.push(e);
                Ok(())
            }
            Err(e) => {
                eprintln!("sigil: skipping invalid otpauth URI: {e}");
                *skipped_invalid += 1;
                Ok(())
            }
        }
    } else {
        Err(format!(
            "unrecognized entry (not otpauth:// or otpauth-migration://): {uri:?}"
        ))
    }
}

/// `sigil totp import <ARG> [--vault <file>]` — import 2FA secrets.
///
/// `<ARG>` is an `otpauth-migration://offline?data=…` URI (Google Authenticator
/// bulk export), a single `otpauth://totp/…` URI, or a PATH to a file with one
/// such URI per line (`#` comments and blank lines ignored). Duplicate labels
/// (already present in the vault) are SKIPPED, not overwritten. HOTP entries and
/// unparseable/invalid entries are skipped. The vault is re-sealed only if at
/// least one entry was imported.
fn cmd_totp_import(args: Vec<String>) -> Result<(), String> {
    let (arg, flags) = take_positional(&args);
    let arg = arg.ok_or_else(|| {
        "missing <ARG>: an otpauth-migration:// URI, an otpauth:// URI, or a file path".to_string()
    })?;
    let (access, rest) = extract_vault_access(flags.to_vec())?;
    let vault_path = access.path.clone();
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }

    let password = access.secret()?;
    let mut vault = load_vault_or_empty(&vault_path, &password)?;

    // Resolve the arg to a list of URI strings: a URI is used directly; anything
    // else is treated as a file with one URI per line.
    let lower = arg.to_ascii_lowercase();
    let uris: Vec<String> =
        if lower.starts_with("otpauth-migration://") || lower.starts_with("otpauth://") {
            vec![arg.clone()]
        } else {
            let text = std::fs::read_to_string(&arg)
                .map_err(|e| format!("could not read import file {arg:?}: {e}"))?;
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        };

    let mut entries: Vec<TotpEntry> = Vec::new();
    let mut skipped_hotp = 0usize;
    let mut skipped_invalid = 0usize;
    let mut batch_notes: Vec<BatchNote> = Vec::new();
    for uri in &uris {
        collect_from_uri(
            uri,
            &mut entries,
            &mut skipped_hotp,
            &mut skipped_invalid,
            &mut batch_notes,
        )?;
    }

    // De-dup by label against the existing vault (and within this batch): SKIP a
    // label that already exists rather than overwrite it.
    let mut imported = 0usize;
    let mut skipped_dup = 0usize;
    for e in entries {
        if vault.find(&e.label).is_some() {
            eprintln!("sigil: skipping {:?}: already in the vault", e.label);
            skipped_dup += 1;
            continue;
        }
        vault.add(e).map_err(|e| e.to_string())?;
        imported += 1;
    }

    if imported > 0 {
        save_vault(&vault_path, &password, &vault)?;
    }
    println!(
        "imported {imported} into {} ({} duplicate, {} HOTP, {} invalid skipped)",
        vault_path.display(),
        skipped_dup,
        skipped_hotp,
        skipped_invalid
    );
    // ⛔ NEVER let the line above be the last word on a multi-QR export. The
    // count is true for what was scanned and false for the transfer, and the
    // whole point of an import feature is not losing accounts.
    if !batch_notes.is_empty() {
        // ⭐ The header is chosen by whether anything is ACTUALLY outstanding,
        // not by "was this a multi-QR export at all". Importing batch 2 of 2
        // used to print "THIS IMPORT IS INCOMPLETE … 0 more QR code(s) must be
        // imported", which is false, and a false alarm trains users to ignore
        // the true one.
        let outstanding = batch_notes.iter().any(|b| b.outstanding);
        if outstanding {
            println!("⚠️  THIS IMPORT IS INCOMPLETE — it is NOT the whole export:");
        } else {
            println!("That was the LAST QR code of a multi-QR export:");
        }
        for b in &batch_notes {
            println!("      - {}", b.note);
        }
        if outstanding {
            println!(
                "    Scan/import the remaining Google Authenticator QR code(s) and run \
                 `sigil totp import` again for each. Do NOT delete anything from the old \
                 app until every batch is in and `sigil totp list` shows every account."
            );
        } else {
            println!(
                "    Nothing further needs scanning from this export. This client keeps no \
                 record of earlier runs, so confirm `sigil totp list` shows every account \
                 before deleting anything from the old app."
            );
        }
    }
    Ok(())
}

/// `sigil totp export [<label>] [--vault <file>] [--migration]
/// [--skip-unsupported] [--out <file>]`.
///
/// Default: print each entry (or just `<label>`) as an `otpauth://totp/…` URI.
/// With `--migration`: emit ALL selected entries as ONE
/// `otpauth-migration://offline?data=…` URI. The output carries SECRETS in the
/// clear, so a LOUD warning is printed to stderr first. Output goes to stdout
/// unless `--out <file>` is given (written mode 0600).
///
/// ⭐ **`--skip-unsupported`** (migration export only). The Google Authenticator
/// wire format cannot express everything Sigil stores — a 7-digit code, a 60 s
/// period, SHA-512 with 8 digits, and so on — and exporting such an entry anyway
/// would produce an account that generates the WRONG codes, so the encoder
/// refuses it. Refusing is the right DEFAULT (nobody should silently receive a
/// partial vault), but it made ONE unusual account cost the user the entire bulk
/// export path — and bulk export is the anti-lock-in feature. With this flag the
/// unsupported entries are skipped, named individually on stderr with the reason,
/// and the rest export normally. The plain `otpauth://` export still carries
/// everything and is pointed at in both messages.
fn cmd_totp_export(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (access, rest) = extract_vault_access(flags.to_vec())?;
    let vault_path = access.path.clone();

    let mut migration = false;
    let mut skip_unsupported = false;
    let mut out: Option<String> = None;
    let mut it = rest.into_iter();
    while let Some(f) = it.next() {
        match f.as_str() {
            "--migration" => migration = true,
            "--skip-unsupported" => skip_unsupported = true,
            "--out" => {
                out = Some(
                    it.next()
                        .ok_or_else(|| "--out requires a value".to_string())?,
                )
            }
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    if skip_unsupported && !migration {
        return Err(
            "--skip-unsupported only applies to `--migration` (the plain otpauth:// export \
             can represent every entry, so it never skips anything)"
                .to_string(),
        );
    }

    let password = access.secret()?;
    let vault = load_vault_required(&vault_path, &password)?;

    let selected: Vec<&TotpEntry> = match &label {
        Some(l) => vec![vault
            .find(l)
            .ok_or_else(|| format!("no entry labelled {l:?} in the vault"))?],
        None => vault.entries.iter().collect(),
    };
    if selected.is_empty() {
        return Err("vault is empty; nothing to export".to_string());
    }

    // LOUD warning: an export is plaintext secret material.
    eprintln!(
        "!! WARNING: this export contains your TOTP SECRETS IN THE CLEAR. Anyone who reads it can\n\
         !! generate your codes. Treat the output like a password — do not paste it into logs,\n\
         !! chats, or shared terminals. !!"
    );

    // How many entries actually made it into the output (differs from
    // `selected.len()` only when --skip-unsupported dropped some).
    let mut exported = selected.len();
    let output = if migration {
        let mut otps = Vec::with_capacity(selected.len());
        // ⛔ ONE UNREPRESENTABLE ACCOUNT MUST NOT COST THE WHOLE EXPORT. Refusing
        // is still the DEFAULT — a silently partial export of your 2FA is worse
        // than a failed one — but `--skip-unsupported` makes it the user's
        // explicit, informed choice instead of a dead end.
        let mut refused: Vec<(String, String)> = Vec::new();
        for e in &selected {
            match entry_to_migration_otp(e) {
                Ok(otp) => otps.push(otp),
                Err(err) => refused.push((e.label.clone(), err.to_string())),
            }
        }
        if !refused.is_empty() {
            if !skip_unsupported {
                // NAME THEM. "one entry is unsupported" leaves the user grepping
                // their own vault to find out which.
                let mut msg = format!(
                    "{} of {} entr{} cannot be represented in the Google Authenticator \
                     migration format, so this export was REFUSED rather than silently \
                     leaving {} out:",
                    refused.len(),
                    selected.len(),
                    if refused.len() == 1 { "y" } else { "ies" },
                    if refused.len() == 1 { "it" } else { "them" },
                );
                for (l, why) in &refused {
                    msg.push_str(&format!("\n      - {l:?}: {why}"));
                }
                msg.push_str(
                    "\n    Either use the plain `sigil totp export` (otpauth:// URIs carry \
                     every field faithfully), or re-run with `--skip-unsupported` to export \
                     the rest and leave these behind.",
                );
                return Err(msg);
            }
            // Opted in: LOUD, itemised, and on stderr so it survives a pipe to a
            // file. The user asked for a partial export; they must still be able
            // to see exactly what is missing from it.
            eprintln!(
                "!! SKIPPING {} of {} entr{} that the Google Authenticator migration format\n\
                 !! cannot represent. THIS EXPORT IS PARTIAL — the following account(s) are\n\
                 !! NOT in it and will NOT arrive in the other app:",
                refused.len(),
                selected.len(),
                if refused.len() == 1 { "y" } else { "ies" },
            );
            for (l, why) in &refused {
                eprintln!("!!   - {l:?}: {why}");
            }
            eprintln!(
                "!! Export those with the plain `sigil totp export` (otpauth:// URIs carry\n\
                 !! every field faithfully) so nothing is lost."
            );
        }
        if otps.is_empty() {
            return Err(
                "nothing left to export: every selected entry is unrepresentable in the \
                 Google Authenticator migration format. Use the plain `sigil totp export` \
                 instead — otpauth:// URIs carry every field."
                    .to_string(),
            );
        }
        exported = otps.len();
        encode_migration_uri(&otps)
    } else {
        let mut lines = Vec::with_capacity(selected.len());
        for e in &selected {
            lines.push(entry_to_otpauth_uri(e).map_err(|err| err.to_string())?);
        }
        lines.join("\n")
    };

    match out {
        Some(path) => {
            use std::io::Write as _;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let p = std::path::Path::new(&path);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(p)
                .map_err(|e| format!("could not create export file {path:?}: {e}"))?;
            f.write_all(output.as_bytes())
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
            f.write_all(b"\n")
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("could not set export permissions {path:?}: {e}"))?;
            println!(
                "wrote {exported} entr{} to {path} (mode 0600){}",
                if exported == 1 { "y" } else { "ies" },
                if exported == selected.len() {
                    String::new()
                } else {
                    format!(
                        " — PARTIAL: {} unsupported entr{} skipped (see the warning above)",
                        selected.len() - exported,
                        if selected.len() - exported == 1 {
                            "y"
                        } else {
                            "ies"
                        }
                    )
                }
            );
        }
        None => println!("{output}"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `sigil recovery` — THE RECOVERY KIT (Phase 54).
//
// A recovery kit is an ORDINARY MEMBER DEVICE whose private keys are derived
// from 32 bytes printed on paper. The server gains no concept of "recovery": it
// sees one more device row, one more hybrid public key and one more opaque
// envelope per covered vault — exactly the shapes it already relays.
//
// ⚠️ THE PRINTED CODE IS PRINTED ONCE, TO STDOUT, AND NEVER WRITTEN ANYWHERE BY
// THIS BINARY (unless the user explicitly redirects it with `--out`, which is a
// deliberate act). It is never logged and never sent to the server.
// ---------------------------------------------------------------------------

/// Parsed flags for the `recovery` subcommands.
#[derive(Default)]
struct RecoveryFlags {
    server: Option<String>,
    key: Option<String>,
    /// The printed 56-character code (`restore` / `verify`). ⚠️ SECRET.
    ///
    /// ⚠️ PASSING IT AS AN ARGUMENT EXPOSES IT: on Linux every process on the
    /// box can read it from /proc/<pid>/cmdline while the command runs, and the
    /// shell writes it to history. It is kept for scripts, but it is no longer
    /// the only way in — see `code_stdin` and `resolve_recovery_code`.
    code: Option<String>,
    /// Read the recovery code from STDIN (one line) instead of argv. This is
    /// also the automatic behaviour when `--code` is absent, so a pipe or a
    /// redirect needs no flag at all; the flag exists to say so explicitly.
    code_stdin: bool,
    /// The kit's server-assigned device id. NOT secret — it is printed on the
    /// sheet precisely so a restore can address the kit's own envelope index.
    device_id: Option<String>,
    /// Repeatable: which vaults to cover at generate time (default: every vault
    /// in the local keyring).
    vault: Vec<String>,
    keyring: Option<String>,
    pins: Option<String>,
    /// Where `restore` writes the recovered vaults + keyring.
    out_dir: Option<String>,
    /// Write the rendered sheet to a file (0600) instead of only stdout.
    out: Option<String>,
    /// The safety number printed on the sheet, required when covering a vault
    /// from a device that did NOT generate the kit.
    safety_number: Option<String>,
    /// `restore` only: ALSO persist the kit's own secrets on this machine.
    adopt: bool,
}

fn parse_recovery_flags(args: Vec<String>) -> Result<RecoveryFlags, String> {
    let mut f = RecoveryFlags::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--server" => set_once(&mut f.server, &mut it, "--server")?,
            "--key" => set_once(&mut f.key, &mut it, "--key")?,
            "--code" => set_once(&mut f.code, &mut it, "--code")?,
            "--code-stdin" => f.code_stdin = true,
            "--device-id" => set_once(&mut f.device_id, &mut it, "--device-id")?,
            "--vault" => {
                let v = it
                    .next()
                    .ok_or_else(|| "--vault requires a value".to_string())?;
                if f.vault.contains(&v) {
                    return Err(format!("--vault {v:?} given more than once"));
                }
                f.vault.push(v);
            }
            "--keyring" => set_once(&mut f.keyring, &mut it, "--keyring")?,
            "--pins" => set_once(&mut f.pins, &mut it, "--pins")?,
            "--out-dir" => set_once(&mut f.out_dir, &mut it, "--out-dir")?,
            "--out" => set_once(&mut f.out, &mut it, "--out")?,
            "--safety-number" => set_once(&mut f.safety_number, &mut it, "--safety-number")?,
            "--adopt" => f.adopt = true,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    Ok(f)
}

/// Dispatch `sigil recovery <sub> ...`.
fn cmd_recovery(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err(
            "missing recovery subcommand: generate | verify | check | cover | restore | revoke"
                .to_string(),
        );
    };
    let rest: Vec<String> = args.collect();
    let f = parse_recovery_flags(rest)?;
    match sub.as_str() {
        "generate" => cmd_recovery_generate(&f),
        "verify" => cmd_recovery_verify(&f),
        "check" => cmd_recovery_check(&f),
        "cover" => cmd_recovery_cover(&f),
        "restore" => cmd_recovery_restore(&f),
        "revoke" => cmd_recovery_revoke(&f),
        other => Err(format!(
            "unknown recovery subcommand {other:?}; try generate | verify | check | cover | \
             restore | revoke"
        )),
    }
}

/// Explain a recovery HTTP failure in the THREE distinct terms a user can act
/// on. Never echoes the code, a seed, or a key.
fn explain_recovery_error(e: CliError, what: &str) -> String {
    match &e {
        CliError::Server { status: 402, .. } => explain_payment_required(&e, what),
        // The offline decode already ran, so a 401 here means exactly one thing.
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> valid code, but this server has no such device.\n     \
             The kit may belong to a DIFFERENT server, or it has been REVOKED. The server\n     \
             deliberately will not say which."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: authenticated, but not permitted while {what}. A kit may read only\n     \
             its OWN envelope index and only the envelopes addressed to it."
        ),
        CliError::Server { status: 501, .. } => format!(
            "{e}\n  -> HTTP 501: this server has the device model turned off, so recovery routes\n     \
             are not serving. Start sigild with SIGILD_ENABLE_DEV_OPS=1 and SIGILD_DEVICE_AUTH=1."
        ),
        _ => e.to_string(),
    }
}

/// Render the printed sheet. ONE renderer, so every surface shows the same
/// warnings.
fn render_recovery_sheet(kit: &sigil_cli::RecoveryKitOutcome) -> String {
    let rule = "─".repeat(70);
    let mut s = String::new();
    s.push_str("SIGIL RECOVERY KIT — v1\n");
    s.push_str(&rule);
    s.push('\n');
    s.push_str(&format!("SECRET   {}\n", format_recovery_kit(&kit.code)));
    s.push_str(&rule);
    s.push('\n');
    s.push_str(&format!("device id     {}\n", kit.public.device_id));
    s.push_str(&format!("account       {}\n", kit.public.account_id));
    s.push_str(&format!("server        {}\n", kit.public.server));
    s.push_str(&format!("safety no.    {}\n", kit.public.safety_number));
    if kit.public.covered.is_empty() {
        s.push_str("covers        (nothing yet — run `sigil recovery cover --vault <id>`)\n");
    } else {
        s.push_str(&format!(
            "covers        {}   (as of the print date)\n",
            kit.public.covered.join(", ")
        ));
    }
    s.push('\n');
    s.push_str(
        "⚠ Anyone holding the SECRET line has FULL CONTROL of this account: they can\n  \
         read every covered vault, revoke every one of your devices and lock you out.\n  \
         It is stronger than a stolen locked phone — no OS lock, no vault password.\n  \
         Store it where your devices are not. Never photograph it.\n\
         ⚠ Losing every device AND this sheet is unrecoverable, by you and by us.\n\
         ⚠ This kit recovers KEYS, not DATA: a vault that was never synced is gone.\n\
         ⚠ Pre-audit, UNAUDITED, dev-only. Do not store real 2FA secrets.\n",
    );
    s
}

/// `sigil recovery generate [--vault <id>]... [--out <sheet>]`
fn cmd_recovery_generate(f: &RecoveryFlags) -> Result<(), String> {
    if f.code.is_some() || f.adopt || f.device_id.is_some() || f.out_dir.is_some() {
        return Err(
            "recovery generate takes --vault (repeatable)/--keyring/--pins/--key/--server/--out only"
                .to_string(),
        );
    }
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());
    let pins = resolve_pins_path(f.pins.clone(), f.keyring.clone());
    let (identity_path, identity) = sharing_identity(f.key.clone())?;
    // Covering a vault is a WRAP: the kit's envelopes are authenticated to this
    // device, so its hybrid secret is required.
    let sender = sender_identity(&identity, &identity_path, None)?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    // Default coverage: every shared vault this device holds a key for. A
    // PASSWORD vault has no key to wrap and is deliberately not silently
    // included — recovery_generate says so by name if one is asked for.
    let vaults: Vec<String> = if f.vault.is_empty() {
        load_keyring(&keyring)
            .map_err(|e| e.to_string())?
            .keys
            .keys()
            .cloned()
            .collect()
    } else {
        f.vault.clone()
    };

    let kit = recovery_generate(&server, &auth, &vaults, &keyring, &pins, None, &sender)
        .map_err(|e| explain_recovery_error(e, "generating the recovery kit"))?;

    // The verification line comes FIRST, because it is the evidence that the
    // sheet below actually works.
    println!(
        "verified before printing: authenticated as {device} in account {account}, \
         index listed {n} vault(s), unwrapped {vault} -> key sha256 {fp}",
        device = kit.public.device_id,
        account = kit.verification.account_id,
        n = kit.verification.indexed_vaults,
        vault = if kit.verification.unwrapped_vault.is_empty() {
            "(nothing — the kit covers no vault yet)"
        } else {
            &kit.verification.unwrapped_vault
        },
        fp = if kit.verification.key_fingerprint.is_empty() {
            "-"
        } else {
            &kit.verification.key_fingerprint
        },
    );
    for (vault_id, fp) in &kit.covered {
        println!("  covered:     {vault_id}  key_sha256={fp}");
    }
    println!(
        "  seats:       {}/{} active devices in this account (the kit consumes one)",
        kit.seats_used, kit.seat_limit
    );
    println!(
        "  pin:         {} (origin \"recovery-kit\" — DERIVED locally, never fetched)",
        pins.display()
    );
    println!();

    let sheet = render_recovery_sheet(&kit);
    print!("{sheet}");
    if let Some(path) = &f.out {
        write_envelope_file(path, sheet.as_bytes())?;
        eprintln!(
            "sigil: wrote the sheet to {path} (mode 0600). ⚠️ IT CONTAINS THE SECRET — print it \
             and delete the file."
        );
    }
    println!();
    println!(
        "Next: print this sheet, verify the safety number, and store the paper somewhere your \
         devices are NOT."
    );
    Ok(())
}

/// `sigil recovery verify --code "<56 chars>"` — OFFLINE. No network at all.
/// Resolve the printed recovery code WITHOUT requiring it on the command line.
///
/// ⚠️ THE PROBLEM THIS SOLVES. The recovery code is, by this design's own
/// admission, a stronger credential than a stolen locked phone: it is a full
/// account takeover. Until now `--code "<56 chars>"` was the ONLY way to supply
/// it, which put it in `argv` — world-readable through `/proc/<pid>/cmdline` on
/// Linux for the life of the process — and in the shell history file. The vault
/// PASSWORD has never had to travel that way (`SIGIL_PASSWORD`), and neither
/// should this.
///
/// Precedence:
///
///   1. `--code <value>` — kept working for scripts, and now WARNS on stderr,
///      because a credential you cannot rotate deserves to be told about.
///   2. `--code-stdin`, or no `--code` at all with stdin NOT a terminal — read
///      one line from stdin, so `sigil recovery restore … < code.txt` and
///      `pass show … | sigil recovery restore …` both work with nothing in argv.
///   3. otherwise — PROMPT on the controlling terminal, with echo disabled where
///      the terminal allows it.
///
/// There is deliberately NO environment variable: an env var is inherited by
/// every child process and shows up in `/proc/<pid>/environ`, which is barely
/// better than argv for a credential of this weight.
fn resolve_recovery_code(f: &RecoveryFlags) -> Result<String, String> {
    use std::io::BufRead as _;

    if let Some(code) = &f.code {
        eprintln!(
            "warning: --code puts the RECOVERY SECRET in this process's argv, where any local \n               user can read it (/proc/<pid>/cmdline on Linux) and where your shell records it in \n               history. Prefer piping it in (sigil recovery restore --code-stdin < file) or letting \n               it prompt."
        );
        return Ok(code.clone());
    }

    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if f.code_stdin || !stdin_is_tty {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("could not read the recovery code from stdin: {e}"))?;
        let code = line.trim().to_string();
        if code.is_empty() {
            return Err(
                "no recovery code on stdin: pipe the printed code in, or pass --code \"<56 \
                 characters>\" (which exposes it in argv)"
                    .to_string(),
            );
        }
        return Ok(code);
    }

    // Interactive. Turn echo off if we can; say so plainly if we cannot, rather
    // than silently printing a recovery secret onto somebody's screen.
    let echo_off = set_terminal_echo(false);
    if !echo_off {
        eprintln!(
            "warning: could not disable terminal echo — the code WILL be visible as you type"
        );
    }
    eprint!("Recovery code (from the printed sheet): ");
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if echo_off {
        set_terminal_echo(true);
        eprintln!();
    }
    read.map_err(|e| format!("could not read the recovery code: {e}"))?;
    let code = line.trim().to_string();
    if code.is_empty() {
        return Err("no recovery code entered".to_string());
    }
    Ok(code)
}

/// Best-effort terminal echo control, via `stty` on the controlling terminal.
///
/// Done by shelling out on purpose: the alternative is a `libc`/`termios`
/// dependency for one `ioctl`, and this crate's dependency list is deliberately
/// short. Returns whether the change actually took effect — the caller warns the
/// user when it did not, so a recovery secret is never echoed silently.
fn set_terminal_echo(on: bool) -> bool {
    let Ok(tty) = std::fs::File::open("/dev/tty") else {
        return false;
    };
    std::process::Command::new("stty")
        .arg(if on { "echo" } else { "-echo" })
        .stdin(tty)
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

fn cmd_recovery_verify(f: &RecoveryFlags) -> Result<(), String> {
    let code = resolve_recovery_code(f)?;
    // Nothing here talks to a server: a mistyped code must never leak to one.
    let seed = recovery_verify(&code).map_err(|e| e.to_string())?;
    let identity = derive_recovery_identity(&seed);
    println!(
        "that recovery code is well-formed (checksum OK, version 1) — checked OFFLINE, no request \
         was made.\n  \
         normalized:   {}\n  \
         hybrid key:   x25519 {}… / ml-kem {}…\n  \
         NOTE: this proves the code was typed correctly. It does NOT prove any server knows this \
         kit, nor that the kit covers anything.",
        format_recovery_kit(&code),
        &identity.hybrid_public.x25519_public_key[..12],
        &identity.hybrid_public.mlkem_encaps_key[..12],
    );
    Ok(())
}

/// `sigil recovery check --device-id <kitID>`
fn cmd_recovery_check(f: &RecoveryFlags) -> Result<(), String> {
    let kit_id = f.device_id.clone().ok_or_else(|| {
        "missing required --device-id <kit device id> (it is on the sheet)".to_string()
    })?;
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());
    let (_p, identity) = sharing_identity(f.key.clone())?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    let rows = recovery_check(&server, &auth, &kit_id, &keyring)
        .map_err(|e| explain_recovery_error(e, "checking recovery coverage"))?;
    if rows.is_empty() {
        println!("no shared vaults in {} to check", keyring.display());
        return Ok(());
    }
    println!("recovery coverage for kit {kit_id}, CHECKED FROM THIS DEVICE:");
    let mut uncovered = 0usize;
    for row in &rows {
        let state = if row.covered {
            "COVERED"
        } else {
            "NOT COVERED"
        };
        let synced = if row.synced {
            "synced"
        } else {
            "⚠ NEVER SYNCED — the key would be recovered but there is no data on the server"
        };
        if !row.covered {
            uncovered += 1;
        }
        println!(
            "  {vault}  {state}{at}  ({synced})",
            vault = row.vault_id,
            at = if row.covered_at.is_empty() {
                String::new()
            } else {
                format!(" since {}", row.covered_at)
            },
        );
    }
    if uncovered > 0 {
        println!(
            "\n{uncovered} vault(s) are NOT covered. Fix each with:\n  \
             sigil recovery cover --device-id {kit_id} --vault <id>"
        );
    }
    println!(
        "\n⚠ This is coverage as seen FROM THIS DEVICE, not \"you are covered\". A vault created \
         on another device that never heard of this kit is invisible here."
    );
    Ok(())
}

/// `sigil recovery cover --device-id <kitID> --vault <id> [--safety-number "..."]`
fn cmd_recovery_cover(f: &RecoveryFlags) -> Result<(), String> {
    let kit_id = f.device_id.clone().ok_or_else(|| {
        "missing required --device-id <kit device id> (it is on the sheet)".to_string()
    })?;
    if f.vault.len() != 1 {
        return Err("recovery cover takes exactly one --vault <id>".to_string());
    }
    let vault_id = f.vault[0].clone();
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());
    let pins = resolve_pins_path(f.pins.clone(), f.keyring.clone());
    let (identity_path, identity) = sharing_identity(f.key.clone())?;
    // Covering is a WRAP, so it needs this device's hybrid secret.
    let sender = sender_identity(&identity, &identity_path, None)?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    let (fp, derived) = recovery_cover(
        &server,
        &auth,
        &kit_id,
        &vault_id,
        &keyring,
        &pins,
        f.safety_number.as_deref(),
        &sender,
    )
    .map_err(|e| explain_recovery_error(e, "covering a vault with the recovery kit"))?;

    println!(
        "vault {vault_id} is now covered by recovery kit {kit_id}\n  \
         key sha256:  {fp} (fingerprint only — the key is never printed)\n  \
         key source:  {source}",
        source = if derived {
            "DERIVED locally from the recovery secret (pinned with origin \"recovery-kit\") — \
             no key was fetched, so there was nothing to substitute"
        } else {
            "fetched from the server and verified against the SAFETY NUMBER you supplied"
        },
    );
    Ok(())
}

/// `sigil recovery restore --device-id <kitID>` — the code is PROMPTED for, or
/// read from stdin; `--code` still works for scripts but exposes it in argv.
fn cmd_recovery_restore(f: &RecoveryFlags) -> Result<(), String> {
    let code = resolve_recovery_code(f)?;
    // The device id is on the sheet and is NOT secret. It is required because
    // sigild assigns it — nothing about the printed secret determines it, and
    // there is deliberately no route that looks a device up by public key.
    let kit_id = f.device_id.clone().ok_or_else(|| {
        "missing required --device-id <kit device id>: it is printed on the sheet under the \
         SECRET line (it is not itself a secret)"
            .to_string()
    })?;
    let server = resolve_server(f.server.clone());
    let out_dir = match &f.out_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => default_state_dir(),
    };

    let report = recovery_restore(&code, &server, &kit_id, &out_dir, f.adopt)
        .map_err(|e| explain_recovery_error(e, "restoring from the recovery kit"))?;

    println!(
        "restored from the recovery kit\n  \
         device:      {device} (account {account})\n  \
         out dir:     {dir} (mode 0700; every file inside is 0600)",
        device = report.device_id,
        account = report.account_id,
        dir = out_dir.display(),
    );
    for (vault_id, path, fp, entries) in &report.vaults {
        println!(
            "  recovered:   {vault_id} -> {path} ({entries} entr{plural}, key_sha256={fp})",
            path = path.display(),
            plural = if *entries == 1 { "y" } else { "ies" },
        );
        println!(
            "               sigil totp list --vault {path} --vault-id {vault_id} --keyring {kr}",
            path = path.display(),
            kr = out_dir.join(VAULT_KEYRING_FILE).display()
        );
    }
    for (vault_id, why) in &report.skipped {
        println!("  ⚠ skipped:   {vault_id}: {why}");
    }
    if report.adopted {
        println!(
            "\n⚠ --adopt: this machine now holds the kit's OWN Ed25519 seed and hybrid secret\n  \
             (0600 in {dir}). IT IS A SECOND COPY OF THE PAPER. Anyone with this machine has\n  \
             everything the sheet has.",
            dir = out_dir.display()
        );
    } else {
        println!(
            "\nThe kit's own secrets were NOT written to disk (that is the default). This machine\n\
             recovered the vaults and is otherwise an ordinary machine."
        );
    }
    println!(
        "\nRecovery is a TRANSITION, not a destination. Now:\n  \
         1. enroll a real device:  sigil account invite   then  sigil device enroll --token <invite>\n  \
         2. share each vault to it: sigil vault share --vault <id> --to <newDeviceID>\n  \
         3. retire this kit:        sigil recovery revoke --device-id {kit}\n  \
         4. rotate each vault:      sigil vault rotate --vault <id> --to <newDeviceID> --drop {kit}\n  \
         5. print a FRESH kit:      sigil recovery generate",
        kit = report.device_id
    );
    Ok(())
}

/// `sigil recovery revoke --device-id <kitID>`
fn cmd_recovery_revoke(f: &RecoveryFlags) -> Result<(), String> {
    let kit_id = f
        .device_id
        .clone()
        .ok_or_else(|| "missing required --device-id <kit device id>".to_string())?;
    let server = resolve_server(f.server.clone());
    let keyring = resolve_keyring_path(f.keyring.clone());
    let (_p, identity) = sharing_identity(f.key.clone())?;
    let identity_opt = Some(identity);
    let auth = auth_for(&identity_opt);

    let vaults: Vec<String> = if f.vault.is_empty() {
        load_keyring(&keyring)
            .map_err(|e| e.to_string())?
            .keys
            .keys()
            .cloned()
            .collect()
    } else {
        f.vault.clone()
    };

    let report = recovery_revoke(&server, &auth, &kit_id, &vaults)
        .map_err(|e| explain_recovery_error(e, "revoking the recovery kit"))?;
    println!("revoked recovery kit {}", report.device_id);
    for vault_id in &report.envelopes_removed {
        println!("  envelope removed: {vault_id}");
    }
    for vault_id in &report.already_clear {
        println!("  already clear:    {vault_id}");
    }
    println!(
        "\n⚠ Revocation stops the kit talking to the server. It CANNOT un-learn a vault key the\n  \
         kit already unwrapped. Rotate each vault so future content is unreadable to it — this\n  \
         command deliberately does NOT do it for you, because rotation re-seals your data:"
    );
    for vault_id in report
        .envelopes_removed
        .iter()
        .chain(report.already_clear.iter())
    {
        println!(
            "  sigil vault rotate --vault {vault_id} --to <yourDeviceID> --drop {}",
            report.device_id
        );
    }
    Ok(())
}

/// The default LOCAL state directory (`$HOME/.sigil`, else the CWD).
fn default_state_dir() -> std::path::PathBuf {
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home).join(".sigil"),
        _ => std::path::PathBuf::from("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payment_error() -> CliError {
        CliError::Server {
            status: 402,
            body:
                r#"{"error":"payment_required","reads_allowed":true,"key_recovery_allowed":true}"#
                    .to_string(),
        }
    }

    /// ⭐ A 402 must read as BILLING on every surface that can receive one — and
    /// must never be dressed up as an auth or permission failure, nor imply that
    /// any code has been lost. Before this, `sigil push` dumped the raw JSON body
    /// while 401/403/501 each got a friendly explainer.
    #[test]
    fn payment_required_is_explained_on_every_surface() {
        let rendered = [
            explain_sync_error(payment_error(), "demo-vault", "v3"),
            explain_device_error(payment_error(), "enrolling this device"),
            explain_account_error(payment_error(), "minting an invite"),
            explain_sharing_error(payment_error(), "depositing a key envelope"),
            explain_recovery_error(payment_error(), "covering a vault"),
        ];
        for msg in rendered {
            assert!(msg.contains("402"), "must name the status: {msg}");
            assert!(msg.contains("BILLING state"), "must call it billing: {msg}");
            assert!(
                msg.contains("not an authentication or permission failure"),
                "must rule out auth/permission: {msg}"
            );
            // The truthful half: reads and key recovery are never refused.
            assert!(msg.contains("Reads are NEVER refused"), "{msg}");
            assert!(msg.contains("recovery generate"), "{msg}");
            // …and it must not be rendered as a raw JSON dump.
            assert!(
                !msg.trim_end().ends_with("key_recovery_allowed\":true}"),
                "the raw body must not be the whole message: {msg}"
            );
        }
    }

    /// A status the explainers do not special-case still falls through unchanged,
    /// so adding the 402 arm cannot have swallowed anything.
    #[test]
    fn other_statuses_are_untouched() {
        let e = CliError::Server {
            status: 418,
            body: "teapot".to_string(),
        };
        assert_eq!(
            explain_sync_error(e, "demo-vault", "v3"),
            CliError::Server {
                status: 418,
                body: "teapot".to_string()
            }
            .to_string()
        );
    }
}
