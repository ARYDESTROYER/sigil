// Hand-written types for @sigil/wasm. Covers the bundler-target wasm exports
// plus the proven JS helpers (totp-vault / sync / totp-migration), which ship
// as plain .mjs with no bundled .d.ts.
//
// Pre-audit / UNAUDITED. Not for real secrets.

// ── wasm exports ────────────────────────────────────────────────────────────

/** RFC 6238 TOTP code (numeric, unpadded — render via {@link format_code}). */
export function totp(
  key: Uint8Array,
  unix_time: number,
  period: number,
  t0: number,
  digits: number,
  algorithm: string,
): number;

/** RFC 4226 HOTP code (numeric, unpadded — render via {@link format_code}). */
export function hotp(
  key: Uint8Array,
  counter: number,
  digits: number,
  algorithm: string,
): number;

/** Zero-pad a numeric OTP code to `digits` width. */
export function format_code(code: number, digits: number): string;

/** Seal one record (Argon2id → XChaCha20-Poly1305 envelope). */
export function seal_record(
  password: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  m_cost: number,
  t_cost: number,
  p_cost: number,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

/** Open one record produced by {@link seal_record}. Throws on failure. */
export function open_record(
  password: Uint8Array,
  salt: Uint8Array,
  m_cost: number,
  t_cost: number,
  p_cost: number,
  envelope: Uint8Array,
): Uint8Array;

/** Seal into a CLI-compatible `SIGILcli` container. */
export function seal_to_container(
  password: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  m_cost: number,
  t_cost: number,
  p_cost: number,
  plaintext: Uint8Array,
): Uint8Array;

/** Open a CLI-compatible `SIGILcli` container. Throws on failure. */
export function open_container(password: Uint8Array, container: Uint8Array): Uint8Array;

/**
 * Read `[m_cost, t_cost, p_cost]` out of a `SIGILcli` header — no password, no
 * KDF, no allocation. Throws on a header that is not ours or whose declared work
 * factors exceed sigil-core's ceilings.
 */
export function container_params(container: Uint8Array): Uint32Array;

/**
 * ⭐ THE NO-DOWNGRADE RATCHET (sigil-core's `Argon2Params::no_downgrade`, the
 * same function `sigil_cli::no_downgrade` delegates to). Returns
 * `[m_cost, t_cost, p_cost]`: the componentwise max of what `container` declares
 * and what the caller asked for.
 */
export function reseal_params(
  container: Uint8Array,
  m_cost: number,
  t_cost: number,
  p_cost: number,
): Uint32Array;

/** Derive the 32-byte X25519 public key from a 32-byte X25519 secret. */
export function hybrid_x25519_public(secret: Uint8Array): Uint8Array;

/** Derive the 1184-byte ML-KEM-768 encapsulation key from a 64-byte seed. */
export function hybrid_mlkem_encaps_key(seed: Uint8Array): Uint8Array;

/** Seal to a recipient hybrid identity, producing a `SIGILhyb` container. */
export function hybrid_seal_to_container(
  recipient_x25519_pub: Uint8Array,
  recipient_mlkem_encaps_key: Uint8Array,
  ephemeral_x25519_secret: Uint8Array,
  mlkem_coin: Uint8Array,
  aead_nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

/** Open a `SIGILhyb` container with the recipient hybrid secret. Throws. */
export function hybrid_open_container(
  recipient_x25519_secret: Uint8Array,
  recipient_mlkem_seed: Uint8Array,
  container: Uint8Array,
): Uint8Array;

/**
 * The CONTEXT-BOUND AAD for a vault-key wrap (Phase 60):
 * `"sigil-vault-key-wrap-v1\n"` then the three identifiers, each `u32`
 * big-endian length-prefixed. Single-sourced in `sigil_core::vault_key_wrap_aad`,
 * which the `sigil` CLI calls too, so Rust and JS agree by construction.
 */
export function vault_key_wrap_aad(
  vault_id: string,
  recipient_device_id: string,
  sender_device_id: string,
): Uint8Array;

/**
 * ⭐ AUTHENTICATED seal to a recipient hybrid identity, AS the holder of
 * `sender_x25519_secret`, producing a `SIGILhyb` **version 2** container.
 *
 * Unlike {@link hybrid_seal_to_container}, a party holding only the recipient's
 * PUBLIC key cannot produce a container this authenticates — the sender's
 * long-term X25519 secret feeds a third Diffie–Hellman that goes into the KDF.
 */
export function hybrid_auth_seal_to_container(
  sender_x25519_secret: Uint8Array,
  recipient_x25519_pub: Uint8Array,
  recipient_mlkem_encaps_key: Uint8Array,
  ephemeral_x25519_secret: Uint8Array,
  mlkem_coin: Uint8Array,
  aead_nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

/**
 * ⭐ AUTHENTICATED open of a `SIGILhyb` **version 2** container, asserting it
 * came from `sender_x25519_pub` and was sealed under exactly `aad`.
 *
 * ⛔ A version-1 (anonymous) container is REFUSED before any cryptography runs.
 * A wrong recipient, a WRONG SENDER, a tampered container or a mismatched AAD
 * all throw, and no plaintext is returned in any of those cases.
 */
export function hybrid_auth_open_container(
  recipient_x25519_secret: Uint8Array,
  recipient_mlkem_seed: Uint8Array,
  sender_x25519_pub: Uint8Array,
  aad: Uint8Array,
  container: Uint8Array,
): Uint8Array;

/** Derive the 32-byte Ed25519 public key from a 32-byte seed. */
export function ed25519_public_key(seed: Uint8Array): Uint8Array;

/** Sign a message with a 32-byte Ed25519 seed, returning the 64-byte signature. */
export function ed25519_sign(seed: Uint8Array, message: Uint8Array): Uint8Array;

/** Strictly verify an Ed25519 signature. Throws on wrong-length inputs. */
export function ed25519_verify(
  public_key: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean;

/**
 * Encode a 32-byte recovery seed as the printed kit code: Crockford base32 over
 * `[version] || seed || checksum`, exactly 56 characters, ungrouped.
 *
 * The RECOVERY KIT IS A CREDENTIAL — whoever holds it has full control of the
 * account. Never log it, never persist it, never put it in a URL.
 */
export function recovery_encode(seed: Uint8Array): string;

/**
 * Decode a printed kit code back to its 32-byte seed. Hyphens and whitespace are
 * ignored; O folds to 0 and I/L to 1; **U is rejected, never folded**. Throws on
 * a bad length, a bad character, a bad checksum, or an unsupported version — in
 * that order, so a flipped version byte reports a bad code rather than an
 * unsupported one.
 */
export function recovery_decode(code: string): Uint8Array;

/** Derive the kit's 32-byte Ed25519 device seed from the recovery seed (HKDF-SHA256). */
export function recovery_derive_ed25519_seed(seed: Uint8Array): Uint8Array;

/** Derive the kit's 32-byte X25519 secret from the recovery seed (HKDF-SHA256). */
export function recovery_derive_x25519_secret(seed: Uint8Array): Uint8Array;

/** Derive the kit's 64-byte ML-KEM-768 keygen seed from the recovery seed (HKDF-SHA256). */
export function recovery_derive_mlkem_seed(seed: Uint8Array): Uint8Array;

/** Render a 56-character kit code as 7 groups of 8, hyphen-joined, for printing. */
export function recovery_format(code: string): string;

/**
 * ⭐ The CONTENT-DERIVED id of a TOTP entry (Phase 61) — one domain-separated,
 * length-prefixed SHA-256 transcript formatted as an RFC 9562 v8 UUID.
 *
 * Single-sourced in `sigil-core` and NOT mirrored in JS: a drift here would be
 * invisible (a vault that opens correctly everywhere and silently duplicates or
 * mis-suppresses entries when two devices merge).
 *
 * `issuer` is `""` when absent, `secret` is the DECODED key bytes, `algorithm` is
 * lowercase, and `disambiguator` is `0` for every ordinary call.
 */
export function entry_id(
  issuer: string,
  label: string,
  secret: Uint8Array,
  algorithm: string,
  digits: number,
  period: number,
  disambiguator: number,
): string;


/** The XChaCha20-Poly1305 nonce length in bytes (24). */
export function nonce_len(): number;

/** The recommended Argon2id salt length in bytes (16). */
export function recommended_salt_len(): number;

/** The sigil-core version string. */
export function version(): string;

/** The full ready wasm binding object (also the shape helpers expect). */
export interface SigilWasm {
  totp: typeof totp;
  hotp: typeof hotp;
  format_code: typeof format_code;
  seal_record: typeof seal_record;
  open_record: typeof open_record;
  seal_to_container: typeof seal_to_container;
  open_container: typeof open_container;
  container_params: typeof container_params;
  reseal_params: typeof reseal_params;
  hybrid_x25519_public: typeof hybrid_x25519_public;
  hybrid_mlkem_encaps_key: typeof hybrid_mlkem_encaps_key;
  hybrid_seal_to_container: typeof hybrid_seal_to_container;
  hybrid_open_container: typeof hybrid_open_container;
  vault_key_wrap_aad: typeof vault_key_wrap_aad;
  hybrid_auth_seal_to_container: typeof hybrid_auth_seal_to_container;
  hybrid_auth_open_container: typeof hybrid_auth_open_container;
  ed25519_public_key: typeof ed25519_public_key;
  ed25519_sign: typeof ed25519_sign;
  ed25519_verify: typeof ed25519_verify;
  recovery_encode: typeof recovery_encode;
  recovery_decode: typeof recovery_decode;
  recovery_derive_ed25519_seed: typeof recovery_derive_ed25519_seed;
  recovery_derive_x25519_secret: typeof recovery_derive_x25519_secret;
  recovery_derive_mlkem_seed: typeof recovery_derive_mlkem_seed;
  recovery_format: typeof recovery_format;
  entry_id: typeof entry_id;
  nonce_len: typeof nonce_len;
  recommended_salt_len: typeof recommended_salt_len;
  version: typeof version;
}

/** Resolve to the ready wasm binding object. */
export function initWasm(): Promise<SigilWasm>;

// ── totp-vault helpers ──────────────────────────────────────────────────────

export const TOTP_VAULT_VERSION: number;
/** Highest `min_reader_version` this build can satisfy. */
export const TOTP_VAULT_READER_VERSION: number;

export interface TotpEntry {
  label: string;
  issuer?: string;
  /** STANDARD base64 of the raw key bytes. */
  secret: string;
  /** "sha1" | "sha256" | "sha512" (lowercase). */
  algorithm: string;
  digits: number;
  period: number;
  /** Stable RFC 4122 v4 entry id. Absent on entries written before Phase 59. */
  uuid?: string;
  /**
   * ⭐ Fields written by a NEWER client that this build does not understand.
   * They are preserved verbatim — do not rebuild an entry field-by-field.
   */
  [unknownField: string]: unknown;
}

export interface TotpVault {
  /** What WROTE this vault. */
  version: number;
  /**
   * What a reader must UNDERSTAND. Refuse iff this exceeds
   * `TOTP_VAULT_READER_VERSION`; absent means "the vault's own `version`".
   */
  min_reader_version?: number;
  entries: TotpEntry[];
  /**
   * ⭐ The REMOVE half of the vault's 2P-Set (Phase 61). An entry whose identity
   * appears here is suppressed no matter how many snapshots still contain it.
   * OMITTED when empty, so a vault that has never had a delete keeps the exact
   * byte shape earlier builds wrote.
   */
  tombstones?: Tombstone[];
  /** ⭐ Unknown top-level fields, preserved verbatim. Use `cloneVault`. */
  [unknownField: string]: unknown;
}

/** One removed entry, recorded so the removal survives a merge (Phase 61). */
export interface Tombstone {
  /** The removed entry's identity. */
  uuid: string;
  /** Unix seconds, from the CALLER's clock. Informational — no merge branches on it. */
  deleted_at?: number;
  [unknownField: string]: unknown;
}

/** What `mergeVaults` did, for a caller to report to a human. */
export interface MergeResult {
  vault: TotpVault;
  added: number;
  removed: number;
  tombstonesAdded: number;
  changed: boolean;
  conflicts: string[];
}

/** What `mergeOpsInto` did over a run of op-log snapshots. */
export interface MergeOpsResult {
  vault: TotpVault;
  applied: number;
  /** Ops that would not open under this secret — skipped and NAMED, never fatal. */
  skipped: { seq: number; reason: string }[];
  tip: number;
  added: number;
  removed: number;
  changed: boolean;
  conflicts: string[];
}

export interface AddEntryInput {
  label: string;
  issuer?: string;
  secretBytes: Uint8Array;
  algorithm: string;
  digits: number;
  period: number;
  /** Omit to draw one; pass `null` to write no `uuid` field at all. */
  uuid?: string | null;
}

export interface Argon2Params {
  m_cost: number;
  t_cost: number;
  p_cost: number;
}

export function base64ToBytes(b64: string): Uint8Array;
export function bytesToBase64(bytes: Uint8Array | ArrayLike<number>): string;
export function base32Decode(input: string): Uint8Array;
export function newVault(): TotpVault;
export function addEntry(vault: TotpVault, input: AddEntryInput): TotpVault;

/**
 * ⛔ THE TOMBSTONE GROWTH LIMIT. A vault is a 2P-Set: its remove-set NEVER
 * shrinks, nothing anywhere prunes a tombstone, and there is no compaction
 * command. `sigild` caps one op body at `MAX_OP_BODY_BYTES` (64 KiB) and answers
 * 413 above it, at which point there is no supported way to shrink the vault.
 *
 * ⭐ Call `opBodySizeWarning(container.length)` BEFORE every push and show the
 * string: a user who first meets this AT the 413 has already lost sync.
 * Returns `null` below `OP_BODY_WARN_BYTES` (75% of the cap).
 */
export const MAX_OP_BODY_BYTES: number;
export const OP_BODY_WARN_BYTES: number;
export function opBodySizeWarning(containerLen: number): string | null;
/**
 * ⭐ Clone a vault for editing WITHOUT dropping fields this build does not know.
 * Use instead of `{ version: v.version, entries: [...v.entries] }`.
 */
export function cloneVault(vault: TotpVault): TotpVault;
export function checkVaultReadable(vault: TotpVault): void;
/**
 * Read the Argon2id work factors a `SIGILcli` container declares, without a
 * password and without opening it. Throws on a header that is not ours.
 */
export function containerParams(
  wasm: Pick<SigilWasm, "container_params">,
  containerBytes: Uint8Array,
): Argon2Params;
/**
 * ⭐ THE NO-DOWNGRADE RATCHET — call at EVERY re-seal. Returns the componentwise
 * max of what `existingContainer` declares and `requested`, so a browser edit can
 * never write a weaker header than the one it read. `null` (a first seal) returns
 * `requested` unchanged; an unparsable container also falls back to `requested`,
 * never to something weaker.
 */
export function ratchetParams(
  wasm: Pick<SigilWasm, "reseal_params">,
  existingContainer: Uint8Array | null | undefined,
  requested: Argon2Params,
): Argon2Params;
export function formatEntryUuid(random16: Uint8Array | ArrayLike<number>): string;
export function randomEntryUuid(): string;

// ── entry identity and the 2P-Set merge (Phase 61) ──────────────────────────

/** The content-derived id of an entry — reaches `sigil_core::entry_id`. */
export function entryContentId(
  wasm: Pick<SigilWasm, "entry_id">,
  entry: TotpEntry,
  disambiguator?: number,
): string;
/** The identity an entry is MERGED by: its `uuid`, else its content-derived id. */
export function entryIdentity(wasm: Pick<SigilWasm, "entry_id">, entry: TotpEntry): string;
/**
 * The content FINGERPRINT, ignoring any `uuid`. ⭐ This — not `entryIdentity` —
 * is what ADD and IMPORT must compare: a candidate carries no id while the copy
 * in the vault carries a random one.
 */
export function entryFingerprint(wasm: Pick<SigilWasm, "entry_id">, entry: TotpEntry): string;
/** Give every entry a stable id, deterministically and idempotently. Mutates. */
export function normalizeVault(wasm: Pick<SigilWasm, "entry_id">, vault: TotpVault): TotpVault;
/** Serialize a vault as it is stored, with an empty `tombstones` omitted. */
export function vaultToJson(vault: TotpVault): string;
/** ⭐ Join two snapshots. Commutative, associative, idempotent; delete wins. */
export function mergeVaults(
  wasm: Pick<SigilWasm, "entry_id">,
  local: TotpVault,
  remote: TotpVault,
): MergeResult;
/**
 * ⭐ Fold EVERY op into `local` instead of adopting the newest — the fix for
 * last-writer-wins. An op that will not open is skipped and NAMED, never fatal.
 */
export function mergeOpsInto(
  wasm: Pick<SigilWasm, "entry_id" | "open_container">,
  secret: string | Uint8Array,
  local: TotpVault,
  ops: { seq: number; container: Uint8Array }[],
): MergeOpsResult;
/** Remove an entry AND record a tombstone. Refuses an ambiguous label. */
export function removeEntry(
  wasm: Pick<SigilWasm, "entry_id">,
  vault: TotpVault,
  selector: { uuid?: string; label?: string },
  deletedAtUnix?: number,
): TotpEntry;
/** `addEntry` that refuses an account already present, compared by FINGERPRINT. */
export function addEntryChecked(
  wasm: Pick<SigilWasm, "entry_id">,
  vault: TotpVault,
  input: AddEntryInput,
): boolean;
export function openVault(
  wasm: Pick<SigilWasm, "open_container">,
  password: string | Uint8Array,
  containerBytes: Uint8Array,
): TotpVault;
export function codeForEntry(
  wasm: Pick<SigilWasm, "totp" | "format_code">,
  entry: TotpEntry,
  unixTimeSeconds: number,
): string;
export function sealVault(
  wasm: Pick<SigilWasm, "seal_to_container">,
  password: string | Uint8Array,
  vault: TotpVault,
  salt: Uint8Array,
  nonce: Uint8Array,
  params: Argon2Params,
): Uint8Array;

// ── sync helpers ────────────────────────────────────────────────────────────

export interface PushResult {
  seq: number;
}

/** One drained op: the verbatim container bytes plus the server chain hash. */
export interface PulledContainer {
  seq: number;
  container: Uint8Array;
  hash?: string;
}

/** Optional transport injection: a fetch-shaped function (e.g. a signing fetch). */
export interface SyncOptions {
  fetch?: (url: string, init?: RequestInit) => Promise<Response>;
}

export function pushContainer(
  baseUrl: string,
  vaultId: string,
  containerBytes: Uint8Array,
  opts?: SyncOptions,
): Promise<PushResult>;
export function pullContainers(
  baseUrl: string,
  vaultId: string,
  sinceOpt?: number,
  opts?: SyncOptions,
): Promise<PulledContainer[]>;

// ── device-auth helpers (sigild multi-device contract v3) ───────────────────

/**
 * A hybrid SECRET identity — the only thing that can open an envelope addressed
 * to this device. BOTH halves are secret; never persist them in plaintext.
 */
export interface HybridSecretIdentity {
  /** X25519 secret scalar (32 bytes). */
  x25519Secret: Uint8Array;
  /** ML-KEM-768 keygen seed `d‖z` (64 bytes). */
  mlkemSeed: Uint8Array;
}

/** The shareable PUBLIC half of a hybrid identity (what the registry stores). */
export interface HybridPublicIdentity {
  deviceId?: string;
  /** X25519 public key (32 bytes). */
  x25519PublicKey: Uint8Array;
  /** ML-KEM-768 encapsulation key (1184 bytes). */
  mlkemEncapsKey: Uint8Array;
  updatedAt?: string;
}

/** A local device identity: the server-assigned id plus the SECRET 32-byte seed. */
export interface DeviceIdentity {
  deviceId: string;
  /** SECRET Ed25519 seed. Never persist this in plaintext. */
  seed: Uint8Array;
  /** The server this identity was enrolled with (informational). */
  baseUrl?: string;
  /** SECRET hybrid identity for vault sharing; null when this device has none. */
  hybrid?: HybridSecretIdentity | null;
  /** SECRET per-vault keys this device holds (`vaultId -> 32 bytes`). */
  vaultKeys?: Record<string, Uint8Array>;
  /**
   * PUBLIC hybrid keys this device TRUSTS (Phase 50 pin store). Not secret, but
   * security-critical: rewriting it silences the key-substitution alarm, which is
   * why it rides inside the SEALED device-identity container.
   */
  pins?: HybridPinStore;
}

/** One pinned hybrid public key. Mirrors cli/src/lib.rs::HybridKeyPin. */
export interface HybridKeyPin {
  device_id: string;
  x25519_public_key: string;
  mlkem_encaps_key: string;
  safety_number: string;
  pinned_at: number;
  repins: number;
}

/** `device id -> the hybrid public key we trust for it`. */
export interface HybridPinStore {
  version: number;
  pins: Record<string, HybridKeyPin>;
}

/** An HTTP failure carrying the status, so 401 and 403 are distinguishable. */
export class DeviceAuthError extends Error {
  status: number;
  body: string;
}

export const DEVICE_SEED_LEN: number;
export const DEVICE_IDENTITY_VERSION: number;

export function generateDeviceSeed(): Uint8Array;
export function devicePublicKey(
  wasm: Pick<SigilWasm, "ed25519_public_key">,
  seed: Uint8Array,
): Uint8Array;
export function explainAuthStatus(status: number): string;
export function enrollTokenHash(token: string): Promise<string>;
export function canonicalV3Message(
  deviceId: string,
  method: string,
  path: string,
  query: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array,
): Uint8Array;
export function canonicalEnrollMessage(
  tokenHashHex: string,
  timestamp: string,
  nonce: string,
  publicKeyB64: string,
  label: string,
): Uint8Array;

export function enrollDevice(
  wasm: Pick<SigilWasm, "ed25519_public_key" | "ed25519_sign">,
  args: { baseUrl: string; token: string; label?: string; seed: Uint8Array },
): Promise<{
  deviceId: string;
  publicKey: Uint8Array;
  publicKeyB64: string;
  label: string;
  status: string;
  createdAt: string;
  /**
   * The ACCOUNT this device now belongs to (Phase 52). An OPERATOR token founds
   * a new account; an account INVITE passed as `token` JOINS the inviter's.
   * `""` against a server without the account model.
   */
  accountId: string;
}>;

export function signedFetch(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity & { baseUrl: string },
  method: string,
  path: string,
  query?: string,
  bodyBytes?: Uint8Array | null,
  headers?: Record<string, string>,
): Promise<Response>;

export function makeSignedFetch(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
): (url: string, init?: RequestInit) => Promise<Response>;

export function pushContainerAuthed(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
  vaultId: string,
  containerBytes: Uint8Array,
  /**
   * `onResponse` receives the raw Response BEFORE its body is read — the only
   * way to see sigild's X-Sigil-Entitlement* grace warning, which rides on a
   * write that is still being SERVED (a 2xx) and so never appears in an error.
   */
  opts?: { onResponse?: (res: Response) => void },
): Promise<PushResult>;

export function pullContainersAuthed(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
  vaultId: string,
  sinceOpt?: number,
): Promise<PulledContainer[]>;

export function grantVaultAccess(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
  vaultId: string,
  granteeDeviceId: string,
  permission?: "read" | "write",
): Promise<unknown>;

export function listVaultGrants(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
  vaultId: string,
): Promise<unknown>;

export function revokeSelf(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
): Promise<unknown>;

export function revokeDeviceAdmin(args: {
  baseUrl: string;
  adminToken: string;
  deviceId: string;
}): Promise<unknown>;

export function listDevices(args: { baseUrl: string; adminToken: string }): Promise<unknown>;

// ── accounts (Phase 52) ─────────────────────────────────────────────────────
//
// An account groups one person's own devices; it is what a subscription and a
// vault's ownership belong to. NO call here names an account — the server reads
// it off the verified signature. A second device JOINS by passing an invite to
// the UNCHANGED `enrollDevice` as its `token`.
//
// ⚠️ Membership grants AUTHORIZATION, never DECRYPTION: a joined device reads
// nothing until a member wraps the vault key to it (see the sharing helpers).
// There is NO RECOVERY — lose every device and the account is unreachable.

/** One member device as reported by `GET /v1/account`. Metadata only. */
export interface AccountMember {
  device_id: string;
  label?: string;
  status?: string;
  created_at?: string;
  revoked_at?: string;
  account_id?: string;
}

/** The caller's own account. There is no route that reads another. */
export interface AccountInfo {
  account_id: string;
  created_at?: string;
  /**
   * ACTIVE devices only — this is what `device_limit` bounds. The cap is on
   * CONCURRENT devices, so a revoked device frees its seat.
   */
  device_count: number;
  /** Revoked members, reported separately rather than folded into the limit. */
  revoked_device_count?: number;
  device_limit: number;
  /** Every member, ACTIVE AND REVOKED — history is listed, it just does not count. */
  devices: AccountMember[];
}

/** An OPEN invite in a listing: the PUBLIC handle and metadata, never a secret. */
export interface AccountInviteInfo {
  invite_id: string;
  created_by_device_id?: string;
  created_at?: string;
  expires_at?: string;
  pinned?: boolean;
}

/**
 * A freshly minted invite. ⚠️ `invite` is a BEARER SECRET returned exactly ONCE:
 * show it, do not persist it, clear it after use.
 */
export interface CreatedAccountInvite {
  invite_id: string;
  invite: string;
  account_id?: string;
  expires_at?: string;
  pinned?: boolean;
}

export function getAccount(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
): Promise<AccountInfo>;

export function createAccountInvite(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
  opts?: { ttlSeconds?: number; inviteePublicKey?: Uint8Array | null },
): Promise<CreatedAccountInvite>;

export function listAccountInvites(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
): Promise<{ invites: AccountInviteInfo[] }>;

export function revokeAccountInvite(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  identity: DeviceIdentity,
  baseUrl: string,
  inviteId: string,
): Promise<{ invite_id: string; revoked: boolean }>;

/** Seal a device identity into a password-protected SIGILcli container. */
export function sealDeviceIdentity(
  wasm: Pick<SigilWasm, "seal_to_container">,
  password: string | Uint8Array,
  identity: DeviceIdentity,
  salt: Uint8Array,
  nonce: Uint8Array,
  params: Argon2Params,
): Uint8Array;

/** Open a sealed device-identity container. Throws on a wrong password. */
export function openDeviceIdentity(
  wasm: Pick<SigilWasm, "open_container">,
  password: string | Uint8Array,
  containerBytes: Uint8Array,
): DeviceIdentity;

// ── sharing helpers (device-to-device vault sharing) ────────────────────────

/**
 * The auth context every sharing call takes: an unlocked device identity plus
 * the server it is enrolled with. This is exactly what {@link openDeviceIdentity}
 * returns, so an unlocked client passes its identity straight in.
 */
export interface SharingAuth extends DeviceIdentity {
  baseUrl: string;
}

export const VAULT_KEY_LEN: number;
export const HYBRID_X25519_SECRET_LEN: number;
export const HYBRID_X25519_PUBLIC_LEN: number;
export const HYBRID_MLKEM_SEED_LEN: number;
export const HYBRID_MLKEM_ENCAPS_LEN: number;
export const KEY_ENVELOPE_MAGIC: string;
/** `SIGILhyb` version 1 — the ANONYMOUS form. NEVER a vault-key envelope. */
export const KEY_ENVELOPE_VERSION_ANONYMOUS: number;
/** `SIGILhyb` version 2 — AUTHENTICATED; the only version an unwrap accepts. */
export const KEY_ENVELOPE_VERSION_AUTHENTICATED: number;
/**
 * Fixed byte overhead of a wrapped 32-byte vault key, EXCLUDING the AAD (1208).
 * Replaces the old flat `WRAPPED_VAULT_KEY_LEN = 1226`, which was true only
 * while every hybrid container shared ONE fixed AAD — the very defect Phase 60
 * closed.
 */
export const WRAPPED_VAULT_KEY_OVERHEAD: number;
/** Exact envelope length for a given wrap context. */
export function wrappedVaultKeyLen(
  vaultId: string,
  recipientDeviceId: string,
  senderDeviceId: string,
): number;
/**
 * Byte length (24) of the vault-key-wrap AAD's domain-separation prefix.
 * Deliberately a length, not a copy of the literal: the AAD is single-sourced in
 * `sigil-core` and reached through `vaultKeyWrapAad`, so a JS copy of the domain
 * string would be a drift surface for no benefit.
 */
export const VAULT_KEY_WRAP_AAD_PREFIX_LEN: number;

/** The `SIGILhyb` container version byte, or `null` if the bytes are not one. */
export function keyEnvelopeVersion(envelopeBytes: Uint8Array): number | null;

/** The CONTEXT a vault-key envelope is bound to. Both sides MUST build it identically. */
export interface VaultKeyWrapContext {
  vaultId: string;
  recipientDeviceId: string;
  senderDeviceId: string;
}

/** The SENDING half of a wrap: which device we are, and the secret proving it. */
export interface SenderIdentity {
  deviceId: string;
  hybrid: HybridSecretIdentity;
}

/** Build the context-bound AAD bytes (single-sourced through the wasm/core). */
export function vaultKeyWrapAad(
  wasm: Pick<SigilWasm, "vault_key_wrap_aad">,
  vaultId: string,
  recipientDeviceId: string,
  senderDeviceId: string,
): Uint8Array;

/** Bundle a device id with the hybrid secret identity that authenticates it. */
export function senderIdentity(
  deviceId: string,
  hybridSecret: HybridSecretIdentity,
): SenderIdentity;

/** The sender identity implied by an unlocked client's `auth`. */
export function senderFromAuth(auth: SharingAuth): SenderIdentity;

/**
 * ⛔ Thrown when a vault-key slot is handed a container that is not an
 * AUTHENTICATED (version 2) envelope — in practice a version-1 anonymous one.
 *
 * ⭐ Its OWN class on purpose: NOT a 401 (the request authenticated fine), NOT a
 * 403 (nothing was forbidden), NOT a `KeyPinMismatchError` (no key changed). The
 * BYTES prove nothing about who produced them.
 */
export class UnauthenticatedEnvelopeError extends Error {
  readonly name: "UnauthenticatedEnvelopeError";
  readonly foundVersion: number;
  readonly expectedVersion: number;
}

/** ⛔ Thrown when an envelope cannot be attributed to an expected SENDER. */
export class UnknownSenderError extends Error {
  readonly name: "UnknownSenderError";
}

/**
 * ⛔ Thrown when the key recovered from an envelope does NOT open the vault's
 * newest op (step 4 of `acceptVault`, mirroring the CLI's `accept_vault_key`).
 * A key that opens nothing never reaches local state.
 */
export class VaultKeyDoesNotOpenError extends Error {
  readonly name: "VaultKeyDoesNotOpenError";
  readonly vaultId: string;
}

/**
 * ⛔ Thrown when accepting would REPLACE a DIFFERENT key already held for the
 * vault (step 5 of `acceptVault`). Legitimate after a rotation — pass
 * `replace: true`. Both fingerprints are SHA-256 prefixes, never key bytes.
 */
export class VaultKeyReplacementError extends Error {
  readonly name: "VaultKeyReplacementError";
  readonly vaultId: string;
  readonly heldFingerprint: string;
  readonly offeredFingerprint: string;
}

/**
 * Normalize/validate the map of vault keys a client already holds. FAILS CLOSED
 * on `null`/`undefined` for the same reason `requirePinStore` does.
 */
export function requireHeldVaultKeys(
  keys: Record<string, Uint8Array> | null | undefined,
): Record<string, Uint8Array>;

/**
 * A sender whose hybrid public key passed the unwrap gate. It CANNOT be
 * constructed directly — only `verifySenderForUnwrap` / `verifiedSenderFromLocal`
 * produce one, which is what makes `unwrapVaultKey`'s signature a proof.
 */
export class VerifiedSender {
  private constructor();
  readonly deviceId: string;
  readonly identity: HybridPublicIdentity;
  readonly trust: RecipientTrust;
  readonly safetyNumber: string;
  readonly x25519PublicKey: Uint8Array;
}

/** ⭐ THE UNWRAP GATE: resolve + pin-check the DEPOSITING device's key. */
export function verifySenderForUnwrap(
  wasm: SigilWasm,
  auth: SharingAuth,
  deviceId: string,
  opts?: { pins?: HybridPinStore | null; expectedSafetyNumber?: string | null },
): Promise<VerifiedSender>;

/** The sender is an identity this process holds the SECRET half of — no fetch. */
export function verifiedSenderFromLocal(
  wasm: Pick<SigilWasm, "hybrid_x25519_public" | "hybrid_mlkem_encaps_key">,
  sender: SenderIdentity,
): Promise<VerifiedSender>;

/** Plain-language explanation of a sharing-endpoint status (401/403/404/409/413). */
export function explainSharingStatus(status: number): string;

/** Draw a fresh hybrid SECRET identity from the CSPRNG. */
export function generateHybridIdentity(): HybridSecretIdentity;

/** Derive the shareable PUBLIC half of a hybrid identity, in the wasm. */
export function hybridPublicIdentity(
  wasm: Pick<SigilWasm, "hybrid_x25519_public" | "hybrid_mlkem_encaps_key">,
  secretIdentity: HybridSecretIdentity,
): HybridPublicIdentity;

/** PUBLISH this device's hybrid PUBLIC key (self-only; upsert). */
export function publishHybridKey(
  wasm: SigilWasm,
  auth: SharingAuth,
  secretIdentity?: HybridSecretIdentity | null,
): Promise<{ deviceId: string; updatedAt: string }>;

/** FETCH another device's published hybrid PUBLIC key. */
export function fetchHybridKey(
  wasm: SigilWasm,
  auth: SharingAuth,
  deviceId: string,
): Promise<HybridPublicIdentity>;

/** Draw a fresh 32-byte VAULT KEY from the CSPRNG. */
export function generateVaultKey(): Uint8Array;

/** First 16 hex chars of SHA-256(key) — a non-reversible fingerprint. */
export function vaultKeyFingerprint(key: Uint8Array): Promise<string>;

/**
 * ⭐ WRAP a vault key to a recipient's hybrid public key, AUTHENTICATED as
 * `sender` and BOUND to `ctx` (fresh entropy per call).
 *
 * `ctx.senderDeviceId` MUST equal `sender.deviceId`.
 */
export function wrapVaultKey(
  wasm: Pick<
    SigilWasm,
    "hybrid_auth_seal_to_container" | "vault_key_wrap_aad" | "nonce_len"
  >,
  sender: SenderIdentity,
  recipientPublic: HybridPublicIdentity,
  ctx: VaultKeyWrapContext,
  vaultKey: Uint8Array,
): Uint8Array;

/**
 * ⭐ UNWRAP an envelope with this device's hybrid SECRET identity — but ONLY as a
 * record from `sender`, and ONLY under `ctx`. Throws
 * `UnauthenticatedEnvelopeError` for a version-1 container, and on any AEAD
 * failure (wrong recipient, WRONG SENDER, tampered bytes, re-filed context).
 */
export function unwrapVaultKey(
  wasm: Pick<SigilWasm, "hybrid_auth_open_container" | "vault_key_wrap_aad">,
  mySecretIdentity: HybridSecretIdentity,
  sender: VerifiedSender,
  ctx: VaultKeyWrapContext,
  envelopeBytes: Uint8Array,
): Uint8Array;

/** DEPOSIT an opaque wrapped vault key addressed to one device. */
export function putKeyEnvelope(
  wasm: SigilWasm,
  auth: SharingAuth,
  vaultId: string,
  recipientDeviceId: string,
  envelopeBytes: Uint8Array,
): Promise<{ vaultId: string; deviceId: string; sizeBytes: number; createdAt: string }>;

/** COLLECT the opaque envelope addressed to a device (addressee only). */
export function getKeyEnvelope(
  wasm: SigilWasm,
  auth: SharingAuth,
  vaultId: string,
  deviceId?: string | null,
): Promise<Uint8Array>;

/** SHARE a vault: gate + wrap (authenticated), then GRANT, then deposit. */
export function shareVault(
  wasm: SigilWasm,
  auth: SharingAuth,
  args: {
    vaultId: string;
    recipientDeviceId: string;
    vaultKey: Uint8Array;
    permission?: "read" | "write";
    pins?: HybridPinStore | null;
    /**
     * The recipient's safety number, read out of band. Optional for an ordinary
     * device; REQUIRED for a RECOVERY KIT this client has never pinned (the
     * wrap gate throws `UnverifiedRecoveryKitError` otherwise).
     */
    expectedSafetyNumber?: string | null;
    /** The AUTHENTICATING identity; defaults to this client's own (`auth`). */
    sender?: SenderIdentity | null;
  },
): Promise<{
  recipientDeviceId: string;
  envelope: Uint8Array;
  envelopeBytes: number;
  permission: string;
  fingerprint: string;
  /** How trust in the recipient's key was established. */
  trust: RecipientTrust;
  /** "first-sight" means this key has NOT been verified by a human yet. */
  pinStatus: "first-sight" | "match";
  safetyNumber: string;
  pins: HybridPinStore;
}>;

/** ACCEPT a vault shared to this device: collect, unwrap, return the key. */
export function acceptVault(
  wasm: SigilWasm,
  auth: SharingAuth,
  args: {
    vaultId: string;
    secretIdentity?: HybridSecretIdentity | null;
    /**
     * The device that DEPOSITED the envelope. Omitted, it is read from this
     * device's own self-only envelope index; if that does not name one, the
     * accept is REFUSED with `UnknownSenderError` rather than unwrapping
     * anonymously.
     */
    senderDeviceId?: string | null;
    /** The sender's safety number, read out of band (closes first contact). */
    expectedSafetyNumber?: string | null;
    pins?: HybridPinStore | null;
    /**
     * The vault keys this client ALREADY HOLDS, so an accept cannot silently
     * REPLACE one. FAILS CLOSED like `pins`: pass `device.vaultKeys`, or `{}` if
     * you deliberately hold none. Defaults to `auth.vaultKeys`.
     */
    heldKeys?: Record<string, Uint8Array> | null;
    /**
     * Explicit opt-in to replacing a DIFFERENT key already held for this vault
     * (the CLI spells this `--replace`). Without it, that case is
     * `VaultKeyReplacementError`.
     */
    replace?: boolean;
  },
): Promise<{
  vaultId: string;
  vaultKey: Uint8Array;
  envelope: Uint8Array;
  fingerprint: string;
  /** The device whose static key the envelope was AUTHENTICATED against. */
  senderDeviceId: string;
  senderTrust: RecipientTrust;
  senderSafetyNumber: string;
  /** Persist this — the sender is now pinned. */
  pins: HybridPinStore;
  /**
   * Whether the recovered key was PROVED to open this vault's newest op. `false`
   * only when the server holds no vault yet — never when an open was attempted
   * and failed (that throws `VaultKeyDoesNotOpenError`).
   */
  verifiedAgainstTip: boolean;
  /** The newest op, already pulled and already proven to open. `null` if none. */
  tipContainer: Uint8Array | null;
  /** Fingerprint of the key this one replaced (needs `replace`), else `null`. */
  replaced: string | null;
}>;

// ── Phase 50: safety numbers, key pinning, rotation ─────────────────────────

export const SAFETY_NUMBER_PREFIX: string;
export const SAFETY_NUMBER_PAIR_PREFIX: string;
export const SAFETY_NUMBER_GROUPS: number;
export const SAFETY_NUMBER_BYTES_PER_GROUP: number;
export const HYBRID_PIN_STORE_VERSION: number;

/** Raw 32-byte digest over the device id + FULL hybrid public key material. */
export function hybridSafetyDigest(
  deviceId: string,
  publicIdentity: HybridPublicIdentity,
): Promise<Uint8Array>;

/** Render a digest as six space-separated 5-digit groups. */
export function renderSafetyNumber(digest: Uint8Array): string;

/**
 * The human-comparable SAFETY NUMBER of one device's hybrid public key. Read it
 * aloud over a channel the SERVER DOES NOT CONTROL to verify a key before the
 * first share — pinning cannot protect first contact.
 */
export function safetyNumber(
  deviceId: string,
  publicIdentity: HybridPublicIdentity,
): Promise<string>;

/** ORDER-INDEPENDENT pairwise safety number: both sides see the same string. */
export function pairwiseSafetyNumber(
  a: { deviceId: string; identity: HybridPublicIdentity },
  b: { deviceId: string; identity: HybridPublicIdentity },
): Promise<string>;

/** ⚠️ Thrown when a device's published hybrid key differs from the pinned one. */
export class KeyPinMismatchError extends Error {
  deviceId: string;
  pinnedSafetyNumber: string;
  presentedSafetyNumber: string;
}

/** A fresh, empty pin store. */
export function newPinStore(): HybridPinStore;

/** Validate/normalize a pin store (null/undefined => empty). */
export function requirePinStore(store: HybridPinStore | null | undefined): HybridPinStore;

/**
 * THE CHOKE POINT: pin on first sight, proceed when unchanged, THROW
 * KeyPinMismatchError when changed. Never accepts a changed key.
 */
export function checkAndPin(
  pins: HybridPinStore | null,
  deviceId: string,
  identity: HybridPublicIdentity,
): Promise<{ status: "first-sight" | "match"; safetyNumber: string; changed: false }>;

/** ⚠️ EXPLICIT re-pin — the ONLY way a changed key is ever accepted. */
export function repinHybridKey(
  pins: HybridPinStore | null,
  deviceId: string,
  identity: HybridPublicIdentity,
): Promise<{ previousSafetyNumber: string | null; safetyNumber: string; repins: number }>;

/** ⛔ A wrap targeted a RECOVERY KIT this client has never pinned, with no safety number. */
export class UnverifiedRecoveryKitError extends Error {
  deviceId: string;
  presentedSafetyNumber: string;
}

/** ⛔ A supplied safety number did not match the key the server is serving. */
export class SafetyNumberMismatchError extends Error {
  deviceId: string;
  expectedSafetyNumber: string;
  presentedSafetyNumber: string;
}

/** How trust in a recipient's hybrid key was established. */
export type RecipientTrust =
  | "derived"
  | "pinned"
  | "verified-first-sight"
  | "unverified-first-sight";

export const TRUST_DERIVED: "derived";
export const TRUST_PINNED: "pinned";
export const TRUST_VERIFIED_FIRST_SIGHT: "verified-first-sight";
export const TRUST_UNVERIFIED_FIRST_SIGHT: "unverified-first-sight";

/**
 * ⭐⭐ THE WRAP GATE. Resolve a recipient's hybrid key AND establish trust in it
 * in ONE call. `shareVault`, `rotateVaultKey` and `coverVault` all go through
 * this; nothing wraps a vault key without it.
 */
export function verifyRecipientForWrap(
  wasm: SigilWasm,
  auth: SharingAuth,
  deviceId: string,
  opts?: {
    pins?: HybridPinStore | null;
    expectedSafetyNumber?: string | null;
    knownRecoveryKit?: boolean;
  },
): Promise<{
  deviceId: string;
  identity: HybridPublicIdentity;
  trust: RecipientTrust;
  safetyNumber: string;
  pins: HybridPinStore;
}>;

// fetchHybridKeyPinned was DELETED in Phase 57 (see sharing.mjs). It was ADR
// 0038's choke point, superseded by verifyRecipientForWrap above, and an
// exported fetch-and-pin WITHOUT the recovery-kit refusal is a ready-made bypass
// of the wrap gate. Use verifyRecipientForWrap to wrap, fetchHybridKey to display.

/** LIST which devices hold an envelope for a vault (owner, WRITE; metadata only). */
export function listKeyEnvelopes(
  wasm: SigilWasm,
  auth: SharingAuth,
  vaultId: string,
): Promise<
  { deviceId: string; senderDeviceId: string; sizeBytes: number; createdAt: string }[]
>;

/** DELETE one device's envelope (owner, WRITE). false = nothing was there. */
export function deleteKeyEnvelope(
  wasm: SigilWasm,
  auth: SharingAuth,
  vaultId: string,
  deviceId: string,
): Promise<boolean>;

/**
 * ROTATE a vault key: fresh key, re-seal, re-wrap to exactly these devices,
 * delete every other envelope. Protects FUTURE content only.
 */
export function rotateVaultKey(
  wasm: SigilWasm,
  auth: SharingAuth,
  args: {
    vaultId: string;
    recipientDeviceIds: string[];
    sealedVault: Uint8Array;
    oldVaultKey: Uint8Array;
    params?: Argon2Params;
    salt?: Uint8Array | null;
    nonce?: Uint8Array | null;
    pins?: HybridPinStore | null;
    /**
     * Devices whose envelope may be DELETED. A current holder named by NEITHER
     * `recipientDeviceIds` nor `drop` throws `RecipientsWouldBeDroppedError`
     * (Phase 54): destroying access must be stated, not implied.
     */
    drop?: string[];
    /**
     * `{ [deviceId]: "the printed digits" }` for any recipient verified out of
     * band. REQUIRED for a first-sight RECOVERY KIT — the wrap gate throws
     * `UnverifiedRecoveryKitError` otherwise, before anything is mutated.
     */
    safetyNumbers?: Record<string, string>;
    /** The AUTHENTICATING identity for every re-wrap; defaults to `auth`'s. */
    sender?: SenderIdentity | null;
  },
): Promise<{
  vaultKey: Uint8Array;
  sealedVault: Uint8Array;
  oldFingerprint: string;
  newFingerprint: string;
  rewrapped: { deviceId: string; trust: RecipientTrust; pinStatus: string }[];
  removed: string[];
  pins: HybridPinStore;
}>;

// ── totp-migration helpers ──────────────────────────────────────────────────

export function base32Encode(bytes: Uint8Array): string;
export function parseOtpauthUri(uri: string): TotpEntry;
export function buildOtpauthUri(entry: TotpEntry): string;
/**
 * ⭐ One decoded `otpauth-migration://` URI — i.e. ONE QR CODE. Google
 * Authenticator splits a large export across several, each carrying a SLICE of
 * the accounts, so `entries` is not necessarily the whole export.
 */
export interface MigrationBatch {
  /** The accounts THIS payload carried. */
  entries: TotpEntry[];
  version: number;
  /** How many QR codes the export was split into; 0/1 means a single one. */
  batchSize: number;
  /** Zero-based index of this QR within the export. */
  batchIndex: number;
  /** Shared id linking the QR codes of one export. */
  batchId: number;
  /** False when there are other QR codes still to import. */
  complete: boolean;
  /**
   * ⭐ True when this was the LAST QR of a multi-QR export — i.e. `complete` is
   * false, but nothing is OUTSTANDING. A UI keys its "INCOMPLETE" alarm off
   * `!finalBatch`, not off `batchNote` being non-null: telling someone who has
   * just scanned the last code that their import is partial is a false alarm,
   * and false alarms are what teach users to click past the real one.
   */
  finalBatch: boolean;
  /** A "batch i of N …" sentence when `complete` is false, else null. MUST be shown. */
  batchNote: string | null;
}

/**
 * ⚠️ Returns a batch, NOT an array. Check `complete` / `batchNote` before
 * telling a user the transfer finished.
 */
export function decodeMigrationUri(uri: string): MigrationBatch;
export function migrationBatchIsComplete(batch: { batchSize?: number }): boolean;
/** ⭐ True only for the LAST QR of a multi-QR export. See `MigrationBatch.finalBatch`. */
export function migrationBatchIsFinal(batch: {
  batchSize?: number;
  batchIndex?: number;
}): boolean;
export function migrationBatchNote(batch: {
  batchSize?: number;
  batchIndex?: number;
  batchId?: number;
  entries?: unknown[];
  otps?: unknown[];
}): string | null;
/**
 * ⛔ Throws for any entry the format cannot represent faithfully — including a
 * `period` other than 30 s, which the wire format cannot carry at all.
 */
export function encodeMigrationUri(entries: TotpEntry[]): string;

// ── recovery kit (Phase 54) ─────────────────────────────────────────────────
//
// A recovery kit is an ORDINARY MEMBER DEVICE whose private keys are derived
// from 32 bytes printed on paper. The server gains no concept of "recovery".
//
// ⚠️ `code` and everything in `RecoveryIdentity` are SECRETS. Render a code
// ONCE; never persist it, never log it, never put it in a URL.

/** The pin `origin` marker for a key DERIVED locally rather than fetched. */
export const PIN_ORIGIN_RECOVERY_KIT: "recovery-kit";

/** The visible device label a recovery kit enrolls under. */
// ⚠️ THIS LITERAL TYPE IS A THIRD HAND-WRITTEN COPY of the label and it drifts
// SILENTLY: a coordinated rename in cli/src/lib.rs and sigil-wasm/recovery.mjs
// leaves this declaration contradicting the runtime value while `tsc` stays
// clean. The golden assertion in sigil-wasm/test/recovery-interop.mjs is what
// actually pins the value; keep this in step with it.
export const RECOVERY_DEVICE_LABEL: "recovery-kit";

/** Bytes in a raw recovery secret. */
export const RECOVERY_SEED_LEN: 32;

/** Characters in a printed (ungrouped) recovery code. */
export const RECOVERY_KIT_CHARS: 56;

/** A recovery-kit failure that is not an HTTP failure. Carries no secret. */
export class RecoveryError extends Error {}

/**
 * Thrown by `rotateVaultKey` when a current envelope holder was named by
 * neither the new recipient set nor `drop`. Nothing was changed.
 */
export class RecipientsWouldBeDroppedError extends Error {
  vaultId: string;
  unknown: { deviceId: string; isRecoveryKit: boolean }[];
}

/** ⚠️ SECRET. The three seeds a recovery kit re-derives. */
export interface RecoveryIdentity {
  ed25519Seed: Uint8Array;
  hybrid: { x25519Secret: Uint8Array; mlkemSeed: Uint8Array };
}

/** Plain-language explanation of a recovery-endpoint status (401/403/404/501). */
export function explainRecoveryStatus(status: number): string;

/** Render a code as 7 groups of 8, hyphen-joined. */
export function formatRecoveryCode(wasm: SigilWasm, code: string): string;

/**
 * Decode + checksum a printed code OFFLINE. Makes NO network request, which is
 * what lets a client distinguish a typo from an unknown device.
 */
export function verifyRecoveryKit(wasm: SigilWasm, code: string): Uint8Array;

/** ⚠️ Derive the kit's SECRET identity from its recovery secret. */
export function deriveRecoveryIdentity(wasm: SigilWasm, seed: Uint8Array): RecoveryIdentity;

/** Which vaults hold a wrapped key for a device. SELF-ONLY; metadata only. */
export interface RecoverableVault {
  vaultId: string;
  senderDeviceId: string;
  sizeBytes: number;
  createdAt: string;
}

/**
 * ⚠️ `truncated` reflects the route's `has_more`. The per-device index has a hard
 * page cap and NO CURSOR, so a truncated answer means the rest is unreachable and
 * a caller must NOT report a partial recovery as a complete one.
 */
export type RecoverableVaultList = RecoverableVault[] & { readonly truncated: boolean };

export function listRecoverableVaults(
  wasm: SigilWasm,
  auth: SharingAuth,
  deviceId?: string | null,
): Promise<RecoverableVaultList>;

/** Pin a key this client DERIVED itself (origin "recovery-kit"). Never replaces. */
export function pinDerivedKey(
  pins: HybridPinStore,
  deviceId: string,
  publicIdentity: { x25519PublicKey: Uint8Array; mlkemEncapsKey: Uint8Array },
): Promise<HybridPinStore>;

/** The DERIVED pin for a device, if this client holds one. */
export function derivedPin(
  pins: HybridPinStore,
  deviceId: string,
): { x25519PublicKey: Uint8Array; mlkemEncapsKey: Uint8Array } | null;

/**
 * Generate a kit and cover a set of vaults with it. It VERIFIES ITSELF end to
 * end before returning, and revokes the partial kit on any failure.
 *
 * ⚠️ `code` is THE SECRET.
 */
export function generateRecoveryKit(
  wasm: SigilWasm,
  auth: SharingAuth,
  args: {
    vaultKeys?: { vaultId: string; vaultKey: Uint8Array }[];
    pins?: HybridPinStore | null;
    inviteTtlSeconds?: number | null;
  },
): Promise<{
  code: string;
  formatted: string;
  deviceId: string;
  accountId: string;
  baseUrl: string;
  safetyNumber: string;
  covered: { vaultId: string; fingerprint: string }[];
  verification: {
    accountId: string;
    indexedVaults: number;
    unwrappedVault: string;
    fingerprint: string;
  };
  pins: HybridPinStore;
}>;

/**
 * Cover one more vault. From a client that did NOT generate the kit,
 * `expectedSafetyNumber` (printed on the sheet) is REQUIRED and must match.
 */
export function coverVault(
  wasm: SigilWasm,
  auth: SharingAuth,
  args: {
    kitDeviceId: string;
    vaultId: string;
    vaultKey: Uint8Array;
    pins?: HybridPinStore | null;
    expectedSafetyNumber?: string | null;
  },
): Promise<{
  vaultId: string;
  kitDeviceId: string;
  derived: boolean;
  fingerprint: string;
  envelopeBytes: number;
  pins: HybridPinStore;
}>;

/**
 * Restore from a printed kit on a client with NO local state. `deviceId` is
 * printed on the sheet and is NOT a secret. Nothing is persisted here — the
 * caller decides, and the browser clients keep everything sealed.
 */
export function restoreFromKit(
  wasm: SigilWasm,
  args: { baseUrl: string; code: string; deviceId: string },
): Promise<{
  deviceId: string;
  accountId: string;
  vaults: {
    vaultId: string;
    vaultKey: Uint8Array;
    fingerprint: string;
    /** The device that deposited the envelope, as AUTHENTICATED (Phase 60). */
    senderDeviceId: string;
    senderTrust: RecipientTrust;
    senderSafetyNumber: string;
  }[];
  /**
   * Vaults NOT restored, and why. A vault whose depositing device the server's
   * index does not name is SKIPPED rather than unwrapped anonymously.
   */
  skipped: { vaultId: string; reason: string }[];
  identity: RecoveryIdentity;
  /** The pin store this restore built (every sender pinned on first sight). */
  pins: HybridPinStore;
}>;

/** Revoke a kit and take back its envelopes. Does NOT auto-rotate. */
export function revokeRecoveryKit(
  wasm: SigilWasm,
  auth: SharingAuth,
  args: { kitDeviceId: string; vaultIds?: string[] },
): Promise<{
  kitDeviceId: string;
  removed: string[];
  alreadyClear: string[];
  rotateReminder: string;
}>;

// ── entitlement (ADR 0043, read side) ───────────────────────────────────────
//
// sigild may refuse WRITES from an account whose subscription lapsed past its
// grace period, with a `402`. It NEVER refuses reads, and never refuses giving a
// device of the caller's OWN account the key to a vault (so replacing a device
// and printing a recovery kit keep working). Say exactly that and nothing more.

export const HEADER_ENTITLEMENT: string;
export const HEADER_ENTITLEMENT_STATUS: string;
export const HEADER_ENTITLEMENT_GRACE_ENDS: string;
export const PAYMENT_REQUIRED_CODE: string;
/** The sentence that must never be softened: what is NOT refused. */
export const NEVER_REFUSED: string;
/** What a lapsed account actually loses: new uploads only. */
export const WHAT_IS_REFUSED: string;

/** ⚠️ A refusal for PAYMENT. Never render this as 401/403. */
export class PaymentRequiredError extends Error {
  status: 402;
  subscriptionStatus: string;
  graceEndedAt: string;
  readsAllowed: boolean;
  keyRecoveryAllowed: boolean;
  checkoutPath: string;
  detail: string;
}

/** The additive block on GET /v1/billing/subscription; absent when off. */
export interface EntitlementBlock {
  enforced: boolean;
  /** "allowed" | "grace" | "refused". */
  writes: string;
  /** ALWAYS "allowed". */
  reads: string;
  grace_ends_at?: string;
}

export interface SubscriptionInfo {
  subject: string;
  provider?: string;
  status: string;
  entitled: boolean;
  current_period_end?: string;
  updated_at?: string;
  entitlement?: EntitlementBlock;
}

export interface EntitlementState {
  level: "off" | "ok" | "grace" | "refused";
  enforced: boolean;
  status: string;
  writes: string;
  graceEndsAt: string;
  entitled: boolean;
}

/** Extract the structured 402 from any thrown transport error, else null. */
export function paymentRequiredFrom(err: unknown, what?: string): PaymentRequiredError | null;

/** Read the three warning headers off a SERVED response; null when healthy. */
export function readEntitlementHeaders(
  res: Response,
): { state: "grace" | "lapsed"; status: string; graceEndsAt: string } | null;

/** READ this device's ACCOUNT's subscription (never gated by entitlement). */
export function getSubscription(
  wasm: Pick<SigilWasm, "ed25519_sign">,
  auth: DeviceIdentity,
  baseUrl?: string | null,
): Promise<SubscriptionInfo>;

export function explainSubscriptionStatus(status: number): string;

/** Reduce a subscription response to one state; "off" means show NOTHING. */
export function entitlementState(subscription: SubscriptionInfo | null): EntitlementState;

export function formatInstant(iso: string): string;

/** User-facing text for a state. tone "billing" is NOT an error. */
export function describeEntitlement(state: EntitlementState): {
  tone: "none" | "info" | "warning" | "billing";
  headline: string;
  detail: string;
};

/** User-facing text for an actual 402, from the server's own body. */
export function describePaymentRequired(err: PaymentRequiredError): {
  tone: "billing";
  headline: string;
  detail: string;
};

// ── passkey-protected local containers (sigil-wasm/passkey.mjs, ADR 0046) ─────
//
// ⚠️ These declarations and the `export *` in index.mjs are TWO SEPARATE HOLES.
// Phase 56 shipped `recovery_*` typed here but never re-exported at runtime, so
// every browser call threw while `tsc` stayed clean. Keep both in step.

export const PASSKEY_PRF_DOMAIN: string;
export const HW_SLOT_VERSION: number;
export const PRF_OUTPUT_LEN: number;
export const CONTAINER_MASTER_KEY_LEN: number;
export const PASSKEY_TIMEOUT_MS: number;
export const CMK_HKDF_SALT: string;
export const CMK_HKDF_INFO: string;

export class PasskeyError extends Error {
  code: string;
}
export class PrfUnavailableError extends PasskeyError {}

/** Is the WebAuthn + subtle-crypto surface even present? NOT a claim that PRF works. */
export function passkeySupport(): { available: boolean; reason: string };

/** SHA-256(PASSKEY_PRF_DOMAIN) — the 32-byte PRF evaluation point. Not secret. */
export function prfSalt(): Promise<Uint8Array>;

/** BE/BS/UP/UV flags of a WebAuthn authenticatorData blob. */
export function backupFlags(authenticatorData: ArrayBuffer | Uint8Array | null): {
  userPresent: boolean;
  userVerified: boolean;
  backupEligible: boolean;
  backupState: boolean;
};

/** The ONE sentence the UI may say about scope, from the LAST ceremony's flags. */
export function describeProtectionScope(info: {
  backupEligible?: boolean;
  attachment?: string;
}): string;

export interface CreatedPasskey {
  credentialId: string;
  rpId: string;
  attachment: string;
  prfEnabled: boolean;
  backupEligible: boolean;
  backupState: boolean;
}

export function createPasskey(options?: {
  rpName?: string;
  userName?: string;
  userDisplayName?: string;
  userId?: Uint8Array | null;
  timeoutMs?: number;
}): Promise<CreatedPasskey>;

export interface PrfAssertion {
  prfOutput: Uint8Array;
  credentialId: string;
  backupEligible: boolean;
  backupState: boolean;
  /** Always true — a UV-less ceremony throws `uv_missing` instead of returning. */
  userVerified: boolean;
  /**
   * ⭐ The REAL `authenticatorAttachment` reported by the ceremony
   * ("platform" | "cross-platform" | ""). Never infer this from other flags.
   */
  attachment: string;
}

/**
 * Run ONE assertion (discoverable credential) and return its 32-byte PRF output.
 *
 * ⛔ Throws `PasskeyError` with code `uv_missing` if the ceremony completed
 * WITHOUT user verification: CTAP hmac-secret keys one secret with UV and a
 * different one without, so those bytes would be the wrong key.
 */
export function evaluatePrf(options?: {
  allowCredentials?: PublicKeyCredentialDescriptor[];
  timeoutMs?: number;
}): Promise<PrfAssertion>;

export interface PrfProbe {
  credentialId: string;
  rpId: string;
  attachment: string;
  prfOutput: Uint8Array;
  backupEligible: boolean;
  backupState: boolean;
}

/** create() + get() + get() again; 32 bytes, byte-identical, or it is UNSUPPORTED. */
export function probePrf(options?: {
  rpName?: string;
  userName?: string;
  userDisplayName?: string;
  userId?: Uint8Array | null;
  timeoutMs?: number;
}): Promise<PrfProbe>;

/** `R ‖ utf8(password)` — fed straight to the container's own Argon2id. */
export function hwSlotSecret(prfOutput: Uint8Array, password: string | Uint8Array): Uint8Array;

/** HKDF-SHA256 over the ADR 0042 recovery seed -> the 32-byte container master key. */
export function deriveContainerMasterKey(kitSeed: Uint8Array): Promise<Uint8Array>;

export interface HwSlot {
  version: number;
  cmk: Uint8Array;
  kitDeviceId: string;
  credentialId: string;
  rpId: string;
  backupEligible: boolean;
  backupState: boolean;
  createdAt: string;
}

export function sealHwSlot(
  wasm: Pick<SigilWasm, "seal_to_container">,
  slot: {
    prfOutput: Uint8Array;
    password: string | Uint8Array;
    cmk: Uint8Array;
    kitDeviceId?: string;
    credentialId?: string;
    rpId?: string;
    backupEligible?: boolean;
    backupState?: boolean;
  },
  salt: Uint8Array,
  nonce: Uint8Array,
  params: Argon2Params,
): Uint8Array;

export function openHwSlot(
  wasm: Pick<SigilWasm, "open_container">,
  prfOutput: Uint8Array,
  password: string | Uint8Array,
  container: Uint8Array,
): HwSlot;

/**
 * Passkey-specific wording. NEVER collapses into "wrong password".
 *
 * ⭐ Pass `{ atUnlock: true }` from an UNLOCK screen. The PRF-failure codes mean
 * "the control refused, nothing was written" during enable and "your containers
 * are already sealed with a key this authenticator can no longer derive" at
 * unlock — the second must point at the recovery sheet, not reassure.
 */
export function explainPasskeyStatus(
  err: unknown,
  options?: { atUnlock?: boolean },
): string;
