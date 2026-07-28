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
  hybrid_x25519_public: typeof hybrid_x25519_public;
  hybrid_mlkem_encaps_key: typeof hybrid_mlkem_encaps_key;
  hybrid_seal_to_container: typeof hybrid_seal_to_container;
  hybrid_open_container: typeof hybrid_open_container;
  ed25519_public_key: typeof ed25519_public_key;
  ed25519_sign: typeof ed25519_sign;
  ed25519_verify: typeof ed25519_verify;
  recovery_encode: typeof recovery_encode;
  recovery_decode: typeof recovery_decode;
  recovery_derive_ed25519_seed: typeof recovery_derive_ed25519_seed;
  recovery_derive_x25519_secret: typeof recovery_derive_x25519_secret;
  recovery_derive_mlkem_seed: typeof recovery_derive_mlkem_seed;
  recovery_format: typeof recovery_format;
  nonce_len: typeof nonce_len;
  recommended_salt_len: typeof recommended_salt_len;
  version: typeof version;
}

/** Resolve to the ready wasm binding object. */
export function initWasm(): Promise<SigilWasm>;

// ── totp-vault helpers ──────────────────────────────────────────────────────

export const TOTP_VAULT_VERSION: number;

export interface TotpEntry {
  label: string;
  issuer?: string;
  /** STANDARD base64 of the raw key bytes. */
  secret: string;
  /** "sha1" | "sha256" | "sha512" (lowercase). */
  algorithm: string;
  digits: number;
  period: number;
}

export interface TotpVault {
  version: number;
  entries: TotpEntry[];
}

export interface AddEntryInput {
  label: string;
  issuer?: string;
  secretBytes: Uint8Array;
  algorithm: string;
  digits: number;
  period: number;
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
export const WRAPPED_VAULT_KEY_LEN: number;

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

/** WRAP a vault key to a recipient's hybrid public key (fresh entropy per call). */
export function wrapVaultKey(
  wasm: Pick<SigilWasm, "hybrid_seal_to_container" | "nonce_len">,
  recipientPublic: HybridPublicIdentity,
  vaultKey: Uint8Array,
): Uint8Array;

/** UNWRAP an envelope with this device's hybrid SECRET identity. Throws. */
export function unwrapVaultKey(
  wasm: Pick<SigilWasm, "hybrid_open_container">,
  mySecretIdentity: HybridSecretIdentity,
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

/** SHARE a vault: fetch key, wrap, deposit, then grant — in one call. */
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
  args: { vaultId: string; secretIdentity?: HybridSecretIdentity | null },
): Promise<{
  vaultId: string;
  vaultKey: Uint8Array;
  envelope: Uint8Array;
  fingerprint: string;
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

/** FETCH a hybrid key AND enforce the pin. Throws KeyPinMismatchError. */
export function fetchHybridKeyPinned(
  wasm: SigilWasm,
  auth: SharingAuth,
  deviceId: string,
  pins?: HybridPinStore | null,
): Promise<{
  identity: HybridPublicIdentity;
  pinStatus: "first-sight" | "match";
  safetyNumber: string;
  pins: HybridPinStore;
}>;

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
export function decodeMigrationUri(uri: string): TotpEntry[];
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
export function listRecoverableVaults(
  wasm: SigilWasm,
  auth: SharingAuth,
  deviceId?: string | null,
): Promise<
  { vaultId: string; senderDeviceId: string; sizeBytes: number; createdAt: string }[]
>;

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
  vaults: { vaultId: string; vaultKey: Uint8Array; fingerprint: string }[];
  skipped: { vaultId: string; reason: string }[];
  identity: RecoveryIdentity;
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
