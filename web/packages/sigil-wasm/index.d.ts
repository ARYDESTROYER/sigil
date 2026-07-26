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

/** A local device identity: the server-assigned id plus the SECRET 32-byte seed. */
export interface DeviceIdentity {
  deviceId: string;
  /** SECRET Ed25519 seed. Never persist this in plaintext. */
  seed: Uint8Array;
  /** The server this identity was enrolled with (informational). */
  baseUrl?: string;
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

// ── totp-migration helpers ──────────────────────────────────────────────────

export function base32Encode(bytes: Uint8Array): string;
export function parseOtpauthUri(uri: string): TotpEntry;
export function buildOtpauthUri(entry: TotpEntry): string;
export function decodeMigrationUri(uri: string): TotpEntry[];
export function encodeMigrationUri(entries: TotpEntry[]): string;
