// totp-vault.mjs — a framework-free, dependency-free ESM module that reads and
// writes the SAME sealed TOTP vault the `sigil totp` CLI uses, so a browser and
// the CLI are cross-clients over ONE vault file (or one op-log vault).
//
// The vault at rest is a normal CLI-compatible SIGILcli container (the same
// self-describing Argon2id + XChaCha20-Poly1305 file that seal_to_container /
// open_container speak). Its DECRYPTED plaintext is a JSON TotpVault. This module
// performs NO cryptography of its own: it hands bytes to the wasm binding
// (open_container / seal_to_container) and computes codes via the wasm TOTP
// primitive (which itself only marshals to sigil-core). The OTP secret never
// leaves this process; the sigild op-log only ever sees the sealed container.
//
// ── THE VAULT JSON SCHEMA IS MIRRORED FROM cli/src/lib.rs — KEEP IT IN SYNC ──
//
//   TotpVault {
//     version: u8,                 // what WROTE this vault; this build writes 1
//     min_reader_version?: u8,     // OMITTED by this build (see below)
//     entries: TotpEntry[],
//     tombstones?: Tombstone[],    // ⭐ Phase 61; OMITTED when empty
//     ...unknown                   // ⭐ preserved verbatim
//   }
//   TotpEntry {
//     label:     string,          // ⚠️ NOT unique — see the identity note below
//     issuer?:   string,          // OMITTED entirely when absent (serde skip)
//     secret:    string,          // STANDARD base64 of the RAW key bytes
//     algorithm: string,          // "sha1" | "sha256" | "sha512"  (lowercase)
//     digits:    number,          // typically 6
//     period:    number,          // seconds, typically 30
//     uuid?:     string,          // ⭐ the entry's IDENTITY; OMITTED when absent
//     ...unknown                  // ⭐ preserved verbatim
//   }
//   Tombstone {
//     uuid:        string,        // the removed entry's identity
//     deleted_at?: number,        // unix seconds; NO merge decision branches on
//                                 // it (merged by MIN, so a hostile clock can
//                                 // only make a delete look EARLIER). It exists
//                                 // for a FUTURE compaction — see the tombstone
//                                 // growth limit near `opBodySizeWarning`.
//     ...unknown                  // ⭐ preserved verbatim
//   }
//
// ⛔ AND A TOMBSTONE IS KEPT FOREVER. The remove-set never shrinks, nothing here
// prunes it, and there is no compaction command anywhere in this repo — so a
// vault with enough removals eventually exceeds sigild's 64 KiB op cap and STOPS
// SYNCING, with no supported way to shrink it. `opBodySizeWarning` (below) is
// the whole mitigation: a warning, not a fix.
//
// A drift from that shape (an extra/renamed field, wrong casing, base32 instead
// of base64 in `secret`) breaks CLI<->browser interop. The cross-client Node
// test (test/totp-interop.mjs) is the guard: it has the CLI write a vault and
// this module read it (and vice versa) through a live opaque sigild.
//
// ── ⭐ FORWARD COMPATIBILITY (Phase 59) — why the two version knobs differ ────
//
// This schema is mirrored across FOUR clients (CLI, webapp, MV3 extension,
// native desktop) plus a printed recovery kit, and vaults sync through an opaque
// op-log where the OLDEST writer wins. The old rules made that a trap:
//
//   * `version !== 1` was refused outright, so ANY addition was a flag day; and
//   * neither side preserved fields it did not know, so an old client that
//     merely opened and re-sealed a vault DELETED a newer client's data.
//
// Both are fixed, additively:
//
//   1. UNKNOWN FIELDS ARE PRESERVED. This module never rebuilds a vault or an
//      entry field-by-field; it spreads (`{...vault}` / `{...entry}`) so anything
//      it does not understand is written back verbatim. ⚠️ A caller that
//      reconstructs `{ version, entries }` by hand throws that away again — use
//      `cloneVault()` below.
//   2. `min_reader_version` states what a reader must UNDERSTAND, separately from
//      `version`, which states what WROTE the vault. A reader refuses iff
//      `min_reader_version > TOTP_VAULT_READER_VERSION`; when the field is absent
//      the vault's own `version` is used, so an un-annotated future vault still
//      fails closed. Mirrors cli/src/lib.rs::check_vault_readable EXACTLY.
//
// Pre-audit / UNAUDITED / DEV. Do NOT store real 2FA secrets in this build.

// The inner TotpVault plaintext version (cli/src/lib.rs::TOTP_VAULT_VERSION) —
// what this build WRITES into `version`.
export const TOTP_VAULT_VERSION = 1;

// The highest `min_reader_version` this build can satisfy
// (cli/src/lib.rs::TOTP_VAULT_READER_VERSION). MUST stay in step with Rust.
export const TOTP_VAULT_READER_VERSION = 1;

// Works in BOTH Node (v20+) and the browser: base64 is feature-detected (Buffer
// in Node, atob/btoa in the browser), matching sync.mjs.

/** Standard-base64 string -> Uint8Array. */
export function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Uint8Array -> standard-base64 string. */
export function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(u8).toString("base64");
  }
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}

// Coerce a password (string or bytes) to the UTF-8 byte array the wasm expects.
function passwordBytes(password) {
  if (password instanceof Uint8Array) return password;
  if (typeof password === "string") return new TextEncoder().encode(password);
  return new Uint8Array(password);
}

/**
 * Decode an RFC 4648 base32 string into raw bytes. Case-insensitive; ASCII
 * whitespace and `=` padding are ignored (so a secret pasted with spaces from a
 * provisioning screen still decodes). Rejects any other non-alphabet character
 * and an all-empty input. Mirrors cli/src/lib.rs::base32_decode.
 *
 * Base32 is the on-the-wire provisioning form (an `otpauth://` secret); the vault
 * stores the DECODED bytes as base64, so use this only when ADDING a secret.
 */
export function base32Decode(input) {
  let acc = 0;
  let nbits = 0;
  const out = [];
  for (const ch of input) {
    if (ch === "=" || /\s/.test(ch)) continue;
    const up = ch.toUpperCase();
    let val;
    if (up >= "A" && up <= "Z") {
      val = up.charCodeAt(0) - 65; // 'A' -> 0
    } else if (up >= "2" && up <= "7") {
      val = up.charCodeAt(0) - 50 + 26; // '2' -> 26
    } else {
      throw new Error(`invalid base32 character ${JSON.stringify(ch)} in secret`);
    }
    acc = (acc << 5) | val;
    nbits += 5;
    if (nbits >= 8) {
      nbits -= 8;
      out.push((acc >> nbits) & 0xff);
      acc &= (1 << nbits) - 1;
    }
  }
  if (out.length === 0) {
    throw new Error("base32 secret decoded to zero bytes");
  }
  return new Uint8Array(out);
}

/**
 * Open a sealed TOTP vault container and return its TotpVault object.
 *
 *   openVault(wasm, password, containerBytes) -> { version, entries: [...] }
 *
 * `wasm` is the imported binding (must expose `open_container`); `password` may
 * be a string or Uint8Array; `containerBytes` is the raw SIGILcli container (as
 * written by the CLI's `sigil totp` or by sealVault below). Throws on a wrong
 * password / tampered container, or if the decrypted JSON is not a valid vault.
 */
export function openVault(wasm, password, containerBytes) {
  const bytes =
    containerBytes instanceof Uint8Array ? containerBytes : new Uint8Array(containerBytes);
  const plaintext = wasm.open_container(passwordBytes(password), bytes);
  let vault;
  try {
    vault = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (e) {
    throw new Error(`decrypted vault is not valid JSON: ${e.message}`);
  }
  if (
    typeof vault !== "object" ||
    vault === null ||
    typeof vault.version !== "number" ||
    !Array.isArray(vault.entries)
  ) {
    throw new Error("decrypted vault is not a { version, entries: [] } object");
  }
  checkVaultReadable(vault);
  // ⭐ Phase 61: every read path assigns a stable id to any entry that has none,
  // deterministically, so two devices holding the same legacy vault agree on
  // those ids without communicating. Mirrors `cli/src/lib.rs::open_vault`.
  normalizeVault(wasm, vault);
  return vault;
}

/**
 * ⭐ The forward-compatibility gate. MIRRORS cli/src/lib.rs::check_vault_readable
 * and MUST stay byte-identical in behaviour — a drift means one client refuses a
 * vault the other happily opens, which on a sync path reads as data loss.
 *
 * A vault is readable when the reader version it DEMANDS is one this build can
 * satisfy. The demand is `min_reader_version` when stated, and otherwise the
 * vault's own `version` — so an un-annotated future vault FAILS CLOSED exactly as
 * the old blanket equality check did, while an explicitly-additive one
 * (`version: 2, min_reader_version: 1`) opens and round-trips losslessly.
 *
 * Throws with the required version named, never a generic "unsupported".
 */
export function checkVaultReadable(vault) {
  const required = vault.min_reader_version ?? vault.version;
  if (typeof required !== "number" || !Number.isInteger(required)) {
    throw new Error("vault version fields must be integers");
  }
  if (required > TOTP_VAULT_READER_VERSION) {
    throw new Error(
      `this vault needs a reader that understands schema version ${required}, and ` +
        `this build understands ${TOTP_VAULT_READER_VERSION} (the vault was written ` +
        `by version ${vault.version}). Upgrade the client that reads it — opening it ` +
        `here could silently discard data it does not understand`,
    );
  }
}

/**
 * ⭐ Clone a vault for editing WITHOUT dropping fields this build does not know.
 *
 * Use this instead of `{ version: v.version, entries: [...v.entries] }`. That
 * shape is the JS twin of rebuilding a serde struct field-by-field: it silently
 * deletes `min_reader_version` and every unknown top-level field, and a client
 * doing it on a shared vault destroys a newer client's data on its next push.
 * The entries array is copied shallowly — entry OBJECTS are shared, which is
 * what keeps their unknown fields intact.
 */
export function cloneVault(vault) {
  const out = { ...vault, entries: [...vault.entries] };
  // ⭐ Phase 61: the remove-set is part of the vault. Dropping it here would be
  // exactly the bug `cloneVault` exists to prevent, one level down — a client
  // that opened and re-sealed a vault would delete its tombstones and every
  // removed account would come back on the next merge.
  //
  // ⚠️ An EMPTY array is never carried: `tombstones` is OMITTED when empty (serde
  // `skip_serializing_if`), so a vault that has never had a delete must stay
  // byte-identical to what earlier builds wrote.
  if (Array.isArray(vault.tombstones) && vault.tombstones.length > 0) {
    out.tombstones = vault.tombstones.map((t) => ({ ...t }));
  } else {
    delete out.tombstones;
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// ⭐⭐ ENTRY IDENTITY AND VAULT MERGE (Phase 61)
//
// ⛔ THE DEFECT. A vault syncs as whole sealed SNAPSHOTS through an append-only
// op-log, and every client ADOPTED THE NEWEST ONE WHOLESALE (`ops[ops.length-1]`
// here, `pull_and_adopt` on the desktop). So: device A adds `github` and pushes;
// device B, which never pulled, adds `gitlab` and pushes; B's snapshot is now the
// tip, it has never seen `github`, and the moment any client adopts the tip that
// account is GONE — with both devices reporting success.
//
// ⭐ THE FIX. A vault is a 2P-Set of entries keyed by identity: `entries` is the
// add-set, `tombstones` the remove-set, `mergeVaults` their union with the
// remove-set winning. Commutative, associative, idempotent — so devices converge
// regardless of pull order or duplicate delivery.
//
// ┌─ MIRRORED — NOT SHARED. KEEP IN STEP WITH cli/src/lib.rs ────────────────┐
// │  `normalizeVault` / `mergeVaults` / `mergeOpsInto` mirror                 │
// │  `normalize_vault` / `merge_vaults` / `merge_ops_into`. A drift does NOT  │
// │  fail loudly — it makes two clients disagree about what the same account  │
// │  is. `sigil-wasm/test/merge-interop.mjs` drives the REAL `sigil` binary   │
// │  against this module and is the guard.                                    │
// │                                                                           │
// │  ⭐ The IDENTITY DERIVATION is NOT mirrored: `wasm.entry_id` reaches       │
// │  `sigil_core::entry_id` directly, because a drift THERE would be          │
// │  invisible (a vault that opens fine everywhere and silently duplicates).  │
// └───────────────────────────────────────────────────────────────────────────┘
//
// ⛔⛔ THE ONE WAY THIS GOES WRONG LATER: someone adds an EDIT. There is no
// clock, no revision counter and no timestamp in the ordering rule, and that is
// correct ONLY because entries are IMMUTABLE — add / import / remove is the
// complete mutation surface in all four clients. **An edit must be implemented as
// delete + add with a fresh uuid, or this merge is wrong.**
// ═══════════════════════════════════════════════════════════════════════════

/**
 * The content-derived id of `entry` — the id it gets when it has no `uuid`.
 * Reaches `sigil_core::entry_id` through the wasm; adds no crypto here.
 *
 * ⚠️ TOTAL by design: a `secret` that is not valid base64 falls back to the raw
 * stored string's UTF-8 bytes, exactly as `cli/src/lib.rs::entry_content_id`
 * does, so a corrupt entry can never abort a merge.
 */
export function entryContentId(wasm, entry, disambiguator = 0) {
  let secret;
  try {
    secret = base64ToBytes(entry.secret);
  } catch {
    secret = new TextEncoder().encode(String(entry.secret ?? ""));
  }
  return wasm.entry_id(
    entry.issuer ?? "",
    entry.label ?? "",
    secret,
    entry.algorithm ?? "",
    entry.digits ?? 0,
    entry.period ?? 0,
    disambiguator,
  );
}

/**
 * The identity an entry is MERGED by: its own `uuid` when it has one, otherwise
 * its content-derived id.
 *
 * ⭐ This answers "which entry is this?" and nothing else — see
 * `entryFingerprint`, which is what the ADD/IMPORT paths must use.
 */
export function entryIdentity(wasm, entry) {
  if (typeof entry.uuid === "string" && entry.uuid.length > 0) return entry.uuid;
  return entryContentId(wasm, entry);
}

/**
 * The content FINGERPRINT of an entry, **ignoring any `uuid` it carries**.
 *
 * ⭐⭐ TWO DIFFERENT JOBS, TWO DIFFERENT MECHANISMS, and conflating them is a real
 * bug this code has already had. `entryIdentity` answers *"which entry is this?"*
 * (a uuid); this answers *"have I already got this account?"* (its content).
 * Import and add must ask the SECOND question: a freshly imported entry carries
 * no id while the copy already in the vault carries a RANDOM one, so comparing
 * identities would never match and re-importing the same Google Authenticator
 * export would duplicate every account in it.
 *
 * Mirrors `cli/src/lib.rs::entry_fingerprint`.
 */
export function entryFingerprint(wasm, entry) {
  return entryContentId(wasm, entry, 0);
}

/**
 * ⭐ Give every entry a stable id, deterministically and idempotently.
 *
 * Mutates and returns `vault`. For each entry with no `uuid` the id is DERIVED
 * from the entry's content, so two devices holding copies of the same
 * pre-Phase-61 vault arrive at the SAME ids without either knowing the other
 * exists. A random id here would double every account in every existing
 * multi-device vault on first sync, and would make a delete performed on one
 * device unable to ever suppress the other's copy.
 *
 * It does not reorder, filter or rebuild anything — it only fills a missing field.
 */
export function normalizeVault(wasm, vault) {
  const seen = new Set(
    vault.entries.filter((e) => typeof e.uuid === "string" && e.uuid).map((e) => e.uuid),
  );
  for (const entry of vault.entries) {
    if (typeof entry.uuid === "string" && entry.uuid.length > 0) continue;
    let n = 0;
    let id = entryContentId(wasm, entry, n);
    while (seen.has(id)) id = entryContentId(wasm, entry, ++n);
    seen.add(id);
    entry.uuid = id;
  }
  return vault;
}

/**
 * Canonical JSON with keys sorted at every level — a deterministic tiebreak,
 * nothing else. ⚠️ It MUST agree with `cli/src/lib.rs::canonical_entry`, which
 * goes through `serde_json::to_value` (whose `Map` is a `BTreeMap`, i.e. sorted)
 * for exactly this reason: if the two sides ordered keys differently they could
 * pick DIFFERENT winners for the same conflict and never converge.
 */
function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeysDeep(value[k]);
    return out;
  }
  return value;
}

function canonicalEntry(entry) {
  return JSON.stringify(sortKeysDeep(entry));
}

/**
 * Canonical JSON for one arbitrary (unknown, forward-compatibility) value — the
 * ordering key used to combine unknown fields commutatively, at both the vault
 * and the TOMBSTONE level.
 *
 * ⚠️ It sorts keys, because the Rust mirror's `canonical_json` goes through
 * `serde_json::Value` (a `BTreeMap`, i.e. sorted). A bare `JSON.stringify` here
 * would let the two clients pick DIFFERENT winners for the same unknown key and
 * never converge.
 */
function canonicalJson(value) {
  return JSON.stringify(sortKeysDeep(value));
}

/**
 * Canonical order: entries by (issuer, label, uuid), tombstones by uuid.
 * ⭐ This is what makes convergence a TESTABLE EQUALITY — two devices that have
 * seen the same snapshots serialize to byte-identical plaintext.
 */
function canonicalizeVault(vault) {
  // ⭐ Sort by `uuid` ALONE, and deliberately not by (issuer, label, uuid).
  // A uuid is ASCII hex, so Rust's byte-wise `Ord` and JavaScript's UTF-16
  // comparison agree EXACTLY. Sorting on user text would not: the two languages
  // order some non-ASCII strings differently, and the two clients would then
  // produce different canonical bytes for the same set and never agree that they
  // had converged. Display order is each client's own business.
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  vault.entries.sort((a, b) => cmp(a.uuid ?? "", b.uuid ?? ""));
  (vault.tombstones ?? []).sort((a, b) => cmp(a.uuid, b.uuid));
  return vault;
}

// ═══════════════════════════════════════════════════════════════════════════
// ⭐⭐ THE SERIALIZED KEY ORDER IS PART OF THE MIRRORED SCHEMA.
//
// ⛔ WHAT WENT WRONG. `vaultToJson` used to be `JSON.stringify({ ...vault })`,
// i.e. JavaScript INSERTION order. Two consequences, both real and both
// reproduced before this was written:
//
//   1. THE MERGE WAS NOT BYTE-COMMUTATIVE. `mergeVaults` builds its result by
//      spreading one side and then appending the other side's keys, so two
//      tombstones sharing a uuid with DISJOINT unknown fields — or two vaults
//      with disjoint unknown TOP-LEVEL fields — produced
//        merge(a,b) -> {"uuid":"t1","deleted_at":100,"alpha":1,"beta":2}
//        merge(b,a) -> {"uuid":"t1","deleted_at":100,"beta":2,"alpha":1}
//      Identical CONTENT, different BYTES. The values were order-independent;
//      the SERIALIZATION was not — while this module's own `mergeVaults`
//      docstring claimed commutativity "byte for byte with no exception".
//   2. RUST AND JS WROTE DIFFERENT BYTES FOR IDENTICAL CONTENT. `serde` emits a
//      struct's fields in DECLARATION order and its `#[serde(flatten)] extra` is
//      a `BTreeMap` (sorted); `addEntry` appended `issuer` LAST and unknown
//      fields landed wherever `JSON.parse` had put them.
//
// Neither is visible to a parser, which is exactly why it survived: every
// interop suite compared PARSED structures, and the new property test compared
// through a canonicalising `canonJson` that normalised the difference away.
//
// ⛔ WHY IT MATTERS ANYWAY. "Have these two devices converged?" is answered in
// this repo by comparing serialized plaintext, and a sealed vault is pushed as
// an opaque op — so two clients holding IDENTICAL content writing DIFFERENT
// bytes means every push is a fresh op, the op-log grows without bound toward
// the 64 KiB cap (see `opBodySizeWarning`), and any future de-duplication,
// content-addressing or "unchanged, skip the push" optimisation is silently
// wrong. `changed` in the merge report is computed by exactly this comparison.
//
// ⭐ THE RULE, mirrored from `cli/src/lib.rs`: KNOWN fields in serde DECLARATION
// order, then UNKNOWN fields sorted, recursively — because `serde_json::Value`
// is a `BTreeMap`. Verified against the real `sigil` binary's own output, not
// inferred: see the BYTES section of `sigil-wasm/test/merge-interop.mjs`.
//
// ⚠️ THESE THREE ARRAYS MUST STAY IN STEP WITH THE STRUCT FIELD ORDER IN
// `cli/src/lib.rs` (`TotpVault` / `TotpEntry` / `Tombstone`). Adding a field to
// the Rust struct and not here does not fail loudly — it makes the two clients
// write different bytes again.
// ═══════════════════════════════════════════════════════════════════════════
const VAULT_FIELD_ORDER = ["version", "min_reader_version", "entries", "tombstones"];
const ENTRY_FIELD_ORDER = ["label", "issuer", "secret", "algorithm", "digits", "period", "uuid"];
const TOMBSTONE_FIELD_ORDER = ["uuid", "deleted_at"];

/**
 * Rebuild `value` with its KNOWN keys in `order` followed by every other key
 * sorted, mirroring what `serde` does to a struct with a flattened `BTreeMap`.
 *
 * `undefined` and `null` are dropped for known keys — that is serde's
 * `skip_serializing_if = "Option::is_none"`, and it is why an absent `issuer`
 * disappears rather than being written as `null`. Unknown keys keep an explicit
 * `null` (it is a `serde_json::Value::Null` on the Rust side and round-trips).
 */
function orderKeys(value, order, transform) {
  const out = {};
  for (const k of order) {
    const v = value[k];
    if (v === undefined || v === null) continue;
    out[k] = transform && transform[k] ? transform[k](v) : v;
  }
  for (const k of Object.keys(value).sort()) {
    if (order.includes(k)) continue;
    if (value[k] === undefined) continue;
    // An unknown value is arbitrary JSON, and Rust holds it as a
    // `serde_json::Value` whose maps are sorted at EVERY depth.
    out[k] = sortKeysDeep(value[k]);
  }
  return out;
}

/**
 * Serialize a vault the way it is stored: `tombstones` omitted when empty, and
 * every object's keys in the exact order `serde` writes them (see the block
 * above). Byte-identical to what the `sigil` CLI writes for the same content.
 */
export function vaultToJson(vault) {
  // `entries` is NOT optional in the Rust struct, so it is filled in BEFORE the
  // ordering pass — appending it afterwards would put it after the unknown
  // fields and defeat the whole point of this function.
  const src = Array.isArray(vault.entries) ? vault : { ...vault, entries: [] };
  const out = orderKeys(src, VAULT_FIELD_ORDER, {
    entries: (es) => es.map((e) => orderKeys(e, ENTRY_FIELD_ORDER)),
    tombstones: (ts) => (Array.isArray(ts) ? ts : []).map((t) => orderKeys(t, TOMBSTONE_FIELD_ORDER)),
  });
  // serde `skip_serializing_if = "Vec::is_empty"` — a vault that has never had a
  // delete stays byte-identical to what pre-Phase-61 builds wrote.
  if (Array.isArray(out.tombstones) && out.tombstones.length === 0) delete out.tombstones;
  return JSON.stringify(out);
}

/**
 * ⭐ Join two vault snapshots. Commutative, associative and idempotent.
 *
 *   mergeVaults(wasm, local, remote) -> { vault, added, removed, tombstonesAdded,
 *                                         changed, conflicts }
 *
 * **Delete wins unconditionally** — safe here precisely because a genuine re-add
 * draws a FRESH random uuid, so a "re-add" of the same id is a stale snapshot or
 * a hostile writer, not a user action, and should lose.
 *
 * Two entries claiming the same id with different content keep the
 * lexicographically greater canonical JSON: deterministic and order-independent,
 * unlike "local wins", which would break convergence.
 *
 * ⭐⭐ EVERY FIELD USES AN ORDER-INDEPENDENT RULE, INCLUDING THE UNKNOWN ONES.
 * The rules are `max` (version, min_reader_version, unknown `extra` at BOTH the
 * vault and the TOMBSTONE level, and the entry tiebreak), `min` (`deleted_at`)
 * and set union (entries, tombstones) — all commutative and associative, so
 * `mergeVaults(a,b)` and `mergeVaults(b,a)` serialize identically with no
 * exception.
 *
 * ⚠️ "SERIALIZE IDENTICALLY" MEANS THROUGH `vaultToJson`, AND THAT IS A LOAD-
 * BEARING QUALIFICATION, not a hedge. The merged OBJECT this returns still
 * carries its keys in whatever order they were inserted; it is `vaultToJson`
 * that imposes serde's field order and sorts the unknown ones. A caller that
 * reaches for a bare `JSON.stringify` gets bytes that depend on merge order —
 * so seal, compare and hash a vault through `vaultToJson` and nothing else.
 *
 * ⚠️ THAT WAS NOT ALWAYS TRUE, TWICE OVER, and both exceptions were real:
 *   1. tombstone-level unknown fields used to merge FIRST-SEEN-WINS
 *      (`{ ...t, ...prev }`), so two vaults whose tombstones shared a uuid but
 *      disagreed about an unknown key did not converge AT ALL; and
 *   2. even after that was fixed the VALUES converged while the BYTES did not —
 *      two tombstones with DISJOINT unknown keys serialized as
 *      `…,"alpha":1,"beta":2` one way round and `…,"beta":2,"alpha":1` the
 *      other. See the block above `vaultToJson`.
 * Both are fixed rather than merely documented, because a forward-compatibility
 * field (ADR 0047) is exactly what a future version writes and a current one
 * must carry through a merge in either order.
 *
 * ⚠️⚠️ THE MERGE IS AN INGEST DOOR AND IT IS DELIBERATELY NOT GATED — read this
 * before "fixing" it. Phase 63's provisioning ceiling (`validateProvisioning` in
 * `totp-migration.mjs`) runs at `parseOtpauthUri` and `migrationOtpToEntry`, i.e.
 * wherever an entry is BUILT FROM UNTRUSTED TEXT. An entry arriving through this
 * function was built somewhere else and is adopted UNCHECKED: a co-owner of a
 * shared vault can push a snapshot containing a `period` of 4294967295, and it
 * lands.
 *
 * ⭐ THAT IS INSIDE THE STATED TRUST MODEL, NOT A HOLE IN IT. Reaching this
 * function at all requires holding the vault key (ADR 0035/0038) — a peer you
 * deliberately shared with, whose key you pinned and whose safety number you were
 * shown. A peer who can write entries can already write anything into a vault you
 * chose to share; a period ceiling is not what stands between you and them.
 *
 * ⛔ AND GATING IT WOULD BE THE WORSE BUG, in the precise direction Phase 61
 * exists to avoid: **refusing to merge an entry is refusing to READ it**. Drop an
 * entry here and the next re-seal writes a vault without it, that vault is pushed,
 * and the account is gone from every device — data loss caused by a validator,
 * which is exactly the shape of the defect ADR 0049 was written to repair. The
 * ingest ceiling bounds what a STRANGER MAY CREATE; it must never decide what a
 * user may KEEP.
 *
 * ⭐ SO THE DOOR IS DISCLOSED RATHER THAN CLOSED, and the mitigation is on the
 * READ path where it cannot destroy anything: `frozenPeriodWarning` (mirrored in
 * Rust as `frozen_period_warning`) is rendered beside any such entry by every
 * client, so a merged non-rotating entry is visible as one instead of wearing an
 * ordinary countdown. `provisioning-interop.mjs` pins BOTH halves of this
 * decision — that the merge still adopts the entry, and that the warning fires.
 *
 * Mirrors `cli/src/lib.rs::merge_vaults`.
 */
export function mergeVaults(wasm, local, remote) {
  const a = canonicalizeVault(normalizeVault(wasm, cloneVault(local)));
  const b = canonicalizeVault(normalizeVault(wasm, cloneVault(remote)));

  // 1) Remove-set: union by uuid, keeping the SMALLER deleted_at. Nothing else
  //    reads the timestamp, so a wrong or hostile clock cannot un-delete.
  const tombs = new Map();
  for (const t of [...(a.tombstones ?? []), ...(b.tombstones ?? [])]) {
    if (!t || typeof t.uuid !== "string" || t.uuid.length === 0) continue;
    const prev = tombs.get(t.uuid);
    if (!prev) {
      tombs.set(t.uuid, { ...t });
      continue;
    }
    const x = typeof prev.deleted_at === "number" ? prev.deleted_at : null;
    const y = typeof t.deleted_at === "number" ? t.deleted_at : null;
    const merged = x === null ? y : y === null ? x : Math.min(x, y);
    // ⭐ Unknown tombstone fields combine by the SAME commutative rule the vault
    // level uses: keep the lexicographically greater canonical JSON.
    // ⚠️ This was `{ ...t, ...prev }` — FIRST-SEEN-WINS — which made
    // `mergeVaults(a,b) != mergeVaults(b,a)` whenever two tombstones shared a
    // uuid and disagreed about an unknown key, contradicting this module's own
    // unqualified commutativity claim. Mirrors `cli/src/lib.rs::merge_vaults`.
    const out = { ...prev };
    for (const [k, v] of Object.entries(t)) {
      if (k === "uuid" || k === "deleted_at") continue;
      if (!(k in out) || canonicalJson(v) > canonicalJson(out[k])) out[k] = v;
    }
    if (merged === null) delete out.deleted_at;
    else out.deleted_at = merged;
    out.uuid = t.uuid;
    tombs.set(t.uuid, out);
  }

  // 2) Add-set: union by identity.
  const adds = new Map();
  const conflicts = [];
  for (const e of [...a.entries, ...b.entries]) {
    const id = entryIdentity(wasm, e);
    const prev = adds.get(id);
    if (!prev) {
      adds.set(id, e);
      continue;
    }
    if (canonicalEntry(prev) === canonicalEntry(e)) continue;
    if (!conflicts.includes(id)) conflicts.push(id);
    if (canonicalEntry(e) > canonicalEntry(prev)) adds.set(id, e);
  }

  // 3) DELETE WINS.
  let removed = 0;
  const entries = [];
  for (const [id, e] of adds) {
    if (tombs.has(id)) removed += 1;
    else entries.push(e);
  }

  // 4) Unknown top-level fields, deterministically; min_reader_version FAILS
  //    CLOSED (the higher demand wins), so a merge can never make a vault look
  //    more readable than either input claimed.
  const known = new Set(["version", "min_reader_version", "entries", "tombstones"]);
  const merged = { version: Math.max(a.version ?? 1, b.version ?? 1) };
  for (const src of [a, b]) {
    for (const [k, v] of Object.entries(src)) {
      if (known.has(k)) continue;
      if (!(k in merged) || canonicalJson(v) > canonicalJson(merged[k])) merged[k] = v;
    }
  }
  const mrv = [a.min_reader_version, b.min_reader_version].filter((x) => typeof x === "number");
  if (mrv.length > 0) merged.min_reader_version = Math.max(...mrv);
  merged.entries = entries;
  const tombList = [...tombs.values()];
  if (tombList.length > 0) merged.tombstones = tombList;
  canonicalizeVault(merged);

  const localIds = new Set(a.entries.map((e) => entryIdentity(wasm, e)));
  const localTombs = new Set((a.tombstones ?? []).map((t) => t.uuid));
  return {
    vault: merged,
    added: merged.entries.filter((e) => !localIds.has(entryIdentity(wasm, e))).length,
    removed,
    tombstonesAdded: (merged.tombstones ?? []).filter((t) => !localTombs.has(t.uuid)).length,
    changed: vaultToJson(merged) !== vaultToJson(a),
    conflicts,
  };
}

/**
 * ⭐ Fold EVERY op into `local`, instead of adopting the newest one.
 *
 *   mergeOpsInto(wasm, secret, local, ops) -> { vault, applied, skipped, tip,
 *                                               added, removed, changed, conflicts }
 *
 * `ops` is what `pullContainers`/`pullContainersAuthed` returned
 * (`[{ seq, container }]`). An op that will not open under `secret` is SKIPPED
 * AND NAMED, never fatal — that is the `vault rekey` / old-password case, and it
 * means the merged snapshot is not always a superset of the log.
 *
 * Mirrors `cli/src/lib.rs::merge_ops_into`.
 */
export function mergeOpsInto(wasm, secret, local, ops) {
  let acc = cloneVault(local);
  let applied = 0;
  let added = 0;
  let removed = 0;
  let tip = 0;
  const skipped = [];
  const conflicts = [];
  for (const op of ops) {
    const seq = op.seq ?? 0;
    if (seq > tip) tip = seq;
    let opened;
    try {
      opened = openVault(wasm, secret, op.container);
    } catch (e) {
      skipped.push({ seq, reason: (e && e.message) || String(e) });
      continue;
    }
    const res = mergeVaults(wasm, acc, opened);
    acc = res.vault;
    applied += 1;
    added += res.added;
    removed += res.removed;
    for (const c of res.conflicts) if (!conflicts.includes(c)) conflicts.push(c);
  }
  const base = canonicalizeVault(normalizeVault(wasm, cloneVault(local)));
  return {
    vault: acc,
    applied,
    skipped,
    tip,
    added,
    removed,
    changed: vaultToJson(acc) !== vaultToJson(base) || vaultToJson(acc) !== vaultToJson(local),
    conflicts,
  };
}

/**
 * Remove an entry AND record a tombstone, so the removal survives a merge with a
 * snapshot that still holds it.
 *
 *   removeEntry(wasm, vault, { uuid } | { label }, deletedAtUnix?) -> the removed entry
 *
 * ⚠️ An AMBIGUOUS label is REFUSED, naming the candidates, rather than silently
 * removing the first match — labels are no longer unique (that is the Google
 * Authenticator import fix) and silently picking one is how a user deletes the
 * wrong account.
 *
 * ⭐ Removing and tombstoning must never come apart: a removal that writes no
 * tombstone is exactly the pre-Phase-61 behaviour, and a merge resurrects it.
 * Mirrors `cli/src/lib.rs::TotpVault::remove_at` / `remove_by_uuid`.
 */
export function removeEntry(wasm, vault, selector, deletedAtUnix) {
  normalizeVault(wasm, vault);
  let index = -1;
  if (selector && typeof selector.uuid === "string" && selector.uuid.length > 0) {
    index = vault.entries.findIndex((e) => entryIdentity(wasm, e) === selector.uuid);
    if (index < 0) {
      const hits = vault.entries.filter((e) => entryIdentity(wasm, e).startsWith(selector.uuid));
      if (hits.length === 1) index = vault.entries.indexOf(hits[0]);
    }
    if (index < 0) throw new Error(`no entry with id ${JSON.stringify(selector.uuid)}`);
  } else {
    const label = selector && selector.label;
    const hits = vault.entries.filter((e) => e.label === label);
    if (hits.length === 0) throw new Error(`no entry labelled ${JSON.stringify(label)}`);
    if (hits.length > 1) {
      const lines = hits
        .map((e) => `  ${e.issuer ? `${e.issuer}: ` : ""}${e.label} (id ${entryIdentity(wasm, e).slice(0, 8)})`)
        .join("\n");
      throw new Error(
        `${hits.length} entries are labelled ${JSON.stringify(label)} — name one by id:\n${lines}`,
      );
    }
    index = vault.entries.indexOf(hits[0]);
  }
  const [entry] = vault.entries.splice(index, 1);
  const uuid = entryIdentity(wasm, entry);
  if (!Array.isArray(vault.tombstones)) vault.tombstones = [];
  if (!vault.tombstones.some((t) => t.uuid === uuid)) {
    const t = { uuid };
    if (typeof deletedAtUnix === "number" && Number.isFinite(deletedAtUnix)) {
      t.deleted_at = Math.floor(deletedAtUnix);
    }
    vault.tombstones.push(t);
  }
  return entry;
}

/**
 * Format 16 bytes of CALLER-supplied entropy as a lowercase RFC 4122 v4 UUID.
 * MIRRORS cli/src/lib.rs::format_entry_uuid (same version/variant bit fixing, so
 * both sides produce the same string from the same bytes).
 */
export function formatEntryUuid(random16) {
  const b = Uint8Array.from(random16);
  if (b.length !== 16) throw new Error(`entry uuid needs exactly 16 bytes, got ${b.length}`);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const h = (from, to) =>
    Array.from(b.slice(from, to), (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h(0, 4)}-${h(4, 6)}-${h(6, 8)}-${h(8, 10)}-${h(10, 16)}`;
}

/**
 * Draw a fresh entry uuid from the platform CSPRNG
 * (`crypto.getRandomValues` — present in Node 20+ and every browser). The
 * entropy is supplied HERE, in JS, never by the wasm (ADR 0007).
 */
export function randomEntryUuid() {
  return formatEntryUuid(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * Compute the current TOTP code for one entry as a zero-padded string.
 *
 *   codeForEntry(wasm, entry, unixTimeSeconds) -> "123456"
 *
 * `unixTimeSeconds` is the caller's clock (e.g. `Math.floor(Date.now()/1000)`) —
 * sigil-core reads no clock, so the time is supplied here. Uses t0 = 0 (the
 * near-universal TOTP epoch offset). Throws on a bad entry (unknown algorithm,
 * out-of-range digits, non-integer time).
 */
export function codeForEntry(wasm, entry, unixTimeSeconds) {
  const secret = base64ToBytes(entry.secret);
  const code = wasm.totp(
    secret,
    unixTimeSeconds,
    entry.period,
    0, // t0
    entry.digits,
    entry.algorithm,
  );
  return wasm.format_code(code, entry.digits);
}

/**
 * Append a TotpEntry to `vault` (mutating and returning it), matching the CLI
 * schema EXACTLY: the raw `secretBytes` are stored as STANDARD base64 in
 * `.secret`, `algorithm` is lowercased, and `issuer` is OMITTED when absent (never
 * written as null) so the JSON is byte-identical to what serde produces.
 *
 *   addEntry(vault, { label, issuer?, secretBytes, algorithm, digits, period, uuid? })
 *
 * Rejects a duplicate label (the CLI treats labels as unique) and out-of-range
 * digits/period up front. A stable `uuid` is drawn from `crypto.getRandomValues`
 * unless the caller supplies one (pass `null` to omit the field entirely, which
 * is what an entry written before the field existed looks like).
 */
export function addEntry(vault, { label, issuer, secretBytes, algorithm, digits, period, uuid }) {
  if (typeof label !== "string" || label.length === 0) {
    throw new Error("label must be a non-empty string");
  }
  // ⭐ Phase 61: a duplicate LABEL is no longer rejected — the same label at a
  // different issuer is a different account, and refusing it was the Google
  // Authenticator import defect. A duplicate IDENTITY is still rejected, by
  // `addEntryChecked` below (which needs `wasm` to compute an identity). This
  // signature is kept `wasm`-free so every existing caller is unchanged.
  const algo = String(algorithm ?? "sha1").toLowerCase();
  if (algo !== "sha1" && algo !== "sha256" && algo !== "sha512") {
    throw new Error(`unknown algorithm ${JSON.stringify(algorithm)}: expected sha1/sha256/sha512`);
  }
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new Error(`digits ${digits} out of range 6..=10`);
  }
  if (!Number.isInteger(period) || period <= 0) {
    throw new Error(`period ${period} must be a positive integer`);
  }

  const entry = {
    label,
    // issuer key is added ONLY when present, mirroring serde's skip_serializing_if.
    secret: bytesToBase64(secretBytes),
    algorithm: algo,
    digits,
    period,
  };
  if (issuer !== undefined && issuer !== null && issuer !== "") {
    entry.issuer = issuer;
  }
  // `uuid: null` means "deliberately omit" (an entry as written before the field
  // existed); undefined means "draw one". Mirrors the CLI, where
  // `new_totp_entry` draws and `new_totp_entry_with_uuid(..., None)` omits.
  if (uuid !== null) {
    entry.uuid = uuid ?? randomEntryUuid();
  }
  vault.entries.push(entry);
  return vault;
}

/**
 * [`addEntry`] that also refuses an account ALREADY IN THE VAULT, compared by
 * **content fingerprint** rather than by label.
 *
 * ⭐ This is the CRITICAL-2 fix on the JS side: `work` at GitHub and `work` at
 * GitLab differ in issuer AND secret, so both are added; re-importing the same
 * Google Authenticator export adds nothing. Mirrors
 * `cli/src/lib.rs::TotpVault::add` + the import de-dup in `cli/src/main.rs`.
 *
 * ⚠️ `entryFingerprint`, NOT `entryIdentity` — see that function's note.
 *
 * Returns `true` when the entry was added, `false` when it was already present.
 */
export function addEntryChecked(wasm, vault, input) {
  const candidate = {
    label: input.label,
    secret: bytesToBase64(input.secretBytes),
    algorithm: String(input.algorithm ?? "sha1").toLowerCase(),
    digits: input.digits,
    period: input.period,
  };
  if (input.issuer !== undefined && input.issuer !== null && input.issuer !== "") {
    candidate.issuer = input.issuer;
  }
  const fp = entryFingerprint(wasm, candidate);
  normalizeVault(wasm, vault);
  if (vault.entries.some((e) => entryFingerprint(wasm, e) === fp)) return false;
  addEntry(vault, input);
  return true;
}

/**
 * Serialize `vault` to JSON and seal it into a CLI-compatible SIGILcli container
 * the `sigil totp` CLI can open back.
 *
 *   sealVault(wasm, password, vault, salt, nonce, params) -> Uint8Array
 *
 * `salt` and `nonce` are caller-supplied entropy (generate with
 * `crypto.getRandomValues`; salt = wasm.recommended_salt_len() bytes, nonce =
 * wasm.nonce_len() bytes). `params` is `{ m_cost, t_cost, p_cost }`. The vault
 * plaintext is UTF-8 JSON with no trailing metadata, matching the CLI's
 * serde_json output shape.
 */
export function sealVault(wasm, password, vault, salt, nonce, params) {
  // ⭐ `vaultToJson`, not `JSON.stringify`: it drops an EMPTY `tombstones` array
  // so a vault that has never had a delete keeps the exact byte shape earlier
  // builds wrote (serde omits it via `skip_serializing_if`).
  const json = new TextEncoder().encode(vaultToJson(vault));
  return wasm.seal_to_container(
    passwordBytes(password),
    salt,
    nonce,
    params.m_cost,
    params.t_cost,
    params.p_cost,
    json,
  );
}

/** Convenience: a fresh empty vault at the current schema version. */
export function newVault() {
  return { version: TOTP_VAULT_VERSION, entries: [] };
}

// ═══════════════════════════════════════════════════════════════════════════
// ⛔⛔ THE TOMBSTONE GROWTH LIMIT — the honest record of an UNSOLVED problem.
//
// A vault is a 2P-Set and the remove-set NEVER SHRINKS. Every removal appends a
// tombstone (~55-95 bytes of JSON) that must be carried forever: dropping it
// resurrects the entry on the next merge with any device still holding a
// pre-delete snapshot. There is NO COMPACTION PATH in this repo — no command, no
// sweep, nothing prunes a tombstone anywhere.
//
// ⛔ THE HARD STOP. `sigild` caps ONE op body at 64 KiB (`maxOpsBodyBytes`,
// sigild/internal/api/middleware.go) and answers 413 above it. The op body is
// the SEALED CONTAINER, so the ceiling is on ciphertext. Past the cap `push`
// fails and THERE IS NO SUPPORTED WAY TO SHRINK IT — a user who first meets this
// AT the 413 has already lost the ability to sync.
//
// ⭐ WHAT IS BUILT HERE IS A WARNING, NOT A FIX. Every client that seals a vault
// for push calls `opBodySizeWarning` first and tells the human while there is
// still room to act. That is strictly less than compaction and is not pretended
// to be more.
//
// ⭐ WHY `deleted_at` EXISTS despite no merge branching on it: it is the field a
// future compaction keys on ("drop tombstones older than a window every device
// has certainly synced within"). It is written today so today's vaults are
// compactable later, and merged by MIN so a hostile clock can only make a delete
// look EARLIER, never postpone it.
//
// ⚠️ MIRRORED — NOT SHARED — from `cli/src/lib.rs` (`MAX_OP_BODY_BYTES` /
// `OP_BODY_WARN_BYTES` / `op_body_size_warning`) and ultimately from sigild's
// `maxOpsBodyBytes`. `sigil-wasm/test/merge-guard.mjs` asserts all three agree.
// ═══════════════════════════════════════════════════════════════════════════

/** The largest op body `sigild` accepts: 64 KiB. */
export const MAX_OP_BODY_BYTES = 64 * 1024;

/** The size at which a client must start warning: 75% of the cap (48 KiB). */
export const OP_BODY_WARN_BYTES = Math.floor(MAX_OP_BODY_BYTES / 4) * 3;

/**
 * A human-readable warning when a sealed container is close to — or past — the
 * server's op-body cap, or `null` when it is comfortably below.
 *
 *   opBodySizeWarning(containerBytes.length) -> string | null
 *
 * ⭐ Call it BEFORE pushing, so the human hears about it while the push still
 * works. The `>= MAX` case is worded differently on purpose: there the next push
 * is a 413 and the advice changes from "plan" to "this will now fail".
 */
export function opBodySizeWarning(containerLen) {
  const n = Number(containerLen) || 0;
  if (n >= MAX_OP_BODY_BYTES) {
    return (
      `This vault seals to ${n} bytes, over the server's ${MAX_OP_BODY_BYTES}-byte op limit — ` +
      `syncing will be REFUSED with HTTP 413. Tombstones (one per removed entry) are never ` +
      `pruned and there is no compaction command; export your accounts and start a fresh vault id.`
    );
  }
  if (n >= OP_BODY_WARN_BYTES) {
    const pct = Math.floor((n * 100) / MAX_OP_BODY_BYTES);
    return (
      `This vault seals to ${n} bytes — ${pct}% of the server's ${MAX_OP_BODY_BYTES}-byte op ` +
      `limit. Tombstones (one per removed entry) are never pruned and there is no compaction ` +
      `command, so this only grows; past the limit syncing is refused with HTTP 413.`
    );
  }
  return null;
}

// ── ⭐ THE NO-DOWNGRADE RATCHET FOR JS RE-SEALS ──────────────────────────────
//
// ⛔ THE BUG THESE CLOSE. A `SIGILcli` container is self-describing: it carries
// the Argon2id work factors it was sealed with. The Rust clients have honoured a
// ratchet since Phase 58 — `sigil_cli::reseal_container` re-seals at
// `no_downgrade(container's params, requested)`, so strength only ever goes up.
// The JS clients had NO equivalent. Every browser re-seal used a hardcoded
// `{ m_cost: 19456, t_cost: 2, p_cost: 1 }`, so a vault the CLI wrote at
// 65536/4/2 came back from ONE browser edit at 19456/2/1 — a 3.4x cut in memory
// cost and half the passes, silently, with no user action and no error. Because
// a re-seal is where new parameters are CHOSEN, that weakening was permanent.
//
// ⭐ The rule is not reimplemented in JS. `wasm.reseal_params` calls
// `sigil-core`'s `Argon2Params::no_downgrade` — literally the function
// `sigil_cli::no_downgrade` delegates to — so the browser and the CLI cannot
// drift. A drifting mirror would be invisible: it produces a container that
// still opens everywhere, just weaker.

/**
 * Read the Argon2id work factors a `SIGILcli` container declares, WITHOUT
 * opening it (no password, no KDF, no allocation).
 *
 *   containerParams(wasm, containerBytes) -> { m_cost, t_cost, p_cost }
 *
 * Throws on anything that is not a valid `SIGILcli` header, including one whose
 * declared factors exceed sigil-core's ceilings.
 */
export function containerParams(wasm, containerBytes) {
  const [m_cost, t_cost, p_cost] = wasm.container_params(containerBytes);
  return { m_cost, t_cost, p_cost };
}

/**
 * ⭐ **Call this at EVERY re-seal.** Returns the work factors to actually write:
 * the componentwise maximum of what `existingContainer` declares and what this
 * client would write today, with Argon2's `m_cost >= 8 * p_cost` floor honoured.
 *
 *   ratchetParams(wasm, existingContainer | null, requested) -> { m_cost, t_cost, p_cost }
 *
 * `existingContainer` is the container about to be REPLACED. `null`/`undefined`/
 * empty means "there is nothing to ratchet from" (a first seal), and `requested`
 * is returned unchanged.
 *
 * ⚠️ It is deliberately FORGIVING of a container it cannot parse: a stored value
 * that is corrupt, truncated or from some future format must not block the user
 * from saving. In that case it falls back to `requested`, which is this build's
 * own defaults — never something weaker than the client would have written
 * anyway. The dangerous direction (a strong header quietly becoming a weak one)
 * is the one that cannot happen.
 */
export function ratchetParams(wasm, existingContainer, requested) {
  if (!existingContainer || existingContainer.length === 0) return requested;
  try {
    const [m_cost, t_cost, p_cost] = wasm.reseal_params(
      existingContainer instanceof Uint8Array ? existingContainer : new Uint8Array(existingContainer),
      requested.m_cost,
      requested.t_cost,
      requested.p_cost,
    );
    return { m_cost, t_cost, p_cost };
  } catch {
    return requested;
  }
}
