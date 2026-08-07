"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AccountInfo,
  DeviceIdentity,
  HybridSecretIdentity,
  MergeOpsResult,
  TotpEntry,
  TotpVault,
} from "@sigil/wasm";

// The full @sigil/wasm module surface (wasm bindings + the proven JS helpers).
// Imported dynamically in the browser only (inside an effect) so the wasm never
// instantiates during SSR — matching totp-demo.tsx.
type Wasm = typeof import("@sigil/wasm");

// localStorage key holding ONLY the sealed SIGILcli container (base64). The
// plaintext vault and the password are NEVER persisted — they live in memory
// while unlocked and vanish on Lock / reload.
const STORAGE_KEY = "sigil.webapp.vault.v1";

// localStorage key holding the SEALED device identity — a SECOND SIGILcli
// container, sealed with the SAME vault password, whose plaintext is
// {device_id, seed, base_url, hybrid?, vault_keys?}. The Ed25519 device SEED,
// the hybrid SECRET identity (X25519 secret + ML-KEM seed) and every accepted
// 32-byte VAULT KEY are secret key material, so NONE of them is ever written in
// plaintext: they are only readable while the vault is unlocked (the password
// lives in memory only). Kept in its own container rather than inside the vault
// JSON so the CLI-mirrored TotpVault schema stays byte-compatible.
const DEVICE_KEY = "sigil.webapp.device.v1";

// ⭐ localStorage key holding the PASSKEY SLOT (ADR 0046) — a THIRD `SIGILcli`
// container, present ONLY while passkey protection is on. It is sealed under
// `PRF_output(32) ‖ utf8(password)` and its plaintext holds the 32-byte CONTAINER
// MASTER KEY that the other two containers are then sealed under.
//
// ⭐ It is a sealed container rather than a plain JSON marker on purpose: the
// browser's persisted key set stays "sealed containers only" (ADR 0036), which
// the leak specs check by decoding every stored value and demanding the
// `SIGILcli` magic. A `{credential_ids, rp_id}` marker would have been the first
// non-container persisted value in this repo's history.
const HWSLOT_KEY = "sigil.webapp.hwslot.v1";

// Argon2id parameters used when (re)sealing. The container is self-describing
// (it stores these), so open needs none and the vault stays CLI-interoperable
// regardless. OWASP-minimum-ish interactive params for a dev build.
const ARGON2 = { m_cost: 19456, t_cost: 2, p_cost: 1 };

type Phase = "loading" | "error" | "setup" | "locked" | "unlocked";

/**
 * What is TRUE about passkey protection right now, derived from a hwslot that
 * ACTUALLY OPENED this session. ⛔ There is deliberately no `protected: true`
 * flag: the truth is the ciphertext, and a flag could only drift from it.
 */
interface ProtectionInfo {
  /** The recovery kit whose printed sheet derives this browser's CMK. */
  kitDeviceId: string;
  credentialId: string;
  /** BE flag from the LAST ceremony — a backup-eligible passkey syncs. */
  backupEligible: boolean;
  /** BS flag from the LAST ceremony. */
  backupState: boolean;
  attachment: string;
}

interface PasskeyProbeSummary {
  backupEligible: boolean;
  attachment: string;
  scope: string;
}

/**
 * A refusal BEFORE anything is written: no recovery kit, or the probe stage was
 * skipped. Distinct from a passkey/PRF failure so the UI can route the user to
 * the RecoveryPanel instead of blaming their authenticator.
 */
class PasskeyPrecondition extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PasskeyPrecondition";
  }
}

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * ⭐ THE ONE SENTENCE ABOUT RECOVERY, SO IT CANNOT DRIFT INTO A LIE AGAIN.
 *
 * The account panel used to state, in the product, that "this app cannot print
 * one" — correct until Phase 56, false ever since (RecoveryPanel is rendered on
 * the same screen). A stale capability claim is worse than no claim when the
 * capability is the only thing standing between the user and permanent,
 * irreversible loss of every account in the vault: it does not merely fail to
 * help, it routes them past the fix.
 *
 * What remains TRUE and must stay in this string: a kit cannot be created AFTER
 * access is lost. That is a property of the design (ADR 0042), not of this
 * client.
 */
const RECOVERY_ADVICE =
  "A kit cannot be created after the fact — but this app CAN print one right " +
  "now: open “Recovery kit (dev)” below and choose “Generate a kit”.";

/**
 * A unix-seconds clock. Honors `?t=<unix>` to PIN the clock for deterministic
 * tests (no ticking); otherwise ticks live once per second.
 */
function useUnixClock(): number {
  const [now, setNow] = useState<number>(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const t = new URLSearchParams(window.location.search).get("t");
    if (t !== null && Number.isFinite(Number(t))) {
      setNow(Math.floor(Number(t)));
      return; // pinned clock: do not tick
    }
    const id = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(id);
  }, []);
  return now;
}

/**
 * The real (dev) authenticator: a multi-account TOTP vault whose codes are
 * computed IN THE WASM, sealed with a password into a CLI-compatible SIGILcli
 * container, and persisted (sealed-only) to localStorage with a lock/unlock flow.
 *
 * Pre-audit / UNAUDITED. Not for real 2FA secrets.
 */
export default function Authenticator() {
  const [wasm, setWasm] = useState<Wasm | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [wasmError, setWasmError] = useState<string>("");
  const [vault, setVault] = useState<TotpVault | null>(null);
  const [announce, setAnnounce] = useState<string>("");
  // The enrolled device identity, decrypted in memory while unlocked (null when
  // this browser has not enrolled). Its seed, hybrid secret and vault keys never
  // leave memory in the clear.
  const [device, setDevice] = useState<DeviceIdentity | null>(null);
  // When this vault has been converted to a SHARED vault, the id it is shared
  // under. Its 32-byte key lives in device.vaultKeys (sealed at rest); null means
  // this is still a personal, password-sealed vault.
  const [activeVaultId, setActiveVaultId] = useState<string | null>(null);

  // The password lives ONLY in memory while unlocked (never persisted).
  const passwordRef = useRef<string>("");
  // The 32-byte VAULT KEY when this vault is SHARED; null for a personal vault.
  // A SIGILcli container takes arbitrary password BYTES, so a random key drops
  // straight in where a password goes — exactly as `sigil vault rekey` does it.
  // ⭐ A container sealed under this is already immune to offline guessing, so
  // ADR 0046 leaves it COMPLETELY ALONE: passkey protection replaces the human
  // password as a sealing secret and nothing else.
  const vaultKeyRef = useRef<Uint8Array | null>(null);
  // ⭐ ADR 0046. The CONTAINER MASTER KEY while unlocked under passkey
  // protection; null when protection is off. Memory-only, exactly like the
  // password.
  const cmkRef = useRef<Uint8Array | null>(null);
  // The PRF output of the ceremony that unlocked (or enabled) this session.
  // Memory-only. Needed to RE-SEAL the slot when the recovery kit is reprinted.
  const prfRef = useRef<Uint8Array | null>(null);
  // The result of the live PRF probe, between the two stages of enabling.
  const probeRef = useRef<
    | {
        credentialId: string;
        rpId: string;
        attachment: string;
        backupEligible: boolean;
        backupState: boolean;
        kitDeviceId: string;
      }
    | null
  >(null);
  // ⭐ THE PROTECTION STATE IS THE CIPHERTEXT, NOT A FLAG. This is non-null only
  // when a hwslot container was present AND actually opened this session — there
  // is deliberately no `protected: true` boolean anywhere that could drift from
  // what the stored bytes really are.
  const [protection, setProtection] = useState<ProtectionInfo | null>(null);
  // ⚠️ A persistent, top-level warning that must OUTLIVE the screen that caused
  // it. The break-glass replaces the locked screen with the unlocked vault the
  // instant it succeeds, so a message rendered inside UnlockPanel would be
  // unmounted before anyone read it — which is precisely how the orphaned
  // device identity became silent.
  const [notice, setNotice] = useState<string>("");
  // ⛔⛔ THE VAULT-SIZE WARNING, RAISED AT THE MOMENT THE VAULT GROWS — not at the
  // moment sync breaks. `opBodySizeWarning` was previously wired only to Push and
  // to the server's 413, so a user who imported a large Google Authenticator
  // export learned their vault no longer syncs at the moment they lost syncing,
  // long after the choice that caused it and with no supported way to shrink it
  // (tombstones are never pruned; there is no `compact`). It is set by `persist`,
  // which is the single place this app seals the vault, so EVERY growth path —
  // form add, otpauth paste, migration import, QR scan, merge adoption — reaches
  // it without any of them having to remember to.
  const [sizeWarn, setSizeWarn] = useState<string>("");
  // ⛔⛔ WHAT A RESTORE COULD NOT ACCOUNT FOR — and the reason it is HERE and not
  // inside `RestorePanel`. A successful restore calls `setPhase("unlocked")`,
  // which swaps the whole screen for `VaultView` and UNMOUNTS the panel, so a
  // message rendered there would be destroyed at the exact instant it became
  // true. `restoreFromKit` builds these notes — a truncated index, an index
  // route that would not answer, rows deposited from outside the account, vaults
  // whose keys came back but whose content did not — and until now the ONLY
  // consumer was the failure throw. So the one scenario this all exists to make
  // honest, a sheet-driven restore of a crowded index, landed in an unlocked
  // vault telling the user NOTHING. Persistent and dismissible, never a toast:
  // "this may not be everything" is not a transient fact.
  const [restoreNotes, setRestoreNotes] = useState<string[]>([]);

  const now = useUnixClock();

  // Announce phase transitions to assistive tech via the polite live region.
  useEffect(() => {
    const messages: Record<Phase, string> = {
      loading: "Loading the WebAssembly crypto core.",
      error: "Failed to load the crypto core.",
      setup: "No vault yet. Create a vault to begin.",
      locked: "Vault locked. Enter your password to unlock.",
      unlocked: "Vault unlocked.",
    };
    setAnnounce(messages[phase]);
  }, [phase]);

  // ⭐ The same warning, recomputed when a vault is OPENED rather than written —
  // otherwise a vault that was already oversized (imported on another client and
  // pulled here) stays silent until the user happens to add something. `persist`
  // covers every write; this covers every unlock.
  useEffect(() => {
    if (!wasm || !vault) {
      setSizeWarn("");
      return;
    }
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (!stored) return;
    setSizeWarn(wasm.opBodySizeWarning(wasm.base64ToBytes(stored).length) ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wasm, vault]);

  // Load the wasm in the browser only, then decide the initial phase from
  // whether a sealed vault already exists in localStorage.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const m: Wasm = await import("@sigil/wasm");
        await m.initWasm();
        if (cancelled) return;
        setWasm(m);
        const stored = window.localStorage.getItem(STORAGE_KEY);
        setPhase(stored ? "locked" : "setup");
      } catch (e) {
        if (cancelled) return;
        setWasmError(msg(e));
        setPhase("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // ⭐⭐ THE ONE FUNCTION THAT PRODUCES A SEALING SECRET (ADR 0046 §"the gate").
  //
  // `persist()` and `persistDevice()` take ONLY its output and NEVER
  // `passwordRef.current` directly. ADR 0042 §4 taught this the hard way: a rule
  // that lives in a command rather than on the path it protects is a habit, and
  // habits are what new call sites forget. JS cannot enforce it by type the way
  // `VerifiedRecipient` does on the Rust side, so it is enforced by MUTATION
  // PROOF M3 instead — making this fall back to the raw password while a hwslot
  // exists must turn `passkey.spec.ts` spec 2 RED.
  //
  // ⛔ There is NO password-only slot while protection is on. AND, never OR: an
  // OR design lets an offline attacker attack the weaker branch, so the passkey
  // would buy literally zero.
  function sealingSecret(): string | Uint8Array {
    return cmkRef.current ?? passwordRef.current;
  }

  // What seals the TOTP VAULT container. A SHARED vault keeps its random 32-byte
  // vault key (already immune to guessing, and peers must be able to open it);
  // a PERSONAL vault gets whatever `sealingSecret()` says.
  function vaultSealingSecret(): string | Uint8Array {
    return vaultKeyRef.current ?? sealingSecret();
  }

  // ⭐⭐ THE NO-DOWNGRADE RATCHET, at every re-seal this app performs.
  //
  // ⛔ A `SIGILcli` container carries the Argon2id work factors it was sealed
  // with, and a re-seal is where new factors get CHOSEN. This app used to write
  // `ARGON2` verbatim, so a vault the CLI wrote at 65536/4/2 came back from ONE
  // edit here at 19456/2/1 — 3.4x less memory and half the passes, silently, on
  // a vault the user shares with their laptop. The Rust clients have ratcheted
  // since Phase 58 (`sigil_cli::reseal_container`); this is the JS half.
  //
  // `ARGON2` is therefore a FLOOR, not an instruction: the factors written are
  // the componentwise max of what the stored container declares and what this
  // build wants. The rule itself is sigil-core's `Argon2Params::no_downgrade`,
  // reached through the wasm — not a JS reimplementation that could drift.
  function sealParams(m: Wasm, storageKey: string): import("@sigil/wasm").Argon2Params {
    const stored = window.localStorage.getItem(storageKey);
    return m.ratchetParams(m, stored ? m.base64ToBytes(stored) : null, ARGON2);
  }

  // Seal `v` with the CURRENT seal secret (fresh salt + nonce from the CSPRNG)
  // and write the sealed container (base64) to localStorage. Only the sealed
  // bytes are stored — never the vault, the password, a vault key or the CMK.
  function persist(m: Wasm, v: TotpVault, secret?: string | Uint8Array): void {
    const salt = crypto.getRandomValues(new Uint8Array(m.recommended_salt_len()));
    const nonce = crypto.getRandomValues(new Uint8Array(m.nonce_len()));
    const container = m.sealVault(
      m,
      secret ?? vaultSealingSecret(),
      v,
      salt,
      nonce,
      sealParams(m, STORAGE_KEY),
    );
    window.localStorage.setItem(STORAGE_KEY, m.bytesToBase64(container));
    // ⭐ Keyed off the SAME `MAX_OP_BODY_BYTES` the push path and the CLI use —
    // `opBodySizeWarning` is the one implementation, so the import-time warning
    // and the push-time warning can never disagree about the threshold. Measured
    // motivation: a 512-entry import (the provisioning ceiling) seals to ~86 KB
    // against sigild's 64 KiB op cap, i.e. the ceiling permits a vault that
    // cannot sync. This is what tells the user while they still have a choice.
    setSizeWarn(m.opBodySizeWarning(container.length) ?? "");
  }

  // Apply a mutation to a fresh clone of the vault, re-seal + persist, and swap
  // in the new state. The mutator may throw (e.g. a duplicate label) BEFORE any
  // persist happens, so a rejected change never corrupts the stored vault.
  function withVault(fn: (draft: TotpVault) => void): TotpVault {
    if (!wasm || !vault) throw new Error("vault is locked");
    // ⭐ `cloneVault`, NOT `{ version, entries }`. Rebuilding the object
    // field-by-field silently deletes `min_reader_version` and every field a
    // newer client wrote, and this browser would then push the stripped vault
    // over the newer one — the oldest writer wins on the op-log.
    const draft: TotpVault = wasm.cloneVault(vault);
    fn(draft);
    persist(wasm, draft);
    setVault(draft);
    return draft;
  }

  // Seal the device identity under the CURRENT sealing secret and store only the
  // sealed container. Passing null forgets the identity entirely.
  function persistDevice(m: Wasm, d: DeviceIdentity | null): void {
    if (!d) {
      window.localStorage.removeItem(DEVICE_KEY);
      setDevice(null);
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(m.recommended_salt_len()));
    const nonce = crypto.getRandomValues(new Uint8Array(m.nonce_len()));
    const container = m.sealDeviceIdentity(
      m,
      sealingSecret(),
      d,
      salt,
      nonce,
      sealParams(m, DEVICE_KEY),
    );
    window.localStorage.setItem(DEVICE_KEY, m.bytesToBase64(container));
    setDevice(d);
  }

  // Decrypt the stored device identity with `secret`. A container that will not
  // open (e.g. sealed under an older password) yields null rather than blocking
  // the unlock. Does NOT touch React state — the caller decides.
  function openStoredDevice(m: Wasm, secret: string | Uint8Array): DeviceIdentity | null {
    const stored = window.localStorage.getItem(DEVICE_KEY);
    if (!stored) return null;
    try {
      return m.openDeviceIdentity(m, secret, m.base64ToBytes(stored));
    } catch {
      return null;
    }
  }

  function createVault(password: string): void {
    if (!wasm) throw new Error("wasm not ready");
    // ⛔⛔ CLEAR THE STALE SLOT FIRST, and this one line is a LOCKOUT FIX.
    //
    // The initial phase is decided from STORAGE_KEY alone, so a profile whose
    // vault container is gone while the hwslot survives (a partial clear, a
    // quota eviction, a botched restore) shows SETUP. Sealing a fresh vault
    // under a NEW password beside the OLD slot closed BOTH doors: unlock ran a
    // ceremony and then failed to open a slot sealed under the previous
    // password, and the break-glass refused too, because the sheet-derived CMK
    // does not open a container sealed under the brand-new password. A vault
    // that has just been created has no passkey and no sheet behind it, so any
    // slot lying next to it belongs to something that no longer exists.
    window.localStorage.removeItem(HWSLOT_KEY);

    // ⛔ A DEVICE IDENTITY THAT SURVIVED A MISSING VAULT MUST NOT VANISH IN
    // SILENCE. Clearing only the vault container (a partial clear, a quota
    // eviction, a botched restore) lands here at SETUP with the device container
    // still present and sealed under the OLD secret — the Ed25519 seed, the
    // hybrid secret and every accepted vault key. Sealing a fresh vault under a
    // NEW password does not open it, and the break-glass form renders only on the
    // LOCKED phase, so nothing would ever tell the user it was there.
    //
    // It is LEFT BYTE-FOR-BYTE IN PLACE — never deleted — and announced. A
    // permanent loss a human is told about is recoverable by a human; a silent
    // one is not. (This is the same rule the break-glass orphan guard follows.)
    const orphanedIdentity = window.localStorage.getItem(DEVICE_KEY) !== null;

    const v = wasm.newVault();
    setNotice(
      orphanedIdentity
        ? "A device identity from a previous vault is still stored in this browser. It is " +
            "sealed with the OLD secret, so this new vault's password does not open it, and it " +
            "has been LEFT IN PLACE rather than deleted. If you still have that vault's password " +
            "or its recovery sheet, restore that vault instead of creating a new one — otherwise " +
            "this browser will need to enrol as a new device."
        : "",
    );
    passwordRef.current = password;
    vaultKeyRef.current = null;
    cmkRef.current = null;
    prfRef.current = null;
    setProtection(null);
    setActiveVaultId(null);
    persist(wasm, v, password);
    setVault(v);
    setDevice(openStoredDevice(wasm, password));
    setPhase("unlocked");
  }

  /**
   * UNLOCK.
   *
   * ⭐ WITH PROTECTION ON the ceremony fires AFTER the password is submitted, so
   * a typo never costs a WebAuthn prompt, and a ceremony that fails, is
   * cancelled or returns different bytes throws a PASSKEY-specific error the
   * caller renders as such. ⛔ It must never fall through to a generic "wrong
   * password" — that is the worst possible message for someone whose passkey
   * just died, and the recovery-sheet field is right there.
   *
   * ⚠️ CMK-then-password, and that is NOT a residual OR slot. The password is
   * tried as a SECOND candidate — but only once the hwslot has ACTUALLY OPENED,
   * which already required the passkey. After a *successful* enable the
   * ciphertext has changed, so the password path stops working by construction
   * rather than by policy.
   *
   * It is kept because enable is not atomic. ⭐ THE SHIPPED WRITE ORDER IS
   * CONTAINERS FIRST, SLOT LAST (ADR 0046 §4), so an interruption can never
   * leave a slot beside password-sealed containers — a surviving slot means both
   * containers are already CMK-sealed. What it CAN leave is a CMK-sealed vault
   * beside a still-password-sealed device identity, with no slot at all; this
   * list is what keeps that state readable rather than silently discarding the
   * Ed25519 seed, the hybrid secret and every accepted vault key.
   */
  async function unlock(password: string): Promise<void> {
    if (!wasm) throw new Error("wasm not ready");
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (!stored) throw new Error("no sealed vault found");
    const container = wasm.base64ToBytes(stored);

    let cmk: Uint8Array | null = null;
    let prf: Uint8Array | null = null;
    let info: ProtectionInfo | null = null;
    const hw = window.localStorage.getItem(HWSLOT_KEY);
    if (hw) {
      const assertion = await wasm.evaluatePrf();
      prf = assertion.prfOutput;
      const slot = wasm.openHwSlot(wasm, assertion.prfOutput, password, wasm.base64ToBytes(hw));
      cmk = slot.cmk;
      // ⭐ The scope claim comes from the flags of THIS ceremony, never from what
      // happened to be true when protection was switched on.
      info = {
        kitDeviceId: slot.kitDeviceId,
        credentialId: slot.credentialId,
        backupEligible: assertion.backupEligible,
        backupState: assertion.backupState,
        // ⭐ The REAL `authenticatorAttachment` from the ceremony. This used to
        // be inferred as `backupEligible ? "" : "platform"`, which told every
        // holder of a non-syncing SECURITY KEY that their factor lived "on this
        // device only" — the opposite of true, and exactly the wrong advice
        // about what they need to keep safe.
        attachment: assertion.attachment,
      };
    }

    const candidates: (string | Uint8Array)[] = cmk ? [cmk, password] : [password];

    // The device identity carries any vault keys, so it must be read first.
    let d: DeviceIdentity | null = null;
    for (const secret of candidates) {
      d = openStoredDevice(wasm, secret);
      if (d) break;
    }

    // A personal vault opens with the sealing secret. A SHARED vault is sealed
    // under a random 32-byte vault key instead, so fall back to the keys this
    // device holds — exactly the CLI's `--vault-id` rule, chosen automatically.
    let v: TotpVault | null = null;
    let usedVaultKey: Uint8Array | null = null;
    let sharedAs: string | null = null;
    let firstError: unknown = null;
    for (const secret of candidates) {
      try {
        v = wasm.openVault(wasm, secret, container);
        break;
      } catch (e) {
        firstError ??= e;
      }
    }
    if (!v) {
      for (const [id, key] of Object.entries(d?.vaultKeys ?? {})) {
        try {
          v = wasm.openVault(wasm, key, container);
          usedVaultKey = key;
          sharedAs = id;
          break;
        } catch {
          // not this vault's key — try the next one
        }
      }
    }
    if (!v) {
      // ⛔ NOT "wrong password or tampered vault". A container that refuses the
      // password is ALSO what a CMK-sealed container looks like once its slot is
      // gone, and telling someone whose password is perfectly correct that it is
      // wrong sends them to retype it forever while the one thing that WOULD
      // work — the printed sheet — sits unmentioned on the same screen. The
      // AEAD tag cannot tell the two apart, so the wording must not pretend to.
      throw new Error(
        "that did not open the vault stored in this browser. Either the password is wrong, or " +
          "this vault is sealed with a key this browser no longer holds — a passkey slot that " +
          "was deleted or overwritten, or a shared-vault key. If you have your printed recovery " +
          "sheet, use it below: it derives the key on its own, with no passkey and no network. " +
          `(${msg(firstError)})`,
      );
    }

    passwordRef.current = password;
    vaultKeyRef.current = usedVaultKey;
    cmkRef.current = cmk;
    prfRef.current = prf;
    setProtection(info);
    setDevice(d);
    setActiveVaultId(sharedAs);
    setVault(v);
    setPhase("unlocked");
  }

  function lock(): void {
    setNotice("");
    passwordRef.current = "";
    vaultKeyRef.current = null;
    cmkRef.current = null;
    prfRef.current = null;
    setProtection(null);
    setActiveVaultId(null);
    setVault(null);
    setDevice(null); // the seed, hybrid secret and vault keys leave memory too
    setPhase("locked");
  }

  function forget(): void {
    setNotice("");
    // The profile these notes were about is being destroyed; keeping them would
    // describe a restore that no longer exists. (`lock()` deliberately does NOT
    // clear them — "this may not be everything" stays true across a lock.)
    setRestoreNotes([]);
    window.localStorage.removeItem(STORAGE_KEY);
    window.localStorage.removeItem(DEVICE_KEY);
    window.localStorage.removeItem(HWSLOT_KEY);
    passwordRef.current = "";
    vaultKeyRef.current = null;
    cmkRef.current = null;
    prfRef.current = null;
    setProtection(null);
    setActiveVaultId(null);
    setVault(null);
    setDevice(null);
    setPhase("setup");
  }

  // ── ADR 0046: passkey protection of the two local containers ───────────────

  /**
   * STAGE 1 of enabling. In this order, because the ORDER IS THE SAFETY
   * PROPERTY:
   *   1. refuse unless a recovery kit already exists — NO SHEET, NO PROTECTION,
   *      because the sheet is the only break-glass and a protected browser
   *      without one is the single new way to lose a vault;
   *   2. probe PRF for real (create + get + get again, 32 bytes, byte-identical).
   *
   * Nothing is written here.
   */
  async function beginPasskeyProtection(baseUrl: string): Promise<PasskeyProbeSummary> {
    if (!wasm) throw new Error("wasm not ready");
    if (!device) {
      throw new PasskeyPrecondition(
        "This browser has no recovery kit to fall back on. Enroll it (Sync → Device identity) " +
          "and print a recovery kit below FIRST — a passkey without a printed sheet is the one " +
          "way this feature could cost you your codes.",
      );
    }
    let kitDeviceId = "";
    try {
      const account = await wasm.getAccount(wasm, device, baseUrl);
      const kits = (account.devices ?? []).filter(
        (d) => d.label === wasm.RECOVERY_DEVICE_LABEL && (d.status ?? "active") === "active",
      );
      if (kits.length === 0) {
        throw new PasskeyPrecondition(
          "This account has no recovery kit. Print one below (Recovery kit → Generate) before " +
            "protecting this browser with a passkey: the printed sheet is the ONLY way back in " +
            "if the passkey ever becomes unavailable.",
        );
      }
      // ⚠️ WHICH kit is recorded, and why it is sometimes NONE. The CMK comes from
      // the code the user types, but the DEVICE ID of the kit that code belongs to
      // is not derivable offline — `GET /v1/account` carries no public key to
      // match against. With exactly one active kit there is no ambiguity. With
      // SEVERAL, picking one would be a guess, and a wrong guess makes the
      // relink banner point at the wrong sheet — worse than no banner, because it
      // would be confidently wrong. So record nothing and monitor nothing; the
      // protection itself is unaffected, since it is keyed by the typed code.
      kitDeviceId = kits.length === 1 ? kits[0].device_id : "";
    } catch (e) {
      if (e instanceof PasskeyPrecondition) throw e;
      throw new PasskeyPrecondition(
        "Could not confirm that this account has a recovery kit, so protection was NOT enabled " +
          `(${msg(e)}). This check fails closed on purpose.`,
      );
    }

    const probe = await wasm.probePrf();
    prfRef.current = probe.prfOutput;
    probeRef.current = { ...probe, kitDeviceId };
    return {
      backupEligible: probe.backupEligible,
      attachment: probe.attachment,
      scope: wasm.describeProtectionScope(probe),
    };
  }

  /**
   * STAGE 2 of enabling: the recovery code is typed back, decoded and
   * checksummed OFFLINE (so a typo never reaches a server), and only then does
   * anything get re-sealed.
   *
   * ⭐ Write order is vault → device → hwslot: CONTAINERS FIRST, SLOT LAST.
   * Enable is NOT atomic, and this ordering chooses which state a crash leaves
   * behind — CMK-sealed containers with no slot, which the printed sheet alone
   * recovers. See the block comment at the write itself for why the reverse
   * order was rejected.
   */
  async function completePasskeyProtection(code: string): Promise<ProtectionInfo> {
    if (!wasm || !vault) throw new Error("vault is locked");
    const probe = probeRef.current;
    if (!probe || !prfRef.current) {
      throw new PasskeyPrecondition("run the passkey check again before protecting this browser");
    }
    const seed = wasm.verifyRecoveryKit(wasm, code); // offline decode + checksum
    const cmk = await wasm.deriveContainerMasterKey(seed);

    const salt = () => crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
    const nonce = () => crypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
    const slotBytes = wasm.sealHwSlot(
      wasm,
      {
        prfOutput: prfRef.current,
        password: passwordRef.current,
        cmk,
        kitDeviceId: probe.kitDeviceId,
        credentialId: probe.credentialId,
        rpId: probe.rpId,
        backupEligible: probe.backupEligible,
        backupState: probe.backupState,
      },
      salt(),
      nonce(),
      sealParams(wasm, HWSLOT_KEY),
    );
    // ⭐ WRITE ORDER IS THE SAFETY PROPERTY: containers FIRST, slot LAST.
    //
    // Enabling is not atomic, so every ordering has an interruption window — the
    // question is only which state a crash leaves behind. Writing the slot first
    // (the original order) left a slot beside still-PASSWORD-sealed containers,
    // and in THAT state the printed sheet alone is not a door: a sheet-derived
    // CMK cannot open a password-sealed container, so recovery also needed the
    // old password. That is information-theoretically true at the unlock end and
    // cannot be fixed there — but it can be avoided here.
    //
    // Writing the containers first and the slot last inverts the window: a crash
    // now leaves CMK-sealed containers with NO slot, which the break-glass opens
    // from the sheet ALONE, exactly as the design promises. The slot is a
    // recoverable marker; the containers are the only copy. Make the last write
    // the one whose loss costs least.
    cmkRef.current = cmk;
    persist(wasm, vault);
    if (device) persistDevice(wasm, device);
    window.localStorage.setItem(HWSLOT_KEY, wasm.bytesToBase64(slotBytes));

    const info: ProtectionInfo = {
      kitDeviceId: probe.kitDeviceId,
      credentialId: probe.credentialId,
      backupEligible: probe.backupEligible,
      backupState: probe.backupState,
      attachment: probe.attachment,
    };
    setProtection(info);
    return info;
  }

  /** Turn protection OFF: re-seal both containers under the password, drop the slot. */
  function disablePasskeyProtection(): void {
    if (!wasm || !vault) throw new Error("vault is locked");
    if (!passwordRef.current) {
      throw new PasskeyPrecondition(
        "this browser was opened with the recovery sheet, so it has no password to fall back to",
      );
    }
    cmkRef.current = null;
    prfRef.current = null;
    probeRef.current = null;
    persist(wasm, vault);
    if (device) persistDevice(wasm, device);
    window.localStorage.removeItem(HWSLOT_KEY);
    setProtection(null);
  }

  /**
   * ⭐ RE-SEAL THE SLOT WHEN THE KIT IS REPRINTED.
   *
   * Reprinting a kit changes the 32 printed bytes and therefore the CMK. The
   * containers stay openable by the passkey (the slot still yields the OLD CMK),
   * so it is not a brick — it is a SILENT LOSS OF THE BREAK-GLASS, which is
   * worse, because nothing tells you. Same failure shape as ADR 0042's
   * `RecipientsWouldBeDropped`, so it is BUILT, not remembered.
   */
  async function rekeyProtectionForNewKit(code: string, kitDeviceId: string): Promise<void> {
    if (!wasm || !vault) throw new Error("vault is locked");
    if (!protection || !prfRef.current) return; // unprotected: nothing to re-seal
    const seed = wasm.verifyRecoveryKit(wasm, code);
    const cmk = await wasm.deriveContainerMasterKey(seed);
    const slotBytes = wasm.sealHwSlot(
      wasm,
      {
        prfOutput: prfRef.current,
        password: passwordRef.current,
        cmk,
        kitDeviceId,
        credentialId: protection.credentialId,
        rpId: probeRef.current?.rpId ?? "",
        backupEligible: protection.backupEligible,
        backupState: protection.backupState,
      },
      crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len())),
      crypto.getRandomValues(new Uint8Array(wasm.nonce_len())),
      sealParams(wasm, HWSLOT_KEY),
    );
    window.localStorage.setItem(HWSLOT_KEY, wasm.bytesToBase64(slotBytes));
    cmkRef.current = cmk;
    persist(wasm, vault);
    if (device) persistDevice(wasm, device);
    setProtection({ ...protection, kitDeviceId });
  }

  /**
   * ⭐⭐ THE BREAK-GLASS (matrix row 3), and the reason constraint 3 holds.
   *
   * The printed ADR 0042 sheet derives the CMK by HKDF, entirely OFFLINE — no
   * server, no network, no passkey — so every way a passkey can become
   * unavailable lands here and loses nothing. It also works with the WRONG
   * password (matrix row 5): the sheet alone opens the containers, which is
   * strictly better than today, where a forgotten password over a personal vault
   * is fatal.
   *
   * On success protection is DROPPED and both containers are re-sealed under the
   * new password: the passkey that is gone cannot re-seal a slot, and leaving a
   * stale slot behind would brick the browser on the next reload.
   *
   * ⚠️ MIXED STATE, handled exactly the way `unlock()` handles it. Enabling is
   * NOT atomic (vault → device → hwslot), so an interruption between the two
   * container writes leaves the device identity sealed under the OLD PASSWORD
   * beside a CMK-sealed vault, and no slot at all. Trying
   * only the CMK there left the Ed25519 seed, the hybrid secret and every
   * accepted vault key permanently unreadable, with no message. So the candidate
   * list is CMK → the optional current password → the new one, and when NONE of
   * them opens it the container is left EXACTLY as it is and the caller is told.
   */
  async function unlockWithRecoverySheet(
    code: string,
    newPassword: string,
    currentPassword = "",
  ): Promise<{ deviceOrphaned: boolean }> {
    if (!wasm) throw new Error("wasm not ready");
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (!stored) throw new Error("no sealed vault found");
    const container = wasm.base64ToBytes(stored);

    const seed = wasm.verifyRecoveryKit(wasm, code); // offline decode + checksum
    const cmk = await wasm.deriveContainerMasterKey(seed);

    const hadDevice = window.localStorage.getItem(DEVICE_KEY) !== null;
    const deviceCandidates: (string | Uint8Array)[] = [cmk];
    if (currentPassword) deviceCandidates.push(currentPassword);
    if (newPassword && newPassword !== currentPassword) deviceCandidates.push(newPassword);
    let d: DeviceIdentity | null = null;
    for (const secret of deviceCandidates) {
      d = openStoredDevice(wasm, secret);
      if (d) break;
    }

    let v: TotpVault | null = null;
    let usedVaultKey: Uint8Array | null = null;
    let sharedAs: string | null = null;
    // ⭐ THE VAULT GETS THE SAME CANDIDATE LIST AS THE DEVICE, and this is a
    // LOCKOUT FIX, not a convenience. Enabling protection is NOT atomic: it
    // re-seals the vault, then the device identity, then writes the slot
    // (containers first, slot last — ADR 0046 §4). A crash between the two
    // container writes leaves a CMK-sealed vault beside a still-PASSWORD-sealed
    // device identity. Trying ONLY the CMK there left the Ed25519 seed, the
    // hybrid secret and every accepted vault key unreadable for a user holding a
    // correct sheet AND the correct old password. Reproduced live.
    //
    // ⚠️ THIS DOES NOT BECOME AN "OR" DESIGN. The whole branch is already gated
    // behind a valid `verifyRecoveryKit(code)`, so the door is
    // "sheet AND (CMK OR the old password)" — the (password AND passkey) door is
    // untouched, and nothing here opens a vault without the printed sheet.
    for (const secret of deviceCandidates) {
      try {
        v = wasm.openVault(wasm, secret, container);
        break;
      } catch {
        // not this secret — try the next candidate
      }
    }
    if (!v) {
      for (const [id, key] of Object.entries(d?.vaultKeys ?? {})) {
        try {
          v = wasm.openVault(wasm, key, container);
          usedVaultKey = key;
          sharedAs = id;
          break;
        } catch {
          // not this vault's key — try the next one
        }
      }
    }
    if (!v) {
      throw new Error(
        "that recovery code is valid, but the key it derives does not open the containers stored " +
          "in THIS browser. Either this browser was protected with a different sheet, or it was " +
          "never protected at all — in which case unlock it with its password instead.",
      );
    }

    passwordRef.current = newPassword;
    vaultKeyRef.current = usedVaultKey;
    cmkRef.current = null; // ⭐ protection is dropped: the passkey is gone
    prfRef.current = null;
    probeRef.current = null;
    persist(wasm, v);
    // ⛔ THE ORPHAN GUARD. When the identity opened, re-seal it under the new
    // secret through the ONE gate. When it did NOT, leave the container byte-for-
    // byte alone: it is still openable by whoever knows the previous password,
    // and overwriting or deleting it would destroy the only copy of the seed,
    // the hybrid secret and every accepted vault key. Either way SAY SO — a
    // permanent loss that announces itself is recoverable by a human; a silent
    // one is not.
    const deviceOrphaned = hadDevice && !d;
    if (d) persistDevice(wasm, d);
    // Safe to drop now, and only now: the vault is password-sealed again, so a
    // slot demanding a passkey could only produce a ceremony this profile no
    // longer needs. Nothing still sealed depends on it — an orphaned identity is
    // sealed under a PASSWORD, which no slot could have supplied anyway.
    window.localStorage.removeItem(HWSLOT_KEY);
    setProtection(null);
    setDevice(d);
    setActiveVaultId(sharedAs);
    setVault(v);
    setPhase("unlocked");
    setNotice(
      deviceOrphaned
        ? "Your vault was recovered, but this browser's DEVICE IDENTITY could not be opened — it " +
            "is still sealed under the password this browser used before, which happens when " +
            "turning protection on was interrupted. It has been left untouched, not deleted. If " +
            "you remember that password, unlock again with the sheet and type it into “Current " +
            "vault password”. Otherwise enroll this browser again: the Ed25519 device key, the " +
            "hybrid secret and any vault keys it held are not readable without it."
        : "",
    );
    return { deviceOrphaned };
  }

  // ── RECOVERY: restore on a client with NO identity and NO vault ────────────
  //
  // ⭐ THE FLOW THAT MATTERS, and the reason it lives up here rather than in the
  // unlocked view: a user who lost every device is looking at a FRESH INSTALL.
  // There is no vault to unlock, no device identity, no pin store and no keyring
  // — only the printed sheet. So restore must be reachable from the setup and
  // locked screens, before anything exists.
  //
  // ⚠️ THE 56-CHARACTER CODE IS A CREDENTIAL. It is never written to
  // localStorage, never put in a URL or query string, never logged, and never
  // sent anywhere except the offline decode + the derivation. `restoreFromKit`
  // decodes and checksums it BEFORE any network I/O, so a mistyped code never
  // reaches a server; the caller clears the field as soon as this returns.
  //
  // ⚠️ WHAT IS PERSISTED, and it is not the code: this browser ADOPTS the kit's
  // derived identity, sealed under a new vault password inside the existing
  // device-identity container. That makes this browser a second copy of the
  // paper credential, which the UI says in those words.
  async function restoreFromRecoveryKit(args: {
    baseUrl: string;
    code: string;
    deviceId: string;
    password: string;
    vaultIds?: string[];
  }): Promise<{ vaultId: string; accounts: number; accountId: string; notes: string[] }> {
    if (!wasm) throw new Error("wasm not ready");
    const baseUrl = args.baseUrl.trim();

    // Offline decode + checksum happens inside restoreFromKit, before any I/O.
    // ⭐ `vaultIds` are the ids printed on the sheet's "covers" line. Supplying
    // them makes the restore ask each VAULT directly instead of asking the
    // server what is waiting for this kit — that listing is ONE uncursored page
    // any other account can crowd rows off. With none supplied and a crowded
    // listing, `restoreFromKit` REFUSES rather than restoring part of the vaults
    // and calling it done.
    const res = await wasm.restoreFromKit(wasm, {
      baseUrl,
      code: args.code,
      deviceId: args.deviceId.trim(),
      vaultIds: args.vaultIds ?? [],
    });

    const kitAuth = {
      deviceId: res.deviceId,
      seed: res.identity.ed25519Seed,
      baseUrl,
      hybrid: res.identity.hybrid,
    };

    // The kit recovers KEYS. Ciphertext still has to exist on the server, so try
    // each recovered vault until one has content this key opens.
    const notes: string[] = res.skipped.map((s) => `${s.vaultId}: ${s.reason}`);
    // ⛔ NEVER PRESENT A TRUNCATED RESTORE AS COMPLETE.
    if (res.indexTruncated) {
      notes.push(
        "⚠️ THIS MAY NOT BE EVERYTHING: this server holds more waiting keys for this kit " +
          "than it will list at once, and there is no way to ask for the rest. What came " +
          "back is what you named plus one page — a vault covered AFTER the sheet was " +
          "printed may exist and be invisible here.",
      );
    }
    // ⚠️ DEGRADED, NOT SILENT. The sheet path deliberately does not depend on the
    // index route, so a dead route is survivable — but nothing here could check
    // for a vault covered AFTER the sheet was printed, and the user has to be
    // told that rather than shown a clean success.
    if (res.indexError) {
      notes.push(
        `the server's list of what is waiting for this kit could not be read (${res.indexError}). ` +
          "Only the vault ids you typed were used, which is what that line on the sheet is for — " +
          "but a vault covered AFTER the sheet was printed could not be looked for.",
      );
    }
    // ⭐ ONE SUMMARY, NEVER ONE LINE PER ROW: a flood is bounded noise, and
    // printing it row by row would bury the result the user came to read — which
    // is exactly what the flood is for.
    if (res.ignoredUntrusted > 0) {
      notes.push(
        `${res.ignoredUntrusted} vault(s) this server listed for this kit were deposited by ` +
          "devices OUTSIDE your account and were ignored — not fetched, not unwrapped, and their " +
          "keys were not pinned. Anyone can address an envelope to a kit; an envelope proves WHO " +
          "sent it, never that they are trusted. A vault genuinely shared to this kit from " +
          "another account has to be collected from a working device.",
      );
    }
    if (res.fromSheet.length > 0) {
      notes.push(
        `found by asking the vault directly (the server's list did not name ${
          res.fromSheet.length === 1 ? "it" : "them"
        }): ${res.fromSheet.join(", ")}`,
      );
    }
    let opened: TotpVault | null = null;
    let openedId = "";
    let openedKey: Uint8Array | null = null;
    let openedContainer: Uint8Array | null = null;
    for (const v of res.vaults) {
      try {
        const ops = await wasm.pullContainersAuthed(wasm, kitAuth, baseUrl, v.vaultId, 0);
        if (ops.length === 0) {
          notes.push(
            `${v.vaultId}: the key was recovered, but the server holds no vault content for it`,
          );
          continue;
        }
        // ⭐ Phase 61: MERGE every op, do not adopt the tip. A restore is the one
        // path where the user cannot check the result against anything, so
        // reconstructing the UNION of every snapshot rather than whichever one
        // happened to be pushed last matters most here. `mergeOpsInto` throws
        // nothing on a bad op — it skips and names it — so an empty result still
        // has to be treated as "nothing opened".
        const merged = wasm.mergeOpsInto(wasm, v.vaultKey, wasm.newVault(), ops);
        if (merged.applied === 0) {
          notes.push(
            `${v.vaultId}: ${merged.skipped.length} op(s) present but none opened with the recovered key`,
          );
          continue;
        }
        for (const sk of merged.skipped) {
          notes.push(`${v.vaultId}: op #${sk.seq} was not merged (${sk.reason})`);
        }
        const container = wasm.sealVault(
          wasm,
          v.vaultKey,
          merged.vault,
          crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len())),
          crypto.getRandomValues(new Uint8Array(wasm.nonce_len())),
          wasm.ratchetParams(wasm, ops[ops.length - 1].container, ARGON2),
        );
        opened = merged.vault;
        openedId = v.vaultId;
        openedKey = v.vaultKey;
        openedContainer = container;
        break;
      } catch (e) {
        notes.push(`${v.vaultId}: ${msg(e)}`);
      }
    }

    if (!opened || !openedKey || !openedContainer) {
      // Persist NOTHING on this path: a half-restored browser (an identity with
      // no vault) is worse than a clean refusal, and this state is the honest,
      // documented limit — a kit recovers keys, not data.
      throw new Error(
        `the recovery code and device id are valid and ${res.vaults.length} vault key(s) were ` +
          "recovered, but no vault content could be opened. A recovery kit recovers KEYS, not " +
          "DATA: a vault whose sealed container was never pushed to this server cannot come " +
          `back.${notes.length ? ` Details: ${notes.join("; ")}.` : ""}`,
      );
    }

    // Adopt the kit: keep every recovered vault key and PIN the kit's own hybrid
    // key as DERIVED (origin "recovery-kit"), so a later cover from this client
    // wraps to a locally derived key and never asks the server for one.
    const vaultKeys: Record<string, Uint8Array> = {};
    for (const v of res.vaults) vaultKeys[v.vaultId] = v.vaultKey;
    // ⭐ PHASE 60: start from the store the restore itself built. Every envelope
    // it opened was AUTHENTICATED against its depositing device's key, and that
    // key was pinned in the process — dropping it here would make each of those
    // senders first-sight all over again on the next accept.
    const pins = res.pins ?? wasm.newPinStore();
    await wasm.pinDerivedKey(
      pins,
      res.deviceId,
      wasm.hybridPublicIdentity(wasm, res.identity.hybrid),
    );

    passwordRef.current = args.password;
    // ⭐ A restored profile is always UNPROTECTED: there is no local hwslot and
    // no passkey here yet. The user may enable protection afterwards.
    cmkRef.current = null;
    prfRef.current = null;
    probeRef.current = null;
    setProtection(null);
    window.localStorage.removeItem(HWSLOT_KEY);
    // Seals the adopted identity under the NEW password — the only thing that
    // ever reaches localStorage is that container.
    persistDevice(wasm, {
      deviceId: res.deviceId,
      seed: res.identity.ed25519Seed,
      baseUrl,
      hybrid: res.identity.hybrid,
      vaultKeys,
      pins,
    });
    window.localStorage.setItem(STORAGE_KEY, wasm.bytesToBase64(openedContainer));
    vaultKeyRef.current = openedKey;
    setActiveVaultId(openedId);
    setVault(opened);
    // ⛔ RAISED BEFORE the phase flip that unmounts the panel, and held at the top
    // level so it survives it. A restore that could not account for everything
    // must say so in the vault it just opened, not in a screen that is about to
    // disappear.
    setRestoreNotes(notes);
    setPhase("unlocked");
    return {
      vaultId: openedId,
      accounts: opened.entries.length,
      accountId: res.accountId,
      notes,
    };
  }

  // ── sharing operations (all secrets stay sealed at rest) ───────────────────

  // Merge a change into the device identity and RE-SEAL it under the vault
  // password. This is how a hybrid secret identity or a newly recovered vault key
  // reaches storage: inside the sealed container, never as plaintext.
  function updateDevice(patch: Partial<DeviceIdentity>): DeviceIdentity {
    if (!wasm) throw new Error("wasm not ready");
    if (!device) {
      throw new Error("enroll this browser as a device first (Sync → Device identity)");
    }
    const next: DeviceIdentity = { ...device, ...patch };
    persistDevice(wasm, next);
    return next;
  }

  // Convert this PERSONAL vault into a SHARED one: re-seal the same accounts
  // under `vaultKey` and remember that key inside the sealed device identity.
  // The human password is NEVER shared, wrapped or sent — this is the one-way
  // door between the two, mirroring `sigil vault rekey`.
  function rekeyVault(vaultId: string, vaultKey: Uint8Array): void {
    if (!wasm || !vault) throw new Error("vault is locked");
    updateDevice({ vaultKeys: { ...(device?.vaultKeys ?? {}), [vaultId]: vaultKey } });
    vaultKeyRef.current = vaultKey;
    persist(wasm, vault, vaultKey);
    setActiveVaultId(vaultId);
  }

  // Adopt a vault that was shared TO this device: remember the recovered key
  // (sealed), store the pulled container, and open it in memory.
  function adoptSharedVault(vaultId: string, vaultKey: Uint8Array, container: Uint8Array): TotpVault {
    if (!wasm) throw new Error("wasm not ready");
    const v = wasm.openVault(wasm, vaultKey, container); // throws before anything is stored
    updateDevice({ vaultKeys: { ...(device?.vaultKeys ?? {}), [vaultId]: vaultKey } });
    window.localStorage.setItem(STORAGE_KEY, wasm.bytesToBase64(container));
    vaultKeyRef.current = vaultKey;
    setActiveVaultId(vaultId);
    setVault(v);
    return v;
  }

  // ⭐⭐ THE FIX FOR LAST-WRITER-WINS (Phase 61), at the level that actually loses
  // the data.
  //
  // ⛔ `pull()` used to take `ops[ops.length - 1]` and write it over the stored
  // container. So: this browser adds `github` and pushes; a phone that never
  // pulled adds `gitlab` and pushes; the phone's snapshot is now the tip, it has
  // never seen `github`, and one Pull click destroys it — with both devices
  // reporting success. For an authenticator a lost 2FA secret can mean a
  // permanently lost account.
  //
  // ⭐ The op-log already holds EVERY snapshot, so the fix costs nothing on the
  // wire: fold them all. It even recovers data the old behaviour already
  // shadowed, because the entry is still sitting in an earlier op.
  //
  // This lives in the PARENT and not in `SyncPanel` because only the parent holds
  // the opening secret — which is why the old panel could do nothing better than
  // store bytes and say "lock and unlock".
  function mergeOpsIntoVault(ops: { seq: number; container: Uint8Array }[]) {
    if (!wasm || !vault) throw new Error("vault is locked");
    const res = wasm.mergeOpsInto(wasm, vaultSealingSecret(), vault, ops);
    // Persist FIRST (it can throw), then swap the in-memory vault in, so a failed
    // seal never leaves the UI showing accounts that are not on disk.
    persist(wasm, res.vault);
    setVault(res.vault);
    return res;
  }

  // ⭐ The locked screen's own view of protection: the SLOT IS PRESENT. It cannot
  // know more than that until the ceremony and the password have both succeeded,
  // which is exactly right — the truth is the ciphertext.
  const hasStoredSlot =
    phase === "locked" && typeof window !== "undefined"
      ? window.localStorage.getItem(HWSLOT_KEY) !== null
      : false;

  let content: React.ReactNode;
  if (phase === "loading") {
    content = (
      <Card>
        <p data-testid="auth-status" className="text-sm text-neutral-600 dark:text-neutral-400">
          Loading WebAssembly crypto core…
        </p>
      </Card>
    );
  } else if (phase === "error") {
    content = (
      <Card>
        <p data-testid="auth-status" role="alert" className="text-sm text-red-700 dark:text-red-400">
          Failed to load the wasm core: {wasmError}
        </p>
      </Card>
    );
  } else if (phase === "setup") {
    content = (
      <div className="space-y-6">
        <SetupPanel onCreate={createVault} />
        {wasm && <RestorePanel wasm={wasm} onRestore={restoreFromRecoveryKit} />}
      </div>
    );
  } else if (phase === "locked") {
    content = (
      <div className="space-y-6">
        {wasm && (
          <UnlockPanel
            wasm={wasm}
            hasPasskeySlot={hasStoredSlot}
            onUnlock={unlock}
            onBreakGlass={unlockWithRecoverySheet}
            onForget={forget}
          />
        )}
        {wasm && <RestorePanel wasm={wasm} onRestore={restoreFromRecoveryKit} />}
      </div>
    );
  } else if (!wasm || !vault) {
    content = null;
  } else {
    content = (
      <VaultView
        wasm={wasm}
        vault={vault}
        now={now}
        device={device}
        activeVaultId={activeVaultId}
        protection={protection}
        onBeginPasskey={beginPasskeyProtection}
        onCompletePasskey={completePasskeyProtection}
        onDisablePasskey={disablePasskeyProtection}
        onKitReprinted={rekeyProtectionForNewKit}
        onDeviceChange={(d) => persistDevice(wasm, d)}
        onUpdateDevice={updateDevice}
        onRekey={rekeyVault}
        onAdoptSharedVault={adoptSharedVault}
        // ⭐ Phase 61: `addEntryChecked`, which refuses an account already in the
        // vault by CONTENT FINGERPRINT rather than by label — so `work` at two
        // different issuers is two accounts, and re-importing the same export is
        // a no-op.
        onAdd={(input) =>
          withVault((d) => {
            if (!wasm.addEntryChecked(wasm, d, input)) {
              throw new Error("this exact account is already in the vault");
            }
          })
        }
        onImportOtpauth={(uri) => {
          const e = wasm.parseOtpauthUri(uri);
          withVault((d) => {
            const added = wasm.addEntryChecked(wasm, d, {
              label: e.label,
              issuer: e.issuer,
              secretBytes: wasm.base64ToBytes(e.secret),
              algorithm: e.algorithm,
              digits: e.digits,
              period: e.period,
            });
            if (!added) throw new Error("this exact account is already in the vault");
          });
        }}
        onImportMigration={(uri) => importMigration(wasm, uri, withVault)}
        // ⭐ Phase 61: remove by IDENTITY (labels are no longer unique) AND record
        // a TOMBSTONE. A removal that writes no tombstone is exactly the
        // pre-Phase-61 behaviour: the entry comes straight back the next time
        // this vault meets a snapshot that still holds it.
        onRemove={(uuid) =>
          withVault((d) => {
            wasm.removeEntry(wasm, d, { uuid }, Math.floor(Date.now() / 1000));
          })
        }
        onMergeOps={mergeOpsIntoVault}
        onLock={lock}
      />
    );
  }

  return (
    <>
      <p data-testid="live-region" role="status" aria-live="polite" className="sr-only">
        {announce}
      </p>
      {sizeWarn && (
        // ⛔ A vault that has outgrown the server's 64 KiB op body cannot be
        // shrunk from here — tombstones are never pruned and there is no
        // compaction command — so this is deliberately a persistent, top-level
        // alert rather than a transient toast attached to whichever import
        // caused it. It says the same thing the CLI and the Push path say,
        // because it IS the same function.
        <div
          data-testid="vault-size-warning"
          role="alert"
          className="mb-4 rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        >
          {sizeWarn}
        </div>
      )}
      {restoreNotes.length > 0 && (
        // ⛔⛔ WHAT THE RESTORE COULD NOT ACCOUNT FOR. Persistent and top-level
        // for the same reason the vault-size warning is: the user cannot act on
        // it from here and it does not stop being true when a toast times out.
        // It deliberately OUTLIVES the panel that produced it — that panel is
        // unmounted by the success it is reporting on.
        <div
          data-testid="restore-notes"
          role="alert"
          className="mb-4 rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        >
          <p className="mb-1 font-semibold">
            This restore could not account for everything.
          </p>
          <ul className="list-disc space-y-1 pl-5">
            {restoreNotes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
          <button
            data-testid="restore-notes-dismiss"
            className={`${btnGhost} mt-2`}
            type="button"
            onClick={() => setRestoreNotes([])}
          >
            Dismiss
          </button>
        </div>
      )}
      {notice && (
        <div
          data-testid="global-notice"
          role="alert"
          className="mb-4 rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        >
          <p>{notice}</p>
          <button
            data-testid="global-notice-dismiss"
            className={`${btnGhost} mt-2`}
            type="button"
            onClick={() => setNotice("")}
          >
            Dismiss
          </button>
        </div>
      )}
      {content}
    </>
  );
}

// Import every TOTP entry from a Google-Authenticator otpauth-migration:// URI,
// skipping duplicates (already-present labels). Returns {imported, skipped}.
function importMigration(
  wasm: Wasm,
  uri: string,
  withVault: (fn: (draft: TotpVault) => void) => TotpVault,
): {
  imported: number;
  skipped: number;
  skippedNames: string[];
  batchNote: string | null;
  finalBatch: boolean;
} {
  // ⛔ ONE URI IS ONE QR CODE. Google Authenticator splits a large export across
  // several, each carrying a SLICE of the accounts, so a count on its own is a
  // lie for exactly the users with the most to lose. `batchNote` is non-null
  // when there are more QRs to import, and the caller must render it.
  const batch = wasm.decodeMigrationUri(uri);
  const entries: TotpEntry[] = batch.entries;
  let imported = 0;
  let skipped = 0;
  // ⭐ NAME what was skipped. A bare count is what let the duplicate-label defect
  // hide: a user saw "skipped 1" and had no way to learn WHICH account it was.
  const skippedNames: string[] = [];
  withVault((draft) => {
    for (const e of entries) {
      try {
        // ⭐ Phase 61: `addEntryChecked` compares the CONTENT FINGERPRINT, not the
        // label. `work` at GitHub and `work` at GitLab are two accounts and both
        // land; re-importing the same export adds nothing. The old `addEntry`
        // threw on a duplicate LABEL, so the second of two same-labelled accounts
        // was counted as "skipped" and SILENTLY DROPPED — in the feature whose
        // entire purpose is not losing accounts.
        const added = wasm.addEntryChecked(wasm, draft, {
          label: e.label,
          issuer: e.issuer,
          secretBytes: wasm.base64ToBytes(e.secret),
          algorithm: e.algorithm,
          digits: e.digits,
          period: e.period,
        });
        if (added) {
          imported += 1;
        } else {
          skipped += 1; // already in the vault, compared by content
          skippedNames.push(e.issuer ? `${e.issuer}: ${e.label}` : e.label);
        }
      } catch (err) {
        skipped += 1; // unsupported params
        skippedNames.push(`${e.issuer ? `${e.issuer}: ` : ""}${e.label} (${msg(err)})`);
      }
    }
  });
  return {
    imported,
    skipped,
    skippedNames,
    batchNote: batch.batchNote,
    finalBatch: !!batch.finalBatch,
  };
}

// ── Presentational shell ─────────────────────────────────────────────────────

function Card({ children }: { children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-neutral-300 p-6 dark:border-neutral-700">
      {children}
    </section>
  );
}

const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500 focus-visible:ring-offset-1 focus-visible:ring-offset-white dark:focus-visible:ring-neutral-400 dark:focus-visible:ring-offset-neutral-950";
const inputCls =
  `w-full rounded border border-neutral-400 bg-transparent px-3 py-2 text-sm dark:border-neutral-600 ${focusRing}`;
const btnCls =
  `rounded bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-neutral-300 ${focusRing}`;
const btnGhost =
  `rounded border border-neutral-400 px-3 py-2 text-sm font-medium hover:bg-neutral-100 dark:border-neutral-600 dark:hover:bg-neutral-800 ${focusRing}`;

// ── Setup (no vault yet) ─────────────────────────────────────────────────────

function SetupPanel({ onCreate }: { onCreate: (password: string) => void }) {
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function submit(ev: React.FormEvent) {
    ev.preventDefault();
    setError("");
    if (pw.length < 1) {
      setError("choose a vault password");
      return;
    }
    if (pw !== confirm) {
      setError("passwords do not match");
      return;
    }
    setBusy(true);
    // Argon2 sealing is CPU-bound; yield a frame so the "Creating…" state paints.
    setTimeout(() => {
      try {
        onCreate(pw);
      } catch (e) {
        setError(msg(e));
        setBusy(false);
      }
    }, 0);
  }

  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold">Create your vault</h2>
      <p className="mb-4 text-sm text-neutral-600 dark:text-neutral-400">
        Your accounts are sealed with this password (Argon2id → XChaCha20-Poly1305)
        into a SIGILcli container. Only the sealed container is stored in your
        browser — the password never is. There is <strong>no recovery</strong> if
        you forget it.
      </p>
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Vault password</span>
          <input
            data-testid="setup-password"
            className={inputCls}
            type="password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Confirm password</span>
          <input
            data-testid="setup-confirm"
            className={inputCls}
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        {error && (
          <p data-testid="setup-error" className="text-sm text-red-600 dark:text-red-400">
            {error}
          </p>
        )}
        <button data-testid="setup-submit" className={btnCls} type="submit" disabled={busy}>
          {busy ? "Creating…" : "Create vault"}
        </button>
      </form>
    </Card>
  );
}

// ── Unlock (sealed vault exists) ─────────────────────────────────────────────

function UnlockPanel({
  wasm,
  hasPasskeySlot,
  onUnlock,
  onBreakGlass,
  onForget,
}: {
  wasm: Wasm;
  hasPasskeySlot: boolean;
  onUnlock: (password: string) => Promise<void>;
  onBreakGlass: (
    code: string,
    newPassword: string,
    currentPassword: string,
  ) => Promise<{ deviceOrphaned: boolean }>;
  onForget: () => void;
}) {
  const [pw, setPw] = useState("");
  const [error, setError] = useState("");
  // ⛔ A PASSKEY failure is NEVER rendered as "wrong password". It gets its own
  // region, its own wording, and points at the recovery sheet below.
  const [passkeyError, setPasskeyError] = useState("");
  const [busy, setBusy] = useState(false);

  // ⭐⭐ Break-glass fields — ALWAYS VISIBLE on the locked screen, and that is a
  // LOCKOUT FIX, not a layout preference. They used to be gated on a stored
  // hwslot, so DELETING `sigil.webapp.hwslot.v1` — a value that is not itself a
  // secret and can vanish for a dozen mundane reasons — removed the only offline
  // way out of the DOM while both containers stayed CMK-sealed. The sheet
  // derives the CMK by HKDF with no reference to the slot whatsoever, which is
  // the entire reason it is derived from the kit; making its form depend on a
  // marker threw that away. It is now reachable whenever a sealed container
  // exists, which on this screen is always.
  const [code, setCode] = useState("");
  const [curPw, setCurPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [sheetError, setSheetError] = useState("");
  const [sheetBusy, setSheetBusy] = useState(false);

  function submit(ev: React.FormEvent) {
    ev.preventDefault();
    setError("");
    setPasskeyError("");
    setBusy(true);
    setTimeout(() => {
      void (async () => {
        try {
          await onUnlock(pw);
        } catch (e) {
          if (e instanceof wasm.PasskeyError) {
            // ⭐ `atUnlock`: at this screen the containers are ALREADY sealed
            // under a key the authenticator can no longer derive, so the enable
            // flow's "Nothing was changed" would tell a locked-out person that
            // everything is fine and never mention the sheet below.
            setPasskeyError(wasm.explainPasskeyStatus(e, { atUnlock: true }));
          } else {
            setError(msg(e));
          }
          setBusy(false);
        }
      })();
    }, 0);
  }

  function submitSheet(ev: React.FormEvent) {
    ev.preventDefault();
    setSheetError("");
    if (newPw.length < 1) {
      setSheetError("choose a new password for this browser");
      return;
    }
    if (newPw !== newPw2) {
      setSheetError("those passwords do not match");
      return;
    }
    setSheetBusy(true);
    setTimeout(() => {
      void (async () => {
        try {
          await onBreakGlass(code, newPw, curPw);
          // ⭐ USED — so it leaves the DOM immediately.
          setCode("");
          setCurPw("");
          setNewPw("");
          setNewPw2("");
        } catch (e) {
          setSheetError(msg(e));
        } finally {
          setSheetBusy(false);
        }
      })();
    }, 0);
  }

  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold">Unlock your vault</h2>
      <p className="mb-4 text-sm text-neutral-600 dark:text-neutral-400">
        A sealed vault is stored in this browser. Enter its password to decrypt it
        in memory.
        {hasPasskeySlot && (
          <>
            {" "}
            <strong data-testid="unlock-passkey-required">
              This browser also asks for its passkey.
            </strong>{" "}
            The passkey prompt appears after you submit, so a typo never costs you
            a prompt.
          </>
        )}
      </p>
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Vault password</span>
          <input
            data-testid="unlock-password"
            className={inputCls}
            type="password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            autoComplete="current-password"
            autoFocus
          />
        </label>
        {/* ⛔ NO "wrong password or tampered vault" PREFIX. The AEAD tag cannot
            distinguish a wrong password from a container sealed under a
            CONTAINER MASTER KEY whose slot has been deleted, so a prefix that
            asserts the first is simply false for the second — and it was shown
            to a user whose password was perfectly correct. The message the
            unlock path throws names both possibilities and points at the sheet
            below. */}
        {error && (
          <p data-testid="unlock-error" className="text-sm text-red-600 dark:text-red-400">
            {error}
          </p>
        )}
        {passkeyError && (
          <div
            data-testid="unlock-passkey-error"
            role="alert"
            className="rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
          >
            <p className="font-semibold">The passkey step did not succeed.</p>
            <p className="mt-1">{passkeyError}</p>
          </div>
        )}
        <div className="flex items-center gap-3">
          <button data-testid="unlock-submit" className={btnCls} type="submit" disabled={busy}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
          <button
            data-testid="forget-vault"
            className={btnGhost}
            type="button"
            onClick={() => {
              if (window.confirm("Delete the sealed vault from this browser? This cannot be undone.")) {
                onForget();
              }
            }}
          >
            Forget vault
          </button>
        </div>
      </form>

      {/* ⭐⭐ UNCONDITIONAL. See the comment on `code` above: gating this on the
          stored slot made a deletable, non-secret marker the single point of
          failure for the only offline escape. */}
      {
        <form
          onSubmit={submitSheet}
          className="mt-6 space-y-3 border-t border-neutral-200 pt-4 dark:border-neutral-800"
        >
          <h3 className="text-base font-semibold">Unlock with your recovery sheet</h3>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Passkey gone, or password forgotten? The 56 characters on your printed
            recovery sheet open this vault <strong>on this device alone</strong> —
            no passkey, no server, no network. Doing this turns passkey protection
            off and re-seals everything under the new password you choose here.
            It works even if this browser&rsquo;s passkey slot has been deleted or
            damaged: the sheet derives the key on its own.
          </p>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Recovery code (from the sheet)</span>
            <input
              data-testid="unlock-recovery-code"
              className={`${inputCls} font-mono`}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              spellCheck={false}
              autoComplete="off"
              placeholder="XXXXXXXX-XXXXXXXX-…"
            />
          </label>
          {/* ⚠️ OPTIONAL, and it exists for ONE state: turning protection on is
              not atomic (containers first, slot last), so an interruption
              between the two container writes can leave this browser's device
              identity sealed under the password it had BEFORE, while the vault
              is already sealed under the sheet's key. Without this field that
              identity — the Ed25519 seed, the hybrid secret and every accepted
              vault key — is unreadable forever. */}
          <label className="block text-sm">
            <span className="mb-1 block font-medium">
              Current vault password (optional)
            </span>
            <input
              data-testid="unlock-recovery-current"
              className={inputCls}
              type="password"
              value={curPw}
              onChange={(e) => setCurPw(e.target.value)}
              autoComplete="off"
            />
            <span className="mt-1 block text-xs text-neutral-500 dark:text-neutral-400">
              Only needed if turning passkey protection on was interrupted. If the
              sheet alone is refused, type this browser&rsquo;s PREVIOUS password
              here — in one interruption window this browser&rsquo;s keys are
              still sealed under it, and the sheet cannot open them without it.
            </span>
          </label>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="mb-1 block font-medium">New vault password</span>
              <input
                data-testid="unlock-recovery-password"
                className={inputCls}
                type="password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                autoComplete="new-password"
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Confirm new password</span>
              <input
                data-testid="unlock-recovery-confirm"
                className={inputCls}
                type="password"
                value={newPw2}
                onChange={(e) => setNewPw2(e.target.value)}
                autoComplete="new-password"
              />
            </label>
          </div>
          {sheetError && (
            <p data-testid="unlock-recovery-error" className="text-sm text-red-600 dark:text-red-400">
              {sheetError}
            </p>
          )}
          <button
            data-testid="unlock-recovery-submit"
            className={btnGhost}
            type="submit"
            disabled={sheetBusy}
          >
            {sheetBusy ? "Opening…" : "Unlock with the sheet"}
          </button>
        </form>
      }
    </Card>
  );
}

// ── Restore from a printed recovery kit (setup + locked screens) ─────────────
//
// ⭐ THE POINT OF THIS PANEL is where it lives: on the screens a FRESH INSTALL
// shows. A customer who lost every device has no vault, no identity and no
// keyring — only a sheet of paper. Putting recovery behind an unlocked vault
// would make it reachable only by people who do not need it.
//
// ⚠️ The 56-character code is a CREDENTIAL, not a password: whoever holds it has
// full control of the account. It is typed here, decoded OFFLINE (so a typo never
// reaches a server), used once, and cleared from this form the moment it works.
// It is never persisted, never logged and never put in a URL.

/** Classify a recovery failure into the four things a user can actually act on. */
function explainRecoveryFailure(wasm: Wasm, e: unknown): { headline: string; detail: string } {
  const text = msg(e);
  const status = (e as { status?: number } | null)?.status;
  if (typeof status === "number" && status >= 400) {
    return {
      headline: `The server refused this kit (HTTP ${status}).`,
      detail: wasm.explainRecoveryStatus(status),
    };
  }
  if (/unsupported recovery kit version/i.test(text)) {
    return {
      headline: "This kit was printed by a newer version of Sigil.",
      detail:
        "The code is intact — its checksum is correct — but this build does not understand its " +
        "format version. Update this client; do not retype the code.",
    };
  }
  if (/not a valid recovery code/i.test(text)) {
    return {
      headline: "That is not a valid recovery code — check for a mistyped character.",
      detail:
        "Nothing was sent anywhere: the code is checked on this device before any request. " +
        "Hyphens, spaces and letter case do not matter. The letters I, L and O are never used " +
        "(read them as 1, 1 and 0) and the letter U is never used at all.",
    };
  }
  if (/nothing to recover/i.test(text)) {
    return {
      headline: "Valid kit, but it covers nothing on this server.",
      detail:
        "The code and device id are correct and the server knows this kit — it just holds no " +
        "vault key for it. The kit was enrolled but never covered a vault, or a later rotation " +
        "dropped it. There is nothing this client can do to recover data it was never given a " +
        "key for.",
    };
  }
  if (/recovers KEYS, not\s+DATA/i.test(text)) {
    return { headline: "Keys recovered, but there is no vault content to open.", detail: text };
  }
  return { headline: "Restore failed.", detail: text };
}

function RestorePanel({
  wasm,
  onRestore,
}: {
  wasm: Wasm;
  onRestore: (args: {
    baseUrl: string;
    code: string;
    deviceId: string;
    password: string;
    vaultIds?: string[];
  }) => Promise<{ vaultId: string; accounts: number; accountId: string; notes: string[] }>;
}) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("http://127.0.0.1:8080");
  const [deviceId, setDeviceId] = useState("");
  const [vaults, setVaults] = useState("");
  const [code, setCode] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [failure, setFailure] = useState<{ headline: string; detail: string } | null>(null);
  const [busy, setBusy] = useState(false);

  function submit(ev: React.FormEvent) {
    ev.preventDefault();
    setFailure(null);
    if (pw.length < 1) {
      setFailure({ headline: "Choose a password for this browser.", detail: "" });
      return;
    }
    if (pw !== pw2) {
      setFailure({ headline: "Those passwords do not match.", detail: "" });
      return;
    }
    setBusy(true);
    setTimeout(() => {
      void (async () => {
        try {
          await onRestore({
            baseUrl: url,
            code,
            deviceId,
            password: pw,
            // Commas, spaces or newlines — someone copying from paper should
            // not have to know which.
            vaultIds: vaults.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean),
          });
          // ⭐ USED — so it leaves the DOM immediately. (This component also
          // unmounts on success, but clearing does not depend on that.)
          setCode("");
          setPw("");
          setPw2("");
        } catch (e) {
          setFailure(explainRecoveryFailure(wasm, e));
        } finally {
          setBusy(false);
        }
      })();
    }, 0);
  }

  if (!open) {
    return (
      <Card>
        <h2 className="mb-1 text-lg font-semibold">Lost every device?</h2>
        <p className="mb-3 text-sm text-neutral-600 dark:text-neutral-400">
          If you printed a <strong>recovery kit</strong> before losing access, you can
          rebuild your vault here — on this fresh install, with nothing stored yet. A
          kit cannot be created after the fact.
        </p>
        <button
          data-testid="restore-open"
          className={btnGhost}
          type="button"
          onClick={() => setOpen(true)}
        >
          Restore from a recovery kit
        </button>
      </Card>
    );
  }

  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold">Restore from a recovery kit</h2>
      <div
        role="note"
        className="mb-3 rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
      >
        <strong>The code on your sheet is a credential.</strong> It is checked on this
        device before anything is sent, is used once, and is then cleared from this
        screen. It is never stored in this browser and never appears in a web address.
        Once this succeeds, <strong>this browser becomes a second copy of that paper</strong> —
        keep the sheet itself somewhere else.
      </div>
      <form onSubmit={submit} className="space-y-3">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Server URL (printed on the sheet)</span>
          <input
            data-testid="restore-url"
            className={`${inputCls} font-mono`}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Kit device id (printed on the sheet)</span>
          <input
            data-testid="restore-device-id"
            className={`${inputCls} font-mono`}
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            placeholder="dev_…"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">
            Vaults from the sheet&rsquo;s &ldquo;covers&rdquo; line
          </span>
          <input
            data-testid="restore-vaults"
            className={`${inputCls} font-mono`}
            value={vaults}
            onChange={(e) => setVaults(e.target.value)}
            placeholder="vault-a, vault-b"
            spellCheck={false}
            autoComplete="off"
          />
          <span className="mt-1 block text-xs text-neutral-600 dark:text-neutral-400">
            Copying these off the sheet asks each vault directly instead of relying on
            the server&rsquo;s list of what is waiting for this kit &mdash; a list anyone
            else can crowd out. Leave it blank and, if that list is being crowded, this
            refuses rather than restoring part of your vaults and calling it done.
          </span>
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Recovery code (56 characters)</span>
          <textarea
            data-testid="restore-code"
            className={`${inputCls} h-20 font-mono tracking-widest`}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX"
            spellCheck={false}
            autoComplete="off"
          />
          <span className="mt-1 block text-xs text-neutral-600 dark:text-neutral-400">
            Hyphens, spaces and upper/lower case are all ignored. The letters I, L and O
            are never used — read them as 1, 1 and 0.
          </span>
        </label>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="mb-1 block font-medium">New password for this browser</span>
            <input
              data-testid="restore-password"
              className={inputCls}
              type="password"
              value={pw}
              onChange={(e) => setPw(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Confirm password</span>
            <input
              data-testid="restore-confirm"
              className={inputCls}
              type="password"
              value={pw2}
              onChange={(e) => setPw2(e.target.value)}
              autoComplete="new-password"
            />
          </label>
        </div>
        {failure && (
          <div
            data-testid="restore-error"
            role="alert"
            className="rounded border border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:border-red-700 dark:bg-red-950 dark:text-red-200"
          >
            <p className="font-semibold">{failure.headline}</p>
            {failure.detail && <p className="mt-1">{failure.detail}</p>}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-3">
          <button data-testid="restore-submit" className={btnCls} type="submit" disabled={busy}>
            {busy ? "Restoring…" : "Restore my vault"}
          </button>
          <button
            data-testid="restore-cancel"
            className={btnGhost}
            type="button"
            onClick={() => {
              setCode("");
              setPw("");
              setPw2("");
              setVaults("");
              setFailure(null);
              setOpen(false);
            }}
          >
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

// ── Unlocked vault view ──────────────────────────────────────────────────────

interface AddInput {
  label: string;
  issuer?: string;
  secretBytes: Uint8Array;
  algorithm: string;
  digits: number;
  period: number;
}

function VaultView({
  wasm,
  vault,
  now,
  device,
  activeVaultId,
  protection,
  onBeginPasskey,
  onCompletePasskey,
  onDisablePasskey,
  onKitReprinted,
  onDeviceChange,
  onUpdateDevice,
  onRekey,
  onAdoptSharedVault,
  onAdd,
  onImportOtpauth,
  onImportMigration,
  onRemove,
  onMergeOps,
  onLock,
}: {
  wasm: Wasm;
  vault: TotpVault;
  now: number;
  device: DeviceIdentity | null;
  activeVaultId: string | null;
  protection: ProtectionInfo | null;
  onBeginPasskey: (baseUrl: string) => Promise<PasskeyProbeSummary>;
  onCompletePasskey: (code: string) => Promise<ProtectionInfo>;
  onDisablePasskey: () => void;
  onKitReprinted: (code: string, kitDeviceId: string) => Promise<void>;
  onDeviceChange: (d: DeviceIdentity | null) => void;
  onUpdateDevice: (patch: Partial<DeviceIdentity>) => DeviceIdentity;
  onRekey: (vaultId: string, vaultKey: Uint8Array) => void;
  onAdoptSharedVault: (vaultId: string, vaultKey: Uint8Array, container: Uint8Array) => TotpVault;
  onAdd: (input: AddInput) => void;
  onImportOtpauth: (uri: string) => void;
  onImportMigration: (uri: string) => {
    imported: number;
    skipped: number;
    /** ⭐ WHICH accounts were skipped. A bare count is what let a defect hide. */
    skippedNames: string[];
    /** Non-null when this was ONE QR of a multi-QR export; must be shown. */
    batchNote: string | null;
    /** True when it was the LAST QR — say so, but do NOT call it incomplete. */
    finalBatch: boolean;
  };
  /** ⭐ Phase 61: by IDENTITY, not label — labels are no longer unique. */
  onRemove: (uuid: string) => void;
  /** ⭐ Phase 61: fold every pulled op into the vault instead of adopting the tip. */
  onMergeOps: (ops: { seq: number; container: Uint8Array }[]) => MergeOpsResult;
  onLock: () => void;
}) {
  // Server URL + vault id are shared by the Sync and Sharing panels: a vault key
  // is per-VAULT-ID, so the two panels must always agree on which vault they mean.
  const [serverUrl, setServerUrl] = useState("http://127.0.0.1:8080");
  const [vaultId, setVaultId] = useState("webapp-demo");

  return (
    <div data-testid="vault-view" className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">
          Accounts{" "}
          <span
            data-testid="account-count"
            className="ml-1 rounded bg-neutral-200 px-2 py-0.5 text-sm font-normal dark:bg-neutral-800"
          >
            {vault.entries.length}
          </span>
        </h2>
        <button data-testid="lock-btn" className={btnGhost} type="button" onClick={onLock}>
          Lock
        </button>
      </div>

      {vault.entries.length === 0 ? (
        <Card>
          <p data-testid="empty-state" className="text-sm text-neutral-600 dark:text-neutral-400">
            No accounts yet. Add one below, paste an <code>otpauth://</code> URI, or
            import a Google Authenticator export.
          </p>
        </Card>
      ) : (
        <ul data-testid="account-list" className="space-y-2">
          {vault.entries.map((entry) => (
            // ⭐ Phase 61: keyed on IDENTITY, not label. Labels are no longer
            // unique (`work` at two issuers is two accounts), and duplicate React
            // keys make rows share state and the wrong row get removed.
            <AccountRow
              key={wasm.entryIdentity(wasm, entry)}
              wasm={wasm}
              entry={entry}
              now={now}
              onRemove={() => onRemove(wasm.entryIdentity(wasm, entry))}
            />
          ))}
        </ul>
      )}

      <AddAccountPanel
        wasm={wasm}
        onAdd={onAdd}
        onImportOtpauth={onImportOtpauth}
        onImportMigration={onImportMigration}
      />
      <ExportPanel wasm={wasm} vault={vault} />
      <PasskeyPanel
        wasm={wasm}
        device={device}
        url={serverUrl}
        protection={protection}
        onBegin={onBeginPasskey}
        onComplete={onCompletePasskey}
        onDisable={onDisablePasskey}
      />
      <SyncPanel
        wasm={wasm}
        device={device}
        onDeviceChange={onDeviceChange}
        url={serverUrl}
        setUrl={setServerUrl}
        vaultId={vaultId}
        setVaultId={setVaultId}
        protection={protection}
        activeVaultId={activeVaultId}
        onMergeOps={onMergeOps}
      />
      <SharingPanel
        wasm={wasm}
        device={device}
        activeVaultId={activeVaultId}
        url={serverUrl}
        vaultId={vaultId}
        onUpdateDevice={onUpdateDevice}
        onRekey={onRekey}
        onAdoptSharedVault={onAdoptSharedVault}
      />
      <RecoveryPanel
        wasm={wasm}
        device={device}
        url={serverUrl}
        vaultId={vaultId}
        protection={protection}
        onKitReprinted={onKitReprinted}
        onUpdateDevice={onUpdateDevice}
      />
    </div>
  );
}

function AccountRow({
  wasm,
  entry,
  now,
  onRemove,
}: {
  wasm: Wasm;
  entry: TotpEntry;
  now: number;
  onRemove: () => void;
}) {
  // ⛔⛔ THE DELETE CONFIRMATION. It is not politeness; it is the only thing
  // between a misclick and permanent, unrecoverable loss of a second factor —
  // and losing a second factor can mean losing the account it protects.
  //
  // Two facts made a bare one-click Remove indefensible here:
  //
  //  1. The button sits inches from the CODE the user came to read, on a row
  //     that RE-RENDERS EVERY SECOND. Misclicks are the expected case, not the
  //     exotic one.
  //  2. ⭐ Phase 61 RAISED the stakes. A removal now writes a TOMBSTONE that
  //     propagates to every device and is specifically protected against
  //     resurrection (ADR 0049 §3: delete wins, and a stale snapshot re-adding
  //     the id LOSES). Before, a stale snapshot might have brought the entry
  //     back by accident; now it provably will not.
  //
  // ⭐ WHY A CONFIRM AND NOT AN UNDO. An undo would have to either (a) write the
  // tombstone and retract it — exactly the resurrection ADR 0049 is built to
  // prevent, and unretractable once any other device has merged it — or (b) hold
  // the delete pending in memory, where closing the tab silently discards the
  // user's intent. A gate BEFORE the irreversible act is the only version that
  // does not fight the merge. The tombstone is written at commit and never
  // before.
  const [confirming, setConfirming] = useState(false);

  let code = "------";
  let error = "";
  try {
    code = wasm.codeForEntry(wasm, entry, now);
  } catch (e) {
    error = msg(e);
  }
  const remaining = entry.period - (now % entry.period);
  const who = entry.issuer ? `${entry.issuer}, ${entry.label}` : entry.label;
  const codeLabel = error
    ? `${who}: code unavailable`
    : `${who}: code ${code.split("").join(" ")}, ${remaining} seconds remaining`;

  if (confirming) {
    return (
      <li
        data-testid="account-row"
        className="rounded-lg border border-red-400 p-3 sm:p-4 dark:border-red-700"
      >
        <div
          data-testid="remove-confirm"
          role="alert"
          className="space-y-2 text-sm text-red-900 dark:text-red-200"
        >
          <p className="font-semibold">
            Delete{" "}
            <span data-testid="remove-confirm-who" className="font-mono">
              {who}
            </span>
            ?
          </p>
          {/* NAMES the account, and states the two things that make this
              different from an ordinary delete: it is permanent, and it
              propagates.
              ⚠️ IT MUST NOT PROMISE A SYNC IT DOES NOT PERFORM. An earlier
              revision said "the deletion is synced to every other device holding
              it", which is FALSE here: sync in this product is MANUAL (explicit
              Push / Pull) and a vault with no server configured never propagates
              at all. This is the sentence a user reads while deciding whether to
              destroy a second factor, so it says exactly what happens and
              exactly what it is conditional on. */}
          <p data-testid="remove-confirm-warning" className="text-xs">
            This permanently deletes the second-factor secret for{" "}
            <strong>{who}</strong> from this vault. Sigil syncs only when you ask
            it to, so the deletion reaches every other device holding this vault
            the next time you Push and they Pull; until you do &mdash; and forever,
            if you never sync &mdash; it applies to this device alone. It cannot be
            undone from here — if you no longer have this secret anywhere else, you
            may lose access to the account it protects.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <button
              data-testid="remove-confirm-yes"
              className={btnCls}
              type="button"
              autoFocus
              onClick={() => {
                setConfirming(false);
                onRemove();
              }}
            >
              Delete permanently
            </button>
            <button
              data-testid="remove-confirm-cancel"
              className={btnGhost}
              type="button"
              onClick={() => setConfirming(false)}
            >
              Keep it
            </button>
          </div>
        </div>
      </li>
    );
  }

  // ⛔⛔ THE READ-PATH FROZEN-ENTRY WARNING (Phase 63). The ingest ceiling is
  // deliberately NOT retroactive, and it deliberately does not cover a Phase 61
  // vault MERGE (see the block comment on `mergeVaults` in totp-vault.mjs for why
  // gating a merge would be the worse bug), so an entry whose code never rotates
  // can still land in this list. Until this existed the row rendered it with an
  // ordinary countdown ring — the product telling the user their second factor is
  // fine when it is a static secret wearing a rotating costume.
  //
  // ⛔ IT REPORTS AND NEVER CORRECTS: the entry is still shown, still generates,
  // and is not altered in any way (ADR 0049 — entries are immutable).
  const frozen = wasm.frozenPeriodWarning(entry.period);

  return (
    <li
      data-testid="account-row"
      className="flex flex-wrap items-center gap-3 rounded-lg border border-neutral-300 p-3 sm:gap-4 sm:p-4 dark:border-neutral-700"
    >
      <CountdownRing remaining={remaining} period={entry.period} />
      <div className="min-w-0 flex-1">
        <div data-testid="account-label" className="truncate text-sm font-medium">
          {entry.issuer ? (
            <>
              <span className="text-neutral-600 dark:text-neutral-400">{entry.issuer}</span>
              <span className="mx-1 text-neutral-500" aria-hidden="true">
                ·
              </span>
            </>
          ) : null}
          {entry.label}
        </div>
        <div className="text-xs text-neutral-600 dark:text-neutral-400">
          {entry.algorithm.toUpperCase()} · {entry.digits} digits · {entry.period}s
        </div>
      </div>
      <div
        data-testid="account-code"
        aria-label={codeLabel}
        className="font-mono text-xl tabular-nums tracking-widest sm:text-2xl"
      >
        {error ? "err" : code}
      </div>
      {/* ⛔ This opens the confirmation. It MUST NOT call onRemove directly:
          onRemove writes a propagating tombstone (see the block comment above). */}
      <button
        data-testid="account-remove"
        aria-label={`Remove ${who}`}
        className={btnGhost}
        type="button"
        onClick={() => setConfirming(true)}
      >
        Remove
      </button>
      {frozen && (
        <p
          data-testid="frozen-warning"
          role="alert"
          className="w-full rounded border border-amber-500 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        >
          {frozen}
        </p>
      )}
    </li>
  );
}

function CountdownRing({ remaining, period }: { remaining: number; period: number }) {
  const size = 34;
  const stroke = 3;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(1, remaining / period));
  const offset = c * (1 - frac);
  return (
    <div
      className="relative shrink-0"
      style={{ width: size, height: size }}
      role="img"
      aria-label={`${remaining} seconds until this code refreshes`}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden="true">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
          className="stroke-neutral-200 dark:stroke-neutral-800"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          className={remaining <= 5 ? "stroke-red-500" : "stroke-emerald-500"}
        />
      </svg>
      <span
        data-testid="account-remaining"
        aria-hidden="true"
        className="absolute inset-0 flex items-center justify-center text-[10px] tabular-nums text-neutral-600 dark:text-neutral-400"
      >
        {remaining}
      </span>
    </div>
  );
}

// ── Add account (form + otpauth paste + migration import) ────────────────────

function AddAccountPanel({
  wasm,
  onAdd,
  onImportOtpauth,
  onImportMigration,
}: {
  wasm: Wasm;
  onAdd: (input: AddInput) => void;
  onImportOtpauth: (uri: string) => void;
  onImportMigration: (uri: string) => {
    imported: number;
    skipped: number;
    /** ⭐ WHICH accounts were skipped. A bare count is what let a defect hide. */
    skippedNames: string[];
    /** Non-null when this was ONE QR of a multi-QR export; must be shown. */
    batchNote: string | null;
    /** True when it was the LAST QR — say so, but do NOT call it incomplete. */
    finalBatch: boolean;
  };
}) {
  const [label, setLabel] = useState("");
  const [issuer, setIssuer] = useState("");
  const [secret, setSecret] = useState("");
  const [algorithm, setAlgorithm] = useState("sha1");
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);
  const [addError, setAddError] = useState("");

  const [otpauth, setOtpauth] = useState("");
  const [otpauthError, setOtpauthError] = useState("");

  const [migration, setMigration] = useState("");
  const [importResult, setImportResult] = useState("");
  const [migrationError, setMigrationError] = useState("");

  // ── QR scanning (Phase 63) ────────────────────────────────────────────────
  // `null` = still probing. The probe is a RUNTIME question: `BarcodeDetector`
  // is absent in Firefox, in Safari and on Linux Chromium, and it is also
  // secure-context gated, so this cannot be decided at build time.
  const [qrSupported, setQrSupported] = useState<boolean | null>(null);
  const [qrError, setQrError] = useState("");
  // ⭐ What was scanned, held for the user to CONFIRM. A scanner that wrote on
  // decode would mean pasting a screenshot from a hostile page silently creates
  // an account (ADR 0050's reasoning, pointed the other way).
  const [qrPending, setQrPending] = useState<null | {
    kind: "otpauth" | "migration";
    text: string;
    summary: string;
  }>(null);

  useEffect(() => {
    let live = true;
    wasm
      .qrSupport()
      .then((s) => {
        if (live) setQrSupported(s);
      })
      .catch(() => {
        if (live) setQrSupported(false);
      });
    return () => {
      live = false;
    };
  }, [wasm]);

  // ⭐ THE PASTE LISTENER IS ON `document`, AND THAT IS NOT A DETAIL.
  //
  // A `paste` event is dispatched at the FOCUSED element (or `document.body`
  // when nothing focusable has focus) and then BUBBLES UP. It never travels
  // DOWN into an unfocused subtree. So a handler on this panel's own <section>
  // — which is not focusable — receives nothing when a user simply presses
  // ⌘V, which is the entire motion this feature is built around.
  //
  // ⚠️ This was a REAL DEFECT in the first cut of this phase, and it is the
  // house failure mode exactly: a spec that dispatched the event directly on
  // the panel passed, while the shipping path was dead for every real user.
  // Measured: with focus on `body` or on an unrelated input, a panel-level
  // listener fired 0 times and a document-level listener fired every time.
  //
  // ⚠️ Listening this widely is safe ONLY because `imageFromEvent` returns null
  // for a text paste — so pasting an `otpauth://` URI into the field below is
  // completely unaffected, and we never read the clipboard, only this event.
  useEffect(() => {
    if (qrSupported !== true) return;
    const onPaste = (ev: ClipboardEvent) => {
      const blob = wasm.imageFromEvent(ev);
      if (!blob) return; // a text paste: leave it entirely alone
      ev.preventDefault();
      void scanImageRef.current?.(blob);
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, [qrSupported, wasm]);

  // Turn an image into a CONFIRMABLE summary. Nothing is written here.
  const scanImage = useCallback(
    async (blob: Blob | null) => {
      setQrError("");
      setQrPending(null);
      if (!blob) return;
      try {
        const found = await wasm.scanProvisioningImage(blob);
        // Parse it to build the summary. This runs the SAME provisioning gate the
        // paste field runs, so a hostile QR is refused here — before anything is
        // shown as addable, and long before anything is stored.
        let summary: string;
        if (found.kind === "otpauth") {
          const e = wasm.parseOtpauthUri(found.text);
          summary =
            `${e.issuer ? `${e.issuer}: ` : ""}${e.label} — ` +
            `${e.algorithm.toUpperCase()}, ${e.digits} digits, every ${e.period}s`;
        } else {
          const batch = wasm.decodeMigrationUri(found.text);
          const n = batch.entries.length;
          summary = `a Google Authenticator export carrying ${n} account${n === 1 ? "" : "s"}`;
        }
        setQrPending({ kind: found.kind, text: found.text, summary });
      } catch (e) {
        setQrError(wasm.explainQrError(e) || msg(e));
      }
    },
    [wasm],
  );

  // The document listener above is registered once and must always call the
  // CURRENT scanImage, without tearing down and re-adding on every render.
  const scanImageRef = useRef<typeof scanImage | null>(null);
  scanImageRef.current = scanImage;

  function confirmQr() {
    if (!qrPending) return;
    setQrError("");
    try {
      if (qrPending.kind === "otpauth") {
        onImportOtpauth(qrPending.text);
        setImportResult("Added the scanned account.");
      } else {
        const { imported, skipped } = onImportMigration(qrPending.text);
        setImportResult(
          `Imported ${imported} account${imported === 1 ? "" : "s"}` +
            (skipped ? `, skipped ${skipped} already in this vault or unsupported.` : "."),
        );
      }
      setQrPending(null);
    } catch (e) {
      setQrError(msg(e));
    }
  }

  function submitForm(ev: React.FormEvent) {
    ev.preventDefault();
    setAddError("");
    try {
      const secretBytes = ((): Uint8Array => {
        // Reuse the proven base32 decoder via a fresh import isn't needed here —
        // the caller-supplied onAdd validates the rest; decode locally for a
        // clear "invalid base32" message before touching the vault.
        return base32Local(secret);
      })();
      // ⭐⭐ THE PROVISIONING GATE, ON THE ADD-BY-FORM DOOR TOO (Phase 63 fix).
      //
      // ⛔ This form reproduced the exact defect the phase exists to close: the
      // period box was `type=number min=1` with NO max, so typing 4294967295 here
      // created a "one-time" password whose code never changes, rendered with an
      // ordinary-looking countdown. `digits` was already bounded (it is a
      // <select>); `period` was not.
      //
      // ⭐ WHY THIS DOES NOT CONTRADICT THE CLI'S DELIBERATE `--period` EXEMPTION.
      // That exemption is for a flag an operator typed into a shell, where the
      // value is in their history and the repo's cross-process clock-pinning
      // artifice depends on it. A GUI form is a different trust surface: it is
      // where a phishing page's "helpful setup instructions" land, nobody reviews
      // it afterwards, and nothing in this repository needs an unbounded period
      // in a browser. The boundary the CLI draws is about a shell, not about
      // "an entry is being created".
      //
      // ⭐ Routed through the SAME `validateProvisioning` (hence the same
      // MAX_PERIOD / MAX_SECRET_BYTES / MAX_LABEL_CHARS) that the URI, migration
      // and QR doors use. A fourth hand-written `600` would be a mirror nobody
      // guards. The `max` attribute on the input below is UX; THIS is the control.
      wasm.validateProvisioning(
        label.trim(),
        issuer.trim() || null,
        secretBytes.length,
        digits,
        period,
      );
      onAdd({
        label: label.trim(),
        issuer: issuer.trim() || undefined,
        secretBytes,
        algorithm,
        digits,
        period,
      });
      setLabel("");
      setIssuer("");
      setSecret("");
    } catch (e) {
      setAddError(msg(e));
    }
  }

  function submitOtpauth(ev: React.FormEvent) {
    ev.preventDefault();
    setOtpauthError("");
    try {
      onImportOtpauth(otpauth.trim());
      setOtpauth("");
    } catch (e) {
      setOtpauthError(msg(e));
    }
  }

  function submitMigration(ev: React.FormEvent) {
    ev.preventDefault();
    setMigrationError("");
    setImportResult("");
    try {
      const { imported, skipped, skippedNames, batchNote, finalBatch } = onImportMigration(
        migration.trim(),
      );
      // ⭐ NAME the skips. "skipped 1 (duplicate or unsupported)" is exactly the
      // message a user saw when the label-keyed de-dup silently dropped their
      // second `work` account, and there was no way to learn which one it was.
      const base = `Imported ${imported} account${imported === 1 ? "" : "s"}${
        skipped
          ? `, skipped ${skipped} already in this vault or unsupported${
              skippedNames.length ? `: ${skippedNames.join("; ")}` : ""
            }`
          : ""
      }.`;
      // ⛔ Never let the count be the last word on a multi-QR export: a user who
      // reads "Imported 12." and deletes the old app loses the other batches.
      // ⭐ But the LAST QR is not an incomplete import. Saying "0 more QR
      // code(s) must be imported — this import is PARTIAL" to someone who has
      // just finished is a false alarm, and false alarms are what teach users to
      // click past the true one. The note still names the batch, because this
      // browser keeps no record of earlier imports and genuinely cannot know.
      setImportResult(
        batchNote && !finalBatch
          ? `${base} ⚠️ THIS IMPORT IS INCOMPLETE — ${batchNote}. Import the remaining QR ` +
              `code(s) before deleting anything from the old app.`
          : batchNote
            ? `${base} ${batchNote}.`
            : base,
      );
      setMigration("");
    } catch (e) {
      setMigrationError(msg(e));
    }
  }

  return (
    <Card>
      <h3 className="mb-4 text-base font-semibold">Add an account</h3>

      {/* ⭐ `noValidate` ON PURPOSE. With native constraint validation on, the
          browser silently swallows an out-of-range period behind a generic
          tooltip and `submitForm` never runs — so the user is refused without
          being told WHY, and the refusal is the browser's rather than ours.
          Turning it off makes ONE control authoritative (`validateProvisioning`,
          the same one the URI/migration/QR doors use) and lets it explain that a
          code that long does not rotate. The `min`/`max` attributes stay as
          affordances. */}
      <form onSubmit={submitForm} className="space-y-3" noValidate>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Label</span>
            <input
              data-testid="add-label"
              className={inputCls}
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="alice@example.com"
              autoComplete="off"
            />
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Issuer (optional)</span>
            <input
              data-testid="add-issuer"
              className={inputCls}
              value={issuer}
              onChange={(e) => setIssuer(e.target.value)}
              placeholder="Example"
              autoComplete="off"
            />
          </label>
        </div>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Base32 secret</span>
          <input
            data-testid="add-secret"
            className={`${inputCls} font-mono`}
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="JBSWY3DPEHPK3PXP"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <div className="grid grid-cols-3 gap-3">
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Algorithm</span>
            <select
              data-testid="add-algorithm"
              className={inputCls}
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
            >
              <option value="sha1">SHA1</option>
              <option value="sha256">SHA256</option>
              <option value="sha512">SHA512</option>
            </select>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Digits</span>
            <select
              data-testid="add-digits"
              className={inputCls}
              value={digits}
              onChange={(e) => setDigits(Number(e.target.value))}
            >
              <option value={6}>6</option>
              <option value={8}>8</option>
            </select>
          </label>
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Period (s)</span>
            {/* `max` comes from the SAME constant the gate uses — never a
                literal. It is only UX (a native tooltip); `submitForm`'s
                `validateProvisioning` call is the actual control, because an
                attribute is trivially bypassed and a form is not a boundary. */}
            <input
              data-testid="add-period"
              className={inputCls}
              type="number"
              min={1}
              max={wasm.MAX_PERIOD}
              value={period}
              onChange={(e) => setPeriod(Number(e.target.value))}
            />
          </label>
        </div>
        {addError && (
          <p data-testid="add-error" className="text-sm text-red-600 dark:text-red-400">
            {addError}
          </p>
        )}
        <button data-testid="add-submit" className={btnCls} type="submit">
          Add account
        </button>
      </form>

      <hr className="my-5 border-neutral-200 dark:border-neutral-800" />

      {/* ── Scan a QR code (Phase 63) ─────────────────────────────────────── */}
      <section
        className="space-y-2"
        data-testid="qr-panel"
        /* Paste is handled at the DOCUMENT level (see the effect above) — a
           paste event never travels down into an unfocused subtree, so a
           handler here would be dead for a real user. Drop still belongs here:
           a drop IS targeted at the element it lands on. */
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          const blob = wasm.imageFromEvent(e.nativeEvent as unknown as DragEvent);
          if (blob) {
            e.preventDefault();
            void scanImage(blob);
          }
        }}
      >
        <h3 className="text-sm font-medium">Scan a QR code</h3>
        {qrSupported === null && (
          <p data-testid="qr-probing" className="text-sm text-neutral-600 dark:text-neutral-400">
            Checking whether this browser can read QR codes…
          </p>
        )}
        {/*
          ⛔ THE UNSUPPORTED BRANCH IS A REAL PRODUCT STATE, NOT AN ERROR PATH.
          There is deliberately NO disabled button here: a control that exists and
          fails is a claim that is not true, and Phase 62 existed to remove two of
          those. Firefox, Safari and Linux Chromium land here.
        */}
        {qrSupported === false && (
          <p
            data-testid="qr-unsupported"
            className="rounded border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200"
          >
            This page cannot read QR codes. Either the browser does not support it (Chrome and
            Edge do; Firefox and Safari do not), or this page was not loaded over a secure
            origin — the API is unavailable on a plain <code>http://</code> address other than{" "}
            <code>localhost</code>. Paste the <code>otpauth://</code> setup link below instead;
            it does exactly the same job.
          </p>
        )}
        {qrSupported === true && (
          <>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Take a screenshot of the QR code and paste it here (or drop an image, or choose a
              file). Nothing is added until you confirm it.
            </p>
            {/* The label is REQUIRED, not decoration: a bare file input is a
                critical axe `label` violation, and a screen-reader user gets an
                unnamed control. Caught by tests/a11y.spec.ts. */}
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Choose a QR code image</span>
              <input
                data-testid="qr-file-input"
                type="file"
                accept="image/*"
                className="block w-full text-sm"
                onChange={(e) => {
                  const f = e.target.files?.[0] ?? null;
                  e.target.value = "";
                  void scanImage(f);
                }}
              />
            </label>
          </>
        )}
        {qrPending && (
          <div
            data-testid="qr-preview"
            className="rounded border border-neutral-300 p-2 text-sm dark:border-neutral-700"
          >
            <p className="mb-2">
              Found: <span data-testid="qr-summary">{qrPending.summary}</span>
            </p>
            <div className="flex gap-2">
              <button
                data-testid="qr-confirm"
                className={btnCls}
                type="button"
                onClick={confirmQr}
              >
                Add this account
              </button>
              <button
                data-testid="qr-cancel"
                className={btnGhost}
                type="button"
                onClick={() => setQrPending(null)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
        {qrError && (
          <p data-testid="qr-error" className="text-sm text-red-600 dark:text-red-400">
            {qrError}
          </p>
        )}
      </section>

      <hr className="my-5 border-neutral-200 dark:border-neutral-800" />

      <form onSubmit={submitOtpauth} className="space-y-2">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Paste an otpauth:// URI</span>
          <input
            data-testid="otpauth-input"
            className={`${inputCls} font-mono`}
            value={otpauth}
            onChange={(e) => setOtpauth(e.target.value)}
            placeholder="otpauth://totp/Example:alice?secret=…"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        {otpauthError && (
          <p data-testid="otpauth-error" className="text-sm text-red-600 dark:text-red-400">
            {otpauthError}
          </p>
        )}
        <button data-testid="otpauth-submit" className={btnGhost} type="submit">
          Add from otpauth URI
        </button>
      </form>

      <hr className="my-5 border-neutral-200 dark:border-neutral-800" />

      <form onSubmit={submitMigration} className="space-y-2">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">
            Import a Google Authenticator export (otpauth-migration:// URI)
          </span>
          <textarea
            data-testid="migration-input"
            className={`${inputCls} h-20 font-mono`}
            value={migration}
            onChange={(e) => setMigration(e.target.value)}
            placeholder="otpauth-migration://offline?data=…"
            spellCheck={false}
          />
        </label>
        {importResult && (
          <p data-testid="import-result" className="text-sm text-emerald-700 dark:text-emerald-400">
            {importResult}
          </p>
        )}
        {migrationError && (
          <p data-testid="migration-error" className="text-sm text-red-600 dark:text-red-400">
            {migrationError}
          </p>
        )}
        <button data-testid="migration-submit" className={btnGhost} type="submit">
          Import export
        </button>
      </form>
    </Card>
  );
}

// A local RFC 4648 base32 decoder used ONLY to produce an early, clear error
// message before handing bytes to the vault. Case-insensitive; ignores ASCII
// whitespace and `=` padding. (Mirrors the proven helper's base32Decode; the
// authoritative decode still happens inside the vault helpers.)
function base32Local(input: string): Uint8Array {
  let acc = 0;
  let nbits = 0;
  const out: number[] = [];
  for (const ch of input) {
    if (ch === "=" || /\s/.test(ch)) continue;
    const up = ch.toUpperCase();
    let val: number;
    if (up >= "A" && up <= "Z") val = up.charCodeAt(0) - 65;
    else if (up >= "2" && up <= "7") val = up.charCodeAt(0) - 50 + 26;
    else throw new Error(`invalid base32 character ${JSON.stringify(ch)} in secret`);
    acc = (acc << 5) | val;
    nbits += 5;
    if (nbits >= 8) {
      nbits -= 8;
      out.push((acc >> nbits) & 0xff);
      acc &= (1 << nbits) - 1;
    }
  }
  if (out.length === 0) throw new Error("base32 secret decoded to zero bytes");
  return new Uint8Array(out);
}

// ── Export (secrets in the clear — behind a loud warning) ────────────────────

function ExportPanel({ wasm, vault }: { wasm: Wasm; vault: TotpVault }) {
  const [otpauth, setOtpauth] = useState<string>("");
  const [migration, setMigration] = useState<string>("");
  const [error, setError] = useState("");

  if (vault.entries.length === 0) return null;

  function showOtpauth() {
    setError("");
    try {
      setOtpauth(vault.entries.map((e) => wasm.buildOtpauthUri(e)).join("\n"));
    } catch (e) {
      setError(msg(e));
    }
  }
  function showMigration() {
    setError("");
    try {
      setMigration(wasm.encodeMigrationUri(vault.entries));
    } catch (e) {
      setError(msg(e));
    }
  }

  return (
    <Card>
      <h3 className="mb-2 text-base font-semibold">Export</h3>
      <div
        role="alert"
        className="mb-3 rounded border border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:border-red-700 dark:bg-red-950 dark:text-red-200"
      >
        <strong>Warning:</strong> exports contain your OTP secrets{" "}
        <strong>in the clear</strong> (unencrypted). Anyone who sees them can
        generate your codes. Do not share or store them insecurely.
      </div>
      <div className="flex flex-wrap gap-3">
        <button data-testid="export-otpauth-btn" className={btnGhost} type="button" onClick={showOtpauth}>
          Reveal otpauth:// URIs
        </button>
        <button data-testid="export-migration-btn" className={btnGhost} type="button" onClick={showMigration}>
          Reveal migration URI
        </button>
      </div>
      {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {otpauth && (
        <textarea
          data-testid="export-otpauth-output"
          readOnly
          className={`${inputCls} mt-3 h-24 font-mono text-xs`}
          value={otpauth}
        />
      )}
      {migration && (
        <textarea
          data-testid="export-migration-output"
          readOnly
          className={`${inputCls} mt-3 h-20 font-mono text-xs`}
          value={migration}
        />
      )}
    </Card>
  );
}

// ── Sync (optional dev feature — sealed container to/from a sigild op-log) ────
//
// Two modes, chosen automatically:
//   * NO device identity  -> unauthenticated push/pull, exactly as before (a
//     sigild with only SIGILD_ENABLE_DEV_OPS on).
//   * device ENROLLED     -> every request is signed under sigild's multi-device
//     contract v3 (X-Sigil-Device + timestamp + fresh nonce + Ed25519 signature
//     produced IN THE WASM), so a sigild with SIGILD_DEVICE_AUTH=1 accepts it.
//
// The enrollment token is a single-use bearer secret: it is sent in a header and
// is never stored or logged. The device SEED is generated here with
// crypto.getRandomValues and is persisted ONLY inside a password-sealed
// container (see DEVICE_KEY) — never in plaintext.

// ── Account membership (Phase 52) ────────────────────────────────────────────
//
// THE STATE THIS EXISTS TO SHOW. An invite pastes straight into the enrollment
// token field — the wire format is unchanged — so this browser can JOIN an
// account today. Joining confers AUTHORIZATION, never DECRYPTION: the joined
// device authenticates, sees the account and its entitlement, and can still
// decrypt NOTHING until an existing member wraps a vault key to its hybrid
// public key (Sharing → Share to this device id).
//
// The CLI and the desktop app already say so. Without this block the browsers
// showed an account and an entitlement beside an empty vault and no explanation,
// which reads as a bug rather than as a step that is still outstanding.
function AccountBlock({
  wasm,
  device,
  url,
  vaultId,
}: {
  wasm: Wasm;
  device: DeviceIdentity;
  url: string;
  vaultId: string;
}) {
  const [account, setAccount] = useState<AccountInfo | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  // This device can DECRYPT the named vault only once it holds that vault's key.
  const holdsKey = Boolean(device.vaultKeys?.[vaultId.trim()]);
  // A single-device account is just this browser; the waiting state is only
  // meaningful once there IS another member who could send a key.
  const hasSiblings = (account?.device_count ?? 0) > 1;

  async function refresh() {
    setBusy(true);
    setStatus("Reading account…");
    try {
      const info = await wasm.getAccount(wasm, { ...device, baseUrl: url.trim() }, url.trim());
      setAccount(info);
      setStatus("");
    } catch (e) {
      setAccount(null);
      const code = (e as { status?: number } | null)?.status;
      // 403 here is the server refusing a device whose account row is missing —
      // a real, repairable data state (`sigild migrate adopt`), not a crash.
      setStatus(
        typeof code === "number" && code >= 400
          ? `Account unavailable: ${wasm.explainAuthStatus(code)}`
          : `Account unavailable: ${msg(e)}`,
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 border-t border-neutral-200 pt-3 dark:border-neutral-800">
      <div className="flex items-center gap-2">
        <h5 className="text-xs font-semibold">Account</h5>
        <button
          data-testid="account-refresh"
          className={btnGhost}
          type="button"
          onClick={refresh}
          disabled={busy}
        >
          {account ? "Refresh" : "Show account"}
        </button>
      </div>

      {status && (
        <p data-testid="account-status" className="mt-2 text-xs text-neutral-600 dark:text-neutral-400">
          {status}
        </p>
      )}

      {account && (
        <>
          <p data-testid="account-id" className="mt-2 break-all font-mono text-xs">
            {account.account_id}
          </p>
          <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-400">
            {account.device_count} of {account.device_limit} device
            {account.device_limit === 1 ? "" : "s"} in use
            {account.revoked_device_count
              ? ` (${account.revoked_device_count} revoked — revoked devices do not use a seat)`
              : ""}
            .
          </p>

          {hasSiblings && !holdsKey && (
            // ⭐ THE HONEST STATE. Not an error, not a spinner: a step that has
            // not happened yet, named plainly, with who has to do it.
            <p
              data-testid="account-awaiting-key"
              role="status"
              className="mt-2 rounded border border-amber-500 bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200"
            >
              <strong>Joined — waiting for a key from another device.</strong> This
              device is a member of the account and its requests are authorized, but
              membership does not hand over any encryption key. It cannot decrypt
              vault <span className="font-mono">{vaultId.trim() || "(none)"}</span>{" "}
              until an existing member shares it here (on that device: Sharing →
              Share to <span className="font-mono">{device.deviceId}</span>). Then
              use Accept below.
            </p>
          )}
          {hasSiblings && holdsKey && (
            <p
              data-testid="account-has-key"
              className="mt-2 text-xs text-neutral-600 dark:text-neutral-400"
            >
              This device holds the key for vault{" "}
              <span className="font-mono">{vaultId.trim()}</span> and can decrypt it.
            </p>
          )}
          {/* ⛔ THIS USED TO SAY "and this app cannot print one". That was true
              before Phase 56 and has been FALSE ever since — RecoveryPanel is
              rendered further down this very screen and calls
              generateRecoveryKit. A stale capability claim about the ONE control
              that prevents permanent account loss does not merely fail to help;
              it routes the user past the fix. RECOVERY_ADVICE is the single
              string, so the two cannot drift apart again. */}
          <p
            data-testid="account-recovery-advice"
            className="mt-2 text-xs text-neutral-600 dark:text-neutral-400"
          >
            An account is reachable only through a member device&rsquo;s private key,
            so losing every device is unrecoverable <em>unless a recovery kit was
            printed in advance</em>. {RECOVERY_ADVICE} Membership is flat — any
            member may invite, and may revoke any other member.
          </p>
        </>
      )}
    </div>
  );
}

// The one sentence both refusals use, so the button state and the operation
// guard can never say different things.
const SYNC_REFUSAL =
  "Sync is off for this vault in BOTH directions: it is a personal vault sealed with this " +
  "browser's passkey, so nothing else can read what is uploaded, and the copy here is the only " +
  "one — downloading would overwrite it. Convert it to a shared vault, or turn passkey " +
  "protection off.";

function SyncPanel({
  wasm,
  device,
  onDeviceChange,
  url,
  setUrl,
  vaultId,
  setVaultId,
  protection,
  activeVaultId,
  onMergeOps,
}: {
  wasm: Wasm;
  device: DeviceIdentity | null;
  onDeviceChange: (d: DeviceIdentity | null) => void;
  url: string;
  setUrl: (v: string) => void;
  vaultId: string;
  setVaultId: (v: string) => void;
  protection: ProtectionInfo | null;
  activeVaultId: string | null;
  /**
   * ⭐ Phase 61: fold every pulled op into the OPEN vault. It lives in the parent
   * because only the parent holds the opening secret — which is exactly why this
   * panel used to be able to do nothing better than store bytes and say
   * "Lock and Unlock to decrypt it", i.e. adopt the tip and lose everything else.
   */
  onMergeOps: (ops: { seq: number; container: Uint8Array }[]) => MergeOpsResult;
}) {
  const [token, setToken] = useState("");
  const [label, setLabel] = useState("this browser");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  // ⭐ A 402 is a BILLING state, not an auth failure and not a bug. It gets its
  // own non-error region so it can never be rendered as "unauthorized".
  const [payment, setPayment] = useState<{ headline: string; detail: string } | null>(null);
  // ⛔ CLOCK SKEW — the top real-world TOTP failure, and the one nothing in this
  // product reported. A code rejected because this device's clock drifted is
  // INDISTINGUISHABLE, to the user, from a wrong secret: they re-scan the QR,
  // re-import the export, delete and re-add the account, and none of it helps.
  //
  // ⛔⛔ IT IS A DIAGNOSTIC, NEVER A CORRECTION. `useUnixClock` still drives every
  // code from this device's own system clock; nothing here adjusts it. A code
  // generated against a server-supplied time is one the user cannot reproduce or
  // compare against any other authenticator.
  const [clock, setClock] = useState<import("@sigil/wasm").ClockSkewReading | null>(null);
  // Passkey-protected AND personal => the container is sealed under a key only
  // this browser holds, so there is nothing useful to upload.
  const protectedPersonal = protection !== null && activeVaultId === null;

  // Read the server's clock (one unauthenticated GET /healthz) and keep the
  // result — including the explicit "unavailable", which is NOT "your clock is
  // fine". Never throws: a diagnostic must not be able to break a sync.
  const checkClock = useCallback(async () => {
    try {
      const reading = await wasm.fetchClockSkew(
        { baseUrl: url.trim() },
        Math.floor(Date.now() / 1000),
      );
      setClock(reading);
    } catch (e) {
      setClock({ state: "unavailable", reason: msg(e) });
    }
  }, [wasm, url]);

  // Map any failure to a message; a device-auth failure carries the status, so
  // 401 (not authenticated) and 403 (not authorized for this vault) are called
  // out explicitly rather than shown as a generic HTTP error.
  function authMsg(e: unknown): string {
    const status = (e as { status?: number } | null)?.status;
    if (status === 401 || status === 403 || status === 501) {
      return wasm.explainAuthStatus(status);
    }
    return msg(e);
  }

  // Returns true when the failure was PAYMENT — in which case it has already been
  // rendered in its own region and must NOT also appear as an error.
  function handledAsPayment(e: unknown, what: string): boolean {
    const pay = wasm.paymentRequiredFrom(e, what);
    if (!pay) return false;
    setPayment(wasm.describePaymentRequired(pay));
    setStatus(`${what} was refused pending payment. Nothing else changed.`);
    return true;
  }

  async function enroll() {
    setBusy(true);
    setStatus("Enrolling this browser as a device…");
    try {
      const seed = wasm.generateDeviceSeed();
      const enrolled = await wasm.enrollDevice(wasm, {
        baseUrl: url.trim(),
        token: token.trim(),
        label: label.trim(),
        seed,
      });
      // Persist SEALED (under the vault password) — never the raw seed.
      onDeviceChange({ deviceId: enrolled.deviceId, seed, baseUrl: url.trim() });
      setToken(""); // single-use; drop it from memory immediately
      setStatus(`Enrolled as device ${enrolled.deviceId}. Sync requests are now signed.`);
    } catch (e) {
      setStatus(`Enrollment failed: ${authMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  function forgetDevice() {
    onDeviceChange(null);
    setStatus("Device identity deleted from this browser. Sync is unauthenticated again.");
  }

  async function push() {
    // A disabled button is UI, not a guard. Refuse in the operation too.
    if (protectedPersonal) {
      setStatus(SYNC_REFUSAL);
      return;
    }
    setBusy(true);
    setStatus("Pushing…");
    setPayment(null);
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (!stored) throw new Error("no sealed vault to push");
      const container = wasm.base64ToBytes(stored);
      // ⛔ THE TOMBSTONE GROWTH LIMIT. A vault is a 2P-Set: its remove-set never
      // shrinks, nothing prunes a tombstone, and past sigild's 64 KiB op cap the
      // push is a 413 with no supported way to shrink. Warn while there is still
      // room to act — meeting this first AT the 413 means sync is already gone.
      const sizeWarn = wasm.opBodySizeWarning(container.length);
      // ⭐ THE GRACE CHANNEL. sigild sets X-Sigil-Entitlement* on a write it is
      // still SERVING inside the grace period — a 2xx — so the warning exists
      // ONLY in the response headers and never in a body or an error. Reading it
      // here is what turns a lapse into a warning the user can act on instead of
      // a refusal that arrives with no notice. (Cross-origin this needs the
      // server's Access-Control-Expose-Headers, which sigild's CORS sets.)
      let warn: { state: string; status: string; graceEndsAt: string } | null = null;
      const { seq } = device
        ? await wasm.pushContainerAuthed(wasm, device, url.trim(), vaultId.trim(), container, {
            onResponse: (res) => {
              warn = wasm.readEntitlementHeaders(res);
            },
          })
        : await wasm.pushContainer(url.trim(), vaultId.trim(), container);
      const w = warn as { state: string; status: string; graceEndsAt: string } | null;
      setStatus(
        `Pushed sealed container as op #${seq}${device ? " (signed as this device)" : ""}.` +
          (w
            ? ` ⚠️ Subscription ${w.status || "lapsed"} — uploading new changes stops${
                w.graceEndsAt ? ` on ${wasm.formatInstant(w.graceEndsAt)}` : " soon"
              }. ${wasm.NEVER_REFUSED}`
            : "") +
          (sizeWarn ? ` ⚠️ ${sizeWarn}` : ""),
      );
      // A successful sync means a reachable server, i.e. a free clock reference.
      // Take the reading here so a broken clock is found while doing something
      // else, long before the user is staring at a rejected login.
      void checkClock();
    } catch (e) {
      // ⚠️ The size warning must survive the FAILURE path too — a 413 is exactly
      // where it matters, and reporting only "Push failed" there tells the user
      // nothing about why or what to do.
      const suffix = wasm.opBodySizeWarning(
        (() => {
          const s = window.localStorage.getItem(STORAGE_KEY);
          return s ? wasm.base64ToBytes(s).length : 0;
        })(),
      );
      if (!handledAsPayment(e, "Push")) {
        setStatus(`Push failed: ${authMsg(e)}${suffix ? ` ⚠️ ${suffix}` : ""}`);
      }
    } finally {
      setBusy(false);
    }
  }

  async function pull() {
    // ⛔⛔ THE DESTRUCTIVE HALF, and it was left enabled beside the disabled
    // Push. `pull()` overwrites STORAGE_KEY with whatever the server returns,
    // and for a protected PERSONAL vault that stored container is the ONLY copy
    // in existence — push is refused precisely because nothing else can read it.
    // One click therefore replaced it with either a stale pre-protection
    // container (silently losing every account added since; the recovery kit
    // recovers KEYS, not DATA) or, on a mistyped vault id, with bytes this
    // browser cannot open with the CMK, the password, the sheet or any held
    // vault key. Refused in the operation as well as the button.
    if (protectedPersonal) {
      setStatus(SYNC_REFUSAL);
      return;
    }
    setBusy(true);
    setStatus("Pulling…");
    try {
      const ops = device
        ? await wasm.pullContainersAuthed(wasm, device, url.trim(), vaultId.trim(), 0)
        : await wasm.pullContainers(url.trim(), vaultId.trim());
      if (ops.length === 0) {
        setStatus("No ops on the server for that vault id.");
        return;
      }
      // ⭐⭐ MERGE EVERY OP — do NOT adopt `ops[ops.length - 1]`.
      //
      // ⛔ This line used to be `const latest = ops[ops.length - 1]` followed by
      // writing that container over STORAGE_KEY. If a phone that had never
      // pulled pushed after this browser did, the phone's snapshot was the tip,
      // it had never seen this browser's accounts, and one click destroyed them.
      // Both devices reported success. Reproduced end to end before the fix.
      const res = onMergeOps(ops);
      const skipNote = res.skipped.length
        ? ` ⚠️ ${res.skipped.length} op(s) could not be opened with this vault's secret and were NOT merged (${res.skipped
            .map((s) => `#${s.seq}`)
            .join(", ")}) — they are still on the server.`
        : "";
      const conflictNote = res.conflicts.length
        ? ` ⚠️ ${res.conflicts.length} entr${res.conflicts.length === 1 ? "y" : "ies"} were claimed by two different snapshots; one was kept deterministically.`
        : "";
      setStatus(
        `Merged ${res.applied} op(s) through #${res.tip}. ${res.added} account(s) added, ` +
          `${res.removed} removed by a delete from another device. ` +
          `${res.vault.entries.length} account(s) now.${skipNote}${conflictNote}`,
      );
      void checkClock();
    } catch (e) {
      setStatus(`Pull failed: ${authMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <h3 className="mb-1 text-base font-semibold">Sync (dev)</h3>
      <p className="mb-3 text-xs text-neutral-600 dark:text-neutral-400">
        Round-trips the <strong>sealed</strong> container through a dev sigild
        op-log over plain HTTP (localhost only, no TLS). Requires a local sigild
        with <code>SIGILD_ENABLE_DEV_OPS</code> on. The server only ever sees
        opaque bytes. If that sigild also has <code>SIGILD_DEVICE_AUTH=1</code>,
        enroll below and every request is signed by this device.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Server URL</span>
          <input
            data-testid="sync-url"
            className={`${inputCls} font-mono`}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            spellCheck={false}
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Vault id</span>
          <input
            data-testid="sync-vault-id"
            className={`${inputCls} font-mono`}
            value={vaultId}
            onChange={(e) => setVaultId(e.target.value)}
            spellCheck={false}
          />
        </label>
      </div>

      {/* ⛔ THE CLOCK DIAGNOSTIC. A TOTP code rejected because this device's
          clock drifted is indistinguishable, to the user, from a wrong secret.
          This is the only place in the product that can tell them apart.
          ⛔⛔ It reports. It never adjusts the clock codes are generated from. */}
      <div className="mt-4 rounded border border-neutral-200 p-3 dark:border-neutral-800">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-sm font-semibold">Device clock</h4>
          <button
            data-testid="clock-check"
            className={btnGhost}
            type="button"
            onClick={() => void checkClock()}
          >
            Check clock
          </button>
        </div>
        <p className="mb-2 text-xs text-neutral-600 dark:text-neutral-400">
          Codes are computed from <em>this device&rsquo;s</em> system clock. Once it
          has drifted more than {wasm.CLOCK_SKEW_WARN_SECONDS}s &mdash; half a TOTP
          step &mdash; codes are likely to be rejected even though the secret is
          perfectly correct, and the further it drifts the more certain that
          becomes. Some verifiers accept a code from one step either side, so a
          small drift may still get through, but that is optional and you cannot
          count on it. A rejected code looks identical to a wrong secret from the
          login screen. This compares against the server&rsquo;s clock; it never
          changes the one codes are generated from.
        </p>
        {clock === null ? (
          <p
            data-testid="clock-status"
            data-state="unread"
            className="text-xs text-neutral-600 dark:text-neutral-400"
          >
            Not checked yet.
          </p>
        ) : (
          <p
            data-testid="clock-status"
            data-state={clock.state}
            role={clock.state === "skewed" ? "alert" : undefined}
            className={
              clock.state === "skewed"
                ? "text-xs font-medium text-red-700 dark:text-red-300"
                : clock.state === "unavailable"
                  ? "text-xs text-amber-800 dark:text-amber-300"
                  : "text-xs text-neutral-700 dark:text-neutral-300"
            }
          >
            {wasm.describeClockSkew(clock)}
          </p>
        )}
      </div>

      <div className="mt-4 rounded border border-neutral-200 p-3 dark:border-neutral-800">
        <h4 className="mb-1 text-sm font-semibold">Device identity</h4>
        {device ? (
          <>
            <p data-testid="device-id" className="mb-2 break-all font-mono text-xs">
              {device.deviceId}
            </p>
            <p className="mb-2 text-xs text-neutral-600 dark:text-neutral-400">
              Requests are signed with this device&rsquo;s Ed25519 key. The key is
              stored only inside a container sealed with your vault password.
            </p>
            <button
              data-testid="device-forget"
              className={btnGhost}
              type="button"
              onClick={forgetDevice}
              disabled={busy}
            >
              Forget device
            </button>
            <AccountBlock wasm={wasm} device={device} url={url} vaultId={vaultId} />
            <EntitlementBlock wasm={wasm} device={device} url={url} />
          </>
        ) : (
          <>
            <p className="mb-2 text-xs text-neutral-600 dark:text-neutral-400">
              Not enrolled — sync requests are unauthenticated. Paste a single-use
              enrollment token from the server operator to enroll this browser.
            </p>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="block text-sm">
                <span className="mb-1 block font-medium">Enrollment token</span>
                <input
                  data-testid="device-token"
                  className={`${inputCls} font-mono`}
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
              <label className="block text-sm">
                <span className="mb-1 block font-medium">Device label</span>
                <input
                  data-testid="device-label"
                  className={inputCls}
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  autoComplete="off"
                />
              </label>
            </div>
            <button
              data-testid="device-enroll"
              className={`${btnGhost} mt-3`}
              type="button"
              onClick={enroll}
              disabled={busy || token.trim() === ""}
            >
              Enroll this browser
            </button>
          </>
        )}
      </div>

      {/* ⭐ ADR 0046 SYNC REFUSAL — BOTH DIRECTIONS. `push` uploads the RAW
          stored container. Under passkey protection a PERSONAL vault is sealed
          under this browser's CONTAINER MASTER KEY, which no peer has and no
          server can ever derive, so pushing would deposit ciphertext nobody
          could ever read.
          ⛔ Silently re-sealing it under the password for the push would move the
          offline attack to the server copy and void the whole feature.
          ⛔⛔ And `pull` is refused for the MIRROR-IMAGE reason, which is worse:
          because push is off, the local container is the ONLY copy, and pull
          OVERWRITES it with whatever the server returns. Disabling one and
          leaving the other is how a feature that protects data becomes the
          feature that loses it. Both escape hatches are the same two the notice
          names — convert to a shared vault, or turn protection off — so nothing
          is taken away, it is only made deliberate. A SHARED vault is sealed
          under its vault key and syncs both ways exactly as before. */}
      {protectedPersonal && (
        <p
          data-testid="sync-push-blocked"
          role="status"
          className="mt-3 rounded border border-neutral-300 p-3 text-sm text-neutral-700 dark:border-neutral-700 dark:text-neutral-300"
        >
          Syncing is off for this vault, <strong>in both directions</strong>. It is
          a <strong>personal</strong> vault sealed with this browser&rsquo;s
          passkey: nothing else could open what was uploaded, so nothing useful is
          on the server — and because of that, the copy in this browser is the{" "}
          <strong>only</strong> one. Downloading would replace it with something
          older or unreadable, and a recovery sheet recovers keys, not data.
          Convert this to a shared vault to sync it (Sharing → Convert), or turn
          passkey protection off.
        </p>
      )}
      <div className="mt-3 flex gap-3">
        <button
          data-testid="sync-push"
          className={btnGhost}
          type="button"
          onClick={push}
          disabled={busy || protectedPersonal}
        >
          Push
        </button>
        <button
          data-testid="sync-pull"
          className={btnGhost}
          type="button"
          onClick={pull}
          disabled={busy || protectedPersonal}
        >
          Pull
        </button>
      </div>
      {/* ⭐ A REFUSED WRITE, rendered as the billing state it is. It deliberately
          does NOT use role="alert" or error styling: the server authenticated and
          authorized this device and then asked for money. Saying "unauthorized"
          here would send the user to debug a key that is working perfectly. */}
      {payment && (
        <div
          data-testid="entitlement-402"
          role="status"
          className="mt-3 rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        >
          <p className="font-semibold">{payment.headline}</p>
          <p className="mt-1">{payment.detail}</p>
        </div>
      )}

      {status && (
        <p data-testid="sync-status" className="mt-3 text-sm text-neutral-600 dark:text-neutral-300">
          {status}
        </p>
      )}
    </Card>
  );
}

// ── Passkey protection (dev) — ADR 0046 ──────────────────────────────────────
//
// ⭐ WHAT IT DOES: replaces the human PASSWORD as the sealing secret for this
// browser's two containers with a 32-byte CONTAINER MASTER KEY, wrapped once
// into a THIRD container under `PRF_output ‖ utf8(password)`. So the at-rest seal
// takes TWO factors, and a stolen copy of localStorage is useless without the
// authenticator.
//
// ⛔ IT DEFENDS STORAGE, NEVER EXECUTION. Anything running in this origin while
// the vault is unlocked still reads everything. ⛔ It is NOT retroactive: earlier
// copies, backups and forensic images stay password-only forever.
//
// ⭐ NO LOCKOUT, and this is the whole reason enabling REFUSES without a printed
// recovery kit: the ADR 0042 sheet derives the same CMK offline, so a lost
// passkey costs a re-enable, never a code.

/** The seven states, named. The UI never implies one it is not in. */
type PasskeyStage =
  | "unprotected"
  | "unavailable"
  | "no-kit"
  | "probing"
  | "probe-failed"
  | "code-required"
  | "sealing"
  | "protected";

function PasskeyPanel({
  wasm,
  device,
  url,
  protection,
  onBegin,
  onComplete,
  onDisable,
}: {
  wasm: Wasm;
  device: DeviceIdentity | null;
  url: string;
  protection: ProtectionInfo | null;
  onBegin: (baseUrl: string) => Promise<PasskeyProbeSummary>;
  onComplete: (code: string) => Promise<ProtectionInfo>;
  onDisable: () => void;
}) {
  const support = typeof window === "undefined" ? { available: false, reason: "" } : wasm.passkeySupport();
  const [stage, setStage] = useState<PasskeyStage>(support.available ? "unprotected" : "unavailable");
  const [detail, setDetail] = useState("");
  const [status, setStatus] = useState("");
  const [code, setCode] = useState("");
  const [scope, setScope] = useState("");
  // ⚠️ The break-glass sheet was REPLACED since this browser was protected.
  const [relink, setRelink] = useState(false);

  // ⭐ RELINK CHECK. Reprinting a kit changes the printed bytes and therefore the
  // CMK. The containers stay openable by the passkey, so nothing looks wrong —
  // the BREAK-GLASS just silently stops working. Detect it, do not remember it.
  useEffect(() => {
    if (!protection || !device || !protection.kitDeviceId) return;
    let cancelled = false;
    void (async () => {
      // ⚠️ BOUNDED RETRY, and it is not padding. Being offline must say NOTHING
      // rather than cry wolf — but with a single attempt one transient failure
      // suppressed the warning FOREVER for that session, which is the same
      // silence the banner exists to break.
      for (let attempt = 0; attempt < 3 && !cancelled; attempt++) {
        try {
          const account = await wasm.getAccount(wasm, device, url.trim());
          if (cancelled) return;
          const live = (account.devices ?? []).some(
            (d) => d.device_id === protection.kitDeviceId && (d.status ?? "active") === "active",
          );
          setRelink(!live);
          return;
        } catch {
          await new Promise((r) => setTimeout(r, 400));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [wasm, device, url, protection]);

  const effective: PasskeyStage = protection ? "protected" : stage;

  function begin() {
    setDetail("");
    setStatus("");
    setStage("probing");
    void (async () => {
      try {
        const probe = await onBegin(url.trim());
        setScope(probe.scope);
        setStage("code-required");
        setStatus(
          "Passkey created and its derived key verified twice. Now type the code from your " +
            "printed recovery sheet — it is checked on this device, and it is what lets you back " +
            "in if the passkey ever stops working.",
        );
      } catch (e) {
        if (e instanceof PasskeyPrecondition) {
          setStage("no-kit");
          setDetail(msg(e));
        } else {
          setStage("probe-failed");
          setDetail(
            e instanceof wasm.PasskeyError ? wasm.explainPasskeyStatus(e) : msg(e),
          );
        }
      }
    })();
  }

  function complete(ev: React.FormEvent) {
    ev.preventDefault();
    setDetail("");
    setStage("sealing");
    setTimeout(() => {
      void (async () => {
        try {
          const info = await onComplete(code);
          setCode(""); // ⭐ USED — out of the DOM immediately.
          setScope(wasm.describeProtectionScope(info));
          setStatus(
            "This browser's stored containers are now sealed with a key that needs BOTH your " +
              "password and this passkey. Your recovery sheet still opens them on its own.",
          );
        } catch (e) {
          setStage("code-required");
          setDetail(
            e instanceof wasm.PasskeyError
              ? wasm.explainPasskeyStatus(e)
              : e instanceof wasm.RecoveryError || /recovery code/i.test(msg(e))
                ? "That is not a valid recovery code — check for a mistyped character. Nothing " +
                  "was sent anywhere: the code is checked on this device. The letters I, L and O " +
                  "are never used (read them as 1, 1 and 0) and U is never used at all."
                : msg(e),
          );
        }
      })();
    }, 0);
  }

  function disable() {
    try {
      onDisable();
      setStage("unprotected");
      setScope("");
      setRelink(false);
      setStatus(
        "Passkey protection is off. Both containers are sealed with your password again.",
      );
    } catch (e) {
      setDetail(msg(e));
    }
  }

  return (
    <Card>
      <h3 className="mb-1 text-base font-semibold">Passkey protection (dev)</h3>
      <p className="mb-3 text-xs text-neutral-600 dark:text-neutral-400">
        Designed to bind this browser&rsquo;s stored vault to a passkey on
        supported browsers (unaudited). It protects what is <strong>stored</strong>
        , not what is running: anything with code execution in this page while the
        vault is unlocked can still read everything. It is not retroactive —
        copies made before you turn it on stay password-only.
      </p>

      <p data-testid="passkey-state" className="mb-2 text-sm font-medium">
        {effective === "protected"
          ? "Protected: password + passkey"
          : effective === "unavailable"
            ? "Unavailable in this browser"
            : "Password only"}
      </p>

      {effective === "protected" && (
        <>
          <p data-testid="passkey-scope" className="mb-2 text-sm text-neutral-600 dark:text-neutral-300">
            {scope || wasm.describeProtectionScope(protection ?? {})}
          </p>
          {relink && (
            <div
              data-testid="passkey-relink"
              role="status"
              className="mb-3 rounded border border-amber-500 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
            >
              <p className="font-semibold">
                Your break-glass sheet has been replaced — re-link this browser.
              </p>
              <p className="mt-1">
                The recovery kit this browser was linked to is no longer active, so
                the sheet you are holding will <strong>not</strong> open it. Turn
                protection off and on again (you will be asked for the code on your
                current sheet).
              </p>
            </div>
          )}
          <button data-testid="passkey-disable" className={btnGhost} type="button" onClick={disable}>
            Turn passkey protection off
          </button>
        </>
      )}

      {effective === "unavailable" && (
        <p data-testid="passkey-detail" className="mb-2 text-sm text-neutral-600 dark:text-neutral-300">
          This browser or authenticator cannot protect your vault with a passkey:{" "}
          {support.reason}. Your vault is unaffected.
        </p>
      )}

      {(effective === "unprotected" ||
        effective === "no-kit" ||
        effective === "probing" ||
        effective === "probe-failed") && (
        <>
          {detail && (
            <p
              data-testid="passkey-detail"
              className="mb-2 text-sm text-amber-800 dark:text-amber-300"
            >
              {detail}
            </p>
          )}
          <button
            data-testid="passkey-enable"
            className={btnGhost}
            type="button"
            onClick={begin}
            disabled={effective === "probing" || !support.available}
          >
            {effective === "probing" ? "Checking your passkey…" : "Protect this browser with a passkey"}
          </button>
        </>
      )}

      {(effective === "code-required" || effective === "sealing") && (
        <form onSubmit={complete} className="space-y-3">
          <label className="block text-sm">
            <span className="mb-1 block font-medium">Recovery code (from your printed sheet)</span>
            <input
              data-testid="passkey-code"
              className={`${inputCls} font-mono`}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              spellCheck={false}
              autoComplete="off"
              placeholder="XXXXXXXX-XXXXXXXX-…"
            />
          </label>
          {detail && (
            <p data-testid="passkey-detail" className="text-sm text-red-600 dark:text-red-400">
              {detail}
            </p>
          )}
          <button
            data-testid="passkey-confirm"
            className={btnCls}
            type="submit"
            disabled={effective === "sealing"}
          >
            {effective === "sealing" ? "Protecting…" : "Protect this browser"}
          </button>
        </form>
      )}

      {status && (
        <p data-testid="passkey-status" className="mt-3 text-sm text-neutral-600 dark:text-neutral-300">
          {status}
        </p>
      )}
    </Card>
  );
}

// ── Sharing (dev) — device-to-device vault sharing ───────────────────────────
//
// The key model, mirrored exactly from the `sigil vault ...` CLI (deviating
// would break interop AND security):
//
//   * a PERSONAL vault stays sealed under your human password. The password is
//     NEVER shared, NEVER wrapped, and never leaves this browser.
//   * a SHARED vault is sealed under a RANDOM 32-byte VAULT KEY. "Convert" is
//     the one-way door between the two (the CLI's `vault rekey`).
//   * that vault key is WRAPPED to each recipient device's published HYBRID
//     public key (X25519 + ML-KEM-768) into an opaque SIGILhyb envelope. sigild
//     relays the envelope and cannot read it: it holds no decapsulation key.
//
// STORAGE: the hybrid SECRET identity and every vault key live INSIDE the
// password-sealed device-identity container (DEVICE_KEY), exactly like the device
// seed. Nothing new is ever written to localStorage in the clear.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST. The construction is a CUSTOM
// KEM-then-AEAD, NOT RFC 9180 HPKE; the system is NOT "post-quantum secure".

function SharingPanel({
  wasm,
  device,
  activeVaultId,
  url,
  vaultId,
  onUpdateDevice,
  onRekey,
  onAdoptSharedVault,
}: {
  wasm: Wasm;
  device: DeviceIdentity | null;
  activeVaultId: string | null;
  url: string;
  vaultId: string;
  onUpdateDevice: (patch: Partial<DeviceIdentity>) => DeviceIdentity;
  onRekey: (vaultId: string, vaultKey: Uint8Array) => void;
  onAdoptSharedVault: (vaultId: string, vaultKey: Uint8Array, container: Uint8Array) => TotpVault;
}) {
  const [recipient, setRecipient] = useState("");
  const [permission, setPermission] = useState<"read" | "write">("read");
  const [status, setStatus] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [busy, setBusy] = useState(false);
  // Phase 50 — key verification. `mySafety` is this device's own safety number
  // (derived locally, no network); `theirSafety` is the recipient's, fetched for
  // DISPLAY only. `mismatch` is set when a fetched key differs from the pinned
  // one: that BLOCKS sharing until the user re-pins deliberately.
  const [mySafety, setMySafety] = useState("");
  const [theirSafety, setTheirSafety] = useState("");
  const [mismatch, setMismatch] = useState<{
    deviceId: string;
    pinned: string;
    presented: string;
  } | null>(null);
  // ⭐ PHASE 60. A vault-key envelope that is not AUTHENTICATED, or that cannot
  // be attributed to a sender, is refused — and it is NOT a 401, NOT a 403 and
  // NOT a pin mismatch, so it gets its own blocking state rather than sharing
  // the generic status line. `kind` drives the wording.
  // ⭐ …and so is a key that opens NOTHING ("does-not-open"), or one that would
  // silently REPLACE a key this browser already depends on ("would-replace") —
  // steps 4 and 5 of the CLI's `accept_vault_key`, which the browsers were
  // missing entirely. Neither is a 401, a 403 or a pin mismatch either.
  const [envelopeRefusal, setEnvelopeRefusal] = useState<{
    kind: "unauthenticated" | "unknown-sender" | "does-not-open" | "would-replace";
    detail: string;
    held?: string;
    offered?: string;
  } | null>(null);
  // The deliberate opt-in behind a "would-replace" refusal — the UI's `--replace`.
  const [acceptReplace, setAcceptReplace] = useState(false);
  const [acceptFrom, setAcceptFrom] = useState("");
  const [rotateTo, setRotateTo] = useState("");
  // ⭐ Phase 53-55 fix round. `shareSafety` is the recipient's safety number read
  // out of band — optional for an ordinary device, REQUIRED by the wrap gate for
  // a RECOVERY KIT this browser has never pinned. `rotateDrop` / `dropAllOthers`
  // exist because rotateVaultKey's drop guard defaults to "drop nothing", so a
  // rotation that excludes ANY current envelope holder — the entire point of
  // rotating — threw RecipientsWouldBeDroppedError with no way for this UI to
  // proceed. `rotateSafety` carries "deviceId=digits" pairs for the same reason
  // as shareSafety.
  const [shareSafety, setShareSafety] = useState("");
  const [rotateDrop, setRotateDrop] = useState("");
  const [rotateSafety, setRotateSafety] = useState("");
  const [dropAllOthers, setDropAllOthers] = useState(false);

  // 401 (not authenticated) vs 403 (authenticated but not permitted) vs 404
  // (nothing shared yet) are spelled out rather than shown as a generic error —
  // they mean completely different things to the user.
  function shareMsg(e: unknown): string {
    // A 402 is BILLING, not authorization: sharing to a device of ANOTHER account
    // is one of the two things a lapsed account loses. Never call it "forbidden".
    const pay = wasm.paymentRequiredFrom(e, "That share");
    if (pay) {
      const d = wasm.describePaymentRequired(pay);
      return `${d.headline} ${d.detail}`;
    }
    const status = (e as { status?: number } | null)?.status;
    if (typeof status === "number" && status >= 400) return wasm.explainSharingStatus(status);
    return msg(e);
  }

  if (!device) {
    return (
      <Card>
        <h3 className="mb-1 text-base font-semibold">Sharing (dev)</h3>
        <p data-testid="sharing-status" className="text-sm text-neutral-600 dark:text-neutral-400">
          Enroll this browser as a device first (Sync → Device identity). Sharing a
          vault requires an enrolled device on both sides.
        </p>
      </Card>
    );
  }

  const id = vaultId.trim();
  const auth = { ...device, baseUrl: url.trim() };
  const isShared = activeVaultId === id && Boolean(device.vaultKeys?.[id]);

  async function run(what: string, fn: () => Promise<void>) {
    setBusy(true);
    setStatus(`${what}…`);
    try {
      await fn();
    } catch (e) {
      // ⭐ A CHANGED hybrid key is not a generic failure. It is either a
      // key-substitution attack or a legitimate re-enrolment, and only a human
      // can tell which — so it gets its own loud, blocking state.
      if (e instanceof wasm.KeyPinMismatchError) {
        setMismatch({
          deviceId: e.deviceId,
          pinned: e.pinnedSafetyNumber,
          presented: e.presentedSafetyNumber,
        });
        setStatus(`${what} was REFUSED: that device's key changed. Nothing was shared.`);
      } else if (e instanceof wasm.UnauthenticatedEnvelopeError) {
        // ⭐ The Phase 60 refusal. The BYTES prove nothing about who produced
        // them — a completely different fact from "you are not signed in" (401),
        // "you may not do that" (403) or "that device's key changed".
        setEnvelopeRefusal({ kind: "unauthenticated", detail: msg(e) });
        setStatus(`${what} was REFUSED: that envelope is not authenticated. Nothing was opened.`);
      } else if (e instanceof wasm.UnknownSenderError) {
        setEnvelopeRefusal({ kind: "unknown-sender", detail: msg(e) });
        setStatus(`${what} was REFUSED: nothing says which device deposited that key.`);
      } else if (e instanceof wasm.VaultKeyDoesNotOpenError) {
        // ⭐ Step 4. The envelope authenticated, so this is not a forgery the
        // sender gate can name — the key inside simply does not open this vault.
        setEnvelopeRefusal({ kind: "does-not-open", detail: msg(e) });
        setStatus(`${what} was REFUSED: that key does not open this vault. Nothing was stored.`);
      } else if (e instanceof wasm.VaultKeyReplacementError) {
        // ⭐ Step 5. Everything checked out; what is refused is the OVERWRITE.
        setEnvelopeRefusal({
          kind: "would-replace",
          detail: msg(e),
          held: e.heldFingerprint,
          offered: e.offeredFingerprint,
        });
        setStatus(
          `${what} was REFUSED: it would replace a DIFFERENT key this browser already holds.`,
        );
      } else {
        setStatus(`${what} failed: ${shareMsg(e)}`);
      }
    } finally {
      setBusy(false);
    }
  }

  // ⭐ PHASE 60. A vault-key envelope is AUTHENTICATED with this device's
  // long-term hybrid secret, and the recipient checks it against the PUBLISHED
  // public half — so a wrap now needs both. Create + publish on demand rather
  // than refusing with "publish first".
  async function ensurePublishedHybrid(): Promise<HybridSecretIdentity> {
    if (device!.hybrid) return device!.hybrid;
    const hybrid = wasm.generateHybridIdentity();
    const next = onUpdateDevice({ hybrid });
    await wasm.publishHybridKey(wasm, { ...next, baseUrl: url.trim() });
    return hybrid;
  }

  // Generate this device's hybrid identity if it has none (sealing it under the
  // vault password), then publish ONLY its public halves. Self-only server-side.
  function publish() {
    void run("Publishing this device's hybrid key", async () => {
      const hybrid = device!.hybrid ?? wasm.generateHybridIdentity();
      const next = onUpdateDevice({ hybrid });
      await wasm.publishHybridKey(wasm, { ...next, baseUrl: url.trim() });
      setStatus(
        `Published this device's hybrid public key (X25519 + ML-KEM-768). Other devices can now share vaults to ${next.deviceId}.`,
      );
    });
  }

  // The one-way door: re-seal this vault under a fresh random 32-byte vault key.
  function convert() {
    void run("Converting to a shared vault", async () => {
      if (!id) throw new Error("set a vault id first (Sync → Vault id)");
      const key = wasm.generateVaultKey();
      onRekey(id, key);
      const fp = await wasm.vaultKeyFingerprint(key);
      setFingerprint(fp);
      setStatus(
        `Vault "${id}" is now sealed under a random 32-byte vault key (key sha256 ${fp}). ` +
          "Your password no longer opens it and was never shared. Push it, then share it.",
      );
    });
  }

  // Fetch the recipient's hybrid key, wrap, deposit, and grant — one call, so
  // authorization and key distribution can never drift apart.
  function share() {
    void run("Sharing the vault", async () => {
      const key = device!.vaultKeys?.[id];
      if (!key) throw new Error(`this vault is not shared yet — convert "${id}" to a shared vault first`);
      const to = recipient.trim();
      if (!to) throw new Error("paste the recipient's device id");
      setMismatch(null);
      setEnvelopeRefusal(null);
      // shareVault fetches the recipient's key through the PIN CHOKE POINT: an
      // unchanged key proceeds, a CHANGED key throws KeyPinMismatchError and
      // nothing is wrapped or uploaded. The envelope it produces is AUTHENTICATED
      // as THIS device (Phase 60): the recipient can prove the key came from us,
      // and nobody holding only our public key can mint one.
      const sender = await ensurePublishedHybrid();
      const res = await wasm.shareVault(wasm, { ...auth, hybrid: sender }, {
        vaultId: id,
        recipientDeviceId: to,
        vaultKey: key,
        permission,
        // ⚠️ EXPLICIT, and it was MISSING. `requirePinStore` FAILS CLOSED, and a
        // browser that has never pinned anything has no store — so the FIRST
        // share from a fresh profile died with "a pin store is required"
        // instead of pinning the recipient on first sight. Passing the empty
        // store is the documented way to say "I genuinely have no pins yet"; it
        // does not skip the check, it starts it.
        pins: device!.pins ?? wasm.newPinStore(),
        // Checked BEFORE anything is wrapped. Blank = not supplied.
        expectedSafetyNumber: shareSafety.trim() === "" ? null : shareSafety.trim(),
      });
      // Persist the (possibly newly-pinned) store INSIDE the sealed container.
      onUpdateDevice({ pins: res.pins });
      setFingerprint(res.fingerprint);
      setTheirSafety(res.safetyNumber);
      setStatus(
        `Shared "${id}" with ${to} (${res.permission}). Wrapped the vault key to that device's hybrid public key: ` +
          `a ${res.envelopeBytes}-byte envelope the server relays but cannot read. Key sha256 ${res.fingerprint}. ` +
          (res.pinStatus === "first-sight"
            ? `FIRST CONTACT — this key was just pinned but NOT yet verified by a human. Read the safety number ` +
              `below to ${to}'s owner over a trusted channel (a phone call, in person) and check it matches.`
            : "That device's key matches the one pinned earlier."),
      );
    });
  }

  // Show a safety number so a human can read it aloud. This is what closes the
  // FIRST-contact window pinning cannot: pinning trusts whatever it saw first.
  function showMySafety() {
    void run("Computing this device's safety number", async () => {
      if (!device!.hybrid) throw new Error("publish this device's hybrid key first");
      const pub = wasm.hybridPublicIdentity(wasm, device!.hybrid);
      setMySafety(await wasm.safetyNumber(device!.deviceId, pub));
      setStatus(
        "Read these digits to anyone about to share a vault with you, over a channel the server " +
          "does not control. Nothing was sent anywhere — this is derived from local key material.",
      );
    });
  }

  function showTheirSafety() {
    void run("Fetching the recipient's safety number", async () => {
      const to = recipient.trim();
      if (!to) throw new Error("paste the recipient's device id");
      const identity = await wasm.fetchHybridKey(wasm, auth, to);
      const sn = await wasm.safetyNumber(to, identity);
      setTheirSafety(sn);
      const pinned = device!.pins?.pins?.[to]?.safety_number;
      setStatus(
        pinned
          ? pinned === sn
            ? `This matches the key already pinned for ${to}.`
            : `⚠️ This does NOT match the key pinned for ${to} (${pinned}). Sharing will be REFUSED.`
          : `${to} is not pinned yet — its key will be pinned the first time you share. Confirm these ` +
              "digits with its owner over a trusted channel FIRST.",
      );
    });
  }

  // ⚠️ The deliberate escape hatch. Only reachable after a mismatch BLOCKED a
  // share, and only by an explicit click on a button that says what it means.
  function repin() {
    void run("Re-pinning that device's key", async () => {
      const to = mismatch!.deviceId;
      const identity = await wasm.fetchHybridKey(wasm, auth, to);
      const pins = device!.pins ?? wasm.newPinStore();
      const res = await wasm.repinHybridKey(pins, to, identity);
      onUpdateDevice({ pins });
      setMismatch(null);
      setTheirSafety(res.safetyNumber);
      setStatus(
        `Re-pinned ${to}. This client now trusts ${res.safetyNumber} for that device. ` +
          "If you did not verify those digits with its owner out of band, undo this by re-enrolling.",
      );
    });
  }

  // Rotate the vault key and re-wrap it to exactly the devices named, deleting
  // every other envelope. Protects FUTURE content only.
  function rotate() {
    void run("Rotating the vault key", async () => {
      const key = device!.vaultKeys?.[id];
      if (!key) throw new Error(`vault "${id}" is not a shared vault`);
      const recipients = rotateTo
        .split(/[\s,]+/)
        .map((x) => x.trim())
        .filter(Boolean);
      if (recipients.length === 0) {
        throw new Error("list every device id that KEEPS access (comma or space separated)");
      }
      // ⭐ THE DROP LIST. rotateVaultKey REFUSES to delete an envelope its caller
      // did not name (Phase 54), and this UI used to pass none — so any rotation
      // that actually excluded somebody, which is the whole point of rotating,
      // hard-failed with no way through. "Drop everyone else" resolves the list
      // from the server so the destruction is still stated, just not retyped.
      const drop = rotateDrop
        .split(/[\s,]+/)
        .map((x) => x.trim())
        .filter(Boolean);
      if (dropAllOthers) {
        for (const holder of await wasm.listKeyEnvelopes(wasm, auth, id)) {
          if (!recipients.includes(holder.deviceId) && !drop.includes(holder.deviceId)) {
            drop.push(holder.deviceId);
          }
        }
      }
      // "dev_x=12345 67890 …" pairs, so a recovery kit among the recipients can
      // be verified against its printed sheet before anything is wrapped.
      const safetyNumbers: Record<string, string> = {};
      for (const entry of rotateSafety.split(",")) {
        const at = entry.indexOf("=");
        if (at <= 0) continue;
        safetyNumbers[entry.slice(0, at).trim()] = entry.slice(at + 1).trim();
      }
      // The sealed container as it sits in localStorage — rotation re-seals THOSE
      // exact bytes under the new key without ever handling the plaintext here.
      const storedVault = window.localStorage.getItem(STORAGE_KEY);
      if (!storedVault) throw new Error("no sealed vault in this browser to rotate");
      const sealed = wasm.base64ToBytes(storedVault);
      const sender = await ensurePublishedHybrid();
      const res = await wasm.rotateVaultKey(wasm, { ...auth, hybrid: sender }, {
        vaultId: id,
        // ⚠️ EXPLICIT for the same reason as the share above: the pin store
        // fails closed, and a rotation is a wrap like any other.
        pins: device!.pins ?? wasm.newPinStore(),
        recipientDeviceIds: recipients,
        sealedVault: sealed,
        oldVaultKey: key,
        params: ARGON2,
        drop,
        safetyNumbers,
      });
      onUpdateDevice({ pins: res.pins });
      onRekey(id, res.vaultKey);
      setFingerprint(res.newFingerprint);
      setStatus(
        `Rotated "${id}": ${res.oldFingerprint} -> ${res.newFingerprint}. Re-wrapped to ` +
          `${res.rewrapped.map((r) => r.deviceId).join(", ")}` +
          (res.removed.length > 0 ? `; deleted the envelope of ${res.removed.join(", ")}` : "") +
          ". Push the vault so the remaining devices get the new content. NOTE: this protects " +
          "FUTURE content only — a device that already unwrapped the old key keeps whatever it copied.",
      );
    });
  }

  // Collect the envelope addressed to THIS device, unwrap it, remember the key
  // (sealed), then pull and open the shared vault.
  //
  // ⭐ PHASE 60. This path used to unwrap ANYTHING that decrypted to 32 bytes,
  // from anybody: `acceptVault` fetched no hybrid key at all, so ADR 0038's pin
  // store was never consulted here and an envelope minted from this device's own
  // PUBLISHED public key installed an attacker-chosen vault key. It now resolves
  // the DEPOSITING device (explicitly, or from this device's self-only envelope
  // index), pin-checks that device's key, and refuses anything that is not an
  // AUTHENTICATED version-2 envelope bound to (this vault, this device, that
  // sender).
  function accept() {
    void run("Accepting the shared vault", async () => {
      if (!id) throw new Error("set the shared vault's id first (Sync → Vault id)");
      // ⚠️ READ THE OPT-IN, THEN RE-ARM THE GUARD. A `--replace` left ticked
      // would silently authorize the NEXT accept — of a different vault, from a
      // different sender — which is exactly the silent overwrite step 5 exists
      // to stop. It survives only for the click it was ticked for.
      const replace = acceptReplace;
      setAcceptReplace(false);
      setEnvelopeRefusal(null);
      const from = acceptFrom.trim();
      const accepted = await wasm.acceptVault(wasm, auth, {
        vaultId: id,
        senderDeviceId: from === "" ? null : from,
        expectedSafetyNumber: shareSafety.trim() === "" ? null : shareSafety.trim(),
        // ⚠️ EXPLICIT, because `requirePinStore` FAILS CLOSED. A browser that has
        // only ever RECEIVED has never pinned anything, and an absent store is
        // treated as a caller bug rather than "everything is first-sight" — so
        // the empty store has to be stated. An empty store means the sender is
        // first sight, which is honest TOFU and exactly what the CLI's empty pin
        // file does; what it does NOT do is skip the check.
        pins: device!.pins ?? wasm.newPinStore(),
        // ⭐ PHASE 60 SYMMETRY, steps 4 and 5 of the CLI's `accept_vault_key`.
        // `heldKeys` FAILS CLOSED exactly like `pins`, and it is what makes an
        // accept refuse to silently REPLACE a key this browser depends on;
        // `replace` is the deliberate opt-in the refusal block below offers.
        // Both checks run INSIDE acceptVault — this call site only supplies the
        // facts it alone knows, so the control cannot be lost by forgetting it.
        heldKeys: device!.vaultKeys ?? {},
        replace,
      });
      // Seal the recovered key immediately, so a failed pull cannot lose it —
      // and the newly-pinned SENDER alongside it, or the next accept would treat
      // that device as first sight all over again. By this point acceptVault has
      // already PROVED the key opens the vault (or that there is nothing to
      // open) and that it is not quietly displacing another.
      onUpdateDevice({
        vaultKeys: { ...(device!.vaultKeys ?? {}), [id]: accepted.vaultKey },
        pins: accepted.pins,
      });
      setFingerprint(accepted.fingerprint);
      setTheirSafety(accepted.senderSafetyNumber);
      const provenance =
        accepted.senderTrust === "unverified-first-sight"
          ? `It was AUTHENTICATED as coming from ${accepted.senderDeviceId}, whose key this browser ` +
            `has just pinned but NOT yet verified by a human — read the safety number below to ` +
            `its owner over a trusted channel.`
          : `It was AUTHENTICATED as coming from ${accepted.senderDeviceId} (${accepted.senderTrust}).`;

      const replacedNote = accepted.replaced
        ? ` It REPLACED the key sha256 ${accepted.replaced} this browser held — anything sealed ` +
          `under that key and not re-sealed under this one is no longer readable here.`
        : "";
      // ⭐ No second pull. `acceptVault` already fetched the newest op to prove
      // the key opens it, and hands those exact bytes back — so the vault is
      // adopted from the container the check ran against, not from a later one.
      if (!accepted.verifiedAgainstTip || !accepted.tipContainer) {
        setStatus(
          `Accepted the vault key for "${id}" (sha256 ${accepted.fingerprint}) and sealed it locally, ` +
            `but the server holds no vault yet — ask the owner to push. ${provenance}${replacedNote}`,
        );
        return;
      }
      const v = onAdoptSharedVault(id, accepted.vaultKey, accepted.tipContainer);
      setStatus(
        `Accepted and opened the shared vault "${id}" — ${v.entries.length} account(s). ` +
          `Key sha256 ${accepted.fingerprint}: compare it with the sender out of band. ${provenance}${replacedNote}`,
      );
    });
  }

  return (
    <Card>
      <h3 className="mb-1 text-base font-semibold">Sharing (dev)</h3>
      <p className="mb-3 text-xs text-neutral-600 dark:text-neutral-400">
        Share this vault with another enrolled device. A shared vault is sealed
        under a <strong>random 32-byte vault key</strong>, and that key is wrapped
        to the recipient&rsquo;s <strong>hybrid</strong> public key (X25519 +
        ML-KEM-768). Your password is never shared or wrapped. The server relays an
        opaque envelope it cannot read. Uses the server URL and vault id from Sync
        above.
      </p>

      <div className="mb-3 rounded border border-neutral-200 p-3 text-xs dark:border-neutral-800">
        <p className="mb-1">
          <span className="font-medium">This device:</span>{" "}
          <span data-testid="sharing-device-id" className="break-all font-mono">
            {device.deviceId}
          </span>{" "}
          <button
            data-testid="sharing-copy-device-id"
            type="button"
            className="underline"
            onClick={() => void navigator.clipboard?.writeText(device.deviceId)}
          >
            copy
          </button>
        </p>
        <p data-testid="sharing-hybrid-state">
          <span className="font-medium">Hybrid key:</span>{" "}
          {device.hybrid
            ? "this device has a hybrid identity (publish it so others can share to you)"
            : "not created yet — publish to create and register one"}
        </p>
        <p className="mt-1">
          <span className="font-medium">Safety number:</span>{" "}
          {mySafety ? (
            <span data-testid="sharing-my-safety-number" className="font-mono tracking-wider">
              {mySafety}
            </span>
          ) : (
            <button
              data-testid="sharing-my-safety"
              type="button"
              className="underline"
              onClick={showMySafety}
              disabled={busy}
            >
              show
            </button>
          )}{" "}
          <span className="text-neutral-500">
            — read it aloud to verify this device&rsquo;s key before someone shares to it
          </span>
        </p>
        <p data-testid="sharing-vault-state">
          <span className="font-medium">Vault &ldquo;{id || "?"}&rdquo;:</span>{" "}
          {isShared
            ? `SHARED — sealed under a random vault key${fingerprint ? ` (sha256 ${fingerprint})` : ""}`
            : "personal — sealed with your password"}
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <button
          data-testid="sharing-publish"
          className={btnGhost}
          type="button"
          onClick={publish}
          disabled={busy}
        >
          Publish this device&rsquo;s hybrid key
        </button>
        <button
          data-testid="sharing-convert"
          className={btnGhost}
          type="button"
          onClick={convert}
          disabled={busy || isShared}
        >
          {isShared ? "Already a shared vault" : "Convert to a shared vault"}
        </button>
        <button
          data-testid="sharing-accept"
          className={btnGhost}
          type="button"
          onClick={accept}
          disabled={busy}
        >
          Accept a vault shared to this device
        </button>
      </div>

      {/* ⭐ PHASE 60. The sender of an envelope is now a CHECKED fact, not an
          assumption. Left blank, it is read from this device's own self-only
          envelope index; naming it explicitly is how a user pins the provenance
          when they know who shared with them. Either way the envelope must be
          AUTHENTICATED to that device's static key. */}
      <label className="mt-4 block text-sm">
        <span className="mb-1 block font-medium">
          Accept from device id{" "}
          <span className="font-normal text-neutral-500">
            (optional — the device that shared with you; blank asks the server which one)
          </span>
        </span>
        <input
          data-testid="sharing-accept-from"
          className={`${inputCls} font-mono`}
          value={acceptFrom}
          onChange={(e) => setAcceptFrom(e.target.value)}
          placeholder="dev_…"
          spellCheck={false}
          autoComplete="off"
        />
      </label>

      {/* ⭐ THE PHASE 60 REFUSAL, in its own block. Deliberately distinct from
          the 401/403 status line and from the pin-mismatch alarm above: nothing
          was forbidden and no key changed — the bytes simply do not prove who
          produced them. */}
      {envelopeRefusal && (
        <div
          data-testid="sharing-envelope-refusal"
          role="alert"
          className="mt-4 rounded border border-red-500 bg-red-50 p-3 text-sm dark:bg-red-950"
        >
          <p className="font-semibold">
            {envelopeRefusal.kind === "unauthenticated"
              ? "REFUSED — that vault-key envelope is NOT AUTHENTICATED."
              : envelopeRefusal.kind === "unknown-sender"
                ? "REFUSED — nothing says which device deposited that vault key."
                : envelopeRefusal.kind === "does-not-open"
                  ? "REFUSED — that key does NOT open this vault."
                  : "REFUSED — that would REPLACE a different key this browser already holds."}
          </p>
          <p className="mt-1">
            {envelopeRefusal.kind === "does-not-open" ? (
              <>
                Nothing was opened and no key was stored. The envelope was properly authenticated,
                so this is <strong>not</strong> a forgery the sender check can name and{" "}
                <strong>not</strong> a permission problem — the key that came out simply does not
                decrypt this vault&rsquo;s newest contents. Either it was deposited for a different
                vault, or the sender <em>rotated</em> the key and has not pushed the re-sealed
                vault yet. Ask them to push, then accept again.
              </>
            ) : envelopeRefusal.kind === "would-replace" ? (
              <>
                Nothing was replaced. This browser already holds a{" "}
                <strong>different</strong> key for this vault (sha256{" "}
                <span className="font-mono">{envelopeRefusal.held}</span>), and the one just offered
                is sha256 <span className="font-mono">{envelopeRefusal.offered}</span>. Overwriting
                it would lose access to everything sealed under the key you have — this browser may
                hold the last copy. If the sender <em>rotated</em> the vault key, that is exactly
                what you want; tick the box below and accept again. If they did not, someone
                deposited a key you did not ask for.
              </>
            ) : envelopeRefusal.kind === "unauthenticated" ? (
              <>
                Nothing was opened and no key was stored. This is <strong>not</strong> a sign-in
                problem (401) and <strong>not</strong> a permission problem (403), and no
                device&rsquo;s key changed. The envelope carries <strong>no sender</strong>: anyone
                who can read this device&rsquo;s <em>published</em> hybrid public key could have
                minted it, so accepting it could install a vault key an attacker chose and let them
                read everything written afterwards. Ask the owner to re-share the vault.
              </>
            ) : (
              <>
                Nothing was opened and no key was stored. A vault-key envelope is authenticated to
                the device that deposited it, so there is nothing to check it against until that
                device is known. Type the sharing device&rsquo;s id into{" "}
                <em>Accept from device id</em> above and try again.
              </>
            )}
          </p>
          {envelopeRefusal.kind === "would-replace" && (
            <label className="mt-2 flex items-center gap-2 text-sm font-medium">
              <input
                data-testid="sharing-accept-replace"
                type="checkbox"
                checked={acceptReplace}
                onChange={(e) => setAcceptReplace(e.target.checked)}
              />
              <span>
                Yes — replace the key I hold for this vault (the CLI spells this{" "}
                <span className="font-mono">--replace</span>)
              </span>
            </label>
          )}
          <p className="mt-2 whitespace-pre-wrap font-mono text-xs">{envelopeRefusal.detail}</p>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <label className="block text-sm sm:col-span-2">
          <span className="mb-1 block font-medium">Recipient device id</span>
          <input
            data-testid="sharing-recipient"
            className={`${inputCls} font-mono`}
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            placeholder="dev_…"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Permission</span>
          <select
            data-testid="sharing-permission"
            className={inputCls}
            value={permission}
            onChange={(e) => setPermission(e.target.value === "write" ? "write" : "read")}
          >
            <option value="read">read</option>
            <option value="write">write</option>
          </select>
        </label>
      </div>
      <div className="mt-3 flex flex-wrap gap-3">
        <button
          data-testid="sharing-share"
          className={btnGhost}
          type="button"
          onClick={share}
          disabled={busy || !isShared || recipient.trim() === "" || mismatch !== null}
        >
          Share this vault with that device
        </button>
        <button
          data-testid="sharing-their-safety"
          className={btnGhost}
          type="button"
          onClick={showTheirSafety}
          disabled={busy || recipient.trim() === ""}
        >
          Show that device&rsquo;s safety number
        </button>
      </div>

      {theirSafety && (
        <p
          data-testid="sharing-their-safety-number"
          className="mt-2 font-mono text-lg tracking-wider"
        >
          {theirSafety}
        </p>
      )}

      {/* ⭐ THE ALARM. A changed key BLOCKS sharing. The only way past it is the
          explicit re-pin button below, which says exactly what it means. */}
      {mismatch && (
        <div
          data-testid="sharing-pin-mismatch"
          role="alert"
          className="mt-4 rounded border border-red-500 bg-red-50 p-3 text-sm dark:bg-red-950"
        >
          <p className="font-semibold">
            REFUSED — the hybrid public key for {mismatch.deviceId} has CHANGED.
          </p>
          <p className="mt-1">
            Nothing was shared and no key was wrapped. This is either a{" "}
            <strong>key-substitution attack</strong> (a hostile or compromised server swapping in a
            key it can decrypt with, so it would receive this vault&rsquo;s key) or a{" "}
            <strong>legitimate re-enrolment</strong> of that device. Only you can tell, by reading
            the new digits to its owner over a channel the server does not control.
          </p>
          <p className="mt-2 font-mono text-xs">
            pinned:&nbsp;&nbsp;&nbsp;{mismatch.pinned}
            <br />
            presented: {mismatch.presented}
          </p>
          <button
            data-testid="sharing-repin"
            className={`${btnGhost} mt-3`}
            type="button"
            onClick={repin}
            disabled={busy}
          >
            I verified {mismatch.presented} with its owner — re-pin this device
          </button>
        </div>
      )}

      {/* ⭐ The out-of-band check, entered BEFORE the wrap. Optional for an
          ordinary device (a first sight is pinned and warned about), MANDATORY
          for a RECOVERY KIT this browser has never pinned — the digits are on
          the printed sheet, and a kit reconstructs the whole account. */}
      <label className="mt-3 block text-sm">
        <span className="mb-1 block font-medium">
          The other device&rsquo;s safety number (optional — required for a recovery kit)
        </span>
        <input
          data-testid="sharing-share-safety"
          className={`${inputCls} font-mono`}
          value={shareSafety}
          onChange={(e) => setShareSafety(e.target.value)}
          placeholder="83791 28129 67801 50284 55242 77845"
          spellCheck={false}
          autoComplete="off"
          inputMode="numeric"
        />
      </label>

      {/* Rotation: a fresh vault key re-wrapped to exactly these devices. */}
      <div className="mt-4 border-t border-neutral-200 pt-4 dark:border-neutral-800">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">
            Rotate: device ids that KEEP access (comma separated)
          </span>
          <input
            data-testid="sharing-rotate-to"
            className={`${inputCls} font-mono`}
            value={rotateTo}
            onChange={(e) => setRotateTo(e.target.value)}
            placeholder="dev_…, dev_… (include THIS device)"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        {/* ⭐ Rotation DELETES the envelope of everyone left out, so it refuses
            to do that by omission. Name them, or tick the box. */}
        <label className="mt-2 block text-sm">
          <span className="mb-1 block font-medium">
            …and device ids whose access is being REMOVED (comma separated)
          </span>
          <input
            data-testid="sharing-rotate-drop"
            className={`${inputCls} font-mono`}
            value={rotateDrop}
            onChange={(e) => setRotateDrop(e.target.value)}
            placeholder="dev_… (their envelope is deleted)"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <label className="mt-2 flex items-center gap-2 text-sm">
          <input
            data-testid="sharing-rotate-drop-all"
            type="checkbox"
            checked={dropAllOthers}
            onChange={(e) => setDropAllOthers(e.target.checked)}
          />
          <span>
            Remove every other device that currently holds a key for this vault
            <span className="block text-xs text-neutral-600 dark:text-neutral-400">
              Includes a RECOVERY KIT if one holds a key — after this the printed sheet no longer
              recovers this vault.
            </span>
          </span>
        </label>
        <label className="mt-2 block text-sm">
          <span className="mb-1 block font-medium">
            Safety numbers for first-sight recipients (dev_x=digits, comma separated)
          </span>
          <input
            data-testid="sharing-rotate-safety"
            className={`${inputCls} font-mono`}
            value={rotateSafety}
            onChange={(e) => setRotateSafety(e.target.value)}
            placeholder="dev_abc=83791 28129 67801 50284 55242 77845"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <button
          data-testid="sharing-rotate"
          className={`${btnGhost} mt-3`}
          type="button"
          onClick={rotate}
          disabled={busy || !isShared || rotateTo.trim() === ""}
        >
          Rotate this vault&rsquo;s key and re-wrap
        </button>
        <p className="mt-2 text-xs text-neutral-600 dark:text-neutral-400">
          Draws a fresh 32-byte vault key, re-seals this vault under it, re-wraps it to those
          devices and <strong>deletes every other device&rsquo;s envelope</strong>. This protects{" "}
          <strong>future content only</strong> — a device that already unwrapped the old key keeps
          whatever it had already copied.
        </p>
      </div>

      {status && (
        <p data-testid="sharing-status" className="mt-3 text-sm text-neutral-600 dark:text-neutral-300">
          {status}
        </p>
      )}
    </Card>
  );
}

// ── Recovery kit (dev) — generate / cover / check / revoke ───────────────────
//
// RESTORE is deliberately NOT here: it lives on the setup and locked screens
// (RestorePanel above), because a fresh install is where it is needed.
//
// ⚠️⚠️ THE KIT IS A CREDENTIAL, and stronger than a stolen locked phone: there is
// no OS lock, no biometric and no vault password in front of it. Whoever holds
// the 56 characters can read every vault it covers and revoke every device. It is
// rendered ONCE, into React state only — never localStorage, never a URL, never a
// log line — and cleared from the DOM the moment the user confirms they have it.

/** The four things a printed sheet must say, in the words the CLI prints. */
const KIT_WARNINGS = [
  "WHOEVER HOLDS THIS CODE HAS FULL CONTROL OF THE ACCOUNT. They can read every vault it covers and revoke every device. There is no OS lock, no biometric and no vault password in front of it — the 56 characters are the whole credential.",
  "STORE IT AWAY FROM YOUR DEVICES: a safe, a sealed envelope, a bank box. Not in a password manager you unlock with one of these devices, and not in the drawer under the laptop.",
  "NEVER PHOTOGRAPH IT and never type it into anything but a Sigil client. It is shown once, here, for you to write down — this browser does not store it and cannot show it again.",
  "IT RECOVERS KEYS, NOT DATA, and only for the vaults listed below AS OF TODAY. A vault created later needs covering; a vault never pushed to the server cannot come back. A kit cannot be created after you have lost access.",
];

interface GeneratedKit {
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
    // ⭐ GENERATION IS THE ONE MOMENT THE USER CAN STILL ACT — re-print, reduce
    // coverage, copy the "covers" line carefully. By restore time the paper is
    // fixed, so a kit whose index is ALREADY crowded has to say so HERE.
    indexTruncated: boolean;
    unwrappedVault: string;
    fingerprint: string;
  };
}

function RecoveryPanel({
  wasm,
  device,
  url,
  vaultId,
  protection,
  onKitReprinted,
  onUpdateDevice,
}: {
  wasm: Wasm;
  device: DeviceIdentity | null;
  url: string;
  vaultId: string;
  protection: ProtectionInfo | null;
  onKitReprinted: (code: string, kitDeviceId: string) => Promise<void>;
  onUpdateDevice: (patch: Partial<DeviceIdentity>) => DeviceIdentity;
}) {
  const [kit, setKit] = useState<GeneratedKit | null>(null);
  const [written, setWritten] = useState(false);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [coverKitId, setCoverKitId] = useState("");
  const [coverSafety, setCoverSafety] = useState("");
  const [revokeKitId, setRevokeKitId] = useState("");
  // ⛔ Set when the wrap gate refused a first-sight recovery kit. It BLOCKS the
  // cover and tells the user to compare the printed digits — the one case where
  // the out-of-band channel is guaranteed to exist, because it is on the sheet.
  const [unverified, setUnverified] = useState<{ deviceId: string; presented: string } | null>(null);
  const [coverage, setCoverage] = useState<
    { kits: { deviceId: string; label: string; status: string }[]; vaults: { vaultId: string; kits: string[]; note: string }[] } | null
  >(null);

  if (!device) {
    return (
      <Card>
        <h3 className="mb-1 text-base font-semibold">Recovery kit (dev)</h3>
        <p data-testid="recovery-status" className="text-sm text-neutral-600 dark:text-neutral-400">
          Enroll this browser as a device first (Sync → Device identity). A recovery kit is an
          ordinary member device of your account whose keys come from paper, so there has to be an
          account to add it to.
        </p>
      </Card>
    );
  }

  const auth = { ...device, baseUrl: url.trim() };
  const id = vaultId.trim();
  const vaultKeys = Object.entries(device.vaultKeys ?? {}).map(([v, k]) => ({
    vaultId: v,
    vaultKey: k,
  }));
  const thisVaultKey = device.vaultKeys?.[id];

  async function run(what: string, fn: () => Promise<void>) {
    setBusy(true);
    setStatus(`${what}…`);
    try {
      await fn();
    } catch (e) {
      if (e instanceof wasm.UnverifiedRecoveryKitError) {
        setUnverified({ deviceId: e.deviceId, presented: e.presentedSafetyNumber });
        setStatus(
          `${what} was REFUSED: that device is a recovery kit this browser has never seen, and ` +
            "the only thing vouching for its key is the server. Nothing was wrapped and nothing " +
            "was uploaded.",
        );
      } else if (e instanceof wasm.SafetyNumberMismatchError) {
        setStatus(
          `${what} was REFUSED: the safety number you typed does not match the key this server is ` +
            `serving for ${e.deviceId}. You typed ${e.expectedSafetyNumber}; the server presented ` +
            `${e.presentedSafetyNumber}. Either it was mistyped, or the server substituted a key ` +
            "it can decrypt with. Nothing was wrapped, nothing uploaded, no key pinned.",
        );
      } else if (e instanceof wasm.KeyPinMismatchError) {
        setStatus(
          `${what} was REFUSED: the hybrid key for ${e.deviceId} has CHANGED since this browser ` +
            `pinned it (pinned ${e.pinnedSafetyNumber}, presented ${e.presentedSafetyNumber}). ` +
            "Nothing was wrapped or uploaded.",
        );
      } else if (e instanceof wasm.UnauthenticatedEnvelopeError) {
        // ⭐ PHASE 60, rendered DISTINCTLY here too: not a 401, not a 403, not a
        // changed key. The bytes prove nothing about who produced them.
        setStatus(
          `${what} was REFUSED: that vault-key envelope is NOT AUTHENTICATED (SIGILhyb version ` +
            `${e.foundVersion}, and a vault key must be version ${e.expectedVersion}). It carries ` +
            "no sender, so anyone who can read this device's published hybrid public key could " +
            "have minted it. Nothing was opened and no key was stored — ask the owner to re-share " +
            "the vault.",
        );
      } else if (e instanceof wasm.UnknownSenderError) {
        setStatus(
          `${what} was REFUSED: nothing says which device deposited that vault key, so there is ` +
            "nothing to authenticate it against. Nothing was opened and no key was stored.",
        );
      } else {
        const f = explainRecoveryFailure(wasm, e);
        setStatus(`${what} failed: ${f.headline} ${f.detail}`);
      }
    } finally {
      setBusy(false);
    }
  }

  // ⭐ PHASE 60. A vault-key envelope is now AUTHENTICATED with the SENDING
  // device's long-term hybrid secret, and the recipient checks it against the
  // PUBLISHED public half — so covering a vault requires this browser to have a
  // hybrid identity AND to have published it. Before Phase 60 a wrap needed only
  // the recipient's public key, which is precisely why anybody else could mint
  // one. This creates and publishes on demand rather than failing with "publish
  // first", because the user did not choose to care about this.
  async function ensurePublishedHybrid(): Promise<HybridSecretIdentity> {
    if (device!.hybrid) return device!.hybrid;
    const hybrid = wasm.generateHybridIdentity();
    const next = onUpdateDevice({ hybrid });
    await wasm.publishHybridKey(wasm, { ...next, baseUrl: url.trim() });
    return hybrid;
  }

  // GENERATE. Mints an invite pinned to the kit's own public key, enrolls the kit
  // under the visible `recovery-kit` label, publishes its hybrid key, PINS the
  // key it DERIVED (so nothing was fetched and nothing could be substituted),
  // covers every vault key this browser holds, and then VERIFIES the whole thing
  // end to end before returning — revoking the partial kit if any step fails.
  function generate() {
    void run("Generating a recovery kit", async () => {
      const pins = device!.pins ?? wasm.newPinStore();
      const sender = await ensurePublishedHybrid();
      const res = await wasm.generateRecoveryKit(
        wasm,
        { ...auth, hybrid: sender },
        { vaultKeys, pins },
      );
      onUpdateDevice({ pins: res.pins }); // the DERIVED pin, re-sealed
      // ⭐⭐ SAME OPERATION, deliberately. A NEW sheet means NEW printed bytes and
      // therefore a NEW container master key. If this browser is passkey-protected
      // and its slot is not re-sealed right here, the containers keep opening (the
      // slot still yields the OLD key) while the BREAK-GLASS silently dies — and
      // nothing would tell anyone. Same failure shape as ADR 0042's
      // `RecipientsWouldBeDropped`, so it is BUILT, not remembered.
      let relinked = "";
      if (protection) {
        await onKitReprinted(res.code, res.deviceId);
        relinked =
          " This browser's passkey protection was re-linked to the NEW sheet in the same step, " +
          "so the code above is the one that opens it.";
      }
      setWritten(false);
      setKit(res);
      setStatus(
        `Kit ${res.deviceId} created in account ${res.accountId} and verified end to end ` +
          `(it re-derived its own identity from the printed code, authenticated, and unwrapped ` +
          `${res.verification.unwrappedVault || "no vault"}). Covers ${res.covered.length} vault(s).` +
          relinked,
      );
    });
  }

  // COVER one more vault, so the kit can actually open it. A kit that covers
  // nothing recovers nothing — the likeliest real-world failure.
  function cover() {
    void run("Covering this vault", async () => {
      if (!id) throw new Error("set a vault id first (Sync → Vault id)");
      if (!thisVaultKey) {
        throw new Error(
          `vault "${id}" is still a PERSONAL vault sealed with your password. A recovery kit can ` +
            "only be given a vault KEY, so convert it to a shared vault first (Sharing → Convert).",
        );
      }
      const to = coverKitId.trim();
      if (!to) throw new Error("paste the kit's device id (it is printed on the sheet)");
      setUnverified(null);
      const sender = await ensurePublishedHybrid();
      const res = await wasm.coverVault(wasm, { ...auth, hybrid: sender }, {
        kitDeviceId: to,
        vaultId: id,
        vaultKey: thisVaultKey,
        pins: device!.pins ?? wasm.newPinStore(),
        expectedSafetyNumber: coverSafety.trim() === "" ? null : coverSafety.trim(),
      });
      onUpdateDevice({ pins: res.pins });
      setStatus(
        `Vault "${id}" is now covered by kit ${to} — a ${res.envelopeBytes}-byte envelope the ` +
          `server relays but cannot read (key sha256 ${res.fingerprint}). ` +
          (res.derived
            ? "The kit's key was derived locally by this browser, so nothing was fetched and " +
              "nothing could have been substituted."
            : "The kit's key came from the server and matched the safety number you supplied."),
      );
    });
  }

  // CHECK: is recovery set up, and which vaults does a kit actually cover?
  function check() {
    void run("Checking recovery", async () => {
      const account = await wasm.getAccount(wasm, device!, url.trim());
      const kits = (account.devices ?? [])
        .filter((d) => d.label === wasm.RECOVERY_DEVICE_LABEL)
        .map((d) => ({
          deviceId: d.device_id,
          label: d.label ?? "",
          status: d.status ?? "active",
        }));
      const vaults: { vaultId: string; kits: string[]; note: string }[] = [];
      for (const { vaultId: v } of vaultKeys) {
        try {
          const holders = await wasm.listKeyEnvelopes(wasm, auth, v);
          vaults.push({
            vaultId: v,
            kits: holders.map((h) => h.deviceId).filter((d) => kits.some((k) => k.deviceId === d)),
            note: "",
          });
        } catch (e) {
          vaults.push({ vaultId: v, kits: [], note: msg(e) });
        }
      }
      setCoverage({ kits, vaults });
      const covered = vaults.filter((v) => v.kits.length > 0).length;
      setStatus(
        kits.length === 0
          ? "Recovery is NOT set up: this account has no recovery kit. If every device is lost, " +
              "the account and its vaults are unreachable — by you and by us. A kit cannot be " +
              "created after the fact."
          : `${kits.length} recovery kit(s) enrolled; ${covered} of ${vaults.length} vault(s) this ` +
              "browser holds a key for are covered. A vault that is not covered cannot be " +
              "recovered by that sheet.",
      );
    });
  }

  // REVOKE. Envelopes are taken back FIRST, while this device's own access is
  // certainly intact; the kit is then refused at the door.
  function revoke() {
    void run("Revoking the kit", async () => {
      const to = revokeKitId.trim();
      if (!to) throw new Error("paste the kit's device id");
      const res = await wasm.revokeRecoveryKit(wasm, auth, {
        kitDeviceId: to,
        vaultIds: vaultKeys.map((v) => v.vaultId),
      });
      setStatus(
        `Revoked kit ${to}; removed its envelope for ${
          res.removed.length ? res.removed.join(", ") : "no vault"
        }. ${res.rotateReminder}`,
      );
    });
  }

  return (
    <Card>
      <h3 className="mb-1 text-base font-semibold">Recovery kit (dev)</h3>
      <p className="mb-3 text-xs text-neutral-600 dark:text-neutral-400">
        A recovery kit is an <strong>ordinary member device of your account whose keys come from
        paper</strong>. The server gains no concept of &ldquo;recovery&rdquo; — it sees one more
        device, one more published public key, and one more opaque envelope per covered vault. It
        is the only thing that gets your vaults back if every device is lost, and{" "}
        <strong>it cannot be created after that happens</strong>.
      </p>

      {/* ── the printed sheet: shown ONCE ─────────────────────────────────── */}
      {kit && (
        <div
          data-testid="recovery-sheet"
          data-print-region=""
          className="mb-4 rounded border-2 border-neutral-900 p-4 dark:border-neutral-100"
        >
          <h4 className="text-sm font-semibold">Your recovery kit — write this down now</h4>
          <p
            data-testid="recovery-code"
            className="my-3 break-all font-mono text-base leading-7 tracking-widest sm:text-lg"
          >
            {kit.formatted}
          </p>
          <dl className="grid grid-cols-1 gap-1 text-xs sm:grid-cols-2">
            <div>
              <dt className="inline font-medium">Kit device id: </dt>
              <dd data-testid="recovery-kit-id" className="inline break-all font-mono">
                {kit.deviceId}
              </dd>
            </div>
            <div>
              <dt className="inline font-medium">Account: </dt>
              <dd className="inline break-all font-mono">{kit.accountId}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="inline font-medium">Server: </dt>
              <dd className="inline break-all font-mono">{kit.baseUrl}</dd>
            </div>
            <div className="sm:col-span-2">
              <dt className="inline font-medium">Safety number: </dt>
              <dd data-testid="recovery-safety-number" className="inline font-mono tracking-wider">
                {kit.safetyNumber}
              </dd>
            </div>
          </dl>
          {/* ⭐ THE LABEL IS THE LITERAL WORD `covers`, and that is not
              cosmetic. The restore field above and the truncation warning below
              both tell the user to copy "the sheet's `covers` line" — and this
              sheet used to be headed "Vaults covered as of today", so in a
              crisis it pointed a person at a label their own paper did not
              carry. `sigil recovery generate` prints `covers <ids> (as of the
              print date)` and the desktop prints `covers:`, so a user may also
              be holding a sheet from another client; one word across all four. */}
          <p className="mt-2 text-xs">
            <span className="font-medium">covers </span>
            <span data-testid="recovery-covered" className="font-mono">
              {kit.covered.length ? kit.covered.map((c) => c.vaultId).join(", ") : "NONE"}
            </span>
            <span className="opacity-70"> (as of the print date)</span>
          </p>
          {kit.covered.length === 0 && (
            <p
              data-testid="recovery-covers-nothing"
              role="alert"
              className="mt-2 rounded border border-red-500 bg-red-50 p-2 text-xs text-red-800 dark:border-red-700 dark:bg-red-950 dark:text-red-200"
            >
              <strong>This kit covers NOTHING, so it would recover nothing.</strong> It can
              authenticate to the account, but it holds no vault key. Convert a vault to a shared
              vault (Sharing → Convert) and then use <em>Cover this vault</em> below, or this sheet
              is worthless.
            </p>
          )}
          {kit.verification.indexTruncated && (
            // ⭐ RENDERED AT THE MOMENT OF PRINTING, deliberately — this is the
            // last point at which the user can do anything about it. The kit
            // still works and is still printed: refusing to print because a
            // stranger crowded a server listing would hand an availability
            // attack the power to stop kits being made at all, which is a denial
            // of the last line of defence (ADR 0040 limitation 1) and strictly
            // worse than the truncation it would be reacting to. Mirrors the
            // block in `cli/src/main.rs`.
            <p
              data-testid="recovery-index-truncated"
              role="alert"
              className="mt-2 rounded border border-amber-500 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
            >
              <strong>
                This server already lists more waiting keys for this kit than it will show at once,
                and there is no way to ask for the rest.
              </strong>{" "}
              The kit works, and the <em>covers</em> line above is what a restore should be given —
              it asks each vault directly, which cannot be crowded out. But do not rely on the
              server being able to tell this kit what it holds, and <strong>re-print</strong> this
              sheet after covering anything new.
            </p>
          )}
          <ul className="mt-3 space-y-2 text-xs">
            {KIT_WARNINGS.map((w) => (
              <li key={w.slice(0, 24)} className="rounded bg-neutral-100 p-2 dark:bg-neutral-900">
                {w}
              </li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap gap-3 print:hidden">
            <button
              data-testid="recovery-print"
              className={btnGhost}
              type="button"
              onClick={() => window.print()}
            >
              Print this sheet
            </button>
            <button
              data-testid="recovery-copy"
              className={btnGhost}
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(kit.formatted);
                setStatus(
                  "Copied to the clipboard — which other applications can read. Paste it into " +
                    "whatever will hold it, then clear your clipboard.",
                );
              }}
            >
              Copy code
            </button>
          </div>
          <label className="mt-3 flex items-start gap-2 text-xs print:hidden">
            <input
              data-testid="recovery-written"
              type="checkbox"
              checked={written}
              onChange={(e) => setWritten(e.target.checked)}
            />
            <span>
              I have written the code down and stored it away from my devices. I understand it
              cannot be shown again.
            </span>
          </label>
          <button
            data-testid="recovery-hide"
            className={`${btnCls} mt-3 print:hidden`}
            type="button"
            disabled={!written}
            onClick={() => {
              // ⭐ USED — clear it from the DOM. Nothing about it was persisted.
              setKit(null);
              setWritten(false);
              setStatus(
                "The recovery code has been cleared from this screen and was never stored. If you " +
                  "did not write it down, generate a new kit and revoke the old one.",
              );
            }}
          >
            I have written it down — hide the code
          </button>
        </div>
      )}

      {!kit && (
        <div className="flex flex-wrap gap-3">
          <button
            data-testid="recovery-generate"
            className={btnGhost}
            type="button"
            onClick={generate}
            disabled={busy}
          >
            Generate a recovery kit
          </button>
          <button
            data-testid="recovery-check"
            className={btnGhost}
            type="button"
            onClick={check}
            disabled={busy}
          >
            Check recovery
          </button>
        </div>
      )}

      {vaultKeys.length === 0 && !kit && (
        <p
          data-testid="recovery-no-vault-keys"
          role="note"
          className="mt-3 rounded border border-amber-500 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
        >
          This browser holds no vault keys yet, so a kit generated now would cover{" "}
          <strong>nothing</strong> — and a kit that covers nothing recovers nothing. Convert this
          vault to a shared vault first (Sharing → Convert to a shared vault).
        </p>
      )}

      {coverage && (
        <div data-testid="recovery-coverage" className="mt-3 rounded border border-neutral-200 p-3 text-xs dark:border-neutral-800">
          <p className="font-medium">
            {coverage.kits.length === 0
              ? "Recovery: NOT SET UP (no recovery kit in this account)"
              : `Recovery: ${coverage.kits.length} kit(s) enrolled`}
          </p>
          <ul className="mt-1 space-y-1">
            {coverage.kits.map((k) => (
              <li key={k.deviceId} className="break-all font-mono">
                {k.deviceId} — {k.status}
              </li>
            ))}
          </ul>
          <ul className="mt-2 space-y-1">
            {coverage.vaults.map((v) => (
              <li key={v.vaultId}>
                <span className="font-mono">{v.vaultId}</span>:{" "}
                {v.note
                  ? `could not be checked (${v.note})`
                  : v.kits.length
                    ? `covered by ${v.kits.join(", ")}`
                    : "NOT covered by any kit"}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ⛔ The first-sight refusal, spelled out. The safety number is on the
          sheet, which is what makes this requirement usable rather than merely
          strict — the out-of-band channel is in the user's hand. */}
      {unverified && (
        <div
          data-testid="recovery-unverified"
          role="alert"
          className="mt-3 rounded border border-red-500 bg-red-50 p-3 text-sm dark:border-red-700 dark:bg-red-950"
        >
          <p className="font-semibold">
            REFUSED — {unverified.deviceId} is a recovery kit this browser has never seen.
          </p>
          <p className="mt-1">
            Nothing was wrapped and nothing was uploaded. The only thing vouching for that kit&rsquo;s
            key is the server, and a hostile server that substituted its own key would be handed
            this vault&rsquo;s key. <strong>The safety number is printed on the recovery sheet.</strong>{" "}
            Compare it with the digits below, out of band, then type it into the field and try again.
          </p>
          <p className="mt-2 font-mono text-xs">from server: {unverified.presented}</p>
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Kit device id</span>
          <input
            data-testid="recovery-cover-kit"
            className={`${inputCls} font-mono`}
            value={coverKitId}
            onChange={(e) => setCoverKitId(e.target.value)}
            placeholder="dev_… (printed on the sheet)"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block font-medium">
            Its safety number (required on a browser that did not print it)
          </span>
          <input
            data-testid="recovery-cover-safety"
            className={`${inputCls} font-mono`}
            value={coverSafety}
            onChange={(e) => setCoverSafety(e.target.value)}
            placeholder="83791 28129 67801 50284 55242 77845"
            spellCheck={false}
            autoComplete="off"
            inputMode="numeric"
          />
        </label>
      </div>
      <button
        data-testid="recovery-cover"
        className={`${btnGhost} mt-3`}
        type="button"
        onClick={cover}
        disabled={busy}
      >
        Cover vault &ldquo;{id || "?"}&rdquo; with that kit
      </button>

      <div className="mt-4 border-t border-neutral-200 pt-4 dark:border-neutral-800">
        <label className="block text-sm">
          <span className="mb-1 block font-medium">Retire a kit (device id)</span>
          <input
            data-testid="recovery-revoke-kit"
            className={`${inputCls} font-mono`}
            value={revokeKitId}
            onChange={(e) => setRevokeKitId(e.target.value)}
            placeholder="dev_…"
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <button
          data-testid="recovery-revoke"
          className={`${btnGhost} mt-3`}
          type="button"
          onClick={revoke}
          disabled={busy}
        >
          Revoke this kit and take back its envelopes
        </button>
        <p className="mt-2 text-xs text-neutral-600 dark:text-neutral-400">
          Revocation stops the sheet talking to the server. It <strong>cannot un-learn</strong> a
          vault key the kit already unwrapped — rotate each vault (Sharing → Rotate, dropping the
          kit) so future content is unreadable to it.
        </p>
      </div>

      {status && (
        <p data-testid="recovery-status" className="mt-3 text-sm text-neutral-600 dark:text-neutral-300">
          {status}
        </p>
      )}
    </Card>
  );
}

// ── Entitlement (dev) — read what sigild says about payment, and say it back ──
//
// ⭐ THE MESSAGE MUST BE TRUE. sigild refuses WRITES only, and only past grace,
// and never a key deposit to a device of the caller's OWN account (ADR 0043). So
// this never says a user has lost access to their codes — they have not: codes
// are generated here, in the wasm, offline, from a vault this browser already
// holds.
//
// A server with enforcement OFF sends no headers and omits the `entitlement`
// block entirely; that renders as NOTHING rather than as a reassuring message
// nobody asked for.

function EntitlementBlock({
  wasm,
  device,
  url,
}: {
  wasm: Wasm;
  device: DeviceIdentity;
  url: string;
}) {
  const [note, setNote] = useState<{ tone: string; headline: string; detail: string } | null>(null);
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    setBusy(true);
    try {
      const sub = await wasm.getSubscription(wasm, { ...device, baseUrl: url.trim() }, url.trim());
      const state = wasm.entitlementState(sub);
      const described = wasm.describeEntitlement(state);
      setNote(described.tone === "none" ? null : described);
      setStatus(
        state.level === "off"
          ? "This server does not enforce payment, so nothing here is gated."
          : "",
      );
    } catch (e) {
      setNote(null);
      const code = (e as { status?: number } | null)?.status;
      setStatus(
        typeof code === "number"
          ? `Subscription unavailable: ${wasm.explainSubscriptionStatus(code)}`
          : `Subscription unavailable: ${msg(e)}`,
      );
    } finally {
      setBusy(false);
    }
  }, [wasm, device, url]);

  // Read it once on mount: a client that only ever READS is never refused and
  // never sees a warning header, so this route is its only warning channel.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <div className="mt-3 border-t border-neutral-200 pt-3 dark:border-neutral-800">
      <div className="flex items-center gap-2">
        <h5 className="text-xs font-semibold">Subscription</h5>
        <button
          data-testid="entitlement-refresh"
          className={btnGhost}
          type="button"
          onClick={() => void refresh()}
          disabled={busy}
        >
          Check
        </button>
      </div>
      {note && (
        <div
          data-testid={note.tone === "billing" ? "entitlement-refused" : "entitlement-grace"}
          // A billing state is NOT an error and NOT an alert: it is information
          // the user should see and act on, not an emergency and not a fault.
          role="status"
          className={
            note.tone === "warning" || note.tone === "billing"
              ? "mt-2 rounded border border-amber-500 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200"
              : "mt-2 text-xs text-neutral-600 dark:text-neutral-400"
          }
        >
          <p className="font-semibold">{note.headline}</p>
          <p className="mt-1">{note.detail}</p>
        </div>
      )}
      {status && (
        <p data-testid="entitlement-status" className="mt-2 text-xs text-neutral-600 dark:text-neutral-400">
          {status}
        </p>
      )}
    </div>
  );
}
