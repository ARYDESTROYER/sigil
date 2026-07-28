"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { AccountInfo, DeviceIdentity, TotpEntry, TotpVault } from "@sigil/wasm";

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

// Argon2id parameters used when (re)sealing. The container is self-describing
// (it stores these), so open needs none and the vault stays CLI-interoperable
// regardless. OWASP-minimum-ish interactive params for a dev build.
const ARGON2 = { m_cost: 19456, t_cost: 2, p_cost: 1 };

type Phase = "loading" | "error" | "setup" | "locked" | "unlocked";

function msg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

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
  // What SEALS the TOTP vault container: the human password for a personal vault,
  // or the 32-byte VAULT KEY for a shared one. A SIGILcli container takes
  // arbitrary password BYTES, so a random key drops straight in where a password
  // goes — exactly as the `sigil vault rekey` CLI does it. Memory-only.
  const sealRef = useRef<string | Uint8Array>("");

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

  // Seal `v` with the CURRENT seal secret (fresh salt + nonce from the CSPRNG)
  // and write the sealed container (base64) to localStorage. Only the sealed
  // bytes are stored — never the vault, the password or a vault key.
  function persist(m: Wasm, v: TotpVault, secret?: string | Uint8Array): void {
    const salt = crypto.getRandomValues(new Uint8Array(m.recommended_salt_len()));
    const nonce = crypto.getRandomValues(new Uint8Array(m.nonce_len()));
    const container = m.sealVault(m, secret ?? sealRef.current, v, salt, nonce, ARGON2);
    window.localStorage.setItem(STORAGE_KEY, m.bytesToBase64(container));
  }

  // Apply a mutation to a fresh clone of the vault, re-seal + persist, and swap
  // in the new state. The mutator may throw (e.g. a duplicate label) BEFORE any
  // persist happens, so a rejected change never corrupts the stored vault.
  function withVault(fn: (draft: TotpVault) => void): TotpVault {
    if (!wasm || !vault) throw new Error("vault is locked");
    const draft: TotpVault = { version: vault.version, entries: [...vault.entries] };
    fn(draft);
    persist(wasm, draft);
    setVault(draft);
    return draft;
  }

  // Seal the device identity under the CURRENT vault password and store only the
  // sealed container. Passing null forgets the identity entirely.
  function persistDevice(m: Wasm, d: DeviceIdentity | null): void {
    if (!d) {
      window.localStorage.removeItem(DEVICE_KEY);
      setDevice(null);
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(m.recommended_salt_len()));
    const nonce = crypto.getRandomValues(new Uint8Array(m.nonce_len()));
    const container = m.sealDeviceIdentity(m, passwordRef.current, d, salt, nonce, ARGON2);
    window.localStorage.setItem(DEVICE_KEY, m.bytesToBase64(container));
    setDevice(d);
  }

  // Decrypt the stored device identity with the just-accepted password. A
  // container that will not open (e.g. sealed under an older password) is
  // treated as "no device" rather than blocking the unlock.
  function loadDevice(m: Wasm, password: string): DeviceIdentity | null {
    const stored = window.localStorage.getItem(DEVICE_KEY);
    if (!stored) {
      setDevice(null);
      return null;
    }
    try {
      const d = m.openDeviceIdentity(m, password, m.base64ToBytes(stored));
      setDevice(d);
      return d;
    } catch {
      setDevice(null);
      return null;
    }
  }

  function createVault(password: string): void {
    if (!wasm) throw new Error("wasm not ready");
    const v = wasm.newVault();
    passwordRef.current = password;
    sealRef.current = password;
    setActiveVaultId(null);
    persist(wasm, v, password);
    setVault(v);
    loadDevice(wasm, password);
    setPhase("unlocked");
  }

  function unlock(password: string): void {
    if (!wasm) throw new Error("wasm not ready");
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (!stored) throw new Error("no sealed vault found");
    const container = wasm.base64ToBytes(stored);

    // The device identity opens with the PASSWORD; it is what carries any vault
    // keys, so it must be read first.
    const d = loadDevice(wasm, password);

    // A personal vault opens with the password. A SHARED vault is sealed under a
    // random 32-byte vault key instead, so fall back to the keys this device
    // holds — exactly the CLI's `--vault-id` rule, just chosen automatically.
    let v: TotpVault;
    let sealedUnder: string | Uint8Array = password;
    let sharedAs: string | null = null;
    try {
      v = wasm.openVault(wasm, password, container);
    } catch (passwordError) {
      let opened: TotpVault | null = null;
      for (const [id, key] of Object.entries(d?.vaultKeys ?? {})) {
        try {
          opened = wasm.openVault(wasm, key, container);
          sealedUnder = key;
          sharedAs = id;
          break;
        } catch {
          // not this vault's key — try the next one
        }
      }
      if (!opened) throw passwordError; // report the password failure, not the last key
      v = opened;
    }

    passwordRef.current = password;
    sealRef.current = sealedUnder;
    setActiveVaultId(sharedAs);
    setVault(v);
    setPhase("unlocked");
  }

  function lock(): void {
    passwordRef.current = "";
    sealRef.current = "";
    setActiveVaultId(null);
    setVault(null);
    setDevice(null); // the seed, hybrid secret and vault keys leave memory too
    setPhase("locked");
  }

  function forget(): void {
    window.localStorage.removeItem(STORAGE_KEY);
    window.localStorage.removeItem(DEVICE_KEY);
    passwordRef.current = "";
    sealRef.current = "";
    setActiveVaultId(null);
    setVault(null);
    setDevice(null);
    setPhase("setup");
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
  }): Promise<{ vaultId: string; accounts: number; accountId: string; notes: string[] }> {
    if (!wasm) throw new Error("wasm not ready");
    const baseUrl = args.baseUrl.trim();

    // Offline decode + checksum happens inside restoreFromKit, before any I/O.
    const res = await wasm.restoreFromKit(wasm, {
      baseUrl,
      code: args.code,
      deviceId: args.deviceId.trim(),
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
        const container = ops[ops.length - 1].container;
        opened = wasm.openVault(wasm, v.vaultKey, container); // throws before anything is stored
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
    const pins = wasm.newPinStore();
    await wasm.pinDerivedKey(
      pins,
      res.deviceId,
      wasm.hybridPublicIdentity(wasm, res.identity.hybrid),
    );

    passwordRef.current = args.password;
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
    sealRef.current = openedKey;
    setActiveVaultId(openedId);
    setVault(opened);
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
    sealRef.current = vaultKey;
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
    sealRef.current = vaultKey;
    setActiveVaultId(vaultId);
    setVault(v);
    return v;
  }

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
        <UnlockPanel onUnlock={unlock} onForget={forget} />
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
        onDeviceChange={(d) => persistDevice(wasm, d)}
        onUpdateDevice={updateDevice}
        onRekey={rekeyVault}
        onAdoptSharedVault={adoptSharedVault}
        onAdd={(input) => withVault((d) => wasm.addEntry(d, input))}
        onImportOtpauth={(uri) => {
          const e = wasm.parseOtpauthUri(uri);
          withVault((d) =>
            wasm.addEntry(d, {
              label: e.label,
              issuer: e.issuer,
              secretBytes: wasm.base64ToBytes(e.secret),
              algorithm: e.algorithm,
              digits: e.digits,
              period: e.period,
            }),
          );
        }}
        onImportMigration={(uri) => importMigration(wasm, uri, withVault)}
        onRemove={(label) =>
          withVault((d) => {
            d.entries = d.entries.filter((e) => e.label !== label);
          })
        }
        onLock={lock}
      />
    );
  }

  return (
    <>
      <p data-testid="live-region" role="status" aria-live="polite" className="sr-only">
        {announce}
      </p>
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
): { imported: number; skipped: number } {
  const entries: TotpEntry[] = wasm.decodeMigrationUri(uri);
  let imported = 0;
  let skipped = 0;
  withVault((draft) => {
    for (const e of entries) {
      try {
        wasm.addEntry(draft, {
          label: e.label,
          issuer: e.issuer,
          secretBytes: wasm.base64ToBytes(e.secret),
          algorithm: e.algorithm,
          digits: e.digits,
          period: e.period,
        });
        imported += 1;
      } catch {
        skipped += 1; // duplicate label or unsupported params
      }
    }
  });
  return { imported, skipped };
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
  onUnlock,
  onForget,
}: {
  onUnlock: (password: string) => void;
  onForget: () => void;
}) {
  const [pw, setPw] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function submit(ev: React.FormEvent) {
    ev.preventDefault();
    setError("");
    setBusy(true);
    setTimeout(() => {
      try {
        onUnlock(pw);
      } catch (e) {
        setError(msg(e));
        setBusy(false);
      }
    }, 0);
  }

  return (
    <Card>
      <h2 className="mb-1 text-lg font-semibold">Unlock your vault</h2>
      <p className="mb-4 text-sm text-neutral-600 dark:text-neutral-400">
        A sealed vault is stored in this browser. Enter its password to decrypt it
        in memory.
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
        {error && (
          <p data-testid="unlock-error" className="text-sm text-red-600 dark:text-red-400">
            wrong password or tampered vault — {error}
          </p>
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
  }) => Promise<{ vaultId: string; accounts: number; accountId: string; notes: string[] }>;
}) {
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState("http://127.0.0.1:8080");
  const [deviceId, setDeviceId] = useState("");
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
          await onRestore({ baseUrl: url, code, deviceId, password: pw });
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
  onDeviceChange,
  onUpdateDevice,
  onRekey,
  onAdoptSharedVault,
  onAdd,
  onImportOtpauth,
  onImportMigration,
  onRemove,
  onLock,
}: {
  wasm: Wasm;
  vault: TotpVault;
  now: number;
  device: DeviceIdentity | null;
  activeVaultId: string | null;
  onDeviceChange: (d: DeviceIdentity | null) => void;
  onUpdateDevice: (patch: Partial<DeviceIdentity>) => DeviceIdentity;
  onRekey: (vaultId: string, vaultKey: Uint8Array) => void;
  onAdoptSharedVault: (vaultId: string, vaultKey: Uint8Array, container: Uint8Array) => TotpVault;
  onAdd: (input: AddInput) => void;
  onImportOtpauth: (uri: string) => void;
  onImportMigration: (uri: string) => { imported: number; skipped: number };
  onRemove: (label: string) => void;
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
            <AccountRow
              key={entry.label}
              wasm={wasm}
              entry={entry}
              now={now}
              onRemove={() => onRemove(entry.label)}
            />
          ))}
        </ul>
      )}

      <AddAccountPanel onAdd={onAdd} onImportOtpauth={onImportOtpauth} onImportMigration={onImportMigration} />
      <ExportPanel wasm={wasm} vault={vault} />
      <SyncPanel
        wasm={wasm}
        device={device}
        onDeviceChange={onDeviceChange}
        url={serverUrl}
        setUrl={setServerUrl}
        vaultId={vaultId}
        setVaultId={setVaultId}
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

  return (
    <li
      data-testid="account-row"
      className="flex items-center gap-3 rounded-lg border border-neutral-300 p-3 sm:gap-4 sm:p-4 dark:border-neutral-700"
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
      <button
        data-testid="account-remove"
        aria-label={`Remove ${who}`}
        className={btnGhost}
        type="button"
        onClick={onRemove}
      >
        Remove
      </button>
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
  onAdd,
  onImportOtpauth,
  onImportMigration,
}: {
  onAdd: (input: AddInput) => void;
  onImportOtpauth: (uri: string) => void;
  onImportMigration: (uri: string) => { imported: number; skipped: number };
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
      const { imported, skipped } = onImportMigration(migration.trim());
      setImportResult(`Imported ${imported} account${imported === 1 ? "" : "s"}${
        skipped ? `, skipped ${skipped} (duplicate or unsupported)` : ""
      }.`);
      setMigration("");
    } catch (e) {
      setMigrationError(msg(e));
    }
  }

  return (
    <Card>
      <h3 className="mb-4 text-base font-semibold">Add an account</h3>

      <form onSubmit={submitForm} className="space-y-3">
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
            <input
              data-testid="add-period"
              className={inputCls}
              type="number"
              min={1}
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
          <p className="mt-2 text-xs text-neutral-600 dark:text-neutral-400">
            An account is reachable only through a member device&rsquo;s private key,
            so losing every device is unrecoverable <em>unless a recovery kit was
            printed in advance</em> (<code>sigil recovery generate</code>) — one
            cannot be created after the fact, and this app cannot print one.
            Membership is flat — any member may invite, and may revoke any other
            member.
          </p>
        </>
      )}
    </div>
  );
}

function SyncPanel({
  wasm,
  device,
  onDeviceChange,
  url,
  setUrl,
  vaultId,
  setVaultId,
}: {
  wasm: Wasm;
  device: DeviceIdentity | null;
  onDeviceChange: (d: DeviceIdentity | null) => void;
  url: string;
  setUrl: (v: string) => void;
  vaultId: string;
  setVaultId: (v: string) => void;
}) {
  const [token, setToken] = useState("");
  const [label, setLabel] = useState("this browser");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  // ⭐ A 402 is a BILLING state, not an auth failure and not a bug. It gets its
  // own non-error region so it can never be rendered as "unauthorized".
  const [payment, setPayment] = useState<{ headline: string; detail: string } | null>(null);

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
    setBusy(true);
    setStatus("Pushing…");
    setPayment(null);
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (!stored) throw new Error("no sealed vault to push");
      const container = wasm.base64ToBytes(stored);
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
            : ""),
      );
    } catch (e) {
      if (!handledAsPayment(e, "Push")) setStatus(`Push failed: ${authMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  async function pull() {
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
      const latest = ops[ops.length - 1];
      // Store the sealed bytes; unlock again to decrypt with your password.
      window.localStorage.setItem(STORAGE_KEY, wasm.bytesToBase64(latest.container));
      setStatus(
        `Pulled op #${latest.seq}. Sealed vault saved locally — Lock and Unlock to decrypt it.`,
      );
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

      <div className="mt-3 flex gap-3">
        <button data-testid="sync-push" className={btnGhost} type="button" onClick={push} disabled={busy}>
          Push
        </button>
        <button data-testid="sync-pull" className={btnGhost} type="button" onClick={pull} disabled={busy}>
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
      } else {
        setStatus(`${what} failed: ${shareMsg(e)}`);
      }
    } finally {
      setBusy(false);
    }
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
      // shareVault fetches the recipient's key through the PIN CHOKE POINT: an
      // unchanged key proceeds, a CHANGED key throws KeyPinMismatchError and
      // nothing is wrapped or uploaded.
      const res = await wasm.shareVault(wasm, auth, {
        vaultId: id,
        recipientDeviceId: to,
        vaultKey: key,
        permission,
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
      const res = await wasm.rotateVaultKey(wasm, auth, {
        vaultId: id,
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
  function accept() {
    void run("Accepting the shared vault", async () => {
      if (!id) throw new Error("set the shared vault's id first (Sync → Vault id)");
      const accepted = await wasm.acceptVault(wasm, auth, { vaultId: id });
      // Seal the recovered key immediately, so a failed pull cannot lose it.
      onUpdateDevice({ vaultKeys: { ...(device!.vaultKeys ?? {}), [id]: accepted.vaultKey } });
      setFingerprint(accepted.fingerprint);

      const ops = await wasm.pullContainersAuthed(wasm, device!, url.trim(), id, 0);
      if (ops.length === 0) {
        setStatus(
          `Accepted the vault key for "${id}" (sha256 ${accepted.fingerprint}) and sealed it locally, ` +
            "but the server holds no vault yet — ask the owner to push.",
        );
        return;
      }
      const v = onAdoptSharedVault(id, accepted.vaultKey, ops[ops.length - 1].container);
      setStatus(
        `Accepted and opened the shared vault "${id}" — ${v.entries.length} account(s). ` +
          `Key sha256 ${accepted.fingerprint}: compare it with the sender out of band.`,
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
          Their safety number (optional — required for a recovery kit)
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
  verification: { accountId: string; indexedVaults: number; unwrappedVault: string; fingerprint: string };
}

function RecoveryPanel({
  wasm,
  device,
  url,
  vaultId,
  onUpdateDevice,
}: {
  wasm: Wasm;
  device: DeviceIdentity | null;
  url: string;
  vaultId: string;
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
      } else {
        const f = explainRecoveryFailure(wasm, e);
        setStatus(`${what} failed: ${f.headline} ${f.detail}`);
      }
    } finally {
      setBusy(false);
    }
  }

  // GENERATE. Mints an invite pinned to the kit's own public key, enrolls the kit
  // under the visible `recovery-kit` label, publishes its hybrid key, PINS the
  // key it DERIVED (so nothing was fetched and nothing could be substituted),
  // covers every vault key this browser holds, and then VERIFIES the whole thing
  // end to end before returning — revoking the partial kit if any step fails.
  function generate() {
    void run("Generating a recovery kit", async () => {
      const pins = device!.pins ?? wasm.newPinStore();
      const res = await wasm.generateRecoveryKit(wasm, auth, { vaultKeys, pins });
      onUpdateDevice({ pins: res.pins }); // the DERIVED pin, re-sealed
      setWritten(false);
      setKit(res);
      setStatus(
        `Kit ${res.deviceId} created in account ${res.accountId} and verified end to end ` +
          `(it re-derived its own identity from the printed code, authenticated, and unwrapped ` +
          `${res.verification.unwrappedVault || "no vault"}). Covers ${res.covered.length} vault(s).`,
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
      const res = await wasm.coverVault(wasm, auth, {
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
          <p className="mt-2 text-xs">
            <span className="font-medium">Vaults covered as of today: </span>
            <span data-testid="recovery-covered" className="font-mono">
              {kit.covered.length ? kit.covered.map((c) => c.vaultId).join(", ") : "NONE"}
            </span>
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
