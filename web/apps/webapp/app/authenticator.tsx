"use client";

import { useEffect, useRef, useState } from "react";
import type { TotpEntry, TotpVault } from "@sigil/wasm";

// The full @sigil/wasm module surface (wasm bindings + the proven JS helpers).
// Imported dynamically in the browser only (inside an effect) so the wasm never
// instantiates during SSR — matching totp-demo.tsx.
type Wasm = typeof import("@sigil/wasm");

// localStorage key holding ONLY the sealed SIGILcli container (base64). The
// plaintext vault and the password are NEVER persisted — they live in memory
// while unlocked and vanish on Lock / reload.
const STORAGE_KEY = "sigil.webapp.vault.v1";

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

  // The password lives ONLY in memory while unlocked (never persisted).
  const passwordRef = useRef<string>("");

  const now = useUnixClock();

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

  // Seal `v` with `password` (fresh salt + nonce from the CSPRNG) and write the
  // sealed container (base64) to localStorage. Only the sealed bytes are stored.
  function persist(m: Wasm, v: TotpVault, password: string): void {
    const salt = crypto.getRandomValues(new Uint8Array(m.recommended_salt_len()));
    const nonce = crypto.getRandomValues(new Uint8Array(m.nonce_len()));
    const container = m.sealVault(m, password, v, salt, nonce, ARGON2);
    window.localStorage.setItem(STORAGE_KEY, m.bytesToBase64(container));
  }

  // Apply a mutation to a fresh clone of the vault, re-seal + persist, and swap
  // in the new state. The mutator may throw (e.g. a duplicate label) BEFORE any
  // persist happens, so a rejected change never corrupts the stored vault.
  function withVault(fn: (draft: TotpVault) => void): TotpVault {
    if (!wasm || !vault) throw new Error("vault is locked");
    const draft: TotpVault = { version: vault.version, entries: [...vault.entries] };
    fn(draft);
    persist(wasm, draft, passwordRef.current);
    setVault(draft);
    return draft;
  }

  function createVault(password: string): void {
    if (!wasm) throw new Error("wasm not ready");
    const v = wasm.newVault();
    persist(wasm, v, password);
    passwordRef.current = password;
    setVault(v);
    setPhase("unlocked");
  }

  function unlock(password: string): void {
    if (!wasm) throw new Error("wasm not ready");
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (!stored) throw new Error("no sealed vault found");
    const container = wasm.base64ToBytes(stored);
    const v = wasm.openVault(wasm, password, container); // throws on wrong password
    passwordRef.current = password;
    setVault(v);
    setPhase("unlocked");
  }

  function lock(): void {
    passwordRef.current = "";
    setVault(null);
    setPhase("locked");
  }

  function forget(): void {
    window.localStorage.removeItem(STORAGE_KEY);
    passwordRef.current = "";
    setVault(null);
    setPhase("setup");
  }

  if (phase === "loading") {
    return (
      <Card>
        <p data-testid="auth-status" className="text-sm text-neutral-500 dark:text-neutral-400">
          Loading WebAssembly crypto core…
        </p>
      </Card>
    );
  }

  if (phase === "error") {
    return (
      <Card>
        <p data-testid="auth-status" className="text-sm text-red-600 dark:text-red-400">
          Failed to load the wasm core: {wasmError}
        </p>
      </Card>
    );
  }

  if (phase === "setup") {
    return <SetupPanel onCreate={createVault} />;
  }

  if (phase === "locked") {
    return <UnlockPanel onUnlock={unlock} onForget={forget} />;
  }

  // unlocked
  if (!wasm || !vault) return null;
  return (
    <VaultView
      wasm={wasm}
      vault={vault}
      now={now}
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

const inputCls =
  "w-full rounded border border-neutral-300 bg-transparent px-3 py-2 text-sm dark:border-neutral-700";
const btnCls =
  "rounded bg-neutral-900 px-4 py-2 text-sm font-medium text-white hover:bg-neutral-700 disabled:opacity-50 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-neutral-300";
const btnGhost =
  "rounded border border-neutral-300 px-3 py-2 text-sm font-medium hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800";

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
      <p className="mb-4 text-sm text-neutral-500 dark:text-neutral-400">
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
      <p className="mb-4 text-sm text-neutral-500 dark:text-neutral-400">
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
  onAdd,
  onImportOtpauth,
  onImportMigration,
  onRemove,
  onLock,
}: {
  wasm: Wasm;
  vault: TotpVault;
  now: number;
  onAdd: (input: AddInput) => void;
  onImportOtpauth: (uri: string) => void;
  onImportMigration: (uri: string) => { imported: number; skipped: number };
  onRemove: (label: string) => void;
  onLock: () => void;
}) {
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
          <p data-testid="empty-state" className="text-sm text-neutral-500 dark:text-neutral-400">
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
      <SyncPanel wasm={wasm} />
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

  return (
    <li
      data-testid="account-row"
      className="flex items-center gap-4 rounded-lg border border-neutral-300 p-4 dark:border-neutral-700"
    >
      <CountdownRing remaining={remaining} period={entry.period} />
      <div className="min-w-0 flex-1">
        <div data-testid="account-label" className="truncate text-sm font-medium">
          {entry.issuer ? (
            <>
              <span className="text-neutral-500 dark:text-neutral-400">{entry.issuer}</span>
              <span className="mx-1 text-neutral-400">·</span>
            </>
          ) : null}
          {entry.label}
        </div>
        <div className="text-xs text-neutral-400">
          {entry.algorithm.toUpperCase()} · {entry.digits} digits · {entry.period}s
        </div>
      </div>
      <div
        data-testid="account-code"
        className="font-mono text-2xl tabular-nums tracking-widest"
      >
        {error ? "err" : code}
      </div>
      <button
        data-testid="account-remove"
        aria-label={`Remove ${entry.label}`}
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
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
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
        className="absolute inset-0 flex items-center justify-center text-[10px] tabular-nums text-neutral-500 dark:text-neutral-400"
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

function SyncPanel({ wasm }: { wasm: Wasm }) {
  const [url, setUrl] = useState("http://127.0.0.1:8080");
  const [vaultId, setVaultId] = useState("webapp-demo");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);

  async function push() {
    setBusy(true);
    setStatus("Pushing…");
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (!stored) throw new Error("no sealed vault to push");
      const container = wasm.base64ToBytes(stored);
      const { seq } = await wasm.pushContainer(url.trim(), vaultId.trim(), container);
      setStatus(`Pushed sealed container as op #${seq}.`);
    } catch (e) {
      setStatus(`Push failed: ${msg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  async function pull() {
    setBusy(true);
    setStatus("Pulling…");
    try {
      const ops = await wasm.pullContainers(url.trim(), vaultId.trim());
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
      setStatus(`Pull failed: ${msg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <h3 className="mb-1 text-base font-semibold">Sync (dev)</h3>
      <p className="mb-3 text-xs text-neutral-500 dark:text-neutral-400">
        Round-trips the <strong>sealed</strong> container through a dev sigild
        op-log over plain HTTP (localhost only, no TLS, no auth). Requires a local
        sigild with <code>SIGILD_ENABLE_DEV_OPS</code> on. The server only ever
        sees opaque bytes.
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
      <div className="mt-3 flex gap-3">
        <button data-testid="sync-push" className={btnGhost} type="button" onClick={push} disabled={busy}>
          Push
        </button>
        <button data-testid="sync-pull" className={btnGhost} type="button" onClick={pull} disabled={busy}>
          Pull
        </button>
      </div>
      {status && (
        <p data-testid="sync-status" className="mt-3 text-sm text-neutral-600 dark:text-neutral-300">
          {status}
        </p>
      )}
    </Card>
  );
}
