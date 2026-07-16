"use client";

import { useEffect, useMemo, useRef, useState } from "react";

// The RFC 6238 SHA-1 test-vector seed ("12345678901234567890") in base32. It is a
// well-known PUBLIC test value, not a real secret — safe to ship as the default.
const DEFAULT_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PERIOD = 30;
const DIGITS = 6;
const ALGORITHM = "sha1";

// The typed surface of @sigil/wasm we actually touch here. We only import the
// module in the browser (inside an effect, via dynamic import) so the wasm never
// evaluates during SSR.
type SigilWasmModule = typeof import("@sigil/wasm");

/**
 * Live TOTP demo. This is the crux of the phase: it proves the REAL libsigil
 * wasm runs in the browser. The 6-digit code and the second-by-second countdown
 * are computed by `sigil-core` compiled to WebAssembly (via the proven
 * `codeForEntry` / `base32Decode` helpers), never by JS TOTP.
 *
 * Test hooks (query params): `?secret=<base32>` overrides the seed and `?t=<unix>`
 * pins the clock to a fixed second so a headless run is deterministic.
 */
export default function TotpDemo() {
  const [mod, setMod] = useState<SigilWasmModule | null>(null);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [loadError, setLoadError] = useState<string>("");

  const [secret, setSecret] = useState<string>(DEFAULT_SECRET);
  const [code, setCode] = useState<string>("------");
  const [remaining, setRemaining] = useState<number>(PERIOD);
  const [computeError, setComputeError] = useState<string>("");

  // A fixed clock override for deterministic tests (?t=<unix>), else null = live.
  const timeOverride = useRef<number | null>(null);

  // Load the wasm in the browser only.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const s = params.get("secret");
        if (s) setSecret(s);
        const t = params.get("t");
        if (t !== null && Number.isFinite(Number(t))) {
          timeOverride.current = Math.floor(Number(t));
        }
        const m: SigilWasmModule = await import("@sigil/wasm");
        await m.initWasm();
        if (cancelled) return;
        setMod(m);
        setStatus("ready");
      } catch (e) {
        if (cancelled) return;
        setLoadError(e instanceof Error ? e.message : String(e));
        setStatus("error");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // A stable TotpEntry for the current secret (base32 -> raw bytes -> base64,
  // exactly the vault schema the CLI uses). Recomputed only when the secret text
  // or the loaded module changes.
  const entry = useMemo(() => {
    if (!mod) return null;
    try {
      const raw = mod.base32Decode(secret);
      return {
        label: "demo",
        secret: mod.bytesToBase64(raw),
        algorithm: ALGORITHM,
        digits: DIGITS,
        period: PERIOD,
      };
    } catch {
      return null;
    }
  }, [mod, secret]);

  // Recompute the code + countdown ~4x/sec from the wasm.
  useEffect(() => {
    if (!mod || status !== "ready") return;

    const compute = () => {
      const now =
        timeOverride.current !== null
          ? timeOverride.current
          : Math.floor(Date.now() / 1000);
      if (!entry) {
        setComputeError("secret is not valid base32");
        setCode("------");
        return;
      }
      try {
        setCode(mod.codeForEntry(mod, entry, now));
        setRemaining(PERIOD - (now % PERIOD));
        setComputeError("");
      } catch (e) {
        setComputeError(e instanceof Error ? e.message : String(e));
        setCode("------");
      }
    };

    compute();
    if (timeOverride.current !== null) return; // pinned clock: no ticking
    const id = window.setInterval(compute, 250);
    return () => window.clearInterval(id);
  }, [mod, status, entry]);

  return (
    <section className="rounded-lg border border-neutral-300 p-6 dark:border-neutral-700">
      <h2 className="mb-1 text-lg font-semibold">Live TOTP (computed in WebAssembly)</h2>
      <p className="mb-4 text-sm text-neutral-600 dark:text-neutral-400">
        The code below is produced by the real <code>sigil-core</code> RFC 6238
        engine compiled to wasm — not by JavaScript. Default seed is the public
        RFC test vector.
      </p>

      <label className="mb-4 block text-sm">
        <span className="mb-1 block font-medium">Base32 secret</span>
        <input
          data-testid="secret-input"
          className="w-full rounded border border-neutral-300 bg-transparent px-3 py-2 font-mono text-sm dark:border-neutral-700"
          value={secret}
          onChange={(e) => setSecret(e.target.value.trim())}
          spellCheck={false}
          autoComplete="off"
        />
      </label>

      <div className="flex items-end gap-6">
        <div
          data-testid="totp-code"
          className="font-mono text-5xl tabular-nums tracking-widest"
        >
          {code}
        </div>
        <div className="pb-2 text-sm text-neutral-600 dark:text-neutral-400">
          <span data-testid="totp-remaining">{remaining}</span>s until refresh
        </div>
      </div>

      <p className="mt-4 text-xs text-neutral-600 dark:text-neutral-400">
        wasm status:{" "}
        <span data-testid="wasm-status" className="font-mono">
          {status}
        </span>
        {status === "error" ? ` — ${loadError}` : ""}
        {computeError ? ` — ${computeError}` : ""}
      </p>
    </section>
  );
}
