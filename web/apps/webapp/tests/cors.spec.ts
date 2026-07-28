import { expect, test, type Page } from "@playwright/test";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

/**
 * ⭐ THE REAL THING. Every other spec in this directory drives the UI against a
 * FAKE server. This one builds and boots the REAL `sigild`, in a REAL Chromium,
 * on a REAL cross-origin port, and enrols the browser as a device over the real
 * contract-v3 signed path.
 *
 * WHY IT EXISTS: sigild routed no OPTIONS and emitted no Access-Control-* header,
 * so every signed request from a browser page — which is preflighted, because
 * X-Sigil-Device/-Timestamp/-Nonce/-Signature are not simple headers — was
 * blocked before it left the browser:
 *
 *   Access to fetch at 'http://127.0.0.1:PORT/v1/devices/enroll' from origin
 *   'http://127.0.0.1:3210' has been blocked by CORS policy: Response to
 *   preflight request doesn't pass access control check: No
 *   Access-Control-Allow-Origin header is present on the requested resource.
 *
 * Enrolment, sync, sharing, restore-from-kit and the entitlement read were ALL
 * dead from the webapp, and the fake server's permissive CORS concealed it. The
 * MV3 extension was unaffected (a host permission exempts it), which is why its
 * suite stayed honest.
 *
 * The spec asserts BOTH directions, so it cannot pass vacuously:
 *   1. against a sigild WITH `SIGILD_CORS_ORIGINS` set, the browser enrols;
 *   2. against a sigild WITHOUT it, the browser is blocked — the exact
 *      pre-fix behaviour, reproduced on demand.
 *
 * It needs the Go toolchain. Without it the spec SKIPS rather than failing: this
 * app's CI job carries Rust + wasm-pack, not Go.
 */

const T = 90_000;
const WEBAPP_ORIGIN = "http://127.0.0.1:3210";
const ENROLL_TOKEN = "cors-proof-token-0123456789abcdef";
// Resolve Go the way the rest of the repo does: $GO, then PATH, then the macOS
// Homebrew path LAST. An earlier version tried only `process.env.GO ?? the
// Homebrew path`, so on a CI runner — where setup-go puts `go` on PATH but sets
// no GO variable — this file `test.skip`ped ITSELF and the job stayed green while
// proving nothing. That is exactly the regression this spec exists to catch, so
// the resolution order matters as much as the assertions do.
// (interop.yml sets `GO: go` explicitly; desktop/core/tests/server_interop.rs
// resolves the same way and PANICS rather than skipping.)
const GO = process.env.GO ?? (whichGo() ?? "/opt/homebrew/bin/go");

function whichGo(): string | null {
  for (const candidate of ["go", "/usr/local/go/bin/go", "/opt/homebrew/bin/go"]) {
    try {
      execFileSync(candidate, ["version"], { stdio: "ignore" });
      return candidate;
    } catch {
      /* try the next one */
    }
  }
  return null;
}
const SIGILD_DIR = path.resolve(__dirname, "../../../../sigild");

function haveGo(): boolean {
  try {
    execFileSync(GO, ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

type Server = { baseUrl: string; stop: () => void };

async function startSigild(binary: string, corsOrigins: string | null): Promise<Server> {
  const port = await freePort();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    SIGILD_ADDR: `127.0.0.1:${port}`,
    SIGILD_ENABLE_DEV_OPS: "1",
    SIGILD_DEVICE_AUTH: "1",
    SIGILD_ENROLL_TOKENS: ENROLL_TOKEN,
  };
  // ⭐ The ONE variable under test. Unset => the pre-fix behaviour, byte for byte.
  if (corsOrigins) env.SIGILD_CORS_ORIGINS = corsOrigins;
  else delete env.SIGILD_CORS_ORIGINS;

  const proc: ChildProcess = spawn(binary, [], { env, stdio: ["ignore", "pipe", "pipe"] });
  proc.stdout?.resume();
  proc.stderr?.resume();

  const baseUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    if (proc.exitCode !== null) throw new Error(`sigild exited early with ${proc.exitCode}`);
    try {
      const res = await fetch(`${baseUrl}/healthz`);
      if (res.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error("sigild did not become healthy");
    await new Promise((r) => setTimeout(r, 150));
  }
  return { baseUrl, stop: () => proc.kill("SIGKILL") };
}

let buildDir = "";
let binary = "";
let withCors: Server | null = null;
let withoutCors: Server | null = null;

const skip = !haveGo();

// Skips the WHOLE file when Go is absent, so this can never fail a Rust-only CI
// job — and can never be mistaken for having run when it did not.
test.skip(skip, `the Go toolchain (${GO}) is unavailable — set GO=/path/to/go to run this`);

// One worker, one Go build, one pair of servers: these two tests share them.
test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  if (skip) return;
  buildDir = mkdtempSync(path.join(tmpdir(), "sigil-cors-"));
  binary = path.join(buildDir, "sigild");
  execFileSync(GO, ["build", "-o", binary, "./cmd/server"], { cwd: SIGILD_DIR, stdio: "inherit" });
  withCors = await startSigild(binary, WEBAPP_ORIGIN);
  withoutCors = await startSigild(binary, null);
});

test.afterAll(() => {
  withCors?.stop();
  withoutCors?.stop();
  if (buildDir) rmSync(buildDir, { recursive: true, force: true });
});

async function setupVault(page: Page, password: string) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-confirm").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

test("the REAL webapp enrols against a REAL sigild whose origin allowlist includes it", async ({
  page,
}: {
  page: Page;
}) => {
  const server = withCors!;

  const consoleErrors: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });

  await setupVault(page, "cors-proof-password");
  await page.getByTestId("sync-url").fill(server.baseUrl);
  await page.getByTestId("sync-vault-id").fill("cors-proof-vault");
  await page.getByTestId("device-token").fill(ENROLL_TOKEN);
  await page.getByTestId("device-enroll").click();

  // ⭐ THE ASSERTION: a signed, preflighted, cross-origin POST reached a real
  // sigild, which verified a real proof-of-possession and enrolled a real device.
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as device dev_", {
    timeout: T,
  });

  // And the rest of the surface works too — a push is a second preflighted,
  // signed, cross-origin request, this time with a body.
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });
  await page.getByTestId("sync-pull").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pulled", { timeout: T });

  expect(consoleErrors.filter((l) => /blocked by CORS/i.test(l))).toEqual([]);
});

test("the SAME sigild WITHOUT the allowlist blocks the browser — the pre-fix defect, on demand", async ({
  page,
}: {
  page: Page;
}) => {
  const server = withoutCors!;

  await setupVault(page, "cors-negative-password");
  await page.getByTestId("sync-url").fill(server.baseUrl);
  await page.getByTestId("sync-vault-id").fill("cors-negative-vault");
  await page.getByTestId("device-token").fill(ENROLL_TOKEN);
  await page.getByTestId("device-enroll").click();

  // The browser refuses to send it, so the UI reports a failure and NO device is
  // enrolled. This is what a user actually saw before SIGILD_CORS_ORIGINS existed.
  await expect(page.getByTestId("sync-status")).toContainText("Enrollment failed", {
    timeout: T,
  });

  // Directly, so the reason is unambiguous rather than inferred from the UI: a
  // preflighted request to the un-allowlisted server rejects, while the very same
  // request to the allowlisted one resolves.
  const blocked = await page.evaluate(async (base: string) => {
    try {
      await fetch(`${base}/v1/devices/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Sigil-Nonce": "probe" },
        body: "{}",
      });
      return "not blocked";
    } catch (e) {
      return `blocked: ${(e as Error).name}`;
    }
  }, server.baseUrl);
  expect(blocked).toContain("blocked");

  const allowed = await page.evaluate(async (base: string) => {
    try {
      const res = await fetch(`${base}/v1/devices/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Sigil-Nonce": "probe" },
        body: "{}",
      });
      return `reached: ${res.status}`;
    } catch (e) {
      return `blocked: ${(e as Error).name}`;
    }
  }, withCors!.baseUrl);
  expect(allowed).toContain("reached");
});
