import { describe, it, expect } from "vitest";
import { POST } from "./route";

// Build a POST Request for the waitlist route. `raw` lets a test send a
// malformed (non-JSON) body to exercise the parse-error branch.
function post(body: unknown, raw?: string): Request {
  return new Request("http://localhost/api/waitlist", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: raw ?? JSON.stringify(body),
  });
}

describe("POST /api/waitlist", () => {
  it("rejects a non-JSON body with 400 invalid_json", async () => {
    const res = await POST(post(undefined, "{ not json"));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_json" });
  });

  it("accepts the honeypot silently (200 ok) and stores nothing", async () => {
    const res = await POST(
      post({ email: "real@example.com", consent: true, website: "http://spam" }),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("honeypot short-circuits BEFORE email/consent validation", async () => {
    // An invalid email + missing consent still returns 200 because `website` is
    // non-empty — the honeypot branch runs first.
    const res = await POST(post({ email: "invalid", consent: false, website: "x" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("rejects a missing or malformed email with 400 invalid_email", async () => {
    const bad: unknown[] = [undefined, 123, null, "", "no-at", "a@b", "a b@c.co", "a@b."];
    for (const email of bad) {
      const res = await POST(post({ email, consent: true }));
      expect(res.status, `email=${JSON.stringify(email)}`).toBe(400);
      expect(await res.json()).toEqual({ error: "invalid_email" });
    }
  });

  it("rejects an over-long email (> 254 chars) with 400 invalid_email", async () => {
    const email = `${"x".repeat(250)}@example.com`; // 262 chars, valid format but too long
    expect(email.length).toBeGreaterThan(254);
    const res = await POST(post({ email, consent: true }));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_email" });
  });

  it("rejects a signup without consent === true with 400 consent_required", async () => {
    const bad: unknown[] = [undefined, false, "true", 1, null, 0];
    for (const consent of bad) {
      const res = await POST(post({ email: "user@example.com", consent }));
      expect(res.status, `consent=${JSON.stringify(consent)}`).toBe(400);
      expect(await res.json()).toEqual({ error: "consent_required" });
    }
  });

  it("accepts a valid signup with 202 and reports it was validated, not persisted", async () => {
    const res = await POST(post({ email: "user@example.com", consent: true }));
    expect(res.status).toBe(202);
    const body = (await res.json()) as { ok: boolean; note: string };
    expect(body.ok).toBe(true);
    // The skeleton must NOT claim persistence (no un-backed-up PII yet).
    expect(body.note).toMatch(/not persisted/);
  });

  it("accepts an empty object body as invalid_email (no email field)", async () => {
    const res = await POST(post({}));
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_email" });
  });
});
