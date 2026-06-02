import { NextResponse } from "next/server";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Consent text + version are recorded with each signup in production so the
// "have read the Privacy Policy" consent is auditable. Bump the version when
// the policy text materially changes.
const CONSENT_VERSION = "2026-06-02";

export async function POST(req: Request) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  const { email, consent, website } = (body ?? {}) as {
    email?: unknown;
    consent?: unknown;
    website?: unknown;
  };

  // Honeypot: real users never fill "website". Pretend success, store nothing.
  if (typeof website === "string" && website.length > 0) {
    return NextResponse.json({ ok: true }, { status: 200 });
  }

  if (typeof email !== "string" || email.length > 254 || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "invalid_email" }, { status: 400 });
  }
  if (consent !== true) {
    return NextResponse.json({ error: "consent_required" }, { status: 400 });
  }

  // PRE-AUDIT SKELETON — persistence is intentionally NOT wired here.
  // Production (Day 2 of the sprint) will:
  //   1. INSERT { email, created_at, consent_bool, consent_text, consent_version,
  //      source } into a BACKED-UP self-hosted Postgres (no managed processor
  //      until an entity + signed DPA exist), and
  //   2. send a Postmark double-opt-in magic link.
  // We deliberately store nothing yet so there is no un-backed-up PII and no
  // consent referencing an unpublished policy.
  void CONSENT_VERSION;

  return NextResponse.json(
    { ok: true, note: "skeleton: validated, not persisted" },
    { status: 202 },
  );
}
