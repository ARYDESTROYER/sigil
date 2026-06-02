"use client";

import { useState } from "react";

type Status = "idle" | "submitting" | "ok" | "error";

export function WaitlistForm() {
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setStatus("submitting");
    setMessage("");

    const form = e.currentTarget;
    const data = new FormData(form);
    const payload = {
      email: String(data.get("email") ?? ""),
      consent: data.get("consent") === "on",
      // Honeypot — bots fill it, humans don't (hidden field).
      website: String(data.get("website") ?? ""),
    };

    try {
      const res = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        setStatus("ok");
        setMessage("Thanks — you're on the list.");
        form.reset();
      } else {
        const body = (await res.json().catch(() => ({}))) as {
          error?: string;
        };
        setStatus("error");
        setMessage(
          body.error === "consent_required"
            ? "Please tick the consent box."
            : "That didn't look like a valid email.",
        );
      }
    } catch {
      setStatus("error");
      setMessage("Network error — please try again.");
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-3" noValidate>
      <input
        type="email"
        name="email"
        required
        autoComplete="email"
        placeholder="you@example.com"
        className="w-full rounded-lg border border-neutral-300 bg-transparent px-4 py-3 outline-none focus:border-neutral-900 dark:border-neutral-700 dark:focus:border-white"
      />

      {/* Honeypot: visually hidden, off-screen, ignored by humans. */}
      <input
        type="text"
        name="website"
        tabIndex={-1}
        autoComplete="off"
        aria-hidden="true"
        className="absolute left-[-9999px] h-0 w-0"
      />

      <label className="flex items-start gap-2 text-sm text-neutral-600 dark:text-neutral-300">
        <input type="checkbox" name="consent" className="mt-1" />
        <span>
          I agree to be contacted about the Sigil beta and have read the{" "}
          <a href="/privacy" className="underline">
            Privacy Policy
          </a>
          .
        </span>
      </label>

      <button
        type="submit"
        disabled={status === "submitting"}
        className="w-full rounded-lg bg-neutral-900 px-4 py-3 font-medium text-white transition hover:opacity-90 disabled:opacity-50 dark:bg-white dark:text-neutral-900"
      >
        {status === "submitting" ? "Submitting…" : "Request early access"}
      </button>

      {message && (
        <p
          role="status"
          className={
            status === "ok"
              ? "text-sm text-green-600"
              : "text-sm text-red-600"
          }
        >
          {message}
        </p>
      )}
    </form>
  );
}
