# Marketing claims guardrail

This product is **pre-audit and pre-launch**. Every public-facing string must be
true *today*, not aspirationally. This file is the allow/deny list for copy on
the marketing surface. CI and reviewers should reject PRs that violate it.

## ❌ Forbidden until the underlying thing is actually true

- "audited", "security-audited", "Cure53-audited" — until the audit completes
  and the report is published. (Currently: engagement only being scoped.)
- "SOC 2", "SOC 2 compliant", "ISO 27001", "HIPAA" — until certified/attested.
- "post-quantum secure", "quantum-proof", "unbreakable" — never; nothing is.
- Unqualified "end-to-end encrypted" as a present-tense product claim — until
  libsigil exists, is correct, and ships. (No shipping client exists yet.)
- "available now", "download today", pricing numbers, or launch dates — pricing
  and launch are out of scope for the stealth splash.
- The committed brand "Sigil" / any domain (`sigilapp.io` is the provisional one
  named in `CLAUDE.md`; no domain is registered) as final — name is a working
  placeholder pending trademark clearance.
- "trusted by", customer logos, testimonials — none exist.

## ✅ Allowed (truthful, qualified, design-intent framed)

- "A paid, encrypted authenticator." (it is designed paid + encrypted)
- "In private development." / "Request early access."
- "Designed end-to-end encrypted." / "Designed so we can't read your codes."
  (design intent, present tense about the *design*, not a shipped guarantee)
- "Post-quantum-ready by design (unaudited)." — only with the "by design /
  unaudited" qualifier, and ideally only behind the password wall.
- "An independent security audit is planned." (true — Cure53 scoping underway)
- "Name and brand are provisional, pending trademark clearance."

## Rule of thumb

If a regulator, a journalist, or a skeptical Hacker News commenter could call a
claim false or misleading **on launch day**, it does not ship now. When in
doubt, frame as *design intent* + an explicit *unaudited / planned* qualifier,
or leave it off the public surface entirely.
