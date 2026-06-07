# 0002 — Standalone CLI crate for `getrandom` isolation

- **Status:** Accepted — 2026-06.

## Context

`libsigil/core` ([`../../libsigil/core/`](../../libsigil/core/)) is the
audit-bound cryptographic core. It is `#![forbid(unsafe_code)]`, `no_std`, and
must keep compiling to `wasm32-unknown-unknown` so the future web app and
browser extension can link it. On `wasm32-unknown-unknown` there is **no system
entropy backend**, so the core is deliberately **RNG-free**: it never generates
randomness — the caller supplies the salt and nonce. Pulling
[`getrandom`](https://docs.rs/getrandom) into the core's dependency tree would
break the wasm build and add a non-pure dependency to the code an auditor must
review.

The [`cli/`](../../cli/) demo binary (`sigil`), however, *does* need to generate
randomness (the Argon2 salt and the AEAD nonce), and for its dev `push`/`pull`
it needs an HTTP client and JSON/base64. Those are native-only concerns — the
CLI never compiles to wasm — but if the CLI were a member of the `libsigil`
workspace it would share `libsigil/Cargo.lock`, dragging `getrandom`, `ureq`,
`serde`, and friends into the lockfile the audit-bound core depends on.

## Decision

Keep `cli/` as a **standalone crate** with its **own
[`cli/Cargo.lock`](../../cli/Cargo.lock)**, **not** a member of the `libsigil`
workspace. `libsigil/Cargo.toml` workspace members stay exactly
`["core", "ffi"]`. The CLI path-depends on `../libsigil/core` but resolves its
own dependencies independently.

Because it is native-only, the CLI *may* depend on `getrandom` (salt/nonce) and
on `ureq` / `serde` / `serde_json` / `base64` (dev `push`/`pull`); all of these
land **only** in `cli/Cargo.lock`. (`ureq` is built with
`default-features = false` so it speaks plain HTTP and pulls in no TLS stack —
push/pull are localhost-dev only; see [ADR 0003](0003-dev-gated-opaque-op-log.md)
and [`../architecture.md`](../architecture.md) §4.)

The invariant is **mechanical and CI-checkable**:

```
grep -c 'name = "getrandom"' libsigil/Cargo.lock   # must be 0
```

and `libsigil/Cargo.lock` must be byte-for-byte unchanged by any CLI work. (As
of this writing: `0` in `libsigil/Cargo.lock`, `1` in `cli/Cargo.lock`.)

## Consequences

- The CLI's native dependencies (`getrandom`, `ureq`, `serde`, `base64`, …)
  **never touch the audit-bound core lockfile**. The auditor's dependency
  surface for `sigil-core` stays minimal and wasm-pure.
- The core stays RNG-free and wasm-buildable; the salt/nonce stay the caller's
  responsibility by construction.
- Two lockfiles to maintain, and the `cli/` build is a separate CI surface (see
  [`../../.github/workflows/cli.yml`](../../.github/workflows/cli.yml), no wasm
  job — native-only). The `getrandom`-count guard and an "unchanged lockfile"
  check are part of the green gate.
- This is a guardrail, not a security claim: the CLI is a **pre-audit demo**,
  not for real secrets. Full build/dependency-isolation rationale lives in
  [`../architecture.md`](../architecture.md) §4 and [`../../CLAUDE.md`](../../CLAUDE.md).
