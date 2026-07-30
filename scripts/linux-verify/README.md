# Linux verification

**Why this exists.** Every suite in this repository is written and gated on **macOS
arm64**, and every job in `.github/workflows/` runs on **ubuntu-latest**. Nothing checked
that the two agreed, and on 2026-07-30 the bill arrived: the `interop` workflow had been
**red for several phases** — three of its four jobs — while `scripts/gate.sh` printed ALL
GREEN on the same commits.

Two idioms, both invisible on macOS:

* six node suites hardcoded `/opt/homebrew/bin/go`, which is `ENOENT` on a Linux runner;
* `stat -f '%Lp' p 2>/dev/null || stat -c '%a' p` reads as "try BSD, fall back to GNU" and
  is not — GNU `-f` means `--file-system` and **does not fail**, so the mode check received
  a filesystem dump concatenated with the real answer.

Both are fixed (`sigil-wasm/test/go-helper.mjs`, `cli/tests/_e2e-lib.sh`) and guarded
(`sigil-wasm/test/portability-guard.mjs`). This directory is how they were *verified*
rather than argued about.

## Run it

```bash
docker build -f scripts/linux-verify/Dockerfile -t sigil-linux:real scripts/linux-verify
docker run --rm \
  -v "$PWD:/src:ro" \
  -v "$PWD/scripts/linux-verify/run.sh:/run.sh:ro" \
  sigil-linux:real bash /run.sh
```

Result on the day it was written: **15 passed, 0 failed** — all three shell e2e proofs and
twelve node suites, on GNU coreutils with a freshly built Linux `sigil` binary.

⛔ **The repo is mounted READ-ONLY and copied inside on purpose.** A Linux `cargo build`
into `cli/target/debug` would clobber the macOS artifacts the local gate is using, and the
next gate run would then be testing a binary it could not execute.

## What this does NOT cover

Say these out loud rather than letting the green line imply more than it proves:

* **`build-wasm.sh` is not exercised.** `pkg-node/` is copied from the macOS build — wasm
  is platform-independent, so the suites run, but the *build* path is unverified on Linux.
* **No Playwright.** There is no browser in the image, so the webapp and extension suites
  are out of scope here; CI runs them.
* **arm64, not x86_64.** GitHub runners are x86_64. This exercises GNU-vs-BSD userland and
  Linux path/toolchain assumptions, not the instruction set.
* **It is a one-off, not a gate.** Nothing runs this automatically. The durable answer is
  the CI workflows themselves, now that they are green.
