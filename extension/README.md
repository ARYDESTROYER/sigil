# extension

Reserved. The browser extension (Chrome/Firefox/Safari/Edge/Brave) where
phishing protection and the passkey-provider integration will live. MV3,
TypeScript, `libsigil` via wasm in a worker. **Deferred** — depends on
`libsigil-wasm`, not yet available.

Planned layout: `src/{background,content,popup,options}/` + `manifest-v3.json`.
