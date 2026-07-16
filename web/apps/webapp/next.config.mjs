/**
 * Pre-launch stealth config for the webapp (a DEV demo, not deployed).
 *
 * Two jobs:
 *  1. No-index at the HTTP layer, byte-for-byte the marketing posture
 *     (belt-and-suspenders with app/robots.ts + layout metadata robots flags).
 *  2. Enable WebAssembly so the bundler-target `@sigil/wasm` import resolves.
 *     `experiments.asyncWebAssembly` lets webpack instantiate the wasm module
 *     automatically when it is imported (the shape wasm-pack `--target bundler`
 *     emits). We only touch the client bundle's experiments.
 *
 * @type {import('next').NextConfig}
 */
const nextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Robots-Tag", value: "noindex, nofollow, noarchive" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
  webpack(config) {
    config.experiments = { ...config.experiments, asyncWebAssembly: true };
    return config;
  },
};

export default nextConfig;
