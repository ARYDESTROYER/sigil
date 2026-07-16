import type { MetadataRoute } from "next";

// Pre-launch: disallow everything. This is an internal DEV demo; nothing here is
// public until the audit completes and trademark clears.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", disallow: "/" }],
  };
}
