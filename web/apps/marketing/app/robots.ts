import type { MetadataRoute } from "next";

// Pre-launch: disallow everything. We ship nothing public until the audit
// completes and trademark clears (brief, GTM Phase 1).
export default function robots(): MetadataRoute.Robots {
  return {
    rules: [{ userAgent: "*", disallow: "/" }],
  };
}
