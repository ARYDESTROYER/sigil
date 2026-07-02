import { describe, it, expect } from "vitest";
import robots from "./robots";

describe("robots policy", () => {
  it("disallows all crawling while pre-launch", () => {
    // The stealth posture: nothing is indexable until the audit completes and
    // trademark clears. A regression that opens crawling must fail this test.
    const result = robots();
    expect(result.rules).toEqual([{ userAgent: "*", disallow: "/" }]);
  });
});
