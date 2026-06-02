import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Pre-launch stealth gate. When SITE_PASSWORD is set, the entire site sits
// behind HTTP Basic Auth so the URL is reviewable but neither publicly
// browsable nor indexable before the audit. When SITE_PASSWORD is unset
// (local dev / CI), the gate is a no-op.
export function middleware(req: NextRequest) {
  const password = process.env.SITE_PASSWORD;
  if (!password) return NextResponse.next();

  const header = req.headers.get("authorization");
  if (header) {
    const [scheme, encoded] = header.split(" ");
    if (scheme === "Basic" && encoded) {
      const decoded = atob(encoded);
      const provided = decoded.slice(decoded.indexOf(":") + 1);
      if (provided === password) return NextResponse.next();
    }
  }

  return new NextResponse("Authentication required.", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="sigil-prelaunch"' },
  });
}

export const config = {
  // Gate everything except Next internals and the security.txt discovery file.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.well-known).*)"],
};
