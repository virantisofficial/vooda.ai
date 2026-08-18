// @ts-check
/**
 * Next.js 15 production config.
 *
 * `output: "standalone"` produces a self-contained `.next/standalone`
 * bundle that the Dockerfile ships as the runtime image — ~3 MB of
 * server code instead of the full ~800 MB node_modules tree.
 *
 * `rewrites()` proxies the SPA's same-origin `/api/*` calls to the
 * internal API service. The destination is read from
 * API_INTERNAL_URL (set at build time via Docker --build-arg in
 * docker-compose.yml). The fallback `localhost:8000` is for raw
 * `next dev` runs outside Docker; in any container build, the build-
 * arg override wins.
 *
 * Why .mjs and not .ts: next.config.ts requires the TypeScript
 * compiler to be available during config evaluation, which broke
 * inside a slim Alpine builder where TS wasn't installed at the
 * config-load step. .mjs is plain ESM JavaScript — no transpile
 * needed, runs identically in dev + build + prod.
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Standalone output → tiny runtime image. See Dockerfile.web for
  // how the .next/standalone tree gets staged into the runner image.
  output: "standalone",

  // The SPA calls same-origin /api/... ; Next.js then proxies those
  // requests to the internal API container. API_INTERNAL_URL is
  // baked in at build time so the route map points at the right
  // upstream. NEXT_PUBLIC_API_URL is the public-facing fallback —
  // empty string in compose means "use same-origin via the proxy".
  async rewrites() {
    const upstream =
      process.env.API_INTERNAL_URL ||
      process.env.NEXT_PUBLIC_API_URL ||
      "http://localhost:8000";
    // Order matters: more-specific paths must come first because
    // Next.js evaluates rewrites in order and stops at the first
    // match. Earlier version had `/api/:path*` first, which
    // shadowed `/api/healthz` (the latter rule never fired) and the
    // docker web healthcheck got 404. Caught by the prod-build
    // smoke 2026-05-04.
    return [
      // Healthcheck route — exposed at /api/healthz so Coolify's
      // proxy + the docker healthcheck can both ping the web tier
      // and have it forward to the API's root /healthz endpoint
      // (no /api/ prefix on the API side).
      {
        source: "/api/healthz",
        destination: `${upstream}/healthz`,
      },
      // Catch-all proxy: anything else under /api/* goes straight
      // through with its path preserved.
      {
        source: "/api/:path*",
        destination: `${upstream}/api/:path*`,
      },
    ];
  },

  // Reduce the standalone bundle size further by tree-shaking these
  // optional dev-only modules out of the server runtime.
  experimental: {
    // Faster server-side imports by skipping rarely-used chunks.
    optimizePackageImports: ["lucide-react", "recharts"],
  },

  // Surface real build errors instead of silently swallowing them —
  // we'd rather a deploy fail loudly than ship a broken bundle.
  typescript: {
    ignoreBuildErrors: false,
  },
  eslint: {
    ignoreDuringBuilds: false,
  },
};

export default nextConfig;
