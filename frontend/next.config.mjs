/** @type {import('next').NextConfig} */
const BACKEND = process.env.MALWARESCAN_API_URL || "http://127.0.0.1:8000";

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // The browser only ever talks to same-origin /api/*. Next.js forwards those
  // requests to the backend on the server side, so no CORS and no browser-side
  // localhost calls are needed (required for the hosted preview).
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${BACKEND}/api/:path*` }];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};
export default nextConfig;
