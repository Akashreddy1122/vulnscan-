# Malware Scan web UI — Next.js production build, non-root.
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    MALWARESCAN_API_URL=http://api:8000
RUN addgroup -S -g 10001 msweb && adduser -S -u 10001 -G msweb msweb
COPY --from=build --chown=msweb:msweb /app/node_modules ./node_modules
COPY --from=build --chown=msweb:msweb /app/.next ./.next
COPY --from=build --chown=msweb:msweb /app/package.json ./package.json
COPY --from=build --chown=msweb:msweb /app/next.config.mjs ./next.config.mjs
COPY --from=build --chown=msweb:msweb /app/public ./public
USER msweb
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/login >/dev/null || exit 1
CMD ["npx", "next", "start", "-H", "0.0.0.0", "-p", "3000"]
