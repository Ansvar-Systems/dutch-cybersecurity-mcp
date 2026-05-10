# ─────────────────────────────────────────────────────────────────────────────
# Dutch Cybersecurity MCP — multi-stage Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Build:  docker build -t dutch-cybersecurity-mcp .
# Run:    docker run --rm -p 3000:3000 dutch-cybersecurity-mcp
#
# The image expects a pre-built database at /app/data/ncsc-nl.db.
# Override with NCSCNL_DB_PATH for a custom location.
#
# Recovery 2026-05-10: production stage now COPYs node_modules from the
# builder stage so the better-sqlite3 native binding survives. Database is
# baked into the image (provisioned by ghcr-build.yml from the GitHub Release
# asset database.db.gz, then copied to /app/data/ncsc-nl.db).
# ─────────────────────────────────────────────────────────────────────────────

# --- Stage 1: Build TypeScript + native deps (with binding) ---
FROM node:20-slim AS builder

WORKDIR /app

# Build toolchain for better-sqlite3 native binding
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
# NOTE: NOT --ignore-scripts here — better-sqlite3 postinstall must run to
# fetch/build the native .node binding.
RUN npm ci
COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

# --- Stage 2: Production ---
FROM node:20-slim AS production

WORKDIR /app
ENV NODE_ENV=production
ENV NCSCNL_DB_PATH=/app/data/ncsc-nl.db

# Bring built artifacts AND node_modules (with native binding) from builder.
# This replaces the broken `RUN npm ci --omit=dev --ignore-scripts` pattern
# that stripped the better-sqlite3 binding fleet-wide.
COPY --from=builder /app/node_modules/ node_modules/
COPY --from=builder /app/dist/ dist/
COPY --from=builder /app/package.json ./

# Database baked into image at build time (ghcr-build.yml provisions
# data/database.db from the GitHub Release asset database.db.gz)
COPY data/database.db data/ncsc-nl.db

# Non-root user for security
RUN addgroup --system --gid 1001 mcp && \
    adduser --system --uid 1001 --ingroup mcp mcp && \
    chown -R mcp:mcp /app
USER mcp

# Health check: verify HTTP server responds
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/src/http-server.js"]
