# The example frontend: Next.js, built once, proxying /api to the backend.
FROM node:24.21.0-trixie-slim
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    NEXT_TELEMETRY_DISABLED=1
RUN corepack enable pnpm

WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY . ./

# Rewrites are fixed at build time (next.config.ts).
ARG BACKEND_URL=http://backend:8000
ENV BACKEND_URL=$BACKEND_URL
RUN pnpm build && chown -R node /app/.next

USER node
EXPOSE 3000
# Next.js directly: pnpm would check (and try to rewrite) node_modules at start.
CMD ["node_modules/.bin/next", "start", "--hostname", "0.0.0.0", "--port", "3000"]
