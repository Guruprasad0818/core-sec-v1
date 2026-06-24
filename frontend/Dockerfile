# Development-mode container: runs `next dev` directly (not a production
# build) so source edits via docker-compose's bind mount hot-reload without
# rebuilding the image - matching the backend's "no rebuild on code change"
# setup. Build from the frontend/ directory:
#   docker build -f frontend/Dockerfile -t cbad-web-dev frontend
#
# node:18-alpine was requested but is incompatible: Next.js 16.x declares
# "engines": { "node": ">=20.9.0" } (see node_modules/next/package.json) and
# will not run on Node 18. Using node:20-alpine instead - same Alpine base,
# the minimum version this app actually supports.
FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install

COPY . .

EXPOSE 3000

ENV NEXT_TELEMETRY_DISABLED=1

CMD ["npm", "run", "dev"]
