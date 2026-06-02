# Build stage — compile React frontend
FROM node:22-alpine AS client-build
WORKDIR /app/client
COPY client/package*.json ./
RUN npm ci
COPY client/ ./
RUN npm run build

# Production stage — run Express API + serve static frontend
FROM node:22-alpine
WORKDIR /app

# Native deps for better-sqlite3
RUN apk add --no-cache python3 make g++

COPY server/package*.json ./server/
WORKDIR /app/server
RUN npm ci --omit=dev

COPY server/ ./
COPY --from=client-build /app/client/dist ../client/dist

ENV NODE_ENV=production
ENV PORT=5000
EXPOSE 5000

# Persist scan history
VOLUME ["/app/server/data"]

CMD ["node", "server.js"]
