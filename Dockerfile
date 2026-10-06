# relay only, bridges stay on each users machine and point at this with --server wss://<host>

FROM node:22-trixie-slim AS core
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config libssl-dev libsodium-dev nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY core ./core
RUN cmake -S core -B core/build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build core/build --target pqs-core

FROM node:22-trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3t64 libsodium23 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY bridge ./bridge
COPY server ./server
COPY --from=core /src/core/build/pqs-core ./core/build/pqs-core
ENV PORT=10000 DB_PATH=/data/pqs-server.db
RUN mkdir -p /data
EXPOSE 10000
CMD ["sh", "-c", "exec node server/index.js --host 0.0.0.0 --port \"$PORT\" --db \"$DB_PATH\""]
