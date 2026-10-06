# hosted demo: landing page + server side bridges + relay on one port, local bridges can still use --server wss://<host>

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
COPY web ./web
COPY hosted ./hosted
COPY --from=core /src/core/build/pqs-core ./core/build/pqs-core
ENV PORT=10000 DATA_DIR=/data
RUN mkdir -p /data
EXPOSE 10000
CMD ["node", "hosted/gateway.js"]
