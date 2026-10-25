FROM node:22-bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends cmake g++ make && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --target packet_analyzer -j2

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --omit=dev
COPY backend/server.js ./backend/server.js
COPY --from=build /app/build/packet_analyzer ./packet_analyzer
RUN mkdir -p /app/backend/uploads /app/backend/reports
EXPOSE 10000
CMD ["node", "backend/server.js"]
