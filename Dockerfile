ARG BUILD_FROM=node:20-alpine
FROM $BUILD_FROM

# Build tools needed to compile better-sqlite3 native module
RUN apk add --no-cache python3 make g++

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY src/ ./src/
COPY public/ ./public/

EXPOSE 8099
CMD ["node", "src/server.js"]
