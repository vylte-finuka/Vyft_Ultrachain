# Étape de build
FROM rustlang/rust:nightly-bullseye AS builder

WORKDIR /usr/src/app

COPY Cargo.toml ./
COPY crates/ ./crates/

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    clang \
    libclang-dev \
    librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

RUN find /usr -name "libclang.so*" || echo "libclang.so not found"

ENV LIBCLANG_PATH=/usr/lib/x86_64-linux-gnu

RUN cargo build --release

# Ajout : pour voir où est le .so
RUN find /usr/src/app/target -type f -name "*.so" || echo "No .so found"

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/vuc-platform /usr/local/bin/vuc-platform
COPY --from=builder /usr/src/app/target /usr/local/bin/target

# Remplace par le nom réel du .so si trouvé, sinon supprime cette ligne
# COPY --from=builder /usr/src/app/target/release/libvuc_platform.so /usr/local/bin/target/libvuc_platform.so

RUN chmod +x /usr/local/bin/vuc-platform

WORKDIR /usr/local/bin

ENTRYPOINT ["./vuc-platform"]

EXPOSE 8080
