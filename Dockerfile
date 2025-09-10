# Build stage
FROM rustlang/rust:nightly AS builder

WORKDIR /usr/src/app

COPY Cargo.toml ./
COPY crates/ ./crates/

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    clang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Set LIBCLANG_PATH
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib

RUN cargo build --release

# Final stage
FROM debian:bullseye-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/vuc-platform /usr/local/bin/vuc-platform

RUN chmod +x /usr/local/bin/vuc-platform

ENTRYPOINT ["vuc-platform"]

EXPOSE 8080