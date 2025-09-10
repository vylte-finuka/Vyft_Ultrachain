# Utiliser une image officielle de Rust comme image de base
FROM rustlang/rust:nightly AS builder

WORKDIR /usr/src/app

COPY Cargo.toml ./
COPY crates/ ./crates/

# Installer les dépendances nécessaires pour la compilation (comme Solana)
RUN apt-get update && apt-get install -y pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

RUN cargo build --release

COPY . .

RUN cargo build --release

# Image finale légère
FROM debian:buster-slim

# Remplacer les sources par les archives Debian
RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g' /etc/apt/sources.list && \
    sed -i '/security.debian.org/d' /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid-until

# Installer les dépendances d'exécution
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/vuc-platform /usr/local/bin/vuc-platform

# S'assurer que le binaire est exécutable
RUN chmod +x /usr/local/bin/vuc-platform

ENTRYPOINT ["vuc-platform"]

EXPOSE 8080