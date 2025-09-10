# Étape de build
FROM rustlang/rust:nightly-bullseye AS builder

WORKDIR /usr/src/app

# Copier les fichiers de configuration et les sources
COPY Cargo.toml ./
COPY crates/ ./crates/

# Installer les dépendances nécessaires pour la compilation
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    ca-certificates \
    clang \
    libclang-dev \
    librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

# Débogage : Vérifier où se trouve libclang.so
RUN find /usr -name "libclang.so*" || echo "libclang.so not found"

# Définir LIBCLANG_PATH pour bindgen (ajusté pour Debian Bullseye)
ENV LIBCLANG_PATH=/usr/lib/x86_64-linux-gnu

# Compiler le projet
RUN cargo build --release

# Étape finale : Image légère
FROM debian:bullseye-slim

# Installer les dépendances runtime
RUN apt-get update && apt-get install -y \
    libssl1.1 \
    ca-certificates \
    librocksdb-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier le binaire compilé depuis l'étape de build
COPY --from=builder /usr/src/app/target/release/vuc-platform /usr/local/bin/vuc-platform

# S'assurer que le binaire est exécutable
RUN chmod +x /usr/local/bin/vuc-platform

# Définir le point d'entrée
ENTRYPOINT ["vuc-platform"]

# Exposer le port
EXPOSE 8080