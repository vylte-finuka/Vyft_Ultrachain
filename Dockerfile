# Étape de build
FROM rustlang/rust:nightly-bullseye AS builder

WORKDIR /usr/src/app

# Copier les fichiers de configuration et les sources
COPY Cargo.toml ./
COPY crates/. ./crates/
COPY vez_bytecode.hex ./
COPY vezcurpoxycore_bytecode.hex ./
COPY vezcurproxycore.json ./
COPY VEZABI.json ./

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

# Copier le binaire compilé et les fichiers nécessaires
COPY --from=builder /usr/src/app/target/release/vuc-platform /usr/local/bin/vuc-platform
COPY --from=builder /usr/src/app/target /usr/local/bin/target

COPY --from=builder /usr/src/app/VEZABI.json /usr/local/bin/VEZABI.json
COPY --from=builder /usr/src/app/VEZABI.json /usr/src/app/VEZABI.json

COPY --from=builder /usr/src/app/vezcurproxycore.json /usr/local/bin/vezcurproxycore.json
COPY --from=builder /usr/src/app/vezcurproxycore.json /usr/src/app/vezcurproxycore.json


# S'assurer que le binaire est exécutable
RUN chmod +x /usr/local/bin/vuc-platform

# Créer le dossier target si besoin
RUN mkdir -p /usr/local/bin/target

# Télécharger lib.so depuis GitHub dans le dossier target
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /usr/local/bin/target/lib.so https://drive.google.com/uc?id=1nAQRc-iVBjiRRrP-wy9pNHo1Mng6fs_P

WORKDIR /usr/local/bin

ENTRYPOINT ["./vuc-platform"]

EXPOSE 8080
