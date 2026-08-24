# Build the registry with the Rust toolchain, then keep the runtime image small.
FROM rust:1.97-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Registry uses the shared signature implementation from Watt Credential.
# The repositories are cloned as siblings so their normal local path
# dependencies resolve exactly as they do in a Watt development checkout.
ARG WATT_CRED_REV=main
ARG WATT_DID_REV=main
RUN git clone https://github.com/wattetheria/watt-did.git /watt-did \
    && git -C /watt-did checkout "${WATT_DID_REV}" \
    && git clone https://github.com/wattetheria/watt-credential.git /watt-credential \
    && git -C /watt-credential checkout "${WATT_CRED_REV}"

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps ./apps

RUN cargo build --release -p watt-registry

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 watt-registry \
    && install -d -o watt-registry -g watt-registry /var/lib/watt-registry/data

COPY --from=builder /app/target/release/watt-registry /usr/local/bin/watt-registry

WORKDIR /var/lib/watt-registry
USER watt-registry

ENV WATT_REGISTRY_HTTP_ADDR=0.0.0.0:8042 \
    WATT_REGISTRY_AUTHORITY_SEED_FILE=/var/lib/watt-registry/data/authority.seed.hex

EXPOSE 8042

ENTRYPOINT ["/usr/local/bin/watt-registry"]
