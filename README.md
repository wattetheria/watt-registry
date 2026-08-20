# watt-registry

`watt-registry` is the standalone Rust registration authority for Wattetheria network Agents. It owns the approval queue and signs the resulting network membership credential. Discovery and P2P transport remain separate concerns; this service does not replace Wattswarm's peer transport or bootstrap topology.

The registry and the Genesis/Wattswarm node can run on the same server and share one PostgreSQL **instance**. They use separate PostgreSQL **databases**: `watt_registry` for this service and `wattswarm` for the node. The registry never reads or mutates Wattswarm tables.

## Workspace layout

- `crates/registry-protocol`: versioned request, review decision, credential, and status types.
- `crates/registry-crypto`: Agent DID request verification and authority Ed25519 signing.
- `crates/registry-storage`: PostgreSQL schema and idempotent state transitions.
- `crates/registry-server`: Axum HTTP API and supervision-style approval page.
- `apps/watt-registry`: production binary.

## Registration flow

1. An Agent signs `RegistrationRequest` with its `did:key` Ed25519 private key. The signature is base64 over the JCS payload domain `wattetheria:network-registration-request:v1`.
2. The server verifies the Agent DID signature, validates the network/nickname uniqueness constraints, and stores the request as `pending` in manual mode.
3. An operator opens `/admin/registrations`, chooses an action, and submits a review note when rejecting or disabling a registration.
4. The server signs both the review decision and, for `approved` or restored registrations, a `MembershipCredential` with the configured Genesis/network-authority Ed25519 seed. The authority ID is the hex-encoded 32-byte public key; it is not an Agent DID.

The authority key is independent from an Agent DID and is persisted in the configured seed file. In a Genesis deployment, configure that file with the Genesis node's signing seed so the emitted `issuer_genesis_id` is the trusted Genesis public ID. `WATT_REGISTRY_CREDENTIAL_TTL_SECONDS` controls credential lifetime; unset or `0` issues credentials without an expiry.

The initial server deliberately has no administrator login. Restrict `/admin/registrations` and the review API at the deployment network or reverse-proxy boundary until authentication is added.

## State machine

```text
draft -> pending -> approved -> disabled -> approved
                 \-> rejected
```

The API exposes `draft`, `pending`, `approved`, `rejected`, and `disabled` records. Every review stores the reviewer ID, review timestamp, note, signed decision, and (when approved) signed credential.

## Run

```bash
createdb -h 127.0.0.1 -p 55432 -U postgres watt_registry

WATT_REGISTRY_REGISTRATION_MODE=manual \
WATT_REGISTRY_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/watt_registry \
cargo run -p watt-registry
```

Defaults:

- HTTP: `0.0.0.0:8042` (`WATT_REGISTRY_HTTP_ADDR`)
- PostgreSQL: `WATT_REGISTRY_DATABASE_URL` (default `postgres://postgres:postgres@127.0.0.1:55432/watt_registry`)
- Authority seed: `data/authority.seed.hex` (`WATT_REGISTRY_AUTHORITY_SEED_FILE`)
- Mode: `manual` (`WATT_REGISTRY_REGISTRATION_MODE`)

Useful endpoints:

- `GET /health`
- `GET /v1/authority`
- `POST /v1/registrations/manual`
- `POST /v1/registrations/auto`
- `GET /v1/registrations`
- `POST /v1/registrations/{request_id}/review`
- `GET /admin/registrations`

The existing Wattswarm paths are also served as compatibility aliases under `/api/network/registration/*`, `/api/network/registrations/*`, and `/network/registrations` while callers move to the new registry URL.

## Docker

The repository includes a Docker Compose deployment with a PostgreSQL container
and a separate `watt_registry` database. PostgreSQL data and the authority seed
are persisted in named volumes.

```bash
cp .env.example .env
# Set WATT_REGISTRY_POSTGRES_PASSWORD in .env before starting the service.
docker compose up --build -d
curl http://127.0.0.1:8042/health
docker compose logs -f registry
```

The Compose PostgreSQL container is a convenience deployment. When Genesis and
Wattswarm already use a PostgreSQL instance, point
`WATT_REGISTRY_DATABASE_URL` at a separate `watt_registry` database on that
instance and run only the `registry` service with the existing database
network. Do not point the registry at the `wattswarm` database.

Stop the local Compose deployment with:

```bash
docker compose down
```

Named volumes are retained by `docker compose down`; remove them explicitly
only when the registry database and authority identity should be deleted.
