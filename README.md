# watt-registry

`watt-registry` is the standalone Rust registration authority for Wattetheria network Agents. It owns the approval queue and signs the resulting network membership credential. Discovery and P2P transport remain separate concerns; this service does not replace Wattswarm's peer transport or bootstrap topology.

The registry and the Genesis/Wattswarm node can run on the same server and share one PostgreSQL **instance**. They use separate PostgreSQL **databases**: `watt_registry` for this service and `wattswarm` for the node. The registry never reads or mutates Wattswarm tables.

## Workspace layout

- `crates/registry-protocol`: versioned request, review decision, credential, and status types.
- `crates/registry-crypto`: Registry key custody and signing policy, delegating all signature-suite operations to `watt-credential`.
- `crates/registry-storage`: PostgreSQL schema and idempotent state transitions.
- `crates/registry-server`: Axum HTTP API and supervision-style approval page.
- `apps/watt-registry`: production binary.

## Registration flow

1. An Agent signs `RegistrationRequest` with its `did:key` Ed25519 private key. The signature is base64 over the JCS payload domain `wattetheria:network-registration-request:v1`; `nickname` remains mutable metadata and is not included in that payload.
2. The server verifies the Agent DID signature, validates the network/nickname uniqueness constraints, and stores the request as `pending` in manual mode.
3. An operator opens `/admin/registrations`, chooses an action, and submits a review note when rejecting or disabling a registration.
4. The server signs both the review decision and, for `approved` or restored registrations, a `MembershipCredential` with the configured Genesis/network-authority key. The Credential embeds an authority-key certificate signed by the Genesis trust anchor, allowing the Agent to detect tampering offline before P2P startup. The Credential subject contains the network and Agent identity, but not the registration `request_id` or mutable nickname.
5. Wattswarm submits its signed `DiscoveryNodeRecord` to `/v1/nodes/discovery`. The registry verifies the node signature, stores the latest node record, and materializes a node-to-Agent link from `source_agent_card.agent_id`.

The authority key is independent from an Agent DID. A bootstrap seed file is
used only to initialize the network authority and signing-key rows; after that,
the active key record in PostgreSQL is the signing source. In a Genesis
deployment, the bootstrap seed must be the Genesis node's signing seed so the
stored signing public key matches the trusted Genesis node ID. Credentials use
`issuer_authority_id` to reference the registry authority record.
The certificate records the signing algorithm and key encoding explicitly so
verification can dispatch through a shared algorithm boundary instead of
binding consumers to Ed25519-specific code. Existing Credentials without this
issuer proof are revoked during schema initialization and must be reissued.
Key generation, public-key derivation, detached signing, and detached
verification all come from `watt-credential`; Registry code does not implement
an independent Ed25519 backend.
`WATT_REGISTRY_CREDENTIAL_TTL_SECONDS` controls credential lifetime; unset or
`0` issues credentials without an expiry.

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
- PostgreSQL: `WATT_REGISTRY_DATABASE_URL` (required)
- PostgreSQL host port: `55432` (`WATT_REGISTRY_POSTGRES_PORT`)
- Authority seed: `data/authority.seed.hex` (`WATT_REGISTRY_AUTHORITY_SEED_FILE`)
- Mode: `manual` (`WATT_REGISTRY_REGISTRATION_MODE`)

Useful endpoints:

- `GET /health`
- `GET /v1/authority`
- `GET /v1/authority/status?network_id=...`
- `POST /v1/authority/initialize`
- `POST /v1/registrations/manual`
- `POST /v1/registrations/auto`
- `GET /v1/registrations`
- `POST /v1/registrations/{request_id}/review`
- `POST /v1/nodes/discovery`
- `GET /v1/nodes`
- `GET /v1/nodes/{node_id}?network_id=...`
- `GET /v1/nodes/{node_id}/agents?network_id=...`
- `GET /admin/registrations`
- `GET /admin/authority`

The `/admin/authority` page contains the Authority key setup form. It accepts
the Genesis node public ID, the signing algorithm, and a seed file (or seed
hex), derives the public key on the server, and rejects mismatches. The
database update is transactional: a new key is inserted into
`registration_signing_keys`, the authority points to it, older active keys are
retired, and credentials issued by a changed authority are revoked so Agents
must register again. The status endpoint is read-only and does not create a
network authority when the network has not been initialized.

The existing Wattswarm paths are also served as compatibility aliases under `/api/network/registration/*`, `/api/network/registrations/*`, and `/network/registrations` while callers move to the new registry URL.

## Docker

The repository includes a Docker Compose deployment with a PostgreSQL container
and a separate `watt_registry` database. PostgreSQL data and the authority seed
are persisted in named volumes.

```bash
cp .env.example .env
# Set WATT_REGISTRY_POSTGRES_USER, WATT_REGISTRY_POSTGRES_DB,
# WATT_REGISTRY_POSTGRES_PASSWORD, and WATT_REGISTRY_DATABASE_URL in .env.
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
