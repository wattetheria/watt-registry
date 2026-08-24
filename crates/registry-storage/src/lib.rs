use anyhow::{Context, Result, bail};
use postgres::{Client, GenericClient, NoTls, Row};
use registry_protocol::{
    MembershipCredential, RegistrationDecision, RegistrationDecisionKind, RegistrationRecord,
    RegistrationRequest, RegistrationStatus, SignedDiscoveryNodeRecord, normalize_nickname,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const REGISTRATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS registration_requests (
    request_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    nickname TEXT NOT NULL,
    nickname_key TEXT NOT NULL,
    tenant_instance_id TEXT,
    nonce TEXT NOT NULL,
    request_json TEXT NOT NULL,
    registration_mode TEXT NOT NULL DEFAULT 'manual'
        CHECK(registration_mode IN ('auto', 'manual')),
    status TEXT NOT NULL CHECK(status IN ('draft', 'pending', 'approved', 'rejected', 'disabled')),
    decision_json TEXT,
    reviewer_id TEXT,
    reviewed_at_ms TIMESTAMPTZ,
    review_note TEXT,
    submitted_at_ms TIMESTAMPTZ NOT NULL,
    updated_at_ms TIMESTAMPTZ NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS registration_nonce_unique
    ON registration_requests(network_id, nonce);
CREATE UNIQUE INDEX IF NOT EXISTS registration_agent_active_unique
    ON registration_requests(network_id, agent_did)
    WHERE status IN ('draft', 'pending', 'approved', 'disabled');
CREATE UNIQUE INDEX IF NOT EXISTS registration_nickname_active_unique
    ON registration_requests(network_id, nickname_key)
    WHERE status IN ('draft', 'pending', 'approved', 'disabled');
CREATE INDEX IF NOT EXISTS registration_status_index
    ON registration_requests(network_id, status, submitted_at_ms DESC);
ALTER TABLE registration_requests
    ADD COLUMN IF NOT EXISTS registration_mode TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE registration_requests
    ADD COLUMN IF NOT EXISTS tenant_instance_id TEXT;
CREATE TABLE IF NOT EXISTS registration_networks_authorities (
    authority_id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    network_id TEXT NOT NULL UNIQUE,
    genesis_node_id TEXT NOT NULL,
    active_signing_key_id TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL DEFAULT 'ed25519',
    registration_mode TEXT NOT NULL DEFAULT 'manual'
        CHECK(registration_mode IN ('auto', 'manual', 'disabled')),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'disabled')),
    created_at_ms TIMESTAMPTZ NOT NULL,
    updated_at_ms TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS registration_signing_keys (
    key_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL
        REFERENCES registration_networks_authorities(network_id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    private_key_hex TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'retired', 'revoked')),
    created_at_ms TIMESTAMPTZ NOT NULL,
    retired_at_ms TIMESTAMPTZ,
    UNIQUE(network_id, public_key_hex)
);
CREATE INDEX IF NOT EXISTS registration_signing_keys_active_index
    ON registration_signing_keys(network_id, status);
CREATE TABLE IF NOT EXISTS registration_credentials (
    credential_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    network_id TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    issuer_authority_id TEXT NOT NULL
        REFERENCES registration_networks_authorities(authority_id),
    signing_key_id TEXT NOT NULL,
    signature_algorithm TEXT NOT NULL,
    credential_json TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'revoked', 'expired')),
    issued_at_ms TIMESTAMPTZ NOT NULL,
    expires_at_ms TIMESTAMPTZ,
    revoked_at_ms TIMESTAMPTZ,
    created_at_ms TIMESTAMPTZ NOT NULL,
    updated_at_ms TIMESTAMPTZ NOT NULL,
    UNIQUE(network_id, agent_did, credential_id)
);
CREATE INDEX IF NOT EXISTS registration_credentials_agent_index
    ON registration_credentials(network_id, agent_did, status, issued_at_ms DESC);
CREATE TABLE IF NOT EXISTS registration_agents (
    request_id TEXT NOT NULL,
    network_id TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    nickname TEXT NOT NULL,
    nickname_key TEXT NOT NULL,
    tenant_instance_id TEXT,
    registration_mode TEXT NOT NULL CHECK(registration_mode IN ('auto', 'manual')),
    credential_id TEXT NOT NULL,
    agent_card_json TEXT,
    agent_card_hash TEXT,
    agent_card_updated_at_ms TIMESTAMPTZ,
    status TEXT NOT NULL CHECK(status IN ('active', 'disabled')),
    registered_at_ms TIMESTAMPTZ NOT NULL,
    updated_at_ms TIMESTAMPTZ NOT NULL,
    disabled_at_ms TIMESTAMPTZ,
    PRIMARY KEY(network_id, agent_did),
    UNIQUE(credential_id)
);
ALTER TABLE registration_agents
    ADD COLUMN IF NOT EXISTS request_id TEXT;
ALTER TABLE registration_agents
    ADD COLUMN IF NOT EXISTS agent_card_json TEXT;
ALTER TABLE registration_agents
    ADD COLUMN IF NOT EXISTS agent_card_hash TEXT;
ALTER TABLE registration_agents
    ADD COLUMN IF NOT EXISTS agent_card_updated_at_ms TIMESTAMPTZ;
UPDATE registration_agents AS agents
SET request_id = requests.request_id
FROM registration_requests AS requests
WHERE agents.request_id IS NULL
  AND requests.network_id = agents.network_id
  AND requests.agent_did = agents.agent_did
  AND requests.status IN ('approved', 'disabled');
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM registration_agents WHERE request_id IS NULL) THEN
        RAISE EXCEPTION 'registration_agents contains rows without request_id';
    END IF;
    ALTER TABLE registration_agents ALTER COLUMN request_id SET NOT NULL;
END
$$;
CREATE UNIQUE INDEX IF NOT EXISTS registration_agents_nickname_active_unique
    ON registration_agents(network_id, nickname_key)
    WHERE status IN ('active', 'disabled');
CREATE INDEX IF NOT EXISTS registration_agents_status_index
    ON registration_agents(network_id, status, updated_at_ms DESC);
CREATE TABLE IF NOT EXISTS registration_nodes (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    signing_public_key_hex TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    record_seq BIGINT NOT NULL,
    record_updated_at_ms TIMESTAMPTZ NOT NULL,
    ttl_ms BIGINT NOT NULL,
    record_expires_at_ms TIMESTAMPTZ NOT NULL,
    geo_json TEXT,
    capabilities_json TEXT NOT NULL,
    topic_providers_json TEXT NOT NULL,
    transport_contact_json TEXT,
    source_agent_card_json TEXT,
    discovery_record_json TEXT NOT NULL,
    record_signature_hex TEXT NOT NULL,
    first_seen_at_ms TIMESTAMPTZ NOT NULL,
    last_seen_at_ms TIMESTAMPTZ NOT NULL,
    created_at_ms TIMESTAMPTZ NOT NULL,
    updated_at_ms TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'revoked')),
    PRIMARY KEY(network_id, node_id),
    UNIQUE(network_id, signing_public_key_hex)
);
CREATE INDEX IF NOT EXISTS registration_nodes_status_index
    ON registration_nodes(network_id, status, last_seen_at_ms DESC);
CREATE INDEX IF NOT EXISTS registration_nodes_expiry_index
    ON registration_nodes(network_id, record_expires_at_ms);
CREATE TABLE IF NOT EXISTS registration_node_agents (
    network_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    agent_card_json TEXT,
    agent_card_hash TEXT,
    relation_status TEXT NOT NULL DEFAULT 'pending'
        CHECK(relation_status IN ('pending', 'active', 'disabled', 'revoked')),
    first_seen_at_ms TIMESTAMPTZ NOT NULL,
    last_seen_at_ms TIMESTAMPTZ NOT NULL,
    created_at_ms TIMESTAMPTZ NOT NULL,
    updated_at_ms TIMESTAMPTZ NOT NULL,
    disabled_at_ms TIMESTAMPTZ,
    PRIMARY KEY(network_id, node_id, agent_did)
);
ALTER TABLE registration_node_agents
    DROP COLUMN IF EXISTS request_id;
CREATE INDEX IF NOT EXISTS registration_node_agents_agent_index
    ON registration_node_agents(network_id, agent_did, relation_status);
CREATE INDEX IF NOT EXISTS registration_node_agents_node_index
    ON registration_node_agents(network_id, node_id, relation_status);
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'registration_node_agents'
          AND column_name = 'agent_card_json'
    ) THEN
        UPDATE registration_agents AS agents
        SET agent_card_json = cards.agent_card_json,
            agent_card_hash = cards.agent_card_hash,
            agent_card_updated_at_ms = cards.updated_at_ms
        FROM (
            SELECT DISTINCT ON (network_id, agent_did)
                   network_id, agent_did,
                   COALESCE((agent_card_json::jsonb -> 'card')::text, agent_card_json) AS agent_card_json,
                   agent_card_hash, updated_at_ms
            FROM registration_node_agents
            WHERE agent_card_json IS NOT NULL
            ORDER BY network_id, agent_did, updated_at_ms DESC, node_id ASC
        ) AS cards
        WHERE agents.network_id = cards.network_id
          AND agents.agent_did = cards.agent_did
          AND (
              agents.agent_card_updated_at_ms IS NULL
              OR agents.agent_card_updated_at_ms <= cards.updated_at_ms
          );
        ALTER TABLE registration_node_agents DROP COLUMN agent_card_json;
        ALTER TABLE registration_node_agents DROP COLUMN agent_card_hash;
    END IF;
END
$$;
UPDATE registration_credentials
SET status = 'revoked',
    revoked_at_ms = COALESCE(revoked_at_ms, CURRENT_TIMESTAMP),
    updated_at_ms = CURRENT_TIMESTAMP
WHERE status = 'active'
  AND NOT (credential_json::jsonb ? 'issuer_key_certificate');
UPDATE registration_requests AS requests
SET status = 'rejected',
    review_note = 'Credential predates offline issuer proof; re-registration is required',
    updated_at_ms = CURRENT_TIMESTAMP
WHERE status IN ('approved', 'disabled')
  AND EXISTS (
      SELECT 1
      FROM registration_credentials AS credentials
      WHERE credentials.request_id = requests.request_id
        AND NOT (credentials.credential_json::jsonb ? 'issuer_key_certificate')
  );
UPDATE registration_agents AS agents
SET status = 'disabled',
    disabled_at_ms = COALESCE(disabled_at_ms, CURRENT_TIMESTAMP),
    updated_at_ms = CURRENT_TIMESTAMP
WHERE EXISTS (
    SELECT 1
    FROM registration_credentials AS credentials
    WHERE credentials.credential_id = agents.credential_id
      AND NOT (credentials.credential_json::jsonb ? 'issuer_key_certificate')
);
UPDATE registration_node_agents AS relations
SET relation_status = 'disabled',
    disabled_at_ms = COALESCE(disabled_at_ms, CURRENT_TIMESTAMP),
    updated_at_ms = CURRENT_TIMESTAMP
WHERE EXISTS (
    SELECT 1
    FROM registration_agents AS agents
    WHERE agents.network_id = relations.network_id
      AND agents.agent_did = relations.agent_did
      AND agents.status = 'disabled'
);
"#;

const REGISTRATION_MODE_AUTO: &str = "auto";
const REGISTRATION_MODE_MANUAL: &str = "manual";
const REGISTRATION_MODE_DISABLED: &str = "disabled";

const TIMESTAMP_COLUMNS: &[(&str, &str)] = &[
    ("registration_requests", "reviewed_at_ms"),
    ("registration_requests", "submitted_at_ms"),
    ("registration_requests", "updated_at_ms"),
    ("registration_networks_authorities", "created_at_ms"),
    ("registration_networks_authorities", "updated_at_ms"),
    ("registration_signing_keys", "created_at_ms"),
    ("registration_signing_keys", "retired_at_ms"),
    ("registration_credentials", "issued_at_ms"),
    ("registration_credentials", "expires_at_ms"),
    ("registration_credentials", "revoked_at_ms"),
    ("registration_credentials", "created_at_ms"),
    ("registration_credentials", "updated_at_ms"),
    ("registration_agents", "registered_at_ms"),
    ("registration_agents", "agent_card_updated_at_ms"),
    ("registration_agents", "updated_at_ms"),
    ("registration_agents", "disabled_at_ms"),
    ("registration_nodes", "record_updated_at_ms"),
    ("registration_nodes", "record_expires_at_ms"),
    ("registration_nodes", "first_seen_at_ms"),
    ("registration_nodes", "last_seen_at_ms"),
    ("registration_nodes", "created_at_ms"),
    ("registration_nodes", "updated_at_ms"),
    ("registration_node_agents", "first_seen_at_ms"),
    ("registration_node_agents", "last_seen_at_ms"),
    ("registration_node_agents", "created_at_ms"),
    ("registration_node_agents", "updated_at_ms"),
    ("registration_node_agents", "disabled_at_ms"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationAgentStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAuthorityRecord {
    pub authority_id: String,
    pub network_id: String,
    pub genesis_node_id: String,
    pub active_signing_key_id: String,
    pub signature_algorithm: String,
    pub registration_mode: String,
    pub status: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAuthorityConfig {
    pub network_id: String,
    pub genesis_node_id: String,
    pub active_signing_key_id: String,
    pub signature_algorithm: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
    pub registration_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationSigningKeyRecord {
    pub key_id: String,
    pub network_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
    pub private_key_hex: String,
    pub status: String,
    pub created_at_ms: u64,
    pub retired_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAuthorityInitializationResult {
    pub authority: NetworkAuthorityRecord,
    pub signing_key: RegistrationSigningKeyRecord,
    pub revoked_credentials: u64,
    pub disabled_agents: u64,
    pub disabled_node_agents: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationCredentialRecord {
    pub credential_id: String,
    pub request_id: String,
    pub network_id: String,
    pub agent_did: String,
    pub issuer_authority_id: String,
    pub signing_key_id: String,
    pub signature_algorithm: String,
    pub credential: MembershipCredential,
    pub status: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub revoked_at_ms: Option<u64>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationAgentRecord {
    pub request_id: String,
    pub network_id: String,
    pub agent_did: String,
    pub nickname: String,
    pub nickname_key: String,
    pub tenant_instance_id: Option<String>,
    pub registration_mode: String,
    pub credential_id: String,
    pub agent_card: Option<Value>,
    pub agent_card_hash: Option<String>,
    pub agent_card_updated_at_ms: Option<u64>,
    pub status: RegistrationAgentStatus,
    pub registered_at_ms: u64,
    pub updated_at_ms: u64,
    pub disabled_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationNodeStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationNodeRecord {
    pub network_id: String,
    pub node_id: String,
    pub signing_public_key_hex: String,
    pub record: SignedDiscoveryNodeRecord,
    pub status: RegistrationNodeStatus,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeAgentRelationStatus {
    Pending,
    Active,
    Disabled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrationNodeAgentRecord {
    pub network_id: String,
    pub node_id: String,
    pub agent_did: String,
    pub relation_status: NodeAgentRelationStatus,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub disabled_at_ms: Option<u64>,
}

struct MemoryState {
    requests: BTreeMap<String, RegistrationRecord>,
    authorities: BTreeMap<String, NetworkAuthorityRecord>,
    signing_keys: BTreeMap<String, RegistrationSigningKeyRecord>,
    credentials: BTreeMap<String, RegistrationCredentialRecord>,
    agents: BTreeMap<(String, String), RegistrationAgentRecord>,
    nodes: BTreeMap<(String, String), RegistrationNodeRecord>,
    node_agents: BTreeMap<(String, String, String), RegistrationNodeAgentRecord>,
}

#[derive(Clone)]
pub struct RegistryStore {
    backend: Arc<Mutex<Backend>>,
}

enum Backend {
    Postgres(Box<Client>),
    Memory(MemoryState),
}

impl std::fmt::Debug for RegistryStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryStore")
            .finish_non_exhaustive()
    }
}

impl RegistryStore {
    pub fn open(database_url: &str) -> Result<Self> {
        let client = Client::connect(database_url, NoTls)
            .with_context(|| format!("connect registry PostgreSQL database {database_url}"))?;
        let store = Self {
            backend: Arc::new(Mutex::new(Backend::Postgres(Box::new(client)))),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Test-only storage that avoids requiring a PostgreSQL daemon. Production
    /// startup always calls [`RegistryStore::open`] with a PostgreSQL URL.
    pub fn open_in_memory() -> Result<Self> {
        Ok(Self {
            backend: Arc::new(Mutex::new(Backend::Memory(MemoryState {
                requests: BTreeMap::new(),
                authorities: BTreeMap::new(),
                signing_keys: BTreeMap::new(),
                credentials: BTreeMap::new(),
                agents: BTreeMap::new(),
                nodes: BTreeMap::new(),
                node_agents: BTreeMap::new(),
            }))),
        })
    }

    fn initialize_schema(&self) -> Result<()> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        if let Backend::Postgres(client) = &mut *backend {
            client.batch_execute("SET TIME ZONE 'UTC'")?;
            migrate_authority_table_name(client)?;
            client.batch_execute(REGISTRATION_SCHEMA)?;
            migrate_timestamp_columns(client)?;
            migrate_authority_ids(client)?;
            invalidate_legacy_agents_postgres(client)?;
            drop_duplicate_credential_columns(client)?;
        }
        Ok(())
    }

    pub fn ensure_network_authority(
        &self,
        config: &NetworkAuthorityConfig,
        now_ms: u64,
    ) -> Result<NetworkAuthorityRecord> {
        validate_non_empty_value("network_id", &config.network_id)?;
        validate_non_empty_value("genesis_node_id", &config.genesis_node_id)?;
        validate_non_empty_value("active_signing_key_id", &config.active_signing_key_id)?;
        validate_non_empty_value("signature_algorithm", &config.signature_algorithm)?;
        validate_non_empty_value("public_key_hex", &config.public_key_hex)?;
        validate_non_empty_value("private_key_hex", &config.private_key_hex)?;
        validate_authority_registration_mode(&config.registration_mode)?;
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => ensure_network_authority_postgres(client, config, now_ms),
            Backend::Memory(state) => ensure_network_authority_memory(state, config, now_ms),
        }
    }

    pub fn get_network_authority(
        &self,
        network_id: &str,
    ) -> Result<Option<NetworkAuthorityRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                get_network_authority_postgres(client.as_mut(), network_id)
            }
            Backend::Memory(state) => Ok(state.authorities.get(network_id).cloned()),
        }
    }

    pub fn list_network_authorities(&self) -> Result<Vec<NetworkAuthorityRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => list_network_authorities_postgres(client.as_mut()),
            Backend::Memory(state) => Ok(state.authorities.values().cloned().collect()),
        }
    }

    pub fn get_active_signing_key(
        &self,
        network_id: &str,
    ) -> Result<Option<RegistrationSigningKeyRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                get_active_signing_key_postgres(client.as_mut(), network_id)
            }
            Backend::Memory(state) => {
                let Some(authority) = state.authorities.get(network_id) else {
                    return Ok(None);
                };
                Ok(state
                    .signing_keys
                    .get(&authority.active_signing_key_id)
                    .cloned())
            }
        }
    }

    pub fn initialize_or_rotate_network_authority(
        &self,
        config: &NetworkAuthorityConfig,
        now_ms: u64,
    ) -> Result<NetworkAuthorityInitializationResult> {
        validate_non_empty_value("network_id", &config.network_id)?;
        validate_non_empty_value("genesis_node_id", &config.genesis_node_id)?;
        validate_non_empty_value("active_signing_key_id", &config.active_signing_key_id)?;
        validate_non_empty_value("signature_algorithm", &config.signature_algorithm)?;
        validate_non_empty_value("public_key_hex", &config.public_key_hex)?;
        validate_non_empty_value("private_key_hex", &config.private_key_hex)?;
        validate_authority_registration_mode(&config.registration_mode)?;

        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                initialize_or_rotate_network_authority_postgres(client, config, now_ms)
            }
            Backend::Memory(state) => {
                initialize_or_rotate_network_authority_memory(state, config, now_ms)
            }
        }
    }

    pub fn insert_request(
        &self,
        request: &RegistrationRequest,
        status: RegistrationStatus,
        registration_mode: &str,
        now_ms: u64,
    ) -> Result<RegistrationRecord> {
        let nickname_key = normalize_nickname(&request.nickname).map_err(anyhow::Error::msg)?;
        validate_registration_mode(registration_mode)?;
        let request_json = serde_json::to_string(request)?;
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => insert_postgres(
                client,
                request,
                &nickname_key,
                &request_json,
                status,
                registration_mode,
                now_ms,
            ),
            Backend::Memory(state) => insert_memory(
                &mut state.requests,
                request,
                &nickname_key,
                &request_json,
                status,
                registration_mode,
                now_ms,
            ),
        }
    }

    pub fn get(&self, request_id: &str) -> Result<Option<RegistrationRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => load_record_postgres(client.as_mut(), request_id),
            Backend::Memory(state) => Ok(state.requests.get(request_id).cloned()),
        }
    }

    pub fn submit_draft(
        &self,
        request_id: &str,
        now_ms: u64,
    ) -> Result<Option<RegistrationRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => submit_draft_postgres(client, request_id, now_ms),
            Backend::Memory(state) => submit_draft_memory(&mut state.requests, request_id, now_ms),
        }
    }

    pub fn list(
        &self,
        network_id: Option<&str>,
        status: Option<RegistrationStatus>,
        limit: usize,
    ) -> Result<Vec<RegistrationRecord>> {
        let limit = limit.clamp(1, 500);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => list_postgres(client, network_id, status, limit),
            Backend::Memory(state) => list_memory(&state.requests, network_id, status, limit),
        }
    }

    pub fn get_agent(
        &self,
        network_id: &str,
        agent_did: &str,
    ) -> Result<Option<RegistrationAgentRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => get_agent_postgres(client, network_id, agent_did),
            Backend::Memory(state) => Ok(state
                .agents
                .get(&(network_id.to_owned(), agent_did.to_owned()))
                .cloned()),
        }
    }

    pub fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<RegistrationCredentialRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => get_credential_postgres(client.as_mut(), credential_id),
            Backend::Memory(state) => Ok(state.credentials.get(credential_id).cloned()),
        }
    }

    pub fn list_agents(
        &self,
        network_id: Option<&str>,
        status: Option<RegistrationAgentStatus>,
        limit: usize,
    ) -> Result<Vec<RegistrationAgentRecord>> {
        let limit = limit.clamp(1, 500);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => list_agents_postgres(client, network_id, status, limit),
            Backend::Memory(state) => list_agents_memory(&state.agents, network_id, status, limit),
        }
    }

    pub fn upsert_discovery_node(
        &self,
        record: &SignedDiscoveryNodeRecord,
        now_ms: u64,
    ) -> Result<RegistrationNodeRecord> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                upsert_discovery_node_postgres(client.as_mut(), record, now_ms)
            }
            Backend::Memory(state) => upsert_discovery_node_memory(state, record, now_ms),
        }
    }

    pub fn get_node(
        &self,
        network_id: &str,
        node_id: &str,
    ) -> Result<Option<RegistrationNodeRecord>> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                expire_discovery_nodes_postgres(client.as_mut(), now_ms())?;
                get_node_postgres(client.as_mut(), network_id, node_id)
            }
            Backend::Memory(state) => {
                expire_discovery_nodes_memory(state, now_ms());
                Ok(state
                    .nodes
                    .get(&(network_id.to_owned(), node_id.to_owned()))
                    .filter(|node| node.status == RegistrationNodeStatus::Active)
                    .cloned())
            }
        }
    }

    pub fn list_nodes(
        &self,
        network_id: Option<&str>,
        status: Option<RegistrationNodeStatus>,
        limit: usize,
    ) -> Result<Vec<RegistrationNodeRecord>> {
        let limit = limit.clamp(1, 500);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                expire_discovery_nodes_postgres(client.as_mut(), now_ms())?;
                list_nodes_postgres(client, network_id, status, limit)
            }
            Backend::Memory(state) => {
                expire_discovery_nodes_memory(state, now_ms());
                list_nodes_memory(
                    &state.nodes,
                    &state.node_agents,
                    &state.agents,
                    &state.credentials,
                    network_id,
                    status,
                    limit,
                )
            }
        }
    }

    pub fn list_node_agents(
        &self,
        network_id: &str,
        node_id: &str,
        limit: usize,
    ) -> Result<Vec<RegistrationNodeAgentRecord>> {
        let limit = limit.clamp(1, 500);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                list_node_agents_postgres(client, network_id, node_id, limit, false)
            }
            Backend::Memory(state) => Ok(state
                .node_agents
                .values()
                .filter(|link| link.network_id == network_id && link.node_id == node_id)
                .take(limit)
                .cloned()
                .collect()),
        }
    }

    pub fn list_visible_node_agents(
        &self,
        network_id: &str,
        node_id: &str,
        limit: usize,
    ) -> Result<Vec<RegistrationNodeAgentRecord>> {
        let limit = limit.clamp(1, 500);
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                expire_discovery_nodes_postgres(client.as_mut(), now_ms())?;
                list_node_agents_postgres(client, network_id, node_id, limit, true)
            }
            Backend::Memory(state) => {
                expire_discovery_nodes_memory(state, now_ms());
                Ok(state
                    .node_agents
                    .values()
                    .filter(|link| {
                        link.network_id == network_id
                            && link.node_id == node_id
                            && link.relation_status == NodeAgentRelationStatus::Active
                            && state
                                .agents
                                .get(&(link.network_id.clone(), link.agent_did.clone()))
                                .is_some_and(|agent| {
                                    agent.status == RegistrationAgentStatus::Active
                                        && state.credentials.get(&agent.credential_id).is_some_and(
                                            |credential| {
                                                credential.status == "active"
                                                    && credential.expires_at_ms.is_none_or(
                                                        |expires_at| expires_at > now_ms(),
                                                    )
                                            },
                                        )
                                })
                    })
                    .take(limit)
                    .cloned()
                    .collect())
            }
        }
    }

    pub fn transition(
        &self,
        request_id: &str,
        action: RegistrationDecisionKind,
        decision: &RegistrationDecision,
        credential: Option<&MembershipCredential>,
        now_ms: u64,
    ) -> Result<RegistrationRecord> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        match &mut *backend {
            Backend::Postgres(client) => {
                transition_postgres(client, request_id, action, decision, credential, now_ms)
            }
            Backend::Memory(state) => {
                let current = state
                    .requests
                    .get(request_id)
                    .cloned()
                    .context("registration not found")?;
                let next_status = next_status(current.status, action)?;
                validate_transition(
                    &current,
                    request_id,
                    action,
                    next_status,
                    decision,
                    credential,
                )?;
                transition_memory(state, request_id, next_status, decision, credential, now_ms)
            }
        }
    }
}

fn migrate_authority_table_name(client: &mut Client) -> Result<()> {
    let legacy_exists: bool = client
        .query_one(
            "SELECT to_regclass('public.registraion_networks_authorities') IS NOT NULL",
            &[],
        )?
        .try_get(0)?;
    let canonical_exists: bool = client
        .query_one(
            "SELECT to_regclass('public.registration_networks_authorities') IS NOT NULL",
            &[],
        )?
        .try_get(0)?;
    if legacy_exists && !canonical_exists {
        client.batch_execute(
            "ALTER TABLE registraion_networks_authorities
             RENAME TO registration_networks_authorities",
        )?;
    } else if legacy_exists && canonical_exists {
        bail!(
            "both legacy registraion_networks_authorities and canonical registration_networks_authorities exist"
        );
    }
    Ok(())
}

fn migrate_authority_ids(client: &mut Client) -> Result<()> {
    let mut transaction = client.transaction()?;
    transaction.batch_execute(
        "ALTER TABLE registration_networks_authorities
             ADD COLUMN IF NOT EXISTS authority_id TEXT;
         ALTER TABLE registration_networks_authorities
             ALTER COLUMN authority_id SET DEFAULT gen_random_uuid()::text;
         UPDATE registration_networks_authorities
             SET authority_id = gen_random_uuid()::text
             WHERE authority_id IS NULL OR btrim(authority_id) = '';
         ALTER TABLE registration_networks_authorities
             ALTER COLUMN authority_id SET NOT NULL;
         CREATE UNIQUE INDEX IF NOT EXISTS registration_networks_authorities_network_id_unique
             ON registration_networks_authorities(network_id);
         DO $$
         DECLARE
             primary_key_name TEXT;
             primary_key_definition TEXT;
         BEGIN
             SELECT constraint_row.conname, pg_get_constraintdef(constraint_row.oid)
               INTO primary_key_name, primary_key_definition
               FROM pg_constraint AS constraint_row
              WHERE constraint_row.conrelid = 'registration_networks_authorities'::regclass
                AND constraint_row.contype = 'p';
             IF primary_key_definition IS DISTINCT FROM 'PRIMARY KEY (authority_id)' THEN
                 IF primary_key_name IS NOT NULL THEN
                     EXECUTE format(
                         'ALTER TABLE registration_networks_authorities DROP CONSTRAINT %I CASCADE',
                         primary_key_name
                     );
                 END IF;
                 ALTER TABLE registration_networks_authorities
                     ADD CONSTRAINT registration_networks_authorities_pkey
                     PRIMARY KEY (authority_id);
             END IF;
         END
         $$;
         DO $$
         BEGIN
             IF NOT EXISTS (
                 SELECT 1
                   FROM pg_constraint
                  WHERE conrelid = 'registration_signing_keys'::regclass
                    AND conname = 'registration_signing_keys_network_id_fkey'
             ) THEN
                 ALTER TABLE registration_signing_keys
                     ADD CONSTRAINT registration_signing_keys_network_id_fkey
                     FOREIGN KEY (network_id)
                     REFERENCES registration_networks_authorities(network_id)
                     ON DELETE CASCADE;
             END IF;
         END
         $$;
         CREATE TEMP TABLE watt_registry_migrated_credentials
             ON COMMIT DROP
             AS
             SELECT credentials.credential_id
               FROM registration_credentials AS credentials
               JOIN registration_networks_authorities AS authorities
                 ON authorities.network_id = credentials.network_id
              WHERE credentials.issuer_authority_id <> authorities.authority_id;
         UPDATE registration_credentials AS credentials
            SET issuer_authority_id = authorities.authority_id,
                status = CASE
                    WHEN credentials.status = 'active' THEN 'revoked'
                    ELSE credentials.status
                END,
                revoked_at_ms = CASE
                    WHEN credentials.status = 'active'
                    THEN COALESCE(credentials.revoked_at_ms, CURRENT_TIMESTAMP)
                    ELSE credentials.revoked_at_ms
                END,
                updated_at_ms = CURRENT_TIMESTAMP
           FROM registration_networks_authorities AS authorities
          WHERE authorities.network_id = credentials.network_id
            AND credentials.issuer_authority_id <> authorities.authority_id;
         UPDATE registration_agents AS agents
            SET status = 'disabled',
                disabled_at_ms = COALESCE(agents.disabled_at_ms, CURRENT_TIMESTAMP),
                updated_at_ms = CURRENT_TIMESTAMP
          WHERE agents.status = 'active'
            AND agents.credential_id IN (
                SELECT credential_id FROM watt_registry_migrated_credentials
            );
         UPDATE registration_node_agents AS links
            SET relation_status = 'disabled',
                disabled_at_ms = COALESCE(links.disabled_at_ms, CURRENT_TIMESTAMP),
                updated_at_ms = CURRENT_TIMESTAMP
           FROM registration_agents AS agents
          WHERE links.network_id = agents.network_id
            AND links.agent_did = agents.agent_did
            AND agents.credential_id IN (
                SELECT credential_id FROM watt_registry_migrated_credentials
            );
         UPDATE registration_requests AS requests
            SET status = 'rejected',
                review_note = 'credential issuer authority migrated; registration must be resubmitted',
                updated_at_ms = CURRENT_TIMESTAMP
          WHERE requests.status IN ('approved', 'disabled')
            AND requests.request_id IN (
                SELECT credentials.request_id
                  FROM registration_credentials AS credentials
                 WHERE credentials.credential_id IN (
                     SELECT credential_id FROM watt_registry_migrated_credentials
                 )
            );
         DO $$
         BEGIN
             IF NOT EXISTS (
                 SELECT 1
                   FROM pg_constraint
                  WHERE conrelid = 'registration_credentials'::regclass
                    AND conname = 'registration_credentials_issuer_authority_id_fkey'
             ) THEN
                 ALTER TABLE registration_credentials
                     ADD CONSTRAINT registration_credentials_issuer_authority_id_fkey
                     FOREIGN KEY (issuer_authority_id)
                     REFERENCES registration_networks_authorities(authority_id);
             END IF;
         END
         $$;",
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_timestamp_columns(client: &mut Client) -> Result<()> {
    for &(table, column) in TIMESTAMP_COLUMNS {
        let data_type: String = client
            .query_one(
                "SELECT udt_name
                 FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = $1
                   AND column_name = $2",
                &[&table, &column],
            )?
            .try_get(0)?;
        match data_type.as_str() {
            "int8" => {
                let statement = format!(
                    "ALTER TABLE {table} ALTER COLUMN {column} TYPE TIMESTAMPTZ \
                     USING to_timestamp({column} / 1000.0)"
                );
                client.batch_execute(&statement)?;
            }
            "timestamptz" => {}
            other => bail!("unsupported type {other} for timestamp column {table}.{column}"),
        }
    }
    Ok(())
}

fn drop_duplicate_credential_columns(client: &mut Client) -> Result<()> {
    client.batch_execute(
        "ALTER TABLE registration_requests DROP COLUMN IF EXISTS credential_json;
         ALTER TABLE registration_agents DROP COLUMN IF EXISTS credential_json;",
    )?;
    Ok(())
}

fn timestamp_from_ms(value: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(value)
}

fn ms_from_timestamp(value: SystemTime) -> Result<u64> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .context("registry timestamp is before the Unix epoch")?;
    u64::try_from(duration.as_millis()).context("registry timestamp exceeds u64 milliseconds")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

fn row_timestamp_ms(row: &Row, index: usize) -> Result<u64> {
    ms_from_timestamp(row.try_get::<_, SystemTime>(index)?)
}

fn row_optional_timestamp_ms(row: &Row, index: usize) -> Result<Option<u64>> {
    row.try_get::<_, Option<SystemTime>>(index)?
        .map(ms_from_timestamp)
        .transpose()
}

fn validate_non_empty_value(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn validate_authority_registration_mode(value: &str) -> Result<()> {
    match value {
        REGISTRATION_MODE_AUTO | REGISTRATION_MODE_MANUAL | REGISTRATION_MODE_DISABLED => Ok(()),
        other => bail!("unsupported registration mode '{other}'"),
    }
}

fn ensure_network_authority_postgres(
    client: &mut Client,
    config: &NetworkAuthorityConfig,
    now_ms: u64,
) -> Result<NetworkAuthorityRecord> {
    let mut transaction = client.transaction()?;
    let existing = get_network_authority_postgres(&mut transaction, &config.network_id)?;
    if let Some(existing) = existing.as_ref()
        && (existing.genesis_node_id != config.genesis_node_id
            || existing.signature_algorithm != config.signature_algorithm)
    {
        bail!(
            "network authority already exists with a different genesis node or signature algorithm"
        );
    }
    transaction.execute(
        "INSERT INTO registration_networks_authorities(
             network_id, genesis_node_id, active_signing_key_id, signature_algorithm,
             registration_mode, status, created_at_ms, updated_at_ms
         ) VALUES ($1, $2, $3, $4, $5, 'active', $6, $6)
         ON CONFLICT (network_id) DO NOTHING",
        &[
            &config.network_id,
            &config.genesis_node_id,
            &config.active_signing_key_id,
            &config.signature_algorithm,
            &config.registration_mode,
            &timestamp_from_ms(now_ms),
        ],
    )?;
    transaction.execute(
        "INSERT INTO registration_signing_keys(
             key_id, network_id, algorithm, public_key_hex, private_key_hex,
             status, created_at_ms
         ) VALUES ($1, $2, $3, $4, $5, 'active', $6)
         ON CONFLICT (key_id) DO NOTHING",
        &[
            &config.active_signing_key_id,
            &config.network_id,
            &config.signature_algorithm,
            &config.public_key_hex,
            &config.private_key_hex,
            &timestamp_from_ms(now_ms),
        ],
    )?;
    let key_row = transaction.query_one(
        "SELECT network_id, algorithm, public_key_hex, private_key_hex
         FROM registration_signing_keys WHERE key_id = $1",
        &[&config.active_signing_key_id],
    )?;
    let stored_network_id: String = key_row.try_get(0)?;
    let stored_algorithm: String = key_row.try_get(1)?;
    let stored_public_key: String = key_row.try_get(2)?;
    let stored_private_key: String = key_row.try_get(3)?;
    if stored_network_id != config.network_id
        || stored_algorithm != config.signature_algorithm
        || stored_public_key != config.public_key_hex
        || stored_private_key != config.private_key_hex
    {
        bail!("registration signing key already exists with different key material");
    }
    if existing.is_none() {
        transaction.execute(
            "UPDATE registration_networks_authorities
             SET active_signing_key_id = $2, updated_at_ms = $3
             WHERE network_id = $1",
            &[
                &config.network_id,
                &config.active_signing_key_id,
                &timestamp_from_ms(now_ms),
            ],
        )?;
    }
    let authority = get_network_authority_postgres(&mut transaction, &config.network_id)?
        .context("network authority disappeared during initialization")?;
    transaction.commit()?;
    Ok(authority)
}

fn ensure_network_authority_memory(
    state: &mut MemoryState,
    config: &NetworkAuthorityConfig,
    now_ms: u64,
) -> Result<NetworkAuthorityRecord> {
    if let Some(existing) = state.authorities.get(&config.network_id)
        && (existing.genesis_node_id != config.genesis_node_id
            || existing.signature_algorithm != config.signature_algorithm)
    {
        bail!(
            "network authority already exists with a different genesis node or signature algorithm"
        );
    }
    state
        .authorities
        .entry(config.network_id.clone())
        .or_insert_with(|| NetworkAuthorityRecord {
            authority_id: Uuid::new_v4().to_string(),
            network_id: config.network_id.clone(),
            genesis_node_id: config.genesis_node_id.clone(),
            active_signing_key_id: config.active_signing_key_id.clone(),
            signature_algorithm: config.signature_algorithm.clone(),
            registration_mode: config.registration_mode.clone(),
            status: "active".to_owned(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        });
    if let Some(key) = state.signing_keys.get(&config.active_signing_key_id)
        && (key.network_id != config.network_id
            || key.algorithm != config.signature_algorithm
            || key.public_key_hex != config.public_key_hex
            || key.private_key_hex != config.private_key_hex)
    {
        bail!("registration signing key already exists with different key material");
    }
    state
        .signing_keys
        .entry(config.active_signing_key_id.clone())
        .or_insert_with(|| RegistrationSigningKeyRecord {
            key_id: config.active_signing_key_id.clone(),
            network_id: config.network_id.clone(),
            algorithm: config.signature_algorithm.clone(),
            public_key_hex: config.public_key_hex.clone(),
            private_key_hex: config.private_key_hex.clone(),
            status: "active".to_owned(),
            created_at_ms: now_ms,
            retired_at_ms: None,
        });
    state
        .authorities
        .get(&config.network_id)
        .cloned()
        .context("network authority disappeared during initialization")
}

fn initialize_or_rotate_network_authority_postgres(
    client: &mut Client,
    config: &NetworkAuthorityConfig,
    now_ms: u64,
) -> Result<NetworkAuthorityInitializationResult> {
    let mut transaction = client.transaction()?;
    let existing = get_network_authority_postgres(&mut transaction, &config.network_id)?;
    let authority_changed = existing.as_ref().is_some_and(|authority| {
        authority.genesis_node_id != config.genesis_node_id
            || authority.active_signing_key_id != config.active_signing_key_id
            || authority.signature_algorithm != config.signature_algorithm
    });
    let timestamp = timestamp_from_ms(now_ms);

    if existing.is_none() {
        transaction.execute(
            "INSERT INTO registration_networks_authorities(
                 network_id, genesis_node_id, active_signing_key_id, signature_algorithm,
                 registration_mode, status, created_at_ms, updated_at_ms
             ) VALUES ($1, $2, $3, $4, $5, 'active', $6, $6)",
            &[
                &config.network_id,
                &config.genesis_node_id,
                &config.active_signing_key_id,
                &config.signature_algorithm,
                &config.registration_mode,
                &timestamp,
            ],
        )?;
    }

    if let Some(existing_key) =
        get_signing_key_postgres(&mut transaction, &config.active_signing_key_id)?
    {
        if existing_key.network_id != config.network_id
            || existing_key.algorithm != config.signature_algorithm
            || existing_key.public_key_hex != config.public_key_hex
            || existing_key.private_key_hex != config.private_key_hex
        {
            bail!("registration signing key already exists with different key material");
        }
        transaction.execute(
            "UPDATE registration_signing_keys
             SET status = 'active', retired_at_ms = NULL
             WHERE key_id = $1",
            &[&config.active_signing_key_id],
        )?;
    } else {
        transaction.execute(
            "INSERT INTO registration_signing_keys(
                 key_id, network_id, algorithm, public_key_hex, private_key_hex,
                 status, created_at_ms
             ) VALUES ($1, $2, $3, $4, $5, 'active', $6)",
            &[
                &config.active_signing_key_id,
                &config.network_id,
                &config.signature_algorithm,
                &config.public_key_hex,
                &config.private_key_hex,
                &timestamp,
            ],
        )?;
    }

    transaction.execute(
        "UPDATE registration_signing_keys
         SET status = 'retired', retired_at_ms = $3
         WHERE network_id = $1 AND key_id <> $2 AND status = 'active'",
        &[
            &config.network_id,
            &config.active_signing_key_id,
            &timestamp,
        ],
    )?;
    transaction.execute(
        "UPDATE registration_networks_authorities
         SET genesis_node_id = $2,
             active_signing_key_id = $3,
             signature_algorithm = $4,
             status = 'active',
             updated_at_ms = $5
         WHERE network_id = $1",
        &[
            &config.network_id,
            &config.genesis_node_id,
            &config.active_signing_key_id,
            &config.signature_algorithm,
            &timestamp,
        ],
    )?;

    let (revoked_credentials, disabled_agents, disabled_node_agents) = if authority_changed {
        let revoked_credentials = transaction.execute(
            "UPDATE registration_credentials
             SET status = 'revoked', revoked_at_ms = $2, updated_at_ms = $2
             WHERE network_id = $1 AND status = 'active'",
            &[&config.network_id, &timestamp],
        )?;
        let disabled_agents = transaction.execute(
            "UPDATE registration_agents
             SET status = 'disabled', disabled_at_ms = $2, updated_at_ms = $2
             WHERE network_id = $1 AND status = 'active'",
            &[&config.network_id, &timestamp],
        )?;
        let disabled_node_agents = transaction.execute(
            "UPDATE registration_node_agents
             SET relation_status = 'disabled', disabled_at_ms = $2, updated_at_ms = $2
             WHERE network_id = $1 AND relation_status = 'active'",
            &[&config.network_id, &timestamp],
        )?;
        (revoked_credentials, disabled_agents, disabled_node_agents)
    } else {
        (0, 0, 0)
    };

    let authority = get_network_authority_postgres(&mut transaction, &config.network_id)?
        .context("network authority disappeared during initialization")?;
    let signing_key = get_active_signing_key_postgres(&mut transaction, &config.network_id)?
        .context("active signing key disappeared during initialization")?;
    transaction.commit()?;
    Ok(NetworkAuthorityInitializationResult {
        authority,
        signing_key,
        revoked_credentials,
        disabled_agents,
        disabled_node_agents,
    })
}

fn initialize_or_rotate_network_authority_memory(
    state: &mut MemoryState,
    config: &NetworkAuthorityConfig,
    now_ms: u64,
) -> Result<NetworkAuthorityInitializationResult> {
    let authority_changed = state
        .authorities
        .get(&config.network_id)
        .is_some_and(|authority| {
            authority.genesis_node_id != config.genesis_node_id
                || authority.active_signing_key_id != config.active_signing_key_id
                || authority.signature_algorithm != config.signature_algorithm
        });
    state
        .authorities
        .entry(config.network_id.clone())
        .or_insert_with(|| NetworkAuthorityRecord {
            authority_id: Uuid::new_v4().to_string(),
            network_id: config.network_id.clone(),
            genesis_node_id: config.genesis_node_id.clone(),
            active_signing_key_id: config.active_signing_key_id.clone(),
            signature_algorithm: config.signature_algorithm.clone(),
            registration_mode: config.registration_mode.clone(),
            status: "active".to_owned(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        });

    if let Some(existing_key) = state.signing_keys.get(&config.active_signing_key_id)
        && (existing_key.network_id != config.network_id
            || existing_key.algorithm != config.signature_algorithm
            || existing_key.public_key_hex != config.public_key_hex
            || existing_key.private_key_hex != config.private_key_hex)
    {
        bail!("registration signing key already exists with different key material");
    }
    state
        .signing_keys
        .entry(config.active_signing_key_id.clone())
        .or_insert_with(|| RegistrationSigningKeyRecord {
            key_id: config.active_signing_key_id.clone(),
            network_id: config.network_id.clone(),
            algorithm: config.signature_algorithm.clone(),
            public_key_hex: config.public_key_hex.clone(),
            private_key_hex: config.private_key_hex.clone(),
            status: "active".to_owned(),
            created_at_ms: now_ms,
            retired_at_ms: None,
        });
    if let Some(key) = state.signing_keys.get_mut(&config.active_signing_key_id) {
        key.status = "active".to_owned();
        key.retired_at_ms = None;
    }
    for key in state.signing_keys.values_mut() {
        if key.network_id == config.network_id
            && key.key_id != config.active_signing_key_id
            && key.status == "active"
        {
            key.status = "retired".to_owned();
            key.retired_at_ms = Some(now_ms);
        }
    }
    let authority = state
        .authorities
        .get_mut(&config.network_id)
        .context("network authority disappeared during initialization")?;
    authority.genesis_node_id = config.genesis_node_id.clone();
    authority.active_signing_key_id = config.active_signing_key_id.clone();
    authority.signature_algorithm = config.signature_algorithm.clone();
    authority.status = "active".to_owned();
    authority.updated_at_ms = now_ms;

    let mut revoked_credentials = 0;
    let mut disabled_agents = 0;
    let mut disabled_node_agents = 0;
    if authority_changed {
        for credential in state.credentials.values_mut() {
            if credential.network_id == config.network_id && credential.status == "active" {
                credential.status = "revoked".to_owned();
                credential.revoked_at_ms = Some(now_ms);
                credential.updated_at_ms = now_ms;
                revoked_credentials += 1;
            }
        }
        for agent in state.agents.values_mut() {
            if agent.network_id == config.network_id
                && agent.status == RegistrationAgentStatus::Active
            {
                agent.status = RegistrationAgentStatus::Disabled;
                agent.disabled_at_ms = Some(now_ms);
                agent.updated_at_ms = now_ms;
                disabled_agents += 1;
            }
        }
        for node_agent in state.node_agents.values_mut() {
            if node_agent.network_id == config.network_id
                && node_agent.relation_status == NodeAgentRelationStatus::Active
            {
                node_agent.relation_status = NodeAgentRelationStatus::Disabled;
                node_agent.disabled_at_ms = Some(now_ms);
                node_agent.updated_at_ms = now_ms;
                disabled_node_agents += 1;
            }
        }
    }
    let authority = state
        .authorities
        .get(&config.network_id)
        .cloned()
        .context("network authority disappeared during initialization")?;
    let signing_key = state
        .signing_keys
        .get(&config.active_signing_key_id)
        .cloned()
        .context("active signing key disappeared during initialization")?;
    Ok(NetworkAuthorityInitializationResult {
        authority,
        signing_key,
        revoked_credentials,
        disabled_agents,
        disabled_node_agents,
    })
}

fn get_network_authority_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
) -> Result<Option<NetworkAuthorityRecord>> {
    client
        .query_opt(
            "SELECT authority_id, network_id, genesis_node_id, active_signing_key_id,
                    signature_algorithm, registration_mode, status,
                    created_at_ms, updated_at_ms
             FROM registration_networks_authorities WHERE network_id = $1",
            &[&network_id],
        )?
        .map(|row| network_authority_from_row(&row))
        .transpose()
}

fn list_network_authorities_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
) -> Result<Vec<NetworkAuthorityRecord>> {
    client
        .query(
            "SELECT authority_id, network_id, genesis_node_id, active_signing_key_id,
                    signature_algorithm, registration_mode, status,
                    created_at_ms, updated_at_ms
             FROM registration_networks_authorities
             ORDER BY network_id",
            &[],
        )?
        .iter()
        .map(network_authority_from_row)
        .collect()
}

fn network_authority_from_row(row: &Row) -> Result<NetworkAuthorityRecord> {
    Ok(NetworkAuthorityRecord {
        authority_id: row.try_get(0)?,
        network_id: row.try_get(1)?,
        genesis_node_id: row.try_get(2)?,
        active_signing_key_id: row.try_get(3)?,
        signature_algorithm: row.try_get(4)?,
        registration_mode: row.try_get(5)?,
        status: row.try_get(6)?,
        created_at_ms: row_timestamp_ms(row, 7)?,
        updated_at_ms: row_timestamp_ms(row, 8)?,
    })
}

fn get_active_signing_key_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
) -> Result<Option<RegistrationSigningKeyRecord>> {
    client
        .query_opt(
            "SELECT keys.key_id, keys.network_id, keys.algorithm,
                    keys.public_key_hex, keys.private_key_hex, keys.status,
                    keys.created_at_ms, keys.retired_at_ms
             FROM registration_signing_keys AS keys
             JOIN registration_networks_authorities AS authorities
               ON authorities.active_signing_key_id = keys.key_id
              AND authorities.network_id = keys.network_id
             WHERE keys.network_id = $1 AND keys.status = 'active'",
            &[&network_id],
        )?
        .map(|row| {
            Ok(RegistrationSigningKeyRecord {
                key_id: row.try_get(0)?,
                network_id: row.try_get(1)?,
                algorithm: row.try_get(2)?,
                public_key_hex: row.try_get(3)?,
                private_key_hex: row.try_get(4)?,
                status: row.try_get(5)?,
                created_at_ms: row_timestamp_ms(&row, 6)?,
                retired_at_ms: row_optional_timestamp_ms(&row, 7)?,
            })
        })
        .transpose()
}

fn get_signing_key_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    key_id: &str,
) -> Result<Option<RegistrationSigningKeyRecord>> {
    client
        .query_opt(
            "SELECT key_id, network_id, algorithm,
                    public_key_hex, private_key_hex, status,
                    created_at_ms, retired_at_ms
             FROM registration_signing_keys WHERE key_id = $1",
            &[&key_id],
        )?
        .map(|row| {
            Ok(RegistrationSigningKeyRecord {
                key_id: row.try_get(0)?,
                network_id: row.try_get(1)?,
                algorithm: row.try_get(2)?,
                public_key_hex: row.try_get(3)?,
                private_key_hex: row.try_get(4)?,
                status: row.try_get(5)?,
                created_at_ms: row_timestamp_ms(&row, 6)?,
                retired_at_ms: row_optional_timestamp_ms(&row, 7)?,
            })
        })
        .transpose()
}

fn insert_postgres(
    client: &mut Client,
    request: &RegistrationRequest,
    nickname_key: &str,
    request_json: &str,
    status: RegistrationStatus,
    registration_mode: &str,
    now_ms: u64,
) -> Result<RegistrationRecord> {
    if let Some(existing) = client.query_opt(
        "SELECT request_json FROM registration_requests WHERE request_id = $1",
        &[&request.request_id],
    )? {
        let existing_json: String = existing.try_get(0)?;
        if existing_json != request_json {
            bail!("request_id already stores a different registration request");
        }
        return load_record_postgres(client, &request.request_id)?
            .context("stored request disappeared");
    }
    if let Some(existing) =
        load_current_request_for_agent_postgres(client, &request.network_id, &request.agent_did)?
    {
        return Ok(existing);
    }

    let status_value = status_string(status);
    if let Err(error) = client.execute(
        "INSERT INTO registration_requests(
             request_id, network_id, agent_did, nickname, nickname_key, tenant_instance_id, nonce,
             request_json, registration_mode, status, submitted_at_ms, updated_at_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)",
        &[
            &request.request_id,
            &request.network_id,
            &request.agent_did,
            &request.nickname,
            &nickname_key,
            &request.tenant_instance_id,
            &request.nonce,
            &request_json,
            &registration_mode,
            &status_value,
            &timestamp_from_ms(now_ms),
        ],
    ) {
        if error
            .as_db_error()
            .and_then(|database_error| database_error.constraint())
            == Some("registration_agent_active_unique")
            && let Some(existing) = load_current_request_for_agent_postgres(
                client,
                &request.network_id,
                &request.agent_did,
            )?
        {
            return Ok(existing);
        }
        return Err(map_insert_error(error));
    }
    load_record_postgres(client, &request.request_id)?.context("inserted request is missing")
}

fn insert_memory(
    records: &mut BTreeMap<String, RegistrationRecord>,
    request: &RegistrationRequest,
    nickname_key: &str,
    request_json: &str,
    status: RegistrationStatus,
    registration_mode: &str,
    now_ms: u64,
) -> Result<RegistrationRecord> {
    if let Some(existing) = records.get(&request.request_id) {
        if serde_json::to_string(&existing.request)? != request_json {
            bail!("request_id already stores a different registration request");
        }
        return Ok(existing.clone());
    }
    if let Some(existing) = records.values().find(|existing| {
        existing.request.network_id == request.network_id
            && existing.request.agent_did == request.agent_did
            && is_active(existing.status)
    }) {
        return Ok(existing.clone());
    }
    for existing in records.values() {
        if existing.request.network_id == request.network_id
            && is_active(existing.status)
            && normalize_nickname(&existing.request.nickname)
                .ok()
                .as_deref()
                == Some(nickname_key)
        {
            bail!("agent or nickname already has an active registration");
        }
        if existing.request.network_id == request.network_id
            && existing.request.nonce == request.nonce
        {
            bail!("registration nonce is already used in this network");
        }
    }
    let record = RegistrationRecord {
        request: request.clone(),
        status,
        registration_mode: registration_mode.to_owned(),
        credential: None,
        decision: None,
        submitted_at_ms: now_ms,
        updated_at_ms: now_ms,
        reviewer_id: None,
        reviewed_at_ms: None,
        review_note: None,
    };
    records.insert(request.request_id.clone(), record.clone());
    Ok(record)
}

fn load_current_request_for_agent_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    agent_did: &str,
) -> Result<Option<RegistrationRecord>> {
    let request_id = client
        .query_opt(
            "SELECT request_id
             FROM registration_requests
             WHERE network_id = $1
               AND agent_did = $2
               AND status IN ('draft', 'pending', 'approved', 'disabled')
             ORDER BY updated_at_ms DESC
             LIMIT 1",
            &[&network_id, &agent_did],
        )?
        .map(|row| row.get::<_, String>(0));
    request_id
        .map(|request_id| {
            load_record_postgres(client, &request_id)?.context("current registration disappeared")
        })
        .transpose()
}

fn submit_draft_postgres(
    client: &mut Client,
    request_id: &str,
    now_ms: u64,
) -> Result<Option<RegistrationRecord>> {
    let Some(current) = load_record_postgres(client, request_id)? else {
        return Ok(None);
    };
    match current.status {
        RegistrationStatus::Draft => {
            client.execute(
                "UPDATE registration_requests
                 SET status = 'pending', submitted_at_ms = $2, updated_at_ms = $2
                 WHERE request_id = $1 AND status = 'draft'",
                &[&request_id, &timestamp_from_ms(now_ms)],
            )?;
            load_record_postgres(client, request_id)
        }
        RegistrationStatus::Pending => Ok(Some(current)),
        _ => bail!("registration cannot be submitted from its current state"),
    }
}

fn submit_draft_memory(
    records: &mut BTreeMap<String, RegistrationRecord>,
    request_id: &str,
    now_ms: u64,
) -> Result<Option<RegistrationRecord>> {
    let Some(record) = records.get_mut(request_id) else {
        return Ok(None);
    };
    match record.status {
        RegistrationStatus::Draft => {
            record.status = RegistrationStatus::Pending;
            record.submitted_at_ms = now_ms;
            record.updated_at_ms = now_ms;
            Ok(Some(record.clone()))
        }
        RegistrationStatus::Pending => Ok(Some(record.clone())),
        _ => bail!("registration cannot be submitted from its current state"),
    }
}

fn list_postgres(
    client: &mut Client,
    network_id: Option<&str>,
    status: Option<RegistrationStatus>,
    limit: usize,
) -> Result<Vec<RegistrationRecord>> {
    let network_id = network_id.map(str::to_owned);
    let status = status.map(status_string).map(str::to_owned);
    let rows = client.query(
        "SELECT requests.request_json, requests.registration_mode, requests.status,
                (SELECT credentials.credential_json
                 FROM registration_credentials AS credentials
                 WHERE credentials.request_id = requests.request_id
                 ORDER BY credentials.issued_at_ms DESC, credentials.credential_id DESC
                 LIMIT 1),
                requests.decision_json,
                submitted_at_ms, updated_at_ms, reviewer_id, reviewed_at_ms, review_note
         FROM registration_requests AS requests
         WHERE ($1::TEXT IS NULL OR requests.network_id = $1)
           AND ($2::TEXT IS NULL OR requests.status = $2)
         ORDER BY requests.submitted_at_ms DESC, requests.request_id ASC
         LIMIT $3",
        &[&network_id, &status, &(limit as i64)],
    )?;
    rows.iter().map(row_to_record).collect()
}

fn list_memory(
    records: &BTreeMap<String, RegistrationRecord>,
    network_id: Option<&str>,
    status: Option<RegistrationStatus>,
    limit: usize,
) -> Result<Vec<RegistrationRecord>> {
    let mut records = records
        .values()
        .filter(|record| {
            network_id.is_none_or(|network| record.request.network_id == network)
                && status.is_none_or(|expected| record.status == expected)
        })
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        right
            .submitted_at_ms
            .cmp(&left.submitted_at_ms)
            .then_with(|| left.request.request_id.cmp(&right.request.request_id))
    });
    records.truncate(limit);
    Ok(records)
}

fn transition_postgres(
    client: &mut Client,
    request_id: &str,
    action: RegistrationDecisionKind,
    decision: &RegistrationDecision,
    credential: Option<&MembershipCredential>,
    now_ms: u64,
) -> Result<RegistrationRecord> {
    let mut transaction = client.transaction()?;
    let current = load_record_postgres_for_update(&mut transaction, request_id)?
        .context("registration not found")?;
    let next_status = next_status(current.status, action)?;
    validate_transition(
        &current,
        request_id,
        action,
        next_status,
        decision,
        credential,
    )?;
    let decision_json = serde_json::to_string(decision)?;
    let reviewer_id = decision.unsigned.reviewer_id.clone();
    let review_note = decision.unsigned.review_note.clone();
    let updated = transaction.execute(
        "UPDATE registration_requests
         SET status = $2, decision_json = $3,
             reviewer_id = $4, reviewed_at_ms = $5, review_note = $6, updated_at_ms = $8
         WHERE request_id = $1 AND status = $7",
        &[
            &request_id,
            &status_string(next_status),
            &decision_json,
            &reviewer_id,
            &timestamp_from_ms(decision.unsigned.reviewed_at_ms),
            &review_note,
            &status_string(current.status),
            &timestamp_from_ms(now_ms),
        ],
    )?;
    if updated == 0 {
        return load_record_postgres(&mut transaction, request_id)?
            .context("registration disappeared");
    }
    match next_status {
        RegistrationStatus::Approved => {
            let credential = credential.context("approved registration requires a credential")?;
            insert_credential_postgres(&mut transaction, &current.request, credential, now_ms)?;
            upsert_agent_postgres(
                &mut transaction,
                &current.request,
                &current.registration_mode,
                credential,
                RegistrationAgentStatus::Active,
                current.submitted_at_ms,
                now_ms,
            )?;
            activate_node_agent_links_postgres(
                &mut transaction,
                &current.request.network_id,
                &current.request.agent_did,
                now_ms,
            )?;
        }
        RegistrationStatus::Disabled => {
            revoke_credentials_postgres(
                &mut transaction,
                &current.request.network_id,
                &current.request.agent_did,
                now_ms,
            )?;
            update_agent_status_postgres(
                &mut transaction,
                &current.request.network_id,
                &current.request.agent_did,
                RegistrationAgentStatus::Disabled,
                now_ms,
            )?;
            disable_node_agent_links_postgres(
                &mut transaction,
                &current.request.network_id,
                &current.request.agent_did,
                now_ms,
            )?;
        }
        RegistrationStatus::Draft | RegistrationStatus::Pending | RegistrationStatus::Rejected => {}
    }
    let record = load_record_postgres(&mut transaction, request_id)?
        .context("updated registration is missing")?;
    transaction.commit()?;
    Ok(record)
}

fn transition_memory(
    state: &mut MemoryState,
    request_id: &str,
    next_status: RegistrationStatus,
    decision: &RegistrationDecision,
    credential: Option<&MembershipCredential>,
    now_ms: u64,
) -> Result<RegistrationRecord> {
    let mut record = state
        .requests
        .get(request_id)
        .cloned()
        .context("registration disappeared")?;
    record.status = next_status;
    if credential.is_some() {
        record.credential = credential.cloned();
    }
    record.decision = Some(decision.clone());
    record.reviewer_id = decision.unsigned.reviewer_id.clone();
    record.reviewed_at_ms = Some(decision.unsigned.reviewed_at_ms);
    record.review_note = decision.unsigned.review_note.clone();
    record.updated_at_ms = now_ms;
    if next_status == RegistrationStatus::Approved {
        let credential = record
            .credential
            .as_ref()
            .context("approved registration is missing membership credential")?;
        let signature_algorithm = credential
            .unsigned
            .signature_algorithm
            .clone()
            .unwrap_or_else(|| "ed25519".to_owned());
        let signing_key_id = credential
            .unsigned
            .signing_key_id
            .clone()
            .unwrap_or_else(|| credential.unsigned.issuer_authority_id.clone());
        state.credentials.insert(
            credential.unsigned.credential_id.clone(),
            RegistrationCredentialRecord {
                credential_id: credential.unsigned.credential_id.clone(),
                request_id: record.request.request_id.clone(),
                network_id: record.request.network_id.clone(),
                agent_did: record.request.agent_did.clone(),
                issuer_authority_id: credential.unsigned.issuer_authority_id.clone(),
                signing_key_id,
                signature_algorithm,
                credential: credential.clone(),
                status: "active".to_owned(),
                issued_at_ms: credential.unsigned.issued_at_ms,
                expires_at_ms: credential.unsigned.expires_at_ms,
                revoked_at_ms: None,
                created_at_ms: now_ms,
                updated_at_ms: now_ms,
            },
        );
        let agent = RegistrationAgentRecord {
            request_id: record.request.request_id.clone(),
            network_id: record.request.network_id.clone(),
            agent_did: record.request.agent_did.clone(),
            nickname: record.request.nickname.clone(),
            nickname_key: normalize_nickname(&record.request.nickname)
                .map_err(anyhow::Error::msg)?,
            tenant_instance_id: record.request.tenant_instance_id.clone(),
            registration_mode: record.registration_mode.clone(),
            credential_id: credential.unsigned.credential_id.clone(),
            agent_card: record.request.agent_card.clone(),
            agent_card_hash: record.request.agent_card_hash.clone(),
            agent_card_updated_at_ms: record.request.agent_card.as_ref().map(|_| now_ms),
            status: RegistrationAgentStatus::Active,
            registered_at_ms: state
                .agents
                .get(&(
                    record.request.network_id.clone(),
                    record.request.agent_did.clone(),
                ))
                .map(|existing| existing.registered_at_ms)
                .unwrap_or(record.submitted_at_ms),
            updated_at_ms: now_ms,
            disabled_at_ms: None,
        };
        state
            .agents
            .insert((agent.network_id.clone(), agent.agent_did.clone()), agent);
        for link in state.node_agents.values_mut().filter(|link| {
            link.network_id == record.request.network_id
                && link.agent_did == record.request.agent_did
        }) {
            link.relation_status = NodeAgentRelationStatus::Active;
            link.updated_at_ms = now_ms;
            link.disabled_at_ms = None;
        }
    } else if next_status == RegistrationStatus::Disabled {
        let key = (
            record.request.network_id.clone(),
            record.request.agent_did.clone(),
        );
        let agent = state
            .agents
            .get_mut(&key)
            .context("disabled registration is missing registered agent")?;
        agent.status = RegistrationAgentStatus::Disabled;
        agent.updated_at_ms = now_ms;
        agent.disabled_at_ms = Some(now_ms);
        for credential in state.credentials.values_mut().filter(|credential| {
            credential.network_id == record.request.network_id
                && credential.agent_did == record.request.agent_did
                && credential.status == "active"
        }) {
            credential.status = "revoked".to_owned();
            credential.revoked_at_ms = Some(now_ms);
            credential.updated_at_ms = now_ms;
        }
        for link in state.node_agents.values_mut().filter(|link| {
            link.network_id == record.request.network_id
                && link.agent_did == record.request.agent_did
        }) {
            link.relation_status = NodeAgentRelationStatus::Disabled;
            link.updated_at_ms = now_ms;
            link.disabled_at_ms = Some(now_ms);
        }
    }
    state.requests.insert(request_id.to_owned(), record.clone());
    Ok(record.clone())
}

fn invalidate_legacy_agents_postgres(client: &mut Client) -> Result<()> {
    // Existing credentials were signed by the previous Genesis authority. They
    // are deliberately not copied into registration_credentials; every Agent
    // must receive a new credential from the current authority.
    client.execute(
        "UPDATE registration_agents AS agents
         SET status = 'disabled',
             disabled_at_ms = COALESCE(agents.disabled_at_ms, CURRENT_TIMESTAMP),
             updated_at_ms = CURRENT_TIMESTAMP
         WHERE agents.status = 'active'
           AND NOT EXISTS (
               SELECT 1
               FROM registration_credentials AS credentials
               WHERE credentials.credential_id = agents.credential_id
           )",
        &[],
    )?;
    client.execute(
        "UPDATE registration_node_agents AS links
         SET relation_status = 'disabled',
             disabled_at_ms = COALESCE(links.disabled_at_ms, CURRENT_TIMESTAMP),
             updated_at_ms = CURRENT_TIMESTAMP
         WHERE links.relation_status = 'active'
           AND EXISTS (
               SELECT 1
               FROM registration_agents AS agents
               WHERE agents.network_id = links.network_id
                 AND agents.agent_did = links.agent_did
                 AND agents.status = 'disabled'
           )",
        &[],
    )?;
    // Release the old request's active uniqueness slots. The request row is
    // retained as audit history, but it must no longer block a fresh request
    // after the Genesis authority rotation.
    client.execute(
        "UPDATE registration_requests AS requests
         SET status = 'rejected',
             review_note = 'membership credential invalidated by Genesis authority rotation; re-registration required',
             updated_at_ms = CURRENT_TIMESTAMP
         WHERE requests.status IN ('approved', 'disabled')
           AND NOT EXISTS (
               SELECT 1
               FROM registration_credentials AS credentials
               WHERE credentials.request_id = requests.request_id
           )",
        &[],
    )?;
    Ok(())
}

fn insert_credential_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    request: &RegistrationRequest,
    credential: &MembershipCredential,
    now_ms: u64,
) -> Result<()> {
    let credential_json = serde_json::to_string(credential)?;
    let signature_algorithm = credential
        .unsigned
        .signature_algorithm
        .as_deref()
        .unwrap_or("ed25519");
    let signing_key_id = credential
        .unsigned
        .signing_key_id
        .as_deref()
        .unwrap_or(&credential.unsigned.issuer_authority_id);
    let issued_at_ms = credential.unsigned.issued_at_ms;
    let expires_at = credential.unsigned.expires_at_ms.map(timestamp_from_ms);
    client.execute(
        "INSERT INTO registration_credentials(
             credential_id, request_id, network_id, agent_did, issuer_authority_id,
             signing_key_id, signature_algorithm, credential_json, signature_hex,
             status, issued_at_ms, expires_at_ms, created_at_ms, updated_at_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11, $12, $12)
         ON CONFLICT (credential_id) DO UPDATE SET
             request_id = EXCLUDED.request_id,
             network_id = EXCLUDED.network_id,
             agent_did = EXCLUDED.agent_did,
             issuer_authority_id = EXCLUDED.issuer_authority_id,
             signing_key_id = EXCLUDED.signing_key_id,
             signature_algorithm = EXCLUDED.signature_algorithm,
             credential_json = EXCLUDED.credential_json,
             signature_hex = EXCLUDED.signature_hex,
             status = 'active',
             expires_at_ms = EXCLUDED.expires_at_ms,
             revoked_at_ms = NULL,
             updated_at_ms = EXCLUDED.updated_at_ms",
        &[
            &credential.unsigned.credential_id,
            &request.request_id,
            &request.network_id,
            &request.agent_did,
            &credential.unsigned.issuer_authority_id,
            &signing_key_id,
            &signature_algorithm,
            &credential_json,
            &credential.signature_hex,
            &timestamp_from_ms(issued_at_ms),
            &expires_at,
            &timestamp_from_ms(now_ms),
        ],
    )?;
    Ok(())
}

fn revoke_credentials_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    agent_did: &str,
    now_ms: u64,
) -> Result<()> {
    client.execute(
        "UPDATE registration_credentials
         SET status = 'revoked', revoked_at_ms = $3, updated_at_ms = $3
         WHERE network_id = $1 AND agent_did = $2 AND status = 'active'",
        &[&network_id, &agent_did, &timestamp_from_ms(now_ms)],
    )?;
    Ok(())
}

fn upsert_agent_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    request: &RegistrationRequest,
    registration_mode: &str,
    credential: &MembershipCredential,
    status: RegistrationAgentStatus,
    registered_at_ms: u64,
    updated_at_ms: u64,
) -> Result<RegistrationAgentRecord> {
    let nickname_key = normalize_nickname(&request.nickname).map_err(anyhow::Error::msg)?;
    let disabled_at_ms = match status {
        RegistrationAgentStatus::Active => None,
        RegistrationAgentStatus::Disabled => Some(timestamp_from_ms(updated_at_ms)),
    };
    client.execute(
        "INSERT INTO registration_agents(
             request_id, network_id, agent_did, nickname, nickname_key, tenant_instance_id,
             registration_mode, credential_id,
             agent_card_json, agent_card_hash, agent_card_updated_at_ms,
             status, registered_at_ms, updated_at_ms, disabled_at_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         ON CONFLICT (network_id, agent_did) DO UPDATE SET
             request_id = EXCLUDED.request_id,
             nickname = EXCLUDED.nickname,
             nickname_key = EXCLUDED.nickname_key,
             tenant_instance_id = EXCLUDED.tenant_instance_id,
             registration_mode = EXCLUDED.registration_mode,
             credential_id = EXCLUDED.credential_id,
             agent_card_json = COALESCE(EXCLUDED.agent_card_json, registration_agents.agent_card_json),
             agent_card_hash = COALESCE(EXCLUDED.agent_card_hash, registration_agents.agent_card_hash),
             agent_card_updated_at_ms = COALESCE(
                 EXCLUDED.agent_card_updated_at_ms,
                 registration_agents.agent_card_updated_at_ms
             ),
             status = EXCLUDED.status,
             updated_at_ms = EXCLUDED.updated_at_ms,
             disabled_at_ms = EXCLUDED.disabled_at_ms",
        &[
            &request.request_id,
            &request.network_id,
            &request.agent_did,
            &request.nickname,
            &nickname_key,
            &request.tenant_instance_id,
            &registration_mode,
            &credential.unsigned.credential_id,
            &optional_json(request.agent_card.as_ref())?,
            &request.agent_card_hash,
            &request
                .agent_card
                .as_ref()
                .map(|_| timestamp_from_ms(updated_at_ms)),
            &agent_status_string(status),
            &timestamp_from_ms(registered_at_ms),
            &timestamp_from_ms(updated_at_ms),
            &disabled_at_ms,
        ],
    )?;
    load_agent_postgres(client, &request.network_id, &request.agent_did)?
        .context("upserted registration agent is missing")
}

fn update_agent_status_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    agent_did: &str,
    status: RegistrationAgentStatus,
    now_ms: u64,
) -> Result<()> {
    let disabled_at_ms = match status {
        RegistrationAgentStatus::Active => None,
        RegistrationAgentStatus::Disabled => Some(timestamp_from_ms(now_ms)),
    };
    let updated = client.execute(
        "UPDATE registration_agents
         SET status = $3, updated_at_ms = $4, disabled_at_ms = $5
         WHERE network_id = $1 AND agent_did = $2",
        &[
            &network_id,
            &agent_did,
            &agent_status_string(status),
            &timestamp_from_ms(now_ms),
            &disabled_at_ms,
        ],
    )?;
    if updated == 0 {
        bail!("registered agent is missing for {network_id}/{agent_did}");
    }
    Ok(())
}

fn get_agent_postgres(
    client: &mut Client,
    network_id: &str,
    agent_did: &str,
) -> Result<Option<RegistrationAgentRecord>> {
    client
        .query_opt(
            "SELECT network_id, agent_did, nickname, nickname_key,
                    request_id,
                    tenant_instance_id, registration_mode,
                    credential_id, agent_card_json, agent_card_hash, agent_card_updated_at_ms,
                    status,
                    registered_at_ms, updated_at_ms, disabled_at_ms
             FROM registration_agents
             WHERE network_id = $1 AND agent_did = $2",
            &[&network_id, &agent_did],
        )?
        .map(|row| row_to_agent(&row))
        .transpose()
}

fn get_credential_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    credential_id: &str,
) -> Result<Option<RegistrationCredentialRecord>> {
    client
        .query_opt(
            "SELECT credential_id, request_id, network_id, agent_did,
                    issuer_authority_id, signing_key_id, signature_algorithm,
                    credential_json, status, issued_at_ms, expires_at_ms,
                    revoked_at_ms, created_at_ms, updated_at_ms
             FROM registration_credentials WHERE credential_id = $1",
            &[&credential_id],
        )?
        .map(|row| row_to_credential(&row))
        .transpose()
}

fn list_agents_postgres(
    client: &mut Client,
    network_id: Option<&str>,
    status: Option<RegistrationAgentStatus>,
    limit: usize,
) -> Result<Vec<RegistrationAgentRecord>> {
    let network_id = network_id.map(str::to_owned);
    let status = status.map(agent_status_string).map(str::to_owned);
    let rows = client.query(
        "SELECT network_id, agent_did, nickname, nickname_key,
                request_id,
                tenant_instance_id, registration_mode,
                credential_id, agent_card_json, agent_card_hash, agent_card_updated_at_ms,
                status,
                registered_at_ms, updated_at_ms, disabled_at_ms
         FROM registration_agents
         WHERE ($1::TEXT IS NULL OR network_id = $1)
           AND ($2::TEXT IS NULL OR status = $2)
         ORDER BY registered_at_ms DESC, agent_did ASC
         LIMIT $3",
        &[&network_id, &status, &(limit as i64)],
    )?;
    rows.iter().map(row_to_agent).collect()
}

fn list_agents_memory(
    agents: &BTreeMap<(String, String), RegistrationAgentRecord>,
    network_id: Option<&str>,
    status: Option<RegistrationAgentStatus>,
    limit: usize,
) -> Result<Vec<RegistrationAgentRecord>> {
    let mut agents = agents
        .values()
        .filter(|agent| {
            network_id.is_none_or(|network| agent.network_id == network)
                && status.is_none_or(|expected| agent.status == expected)
        })
        .cloned()
        .collect::<Vec<_>>();
    agents.sort_by(|left, right| {
        right
            .registered_at_ms
            .cmp(&left.registered_at_ms)
            .then_with(|| left.agent_did.cmp(&right.agent_did))
    });
    agents.truncate(limit);
    Ok(agents)
}

fn load_record_postgres_for_update<C: GenericClient + ?Sized>(
    client: &mut C,
    request_id: &str,
) -> Result<Option<RegistrationRecord>> {
    client
        .query_opt(
            "SELECT requests.request_json, requests.registration_mode, requests.status,
                    (SELECT credentials.credential_json
                     FROM registration_credentials AS credentials
                     WHERE credentials.request_id = requests.request_id
                     ORDER BY credentials.issued_at_ms DESC, credentials.credential_id DESC
                     LIMIT 1),
                    requests.decision_json,
                    submitted_at_ms, updated_at_ms, reviewer_id, reviewed_at_ms, review_note
             FROM registration_requests AS requests
             WHERE requests.request_id = $1 FOR UPDATE",
            &[&request_id],
        )?
        .map(|row| row_to_record(&row))
        .transpose()
}

fn load_agent_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    agent_did: &str,
) -> Result<Option<RegistrationAgentRecord>> {
    client
        .query_opt(
            "SELECT network_id, agent_did, nickname, nickname_key,
                    request_id,
                    tenant_instance_id, registration_mode,
                    credential_id, agent_card_json, agent_card_hash, agent_card_updated_at_ms,
                    status,
                    registered_at_ms, updated_at_ms, disabled_at_ms
             FROM registration_agents
             WHERE network_id = $1 AND agent_did = $2",
            &[&network_id, &agent_did],
        )?
        .map(|row| row_to_agent(&row))
        .transpose()
}

fn row_to_agent(row: &Row) -> Result<RegistrationAgentRecord> {
    let agent_card = row
        .try_get::<_, Option<String>>(8)?
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .context("decode registered Agent Card")?;
    Ok(RegistrationAgentRecord {
        request_id: row.try_get(4)?,
        network_id: row.try_get(0)?,
        agent_did: row.try_get(1)?,
        nickname: row.try_get(2)?,
        nickname_key: row.try_get(3)?,
        tenant_instance_id: row.try_get(5)?,
        registration_mode: row.try_get(6)?,
        credential_id: row.try_get(7)?,
        agent_card,
        agent_card_hash: row.try_get(9)?,
        agent_card_updated_at_ms: row_optional_timestamp_ms(row, 10)?,
        status: parse_agent_status(row.try_get::<_, String>(11)?.as_str())?,
        registered_at_ms: row_timestamp_ms(row, 12)?,
        updated_at_ms: row_timestamp_ms(row, 13)?,
        disabled_at_ms: row_optional_timestamp_ms(row, 14)?,
    })
}

fn upsert_discovery_node_memory(
    state: &mut MemoryState,
    record: &SignedDiscoveryNodeRecord,
    now_ms: u64,
) -> Result<RegistrationNodeRecord> {
    let key = (record.body.network_id.clone(), record.body.node_id.clone());
    if let Some(existing) = state.nodes.get(&key)
        && !is_newer_discovery_record(&existing.record, record)
    {
        return Ok(existing.clone());
    }
    let existing = state.nodes.get(&key).cloned();
    let node = RegistrationNodeRecord {
        network_id: record.body.network_id.clone(),
        node_id: record.body.node_id.clone(),
        signing_public_key_hex: record.body.signing_public_key_hex.clone(),
        record: record.clone(),
        status: RegistrationNodeStatus::Active,
        first_seen_at_ms: existing
            .as_ref()
            .map(|node| node.first_seen_at_ms)
            .unwrap_or(now_ms),
        last_seen_at_ms: now_ms,
        created_at_ms: existing
            .as_ref()
            .map(|node| node.created_at_ms)
            .unwrap_or(now_ms),
        updated_at_ms: now_ms,
    };
    state.nodes.insert(key.clone(), node.clone());
    sync_discovered_agent_link_memory(state, record, now_ms)?;
    Ok(node)
}

fn sync_discovered_agent_link_memory(
    state: &mut MemoryState,
    record: &SignedDiscoveryNodeRecord,
    now_ms: u64,
) -> Result<()> {
    let Some(details) = source_agent_details(record)? else {
        return Ok(());
    };
    let key = (
        record.body.network_id.clone(),
        record.body.node_id.clone(),
        details.agent_did.clone(),
    );
    let existing = state.node_agents.get(&key).cloned();
    let relation_status = match state
        .agents
        .get(&(record.body.network_id.clone(), details.agent_did.clone()))
    {
        Some(agent) => match agent.status {
            RegistrationAgentStatus::Active => NodeAgentRelationStatus::Active,
            RegistrationAgentStatus::Disabled => NodeAgentRelationStatus::Disabled,
        },
        None => NodeAgentRelationStatus::Pending,
    };
    if let Some(agent) = state
        .agents
        .get_mut(&(record.body.network_id.clone(), details.agent_did.clone()))
    {
        agent.agent_card = Some(details.card);
        agent.agent_card_hash = details.card_hash;
        agent.agent_card_updated_at_ms = Some(now_ms);
        agent.updated_at_ms = now_ms;
    }
    let link = RegistrationNodeAgentRecord {
        network_id: record.body.network_id.clone(),
        node_id: record.body.node_id.clone(),
        agent_did: details.agent_did,
        relation_status,
        first_seen_at_ms: existing
            .as_ref()
            .map(|link| link.first_seen_at_ms)
            .unwrap_or(now_ms),
        last_seen_at_ms: now_ms,
        created_at_ms: existing
            .as_ref()
            .map(|link| link.created_at_ms)
            .unwrap_or(now_ms),
        updated_at_ms: now_ms,
        disabled_at_ms: if relation_status == NodeAgentRelationStatus::Disabled {
            Some(now_ms)
        } else {
            None
        },
    };
    state.node_agents.insert(key, link);
    Ok(())
}

fn upsert_discovery_node_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    record: &SignedDiscoveryNodeRecord,
    now_ms: u64,
) -> Result<RegistrationNodeRecord> {
    if let Some(existing) = client.query_opt(
        "SELECT record_seq, record_updated_at_ms
         FROM registration_nodes
         WHERE network_id = $1 AND node_id = $2",
        &[&record.body.network_id, &record.body.node_id],
    )? {
        let existing_seq: i64 = existing.try_get(0)?;
        let existing_updated_at = row_timestamp_ms(&existing, 1)?;
        if !is_newer_discovery_record_values(
            existing_seq.max(0) as u64,
            existing_updated_at,
            record,
        ) {
            return get_node_postgres(client, &record.body.network_id, &record.body.node_id)?
                .context("stored discovery node disappeared");
        }
    }
    let body = &record.body;
    let geo_json = optional_json(body.geo.as_ref())?;
    let capabilities_json = serde_json::to_string(&body.capabilities)?;
    let topic_providers_json = serde_json::to_string(&body.topic_providers)?;
    let transport_contact_json = optional_json(body.transport_contact.as_ref())?;
    let source_agent_card_json = optional_json(body.source_agent_card.as_ref())?;
    let discovery_record_json = serde_json::to_string(record)?;
    client.execute(
        "INSERT INTO registration_nodes(
             network_id, node_id, signing_public_key_hex, protocol_version,
             record_seq, record_updated_at_ms, ttl_ms, record_expires_at_ms,
             geo_json, capabilities_json, topic_providers_json,
             transport_contact_json, source_agent_card_json, discovery_record_json,
             record_signature_hex, first_seen_at_ms, last_seen_at_ms,
             created_at_ms, updated_at_ms, status
         ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
             $11, $12, $13, $14, $15, $16, $16, $16, $16, 'active'
         )
         ON CONFLICT (network_id, node_id) DO UPDATE SET
             signing_public_key_hex = EXCLUDED.signing_public_key_hex,
             protocol_version = EXCLUDED.protocol_version,
             record_seq = EXCLUDED.record_seq,
             record_updated_at_ms = EXCLUDED.record_updated_at_ms,
             ttl_ms = EXCLUDED.ttl_ms,
             record_expires_at_ms = EXCLUDED.record_expires_at_ms,
             geo_json = EXCLUDED.geo_json,
             capabilities_json = EXCLUDED.capabilities_json,
             topic_providers_json = EXCLUDED.topic_providers_json,
             transport_contact_json = EXCLUDED.transport_contact_json,
             source_agent_card_json = EXCLUDED.source_agent_card_json,
             discovery_record_json = EXCLUDED.discovery_record_json,
             record_signature_hex = EXCLUDED.record_signature_hex,
             last_seen_at_ms = EXCLUDED.last_seen_at_ms,
             updated_at_ms = EXCLUDED.updated_at_ms,
             status = 'active'",
        &[
            &body.network_id,
            &body.node_id,
            &body.signing_public_key_hex,
            &body.protocol_version,
            &(body.seq as i64),
            &timestamp_from_ms(body.updated_at_ms),
            &(body.ttl_ms as i64),
            &timestamp_from_ms(body.expires_at_ms()),
            &geo_json,
            &capabilities_json,
            &topic_providers_json,
            &transport_contact_json,
            &source_agent_card_json,
            &discovery_record_json,
            &record.signature_hex,
            &timestamp_from_ms(now_ms),
        ],
    )?;
    sync_discovered_agent_link_postgres(client, record, now_ms)?;
    get_node_postgres(client, &body.network_id, &body.node_id)?
        .context("upserted discovery node is missing")
}

fn sync_discovered_agent_link_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    record: &SignedDiscoveryNodeRecord,
    now_ms: u64,
) -> Result<()> {
    let Some(details) = source_agent_details(record)? else {
        return Ok(());
    };
    let relation_status = match client.query_opt(
        "SELECT status
         FROM registration_agents
         WHERE network_id = $1 AND agent_did = $2",
        &[&record.body.network_id, &details.agent_did],
    )? {
        Some(row) => {
            let status: String = row.try_get(0)?;
            match status.as_str() {
                "active" => "active",
                "disabled" => "disabled",
                _ => "pending",
            }
        }
        None => "pending",
    };
    let card_json = serde_json::to_string(&details.card)?;
    client.execute(
        "UPDATE registration_agents
         SET agent_card_json = $3,
             agent_card_hash = $4,
             agent_card_updated_at_ms = $5,
             updated_at_ms = $5
         WHERE network_id = $1 AND agent_did = $2",
        &[
            &record.body.network_id,
            &details.agent_did,
            &card_json,
            &details.card_hash,
            &timestamp_from_ms(now_ms),
        ],
    )?;
    client.execute(
        "INSERT INTO registration_node_agents(
             network_id, node_id, agent_did,
             relation_status,
             first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms,
             disabled_at_ms
         ) VALUES ($1, $2, $3, $4, $5, $5, $5, $5, $6)
         ON CONFLICT (network_id, node_id, agent_did) DO UPDATE SET
             relation_status = EXCLUDED.relation_status,
             last_seen_at_ms = EXCLUDED.last_seen_at_ms,
             updated_at_ms = EXCLUDED.updated_at_ms,
             disabled_at_ms = EXCLUDED.disabled_at_ms",
        &[
            &record.body.network_id,
            &record.body.node_id,
            &details.agent_did,
            &relation_status,
            &timestamp_from_ms(now_ms),
            &((relation_status == "disabled").then(|| timestamp_from_ms(now_ms))),
        ],
    )?;
    Ok(())
}

fn activate_node_agent_links_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    agent_did: &str,
    now_ms: u64,
) -> Result<()> {
    client.execute(
        "UPDATE registration_node_agents AS links
         SET relation_status = 'active',
             updated_at_ms = $3,
             disabled_at_ms = NULL
         FROM registration_agents AS agents
         WHERE links.network_id = $1 AND links.agent_did = $2
           AND agents.network_id = links.network_id
           AND agents.agent_did = links.agent_did
           AND agents.status = 'active'
           AND links.relation_status <> 'revoked'",
        &[&network_id, &agent_did, &timestamp_from_ms(now_ms)],
    )?;
    Ok(())
}

fn disable_node_agent_links_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    agent_did: &str,
    now_ms: u64,
) -> Result<()> {
    client.execute(
        "UPDATE registration_node_agents
         SET relation_status = 'disabled', updated_at_ms = $3, disabled_at_ms = $3
         WHERE network_id = $1 AND agent_did = $2 AND relation_status <> 'revoked'",
        &[&network_id, &agent_did, &timestamp_from_ms(now_ms)],
    )?;
    Ok(())
}

fn expire_discovery_nodes_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    now_ms: u64,
) -> Result<()> {
    let now = timestamp_from_ms(now_ms);
    client.execute(
        "UPDATE registration_nodes
         SET status = 'revoked', updated_at_ms = $1
         WHERE status = 'active' AND record_expires_at_ms <= $1",
        &[&now],
    )?;
    client.execute(
        "UPDATE registration_node_agents AS links
         SET relation_status = 'revoked', updated_at_ms = $1
         WHERE links.relation_status = 'active'
           AND EXISTS (
               SELECT 1
               FROM registration_nodes AS nodes
               WHERE nodes.network_id = links.network_id
                 AND nodes.node_id = links.node_id
                 AND nodes.status = 'revoked'
           )",
        &[&now],
    )?;
    Ok(())
}

fn expire_discovery_nodes_memory(state: &mut MemoryState, now_ms: u64) {
    let expired = state
        .nodes
        .values_mut()
        .filter(|node| {
            node.status == RegistrationNodeStatus::Active
                && node.record.body.expires_at_ms() <= now_ms
        })
        .map(|node| {
            node.status = RegistrationNodeStatus::Revoked;
            node.updated_at_ms = now_ms;
            (node.network_id.clone(), node.node_id.clone())
        })
        .collect::<Vec<_>>();
    for (network_id, node_id) in expired {
        for link in state.node_agents.values_mut().filter(|link| {
            link.network_id == network_id
                && link.node_id == node_id
                && link.relation_status == NodeAgentRelationStatus::Active
        }) {
            link.relation_status = NodeAgentRelationStatus::Revoked;
            link.updated_at_ms = now_ms;
        }
    }
}

fn get_node_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    network_id: &str,
    node_id: &str,
) -> Result<Option<RegistrationNodeRecord>> {
    client
        .query_opt(
            "SELECT network_id, node_id, signing_public_key_hex,
                    discovery_record_json, status,
                    first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms
             FROM registration_nodes
             WHERE network_id = $1 AND node_id = $2
               AND status = 'active'
               AND record_expires_at_ms > CURRENT_TIMESTAMP",
            &[&network_id, &node_id],
        )?
        .map(|row| row_to_node(&row))
        .transpose()
}

fn list_nodes_postgres(
    client: &mut Client,
    network_id: Option<&str>,
    status: Option<RegistrationNodeStatus>,
    limit: usize,
) -> Result<Vec<RegistrationNodeRecord>> {
    let network_id = network_id.map(str::to_owned);
    let status = status
        .map(node_status_string)
        .map(str::to_owned)
        .unwrap_or_else(|| "active".to_owned());
    let rows = client.query(
        "SELECT network_id, node_id, signing_public_key_hex,
                discovery_record_json, status,
                first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms
         FROM registration_nodes
         WHERE ($1::TEXT IS NULL OR network_id = $1)
           AND status = $2
           AND (status <> 'active' OR record_expires_at_ms > CURRENT_TIMESTAMP)
           AND (
               status <> 'active'
               OR source_agent_card_json IS NULL
               OR EXISTS (
                   SELECT 1
                   FROM registration_node_agents AS links
                   JOIN registration_agents AS agents
                     ON agents.network_id = links.network_id
                    AND agents.agent_did = links.agent_did
                   JOIN registration_credentials AS credentials
                     ON credentials.credential_id = agents.credential_id
                    AND credentials.network_id = agents.network_id
                    AND credentials.agent_did = agents.agent_did
                   WHERE links.network_id = registration_nodes.network_id
                     AND links.node_id = registration_nodes.node_id
                     AND links.relation_status = 'active'
                     AND agents.status = 'active'
                     AND credentials.status = 'active'
                     AND (
                         credentials.expires_at_ms IS NULL
                         OR credentials.expires_at_ms > CURRENT_TIMESTAMP
                     )
               )
           )
         ORDER BY last_seen_at_ms DESC, node_id ASC
         LIMIT $3",
        &[&network_id, &status, &(limit as i64)],
    )?;
    rows.iter().map(row_to_node).collect()
}

fn list_nodes_memory(
    nodes: &BTreeMap<(String, String), RegistrationNodeRecord>,
    node_agents: &BTreeMap<(String, String, String), RegistrationNodeAgentRecord>,
    agents: &BTreeMap<(String, String), RegistrationAgentRecord>,
    credentials: &BTreeMap<String, RegistrationCredentialRecord>,
    network_id: Option<&str>,
    status: Option<RegistrationNodeStatus>,
    limit: usize,
) -> Result<Vec<RegistrationNodeRecord>> {
    let expected_status = status.unwrap_or(RegistrationNodeStatus::Active);
    let mut nodes = nodes
        .values()
        .filter(|node| {
            if network_id.is_some_and(|network| node.network_id != network)
                || node.status != expected_status
            {
                return false;
            }
            if expected_status != RegistrationNodeStatus::Active {
                return true;
            }
            if node.record.body.expires_at_ms() <= now_ms() {
                return false;
            }
            let Some(card) = node.record.body.source_agent_card.as_ref() else {
                return true;
            };
            let Some(agent_did) = card.get("agent_id").and_then(Value::as_str) else {
                return false;
            };
            node_agents.values().any(|link| {
                link.network_id == node.network_id
                    && link.node_id == node.node_id
                    && link.agent_did == agent_did
                    && link.relation_status == NodeAgentRelationStatus::Active
                    && agents
                        .get(&(node.network_id.clone(), agent_did.to_owned()))
                        .is_some_and(|agent| {
                            agent.status == RegistrationAgentStatus::Active
                                && credentials
                                    .get(&agent.credential_id)
                                    .is_some_and(|credential| {
                                        credential.status == "active"
                                            && credential
                                                .expires_at_ms
                                                .is_none_or(|expires_at| expires_at > now_ms())
                                    })
                        })
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| {
        right
            .last_seen_at_ms
            .cmp(&left.last_seen_at_ms)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    nodes.truncate(limit);
    Ok(nodes)
}

fn list_node_agents_postgres(
    client: &mut Client,
    network_id: &str,
    node_id: &str,
    limit: usize,
    visible_only: bool,
) -> Result<Vec<RegistrationNodeAgentRecord>> {
    let relation_status = visible_only.then_some("active");
    let rows = client.query(
        "SELECT network_id, node_id, agent_did, relation_status,
                first_seen_at_ms, last_seen_at_ms, created_at_ms, updated_at_ms,
                disabled_at_ms
         FROM registration_node_agents
         WHERE network_id = $1 AND node_id = $2
           AND ($4::TEXT IS NULL OR relation_status = $4)
           AND ($4::TEXT IS NULL OR EXISTS (
               SELECT 1
               FROM registration_nodes AS nodes
               JOIN registration_agents AS agents
                 ON agents.network_id = registration_node_agents.network_id
                AND agents.agent_did = registration_node_agents.agent_did
               JOIN registration_credentials AS credentials
                 ON credentials.credential_id = agents.credential_id
                AND credentials.network_id = agents.network_id
                AND credentials.agent_did = agents.agent_did
               WHERE nodes.network_id = registration_node_agents.network_id
                 AND nodes.node_id = registration_node_agents.node_id
                 AND nodes.status = 'active'
                 AND nodes.record_expires_at_ms > CURRENT_TIMESTAMP
                 AND agents.status = 'active'
                 AND credentials.status = 'active'
                 AND (
                     credentials.expires_at_ms IS NULL
                     OR credentials.expires_at_ms > CURRENT_TIMESTAMP
                 )
           ))
         ORDER BY last_seen_at_ms DESC, agent_did ASC
         LIMIT $3",
        &[&network_id, &node_id, &(limit as i64), &relation_status],
    )?;
    rows.iter().map(row_to_node_agent).collect()
}

fn row_to_node(row: &Row) -> Result<RegistrationNodeRecord> {
    let record: SignedDiscoveryNodeRecord =
        serde_json::from_str(row.try_get(3)?).context("decode stored discovery node record")?;
    Ok(RegistrationNodeRecord {
        network_id: row.try_get(0)?,
        node_id: row.try_get(1)?,
        signing_public_key_hex: row.try_get(2)?,
        record,
        status: parse_node_status(row.try_get::<_, String>(4)?.as_str())?,
        first_seen_at_ms: row_timestamp_ms(row, 5)?,
        last_seen_at_ms: row_timestamp_ms(row, 6)?,
        created_at_ms: row_timestamp_ms(row, 7)?,
        updated_at_ms: row_timestamp_ms(row, 8)?,
    })
}

fn row_to_credential(row: &Row) -> Result<RegistrationCredentialRecord> {
    let credential: MembershipCredential =
        serde_json::from_str(row.try_get::<_, String>(7)?.as_str())
            .context("decode stored registration credential")?;
    Ok(RegistrationCredentialRecord {
        credential_id: row.try_get(0)?,
        request_id: row.try_get(1)?,
        network_id: row.try_get(2)?,
        agent_did: row.try_get(3)?,
        issuer_authority_id: row.try_get(4)?,
        signing_key_id: row.try_get(5)?,
        signature_algorithm: row.try_get(6)?,
        credential,
        status: row.try_get(8)?,
        issued_at_ms: row_timestamp_ms(row, 9)?,
        expires_at_ms: row_optional_timestamp_ms(row, 10)?,
        revoked_at_ms: row_optional_timestamp_ms(row, 11)?,
        created_at_ms: row_timestamp_ms(row, 12)?,
        updated_at_ms: row_timestamp_ms(row, 13)?,
    })
}

fn row_to_node_agent(row: &Row) -> Result<RegistrationNodeAgentRecord> {
    Ok(RegistrationNodeAgentRecord {
        network_id: row.try_get(0)?,
        node_id: row.try_get(1)?,
        agent_did: row.try_get(2)?,
        relation_status: parse_node_agent_relation_status(row.try_get::<_, String>(3)?.as_str())?,
        first_seen_at_ms: row_timestamp_ms(row, 4)?,
        last_seen_at_ms: row_timestamp_ms(row, 5)?,
        created_at_ms: row_timestamp_ms(row, 6)?,
        updated_at_ms: row_timestamp_ms(row, 7)?,
        disabled_at_ms: row_optional_timestamp_ms(row, 8)?,
    })
}

#[derive(Debug)]
struct SourceAgentDetails {
    agent_did: String,
    card: Value,
    card_hash: Option<String>,
}

fn source_agent_details(record: &SignedDiscoveryNodeRecord) -> Result<Option<SourceAgentDetails>> {
    let Some(card) = record.body.source_agent_card.clone() else {
        return Ok(None);
    };
    let agent_did = card
        .get("agent_id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .context("source_agent_card.agent_id is required")?
        .to_owned();
    if let Some(card_node_id) = card.get("node_id").and_then(|value| value.as_str())
        && card_node_id != record.body.node_id
    {
        bail!("source_agent_card node_id must match discovery node_id");
    }
    let card_value = card
        .get("card")
        .cloned()
        .context("source_agent_card.card is required")?;
    Ok(Some(SourceAgentDetails {
        agent_did,
        card_hash: card
            .get("card_hash")
            .and_then(|value| value.as_str())
            .map(str::to_owned),
        card: card_value,
    }))
}

fn optional_json(value: Option<&Value>) -> Result<Option<String>> {
    value
        .map(serde_json::to_string)
        .transpose()
        .map_err(Into::into)
}

fn is_newer_discovery_record(
    existing: &SignedDiscoveryNodeRecord,
    incoming: &SignedDiscoveryNodeRecord,
) -> bool {
    is_newer_discovery_record_values(existing.body.seq, existing.body.updated_at_ms, incoming)
}

fn is_newer_discovery_record_values(
    existing_seq: u64,
    existing_updated_at_ms: u64,
    incoming: &SignedDiscoveryNodeRecord,
) -> bool {
    incoming.body.seq > existing_seq
        || (incoming.body.seq == existing_seq
            && incoming.body.updated_at_ms > existing_updated_at_ms)
}

fn validate_transition(
    current: &RegistrationRecord,
    request_id: &str,
    action: RegistrationDecisionKind,
    next_status: RegistrationStatus,
    decision: &RegistrationDecision,
    credential: Option<&MembershipCredential>,
) -> Result<()> {
    if decision.unsigned.request_id != request_id
        || decision.unsigned.network_id != current.request.network_id
        || decision.unsigned.agent_did != current.request.agent_did
        || decision.unsigned.action != action
        || decision.unsigned.status != next_status
    {
        bail!("signed registration decision does not match the stored request");
    }
    if matches!(next_status, RegistrationStatus::Approved) && credential.is_none() {
        bail!("approved registration requires a membership credential");
    }
    if credential.is_some_and(|credential| {
        credential.unsigned.network_id != current.request.network_id
            || credential.unsigned.agent_did != current.request.agent_did
    }) {
        bail!("membership credential does not match the stored request");
    }
    Ok(())
}

fn load_record_postgres<C: GenericClient + ?Sized>(
    client: &mut C,
    request_id: &str,
) -> Result<Option<RegistrationRecord>> {
    client
        .query_opt(
            "SELECT requests.request_json, requests.registration_mode, requests.status,
                    (SELECT credentials.credential_json
                     FROM registration_credentials AS credentials
                     WHERE credentials.request_id = requests.request_id
                     ORDER BY credentials.issued_at_ms DESC, credentials.credential_id DESC
                     LIMIT 1),
                    requests.decision_json,
                    submitted_at_ms, updated_at_ms, reviewer_id, reviewed_at_ms, review_note
             FROM registration_requests AS requests WHERE requests.request_id = $1",
            &[&request_id],
        )?
        .map(|row| row_to_record(&row))
        .transpose()
}

fn row_to_record(row: &Row) -> Result<RegistrationRecord> {
    let request_json: String = row.try_get(0)?;
    let registration_mode: String = row.try_get(1)?;
    let status: String = row.try_get(2)?;
    Ok(RegistrationRecord {
        request: serde_json::from_str(&request_json)
            .context("decode stored registration request")?,
        status: parse_status(&status)?,
        registration_mode,
        credential: parse_optional_json(row.try_get(3)?, "credential")?,
        decision: parse_optional_json(row.try_get(4)?, "decision")?,
        submitted_at_ms: row_timestamp_ms(row, 5)?,
        updated_at_ms: row_timestamp_ms(row, 6)?,
        reviewer_id: row.try_get(7)?,
        reviewed_at_ms: row_optional_timestamp_ms(row, 8)?,
        review_note: row.try_get(9)?,
    })
}

fn parse_optional_json<T: serde::de::DeserializeOwned>(
    value: Option<String>,
    label: &str,
) -> Result<Option<T>> {
    value
        .map(|value| serde_json::from_str(&value).with_context(|| format!("decode stored {label}")))
        .transpose()
}

fn parse_status(value: &str) -> Result<RegistrationStatus> {
    match value {
        "draft" => Ok(RegistrationStatus::Draft),
        "pending" => Ok(RegistrationStatus::Pending),
        "approved" => Ok(RegistrationStatus::Approved),
        "rejected" => Ok(RegistrationStatus::Rejected),
        "disabled" => Ok(RegistrationStatus::Disabled),
        other => bail!("unknown registration status '{other}'"),
    }
}

fn validate_registration_mode(value: &str) -> Result<()> {
    match value {
        REGISTRATION_MODE_AUTO | REGISTRATION_MODE_MANUAL => Ok(()),
        other => bail!("unsupported registration mode '{other}'"),
    }
}

fn agent_status_string(status: RegistrationAgentStatus) -> &'static str {
    match status {
        RegistrationAgentStatus::Active => "active",
        RegistrationAgentStatus::Disabled => "disabled",
    }
}

fn parse_agent_status(value: &str) -> Result<RegistrationAgentStatus> {
    match value {
        "active" => Ok(RegistrationAgentStatus::Active),
        "disabled" => Ok(RegistrationAgentStatus::Disabled),
        other => bail!("unknown registration agent status '{other}'"),
    }
}

fn node_status_string(status: RegistrationNodeStatus) -> &'static str {
    match status {
        RegistrationNodeStatus::Active => "active",
        RegistrationNodeStatus::Revoked => "revoked",
    }
}

fn parse_node_status(value: &str) -> Result<RegistrationNodeStatus> {
    match value {
        "active" => Ok(RegistrationNodeStatus::Active),
        "revoked" => Ok(RegistrationNodeStatus::Revoked),
        other => bail!("unknown registration node status '{other}'"),
    }
}

fn parse_node_agent_relation_status(value: &str) -> Result<NodeAgentRelationStatus> {
    match value {
        "pending" => Ok(NodeAgentRelationStatus::Pending),
        "active" => Ok(NodeAgentRelationStatus::Active),
        "disabled" => Ok(NodeAgentRelationStatus::Disabled),
        "revoked" => Ok(NodeAgentRelationStatus::Revoked),
        other => bail!("unknown node-agent relation status '{other}'"),
    }
}

fn map_insert_error(error: postgres::Error) -> anyhow::Error {
    let constraint = error
        .as_db_error()
        .and_then(|database_error| database_error.constraint())
        .unwrap_or_default()
        .to_owned();
    match constraint.as_str() {
        "registration_agent_active_unique" | "registration_nickname_active_unique" => {
            anyhow::anyhow!("agent or nickname already has an active registration")
        }
        "registration_nonce_unique" => {
            anyhow::anyhow!("registration nonce is already used in this network")
        }
        _ => error.into(),
    }
}

fn next_status(
    current: RegistrationStatus,
    action: RegistrationDecisionKind,
) -> Result<RegistrationStatus> {
    let next = match (current, action) {
        (RegistrationStatus::Draft, RegistrationDecisionKind::Approve)
        | (RegistrationStatus::Pending, RegistrationDecisionKind::Approve)
        | (RegistrationStatus::Disabled, RegistrationDecisionKind::Restore) => {
            RegistrationStatus::Approved
        }
        (RegistrationStatus::Draft, RegistrationDecisionKind::Reject)
        | (RegistrationStatus::Pending, RegistrationDecisionKind::Reject) => {
            RegistrationStatus::Rejected
        }
        (RegistrationStatus::Approved, RegistrationDecisionKind::Disable) => {
            RegistrationStatus::Disabled
        }
        _ => bail!("invalid registration state transition"),
    };
    Ok(next)
}

fn status_string(status: RegistrationStatus) -> &'static str {
    match status {
        RegistrationStatus::Draft => "draft",
        RegistrationStatus::Pending => "pending",
        RegistrationStatus::Approved => "approved",
        RegistrationStatus::Rejected => "rejected",
        RegistrationStatus::Disabled => "disabled",
    }
}

fn is_active(status: RegistrationStatus) -> bool {
    matches!(
        status,
        RegistrationStatus::Draft
            | RegistrationStatus::Pending
            | RegistrationStatus::Approved
            | RegistrationStatus::Disabled
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_protocol::{
        AuthorityKeyCertificate, BINARY_ENCODING_HEX, DISCOVERY_PROTOCOL_VERSION,
        DiscoveryNodeRecordBody, MembershipCredential, REGISTRATION_PROTOCOL_VERSION,
        RegistrationDecisionKind, RegistrationRequest, SIGNATURE_ALGORITHM_ED25519,
        SignedDiscoveryNodeRecord, UnsignedAuthorityKeyCertificate, UnsignedMembershipCredential,
        UnsignedRegistrationDecision,
    };
    use serde_json::json;

    fn request(id: &str, nickname: &str) -> RegistrationRequest {
        RegistrationRequest {
            version: REGISTRATION_PROTOCOL_VERSION,
            request_id: id.to_owned(),
            network_id: "network-1".to_owned(),
            agent_did: format!("did:key:{id}"),
            nickname: nickname.to_owned(),
            agent_card: None,
            agent_card_hash: None,
            tenant_instance_id: None,
            nonce: format!("nonce-{id}"),
            signature_b64: "signature".to_owned(),
        }
    }

    fn decision(
        request: &RegistrationRequest,
        action: RegistrationDecisionKind,
        status: RegistrationStatus,
        reviewed_at_ms: u64,
    ) -> RegistrationDecision {
        RegistrationDecision {
            unsigned: UnsignedRegistrationDecision {
                version: REGISTRATION_PROTOCOL_VERSION,
                request_id: request.request_id.clone(),
                network_id: request.network_id.clone(),
                agent_did: request.agent_did.clone(),
                action,
                status,
                reviewer_id: Some("operator".to_owned()),
                reviewed_at_ms,
                review_note: None,
                issuer_authority_id: "authority".to_owned(),
                signing_key_id: None,
                signature_algorithm: None,
            },
            signature_hex: "signature".to_owned(),
        }
    }

    fn credential(request: &RegistrationRequest, credential_id: &str) -> MembershipCredential {
        MembershipCredential {
            unsigned: UnsignedMembershipCredential {
                version: REGISTRATION_PROTOCOL_VERSION,
                credential_id: credential_id.to_owned(),
                network_id: request.network_id.clone(),
                agent_did: request.agent_did.clone(),
                issuer_authority_id: "authority".to_owned(),
                issued_at_ms: 20,
                expires_at_ms: None,
                signing_key_id: None,
                signature_algorithm: None,
                issuer_key_certificate: Some(AuthorityKeyCertificate {
                    unsigned: UnsignedAuthorityKeyCertificate {
                        version: REGISTRATION_PROTOCOL_VERSION,
                        network_id: request.network_id.clone(),
                        authority_id: "authority".to_owned(),
                        key_id: "key".to_owned(),
                        signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                        public_key_encoding: BINARY_ENCODING_HEX.to_owned(),
                        public_key: "public-key".to_owned(),
                        trust_anchor_id: "genesis".to_owned(),
                        issued_at_ms: 10,
                        expires_at_ms: None,
                    },
                    trust_anchor_signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                    trust_anchor_signature_encoding: BINARY_ENCODING_HEX.to_owned(),
                    trust_anchor_signature: "certificate-signature".to_owned(),
                }),
            },
            signature_hex: "signature".to_owned(),
        }
    }

    fn discovery_record(agent_did: &str, seq: u64) -> SignedDiscoveryNodeRecord {
        let node_id = "node-a".to_owned();
        SignedDiscoveryNodeRecord {
            body: DiscoveryNodeRecordBody {
                protocol_version: DISCOVERY_PROTOCOL_VERSION.to_owned(),
                network_id: "network-1".to_owned(),
                node_id,
                signing_public_key_hex: "node-a-public-key".to_owned(),
                seq,
                updated_at_ms: 1_000 + seq,
                ttl_ms: 5_000,
                geo: None,
                capabilities: json!({"services": ["wattswarm.node"]}),
                topic_providers: Vec::new(),
                transport_contact: Some(json!({"peer_id": "node-a"})),
                source_agent_card: Some(json!({
                    "agent_id": agent_did,
                    "node_id": "node-a",
                    "card_hash": "sha256:test",
                    "issued_at": 1_000,
                    "card": {"name": "Test Agent"},
                })),
            },
            signature_hex: "signature".to_owned(),
        }
    }

    #[test]
    fn status_transitions_store_reviewer_note_and_are_idempotent_at_read_level() {
        let store = RegistryStore::open_in_memory().expect("store");
        let request = request("one", "Agent One");
        store
            .insert_request(&request, RegistrationStatus::Pending, "manual", 10)
            .expect("insert");
        let decision = RegistrationDecision {
            unsigned: UnsignedRegistrationDecision {
                version: REGISTRATION_PROTOCOL_VERSION,
                request_id: request.request_id.clone(),
                network_id: request.network_id.clone(),
                agent_did: request.agent_did.clone(),
                action: RegistrationDecisionKind::Reject,
                status: RegistrationStatus::Rejected,
                reviewer_id: Some("operator".to_owned()),
                reviewed_at_ms: 20,
                review_note: Some("not approved yet".to_owned()),
                issuer_authority_id: "authority".to_owned(),
                signing_key_id: None,
                signature_algorithm: None,
            },
            signature_hex: "signature".to_owned(),
        };
        let record = store
            .transition(
                &request.request_id,
                RegistrationDecisionKind::Reject,
                &decision,
                None,
                20,
            )
            .expect("reject");
        assert_eq!(record.status, RegistrationStatus::Rejected);
        assert_eq!(record.reviewer_id.as_deref(), Some("operator"));
        assert_eq!(record.review_note.as_deref(), Some("not approved yet"));
        assert_eq!(
            store
                .list(None, Some(RegistrationStatus::Rejected), 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn active_nickname_is_unique_per_network_but_rejected_nickname_can_retry() {
        let store = RegistryStore::open_in_memory().expect("store");
        let first = request("one", "Agent One");
        store
            .insert_request(&first, RegistrationStatus::Pending, "manual", 10)
            .expect("first insert");

        let mut duplicate = request("two", " @AGENT   ONE ");
        duplicate.agent_did = "did:key:two".to_owned();
        let error = store
            .insert_request(&duplicate, RegistrationStatus::Pending, "manual", 11)
            .expect_err("duplicate nickname must fail");
        assert!(error.to_string().contains("active registration"));

        let decision = RegistrationDecision {
            unsigned: UnsignedRegistrationDecision {
                version: REGISTRATION_PROTOCOL_VERSION,
                request_id: first.request_id.clone(),
                network_id: first.network_id.clone(),
                agent_did: first.agent_did.clone(),
                action: RegistrationDecisionKind::Reject,
                status: RegistrationStatus::Rejected,
                reviewer_id: Some("operator".to_owned()),
                reviewed_at_ms: 12,
                review_note: Some("retry later".to_owned()),
                issuer_authority_id: "authority".to_owned(),
                signing_key_id: None,
                signature_algorithm: None,
            },
            signature_hex: "signature".to_owned(),
        };
        store
            .transition(
                &first.request_id,
                RegistrationDecisionKind::Reject,
                &decision,
                None,
                12,
            )
            .expect("reject first request");
        store
            .insert_request(&duplicate, RegistrationStatus::Pending, "manual", 13)
            .expect("rejected nickname can retry");
    }

    #[test]
    fn active_agent_submission_returns_current_request_but_rejected_agent_can_retry() {
        let store = RegistryStore::open_in_memory().expect("store");
        let first = request("one", "Agent One");
        store
            .insert_request(&first, RegistrationStatus::Pending, "manual", 10)
            .expect("first insert");

        let mut retry_while_pending = request("two", "Agent Renamed");
        retry_while_pending.agent_did.clone_from(&first.agent_did);
        let existing = store
            .insert_request(
                &retry_while_pending,
                RegistrationStatus::Pending,
                "manual",
                11,
            )
            .expect("pending retry returns current request");
        assert_eq!(existing.request.request_id, first.request_id);
        assert_eq!(store.list(None, None, 10).unwrap().len(), 1);

        let rejection = decision(
            &first,
            RegistrationDecisionKind::Reject,
            RegistrationStatus::Rejected,
            12,
        );
        store
            .transition(
                &first.request_id,
                RegistrationDecisionKind::Reject,
                &rejection,
                None,
                12,
            )
            .expect("reject first request");

        let replacement = store
            .insert_request(
                &retry_while_pending,
                RegistrationStatus::Pending,
                "manual",
                13,
            )
            .expect("rejected agent can submit a new request");
        assert_eq!(
            replacement.request.request_id,
            retry_while_pending.request_id
        );
        assert_eq!(store.list(None, None, 10).unwrap().len(), 2);
    }

    #[test]
    fn network_authority_and_active_signing_key_are_persisted_separately() {
        let store = RegistryStore::open_in_memory().expect("store");
        let authority = store
            .ensure_network_authority(
                &NetworkAuthorityConfig {
                    network_id: "network-1".to_owned(),
                    genesis_node_id: "genesis-public-key".to_owned(),
                    active_signing_key_id: "key-1".to_owned(),
                    signature_algorithm: "ed25519".to_owned(),
                    public_key_hex: "signing-public-key".to_owned(),
                    private_key_hex: "signing-private-key".to_owned(),
                    registration_mode: "manual".to_owned(),
                },
                10,
            )
            .expect("authority initialization");
        assert_eq!(authority.genesis_node_id, "genesis-public-key");
        assert_eq!(authority.active_signing_key_id, "key-1");
        Uuid::parse_str(&authority.authority_id).expect("authority ID is a UUID");
        assert_eq!(
            store.list_network_authorities().expect("authority list"),
            vec![authority.clone()]
        );
        let key = store
            .get_active_signing_key("network-1")
            .expect("signing key lookup")
            .expect("active signing key");
        assert_eq!(key.public_key_hex, "signing-public-key");
        assert_eq!(key.private_key_hex, "signing-private-key");

        let error = store
            .ensure_network_authority(
                &NetworkAuthorityConfig {
                    network_id: "network-1".to_owned(),
                    genesis_node_id: "another-genesis".to_owned(),
                    active_signing_key_id: "key-2".to_owned(),
                    signature_algorithm: "ed25519".to_owned(),
                    public_key_hex: "another-public-key".to_owned(),
                    private_key_hex: "another-private-key".to_owned(),
                    registration_mode: "manual".to_owned(),
                },
                20,
            )
            .expect_err("authority identity cannot change implicitly");
        assert!(error.to_string().contains("different genesis node"));
    }

    #[test]
    fn authority_initialization_rotates_key_and_invalidates_membership_state() {
        let store = RegistryStore::open_in_memory().expect("store");
        store
            .ensure_network_authority(
                &NetworkAuthorityConfig {
                    network_id: "network-1".to_owned(),
                    genesis_node_id: "genesis-old".to_owned(),
                    active_signing_key_id: "key-old".to_owned(),
                    signature_algorithm: "ed25519".to_owned(),
                    public_key_hex: "public-old".to_owned(),
                    private_key_hex: "private-old".to_owned(),
                    registration_mode: "manual".to_owned(),
                },
                10,
            )
            .expect("old authority");
        let original_authority_id = store
            .get_network_authority("network-1")
            .expect("authority lookup")
            .expect("network authority")
            .authority_id;

        let result = store
            .initialize_or_rotate_network_authority(
                &NetworkAuthorityConfig {
                    network_id: "network-1".to_owned(),
                    genesis_node_id: "genesis-new".to_owned(),
                    active_signing_key_id: "key-new".to_owned(),
                    signature_algorithm: "ed25519".to_owned(),
                    public_key_hex: "public-new".to_owned(),
                    private_key_hex: "private-new".to_owned(),
                    registration_mode: "manual".to_owned(),
                },
                20,
            )
            .expect("authority rotation");

        assert_eq!(result.authority.authority_id, original_authority_id);
        assert_eq!(result.authority.genesis_node_id, "genesis-new");
        assert_eq!(result.authority.active_signing_key_id, "key-new");
        assert_eq!(result.signing_key.public_key_hex, "public-new");
        assert_eq!(
            store
                .get_active_signing_key("network-1")
                .expect("active key lookup")
                .expect("active key")
                .key_id,
            "key-new"
        );
    }

    #[test]
    fn auto_and_manual_registrations_materialize_current_agent_projection() {
        let store = RegistryStore::open_in_memory().expect("store");
        let mut manual = request("manual", "Manual Agent");
        manual.agent_card = Some(json!({"name": "Manual Agent"}));
        manual.agent_card_hash = Some("sha256:manual".to_owned());
        store
            .insert_request(&manual, RegistrationStatus::Pending, "manual", 10)
            .expect("manual insert");
        store
            .transition(
                &manual.request_id,
                RegistrationDecisionKind::Approve,
                &decision(
                    &manual,
                    RegistrationDecisionKind::Approve,
                    RegistrationStatus::Approved,
                    20,
                ),
                Some(&credential(&manual, "credential-manual")),
                20,
            )
            .expect("manual approval");

        let manual_agent = store
            .get_agent(&manual.network_id, &manual.agent_did)
            .expect("manual agent lookup")
            .expect("manual agent projection");
        assert_eq!(manual_agent.status, RegistrationAgentStatus::Active);
        assert_eq!(manual_agent.registration_mode, "manual");
        assert_eq!(
            manual_agent
                .agent_card
                .as_ref()
                .and_then(|card| card["name"].as_str()),
            Some("Manual Agent")
        );
        assert_eq!(
            manual_agent.agent_card_hash.as_deref(),
            Some("sha256:manual")
        );
        let manual_credential = store
            .get_credential("credential-manual")
            .expect("manual credential lookup")
            .expect("manual credential record");
        assert_eq!(manual_credential.request_id, manual.request_id);
        assert_eq!(manual_credential.agent_did, manual.agent_did);
        assert_eq!(manual_credential.status, "active");

        let auto = request("auto", "Auto Agent");
        store
            .insert_request(&auto, RegistrationStatus::Pending, "auto", 30)
            .expect("auto insert");
        store
            .transition(
                &auto.request_id,
                RegistrationDecisionKind::Approve,
                &decision(
                    &auto,
                    RegistrationDecisionKind::Approve,
                    RegistrationStatus::Approved,
                    40,
                ),
                Some(&credential(&auto, "credential-auto")),
                40,
            )
            .expect("auto approval");

        let agents = store
            .list_agents(
                Some(&auto.network_id),
                Some(RegistrationAgentStatus::Active),
                10,
            )
            .expect("agent list");
        assert_eq!(agents.len(), 2);
        assert!(agents.iter().any(|agent| {
            agent.agent_did == auto.agent_did && agent.registration_mode == "auto"
        }));

        store
            .transition(
                &manual.request_id,
                RegistrationDecisionKind::Disable,
                &decision(
                    &manual,
                    RegistrationDecisionKind::Disable,
                    RegistrationStatus::Disabled,
                    50,
                ),
                None,
                50,
            )
            .expect("manual disable");
        let disabled_agent = store
            .get_agent(&manual.network_id, &manual.agent_did)
            .expect("disabled agent lookup")
            .expect("disabled agent projection");
        assert_eq!(disabled_agent.status, RegistrationAgentStatus::Disabled);
        assert_eq!(disabled_agent.credential_id, "credential-manual");
        assert_eq!(
            store
                .get_credential("credential-manual")
                .expect("revoked credential lookup")
                .expect("revoked credential record")
                .status,
            "revoked"
        );
    }

    #[test]
    fn discovery_nodes_keep_agent_links_pending_until_registration_is_approved() {
        let store = RegistryStore::open_in_memory().expect("store");
        let agent = request("agent", "Node Agent");
        let record = discovery_record(&agent.agent_did, 1);
        let node = store
            .upsert_discovery_node(&record, 2_000)
            .expect("store discovery node");
        assert_eq!(node.node_id, "node-a");
        let pending = store
            .list_node_agents("network-1", "node-a", 10)
            .expect("pending node-agent links");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].relation_status, NodeAgentRelationStatus::Pending);

        store
            .insert_request(&agent, RegistrationStatus::Pending, "auto", 2_100)
            .expect("insert agent request");
        store
            .transition(
                &agent.request_id,
                RegistrationDecisionKind::Approve,
                &decision(
                    &agent,
                    RegistrationDecisionKind::Approve,
                    RegistrationStatus::Approved,
                    2_200,
                ),
                Some(&credential(&agent, "credential-agent")),
                2_200,
            )
            .expect("approve agent");
        let active = store
            .list_node_agents("network-1", "node-a", 10)
            .expect("active node-agent links");
        assert_eq!(active[0].relation_status, NodeAgentRelationStatus::Active);

        store
            .upsert_discovery_node(&discovery_record(&agent.agent_did, 2), 2_250)
            .expect("refresh registered Agent Card");
        let registered_agent = store
            .get_agent(&agent.network_id, &agent.agent_did)
            .expect("registered agent lookup")
            .expect("registered agent projection");
        assert_eq!(
            registered_agent
                .agent_card
                .as_ref()
                .and_then(|card| card["name"].as_str()),
            Some("Test Agent")
        );
        assert_eq!(
            registered_agent.agent_card_hash.as_deref(),
            Some("sha256:test")
        );

        store
            .transition(
                &agent.request_id,
                RegistrationDecisionKind::Disable,
                &decision(
                    &agent,
                    RegistrationDecisionKind::Disable,
                    RegistrationStatus::Disabled,
                    2_300,
                ),
                None,
                2_300,
            )
            .expect("disable agent");
        let disabled = store
            .list_node_agents("network-1", "node-a", 10)
            .expect("disabled node-agent links");
        assert_eq!(
            disabled[0].relation_status,
            NodeAgentRelationStatus::Disabled
        );
    }
}
