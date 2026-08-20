use anyhow::{Context, Result, bail};
use postgres::{Client, NoTls, Row};
use registry_protocol::{
    MembershipCredential, RegistrationDecision, RegistrationDecisionKind, RegistrationRecord,
    RegistrationRequest, RegistrationStatus, normalize_nickname,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const REGISTRATION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS registration_requests (
    request_id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL,
    agent_did TEXT NOT NULL,
    nickname TEXT NOT NULL,
    nickname_key TEXT NOT NULL,
    nonce TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('draft', 'pending', 'approved', 'rejected', 'disabled')),
    credential_json TEXT,
    decision_json TEXT,
    reviewer_id TEXT,
    reviewed_at_ms BIGINT,
    review_note TEXT,
    submitted_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
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
"#;

#[derive(Clone)]
pub struct RegistryStore {
    backend: Arc<Mutex<Backend>>,
}

enum Backend {
    Postgres(Box<Client>),
    Memory(BTreeMap<String, RegistrationRecord>),
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
            backend: Arc::new(Mutex::new(Backend::Memory(BTreeMap::new()))),
        })
    }

    fn initialize_schema(&self) -> Result<()> {
        let mut backend = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("registry database mutex poisoned"))?;
        if let Backend::Postgres(client) = &mut *backend {
            client.batch_execute(REGISTRATION_SCHEMA)?;
        }
        Ok(())
    }

    pub fn insert_request(
        &self,
        request: &RegistrationRequest,
        status: RegistrationStatus,
        now_ms: u64,
    ) -> Result<RegistrationRecord> {
        let nickname_key = normalize_nickname(&request.nickname).map_err(anyhow::Error::msg)?;
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
                now_ms,
            ),
            Backend::Memory(records) => insert_memory(
                records,
                request,
                &nickname_key,
                &request_json,
                status,
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
            Backend::Postgres(client) => load_record_postgres(client, request_id),
            Backend::Memory(records) => Ok(records.get(request_id).cloned()),
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
            Backend::Memory(records) => submit_draft_memory(records, request_id, now_ms),
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
            Backend::Memory(records) => list_memory(records, network_id, status, limit),
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
        let current = match &mut *backend {
            Backend::Postgres(client) => {
                load_record_postgres(client, request_id)?.context("registration not found")?
            }
            Backend::Memory(records) => records
                .get(request_id)
                .cloned()
                .context("registration not found")?,
        };
        let next_status = next_status(current.status, action)?;
        validate_transition(
            &current,
            request_id,
            action,
            next_status,
            decision,
            credential,
        )?;

        match &mut *backend {
            Backend::Postgres(client) => transition_postgres(
                client,
                request_id,
                current.status,
                next_status,
                decision,
                credential,
                now_ms,
            ),
            Backend::Memory(records) => transition_memory(
                records,
                request_id,
                next_status,
                decision,
                credential,
                now_ms,
            ),
        }
    }
}

fn insert_postgres(
    client: &mut Client,
    request: &RegistrationRequest,
    nickname_key: &str,
    request_json: &str,
    status: RegistrationStatus,
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

    let status_value = status_string(status);
    if let Err(error) = client.execute(
        "INSERT INTO registration_requests(
             request_id, network_id, agent_did, nickname, nickname_key, nonce,
             request_json, status, submitted_at_ms, updated_at_ms
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)",
        &[
            &request.request_id,
            &request.network_id,
            &request.agent_did,
            &request.nickname,
            &nickname_key,
            &request.nonce,
            &request_json,
            &status_value,
            &(now_ms as i64),
        ],
    ) {
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
    now_ms: u64,
) -> Result<RegistrationRecord> {
    if let Some(existing) = records.get(&request.request_id) {
        if serde_json::to_string(&existing.request)? != request_json {
            bail!("request_id already stores a different registration request");
        }
        return Ok(existing.clone());
    }
    for existing in records.values() {
        if existing.request.network_id == request.network_id
            && is_active(existing.status)
            && (existing.request.agent_did == request.agent_did
                || normalize_nickname(&existing.request.nickname)
                    .ok()
                    .as_deref()
                    == Some(nickname_key))
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
                &[&request_id, &(now_ms as i64)],
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
        "SELECT request_json, status, credential_json, decision_json,
                submitted_at_ms, updated_at_ms, reviewer_id, reviewed_at_ms, review_note
         FROM registration_requests
         WHERE ($1::TEXT IS NULL OR network_id = $1)
           AND ($2::TEXT IS NULL OR status = $2)
         ORDER BY submitted_at_ms DESC, request_id ASC
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
    current_status: RegistrationStatus,
    next_status: RegistrationStatus,
    decision: &RegistrationDecision,
    credential: Option<&MembershipCredential>,
    now_ms: u64,
) -> Result<RegistrationRecord> {
    let decision_json = serde_json::to_string(decision)?;
    let credential_json = credential.map(serde_json::to_string).transpose()?;
    let reviewer_id = decision.unsigned.reviewer_id.clone();
    let review_note = decision.unsigned.review_note.clone();
    let updated = client.execute(
        "UPDATE registration_requests
         SET status = $2, credential_json = $3, decision_json = $4,
             reviewer_id = $5, reviewed_at_ms = $6, review_note = $7, updated_at_ms = $9
         WHERE request_id = $1 AND status = $8",
        &[
            &request_id,
            &status_string(next_status),
            &credential_json,
            &decision_json,
            &reviewer_id,
            &(decision.unsigned.reviewed_at_ms as i64),
            &review_note,
            &status_string(current_status),
            &(now_ms as i64),
        ],
    )?;
    if updated == 0 {
        return load_record_postgres(client, request_id)?.context("registration disappeared");
    }
    load_record_postgres(client, request_id)?.context("updated registration is missing")
}

fn transition_memory(
    records: &mut BTreeMap<String, RegistrationRecord>,
    request_id: &str,
    next_status: RegistrationStatus,
    decision: &RegistrationDecision,
    credential: Option<&MembershipCredential>,
    now_ms: u64,
) -> Result<RegistrationRecord> {
    let record = records
        .get_mut(request_id)
        .context("registration disappeared")?;
    record.status = next_status;
    record.credential = credential.cloned();
    record.decision = Some(decision.clone());
    record.reviewer_id = decision.unsigned.reviewer_id.clone();
    record.reviewed_at_ms = Some(decision.unsigned.reviewed_at_ms);
    record.review_note = decision.unsigned.review_note.clone();
    record.updated_at_ms = now_ms;
    Ok(record.clone())
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
        credential.unsigned.request_id != request_id
            || credential.unsigned.network_id != current.request.network_id
            || credential.unsigned.agent_did != current.request.agent_did
    }) {
        bail!("membership credential does not match the stored request");
    }
    Ok(())
}

fn load_record_postgres(
    client: &mut Client,
    request_id: &str,
) -> Result<Option<RegistrationRecord>> {
    client
        .query_opt(
            "SELECT request_json, status, credential_json, decision_json,
                    submitted_at_ms, updated_at_ms, reviewer_id, reviewed_at_ms, review_note
             FROM registration_requests WHERE request_id = $1",
            &[&request_id],
        )?
        .map(|row| row_to_record(&row))
        .transpose()
}

fn row_to_record(row: &Row) -> Result<RegistrationRecord> {
    let request_json: String = row.try_get(0)?;
    let status: String = row.try_get(1)?;
    Ok(RegistrationRecord {
        request: serde_json::from_str(&request_json)
            .context("decode stored registration request")?,
        status: parse_status(&status)?,
        credential: parse_optional_json(row.try_get(2)?, "credential")?,
        decision: parse_optional_json(row.try_get(3)?, "decision")?,
        submitted_at_ms: row.try_get::<_, i64>(4)?.max(0) as u64,
        updated_at_ms: row.try_get::<_, i64>(5)?.max(0) as u64,
        reviewer_id: row.try_get(6)?,
        reviewed_at_ms: row
            .try_get::<_, Option<i64>>(7)?
            .map(|value| value.max(0) as u64),
        review_note: row.try_get(8)?,
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
        REGISTRATION_PROTOCOL_VERSION, RegistrationDecisionKind, RegistrationRequest,
        UnsignedRegistrationDecision,
    };

    fn request(id: &str, nickname: &str) -> RegistrationRequest {
        RegistrationRequest {
            version: REGISTRATION_PROTOCOL_VERSION,
            request_id: id.to_owned(),
            network_id: "network-1".to_owned(),
            agent_did: format!("did:key:{id}"),
            nickname: nickname.to_owned(),
            tenant_instance_id: None,
            nonce: format!("nonce-{id}"),
            signature_b64: "signature".to_owned(),
        }
    }

    #[test]
    fn status_transitions_store_reviewer_note_and_are_idempotent_at_read_level() {
        let store = RegistryStore::open_in_memory().expect("store");
        let request = request("one", "Agent One");
        store
            .insert_request(&request, RegistrationStatus::Pending, 10)
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
            .insert_request(&first, RegistrationStatus::Pending, 10)
            .expect("first insert");

        let mut duplicate = request("two", " @AGENT   ONE ");
        duplicate.agent_did = "did:key:two".to_owned();
        let error = store
            .insert_request(&duplicate, RegistrationStatus::Pending, 11)
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
            .insert_request(&duplicate, RegistrationStatus::Pending, 13)
            .expect("rejected nickname can retry");
    }
}
