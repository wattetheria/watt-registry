use anyhow::{Context, Result, bail};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_crypto::{
    AuthoritySigner, status_allows_credential, verify_agent_registration_request,
};
use registry_protocol::{
    RegistrationDecisionKind, RegistrationRecord, RegistrationRequest, RegistrationReviewRequest,
    RegistrationStatus, UnsignedMembershipCredential, UnsignedRegistrationDecision,
    normalize_nickname,
};
use registry_storage::RegistryStore;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const ENV_HTTP_ADDR: &str = "WATT_REGISTRY_HTTP_ADDR";
const ENV_DATABASE_URL: &str = "WATT_REGISTRY_DATABASE_URL";
const ENV_AUTHORITY_SEED_HEX: &str = "WATT_REGISTRY_AUTHORITY_SEED_HEX";
const ENV_AUTHORITY_SEED_FILE: &str = "WATT_REGISTRY_AUTHORITY_SEED_FILE";
const ENV_REGISTRATION_MODE: &str = "WATT_REGISTRY_REGISTRATION_MODE";
const ENV_CREDENTIAL_TTL_SECONDS: &str = "WATT_REGISTRY_CREDENTIAL_TTL_SECONDS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    Auto,
    Manual,
    Disabled,
}

impl RegistrationMode {
    pub fn from_env() -> Result<Self> {
        match std::env::var(ENV_REGISTRATION_MODE)
            .unwrap_or_else(|_| "manual".to_owned())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "auto" => Ok(Self::Auto),
            "manual" => Ok(Self::Manual),
            "disabled" | "off" => Ok(Self::Disabled),
            value => bail!("unsupported {ENV_REGISTRATION_MODE} '{value}'"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub http_addr: String,
    pub database_url: String,
    pub authority_seed_file: PathBuf,
    pub credential_ttl_seconds: Option<u64>,
    pub registration_mode: RegistrationMode,
}

impl RegistryConfig {
    pub fn from_env() -> Result<Self> {
        let authority_seed_file = std::env::var(ENV_AUTHORITY_SEED_FILE)
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/authority.seed.hex"));
        let credential_ttl_seconds = parse_ttl_seconds()?;
        Ok(Self {
            http_addr: std::env::var(ENV_HTTP_ADDR).unwrap_or_else(|_| "0.0.0.0:8042".to_owned()),
            database_url: std::env::var(ENV_DATABASE_URL).unwrap_or_else(|_| {
                "postgres://postgres:postgres@127.0.0.1:55432/watt_registry".to_owned()
            }),
            authority_seed_file,
            credential_ttl_seconds,
            registration_mode: RegistrationMode::from_env()?,
        })
    }
}

#[derive(Clone)]
pub struct RegistryState {
    pub store: RegistryStore,
    pub authority: AuthoritySigner,
    pub credential_ttl_seconds: Option<u64>,
    pub registration_mode: RegistrationMode,
}

impl std::fmt::Debug for RegistryState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryState")
            .field("authority_id", &self.authority.authority_id())
            .field("credential_ttl_seconds", &self.credential_ttl_seconds)
            .field("registration_mode", &self.registration_mode)
            .finish()
    }
}

impl RegistryState {
    pub fn from_config(config: &RegistryConfig) -> Result<Self> {
        let authority = if let Ok(seed) = std::env::var(ENV_AUTHORITY_SEED_HEX) {
            AuthoritySigner::from_seed_hex(&seed)?
        } else {
            AuthoritySigner::load_or_create(&config.authority_seed_file)?
        };
        Ok(Self {
            store: RegistryStore::open(&config.database_url)?,
            authority,
            credential_ttl_seconds: config.credential_ttl_seconds,
            registration_mode: config.registration_mode,
        })
    }
}

pub fn build_router(state: RegistryState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/authority", get(authority))
        .route("/v1/registrations/draft", post(create_draft))
        .route("/v1/registrations/manual", post(create_manual))
        .route("/v1/registrations/auto", post(create_auto))
        .route("/v1/registrations", get(list_registrations))
        .route("/v1/registrations/{request_id}", get(get_registration))
        .route(
            "/v1/registrations/{request_id}/submit",
            post(submit_registration),
        )
        .route(
            "/v1/registrations/{request_id}/review",
            post(review_registration),
        )
        .route("/admin/registrations", get(admin_page))
        // Existing Wattswarm clients can switch their registration base URL
        // without changing their request and response paths first.
        .route("/api/network/registration/auto", post(create_auto_legacy))
        .route(
            "/api/network/registration/manual",
            post(create_manual_legacy),
        )
        .route("/api/network/registrations", get(list_registrations_legacy))
        .route(
            "/api/network/registrations/{request_id}",
            get(get_registration_legacy),
        )
        .route(
            "/api/network/registrations/{request_id}/decision",
            post(review_registration_legacy),
        )
        .route("/network/registrations", get(admin_page))
        .with_state(state)
}

pub async fn serve(config: RegistryConfig, state: RegistryState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&config.http_addr)
        .await
        .with_context(|| format!("bind registry HTTP address {}", config.http_addr))?;
    println!(
        "watt-registry listening on {} authority_id={} mode={:?}",
        config.http_addr,
        state.authority.authority_id(),
        state.registration_mode
    );
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

#[derive(Debug, Deserialize, Default)]
struct RegistrationListQuery {
    network_id: Option<String>,
    status: Option<RegistrationStatus>,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct LegacyRegistrationListQuery {
    network_id: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"ok": true, "service": "watt-registry"}))
}

async fn authority(State(state): State<RegistryState>) -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "authority_id": state.authority.authority_id(),
        "registration_mode": format_registration_mode(state.registration_mode),
    }))
}

fn format_registration_mode(mode: RegistrationMode) -> &'static str {
    match mode {
        RegistrationMode::Auto => "auto",
        RegistrationMode::Manual => "manual",
        RegistrationMode::Disabled => "disabled",
    }
}

async fn run_blocking<T, F>(task: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|error| ApiError::bad_request(format!("registry worker failed: {error}")))?
}

async fn create_draft(
    State(state): State<RegistryState>,
    Json(request): Json<RegistrationRequest>,
) -> ApiResult<Json<RegistrationRecord>> {
    if state.registration_mode == RegistrationMode::Disabled {
        return Err(ApiError::bad_request("registration is disabled by policy"));
    }
    validate_request(&request)?;
    let store = state.store.clone();
    let record = run_blocking(move || {
        Ok(store.insert_request(&request, RegistrationStatus::Draft, now_ms())?)
    })
    .await?;
    Ok(Json(record))
}

async fn create_manual(
    State(state): State<RegistryState>,
    Json(request): Json<RegistrationRequest>,
) -> ApiResult<Json<RegistrationRecord>> {
    if state.registration_mode != RegistrationMode::Manual {
        return Err(ApiError::bad_request(
            "manual registration is disabled by policy",
        ));
    }
    validate_request(&request)?;
    let store = state.store.clone();
    let record = run_blocking(move || {
        Ok(store.insert_request(&request, RegistrationStatus::Pending, now_ms())?)
    })
    .await?;
    Ok(Json(record))
}

async fn create_auto(
    State(state): State<RegistryState>,
    Json(request): Json<RegistrationRequest>,
) -> ApiResult<Json<RegistrationRecord>> {
    if state.registration_mode != RegistrationMode::Auto {
        return Err(ApiError::bad_request(
            "automatic registration is disabled by policy",
        ));
    }
    validate_request(&request)?;
    let state_for_task = state.clone();
    let record = run_blocking(move || {
        let record =
            state_for_task
                .store
                .insert_request(&request, RegistrationStatus::Pending, now_ms())?;
        let record = match record.status {
            RegistrationStatus::Approved => record,
            RegistrationStatus::Pending => apply_review(
                &state_for_task,
                record,
                RegistrationDecisionKind::Approve,
                Some("automatic".to_owned()),
                Some("Automatically approved by registration policy".to_owned()),
            )?,
            RegistrationStatus::Disabled => {
                return Err(ApiError::conflict("registration is disabled"));
            }
            _ => {
                return Err(ApiError::conflict(
                    "registration cannot be automatically approved",
                ));
            }
        };
        Ok(record)
    })
    .await?;
    Ok(Json(record))
}

async fn create_manual_legacy(
    State(state): State<RegistryState>,
    Json(request): Json<RegistrationRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let Json(record) = create_manual(State(state), Json(request)).await?;
    Ok(Json(json!({
        "request_id": record.request.request_id,
        "status": "pending",
    })))
}

async fn create_auto_legacy(
    State(state): State<RegistryState>,
    Json(request): Json<RegistrationRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let Json(record) = create_auto(State(state), Json(request)).await?;
    let credential = record
        .credential
        .ok_or_else(|| ApiError::conflict("approved registration is missing credential"))?;
    let decision = record
        .decision
        .ok_or_else(|| ApiError::conflict("approved registration is missing decision"))?;
    Ok(Json(json!({
        "request_id": record.request.request_id,
        "status": "active",
        "credential": credential,
        "decision": decision,
    })))
}

async fn list_registrations(
    State(state): State<RegistryState>,
    Query(query): Query<RegistrationListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.clone();
    let network_id = query.network_id;
    let status = query.status;
    let limit = query.limit.unwrap_or(100);
    let records =
        run_blocking(move || Ok(store.list(network_id.as_deref(), status, limit)?)).await?;
    Ok(Json(json!({"ok": true, "records": records})))
}

async fn list_registrations_legacy(
    State(state): State<RegistryState>,
    Query(query): Query<LegacyRegistrationListQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let status = query
        .status
        .as_deref()
        .map(parse_legacy_status)
        .transpose()?;
    let store = state.store.clone();
    let network_id = query.network_id;
    let limit = query.limit.unwrap_or(100);
    let records =
        run_blocking(move || Ok(store.list(network_id.as_deref(), status, limit)?)).await?;
    let records = records
        .into_iter()
        .map(legacy_record_value)
        .collect::<Result<Vec<_>>>()?;
    Ok(Json(json!({"ok": true, "records": records})))
}

async fn get_registration(
    State(state): State<RegistryState>,
    Path(request_id): Path<String>,
) -> ApiResult<Json<RegistrationRecord>> {
    let store = state.store.clone();
    let record = run_blocking(move || {
        store
            .get(&request_id)?
            .ok_or_else(|| ApiError::not_found("registration not found"))
    })
    .await?;
    Ok(Json(record))
}

async fn get_registration_legacy(
    State(state): State<RegistryState>,
    Path(request_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let store = state.store.clone();
    let record = run_blocking(move || {
        store
            .get(&request_id)?
            .ok_or_else(|| ApiError::not_found("registration not found"))
    })
    .await?;
    Ok(Json(legacy_record_value(record)?))
}

async fn submit_registration(
    State(state): State<RegistryState>,
    Path(request_id): Path<String>,
) -> ApiResult<Json<RegistrationRecord>> {
    let store = state.store.clone();
    let record = run_blocking(move || {
        store
            .submit_draft(&request_id, now_ms())?
            .ok_or_else(|| ApiError::not_found("registration not found"))
    })
    .await?;
    Ok(Json(record))
}

async fn review_registration(
    State(state): State<RegistryState>,
    Path(request_id): Path<String>,
    Json(review): Json<RegistrationReviewRequest>,
) -> ApiResult<Json<RegistrationRecord>> {
    validate_review_field("reviewer_id", review.reviewer_id.as_deref(), 128)?;
    validate_review_field("review_note", review.review_note.as_deref(), 2_000)?;
    if matches!(
        review.action,
        RegistrationDecisionKind::Reject | RegistrationDecisionKind::Disable
    ) && review
        .review_note
        .as_deref()
        .is_none_or(|note| note.trim().is_empty())
    {
        return Err(ApiError::bad_request(
            "review_note is required for reject and disable",
        ));
    }
    let state_for_task = state.clone();
    let result = run_blocking(move || {
        let record = state_for_task
            .store
            .get(&request_id)?
            .ok_or_else(|| ApiError::not_found("registration not found"))?;
        apply_review(
            &state_for_task,
            record,
            review.action,
            review.reviewer_id,
            review.review_note,
        )
    })
    .await?;
    Ok(Json(result))
}

fn validate_review_field(
    field: &str,
    value: Option<&str>,
    max_chars: usize,
) -> Result<(), ApiError> {
    if value.is_some_and(|value| {
        value.chars().count() > max_chars || value.chars().any(char::is_control)
    }) {
        return Err(ApiError::bad_request(format!("{field} is invalid")));
    }
    Ok(())
}

async fn review_registration_legacy(
    State(state): State<RegistryState>,
    Path(request_id): Path<String>,
    Json(review): Json<RegistrationReviewRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let Json(record) = review_registration(State(state), Path(request_id), Json(review)).await?;
    Ok(Json(legacy_record_value(record)?))
}

fn apply_review(
    state: &RegistryState,
    record: RegistrationRecord,
    action: RegistrationDecisionKind,
    reviewer_id: Option<String>,
    review_note: Option<String>,
) -> Result<RegistrationRecord, ApiError> {
    let reviewed_at_ms = now_ms();
    let next_status = match (record.status, action) {
        (
            RegistrationStatus::Draft | RegistrationStatus::Pending,
            RegistrationDecisionKind::Approve,
        )
        | (RegistrationStatus::Disabled, RegistrationDecisionKind::Restore) => {
            RegistrationStatus::Approved
        }
        (
            RegistrationStatus::Draft | RegistrationStatus::Pending,
            RegistrationDecisionKind::Reject,
        ) => RegistrationStatus::Rejected,
        (RegistrationStatus::Approved, RegistrationDecisionKind::Disable) => {
            RegistrationStatus::Disabled
        }
        _ => return Err(ApiError::conflict("invalid registration state transition")),
    };
    let reviewer_id = reviewer_id
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .or_else(|| Some("operator".to_owned()));
    let unsigned_decision = UnsignedRegistrationDecision {
        version: registry_protocol::REGISTRATION_PROTOCOL_VERSION,
        request_id: record.request.request_id.clone(),
        network_id: record.request.network_id.clone(),
        agent_did: record.request.agent_did.clone(),
        action,
        status: next_status,
        reviewer_id,
        reviewed_at_ms,
        review_note: review_note
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        issuer_authority_id: state.authority.authority_id(),
    };
    let decision = state.authority.sign_decision(unsigned_decision)?;
    AuthoritySigner::verify_decision(&decision, &state.authority.authority_id())?;

    let credential = if status_allows_credential(next_status) {
        let issued_at_ms = reviewed_at_ms;
        let expires_at_ms = credential_expiry(state, issued_at_ms)?;
        let credential = state
            .authority
            .sign_credential(UnsignedMembershipCredential {
                version: registry_protocol::REGISTRATION_PROTOCOL_VERSION,
                credential_id: Uuid::new_v4().to_string(),
                request_id: record.request.request_id.clone(),
                network_id: record.request.network_id.clone(),
                agent_did: record.request.agent_did.clone(),
                issuer_authority_id: state.authority.authority_id(),
                issued_at_ms,
                expires_at_ms,
            })?;
        AuthoritySigner::verify_credential(
            &credential,
            &state.authority.authority_id(),
            issued_at_ms,
        )?;
        Some(credential)
    } else {
        None
    };
    Ok(state.store.transition(
        &record.request.request_id,
        action,
        &decision,
        credential.as_ref(),
        reviewed_at_ms,
    )?)
}

fn validate_request(request: &RegistrationRequest) -> Result<(), ApiError> {
    if request.version != registry_protocol::REGISTRATION_PROTOCOL_VERSION {
        return Err(ApiError::bad_request(
            "unsupported registration protocol version",
        ));
    }
    for (field, value, max_chars) in [
        ("request_id", request.request_id.as_str(), 128),
        ("network_id", request.network_id.as_str(), 256),
        ("agent_did", request.agent_did.as_str(), 512),
        ("nickname", request.nickname.as_str(), 80),
        ("nonce", request.nonce.as_str(), 256),
    ] {
        if value.trim().is_empty() || value.chars().count() > max_chars {
            return Err(ApiError::bad_request(format!("{field} is invalid")));
        }
        if value.chars().any(char::is_control) {
            return Err(ApiError::bad_request(format!(
                "{field} contains a control character"
            )));
        }
    }
    normalize_nickname(&request.nickname).map_err(ApiError::bad_request)?;
    if request
        .tenant_instance_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 128)
    {
        return Err(ApiError::bad_request("tenant_instance_id is invalid"));
    }
    if request.signature_b64.trim().is_empty() || request.signature_b64.chars().count() > 128 {
        return Err(ApiError::bad_request("signature_b64 is invalid"));
    }
    verify_agent_registration_request(request)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(())
}

fn parse_legacy_status(value: &str) -> Result<RegistrationStatus, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "pending" => Ok(RegistrationStatus::Pending),
        "active" | "approved" => Ok(RegistrationStatus::Approved),
        "rejected" => Ok(RegistrationStatus::Rejected),
        "disabled" => Ok(RegistrationStatus::Disabled),
        "draft" => Ok(RegistrationStatus::Draft),
        _ => Err(ApiError::bad_request("unsupported registration status")),
    }
}

fn legacy_status(status: RegistrationStatus) -> &'static str {
    match status {
        RegistrationStatus::Approved => "active",
        RegistrationStatus::Draft => "draft",
        RegistrationStatus::Pending => "pending",
        RegistrationStatus::Rejected => "rejected",
        RegistrationStatus::Disabled => "disabled",
    }
}

fn legacy_record_value(record: RegistrationRecord) -> Result<serde_json::Value> {
    let legacy_status = legacy_status(record.status);
    let mut value = serde_json::to_value(record)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "status".to_owned(),
            serde_json::Value::String(legacy_status.to_owned()),
        );
        if let Some(submitted_at) = object.get("submitted_at_ms").cloned() {
            object.insert("submitted_at".to_owned(), submitted_at);
        }
        if let Some(reviewed_at) = object.get("reviewed_at_ms").cloned() {
            object.insert("decided_at".to_owned(), reviewed_at);
        }
    }
    Ok(value)
}

fn parse_ttl_seconds() -> Result<Option<u64>> {
    let Some(value) = std::env::var_os(ENV_CREDENTIAL_TTL_SECONDS) else {
        return Ok(None);
    };
    let seconds = value
        .to_string_lossy()
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parse {ENV_CREDENTIAL_TTL_SECONDS}"))?;
    Ok((seconds > 0).then_some(seconds))
}

fn credential_expiry(state: &RegistryState, issued_at_ms: u64) -> Result<Option<u64>> {
    let Some(seconds) = state.credential_ttl_seconds else {
        return Ok(None);
    };
    let ttl_ms = seconds
        .checked_mul(1_000)
        .context("credential TTL is too large")?;
    issued_at_ms
        .checked_add(ttl_ms)
        .map(Some)
        .context("credential expiry overflows u64")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        let message = format!("{error:#}");
        let status =
            if message.contains("already") || message.contains("invalid registration state") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
        Self { status, message }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"ok": false, "error": self.message})),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

async fn admin_page() -> Html<&'static str> {
    Html(include_str!("../web/registrations.html"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use registry_protocol::{REGISTRATION_PROTOCOL_VERSION, RegistrationRequest};
    use tower::ServiceExt;

    fn signed_request() -> RegistrationRequest {
        let key = SigningKey::from_bytes(&[11; 32]);
        let did = watt_did::DidKey::from_ed25519_public_key(key.verifying_key().to_bytes())
            .expect("Agent DID");
        let mut request = RegistrationRequest {
            version: REGISTRATION_PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            network_id: "network-1".to_owned(),
            agent_did: format!("did:key:{}", did.public_key_multibase),
            nickname: "Agent One".to_owned(),
            tenant_instance_id: None,
            nonce: "nonce-1".to_owned(),
            signature_b64: String::new(),
        };
        request.signature_b64 = base64::engine::general_purpose::STANDARD.encode(
            key.sign(&request.signing_message().expect("bytes"))
                .to_bytes(),
        );
        request
    }

    #[tokio::test]
    async fn manual_registration_can_be_approved_without_admin_authentication() {
        let state = RegistryState {
            store: RegistryStore::open_in_memory().expect("store"),
            authority: AuthoritySigner::from_seed([12; 32]),
            credential_ttl_seconds: None,
            registration_mode: RegistrationMode::Manual,
        };
        let app = build_router(state);
        let request = signed_request();
        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/registrations/manual")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).expect("json")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .oneshot(
                Request::get("/v1/registrations?status=pending")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn approval_issues_a_verifiable_credential_and_records_review_metadata() {
        let authority = AuthoritySigner::from_seed([22; 32]);
        let authority_id = authority.authority_id();
        let state = RegistryState {
            store: RegistryStore::open_in_memory().expect("store"),
            authority,
            credential_ttl_seconds: Some(60),
            registration_mode: RegistrationMode::Manual,
        };
        let app = build_router(state);
        let request = signed_request();
        let request_id = request.request_id.clone();

        let response = app
            .clone()
            .oneshot(
                Request::post("/v1/registrations/manual")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&request).expect("json")))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::post(format!("/v1/registrations/{request_id}/review"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "action": "approve",
                            "reviewer_id": "operator-1",
                            "review_note": "verified by operator",
                        }))
                        .expect("json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: RegistrationRecord = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body"),
        )
        .expect("record");
        assert_eq!(body.status, RegistrationStatus::Approved);
        assert_eq!(body.reviewer_id.as_deref(), Some("operator-1"));
        let credential = body.credential.expect("credential");
        AuthoritySigner::verify_credential(
            &credential,
            &authority_id,
            credential.unsigned.issued_at_ms,
        )
        .expect("credential verifies");
        assert_eq!(credential.unsigned.issuer_authority_id, authority_id);
    }

    #[tokio::test]
    async fn legacy_paths_keep_wattswarm_registration_wire_statuses() {
        let state = RegistryState {
            store: RegistryStore::open_in_memory().expect("store"),
            authority: AuthoritySigner::from_seed([32; 32]),
            credential_ttl_seconds: None,
            registration_mode: RegistrationMode::Auto,
        };
        let app = build_router(state);
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/network/registration/auto")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&signed_request()).expect("json"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body"),
        )
        .expect("json body");
        assert_eq!(body["status"], "active");
        assert!(body["credential"]["issuer_genesis_id"].is_string());
        assert!(body["credential"]["issued_at"].is_number());

        let response = app
            .oneshot(
                Request::get("/api/network/registrations?status=active")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body"),
        )
        .expect("json body");
        assert_eq!(body["records"][0]["status"], "active");
    }
}
