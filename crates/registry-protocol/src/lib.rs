use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const REGISTRATION_PROTOCOL_VERSION: u32 = 1;
pub const DISCOVERY_PROTOCOL_VERSION: &str = "wattswarm-discovery/1";
pub const REGISTRATION_REQUEST_DOMAIN: &str = "wattetheria:network-registration-request:v1";
pub const REGISTRATION_DECISION_DOMAIN: &str = "wattetheria:network-registration-decision:v1";
pub const MEMBERSHIP_CREDENTIAL_DOMAIN: &str = "wattetheria:network-membership-credential:v1";
pub const SIGNATURE_ALGORITHM_ED25519: &str = "ed25519";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Draft,
    Pending,
    Approved,
    Rejected,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationDecisionKind {
    #[serde(rename = "accept", alias = "approve")]
    Approve,
    Reject,
    Disable,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub version: u32,
    pub request_id: String,
    pub network_id: String,
    pub agent_did: String,
    pub nickname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_instance_id: Option<String>,
    pub nonce: String,
    pub signature_b64: String,
}

impl RegistrationRequest {
    pub fn signing_message(&self) -> Result<Vec<u8>, serde_json::Error> {
        self.signing_message_with_nickname(false)
    }

    /// The v1 request format included nickname in the signed payload.
    /// Keep this form for verifying requests created before nickname became
    /// mutable metadata.
    pub fn legacy_signing_message(&self) -> Result<Vec<u8>, serde_json::Error> {
        self.signing_message_with_nickname(true)
    }

    fn signing_message_with_nickname(
        &self,
        include_nickname: bool,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let mut payload = serde_json::Map::new();
        payload.insert("domain".to_owned(), json!(REGISTRATION_REQUEST_DOMAIN));
        payload.insert("version".to_owned(), json!(self.version));
        payload.insert("request_id".to_owned(), json!(self.request_id));
        payload.insert("network_id".to_owned(), json!(self.network_id));
        payload.insert("agent_did".to_owned(), json!(self.agent_did));
        if include_nickname {
            payload.insert("nickname".to_owned(), json!(self.nickname));
        }
        if let Some(agent_card_hash) = self.agent_card_hash.as_ref() {
            payload.insert("agent_card_hash".to_owned(), json!(agent_card_hash));
        }
        payload.insert(
            "tenant_instance_id".to_owned(),
            json!(self.tenant_instance_id),
        );
        payload.insert("nonce".to_owned(), json!(self.nonce));
        serde_jcs::to_vec(&Value::Object(payload))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedRegistrationDecision {
    pub version: u32,
    pub request_id: String,
    pub network_id: String,
    pub agent_did: String,
    #[serde(rename = "decision", alias = "action")]
    pub action: RegistrationDecisionKind,
    pub status: RegistrationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    pub reviewed_at_ms: u64,
    #[serde(
        rename = "reason",
        alias = "review_note",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub review_note: Option<String>,
    #[serde(alias = "issuer_genesis_id")]
    pub issuer_authority_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationDecision {
    #[serde(flatten)]
    pub unsigned: UnsignedRegistrationDecision,
    pub signature_hex: String,
}

impl UnsignedRegistrationDecision {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_jcs::to_vec(&serde_json::json!({
            "domain": REGISTRATION_DECISION_DOMAIN,
            "version": self.version,
            "request_id": self.request_id,
            "network_id": self.network_id,
            "agent_did": self.agent_did,
            "decision": self.action,
            "status": self.status,
            "reviewer_id": self.reviewer_id,
            "reason": self.review_note,
            "issuer_authority_id": self.issuer_authority_id,
            "decided_at": self.reviewed_at_ms,
            "signing_key_id": self.signing_key_id,
            "signature_algorithm": self.signature_algorithm,
        }))
    }
}

impl RegistrationDecision {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        self.unsigned.signing_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedMembershipCredential {
    pub version: u32,
    pub credential_id: String,
    pub request_id: String,
    pub network_id: String,
    pub agent_did: String,
    #[serde(alias = "issuer_genesis_id")]
    pub issuer_authority_id: String,
    #[serde(rename = "issued_at", alias = "issued_at_ms")]
    pub issued_at_ms: u64,
    #[serde(
        rename = "expires_at",
        alias = "expires_at_ms",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCredential {
    #[serde(flatten)]
    pub unsigned: UnsignedMembershipCredential,
    pub signature_hex: String,
}

impl UnsignedMembershipCredential {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_jcs::to_vec(&serde_json::json!({
            "domain": MEMBERSHIP_CREDENTIAL_DOMAIN,
            "version": self.version,
            "credential_id": self.credential_id,
            "request_id": self.request_id,
            "network_id": self.network_id,
            "agent_did": self.agent_did,
            "issuer_authority_id": self.issuer_authority_id,
            "issued_at": self.issued_at_ms,
            "expires_at": self.expires_at_ms,
            "signing_key_id": self.signing_key_id,
            "signature_algorithm": self.signature_algorithm,
        }))
    }
}

impl MembershipCredential {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        self.unsigned.signing_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRecord {
    pub request: RegistrationRequest,
    pub status: RegistrationStatus,
    #[serde(default = "default_registration_mode")]
    pub registration_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<MembershipCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<RegistrationDecision>,
    pub submitted_at_ms: u64,
    pub updated_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_note: Option<String>,
}

fn default_registration_mode() -> String {
    "manual".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationReviewRequest {
    #[serde(rename = "action", alias = "decision")]
    pub action: RegistrationDecisionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    #[serde(
        rename = "review_note",
        alias = "reason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub review_note: Option<String>,
}

/// The wire-compatible discovery envelope emitted by Wattswarm.
///
/// The registry deliberately keeps the nested transport, capability, topic,
/// geo, and Agent Card payloads as JSON. This preserves the Wattswarm wire
/// contract without coupling the registry protocol crate to Wattswarm's
/// transport crates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveryNodeRecordBody {
    pub protocol_version: String,
    pub network_id: String,
    pub node_id: String,
    pub signing_public_key_hex: String,
    pub seq: u64,
    pub updated_at_ms: u64,
    pub ttl_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<Value>,
    #[serde(default = "default_discovery_capabilities")]
    pub capabilities: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topic_providers: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_contact: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_agent_card: Option<Value>,
}

impl DiscoveryNodeRecordBody {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_jcs::to_vec(self)
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.updated_at_ms.saturating_add(self.ttl_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedDiscoveryNodeRecord {
    pub body: DiscoveryNodeRecordBody,
    pub signature_hex: String,
}

fn default_discovery_capabilities() -> Value {
    json!({"services": []})
}

pub fn normalize_nickname(value: &str) -> Result<String, String> {
    let normalized = value
        .trim()
        .strip_prefix('@')
        .unwrap_or(value.trim())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if normalized.is_empty() {
        return Err("nickname is required".to_owned());
    }
    if normalized.chars().count() > 80 {
        return Err("nickname must be 80 characters or less".to_owned());
    }
    if normalized.chars().any(char::is_control) {
        return Err("nickname must not contain control characters".to_owned());
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_signing_bytes_are_stable_and_domain_separated() {
        let request = RegistrationRequest {
            version: REGISTRATION_PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            network_id: "network-1".to_owned(),
            agent_did: "did:key:z6Mkw".to_owned(),
            nickname: "Agent One".to_owned(),
            agent_card: None,
            agent_card_hash: None,
            tenant_instance_id: None,
            nonce: "nonce-1".to_owned(),
            signature_b64: String::new(),
        };
        let first = request.signing_message().expect("signing bytes");
        let second = request.signing_message().expect("signing bytes");
        assert_eq!(first, second);
        assert!(
            String::from_utf8(first)
                .expect("utf8")
                .contains(REGISTRATION_REQUEST_DOMAIN)
        );
    }

    #[test]
    fn nickname_is_not_part_of_the_current_signing_message() {
        let first = RegistrationRequest {
            version: REGISTRATION_PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            network_id: "network-1".to_owned(),
            agent_did: "did:key:z6Mkw".to_owned(),
            nickname: "Agent One".to_owned(),
            agent_card: None,
            agent_card_hash: None,
            tenant_instance_id: None,
            nonce: "nonce-1".to_owned(),
            signature_b64: String::new(),
        };
        let mut second = first.clone();
        second.nickname = "Agent Renamed".to_owned();
        assert_eq!(
            first.signing_message().expect("signing bytes"),
            second.signing_message().expect("signing bytes")
        );
        assert_ne!(
            first
                .legacy_signing_message()
                .expect("legacy signing bytes"),
            second
                .legacy_signing_message()
                .expect("legacy signing bytes")
        );
    }

    #[test]
    fn nickname_normalization_is_case_and_whitespace_insensitive() {
        assert_eq!(normalize_nickname(" @Agent   One ").unwrap(), "agent one");
    }
}
