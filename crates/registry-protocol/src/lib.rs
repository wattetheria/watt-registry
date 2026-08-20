use serde::{Deserialize, Serialize};

pub const REGISTRATION_PROTOCOL_VERSION: u32 = 1;
pub const REGISTRATION_REQUEST_DOMAIN: &str = "wattetheria:network-registration-request:v1";
pub const REGISTRATION_DECISION_DOMAIN: &str = "wattetheria:network-registration-decision:v1";
pub const MEMBERSHIP_CREDENTIAL_DOMAIN: &str = "wattetheria:network-membership-credential:v1";

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
    pub tenant_instance_id: Option<String>,
    pub nonce: String,
    pub signature_b64: String,
}

impl RegistrationRequest {
    pub fn signing_message(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_jcs::to_vec(&serde_json::json!({
            "domain": REGISTRATION_REQUEST_DOMAIN,
            "version": self.version,
            "request_id": self.request_id,
            "network_id": self.network_id,
            "agent_did": self.agent_did,
            "nickname": self.nickname,
            "tenant_instance_id": self.tenant_instance_id,
            "nonce": self.nonce,
        }))
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
    #[serde(rename = "issuer_genesis_id", alias = "issuer_authority_id")]
    pub issuer_authority_id: String,
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
            "issuer_genesis_id": self.issuer_authority_id,
            "decided_at": self.reviewed_at_ms,
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
    #[serde(rename = "issuer_genesis_id", alias = "issuer_authority_id")]
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
            "issuer_genesis_id": self.issuer_authority_id,
            "issued_at": self.issued_at_ms,
            "expires_at": self.expires_at_ms,
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
    fn nickname_normalization_is_case_and_whitespace_insensitive() {
        assert_eq!(normalize_nickname(" @Agent   One ").unwrap(), "agent one");
    }
}
