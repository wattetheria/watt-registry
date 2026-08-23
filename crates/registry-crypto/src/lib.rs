use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use registry_protocol::{
    DISCOVERY_PROTOCOL_VERSION, MembershipCredential, RegistrationDecision, RegistrationRequest,
    RegistrationStatus, SIGNATURE_ALGORITHM_ED25519, SignedDiscoveryNodeRecord,
    UnsignedMembershipCredential, UnsignedRegistrationDecision,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use watt_did::{Did, DidKey, DidKeyPublicKey};

#[derive(Clone)]
pub struct AuthoritySigner {
    signing_key: SigningKey,
}

impl std::fmt::Debug for AuthoritySigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthoritySigner")
            .field("public_key_hex", &self.public_key_hex())
            .finish()
    }
}

impl AuthoritySigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_seed_hex(value: &str) -> Result<Self> {
        let bytes = hex::decode(value.trim()).context("decode authority seed hex")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("authority seed must contain 32 bytes"))?;
        Ok(Self::from_seed(seed))
    }

    /// Construct a signer for the algorithm recorded in the registry.
    ///
    /// The registry persists the algorithm alongside every signing key so the
    /// dispatch point is explicit. Ed25519 is the only implemented backend in
    /// this release; adding another algorithm belongs here rather than in the
    /// HTTP or storage layers.
    pub fn from_algorithm_seed_hex(algorithm: &str, value: &str) -> Result<Self> {
        match algorithm {
            SIGNATURE_ALGORITHM_ED25519 => Self::from_seed_hex(value),
            other => bail!("unsupported signature algorithm '{other}'"),
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let seed = std::fs::read_to_string(path)
                .with_context(|| format!("read authority seed at {}", path.display()))?;
            return Self::from_seed_hex(&seed);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("create authority state directory {}", parent.display())
            })?;
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let seed = hex::encode(signing_key.to_bytes());
        std::fs::write(path, format!("{seed}\n"))
            .with_context(|| format!("write authority seed at {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restrict authority seed at {}", path.display()))?;
        }
        Ok(Self { signing_key })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn algorithm(&self) -> &'static str {
        SIGNATURE_ALGORITHM_ED25519
    }

    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn sign_decision(
        &self,
        payload: UnsignedRegistrationDecision,
    ) -> Result<RegistrationDecision> {
        if payload.version != registry_protocol::REGISTRATION_PROTOCOL_VERSION {
            bail!("unsupported registration decision protocol version");
        }
        validate_non_empty("issuer_authority_id", &payload.issuer_authority_id)?;
        validate_algorithm(payload.signature_algorithm.as_deref())?;
        let signature_hex =
            hex::encode(self.signing_key.sign(&payload.signing_bytes()?).to_bytes());
        Ok(RegistrationDecision {
            unsigned: payload,
            signature_hex,
        })
    }

    pub fn sign_credential(
        &self,
        payload: UnsignedMembershipCredential,
    ) -> Result<MembershipCredential> {
        if payload.version != registry_protocol::REGISTRATION_PROTOCOL_VERSION {
            bail!("unsupported membership credential protocol version");
        }
        validate_non_empty("issuer_authority_id", &payload.issuer_authority_id)?;
        validate_algorithm(payload.signature_algorithm.as_deref())?;
        if payload
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= payload.issued_at_ms)
        {
            bail!("credential expiry must be after issued_at_ms");
        }
        let signature_hex =
            hex::encode(self.signing_key.sign(&payload.signing_bytes()?).to_bytes());
        Ok(MembershipCredential {
            unsigned: payload,
            signature_hex,
        })
    }

    pub fn verify_decision(
        decision: &RegistrationDecision,
        expected_authority_id: &str,
        expected_public_key_hex: &str,
    ) -> Result<()> {
        if decision.unsigned.issuer_authority_id != expected_authority_id {
            bail!("registration decision issuer is not trusted");
        }
        verify_authority_signature(
            decision.unsigned.signature_algorithm.as_deref(),
            expected_public_key_hex,
            &decision.signing_bytes()?,
            &decision.signature_hex,
        )
    }

    pub fn verify_credential(
        credential: &MembershipCredential,
        expected_authority_id: &str,
        expected_public_key_hex: &str,
        now_ms: u64,
    ) -> Result<()> {
        if credential.unsigned.issuer_authority_id != expected_authority_id {
            bail!("membership credential issuer is not trusted");
        }
        if credential
            .unsigned
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= now_ms)
        {
            bail!("membership credential has expired");
        }
        verify_authority_signature(
            credential.unsigned.signature_algorithm.as_deref(),
            expected_public_key_hex,
            &credential.signing_bytes()?,
            &credential.signature_hex,
        )
    }
}

pub fn verify_agent_registration_request(request: &RegistrationRequest) -> Result<()> {
    if request.signature_b64.trim().is_empty() {
        bail!("registration request signature is required");
    }
    if request.version != registry_protocol::REGISTRATION_PROTOCOL_VERSION {
        bail!(
            "unsupported registration protocol version {}",
            request.version
        );
    }
    verify_registration_agent_card(request)?;
    let verifying_key = agent_verifying_key(&request.agent_did)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(request.signature_b64.trim())
        .context("decode registration request signature base64")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("registration signature must contain 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);
    if verifying_key
        .verify(&request.signing_message()?, &signature)
        .is_ok()
    {
        return Ok(());
    }
    verifying_key
        .verify(&request.legacy_signing_message()?, &signature)
        .context("registration request signature verification failed")
}

fn verify_registration_agent_card(request: &RegistrationRequest) -> Result<()> {
    let (Some(card), Some(card_hash)) = (
        request.agent_card.as_ref(),
        request.agent_card_hash.as_deref(),
    ) else {
        if request.agent_card.is_some() || request.agent_card_hash.is_some() {
            bail!("registration Agent Card and its hash must be provided together");
        }
        return Ok(());
    };
    let card_agent_did = card
        .pointer("/metadata/agent_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("registration Agent Card metadata.agent_id is required")?;
    if card_agent_did != request.agent_did {
        bail!("registration Agent Card agent_id must match registration Agent DID");
    }
    let canonical_card = serde_jcs::to_vec(card).context("canonicalize registration Agent Card")?;
    if canonical_card.len() > 64 * 1024 {
        bail!("registration Agent Card exceeds 64 KiB");
    }
    let expected_hash = format!("sha256:{}", hex::encode(Sha256::digest(&canonical_card)));
    if card_hash != expected_hash {
        bail!("registration Agent Card hash does not match card");
    }
    Ok(())
}

/// Verify the Wattswarm discovery envelope without coupling the registry to
/// Wattswarm's transport implementation. The node public key is the hex
/// encoded Ed25519 key used as `node_id`, and the signature covers the JCS
/// encoded discovery body.
pub fn verify_discovery_node_record(record: &SignedDiscoveryNodeRecord, now_ms: u64) -> Result<()> {
    let body = &record.body;
    if body.protocol_version != DISCOVERY_PROTOCOL_VERSION {
        bail!(
            "unsupported discovery protocol version {}",
            body.protocol_version
        );
    }
    validate_non_empty("network_id", &body.network_id)?;
    validate_non_empty("node_id", &body.node_id)?;
    validate_non_empty("signing_public_key_hex", &body.signing_public_key_hex)?;
    if body.node_id != body.signing_public_key_hex {
        bail!("node_id must match signing_public_key_hex");
    }
    if body.ttl_ms == 0 {
        bail!("discovery record ttl_ms must be greater than zero");
    }
    if body.expires_at_ms() <= now_ms {
        bail!("discovery record is expired");
    }
    let public_key_bytes =
        hex::decode(&body.signing_public_key_hex).context("decode discovery node public key")?;
    let public_key_bytes: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("discovery node public key must contain 32 bytes"))?;
    if let Some(contact) = body.transport_contact.as_ref()
        && let Some(peer_id) = contact.get("peer_id").and_then(|value| value.as_str())
        && peer_id != body.node_id
    {
        bail!("discovery transport contact peer_id must match node_id");
    }
    if let Some(card) = body.source_agent_card.as_ref() {
        let agent_id = card
            .get("agent_id")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .context("source_agent_card.agent_id is required")?;
        let _ = agent_id;
        if let Some(card_node_id) = card.get("node_id").and_then(|value| value.as_str())
            && card_node_id != body.node_id
        {
            bail!("source_agent_card node_id must match discovery node_id");
        }
        let card_hash = card
            .get("card_hash")
            .and_then(|value| value.as_str())
            .filter(|value| !value.trim().is_empty())
            .context("source_agent_card.card_hash is required")?;
        let card_value = card
            .get("card")
            .context("source_agent_card.card is required")?;
        let canonical_card =
            serde_jcs::to_string(card_value).context("canonicalize source Agent Card")?;
        if canonical_card.len() > 64 * 1024 {
            bail!("source Agent Card exceeds 64 KiB");
        }
        let expected_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical_card.as_bytes()))
        );
        if card_hash != expected_hash {
            bail!("source_agent_card.card_hash does not match card");
        }
    }
    let signature =
        hex::decode(record.signature_hex.trim()).context("decode discovery record signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("discovery record signature must contain 64 bytes"))?;
    let record_size = serde_json::to_vec(record)
        .context("serialize discovery record for size validation")?
        .len();
    if record_size > 256 * 1024 {
        bail!("discovery record exceeds 256 KiB");
    }
    VerifyingKey::from_bytes(&public_key_bytes)?
        .verify(&body.signing_bytes()?, &Signature::from_bytes(&signature))?;
    Ok(())
}

fn validate_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn agent_verifying_key(agent_did: &str) -> Result<VerifyingKey> {
    let did = Did::parse(agent_did).context("parse Agent DID")?;
    if did.method() != "key" {
        bail!("registration requires a did:key Agent DID");
    }
    let did_key = DidKey::from_did(did).context("decode Agent did:key")?;
    let DidKeyPublicKey::Ed25519(public_key) = did_key
        .decode_public_key()
        .context("decode Agent DID Ed25519 public key")?
    else {
        bail!("registration requires an Ed25519 Agent DID");
    };
    Ok(VerifyingKey::from_bytes(&public_key)?)
}

fn verify_authority_signature(
    algorithm: Option<&str>,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    validate_algorithm(algorithm)?;
    let public_key = hex::decode(public_key_hex.trim()).context("decode authority public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("authority public key must contain 32 bytes"))?;
    let signature = hex::decode(signature_hex.trim()).context("decode authority signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("authority signature must contain 64 bytes"))?;
    VerifyingKey::from_bytes(&public_key)?.verify(message, &Signature::from_bytes(&signature))?;
    Ok(())
}

fn validate_algorithm(algorithm: Option<&str>) -> Result<()> {
    match algorithm.unwrap_or(SIGNATURE_ALGORITHM_ED25519) {
        SIGNATURE_ALGORITHM_ED25519 => Ok(()),
        other => bail!("unsupported signature algorithm '{other}'"),
    }
}

pub fn status_allows_credential(status: RegistrationStatus) -> bool {
    matches!(status, RegistrationStatus::Approved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use registry_protocol::{
        DISCOVERY_PROTOCOL_VERSION, DiscoveryNodeRecordBody, REGISTRATION_PROTOCOL_VERSION,
        RegistrationDecisionKind, SignedDiscoveryNodeRecord, UnsignedMembershipCredential,
        UnsignedRegistrationDecision,
    };
    use serde_json::json;

    fn request_for(key: &SigningKey) -> RegistrationRequest {
        let did = DidKey::from_ed25519_public_key(key.verifying_key().to_bytes())
            .expect("build Agent DID");
        let mut request = RegistrationRequest {
            version: REGISTRATION_PROTOCOL_VERSION,
            request_id: "request-1".to_owned(),
            network_id: "network-1".to_owned(),
            agent_did: format!("did:key:{}", did.public_key_multibase),
            nickname: "Agent One".to_owned(),
            agent_card: None,
            agent_card_hash: None,
            tenant_instance_id: None,
            nonce: "nonce-1".to_owned(),
            signature_b64: String::new(),
        };
        request.signature_b64 = base64::engine::general_purpose::STANDARD.encode(
            key.sign(&request.signing_message().expect("signing bytes"))
                .to_bytes(),
        );
        request
    }

    #[test]
    fn registration_request_binds_the_canonical_agent_card_hash() {
        let agent_key = SigningKey::from_bytes(&[6; 32]);
        let mut request = request_for(&agent_key);
        let card = json!({
            "name": "Agent One",
            "metadata": {"agent_id": request.agent_did.clone()}
        });
        let canonical = serde_jcs::to_vec(&card).expect("canonical Agent Card");
        request.agent_card_hash = Some(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(&canonical))
        ));
        request.agent_card = Some(card);
        request.signature_b64 = base64::engine::general_purpose::STANDARD.encode(
            agent_key
                .sign(&request.signing_message().expect("signing bytes"))
                .to_bytes(),
        );
        verify_agent_registration_request(&request).expect("Agent Card request verifies");

        request.agent_card.as_mut().expect("Agent Card")["name"] = json!("Tampered");
        let error = verify_agent_registration_request(&request)
            .expect_err("tampered Agent Card must be rejected");
        assert!(error.to_string().contains("hash does not match"));
    }

    #[test]
    fn agent_did_request_and_authority_credential_verify() {
        let agent_key = SigningKey::from_bytes(&[7; 32]);
        let request = request_for(&agent_key);
        verify_agent_registration_request(&request).expect("request verifies");

        let authority = AuthoritySigner::from_seed([8; 32]);
        let authority_id = "authority-1";
        let decision = authority
            .sign_decision(UnsignedRegistrationDecision {
                version: REGISTRATION_PROTOCOL_VERSION,
                request_id: request.request_id.clone(),
                network_id: request.network_id.clone(),
                agent_did: request.agent_did.clone(),
                action: RegistrationDecisionKind::Approve,
                status: RegistrationStatus::Approved,
                reviewer_id: Some("operator".to_owned()),
                reviewed_at_ms: 100,
                review_note: None,
                issuer_authority_id: authority_id.to_owned(),
                signing_key_id: None,
                signature_algorithm: None,
            })
            .expect("decision signs");
        AuthoritySigner::verify_decision(&decision, authority_id, &authority.public_key_hex())
            .expect("decision verifies");

        let credential = authority
            .sign_credential(UnsignedMembershipCredential {
                version: REGISTRATION_PROTOCOL_VERSION,
                credential_id: "credential-1".to_owned(),
                request_id: request.request_id,
                network_id: request.network_id,
                agent_did: request.agent_did,
                issuer_authority_id: authority_id.to_owned(),
                issued_at_ms: 100,
                expires_at_ms: None,
                signing_key_id: None,
                signature_algorithm: None,
            })
            .expect("credential signs");
        AuthoritySigner::verify_credential(
            &credential,
            authority_id,
            &authority.public_key_hex(),
            101,
        )
        .expect("credential verifies");
        assert!(
            AuthoritySigner::verify_credential(
                &credential,
                "another-authority",
                &authority.public_key_hex(),
                101,
            )
            .is_err(),
            "a valid signature must still be bound to the expected authority ID"
        );
        let credential_json = serde_json::to_value(&credential).expect("credential JSON");
        assert_eq!(credential_json["issuer_authority_id"], authority_id);
        assert!(credential_json.get("issuer_genesis_id").is_none());

        let mut tampered = credential;
        tampered.unsigned.agent_did = "did:key:zTampered".to_owned();
        assert!(
            AuthoritySigner::verify_credential(
                &tampered,
                authority_id,
                &authority.public_key_hex(),
                101,
            )
            .is_err(),
            "changing signed credential fields must invalidate the signature"
        );
    }

    #[test]
    fn changing_nickname_does_not_invalidate_current_request_signature() {
        let agent_key = SigningKey::from_bytes(&[9; 32]);
        let mut request = request_for(&agent_key);
        request.nickname = "Agent Renamed".to_owned();
        verify_agent_registration_request(&request).expect("renamed request verifies");
    }

    #[test]
    fn legacy_request_signature_remains_accepted_during_transition() {
        let agent_key = SigningKey::from_bytes(&[10; 32]);
        let mut request = request_for(&agent_key);
        request.signature_b64 = base64::engine::general_purpose::STANDARD.encode(
            agent_key
                .sign(
                    &request
                        .legacy_signing_message()
                        .expect("legacy signing bytes"),
                )
                .to_bytes(),
        );
        verify_agent_registration_request(&request).expect("legacy request verifies");
    }

    #[test]
    fn discovery_record_signature_and_source_agent_card_are_verified() {
        let node_key = SigningKey::from_bytes(&[31; 32]);
        let node_id = hex::encode(node_key.verifying_key().to_bytes());
        let card = json!({
            "name": "Registry Agent",
            "metadata": {"node_id": node_id},
        });
        let card_hash = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                serde_jcs::to_string(&card).unwrap().as_bytes()
            ))
        );
        let mut body = DiscoveryNodeRecordBody {
            protocol_version: DISCOVERY_PROTOCOL_VERSION.to_owned(),
            network_id: "network-1".to_owned(),
            node_id: node_id.clone(),
            signing_public_key_hex: node_id.clone(),
            seq: 1,
            updated_at_ms: 1_000,
            ttl_ms: 5_000,
            geo: None,
            capabilities: json!({"services": ["wattswarm.node"]}),
            topic_providers: Vec::new(),
            transport_contact: None,
            source_agent_card: Some(json!({
                "agent_id": "did:key:zAgent",
                "node_id": node_id,
                "card_hash": card_hash,
                "issued_at": 1_000,
                "card": card,
                "signature": "agent-card-signature",
            })),
        };
        let signature = node_key.sign(&body.signing_bytes().unwrap());
        let record = SignedDiscoveryNodeRecord {
            body: body.clone(),
            signature_hex: hex::encode(signature.to_bytes()),
        };
        verify_discovery_node_record(&record, 1_500).expect("discovery record verifies");

        body.network_id = "tampered-network".to_owned();
        let tampered = SignedDiscoveryNodeRecord {
            body,
            signature_hex: record.signature_hex,
        };
        assert!(verify_discovery_node_record(&tampered, 1_500).is_err());
    }
}
