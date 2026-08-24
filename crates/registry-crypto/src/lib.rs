use anyhow::{Context, Result, bail};
use base64::Engine as _;
use registry_protocol::{
    AuthorityKeyCertificate, BINARY_ENCODING_HEX, DISCOVERY_PROTOCOL_VERSION, MembershipCredential,
    RegistrationDecision, RegistrationRequest, RegistrationStatus, SIGNATURE_ALGORITHM_ED25519,
    SignedDiscoveryNodeRecord, UnsignedAuthorityKeyCertificate, UnsignedMembershipCredential,
    UnsignedRegistrationDecision,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use watt_credential::{
    DetachedSignature, SigningKeyMaterial, derive_public_key, generate_signing_key, sign_detached,
    validate_signature_algorithm, verify_detached_signature,
};
use watt_did::{Did, DidKey, DidKeyPublicKey};

#[derive(Clone)]
pub struct AuthoritySigner {
    algorithm: String,
    private_key_hex: String,
    public_key_hex: String,
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
        Self::from_seed_hex(&hex::encode(seed)).expect("fixed Ed25519 seed must be valid")
    }

    pub fn from_seed_hex(value: &str) -> Result<Self> {
        Self::from_algorithm_seed_hex(SIGNATURE_ALGORITHM_ED25519, value)
    }

    /// Construct a signer for the algorithm recorded in the registry.
    ///
    /// Algorithm selection and key validation are delegated to Watt Credential.
    /// The registry only retains the selected algorithm and private key material.
    pub fn from_algorithm_seed_hex(algorithm: &str, value: &str) -> Result<Self> {
        let private_key_hex = value.trim().to_owned();
        let public_key_hex = derive_public_key(
            SigningKeyMaterial {
                algorithm,
                private_key_encoding: BINARY_ENCODING_HEX,
                private_key: &private_key_hex,
            },
            BINARY_ENCODING_HEX,
        )
        .context("derive authority public key")?;
        Ok(Self {
            algorithm: algorithm.to_owned(),
            private_key_hex,
            public_key_hex,
        })
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
        let generated = generate_signing_key(SIGNATURE_ALGORITHM_ED25519)
            .context("generate authority signing key")?;
        std::fs::write(path, format!("{}\n", generated.private_key))
            .with_context(|| format!("write authority seed at {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("restrict authority seed at {}", path.display()))?;
        }
        Ok(Self {
            algorithm: generated.algorithm,
            private_key_hex: generated.private_key,
            public_key_hex: generated.public_key,
        })
    }

    pub fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn seed_hex(&self) -> String {
        self.private_key_hex.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<String> {
        sign_detached(
            SigningKeyMaterial {
                algorithm: &self.algorithm,
                private_key_encoding: BINARY_ENCODING_HEX,
                private_key: &self.private_key_hex,
            },
            BINARY_ENCODING_HEX,
            message,
        )
        .context("sign registry payload")
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
        validate_signer_algorithm(self, payload.signature_algorithm.as_deref())?;
        let signature_hex = self.sign(&payload.signing_bytes()?)?;
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
        validate_credential_key_certificate(&payload)?;
        if payload
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= payload.issued_at_ms)
        {
            bail!("credential expiry must be after issued_at_ms");
        }
        validate_signer_algorithm(self, payload.signature_algorithm.as_deref())?;
        let signature_hex = self.sign(&payload.signing_bytes()?)?;
        Ok(MembershipCredential {
            unsigned: payload,
            signature_hex,
        })
    }

    pub fn sign_authority_key_certificate(
        &self,
        payload: UnsignedAuthorityKeyCertificate,
    ) -> Result<AuthorityKeyCertificate> {
        if payload.version != registry_protocol::REGISTRATION_PROTOCOL_VERSION {
            bail!("unsupported authority key certificate protocol version");
        }
        validate_non_empty("network_id", &payload.network_id)?;
        validate_non_empty("authority_id", &payload.authority_id)?;
        validate_non_empty("key_id", &payload.key_id)?;
        validate_non_empty("trust_anchor_id", &payload.trust_anchor_id)?;
        validate_signer_algorithm(self, Some(&payload.signature_algorithm))?;
        if payload.public_key_encoding != BINARY_ENCODING_HEX {
            bail!("unsupported authority public key encoding");
        }
        if payload
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= payload.issued_at_ms)
        {
            bail!("authority key certificate expiry must be after issued_at_ms");
        }
        Ok(AuthorityKeyCertificate {
            trust_anchor_signature_algorithm: self.algorithm().to_owned(),
            trust_anchor_signature_encoding: BINARY_ENCODING_HEX.to_owned(),
            trust_anchor_signature: self.sign(&payload.signing_bytes()?)?,
            unsigned: payload,
        })
    }

    pub fn verify_authority_key_certificate(
        certificate: &AuthorityKeyCertificate,
        expected_trust_anchor_id: &str,
        expected_trust_anchor_public_key_hex: &str,
        now_ms: u64,
    ) -> Result<()> {
        if certificate.unsigned.trust_anchor_id != expected_trust_anchor_id {
            bail!("authority key certificate trust anchor is not trusted");
        }
        if certificate.trust_anchor_signature_encoding != BINARY_ENCODING_HEX {
            bail!("unsupported trust anchor signature encoding");
        }
        if certificate
            .unsigned
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= now_ms)
        {
            bail!("authority key certificate has expired");
        }
        verify_authority_signature(
            Some(&certificate.trust_anchor_signature_algorithm),
            expected_trust_anchor_public_key_hex,
            &certificate.signing_bytes()?,
            &certificate.trust_anchor_signature,
        )
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
        expected_trust_anchor_id: &str,
        expected_trust_anchor_public_key_hex: &str,
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
        let certificate = credential
            .unsigned
            .issuer_key_certificate
            .as_ref()
            .context("membership credential has no issuer key certificate; reissue is required")?;
        if certificate.unsigned.network_id != credential.unsigned.network_id
            || certificate.unsigned.authority_id != credential.unsigned.issuer_authority_id
            || Some(certificate.unsigned.key_id.as_str())
                != credential.unsigned.signing_key_id.as_deref()
            || Some(certificate.unsigned.signature_algorithm.as_str())
                != credential.unsigned.signature_algorithm.as_deref()
        {
            bail!("membership credential issuer key certificate does not match credential");
        }
        Self::verify_authority_key_certificate(
            certificate,
            expected_trust_anchor_id,
            expected_trust_anchor_public_key_hex,
            now_ms,
        )?;
        verify_authority_signature(
            credential.unsigned.signature_algorithm.as_deref(),
            &certificate.unsigned.public_key,
            &credential.signing_bytes()?,
            &credential.signature_hex,
        )
    }
}

fn validate_credential_key_certificate(payload: &UnsignedMembershipCredential) -> Result<()> {
    let certificate = payload
        .issuer_key_certificate
        .as_ref()
        .context("membership credential has no issuer key certificate")?;
    if certificate.unsigned.network_id != payload.network_id
        || certificate.unsigned.authority_id != payload.issuer_authority_id
        || Some(certificate.unsigned.key_id.as_str()) != payload.signing_key_id.as_deref()
        || Some(certificate.unsigned.signature_algorithm.as_str())
            != payload.signature_algorithm.as_deref()
    {
        bail!("membership credential issuer key certificate does not match credential");
    }
    Ok(())
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
    let public_key_hex = agent_public_key_hex(&request.agent_did)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(request.signature_b64.trim())
        .context("decode registration request signature base64")?;
    let signature_hex = hex::encode(signature_bytes);
    if verify_signature(
        SIGNATURE_ALGORITHM_ED25519,
        &public_key_hex,
        &request.signing_message()?,
        &signature_hex,
    )
    .is_ok()
    {
        return Ok(());
    }
    verify_signature(
        SIGNATURE_ALGORITHM_ED25519,
        &public_key_hex,
        &request.legacy_signing_message()?,
        &signature_hex,
    )
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
    let record_size = serde_json::to_vec(record)
        .context("serialize discovery record for size validation")?
        .len();
    if record_size > 256 * 1024 {
        bail!("discovery record exceeds 256 KiB");
    }
    verify_signature(
        SIGNATURE_ALGORITHM_ED25519,
        &body.signing_public_key_hex,
        &body.signing_bytes()?,
        &record.signature_hex,
    )
    .context("verify discovery record signature")
}

fn validate_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value != value.trim() {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn agent_public_key_hex(agent_did: &str) -> Result<String> {
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
    Ok(hex::encode(public_key))
}

fn verify_authority_signature(
    algorithm: Option<&str>,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    verify_signature(
        algorithm.unwrap_or(SIGNATURE_ALGORITHM_ED25519),
        public_key_hex,
        message,
        signature_hex,
    )
}

fn validate_algorithm(algorithm: Option<&str>) -> Result<()> {
    validate_signature_algorithm(algorithm.unwrap_or(SIGNATURE_ALGORITHM_ED25519))
        .context("validate registry signature algorithm")
}

fn validate_signer_algorithm(signer: &AuthoritySigner, algorithm: Option<&str>) -> Result<()> {
    let algorithm = algorithm.unwrap_or(SIGNATURE_ALGORITHM_ED25519);
    validate_algorithm(Some(algorithm))?;
    if algorithm != signer.algorithm() {
        bail!(
            "payload signature algorithm '{algorithm}' does not match registry signer '{}'",
            signer.algorithm()
        );
    }
    Ok(())
}

fn verify_signature(
    algorithm: &str,
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    verify_detached_signature(
        DetachedSignature {
            algorithm,
            public_key_encoding: BINARY_ENCODING_HEX,
            public_key: public_key_hex,
            signature_encoding: BINARY_ENCODING_HEX,
            signature: signature_hex,
        },
        message,
    )
    .context("verify registry signature")
}

pub fn status_allows_credential(status: RegistrationStatus) -> bool {
    matches!(status, RegistrationStatus::Approved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_protocol::{
        BINARY_ENCODING_HEX, DISCOVERY_PROTOCOL_VERSION, DiscoveryNodeRecordBody,
        REGISTRATION_PROTOCOL_VERSION, RegistrationDecisionKind, SignedDiscoveryNodeRecord,
        UnsignedAuthorityKeyCertificate, UnsignedMembershipCredential,
        UnsignedRegistrationDecision,
    };
    use serde_json::json;

    fn private_key_hex(seed: u8) -> String {
        hex::encode([seed; 32])
    }

    fn public_key_hex(seed: u8) -> String {
        let private_key = private_key_hex(seed);
        derive_public_key(
            SigningKeyMaterial {
                algorithm: SIGNATURE_ALGORITHM_ED25519,
                private_key_encoding: BINARY_ENCODING_HEX,
                private_key: &private_key,
            },
            BINARY_ENCODING_HEX,
        )
        .expect("derive test public key")
    }

    fn sign_hex(seed: u8, message: &[u8]) -> String {
        let private_key = private_key_hex(seed);
        sign_detached(
            SigningKeyMaterial {
                algorithm: SIGNATURE_ALGORITHM_ED25519,
                private_key_encoding: BINARY_ENCODING_HEX,
                private_key: &private_key,
            },
            BINARY_ENCODING_HEX,
            message,
        )
        .expect("sign test payload")
    }

    fn sign_b64(seed: u8, message: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD
            .encode(hex::decode(sign_hex(seed, message)).expect("decode test signature"))
    }

    fn request_for(seed: u8) -> RegistrationRequest {
        let public_key: [u8; 32] = hex::decode(public_key_hex(seed))
            .expect("decode test public key")
            .try_into()
            .expect("test public key length");
        let did = DidKey::from_ed25519_public_key(public_key).expect("build Agent DID");
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
        request.signature_b64 = sign_b64(seed, &request.signing_message().expect("signing bytes"));
        request
    }

    #[test]
    fn registration_request_binds_the_canonical_agent_card_hash() {
        let mut request = request_for(6);
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
        request.signature_b64 = sign_b64(6, &request.signing_message().expect("signing bytes"));
        verify_agent_registration_request(&request).expect("Agent Card request verifies");

        request.agent_card.as_mut().expect("Agent Card")["name"] = json!("Tampered");
        let error = verify_agent_registration_request(&request)
            .expect_err("tampered Agent Card must be rejected");
        assert!(error.to_string().contains("hash does not match"));
    }

    #[test]
    fn agent_did_request_and_authority_credential_verify() {
        let request = request_for(7);
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

        let authority_public_key = authority.public_key_hex();
        let key_id = format!("ed25519-{authority_public_key}");
        let issuer_key_certificate = authority
            .sign_authority_key_certificate(UnsignedAuthorityKeyCertificate {
                version: REGISTRATION_PROTOCOL_VERSION,
                network_id: request.network_id.clone(),
                authority_id: authority_id.to_owned(),
                key_id: key_id.clone(),
                signature_algorithm: SIGNATURE_ALGORITHM_ED25519.to_owned(),
                public_key_encoding: BINARY_ENCODING_HEX.to_owned(),
                public_key: authority_public_key.clone(),
                trust_anchor_id: authority_public_key.clone(),
                issued_at_ms: 90,
                expires_at_ms: None,
            })
            .expect("authority key certificate signs");
        let credential = authority
            .sign_credential(UnsignedMembershipCredential {
                version: REGISTRATION_PROTOCOL_VERSION,
                credential_id: "credential-1".to_owned(),
                network_id: request.network_id,
                agent_did: request.agent_did,
                issuer_authority_id: authority_id.to_owned(),
                issued_at_ms: 100,
                expires_at_ms: None,
                signing_key_id: Some(key_id),
                signature_algorithm: Some(SIGNATURE_ALGORITHM_ED25519.to_owned()),
                issuer_key_certificate: Some(issuer_key_certificate),
            })
            .expect("credential signs");
        AuthoritySigner::verify_credential(
            &credential,
            authority_id,
            &authority_public_key,
            &authority_public_key,
            101,
        )
        .expect("credential verifies");
        assert!(
            AuthoritySigner::verify_credential(
                &credential,
                "another-authority",
                &authority_public_key,
                &authority_public_key,
                101,
            )
            .is_err(),
            "a valid signature must still be bound to the expected authority ID"
        );
        let credential_json = serde_json::to_value(&credential).expect("credential JSON");
        assert_eq!(credential_json["issuer_authority_id"], authority_id);
        assert!(credential_json.get("issuer_genesis_id").is_none());

        let mut legacy = credential.clone();
        legacy.unsigned.issuer_key_certificate = None;
        let error = AuthoritySigner::verify_credential(
            &legacy,
            authority_id,
            &authority_public_key,
            &authority_public_key,
            101,
        )
        .expect_err("Credential without issuer proof must be reissued");
        assert!(error.to_string().contains("reissue is required"));

        let mut tampered = credential;
        tampered.unsigned.agent_did = "did:key:zTampered".to_owned();
        assert!(
            AuthoritySigner::verify_credential(
                &tampered,
                authority_id,
                &authority_public_key,
                &authority_public_key,
                101,
            )
            .is_err(),
            "changing signed credential fields must invalidate the signature"
        );
    }

    #[test]
    fn changing_nickname_does_not_invalidate_current_request_signature() {
        let mut request = request_for(9);
        request.nickname = "Agent Renamed".to_owned();
        verify_agent_registration_request(&request).expect("renamed request verifies");
    }

    #[test]
    fn legacy_request_signature_remains_accepted_during_transition() {
        let mut request = request_for(10);
        request.signature_b64 = sign_b64(
            10,
            &request
                .legacy_signing_message()
                .expect("legacy signing bytes"),
        );
        verify_agent_registration_request(&request).expect("legacy request verifies");
    }

    #[test]
    fn discovery_record_signature_and_source_agent_card_are_verified() {
        let node_id = public_key_hex(31);
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
        let record = SignedDiscoveryNodeRecord {
            body: body.clone(),
            signature_hex: sign_hex(31, &body.signing_bytes().unwrap()),
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
