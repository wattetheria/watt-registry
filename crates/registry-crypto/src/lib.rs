use anyhow::{Context, Result, bail};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use registry_protocol::{
    MembershipCredential, RegistrationDecision, RegistrationRequest, RegistrationStatus,
    UnsignedMembershipCredential, UnsignedRegistrationDecision,
};
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
            .field("authority_id", &self.authority_id())
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

    pub fn authority_id(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign_decision(
        &self,
        payload: UnsignedRegistrationDecision,
    ) -> Result<RegistrationDecision> {
        if payload.version != registry_protocol::REGISTRATION_PROTOCOL_VERSION {
            bail!("unsupported registration decision protocol version");
        }
        if payload.issuer_authority_id != self.authority_id() {
            bail!("registration decision issuer does not match authority signer");
        }
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
        if payload.issuer_authority_id != self.authority_id() {
            bail!("membership credential issuer does not match authority signer");
        }
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
    ) -> Result<()> {
        if decision.unsigned.issuer_authority_id != expected_authority_id {
            bail!("registration decision issuer is not trusted");
        }
        verify_authority_signature(
            expected_authority_id,
            &decision.signing_bytes()?,
            &decision.signature_hex,
        )
    }

    pub fn verify_credential(
        credential: &MembershipCredential,
        expected_authority_id: &str,
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
            expected_authority_id,
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
    let verifying_key = agent_verifying_key(&request.agent_did)?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(request.signature_b64.trim())
        .context("decode registration request signature base64")?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("registration signature must contain 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);
    verifying_key
        .verify(&request.signing_message()?, &signature)
        .context("registration request signature verification failed")
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
    authority_id: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<()> {
    let public_key = hex::decode(authority_id.trim()).context("decode authority public key")?;
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("authority id must contain a 32-byte public key"))?;
    let signature = hex::decode(signature_hex.trim()).context("decode authority signature")?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("authority signature must contain 64 bytes"))?;
    VerifyingKey::from_bytes(&public_key)?.verify(message, &Signature::from_bytes(&signature))?;
    Ok(())
}

pub fn status_allows_credential(status: RegistrationStatus) -> bool {
    matches!(status, RegistrationStatus::Approved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use registry_protocol::{
        REGISTRATION_PROTOCOL_VERSION, RegistrationDecisionKind, UnsignedMembershipCredential,
        UnsignedRegistrationDecision,
    };

    fn request_for(key: &SigningKey) -> RegistrationRequest {
        let did = DidKey::from_ed25519_public_key(key.verifying_key().to_bytes())
            .expect("build Agent DID");
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
            key.sign(&request.signing_message().expect("signing bytes"))
                .to_bytes(),
        );
        request
    }

    #[test]
    fn agent_did_request_and_authority_credential_verify() {
        let agent_key = SigningKey::from_bytes(&[7; 32]);
        let request = request_for(&agent_key);
        verify_agent_registration_request(&request).expect("request verifies");

        let authority = AuthoritySigner::from_seed([8; 32]);
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
                issuer_authority_id: authority.authority_id(),
            })
            .expect("decision signs");
        AuthoritySigner::verify_decision(&decision, &authority.authority_id())
            .expect("decision verifies");

        let credential = authority
            .sign_credential(UnsignedMembershipCredential {
                version: REGISTRATION_PROTOCOL_VERSION,
                credential_id: "credential-1".to_owned(),
                request_id: request.request_id,
                network_id: request.network_id,
                agent_did: request.agent_did,
                issuer_authority_id: authority.authority_id(),
                issued_at_ms: 100,
                expires_at_ms: None,
            })
            .expect("credential signs");
        AuthoritySigner::verify_credential(&credential, &authority.authority_id(), 101)
            .expect("credential verifies");
    }
}
