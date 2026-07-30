use crate::identity::{verify_identity, AgentId, Identity};
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAction {
    Query,
    Answer,
    Propose,
    Critique,
    Acknowledge,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    pub schema: String,
    pub issuer: AgentId,
    pub issuer_public_key: String,
    pub grantee: AgentId,
    pub audience: AgentId,
    pub actions: Vec<CapabilityAction>,
    pub max_messages: u32,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedCapability<'a> {
    schema: &'a str,
    issuer: &'a AgentId,
    issuer_public_key: &'a str,
    grantee: &'a AgentId,
    audience: &'a AgentId,
    actions: &'a [CapabilityAction],
    max_messages: u32,
    expires_at: DateTime<Utc>,
    nonce: &'a str,
}

impl Capability {
    pub fn issue(
        issuer: &Identity,
        grantee: AgentId,
        actions: Vec<CapabilityAction>,
        max_messages: u32,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        let mut token = Self {
            schema: "aeronet.capability.v1".into(),
            issuer: issuer.id(),
            issuer_public_key: issuer.public_key_b64(),
            grantee,
            audience: issuer.id(),
            actions,
            max_messages,
            expires_at,
            nonce: uuid::Uuid::new_v4().to_string(),
            signature: String::new(),
        };
        token.signature = issuer.sign(&token.signing_bytes()?);
        Ok(token)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&UnsignedCapability {
            schema: &self.schema,
            issuer: &self.issuer,
            issuer_public_key: &self.issuer_public_key,
            grantee: &self.grantee,
            audience: &self.audience,
            actions: &self.actions,
            max_messages: self.max_messages,
            expires_at: self.expires_at,
            nonce: &self.nonce,
        })?)
    }

    pub fn verify(
        &self,
        sender: &AgentId,
        recipient: &AgentId,
        action: &CapabilityAction,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.schema != "aeronet.capability.v1" {
            bail!("Unsupported capability schema")
        }
        if &self.grantee != sender || &self.audience != recipient || &self.issuer != recipient {
            bail!("Capability was not granted for this route")
        }
        if !self.actions.contains(action) {
            bail!("Capability does not allow this action")
        }
        if self.expires_at <= now {
            bail!("Capability has expired")
        }
        verify_identity(
            &self.issuer,
            &self.issuer_public_key,
            &self.signing_bytes()?,
            &self.signature,
        )
    }
}
