use crate::{
    capability::{Capability, CapabilityAction},
    identity::{verify_identity, AgentId, Identity},
};
use anyhow::{bail, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthProof {
    pub agent_id: AgentId,
    pub public_key: String,
    pub challenge: String,
    pub signature: String,
}

impl AuthProof {
    pub fn create(identity: &Identity, challenge: String) -> Self {
        Self {
            agent_id: identity.id(),
            public_key: identity.public_key_b64(),
            signature: identity.sign(challenge.as_bytes()),
            challenge,
        }
    }

    pub fn verify(&self, expected_challenge: &str) -> Result<()> {
        if self.challenge != expected_challenge {
            bail!("Challenge mismatch")
        }
        verify_identity(
            &self.agent_id,
            &self.public_key,
            self.challenge.as_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Query,
    Answer,
    Proposal,
    Critique,
    Ack,
    End,
}

impl MessageKind {
    pub fn capability_action(&self) -> Option<CapabilityAction> {
        match self {
            Self::Query => Some(CapabilityAction::Query),
            Self::Answer => Some(CapabilityAction::Answer),
            Self::Proposal => Some(CapabilityAction::Propose),
            Self::Critique => Some(CapabilityAction::Critique),
            Self::Ack => Some(CapabilityAction::Acknowledge),
            Self::End => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskContract {
    pub goal: String,
    #[serde(default)]
    pub constraints: Vec<String>,
    pub budget_units: Option<u64>,
    pub deadline: Option<DateTime<Utc>>,
    pub expected_output_schema: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    Task {
        contract: TaskContract,
    },
    Knowledge {
        ontology: String,
        data: serde_json::Value,
        confidence: Option<f32>,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        superseded_by: Option<String>,
    },
    Text {
        content: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub schema: String,
    pub id: String,
    pub in_reply_to: Option<String>,
    pub from: AgentId,
    pub from_public_key: String,
    pub to: AgentId,
    pub kind: MessageKind,
    pub payload: Payload,
    pub capability: Option<Capability>,
    pub created_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub cost_microunits: Option<u64>,
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    schema: &'a str,
    id: &'a str,
    in_reply_to: &'a Option<String>,
    from: &'a AgentId,
    from_public_key: &'a str,
    to: &'a AgentId,
    kind: &'a MessageKind,
    payload: &'a Payload,
    capability: &'a Option<Capability>,
    created_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    cost_microunits: Option<u64>,
}

impl Envelope {
    pub fn new(
        identity: &Identity,
        to: AgentId,
        kind: MessageKind,
        payload: Payload,
        in_reply_to: Option<String>,
        capability: Option<Capability>,
        ttl: Duration,
    ) -> Result<Self> {
        let now = Utc::now();
        let mut value = Self {
            schema: "aeronet.message.v1".into(),
            id: uuid::Uuid::new_v4().to_string(),
            in_reply_to,
            from: identity.id(),
            from_public_key: identity.public_key_b64(),
            to,
            kind,
            payload,
            capability,
            created_at: now,
            valid_until: now + ttl,
            cost_microunits: None,
            signature: String::new(),
        };
        value.signature = identity.sign(&value.signing_bytes()?);
        Ok(value)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&UnsignedEnvelope {
            schema: &self.schema,
            id: &self.id,
            in_reply_to: &self.in_reply_to,
            from: &self.from,
            from_public_key: &self.from_public_key,
            to: &self.to,
            kind: &self.kind,
            payload: &self.payload,
            capability: &self.capability,
            created_at: self.created_at,
            valid_until: self.valid_until,
            cost_microunits: self.cost_microunits,
        })?)
    }

    pub fn verify(&self, now: DateTime<Utc>) -> Result<()> {
        if self.schema != "aeronet.message.v1" {
            bail!("Unsupported message schema")
        }
        if self.valid_until <= now || self.created_at > now + Duration::minutes(5) {
            bail!("Message expired or timestamped in the future")
        }
        verify_identity(
            &self.from,
            &self.from_public_key,
            &self.signing_bytes()?,
            &self.signature,
        )?;
        if let Some(action) = self.kind.capability_action() {
            self.capability
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing capability token"))?
                .verify(&self.from, &self.to, &action, now)?;
        }
        if let Payload::Knowledge {
            valid_from,
            valid_until,
            ..
        } = &self.payload
        {
            if valid_until <= valid_from || *valid_until <= now {
                bail!("Knowledge object is no longer valid")
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_task_verifies_and_tampering_fails() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let cap = Capability::issue(
            &bob,
            alice.id(),
            vec![CapabilityAction::Query],
            5,
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
        let mut msg = Envelope::new(
            &alice,
            bob.id(),
            MessageKind::Query,
            Payload::Task {
                contract: TaskContract {
                    goal: "analyze the dataset".into(),
                    constraints: vec!["no PII".into()],
                    budget_units: Some(100),
                    deadline: None,
                    expected_output_schema: Some("report.v1".into()),
                },
            },
            None,
            Some(cap),
            Duration::minutes(5),
        )
        .unwrap();
        msg.verify(Utc::now()).unwrap();
        if let Payload::Task { contract } = &mut msg.payload {
            contract.goal = "tampered content".into();
        }
        assert!(msg.verify(Utc::now()).is_err());
    }

    #[test]
    fn capability_cannot_be_reused_for_another_sender() {
        let alice = Identity::generate();
        let mallory = Identity::generate();
        let bob = Identity::generate();
        let cap = Capability::issue(
            &bob,
            alice.id(),
            vec![CapabilityAction::Query],
            1,
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
        let msg = Envelope::new(
            &mallory,
            bob.id(),
            MessageKind::Query,
            Payload::Text {
                content: "unauthorized".into(),
            },
            None,
            Some(cap),
            Duration::minutes(1),
        )
        .unwrap();
        assert!(msg.verify(Utc::now()).is_err());
    }

    #[test]
    fn expired_message_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let msg = Envelope::new(
            &alice,
            bob.id(),
            MessageKind::End,
            Payload::Text {
                content: "bye".into(),
            },
            None,
            None,
            Duration::seconds(-1),
        )
        .unwrap();
        assert!(msg.verify(Utc::now()).is_err());
    }
}
