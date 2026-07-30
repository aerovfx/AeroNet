//! Durable broker state: replay protection, capability usage and offline delivery.

use crate::{Envelope, MessageKind};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

pub struct DeliveryStore {
    connection: Connection,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AcceptOutcome {
    Queued,
    Acknowledged,
}

impl DeliveryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS seen_messages (
                 id TEXT PRIMARY KEY,
                 seen_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS pending_messages (
                 id TEXT PRIMARY KEY REFERENCES seen_messages(id) ON DELETE CASCADE,
                 recipient TEXT NOT NULL,
                 envelope_json TEXT NOT NULL,
                 valid_until TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS pending_recipient_idx
                 ON pending_messages(recipient, valid_until);
             CREATE TABLE IF NOT EXISTS capability_usage (
                 nonce TEXT PRIMARY KEY,
                 uses INTEGER NOT NULL
             );",
        )?;
        Ok(Self { connection })
    }

    /// Atomically records replay state, consumes capability quota, and either
    /// queues a message or acknowledges a previously queued message.
    pub fn accept(&mut self, envelope: &Envelope) -> Result<AcceptOutcome> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO seen_messages(id, seen_at) VALUES (?1, ?2)",
            params![envelope.id, Utc::now().to_rfc3339()],
        )?;
        if inserted == 0 {
            bail!("Message replay detected: {}", envelope.id)
        }

        if let Some(capability) = &envelope.capability {
            let uses: u32 = transaction
                .query_row(
                    "SELECT uses FROM capability_usage WHERE nonce = ?1",
                    params![capability.nonce],
                    |row| row.get(0),
                )
                .optional()?
                .unwrap_or(0);
            if uses >= capability.max_messages {
                bail!("Capability quota exhausted")
            }
            transaction.execute(
                "INSERT INTO capability_usage(nonce, uses) VALUES (?1, 1)
                 ON CONFLICT(nonce) DO UPDATE SET uses = uses + 1",
                params![capability.nonce],
            )?;
        }

        let outcome = if matches!(envelope.kind, MessageKind::Ack) {
            let original_id = envelope
                .in_reply_to
                .as_deref()
                .context("Delivery ACK is missing in_reply_to")?;
            transaction.execute(
                "DELETE FROM pending_messages WHERE id = ?1 AND recipient = ?2",
                params![original_id, envelope.from.to_string()],
            )?;
            AcceptOutcome::Acknowledged
        } else {
            transaction.execute(
                "INSERT INTO pending_messages(id, recipient, envelope_json, valid_until)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    envelope.id,
                    envelope.to.to_string(),
                    serde_json::to_string(envelope)?,
                    envelope.valid_until.to_rfc3339()
                ],
            )?;
            AcceptOutcome::Queued
        };

        transaction.commit()?;
        Ok(outcome)
    }

    pub fn pending_for(&mut self, recipient: &str) -> Result<Vec<Envelope>> {
        self.connection.execute(
            "DELETE FROM pending_messages WHERE valid_until <= ?1",
            params![Utc::now().to_rfc3339()],
        )?;
        let mut statement = self.connection.prepare(
            "SELECT envelope_json FROM pending_messages
             WHERE recipient = ?1 ORDER BY rowid ASC",
        )?;
        let rows = statement.query_map(params![recipient], |row| row.get::<_, String>(0))?;
        rows.map(|row| {
            let json = row?;
            serde_json::from_str(&json).context("Invalid pending envelope in database")
        })
        .collect()
    }

    pub fn pending_count(&self) -> Result<u64> {
        Ok(self
            .connection
            .query_row("SELECT COUNT(*) FROM pending_messages", [], |row| {
                row.get(0)
            })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, CapabilityAction, Identity, Payload};
    use chrono::Duration;

    fn signed_message(sender: &Identity, recipient: &Identity, max_messages: u32) -> Envelope {
        let capability = Capability::issue(
            recipient,
            sender.id(),
            vec![CapabilityAction::Query, CapabilityAction::Acknowledge],
            max_messages,
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
        Envelope::new(
            sender,
            recipient.id(),
            MessageKind::Query,
            Payload::Text {
                content: "hello".into(),
            },
            None,
            Some(capability),
            Duration::minutes(5),
        )
        .unwrap()
    }

    #[test]
    fn queues_rejects_replay_and_restores_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("broker.db");
        let alice = Identity::generate();
        let bob = Identity::generate();
        let message = signed_message(&alice, &bob, 2);

        let mut store = DeliveryStore::open(&path).unwrap();
        assert_eq!(store.accept(&message).unwrap(), AcceptOutcome::Queued);
        assert!(store.accept(&message).is_err());
        drop(store);

        let mut reopened = DeliveryStore::open(&path).unwrap();
        let pending = reopened.pending_for(&bob.id().to_string()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, message.id);
    }

    #[test]
    fn signed_ack_removes_only_recipient_message() {
        let mut store = DeliveryStore::open(":memory:").unwrap();
        let alice = Identity::generate();
        let bob = Identity::generate();
        let message = signed_message(&alice, &bob, 2);
        store.accept(&message).unwrap();

        let ack_capability = Capability::issue(
            &alice,
            bob.id(),
            vec![CapabilityAction::Acknowledge],
            1,
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
        let ack = Envelope::new(
            &bob,
            alice.id(),
            MessageKind::Ack,
            Payload::Text {
                content: "delivered".into(),
            },
            Some(message.id),
            Some(ack_capability),
            Duration::minutes(1),
        )
        .unwrap();
        assert_eq!(store.accept(&ack).unwrap(), AcceptOutcome::Acknowledged);
        assert_eq!(store.pending_count().unwrap(), 0);
    }
}
