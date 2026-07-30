//! Noise Protocol Framework transport encryption for the agent<->broker link.
//!
//! Every WebSocket connection is wrapped in a Noise_NN handshake (anonymous,
//! ephemeral X25519, forward-secret) immediately after the WebSocket upgrade.
//! Noise_NN alone does not authenticate either side, so the resulting
//! handshake hash is used as a channel-binding value: it is folded into the
//! signed [`crate::AuthProof`] that the existing Ed25519 DID challenge-response
//! already produces. If an active attacker spliced two separate Noise
//! sessions together (one with the agent, one with the broker), the two
//! sides would compute different handshake hashes and the bound proof would
//! fail verification on whichever side did not originate the handshake.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use snow::{Builder, TransportState};
use std::sync::Mutex;

const NOISE_PARAMS: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";
/// Noise message framing overhead (16-byte Poly1305 tag) plus generous room
/// for the largest envelope we expect to encrypt in one frame.
const MAX_MESSAGE_LEN: usize = 65535;

/// One side of a completed Noise_NN handshake, ready to encrypt/decrypt
/// application frames. Encrypt and decrypt use independent nonce counters,
/// so the state can safely be shared (behind a mutex) between a send task
/// and a receive loop running concurrently on the same connection.
pub struct NoiseSession {
    transport: Mutex<TransportState>,
    handshake_hash: [u8; 32],
}

impl NoiseSession {
    /// Base64 handshake transcript hash, used as a channel-binding value.
    pub fn channel_binding(&self) -> String {
        B64.encode(self.handshake_hash)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; plaintext.len() + 16];
        let mut transport = self.transport.lock().unwrap();
        let len = transport
            .write_message(plaintext, &mut buffer)
            .context("Noise encryption failed")?;
        buffer.truncate(len);
        Ok(buffer)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; ciphertext.len()];
        let mut transport = self.transport.lock().unwrap();
        let len = transport
            .read_message(ciphertext, &mut buffer)
            .context("Noise decryption failed (tampered or replayed frame)")?;
        buffer.truncate(len);
        Ok(buffer)
    }
}

/// Runs the Noise_NN responder side of the handshake over a pair of
/// caller-provided send/receive closures for the two required handshake
/// messages, then returns the resulting session.
pub async fn responder_handshake<S, R, SFut, RFut>(send: S, recv: R) -> Result<NoiseSession>
where
    S: FnOnce(Vec<u8>) -> SFut,
    SFut: std::future::Future<Output = Result<()>>,
    R: FnOnce() -> RFut,
    RFut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let mut handshake = Builder::new(NOISE_PARAMS.parse()?)
        .build_responder()
        .context("cannot build Noise responder")?;

    // <- e
    let incoming = recv().await?;
    let mut scratch = [0u8; MAX_MESSAGE_LEN];
    handshake
        .read_message(&incoming, &mut scratch)
        .context("invalid Noise handshake message from initiator")?;

    // -> e, ee
    let mut outgoing = vec![0u8; MAX_MESSAGE_LEN];
    let len = handshake
        .write_message(&[], &mut outgoing)
        .context("cannot write Noise responder handshake message")?;
    outgoing.truncate(len);
    send(outgoing).await?;

    finish(handshake)
}

/// Runs the Noise_NN initiator side of the handshake.
pub async fn initiator_handshake<S, R, SFut, RFut>(send: S, recv: R) -> Result<NoiseSession>
where
    S: FnOnce(Vec<u8>) -> SFut,
    SFut: std::future::Future<Output = Result<()>>,
    R: FnOnce() -> RFut,
    RFut: std::future::Future<Output = Result<Vec<u8>>>,
{
    let mut handshake = Builder::new(NOISE_PARAMS.parse()?)
        .build_initiator()
        .context("cannot build Noise initiator")?;

    // -> e
    let mut outgoing = vec![0u8; MAX_MESSAGE_LEN];
    let len = handshake
        .write_message(&[], &mut outgoing)
        .context("cannot write Noise initiator handshake message")?;
    outgoing.truncate(len);
    send(outgoing).await?;

    // <- e, ee
    let incoming = recv().await?;
    let mut scratch = [0u8; MAX_MESSAGE_LEN];
    handshake
        .read_message(&incoming, &mut scratch)
        .context("invalid Noise handshake message from responder")?;

    finish(handshake)
}

fn finish(handshake: snow::HandshakeState) -> Result<NoiseSession> {
    if !handshake.is_handshake_finished() {
        bail!("Noise handshake did not complete")
    }
    let handshake_hash: [u8; 32] = handshake
        .get_handshake_hash()
        .try_into()
        .map_err(|_| anyhow::anyhow!("unexpected Noise handshake hash length"))?;
    let transport = handshake
        .into_transport_mode()
        .context("cannot switch Noise session into transport mode")?;
    Ok(NoiseSession {
        transport: Mutex::new(transport),
        handshake_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshake_produces_matching_channel_binding_and_working_cipher() {
        let (to_responder_tx, mut to_responder_rx) = tokio::sync::mpsc::unbounded_channel();
        let (to_initiator_tx, mut to_initiator_rx) = tokio::sync::mpsc::unbounded_channel();

        let initiator = tokio::spawn(async move {
            initiator_handshake(
                move |msg| async move {
                    to_responder_tx.send(msg).ok();
                    Ok(())
                },
                move || async move { Ok(to_initiator_rx.recv().await.unwrap()) },
            )
            .await
        });
        let responder = tokio::spawn(async move {
            responder_handshake(
                move |msg| async move {
                    to_initiator_tx.send(msg).ok();
                    Ok(())
                },
                move || async move { Ok(to_responder_rx.recv().await.unwrap()) },
            )
            .await
        });

        let initiator_session = initiator.await.unwrap().unwrap();
        let responder_session = responder.await.unwrap().unwrap();

        assert_eq!(
            initiator_session.channel_binding(),
            responder_session.channel_binding()
        );

        let ciphertext = initiator_session.encrypt(b"hello broker").unwrap();
        let plaintext = responder_session.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello broker");
    }

    #[tokio::test]
    async fn tampered_ciphertext_is_rejected() {
        let (to_responder_tx, mut to_responder_rx) = tokio::sync::mpsc::unbounded_channel();
        let (to_initiator_tx, mut to_initiator_rx) = tokio::sync::mpsc::unbounded_channel();

        let initiator = tokio::spawn(async move {
            initiator_handshake(
                move |msg| async move {
                    to_responder_tx.send(msg).ok();
                    Ok(())
                },
                move || async move { Ok(to_initiator_rx.recv().await.unwrap()) },
            )
            .await
        });
        let responder = tokio::spawn(async move {
            responder_handshake(
                move |msg| async move {
                    to_initiator_tx.send(msg).ok();
                    Ok(())
                },
                move || async move { Ok(to_responder_rx.recv().await.unwrap()) },
            )
            .await
        });

        let initiator_session = initiator.await.unwrap().unwrap();
        let responder_session = responder.await.unwrap().unwrap();

        let mut ciphertext = initiator_session.encrypt(b"hello broker").unwrap();
        *ciphertext.last_mut().unwrap() ^= 0xFF;
        assert!(responder_session.decrypt(&ciphertext).is_err());
    }
}
