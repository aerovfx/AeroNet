use aeronet::{
    storage::{AcceptOutcome, DeliveryStore},
    transport, AgentId, AuthChallenge, AuthProof, Envelope, Identity, NoiseSession,
};
use anyhow::Context;
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, Mutex},
};
use tokio_tungstenite::tungstenite::Message as TWsMessage;

#[derive(Parser)]
#[command(about = "AeroNet secure resolver/relay")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long, default_value = "conversation.jsonl")]
    audit_log: PathBuf,
    #[arg(long, default_value = "aeronet.db")]
    state_db: PathBuf,
    /// Path to this broker's own Ed25519 identity key, generated the same
    /// way as an agent's (`aeronet-key generate`). Required when
    /// `--peer-broker` is used to federate with other brokers.
    #[arg(long)]
    broker_key: Option<PathBuf>,
    /// A trusted peer broker to federate with, formatted as
    /// `ws://host:port@did:aeronet:...`. Repeatable. Both brokers must list
    /// each other for the mesh link to be mutually authenticated.
    #[arg(long = "peer-broker", value_parser = parse_peer_broker)]
    peer_brokers: Vec<PeerBrokerSpec>,
}

#[derive(Clone, Debug)]
struct PeerBrokerSpec {
    url: String,
    did: AgentId,
}

fn parse_peer_broker(raw: &str) -> Result<PeerBrokerSpec, String> {
    let (url, did) = raw
        .rsplit_once('@')
        .ok_or_else(|| "expected ws://host:port@did:aeronet:...".to_string())?;
    let did = AgentId::from_str(did).map_err(|error| error.to_string())?;
    Ok(PeerBrokerSpec {
        url: url.to_string(),
        did,
    })
}

#[derive(Clone)]
struct PeerConnection {
    session_id: String,
    sender: mpsc::UnboundedSender<Envelope>,
}

type Peers = Arc<Mutex<HashMap<String, PeerConnection>>>;
/// Live outbound links to federation peer brokers, keyed by the peer's DID.
type FederationOutbound = Arc<Mutex<HashMap<AgentId, mpsc::UnboundedSender<Envelope>>>>;

#[derive(Clone)]
struct AppState {
    peers: Peers,
    store: Arc<Mutex<DeliveryStore>>,
    audit_log: Arc<PathBuf>,
    /// DIDs of brokers allowed to relay envelopes on behalf of arbitrary
    /// senders over their authenticated connection (see `process_envelope`).
    federation_peers: Arc<HashSet<AgentId>>,
    federation_outbound: FederationOutbound,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    if !args.peer_brokers.is_empty() && args.broker_key.is_none() {
        anyhow::bail!("--broker-key is required when --peer-broker is configured");
    }
    let broker_identity = args
        .broker_key
        .as_ref()
        .map(Identity::load)
        .transpose()?
        .map(Arc::new);
    let federation_peers = args
        .peer_brokers
        .iter()
        .map(|peer| peer.did.clone())
        .collect();
    let state = AppState {
        peers: Arc::new(Mutex::new(HashMap::new())),
        store: Arc::new(Mutex::new(DeliveryStore::open(&args.state_db)?)),
        audit_log: Arc::new(args.audit_log),
        federation_peers: Arc::new(federation_peers),
        federation_outbound: Arc::new(Mutex::new(HashMap::new())),
    };
    for peer in args.peer_brokers {
        let identity = broker_identity
            .clone()
            .expect("checked above: broker_key is required when peer_brokers is non-empty");
        tokio::spawn(federation_link(peer, identity, state.clone()));
    }
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ws/:did", get(ws_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "AeroNet broker ready");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(did): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, did, state))
}

async fn handle_socket(socket: WebSocket, did: String, state: AppState) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Wrap the raw WebSocket connection in a Noise_NN session before any
    // application data is exchanged. This gives the link forward-secret
    // encryption and integrity even though Noise_NN itself is anonymous.
    let noise = match transport::responder_handshake(
        |message| async {
            ws_tx
                .send(WsMessage::Binary(message))
                .await
                .map_err(|error| anyhow::anyhow!("cannot send Noise handshake frame: {error}"))
        },
        || async {
            match ws_rx.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => Ok(bytes),
                _ => anyhow::bail!("expected a Noise handshake frame"),
            }
        },
    )
    .await
    {
        Ok(session) => Arc::new(session),
        Err(error) => {
            tracing::warn!(agent = %did, %error, "Noise handshake failed");
            return;
        }
    };
    let channel_binding = noise.channel_binding();

    let challenge = uuid::Uuid::new_v4().to_string();
    let challenge_frame = AuthChallenge {
        challenge: challenge.clone(),
    };
    let Ok(challenge_bytes) = serde_json::to_vec(&challenge_frame) else {
        return;
    };
    let Ok(challenge_ciphertext) = noise.encrypt(&challenge_bytes) else {
        return;
    };
    if ws_tx
        .send(WsMessage::Binary(challenge_ciphertext))
        .await
        .is_err()
    {
        return;
    }
    let proof = match ws_rx.next().await {
        Some(Ok(WsMessage::Binary(bytes))) => noise
            .decrypt(&bytes)
            .ok()
            .and_then(|plaintext| serde_json::from_slice::<AuthProof>(&plaintext).ok()),
        _ => None,
    };
    let Some(proof) = proof else {
        tracing::warn!(agent = %did, "missing authentication proof");
        return;
    };
    if proof.agent_id.to_string() != did || proof.verify(&challenge, &channel_binding).is_err() {
        tracing::warn!(agent = %did, "authentication failed");
        return;
    }
    let is_federation_peer = AgentId::from_str(&did)
        .map(|id| state.federation_peers.contains(&id))
        .unwrap_or(false);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let session_id = uuid::Uuid::new_v4().to_string();
    state.peers.lock().await.insert(
        did.clone(),
        PeerConnection {
            session_id: session_id.clone(),
            sender: tx.clone(),
        },
    );
    tracing::info!(agent = %did, "agent connected");

    match state.store.lock().await.pending_for(&did) {
        Ok(pending) => {
            tracing::info!(agent = %did, count = pending.len(), "restoring pending messages");
            for envelope in pending {
                let _ = tx.send(envelope);
            }
        }
        Err(error) => tracing::error!(agent = %did, %error, "cannot restore pending messages"),
    }

    let noise_for_forward = noise.clone();
    let forward = tokio::spawn(async move {
        while let Some(envelope) = rx.recv().await {
            let Ok(json) = serde_json::to_vec(&envelope) else {
                continue;
            };
            let Ok(ciphertext) = noise_for_forward.encrypt(&json) else {
                continue;
            };
            if ws_tx.send(WsMessage::Binary(ciphertext)).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(WsMessage::Binary(bytes))) = ws_rx.next().await {
        let Ok(plaintext) = noise.decrypt(&bytes) else {
            tracing::warn!(agent = %did, "dropping frame with invalid Noise ciphertext");
            continue;
        };
        let envelope: Envelope = match serde_json::from_slice(&plaintext) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(agent = %did, %error, "invalid JSON envelope");
                continue;
            }
        };
        if envelope.from.to_string() != did && !is_federation_peer {
            tracing::warn!(agent = %did, "sender DID does not match connection");
            continue;
        }
        process_envelope(&state, envelope).await;
    }
    let mut peers = state.peers.lock().await;
    if peers
        .get(&did)
        .is_some_and(|peer| peer.session_id == session_id)
    {
        peers.remove(&did);
    }
    drop(peers);
    forward.abort();
    tracing::info!(agent = %did, "agent disconnected");
}

/// Verifies, durably records, and either locally delivers or forwards an
/// envelope. Shared by directly-connected agents and by envelopes relayed in
/// from a federation peer broker, since both need identical replay
/// protection, capability accounting, audit logging and delivery logic.
async fn process_envelope(state: &AppState, envelope: Envelope) {
    if let Err(error) = envelope.verify(chrono::Utc::now()) {
        tracing::warn!(message_id = %envelope.id, %error, "rejected envelope");
        return;
    }
    let outcome = match state.store.lock().await.accept(&envelope) {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(message_id = %envelope.id, %error, "rejected durable state transition");
            return;
        }
    };
    if let Err(error) = append_audit(&state.audit_log, &envelope).await {
        tracing::error!(%error, "cannot write audit log");
    }
    if outcome == AcceptOutcome::Acknowledged {
        tracing::debug!(message_id = %envelope.id, in_reply_to = ?envelope.in_reply_to, "delivery acknowledged");
        return;
    }
    let target = state
        .peers
        .lock()
        .await
        .get(&envelope.to.to_string())
        .map(|peer| peer.sender.clone());
    if let Some(target) = target {
        let _ = target.send(envelope);
        return;
    }
    let federation_targets: Vec<_> = state
        .federation_outbound
        .lock()
        .await
        .values()
        .cloned()
        .collect();
    if federation_targets.is_empty() {
        tracing::info!(to = %envelope.to, message_id = %envelope.id, "recipient offline; message queued durably");
        return;
    }
    tracing::info!(
        to = %envelope.to,
        message_id = %envelope.id,
        peers = federation_targets.len(),
        "recipient not local; forwarded to federation peers and queued durably"
    );
    for target in federation_targets {
        let _ = target.send(envelope.clone());
    }
}

/// Dials a configured federation peer broker exactly like an agent would
/// (same Noise handshake + signed DID auth proof), keeps the link open, and
/// reconnects with a fixed backoff if it drops. This is the only broker
/// endpoint any peer needs to reach: there is no separate federation port or
/// protocol, so trust is symmetric and mutual once both sides list each
/// other, but the DID of whoever answers a configured URL is only proven for
/// the side that dialed — same address-based trust an agent places in
/// `--broker <addr>` today.
async fn federation_link(peer: PeerBrokerSpec, identity: Arc<Identity>, state: AppState) {
    loop {
        match run_federation_link(&peer, &identity, &state).await {
            Ok(()) => tracing::info!(peer = %peer.did, "federation link closed"),
            Err(error) => tracing::warn!(peer = %peer.did, %error, "federation link failed"),
        }
        state.federation_outbound.lock().await.remove(&peer.did);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run_federation_link(
    peer: &PeerBrokerSpec,
    identity: &Identity,
    state: &AppState,
) -> anyhow::Result<()> {
    let url = format!("{}/ws/{}", peer.url, identity.id());
    let (stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .context("cannot connect to peer broker")?;
    let (mut ws_tx, mut ws_rx) = stream.split();

    let noise = transport::initiator_handshake(
        |message| async {
            ws_tx
                .send(TWsMessage::Binary(message))
                .await
                .map_err(|error| anyhow::anyhow!("cannot send Noise handshake frame: {error}"))
        },
        || async {
            match ws_rx.next().await {
                Some(Ok(TWsMessage::Binary(bytes))) => Ok(bytes),
                _ => anyhow::bail!("expected a Noise handshake frame"),
            }
        },
    )
    .await
    .context("Noise handshake with peer broker failed")?;
    let channel_binding = noise.channel_binding();

    let challenge = match ws_rx.next().await {
        Some(Ok(TWsMessage::Binary(bytes))) => {
            let plaintext = noise
                .decrypt(&bytes)
                .context("cannot decrypt authentication challenge")?;
            serde_json::from_slice::<AuthChallenge>(&plaintext)?
        }
        _ => anyhow::bail!("peer broker did not send an authentication challenge"),
    };
    let proof = AuthProof::create(identity, challenge.challenge, channel_binding);
    let proof_ciphertext = noise.encrypt(&serde_json::to_vec(&proof)?)?;
    ws_tx.send(TWsMessage::Binary(proof_ciphertext)).await?;

    let noise: Arc<NoiseSession> = Arc::new(noise);
    let (tx, mut rx) = mpsc::unbounded_channel::<Envelope>();
    state
        .federation_outbound
        .lock()
        .await
        .insert(peer.did.clone(), tx);
    tracing::info!(peer = %peer.did, "federation link established");

    let noise_for_forward = noise.clone();
    let forward = tokio::spawn(async move {
        while let Some(envelope) = rx.recv().await {
            let Ok(json) = serde_json::to_vec(&envelope) else {
                continue;
            };
            let Ok(ciphertext) = noise_for_forward.encrypt(&json) else {
                continue;
            };
            if ws_tx.send(TWsMessage::Binary(ciphertext)).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(TWsMessage::Binary(bytes))) = ws_rx.next().await {
        let Ok(plaintext) = noise.decrypt(&bytes) else {
            tracing::warn!(peer = %peer.did, "dropping frame with invalid Noise ciphertext");
            continue;
        };
        match serde_json::from_slice::<Envelope>(&plaintext) {
            Ok(envelope) => process_envelope(state, envelope).await,
            Err(error) => {
                tracing::warn!(peer = %peer.did, %error, "invalid JSON envelope from peer broker")
            }
        }
    }
    forward.abort();
    Ok(())
}

async fn append_audit(path: &PathBuf, envelope: &Envelope) -> anyhow::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(serde_json::to_string(envelope)?.as_bytes())
        .await?;
    file.write_all(b"\n").await?;
    Ok(())
}
