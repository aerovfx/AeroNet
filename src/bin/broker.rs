use aeronet::{
    storage::{AcceptOutcome, DeliveryStore},
    AuthChallenge, AuthProof, Envelope,
};
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
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, Mutex},
};

#[derive(Parser)]
#[command(about = "AeroNet secure resolver/relay")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    #[arg(long, default_value = "conversation.jsonl")]
    audit_log: PathBuf,
    #[arg(long, default_value = "aeronet.db")]
    state_db: PathBuf,
}

#[derive(Clone)]
struct PeerConnection {
    session_id: String,
    sender: mpsc::UnboundedSender<Envelope>,
}

type Peers = Arc<Mutex<HashMap<String, PeerConnection>>>;

#[derive(Clone)]
struct AppState {
    peers: Peers,
    store: Arc<Mutex<DeliveryStore>>,
    audit_log: Arc<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let state = AppState {
        peers: Arc::new(Mutex::new(HashMap::new())),
        store: Arc::new(Mutex::new(DeliveryStore::open(&args.state_db)?)),
        audit_log: Arc::new(args.audit_log),
    };
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

async fn handle_socket(mut socket: WebSocket, did: String, state: AppState) {
    let challenge = uuid::Uuid::new_v4().to_string();
    let challenge_frame = AuthChallenge {
        challenge: challenge.clone(),
    };
    if socket
        .send(WsMessage::Text(
            serde_json::to_string(&challenge_frame).unwrap(),
        ))
        .await
        .is_err()
    {
        return;
    }
    let proof = match socket.recv().await {
        Some(Ok(WsMessage::Text(text))) => serde_json::from_str::<AuthProof>(&text).ok(),
        _ => None,
    };
    let Some(proof) = proof else {
        tracing::warn!(agent = %did, "missing authentication proof");
        return;
    };
    if proof.agent_id.to_string() != did || proof.verify(&challenge).is_err() {
        tracing::warn!(agent = %did, "authentication failed");
        return;
    }
    let (mut ws_tx, mut ws_rx) = socket.split();
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

    let forward = tokio::spawn(async move {
        while let Some(envelope) = rx.recv().await {
            let Ok(json) = serde_json::to_string(&envelope) else {
                continue;
            };
            if ws_tx.send(WsMessage::Text(json)).await.is_err() {
                break;
            }
        }
    });

    while let Some(Ok(WsMessage::Text(text))) = ws_rx.next().await {
        let envelope: Envelope = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(agent = %did, %error, "invalid JSON envelope");
                continue;
            }
        };
        if envelope.from.to_string() != did {
            tracing::warn!(agent = %did, "sender DID does not match connection");
            continue;
        }
        if let Err(error) = envelope.verify(chrono::Utc::now()) {
            tracing::warn!(agent = %did, %error, "rejected envelope");
            continue;
        }
        let outcome = match state.store.lock().await.accept(&envelope) {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(agent = %did, message_id = %envelope.id, %error, "rejected durable state transition");
                continue;
            }
        };
        if let Err(error) = append_audit(&state.audit_log, &envelope).await {
            tracing::error!(%error, "cannot write audit log");
        }
        if outcome == AcceptOutcome::Acknowledged {
            tracing::debug!(message_id = %envelope.id, in_reply_to = ?envelope.in_reply_to, "delivery acknowledged");
            continue;
        }
        let target = state
            .peers
            .lock()
            .await
            .get(&envelope.to.to_string())
            .map(|peer| peer.sender.clone());
        if let Some(target) = target {
            let _ = target.send(envelope);
        } else {
            tracing::info!(to = %envelope.to, message_id = %envelope.id, "recipient offline; message queued durably");
        }
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
