use aeronet::{AuthChallenge, AuthProof, Envelope};
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
}

type Peers = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Envelope>>>>;

#[derive(Clone)]
struct AppState {
    peers: Peers,
    token_usage: Arc<Mutex<HashMap<String, u32>>>,
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
        token_usage: Arc::new(Mutex::new(HashMap::new())),
        audit_log: Arc::new(args.audit_log),
    };
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ws/:did", get(ws_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "AeroNet broker sẵn sàng");
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
    state.peers.lock().await.insert(did.clone(), tx);
    tracing::info!(agent = %did, "agent connected");
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
        if let Some(cap) = &envelope.capability {
            let mut usages = state.token_usage.lock().await;
            let count = usages.entry(cap.nonce.clone()).or_default();
            if *count >= cap.max_messages {
                tracing::warn!(nonce = %cap.nonce, "capability quota exhausted");
                continue;
            }
            *count += 1;
        }
        if let Err(error) = append_audit(&state.audit_log, &envelope).await {
            tracing::error!(%error, "cannot write audit log");
        }
        let target = state
            .peers
            .lock()
            .await
            .get(&envelope.to.to_string())
            .cloned();
        if let Some(target) = target {
            let _ = target.send(envelope);
        } else {
            tracing::warn!(to = %envelope.to, "recipient offline; message retained only in audit log");
        }
    }
    state.peers.lock().await.remove(&did);
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
