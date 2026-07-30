use aeronet::{
    resolve_passphrase, transport, AgentId, AuthChallenge, AuthProof, Capability, Envelope,
    Identity, MessageKind, NoiseSession, Payload, TaskContract,
};
use anyhow::{Context, Result};
use chrono::Duration;
use clap::{Parser, ValueEnum};
use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::{fs, path::PathBuf, str::FromStr};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

#[derive(Clone, Debug, ValueEnum)]
enum Provider {
    Anthropic,
    Echo,
}

#[derive(Parser, Debug)]
#[command(about = "Agent participating in the AeroNet network")]
struct Args {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    peer: String,
    /// Capability token issued by the peer to this agent.
    #[arg(long)]
    capability: PathBuf,
    #[arg(
        long,
        default_value = "You are a helpful, precise and concise AI agent."
    )]
    system: String,
    #[arg(long)]
    kickoff: Option<String>,
    #[arg(long, value_delimiter = ',')]
    constraint: Vec<String>,
    #[arg(long)]
    budget_units: Option<u64>,
    #[arg(long, default_value_t = 6)]
    max_turns: u32,
    #[arg(long, value_enum, default_value = "anthropic")]
    provider: Provider,
    #[arg(long, default_value = "claude-sonnet-5")]
    model: String,
    #[arg(long, default_value = "127.0.0.1:8787")]
    broker: String,
}

#[derive(Clone)]
struct HistoryTurn {
    role: &'static str,
    content: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let passphrase = resolve_passphrase(&format!("key {}", args.key.display()), false)?;
    let identity = Identity::load(&args.key, &passphrase)?;
    let peer = AgentId::from_str(&args.peer)?;
    let capability: Capability = serde_json::from_slice(&fs::read(&args.capability)?)?;
    let initial_action = if args.kickoff.is_some() {
        aeronet::CapabilityAction::Query
    } else {
        aeronet::CapabilityAction::Answer
    };
    capability
        .verify(&identity.id(), &peer, &initial_action, chrono::Utc::now())
        .context("Capability cannot be used for the selected role")?;
    capability
        .verify(
            &identity.id(),
            &peer,
            &aeronet::CapabilityAction::Acknowledge,
            chrono::Utc::now(),
        )
        .context("Capability must allow acknowledge for durable delivery")?;

    let api_key = match args.provider {
        Provider::Anthropic => {
            Some(std::env::var("ANTHROPIC_API_KEY").context("Missing ANTHROPIC_API_KEY")?)
        }
        Provider::Echo => None,
    };
    let client = reqwest::Client::new();
    let url = format!("ws://{}/ws/{}", args.broker, identity.id());
    let (stream, _) = connect_async(&url)
        .await
        .context("Cannot connect to broker")?;
    let (mut tx, mut rx) = stream.split();

    // Wrap the connection in a Noise_NN session before any application data
    // is exchanged. See src/transport.rs for why this is enough combined
    // with signing the resulting channel binding in the AuthProof below.
    let noise = transport::initiator_handshake(
        |message| async {
            tx.send(WsMessage::Binary(message))
                .await
                .map_err(|error| anyhow::anyhow!("cannot send Noise handshake frame: {error}"))
        },
        || async {
            match rx.next().await {
                Some(Ok(WsMessage::Binary(bytes))) => Ok(bytes),
                _ => anyhow::bail!("expected a Noise handshake frame"),
            }
        },
    )
    .await
    .context("Noise handshake with broker failed")?;
    let channel_binding = noise.channel_binding();

    let challenge = match rx.next().await {
        Some(Ok(WsMessage::Binary(bytes))) => {
            let plaintext = noise
                .decrypt(&bytes)
                .context("cannot decrypt authentication challenge")?;
            serde_json::from_slice::<AuthChallenge>(&plaintext)?
        }
        _ => anyhow::bail!("Broker did not send an authentication challenge"),
    };
    let proof = AuthProof::create(&identity, challenge.challenge, channel_binding);
    let proof_ciphertext = noise.encrypt(&serde_json::to_vec(&proof)?)?;
    tx.send(WsMessage::Binary(proof_ciphertext)).await?;
    let mut history = Vec::new();
    let mut turns = 0u32;

    if let Some(goal) = &args.kickoff {
        let payload = Payload::Task {
            contract: TaskContract {
                goal: goal.clone(),
                constraints: args.constraint.clone(),
                budget_units: args.budget_units,
                deadline: None,
                expected_output_schema: Some("aeronet.text.v1".into()),
            },
        };
        let envelope = Envelope::new(
            &identity,
            peer.clone(),
            MessageKind::Query,
            payload,
            None,
            Some(capability.clone()),
            Duration::minutes(5),
        )?;
        send(&mut tx, &noise, &envelope).await?;
        history.push(HistoryTurn {
            role: "assistant",
            content: goal.clone(),
        });
        turns += 1;
        println!("[{}] sent task {}", identity.id(), envelope.id);
    }

    while let Some(frame) = rx.next().await {
        let bytes = match frame? {
            WsMessage::Binary(value) => value,
            WsMessage::Close(_) => break,
            _ => continue,
        };
        let plaintext = noise
            .decrypt(&bytes)
            .context("received a frame with invalid Noise ciphertext")?;
        let incoming: Envelope = serde_json::from_slice(&plaintext)?;
        incoming
            .verify(chrono::Utc::now())
            .context("Broker relayed an invalid message")?;
        if incoming.from != peer || incoming.to != identity.id() {
            tracing::warn!(message_id = %incoming.id, "ignoring message outside the configured peer session");
            continue;
        }
        let delivery_ack = Envelope::new(
            &identity,
            peer.clone(),
            MessageKind::Ack,
            Payload::Text {
                content: "delivered".into(),
            },
            Some(incoming.id.clone()),
            Some(capability.clone()),
            Duration::minutes(1),
        )?;
        send(&mut tx, &noise, &delivery_ack).await?;
        if matches!(incoming.kind, MessageKind::End) {
            break;
        }
        let incoming_text = payload_text(&incoming.payload);
        println!(
            "[{}] received from {}: {}",
            identity.id(),
            incoming.from,
            incoming_text
        );
        history.push(HistoryTurn {
            role: "user",
            content: incoming_text,
        });

        if turns >= args.max_turns {
            let end = Envelope::new(
                &identity,
                peer.clone(),
                MessageKind::End,
                Payload::Text {
                    content: "Turn limit reached.".into(),
                },
                Some(incoming.id),
                None,
                Duration::minutes(1),
            )?;
            send(&mut tx, &noise, &end).await?;
            break;
        }
        let answer = match args.provider {
            Provider::Echo => format!("Task received. Test reply from {}.", identity.id()),
            Provider::Anthropic => {
                call_anthropic(
                    &client,
                    api_key.as_deref().unwrap(),
                    &args.model,
                    &args.system,
                    &history,
                )
                .await?
            }
        };
        history.push(HistoryTurn {
            role: "assistant",
            content: answer.clone(),
        });
        let reply = Envelope::new(
            &identity,
            peer.clone(),
            MessageKind::Answer,
            Payload::Text { content: answer },
            Some(incoming.id),
            Some(capability.clone()),
            Duration::minutes(5),
        )?;
        send(&mut tx, &noise, &reply).await?;
        turns += 1;
    }
    Ok(())
}

fn payload_text(payload: &Payload) -> String {
    match payload {
        Payload::Text { content } => content.clone(),
        Payload::Task { contract } => serde_json::to_string(contract).unwrap_or_default(),
        Payload::Knowledge { data, .. } => data.to_string(),
    }
}

async fn send<S>(tx: &mut S, noise: &NoiseSession, envelope: &Envelope) -> Result<()>
where
    S: futures_util::Sink<WsMessage> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let ciphertext = noise.encrypt(&serde_json::to_vec(envelope)?)?;
    tx.send(WsMessage::Binary(ciphertext)).await?;
    Ok(())
}

async fn call_anthropic(
    client: &reqwest::Client,
    api_key: &str,
    model: &str,
    system: &str,
    history: &[HistoryTurn],
) -> Result<String> {
    let messages: Vec<_> = history
        .iter()
        .map(|turn| json!({"role": turn.role, "content": turn.content}))
        .collect();
    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .json(&json!({"model": model, "max_tokens": 1024, "system": system, "messages": messages}))
        .send()
        .await
        .context("Anthropic API call failed")?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.context("API response is not JSON")?;
    if !status.is_success() {
        anyhow::bail!("Anthropic API error {status}: {body}")
    }
    body["content"]
        .as_array()
        .and_then(|blocks| blocks.iter().find(|b| b["type"] == "text"))
        .and_then(|b| b["text"].as_str())
        .map(str::to_owned)
        .context("Response has no text")
}
