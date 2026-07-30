use aeronet::{
    AgentId, AuthChallenge, AuthProof, Capability, Envelope, Identity, MessageKind, Payload,
    TaskContract,
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
#[command(about = "Agent tham gia mạng AeroNet")]
struct Args {
    #[arg(long)]
    key: PathBuf,
    #[arg(long)]
    peer: String,
    /// Token do peer cấp cho agent này.
    #[arg(long)]
    capability: PathBuf,
    #[arg(
        long,
        default_value = "Bạn là một AI agent hữu ích, chính xác và súc tích."
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
    let identity = Identity::load(&args.key)?;
    let peer = AgentId::from_str(&args.peer)?;
    let capability: Capability = serde_json::from_slice(&fs::read(&args.capability)?)?;
    let initial_action = if args.kickoff.is_some() {
        aeronet::CapabilityAction::Query
    } else {
        aeronet::CapabilityAction::Answer
    };
    capability
        .verify(&identity.id(), &peer, &initial_action, chrono::Utc::now())
        .context("Capability không dùng được cho vai trò đã chọn")?;
    capability
        .verify(
            &identity.id(),
            &peer,
            &aeronet::CapabilityAction::Acknowledge,
            chrono::Utc::now(),
        )
        .context("Capability phải cho phép acknowledge để giao nhận bền vững")?;

    let api_key = match args.provider {
        Provider::Anthropic => {
            Some(std::env::var("ANTHROPIC_API_KEY").context("Thiếu ANTHROPIC_API_KEY")?)
        }
        Provider::Echo => None,
    };
    let client = reqwest::Client::new();
    let url = format!("ws://{}/ws/{}", args.broker, identity.id());
    let (mut stream, _) = connect_async(&url)
        .await
        .context("Không kết nối được broker")?;
    let challenge = match stream.next().await {
        Some(Ok(WsMessage::Text(text))) => serde_json::from_str::<AuthChallenge>(&text)?,
        _ => anyhow::bail!("Broker không gửi authentication challenge"),
    };
    let proof = AuthProof::create(&identity, challenge.challenge);
    stream
        .send(WsMessage::Text(serde_json::to_string(&proof)?))
        .await?;
    let (mut tx, mut rx) = stream.split();
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
        send(&mut tx, &envelope).await?;
        history.push(HistoryTurn {
            role: "assistant",
            content: goal.clone(),
        });
        turns += 1;
        println!("[{}] gửi task {}", identity.id(), envelope.id);
    }

    while let Some(frame) = rx.next().await {
        let text = match frame? {
            WsMessage::Text(value) => value,
            WsMessage::Close(_) => break,
            _ => continue,
        };
        let incoming: Envelope = serde_json::from_str(&text)?;
        incoming
            .verify(chrono::Utc::now())
            .context("Broker chuyển message không hợp lệ")?;
        if incoming.from != peer || incoming.to != identity.id() {
            tracing::warn!(message_id = %incoming.id, "Bỏ qua message ngoài phiên peer đã cấu hình");
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
        send(&mut tx, &delivery_ack).await?;
        if matches!(incoming.kind, MessageKind::End) {
            break;
        }
        let incoming_text = payload_text(&incoming.payload);
        println!(
            "[{}] nhận từ {}: {}",
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
                    content: "Đã đạt giới hạn lượt.".into(),
                },
                Some(incoming.id),
                None,
                Duration::minutes(1),
            )?;
            send(&mut tx, &end).await?;
            break;
        }
        let answer = match args.provider {
            Provider::Echo => format!("Đã nhận task. Phản hồi thử nghiệm từ {}.", identity.id()),
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
        send(&mut tx, &reply).await?;
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

async fn send<S>(tx: &mut S, envelope: &Envelope) -> Result<()>
where
    S: futures_util::Sink<WsMessage> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    tx.send(WsMessage::Text(serde_json::to_string(envelope)?))
        .await?;
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
        .context("Gọi Anthropic API thất bại")?;
    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .context("Response API không phải JSON")?;
    if !status.is_success() {
        anyhow::bail!("Anthropic API lỗi {status}: {body}")
    }
    body["content"]
        .as_array()
        .and_then(|blocks| blocks.iter().find(|b| b["type"] == "text"))
        .and_then(|b| b["text"].as_str())
        .map(str::to_owned)
        .context("Response không có text")
}
