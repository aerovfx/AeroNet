use aeronet::{AgentId, Capability, CapabilityAction, Identity};
use anyhow::Result;
use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf, str::FromStr};

#[derive(Parser)]
#[command(about = "Manage AeroNet identities and capabilities")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        #[arg(long)]
        out: PathBuf,
    },
    Show {
        #[arg(long)]
        key: PathBuf,
    },
    Issue {
        #[arg(long)]
        issuer_key: PathBuf,
        #[arg(long)]
        grantee: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(
            long,
            value_enum,
            value_delimiter = ',',
            default_value = "query,answer,propose,critique,acknowledge"
        )]
        actions: Vec<ActionArg>,
        #[arg(long, default_value_t = 100)]
        max_messages: u32,
        #[arg(long, default_value_t = 24)]
        ttl_hours: i64,
    },
}

#[derive(Clone, clap::ValueEnum)]
enum ActionArg {
    Query,
    Answer,
    Propose,
    Critique,
    Acknowledge,
}
impl From<ActionArg> for CapabilityAction {
    fn from(value: ActionArg) -> Self {
        match value {
            ActionArg::Query => Self::Query,
            ActionArg::Answer => Self::Answer,
            ActionArg::Propose => Self::Propose,
            ActionArg::Critique => Self::Critique,
            ActionArg::Acknowledge => Self::Acknowledge,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate { out } => {
            let identity = Identity::generate();
            identity.save(&out)?;
            println!("{}", identity.id());
        }
        Command::Show { key } => println!("{}", Identity::load(key)?.id()),
        Command::Issue {
            issuer_key,
            grantee,
            out,
            actions,
            max_messages,
            ttl_hours,
        } => {
            if out.exists() {
                anyhow::bail!("Refusing to overwrite existing token: {}", out.display())
            }
            let issuer = Identity::load(issuer_key)?;
            let token = Capability::issue(
                &issuer,
                AgentId::from_str(&grantee)?,
                actions.into_iter().map(Into::into).collect(),
                max_messages,
                Utc::now() + Duration::hours(ttl_hours),
            )?;
            fs::write(&out, serde_json::to_vec_pretty(&token)?)?;
            println!(
                "Issued token to {} for audience {}",
                token.grantee, token.audience
            );
        }
    }
    Ok(())
}
