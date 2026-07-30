use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, fs, path::Path, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(String);

impl AgentId {
    pub fn from_public_key(key: &VerifyingKey) -> Self {
        let digest = Sha256::digest(key.as_bytes());
        Self(format!(
            "did:aeronet:{}",
            bs58::encode(digest).into_string()
        ))
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for AgentId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        if !value.starts_with("did:aeronet:") || value.len() < 20 {
            bail!("Agent DID không hợp lệ")
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    secret_key: String,
}

pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let stored: StoredKey = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("Không đọc được key {}", path.display()))?,
        )?;
        let bytes: [u8; 32] = B64
            .decode(stored.secret_key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("Secret key phải dài 32 byte"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            bail!("Từ chối ghi đè key đã tồn tại: {}", path.display())
        }
        let stored = StoredKey {
            secret_key: B64.encode(self.signing_key.to_bytes()),
        };
        fs::write(path, serde_json::to_vec_pretty(&stored)?)?;
        Ok(())
    }

    pub fn id(&self) -> AgentId {
        AgentId::from_public_key(&self.signing_key.verifying_key())
    }
    pub fn public_key_b64(&self) -> String {
        B64.encode(self.signing_key.verifying_key().as_bytes())
    }
    pub fn sign(&self, data: &[u8]) -> String {
        B64.encode(self.signing_key.sign(data).to_bytes())
    }
}

pub fn verify_identity(
    id: &AgentId,
    public_key_b64: &str,
    data: &[u8],
    signature_b64: &str,
) -> Result<()> {
    let key_bytes: [u8; 32] = B64
        .decode(public_key_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key phải dài 32 byte"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    if &AgentId::from_public_key(&key) != id {
        bail!("DID không khớp public key")
    }
    let signature = Signature::from_slice(&B64.decode(signature_b64)?)?;
    key.verify(data, &signature).context("Chữ ký không hợp lệ")
}
