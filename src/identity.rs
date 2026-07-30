use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::{self, IsTerminal, Write},
    path::Path,
    str::FromStr,
};

const KEY_FILE_FORMAT: &str = "aeronet-key-v1";
const KDF_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

/// Resolves the passphrase used to encrypt/decrypt a key file: the
/// `AERONET_KEY_PASSPHRASE` environment variable if set (for scripts, CI and
/// tests), otherwise an interactive hidden prompt. Never accept a
/// passphrase as a CLI argument — it would leak via shell history and `ps`.
pub fn resolve_passphrase(label: &str, confirm: bool) -> Result<String> {
    if let Ok(value) = std::env::var("AERONET_KEY_PASSPHRASE") {
        return Ok(value);
    }
    if !io::stdin().is_terminal() {
        bail!(
            "no TTY and AERONET_KEY_PASSPHRASE is not set; cannot prompt for a passphrase for {label}"
        );
    }
    let passphrase = rpassword::prompt_password(format!("Passphrase for {label}: "))?;
    if confirm {
        io::stdout().flush().ok();
        let confirmation = rpassword::prompt_password(format!("Confirm passphrase for {label}: "))?;
        if confirmation != passphrase {
            bail!("passphrases did not match");
        }
    }
    Ok(passphrase)
}

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
            bail!("Invalid agent DID")
        }
        Ok(Self(value.to_owned()))
    }
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    format: String,
    kdf_salt: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut derived = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|error| anyhow::anyhow!("key derivation failed: {error}"))?;
    Ok(derived)
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

    pub fn load(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let path = path.as_ref();
        let stored: StoredKey = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("Cannot read key {}", path.display()))?,
        )?;
        if stored.format != KEY_FILE_FORMAT {
            bail!("Unsupported key file format: {}", stored.format);
        }
        let salt = B64.decode(&stored.kdf_salt).context("invalid key salt")?;
        let nonce_bytes: [u8; NONCE_LEN] = B64
            .decode(&stored.nonce)
            .context("invalid key nonce")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid key nonce length"))?;
        let ciphertext = B64
            .decode(&stored.ciphertext)
            .context("invalid key ciphertext")?;
        let derived_key = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let nonce = XNonce::from(nonce_bytes);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| anyhow::anyhow!("wrong passphrase or corrupted key file"))?;
        let bytes: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| anyhow::anyhow!("Secret key must be 32 bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn save(&self, path: impl AsRef<Path>, passphrase: &str) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            bail!("Refusing to overwrite existing key: {}", path.display())
        }
        let mut salt = [0u8; KDF_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let derived_key = derive_key(passphrase, &salt)?;
        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, self.signing_key.to_bytes().as_ref())
            .map_err(|_| anyhow::anyhow!("key encryption failed"))?;
        let stored = StoredKey {
            format: KEY_FILE_FORMAT.to_string(),
            kdf_salt: B64.encode(salt),
            nonce: B64.encode(nonce_bytes),
            ciphertext: B64.encode(ciphertext),
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
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    if &AgentId::from_public_key(&key) != id {
        bail!("DID does not match public key")
    }
    let signature = Signature::from_slice(&B64.decode(signature_b64)?)?;
    key.verify(data, &signature).context("Invalid signature")
}
