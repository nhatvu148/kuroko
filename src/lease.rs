//! Self-describing, signed element handles.
//!
//! A lease is not a pointer and not a session key - it is a *recipe for
//! re-finding an element*, signed so it cannot be forged, and stamped so a
//! stale one is detected rather than acted on. That keeps the server stateless:
//! there is no lease table to look up, expire, or garbage-collect, and a server
//! restart does not invalidate work already in flight.
//!
//! One scope token is issued per discovery, not per element: every entity in a
//! response shares the same window, generation and expiry, so signing those 175
//! times was pure duplication. The per-element part - the child-index path - is
//! carried unsigned on the entity. That is safe because the signature is what
//! authorises *which window and when*; a path is only a coordinate inside a
//! window the caller was already granted, and a wrong one either fails to
//! resolve or fails the bounds guard.
//!
//! Wire format: `base64url(json).base64url(hmac_sha256(json)[..16])`

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Leases are deliberately short-lived: a desktop changes under you, and an
/// hour-old handle is far more likely to point at something else than at what
/// the caller meant.
pub const DEFAULT_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Owning top-level window.
    #[serde(rename = "h")]
    pub hwnd: isize,
    /// Cheap fingerprint of the owning window at discovery time. If this no
    /// longer matches, the window was replaced or substantially redrawn.
    #[serde(rename = "g")]
    pub generation: u64,
    #[serde(rename = "e")]
    pub exp: u64,
}

impl Scope {
    pub fn expired(&self) -> bool {
        now() > self.exp
    }

    pub fn encode(&self, key: &[u8]) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| anyhow!("bad key: {e}"))?;
        mac.update(&json);
        Ok(format!(
            "{}.{}",
            B64.encode(&json),
            B64.encode(&mac.finalize().into_bytes()[..16])
        ))
    }

    /// Verifies the signature *before* deserialising, so malformed or forged
    /// payloads never reach the parser.
    pub fn decode(token: &str, key: &[u8]) -> Result<Scope> {
        let (p, s) = token
            .split_once('.')
            .ok_or_else(|| anyhow!("malformed lease"))?;
        let json = B64.decode(p).map_err(|_| anyhow!("malformed lease payload"))?;
        let sig = B64.decode(s).map_err(|_| anyhow!("malformed lease signature"))?;

        let mut mac = HmacSha256::new_from_slice(key).map_err(|e| anyhow!("bad key: {e}"))?;
        mac.update(&json);
        mac.verify_truncated_left(&sig)
            .map_err(|_| anyhow!("lease signature invalid"))?;

        let lease: Scope = serde_json::from_slice(&json)?;
        if lease.expired() {
            bail!("lease expired {}s ago", now().saturating_sub(lease.exp));
        }
        Ok(lease)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn key_path() -> PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("kuroko").join("lease.key")
}

/// Persisted so leases survive a restart - the generation stamp and expiry,
/// not process lifetime, are what decide whether a lease is still good.
pub fn load_or_create_key() -> Result<Vec<u8>> {
    let path = key_path();
    if let Ok(k) = std::fs::read(&path) {
        if k.len() >= 32 {
            return Ok(k);
        }
    }
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).map_err(|e| anyhow!("getrandom failed: {e}"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, k)?;
    Ok(k.to_vec())
}
