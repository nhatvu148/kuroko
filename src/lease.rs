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
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Leases are deliberately short-lived: a desktop changes under you, and an
/// hour-old handle is far more likely to point at something else than at what
/// the caller meant.
// Raised from 60 after field use: a scope is bound to hwnd AND generation, so
// it self-invalidates the moment the window is retitled, resized or replaced -
// the TTL is a backstop, not the guard. Sixty seconds forced a re-discovery
// (400-500 ms on a heavy app) before nearly every act, which bought no safety
// the generation hash was not already providing.
pub const DEFAULT_TTL_SECS: u64 = 300;

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
        let json = B64
            .decode(p)
            .map_err(|_| anyhow!("malformed lease payload"))?;
        let sig = B64
            .decode(s)
            .map_err(|_| anyhow!("malformed lease signature"))?;

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

/// Generated fresh per process and never written to disk.
///
/// It was previously persisted so leases survived a restart. That traded a real
/// security property for a negligible convenience: the file sat under
/// `%LOCALAPPDATA%` with default ACLs, readable by any process running as this
/// user at *any* integrity level, so a Medium-integrity process could mint
/// scopes for this High-integrity server. Scopes live 60 seconds; losing them on
/// restart costs nothing worth that.
pub fn new_key() -> Result<Vec<u8>> {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).map_err(|e| anyhow!("getrandom failed: {e}"))?;
    Ok(k.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![7u8; 32]
    }

    fn scope(exp_offset: i64) -> Scope {
        Scope {
            hwnd: 0x1234,
            generation: 0xdead_beef,
            exp: (now() as i64 + exp_offset) as u64,
        }
    }

    #[test]
    fn round_trips() {
        let s = scope(60);
        let back = Scope::decode(&s.encode(&key()).unwrap(), &key()).unwrap();
        assert_eq!(back.hwnd, s.hwnd);
        assert_eq!(back.generation, s.generation);
        assert_eq!(back.exp, s.exp);
    }

    #[test]
    fn rejects_a_different_key() {
        let token = scope(60).encode(&key()).unwrap();
        let err = Scope::decode(&token, &[9u8; 32]).unwrap_err().to_string();
        assert!(err.contains("signature"), "unexpected error: {err}");
    }

    /// The payload is what authorises a window; flipping a bit in it must not
    /// survive verification, or the signature is decoration.
    #[test]
    fn rejects_a_tampered_payload() {
        let token = scope(60).encode(&key()).unwrap();
        let (payload, sig) = token.split_once('.').unwrap();
        let mut raw = B64.decode(payload).unwrap();
        let i = raw.len() / 2;
        raw[i] ^= 0x01;
        let forged = format!("{}.{}", B64.encode(&raw), sig);
        assert!(Scope::decode(&forged, &key()).is_err());
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let token = scope(60).encode(&key()).unwrap();
        let (payload, sig) = token.split_once('.').unwrap();
        let mut raw = B64.decode(sig).unwrap();
        raw[0] ^= 0x01;
        let forged = format!("{payload}.{}", B64.encode(&raw));
        assert!(Scope::decode(&forged, &key()).is_err());
    }

    #[test]
    fn rejects_an_expired_scope() {
        let token = scope(-1).encode(&key()).unwrap();
        let err = Scope::decode(&token, &key()).unwrap_err().to_string();
        assert!(err.contains("expired"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_malformed_tokens() {
        for bad in ["", "nodot", "a.b", ".", "....", "!!!.???"] {
            assert!(
                Scope::decode(bad, &key()).is_err(),
                "accepted malformed token {bad:?}"
            );
        }
    }

    /// A 128-bit tag is the deliberate size; a regression to a full 256-bit tag
    /// would silently double the per-response cost the scope design exists to avoid.
    #[test]
    fn signature_is_truncated_to_128_bits() {
        let token = scope(60).encode(&key()).unwrap();
        let sig = token.split_once('.').unwrap().1;
        assert_eq!(B64.decode(sig).unwrap().len(), 16);
    }
}
