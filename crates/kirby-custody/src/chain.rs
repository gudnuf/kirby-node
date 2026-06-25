//! Mutinynet esplora client + faucet (C-3). Reuses the C-1 base
//! https://mutinynet.com/api. A real Rust HTTP client (ureq, blocking) now that
//! broadcast and fetch actually need it (deferred from C-1, where a curl
//! reachability check sufficed). JSON responses parse via serde_json.

use serde::Deserialize;

/// Mutinynet esplora REST base (same chain as the C-1 tip-height check).
pub const MUTINYNET_ESPLORA: &str = "https://mutinynet.com/api";
/// Mutinynet faucet on-chain endpoint (GitHub-auth gated; needs a bearer JWT, see faucet_fund).
pub const MUTINYNET_FAUCET: &str = "https://faucet.mutinynet.com/api/onchain";
/// Default external location of the Mutinynet faucet JWT (a GitHub-auth bearer
/// token). Kept OUT of the repo; overridable via the FAUCET_JWT env var.
pub const FAUCET_JWT_PATH: &str = "/srv/forge/scratch/mutinynet-e2e/logs/faucet-jwt.txt";

/// An esplora UTXO at an address.
#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: TxStatus,
}

/// An esplora confirmation status (UTXO or tx).
#[derive(Debug, Clone, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

/// A thin esplora REST client.
pub struct Esplora {
    base: String,
}

impl Esplora {
    /// Client against the Mutinynet public esplora.
    pub fn mutinynet() -> Self {
        Self {
            base: MUTINYNET_ESPLORA.to_string(),
        }
    }

    /// Current chain tip height (GET /blocks/tip/height).
    pub fn tip_height(&self) -> Result<u64, Box<dyn std::error::Error>> {
        let body = ureq::get(&format!("{}/blocks/tip/height", self.base))
            .call()?
            .into_string()?;
        Ok(body.trim().parse()?)
    }

    /// All UTXOs at `address` (GET /address/{addr}/utxo).
    pub fn utxos(&self, address: &str) -> Result<Vec<Utxo>, Box<dyn std::error::Error>> {
        let body = ureq::get(&format!("{}/address/{}/utxo", self.base, address))
            .call()?
            .into_string()?;
        Ok(serde_json::from_str(&body)?)
    }

    /// Only the CONFIRMED UTXOs at `address` (spendable now).
    pub fn confirmed_utxos(&self, address: &str) -> Result<Vec<Utxo>, Box<dyn std::error::Error>> {
        Ok(self
            .utxos(address)?
            .into_iter()
            .filter(|u| u.status.confirmed)
            .collect())
    }

    /// Broadcast a raw tx hex (POST /tx). Returns the txid on accept, or an error
    /// carrying the node's rejection reason (e.g. a bad witness or fee).
    pub fn broadcast(&self, tx_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
        match ureq::post(&format!("{}/tx", self.base)).send_string(tx_hex) {
            Ok(r) => Ok(r.into_string()?.trim().to_string()),
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                Err(format!("broadcast rejected (HTTP {code}): {body}").into())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Confirmation status of a tx (GET /tx/{txid}/status).
    pub fn tx_status(&self, txid: &str) -> Result<TxStatus, Box<dyn std::error::Error>> {
        let body = ureq::get(&format!("{}/tx/{}/status", self.base, txid))
            .call()?
            .into_string()?;
        Ok(serde_json::from_str(&body)?)
    }
}

/// Read the faucet JWT from $FAUCET_JWT, else from FAUCET_JWT_PATH. Returned for
/// immediate use only; callers MUST never log it.
fn load_faucet_jwt() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(v) = std::env::var("FAUCET_JWT") {
        let v = v.trim().to_string();
        if !v.is_empty() {
            return Ok(v);
        }
    }
    let raw = std::fs::read_to_string(FAUCET_JWT_PATH).map_err(|e| {
        format!("no FAUCET_JWT env var and cannot read the faucet JWT at {FAUCET_JWT_PATH}: {e}")
    })?;
    let jwt = raw.trim().to_string();
    if jwt.is_empty() {
        return Err(format!("faucet JWT at {FAUCET_JWT_PATH} is empty").into());
    }
    Ok(jwt)
}

/// Extract the txid from the faucet JSON response without surfacing the full body.
fn faucet_txid(resp: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(resp).ok()?;
    v.get("txid")?.as_str().map(|s| s.to_string())
}

/// Fund `address` with `sats` via the Mutinynet faucet, authenticating with the
/// faucet JWT (the faucet is GitHub-auth gated: an anonymous POST returns 401).
/// Returns the funding txid. The bearer token is NEVER logged, and neither the raw
/// response nor an error body is surfaced verbatim (so no auth detail can leak).
pub fn faucet_fund(address: &str, sats: u64) -> Result<String, Box<dyn std::error::Error>> {
    let jwt = load_faucet_jwt()?;
    let body = format!("{{\"address\":\"{address}\",\"sats\":{sats}}}");
    match ureq::post(MUTINYNET_FAUCET)
        .set("Authorization", &format!("Bearer {jwt}"))
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(r) => {
            let resp = r.into_string()?;
            match faucet_txid(&resp) {
                Some(txid) => Ok(txid),
                None => Err("faucet accepted the request but returned no txid".into()),
            }
        }
        // Do NOT include the response body (it could carry auth-related detail).
        Err(ureq::Error::Status(code, _r)) => Err(format!("faucet refused (HTTP {code})").into()),
        Err(e) => Err(e.into()),
    }
}
