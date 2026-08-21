//! On-chain inclusion checks for a DLC's collateral transaction.
//!
//! The enclave calls a Blockstream Esplora instance directly over egress, so the result
//! is fetched by the same attested code that verified the contract. Nothing about the
//! chain state is taken on trust from the caller.

use serde::{Deserialize, Serialize};

use crate::client::HttpClient;

/// Confirmations required before collateral counts as locked. One is enough to
/// demonstrate the check; a production gate would raise this.
pub const MIN_CONFIRMATIONS: u32 = 1;

/// Which chain to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    /// Bitcoin mainnet.
    Mainnet,
    /// Testnet3, the default for the demo.
    #[default]
    Testnet,
}

impl BitcoinNetwork {
    /// Base URL of the Esplora API for this network.
    #[must_use]
    pub fn esplora_base(self) -> &'static str {
        match self {
            Self::Mainnet => "https://blockstream.info/api",
            Self::Testnet => "https://blockstream.info/testnet/api",
        }
    }

    /// Name used in responses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

/// Why an inclusion check could not be completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "detail")]
pub enum InclusionError {
    /// The explorer has no record of this transaction.
    NotFound,
    /// The explorer could not be reached, or returned something unusable.
    ExplorerUnavailable(String),
    /// The supplied txid was not 32 bytes of hex.
    MalformedTxid(String),
}

impl std::fmt::Display for InclusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "transaction not found on chain"),
            Self::ExplorerUnavailable(detail) => write!(f, "explorer unavailable: {detail}"),
            Self::MalformedTxid(detail) => write!(f, "malformed txid: {detail}"),
        }
    }
}

/// What the chain says about a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inclusion {
    /// The transaction queried.
    pub txid: String,
    /// Network queried.
    pub network: String,
    /// Whether the explorer knows the transaction at all.
    pub included: bool,
    /// Whether it is in a block rather than the mempool.
    pub confirmed: bool,
    /// Height of the containing block.
    pub block_height: Option<u32>,
    /// Confirmations, counting the containing block.
    pub confirmations: Option<u32>,
    /// Whether an output pays the contract's 2-of-2 script for the expected amount.
    /// `None` when there was nothing to compare against.
    pub funding_output_match: Option<bool>,
    /// Total value paid to the contract's funding script.
    pub funding_output_value: Option<u64>,
}

/// Esplora's transaction representation, narrowed to the fields used here.
#[derive(Debug, Deserialize)]
struct EsploraTx {
    txid: String,
    vout: Vec<EsploraVout>,
}

#[derive(Debug, Deserialize)]
struct EsploraVout {
    scriptpubkey: String,
    value: u64,
}

#[derive(Debug, Deserialize)]
struct EsploraStatus {
    confirmed: bool,
    block_height: Option<u32>,
}

/// Validate a txid without allocating a second copy on the happy path.
fn normalize_txid(txid: &str) -> Result<String, InclusionError> {
    let cleaned = txid.trim().to_lowercase();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(InclusionError::MalformedTxid(
            "expected 64 hex characters".to_string(),
        ));
    }
    Ok(cleaned)
}

/// Look up `txid` and report whether it is on chain.
///
/// When `expected_funding_spk` and `expected_value` are supplied, the transaction's
/// outputs are checked for one paying that script the expected amount, which is what ties
/// an arbitrary transaction to *this* contract.
///
/// # Errors
///
/// Returns [`InclusionError`] if the txid is malformed, the transaction is unknown, or
/// the explorer cannot be reached.
pub async fn check_inclusion(
    http: &HttpClient,
    network: BitcoinNetwork,
    txid: &str,
    expected_funding_spk: Option<&str>,
    expected_value: Option<u64>,
) -> Result<Inclusion, InclusionError> {
    let txid = normalize_txid(txid)?;
    let base = network.esplora_base();

    let tx: EsploraTx = fetch_json(http, &format!("{base}/tx/{txid}")).await?;
    let status: EsploraStatus = fetch_json(http, &format!("{base}/tx/{txid}/status")).await?;

    if tx.txid.to_lowercase() != txid {
        return Err(InclusionError::ExplorerUnavailable(format!(
            "explorer returned txid {} for a request for {txid}",
            tx.txid
        )));
    }

    // The tip is only needed to turn a block height into a confirmation count, so a
    // failure here degrades the result rather than failing the check.
    let tip_height = fetch_text(http, &format!("{base}/blocks/tip/height"))
        .await
        .ok()
        .and_then(|body| body.trim().parse::<u32>().ok());

    let confirmations = match (status.confirmed, status.block_height, tip_height) {
        (true, Some(height), Some(tip)) => Some(tip.saturating_sub(height).saturating_add(1)),
        // Confirmed, but the tip is unknown: it has at least one confirmation.
        (true, _, _) => Some(1),
        (false, _, _) => Some(0),
    };

    let funding_output_value = expected_funding_spk.map(|spk| {
        let spk = spk.to_lowercase();
        tx.vout
            .iter()
            .filter(|out| out.scriptpubkey.to_lowercase() == spk)
            .map(|out| out.value)
            .sum()
    });
    let funding_output_match = match (funding_output_value, expected_value) {
        (Some(found), Some(expected)) => Some(found == expected),
        (Some(found), None) => Some(found > 0),
        (None, _) => None,
    };

    Ok(Inclusion {
        txid,
        network: network.as_str().to_string(),
        included: true,
        confirmed: status.confirmed,
        block_height: status.block_height,
        confirmations,
        funding_output_match,
        funding_output_value,
    })
}

/// GET a URL and decode JSON, mapping a 404 to [`InclusionError::NotFound`].
async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &HttpClient,
    url: &str,
) -> Result<T, InclusionError> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|e| InclusionError::ExplorerUnavailable(e.to_string()))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(InclusionError::NotFound);
    }
    if !response.status().is_success() {
        return Err(InclusionError::ExplorerUnavailable(format!(
            "explorer returned HTTP {}",
            response.status()
        )));
    }
    response
        .json()
        .await
        .map_err(|e| InclusionError::ExplorerUnavailable(format!("unreadable response: {e}")))
}

/// GET a URL and return the body as text.
async fn fetch_text(http: &HttpClient, url: &str) -> Result<String, InclusionError> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|e| InclusionError::ExplorerUnavailable(e.to_string()))?;
    if !response.status().is_success() {
        return Err(InclusionError::ExplorerUnavailable(format!(
            "explorer returned HTTP {}",
            response.status()
        )));
    }
    response
        .text()
        .await
        .map_err(|e| InclusionError::ExplorerUnavailable(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_well_formed_txid_in_any_case() {
        let upper = "DCF70D60370559665CC45B66841A2AAB6D755B1DF38A823BBBC8D38DD05DB03D";
        assert_eq!(
            normalize_txid(upper).unwrap(),
            upper.to_lowercase(),
            "txids should normalize to lowercase"
        );
        assert_eq!(
            normalize_txid("  dcf70d60370559665cc45b66841a2aab6d755b1df38a823bbbc8d38dd05db03d  ")
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn rejects_txids_that_are_not_32_bytes_of_hex() {
        assert!(normalize_txid("").is_err());
        assert!(normalize_txid("abc").is_err());
        assert!(normalize_txid(&"z".repeat(64)).is_err());
        assert!(normalize_txid(&"a".repeat(63)).is_err());
        assert!(normalize_txid(&"a".repeat(65)).is_err());
    }

    #[test]
    fn networks_point_at_the_right_explorer() {
        assert_eq!(
            BitcoinNetwork::Testnet.esplora_base(),
            "https://blockstream.info/testnet/api"
        );
        assert_eq!(
            BitcoinNetwork::Mainnet.esplora_base(),
            "https://blockstream.info/api"
        );
        assert_eq!(BitcoinNetwork::default(), BitcoinNetwork::Testnet);
    }
}
