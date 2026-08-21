//! Verification of a DLC offer/accept/sign set.
//!
//! This is a Rust reimplementation of the checks in Lygos's `dlc-verify`, arranged so the
//! whole thing runs inside the enclave with no native addon. The verification is pure:
//! given the same messages it always produces the same result, and it performs no I/O.

use bitcoin::{Address, Amount, Network, ScriptBuf};
use dlc_messages::contract_msgs::{ContractDescriptor, ContractInfo};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleInfo as MsgOracleInfo};
use dlc_messages::ser_impls::write_as_tlv;
use secp256k1_zkp::{Message, Secp256k1};
use serde::{Deserialize, Serialize};

use super::codec;
use super::txs::{self, PartyInputs, Payout};

/// BIP340 tag for the oracle's announcement signature.
const ANNOUNCEMENT_TAG: &[u8] = b"DLC/oracle/announcement/v0";
/// BIP340 tag for the message an oracle attests to.
const ATTESTATION_TAG: &[u8] = b"DLC/oracle/attestation/v0";

/// A single outcome and how it splits the collateral.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    /// The outcome string the oracle will attest to.
    pub label: String,
    /// Satoshis paid to the offerer under this outcome.
    pub offerer_sats: u64,
    /// Satoshis paid to the accepter under this outcome.
    pub accepter_sats: u64,
}

/// A funding input, as an outpoint and its value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FundingInputInfo {
    /// `txid:vout` of the spent output.
    pub outpoint: String,
    /// Value of the spent output, if the previous transaction could be decoded.
    pub sats: Option<u64>,
    /// Contract id, when this input is itself funded by another DLC.
    pub dlc_contract_id: Option<String>,
}

/// Everything the verifier learned about a contract.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DlcVerification {
    /// Whether every message parsed.
    pub structurally_valid: bool,
    /// Network implied by the offer's chain hash, when recognised.
    pub chain_hash_network: Option<String>,
    /// Contract descriptor kind, e.g. `Enumerated`.
    pub contract_type: Option<String>,
    /// Total collateral locked by the contract.
    pub total_collateral: Option<u64>,
    /// Collateral contributed by the offerer.
    pub offer_collateral: Option<u64>,
    /// Collateral contributed by the accepter.
    pub accept_collateral: Option<u64>,
    /// True when the accepter contributes no collateral and no inputs.
    pub single_funded: bool,
    /// Every outcome and its payouts.
    pub outcomes: Vec<Outcome>,
    /// The oracle key found in the offer.
    pub extracted_oracle_pubkey: Option<String>,
    /// The oracle key the caller said to expect.
    pub expected_oracle_pubkey: Option<String>,
    /// Whether the two agree. `None` when the caller expressed no expectation.
    pub oracle_pubkey_matches_expected: Option<bool>,
    /// The oracle's event id.
    pub oracle_event_id: Option<String>,
    /// Whether the oracle's announcement signature verified.
    pub oracle_sig_valid: bool,
    /// Why the announcement signature failed, when it did.
    pub oracle_sig_error: Option<String>,
    /// Locktime on the CETs.
    pub cet_locktime: Option<u32>,
    /// Locktime on the refund transaction.
    pub refund_locktime: Option<u32>,
    /// Fee rate the contract was built at.
    pub fee_rate_per_vb: Option<u64>,
    /// Offerer's key in the 2-of-2 fund script.
    pub offerer_funding_pubkey: Option<String>,
    /// Accepter's key in the 2-of-2 fund script.
    pub accepter_funding_pubkey: Option<String>,
    /// The 2-of-2 address holding the collateral.
    pub funding_address: Option<String>,
    /// The 2-of-2 redeem script.
    pub funding_script: Option<String>,
    /// Offerer's funding inputs.
    pub offer_inputs: Vec<FundingInputInfo>,
    /// Accepter's funding inputs.
    pub accept_inputs: Vec<FundingInputInfo>,
    /// Txid of the reconstructed fund transaction.
    pub fund_txid: Option<String>,
    /// Index of the 2-of-2 output in the fund transaction.
    pub fund_vout: Option<u32>,
    /// Value of the fund output: collateral plus the prepaid CET fee.
    pub fund_output_value: Option<u64>,
    /// Fee paid by the fund transaction.
    pub fund_fee: Option<u64>,
    /// CET fee, prepaid into the fund output.
    pub cet_fee: Option<u64>,
    /// Contract id derived from the fund outpoint and the temporary contract id.
    pub contract_id: Option<String>,
    /// Number of CETs reconstructed.
    pub cet_count: Option<usize>,
    /// Whether every adaptor signature verified.
    pub adaptor_sigs_valid: Option<bool>,
    /// How many adaptor signatures verified.
    pub adaptor_valid_count: usize,
    /// How many adaptor signatures were supplied.
    pub adaptor_total_count: usize,
    /// Why adaptor verification could not be completed, or which CETs failed.
    pub adaptor_error: Option<String>,
    /// Whether a sign message was supplied.
    pub sign_available: bool,
    /// Contract id carried by the sign message.
    pub sign_contract_id: Option<String>,
    /// Whether that contract id matches the computed one.
    pub sign_contract_id_matches: Option<bool>,
    /// Fatal error that stopped verification.
    pub error: Option<String>,
}

/// What the caller wants verified, beyond the messages themselves.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyOptions {
    /// Oracle key the contract is required to reference.
    pub expected_oracle_pubkey: Option<String>,
    /// Network used to render addresses. Defaults to the offer's chain hash.
    pub network: Option<String>,
}

/// BIP340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{Hash, HashEngine, sha256};
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(tag_hash.as_ref());
    engine.input(tag_hash.as_ref());
    engine.input(msg);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Verify the oracle's announcement signature.
///
/// `rust-dlc`'s own `OracleAnnouncement::validate` cannot be used here: it hashes the
/// oracle event with a plain SHA-256 over the non-TLV encoding, whereas the DLC
/// specification — and therefore every announcement Lygos produces — uses a BIP340 tagged
/// hash over the TLV encoding. Using the upstream check reports valid announcements as
/// invalid.
fn verify_announcement<C: secp256k1_zkp::Verification>(
    secp: &Secp256k1<C>,
    announcement: &OracleAnnouncement,
) -> Result<(), String> {
    let mut event_tlv = Vec::new();
    write_as_tlv(&announcement.oracle_event, &mut event_tlv)
        .map_err(|e| format!("failed to serialize oracle event: {e}"))?;
    let digest = tagged_hash(ANNOUNCEMENT_TAG, &event_tlv);
    secp.verify_schnorr(
        &announcement.announcement_signature,
        &Message::from_digest(digest),
        &announcement.oracle_public_key,
    )
    .map_err(|e| format!("schnorr verification failed: {e}"))
}

/// Normalise an x-only public key to lowercase hex without a `0x` prefix.
fn normalize_pubkey(pubkey: &str) -> Result<String, String> {
    let cleaned: String = pubkey
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected a 32-byte x-only public key as 64 hex characters".to_string());
    }
    Ok(cleaned)
}

/// Map a chain hash to a network name. The hash is the genesis block hash in internal
/// byte order.
fn network_from_chain_hash(chain_hash: &[u8; 32]) -> Option<(&'static str, Network)> {
    for (name, network) in [
        ("mainnet", Network::Bitcoin),
        ("testnet", Network::Testnet),
        ("signet", Network::Signet),
        ("regtest", Network::Regtest),
    ] {
        if network.chain_hash().to_bytes() == *chain_hash {
            return Some((name, network));
        }
    }
    None
}

/// Derive the contract id from the fund outpoint and the offer's temporary contract id.
fn compute_contract_id(
    temporary_contract_id: &[u8; 32],
    fund_txid: &bitcoin::Txid,
    fund_vout: u32,
) -> [u8; 32] {
    // The txid is mixed in display (reversed) byte order, matching the specification's
    // use of the RPC-style txid.
    use bitcoin::hashes::Hash as _;
    let mut txid_bytes = fund_txid.to_raw_hash().to_byte_array();
    txid_bytes.reverse();
    let vout_bytes = fund_vout.to_be_bytes();
    txid_bytes[30] ^= vout_bytes[2];
    txid_bytes[31] ^= vout_bytes[3];

    let mut contract_id = [0u8; 32];
    for i in 0..32 {
        contract_id[i] = txid_bytes[i] ^ temporary_contract_id[i];
    }
    contract_id
}

/// Pull the contract descriptor and oracle info out of either contract-info shape.
fn contract_parts(contract_info: &ContractInfo) -> (&ContractDescriptor, &MsgOracleInfo, Amount) {
    match contract_info {
        ContractInfo::SingleContractInfo(single) => (
            &single.contract_info.contract_descriptor,
            &single.contract_info.oracle_info,
            single.total_collateral,
        ),
        ContractInfo::DisjointContractInfo(disjoint) => (
            &disjoint.contract_infos[0].contract_descriptor,
            &disjoint.contract_infos[0].oracle_info,
            disjoint.total_collateral,
        ),
    }
}

/// The announcement a contract's oracle info points at.
fn announcement_of(oracle_info: &MsgOracleInfo) -> Option<&OracleAnnouncement> {
    match oracle_info {
        MsgOracleInfo::Single(single) => Some(&single.oracle_announcement),
        MsgOracleInfo::Multi(multi) => multi.oracle_announcements.first(),
    }
}

/// Describe a party's funding inputs without failing the whole verification if one of
/// them cannot be decoded.
fn describe_inputs(
    inputs: &[dlc_messages::FundingInput],
    dlc_inputs: &[Option<codec::DlcInputInfo>],
) -> Vec<FundingInputInfo> {
    use bitcoin::consensus::Decodable;
    inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let decoded =
                bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(&input.prev_tx))
                    .ok();
            let outpoint = decoded.as_ref().map_or_else(
                || format!("<undecodable>:{}", input.prev_tx_vout),
                |tx| format!("{}:{}", tx.compute_txid(), input.prev_tx_vout),
            );
            let sats = decoded
                .as_ref()
                .and_then(|tx| tx.output.get(input.prev_tx_vout as usize))
                .map(|out| out.value.to_sat());
            FundingInputInfo {
                outpoint,
                sats,
                dlc_contract_id: dlc_inputs
                    .get(index)
                    .and_then(|d| d.as_ref())
                    .map(|d| qos_hex::encode(&d.contract_id)),
            }
        })
        .collect()
}

/// Verify a DLC offer/accept pair, and a sign message when one is supplied.
///
/// Never returns `Err`: a failure to parse or verify is reported in the returned value so
/// callers always receive a complete picture. `DlcVerification::error` is set when
/// verification could not proceed at all.
#[must_use]
pub fn verify_dlc(
    offer_hex: &str,
    accept_hex: &str,
    sign_hex: Option<&str>,
    options: &VerifyOptions,
) -> DlcVerification {
    let mut result = DlcVerification::default();

    let expected_oracle_pubkey = match options.expected_oracle_pubkey.as_deref() {
        Some(pubkey) => match normalize_pubkey(pubkey) {
            Ok(normalized) => Some(normalized),
            Err(e) => {
                result.error = Some(format!("invalid expectedOraclePubkey: {e}"));
                return result;
            }
        },
        None => None,
    };
    result.expected_oracle_pubkey = expected_oracle_pubkey.clone();

    let decoded = match codec::read_offer(offer_hex) {
        Ok(decoded) => decoded,
        Err(e) => {
            result.error = Some(format!("failed to decode offer: {e:?}"));
            return result;
        }
    };
    let accept = match codec::read_accept(accept_hex) {
        Ok(accept) => accept,
        Err(e) => {
            result.error = Some(format!("failed to decode accept: {e:?}"));
            return result;
        }
    };
    let offer = &decoded.offer;
    result.structurally_valid = true;

    let secp = Secp256k1::new();

    let (chain_name, network) = network_from_chain_hash(&offer.chain_hash)
        .map_or((None, Network::Bitcoin), |(n, net)| (Some(n), net));
    result.chain_hash_network = chain_name.map(ToString::to_string);
    let network = match options.network.as_deref() {
        Some("mainnet") => Network::Bitcoin,
        Some("testnet") => Network::Testnet,
        Some("signet") => Network::Signet,
        Some("regtest") => Network::Regtest,
        _ => network,
    };

    let (descriptor, oracle_info, total_collateral) = contract_parts(&offer.contract_info);
    result.total_collateral = Some(total_collateral.to_sat());
    result.offer_collateral = Some(offer.offer_collateral.to_sat());
    result.accept_collateral = Some(accept.accept_collateral.to_sat());
    result.cet_locktime = Some(offer.cet_locktime);
    result.refund_locktime = Some(offer.refund_locktime);
    result.fee_rate_per_vb = Some(offer.fee_rate_per_vb);
    result.offerer_funding_pubkey = Some(offer.funding_pubkey.to_string());
    result.accepter_funding_pubkey = Some(accept.funding_pubkey.to_string());
    result.offer_inputs = describe_inputs(&offer.funding_inputs, &decoded.dlc_inputs);
    result.accept_inputs = describe_inputs(&accept.funding_inputs, &[]);

    let single_funded =
        accept.accept_collateral == Amount::ZERO && accept.funding_inputs.is_empty();
    result.single_funded = single_funded;

    let payouts: Vec<Payout> = match descriptor {
        ContractDescriptor::EnumeratedContractDescriptor(enumerated) => {
            result.contract_type = Some("Enumerated".to_string());
            result.outcomes = enumerated
                .payouts
                .iter()
                .map(|payout| Outcome {
                    label: payout.outcome.clone(),
                    offerer_sats: payout.offer_payout.to_sat(),
                    accepter_sats: total_collateral
                        .to_sat()
                        .saturating_sub(payout.offer_payout.to_sat()),
                })
                .collect();
            enumerated
                .payouts
                .iter()
                .map(|payout| Payout {
                    offer: payout.offer_payout,
                    accept: total_collateral - payout.offer_payout,
                })
                .collect()
        }
        ContractDescriptor::NumericOutcomeContractDescriptor(numeric) => {
            result.contract_type = Some(format!("Numeric ({} digits)", numeric.num_digits));
            Vec::new()
        }
    };

    // Oracle identity and announcement signature.
    if let Some(announcement) = announcement_of(oracle_info) {
        let extracted = qos_hex::encode(&announcement.oracle_public_key.serialize());
        result.oracle_pubkey_matches_expected = expected_oracle_pubkey
            .as_ref()
            .map(|expected| *expected == extracted);
        result.extracted_oracle_pubkey = Some(extracted);
        result.oracle_event_id = Some(announcement.oracle_event.event_id.clone());
        match verify_announcement(&secp, announcement) {
            Ok(()) => result.oracle_sig_valid = true,
            Err(e) => result.oracle_sig_error = Some(e),
        }
    } else {
        result.oracle_sig_error = Some("offer contains no oracle announcement".to_string());
    }

    let funding_script =
        dlc::make_funding_redeemscript(&offer.funding_pubkey, &accept.funding_pubkey);
    result.funding_script = Some(funding_script.to_hex_string());
    result.funding_address = Address::from_script(&funding_script.to_p2wsh(), network)
        .ok()
        .map(|address| address.to_string());

    // Reconstruct the transactions and check the accepter's adaptor signatures against
    // them. Only the single-funded shape is supported; see `txs` for why.
    if !single_funded {
        result.adaptor_error = Some(
            "adaptor signature verification supports single-funded contracts only \
             (the accepter contributed collateral or inputs)"
                .to_string(),
        );
    } else if payouts.is_empty() {
        result.adaptor_error =
            Some("adaptor signature verification supports enumerated contracts only".to_string());
    } else {
        let offer_party = party_inputs(
            offer.funding_pubkey,
            offer.change_spk.clone(),
            offer.change_serial_id,
            offer.payout_spk.clone(),
            offer.payout_serial_id,
            offer.offer_collateral,
        );
        let accept_party = party_inputs(
            accept.funding_pubkey,
            accept.change_spk.clone(),
            accept.change_serial_id,
            accept.payout_spk.clone(),
            accept.payout_serial_id,
            accept.accept_collateral,
        );

        match txs::build_single_funded(
            &offer_party,
            &accept_party,
            &offer.funding_inputs,
            &payouts,
            &txs::ContractTerms {
                total_collateral,
                fee_rate_per_vb: offer.fee_rate_per_vb,
                fund_output_serial_id: offer.fund_output_serial_id,
                cet_locktime: offer.cet_locktime,
            },
        ) {
            Ok(built) => {
                let fund_txid = built.fund.compute_txid();
                result.fund_txid = Some(fund_txid.to_string());
                result.fund_vout = Some(built.fund_vout);
                result.fund_output_value = Some(built.fund_output_value.to_sat());
                result.fund_fee = Some(built.fund_fee.to_sat());
                result.cet_fee = Some(built.cet_fee.to_sat());
                result.cet_count = Some(built.cets.len());
                result.contract_id = Some(qos_hex::encode(&compute_contract_id(
                    &offer.temporary_contract_id,
                    &fund_txid,
                    built.fund_vout,
                )));

                verify_adaptor_signatures(&secp, &mut result, &built, &accept, oracle_info);
            }
            Err(e) => result.adaptor_error = Some(format!("could not rebuild transactions: {e}")),
        }
    }

    if let Some(sign_hex) = sign_hex.filter(|s| !s.trim().is_empty()) {
        match codec::read_sign(sign_hex) {
            Ok(sign) => {
                let sign_contract_id = qos_hex::encode(&sign.contract_id);
                result.sign_available = true;
                result.sign_contract_id_matches = result
                    .contract_id
                    .as_ref()
                    .map(|computed| *computed == sign_contract_id);
                result.sign_contract_id = Some(sign_contract_id);
            }
            Err(e) => {
                result.error = Some(format!("failed to decode sign message: {e:?}"));
            }
        }
    }

    result
}

/// Build the party description the transaction builder needs.
fn party_inputs(
    funding_pubkey: secp256k1_zkp::PublicKey,
    change_spk: ScriptBuf,
    change_serial_id: u64,
    payout_spk: ScriptBuf,
    payout_serial_id: u64,
    collateral: Amount,
) -> PartyInputs {
    PartyInputs {
        funding_pubkey,
        change_spk,
        change_serial_id,
        payout_spk,
        payout_serial_id,
        collateral,
    }
}

/// Check every adaptor signature in the accept message against the rebuilt CETs.
fn verify_adaptor_signatures(
    secp: &Secp256k1<secp256k1_zkp::All>,
    result: &mut DlcVerification,
    built: &txs::DlcTransactions,
    accept: &dlc_messages::AcceptDlc,
    oracle_info: &MsgOracleInfo,
) {
    let oracle_infos: Vec<dlc::OracleInfo> = match oracle_info {
        MsgOracleInfo::Single(single) => vec![dlc::OracleInfo {
            public_key: single.oracle_announcement.oracle_public_key,
            nonces: single
                .oracle_announcement
                .oracle_event
                .oracle_nonces
                .clone(),
        }],
        MsgOracleInfo::Multi(multi) => multi
            .oracle_announcements
            .iter()
            .map(|announcement| dlc::OracleInfo {
                public_key: announcement.oracle_public_key,
                nonces: announcement.oracle_event.oracle_nonces.clone(),
            })
            .collect(),
    };

    let signatures = &accept.cet_adaptor_signatures.ecdsa_adaptor_signatures;
    result.adaptor_total_count = signatures.len();

    if signatures.len() != built.cets.len() {
        result.adaptor_sigs_valid = Some(false);
        result.adaptor_error = Some(format!(
            "contract has {} CETs but the accept message carries {} adaptor signatures",
            built.cets.len(),
            signatures.len()
        ));
        return;
    }

    let mut failed = Vec::new();
    for (index, (cet, signature)) in built.cets.iter().zip(signatures.iter()).enumerate() {
        let Some(outcome) = result.outcomes.get(index) else {
            failed.push(format!("CET {index} (no matching outcome)"));
            continue;
        };
        let digest = tagged_hash(ATTESTATION_TAG, outcome.label.as_bytes());
        let messages = vec![vec![Message::from_digest(digest)]];
        match dlc::verify_cet_adaptor_sig_from_oracle_info(
            secp,
            &signature.signature,
            cet,
            &oracle_infos,
            &accept.funding_pubkey,
            &built.funding_script,
            built.fund_output_value,
            &messages,
        ) {
            Ok(()) => result.adaptor_valid_count += 1,
            Err(e) => failed.push(format!("{} ({e})", outcome.label)),
        }
    }

    result.adaptor_sigs_valid = Some(failed.is_empty());
    if !failed.is_empty() {
        result.adaptor_error = Some(format!("invalid adaptor signatures: {}", failed.join(", ")));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fixtures;

    /// Every contract Lygos supplied must verify end to end. The adaptor-signature counts
    /// match what their `dlc-verify` tool reports for the same messages.
    #[test]
    fn verifies_every_lygos_fixture() {
        for (name, offer, accept, sign, expected_sigs) in [
            (
                "sample",
                fixtures::SAMPLE_OFFER,
                fixtures::SAMPLE_ACCEPT,
                Some(fixtures::SAMPLE_SIGN),
                5,
            ),
            (
                "testnet",
                fixtures::TESTNET_OFFER,
                fixtures::TESTNET_ACCEPT,
                Some(fixtures::TESTNET_SIGN),
                5,
            ),
            (
                "matured",
                fixtures::MATURED_OFFER,
                fixtures::MATURED_ACCEPT,
                None,
                4,
            ),
        ] {
            let result = verify_dlc(offer, accept, sign, &VerifyOptions::default());

            assert!(result.error.is_none(), "{name}: {:?}", result.error);
            assert!(result.structurally_valid, "{name} should parse");
            assert!(result.single_funded, "{name} should be single-funded");
            assert!(
                result.oracle_sig_valid,
                "{name}: {:?}",
                result.oracle_sig_error
            );
            assert_eq!(
                result.adaptor_sigs_valid,
                Some(true),
                "{name}: {:?}",
                result.adaptor_error
            );
            assert_eq!(result.adaptor_valid_count, expected_sigs, "{name}");
            assert_eq!(result.adaptor_total_count, expected_sigs, "{name}");
            assert_eq!(
                result.contract_type.as_deref(),
                Some("Enumerated"),
                "{name}"
            );
        }
    }

    /// The fund transaction must match the one DDK builds, because the adaptor signatures
    /// commit to it. These values were taken from DDK's output for the same messages.
    #[test]
    fn rebuilds_the_fund_transaction_that_ddk_produces() {
        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions::default(),
        );

        assert_eq!(
            result.fund_txid.as_deref(),
            Some("15659a28391a81337f7512427e0a07b3f32d16514f81f58303adec3955604274")
        );
        assert_eq!(result.fund_vout, Some(0));
        assert_eq!(result.fund_output_value, Some(11_470));
        assert_eq!(result.cet_fee, Some(1_470));
        assert_eq!(result.fund_fee, Some(2_490));
        assert_eq!(result.total_collateral, Some(10_000));

        // The published dlc-verify report for the `7932e4c2` loan quotes this fund txid.
        let matured = verify_dlc(
            fixtures::MATURED_OFFER,
            fixtures::MATURED_ACCEPT,
            None,
            &VerifyOptions::default(),
        );
        assert_eq!(
            matured.fund_txid.as_deref(),
            Some("fdc7dfe8e53f8fb66c40c74bc717ea1d4ed9b8c546bbdbdf2e844ecb894620dc")
        );
    }

    #[test]
    fn sign_message_contract_id_matches_the_computed_one() {
        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            Some(fixtures::SAMPLE_SIGN),
            &VerifyOptions::default(),
        );

        assert!(result.sign_available);
        assert_eq!(result.sign_contract_id_matches, Some(true));
        assert_eq!(
            result.contract_id.as_deref(),
            Some("817e5025e0218d798d868f846f0a958ac5716bdfe341096a7aa8714fb6521d6d")
        );
    }

    #[test]
    fn reports_the_expected_oracle_key_matching_and_not_matching() {
        let matching = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions {
                expected_oracle_pubkey: Some(
                    "8731249d979def2d5d76c61795969e953807d37ff36ef8dbab60d57ae08bb004".to_string(),
                ),
                network: None,
            },
        );
        assert_eq!(matching.oracle_pubkey_matches_expected, Some(true));

        let mismatched = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions {
                expected_oracle_pubkey: Some("ff".repeat(32)),
                network: None,
            },
        );
        assert_eq!(mismatched.oracle_pubkey_matches_expected, Some(false));
        // A wrong expectation must not cast doubt on the contract's own validity.
        assert!(mismatched.oracle_sig_valid);
        assert_eq!(mismatched.adaptor_sigs_valid, Some(true));
    }

    #[test]
    fn no_expectation_means_no_verdict_on_the_oracle_key() {
        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions::default(),
        );
        assert_eq!(result.oracle_pubkey_matches_expected, None);
        assert!(result.extracted_oracle_pubkey.is_some());
    }

    #[test]
    fn surfaces_the_dlc_funded_input_contract_id() {
        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions::default(),
        );

        assert_eq!(result.offer_inputs.len(), 2);
        assert_eq!(
            result.offer_inputs[0].dlc_contract_id.as_deref(),
            Some("1bfb5a41e4597462a2b9250dd9c86fe60b0b28baa815caeb4448f50cb37bc0b8")
        );
        assert!(result.offer_inputs[0].sats.is_some());
        assert!(result.offer_inputs[1].dlc_contract_id.is_none());
    }

    #[test]
    fn tampering_with_an_adaptor_signature_is_detected() {
        // Flip a byte in the middle of the accept message's adaptor signatures. The
        // contract still parses, but the signature must no longer verify.
        let mut bytes = qos_hex::decode(fixtures::SAMPLE_ACCEPT).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 0x01;
        let tampered = qos_hex::encode(&bytes);

        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            &tampered,
            None,
            &VerifyOptions::default(),
        );

        let tampering_detected = result.error.is_some() || result.adaptor_sigs_valid != Some(true);
        assert!(
            tampering_detected,
            "a corrupted accept message must not verify: {result:?}"
        );
    }

    #[test]
    fn malformed_input_is_reported_rather_than_panicking() {
        let result = verify_dlc(
            "not-hex",
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions::default(),
        );
        assert!(result.error.is_some());
        assert!(!result.structurally_valid);

        let swapped = verify_dlc(
            fixtures::SAMPLE_ACCEPT,
            fixtures::SAMPLE_OFFER,
            None,
            &VerifyOptions::default(),
        );
        assert!(swapped.error.is_some());
    }

    #[test]
    fn rejects_a_malformed_expected_oracle_key() {
        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions {
                expected_oracle_pubkey: Some("abc".to_string()),
                network: None,
            },
        );
        assert!(result.error.is_some());
    }

    #[test]
    fn normalizes_oracle_key_formatting() {
        let key = "8731249D979DEF2D5D76C61795969E953807D37FF36EF8DBAB60D57AE08BB004";
        let result = verify_dlc(
            fixtures::SAMPLE_OFFER,
            fixtures::SAMPLE_ACCEPT,
            None,
            &VerifyOptions {
                expected_oracle_pubkey: Some(format!("0x{key}")),
                network: None,
            },
        );
        assert_eq!(result.oracle_pubkey_matches_expected, Some(true));
    }

    #[test]
    fn identical_input_produces_identical_output() {
        let run = || {
            serde_json::to_string(&verify_dlc(
                fixtures::SAMPLE_OFFER,
                fixtures::SAMPLE_ACCEPT,
                Some(fixtures::SAMPLE_SIGN),
                &VerifyOptions::default(),
            ))
            .unwrap()
        };
        assert_eq!(run(), run());
    }
}
