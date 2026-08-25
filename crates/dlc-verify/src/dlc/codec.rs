//! Wire-format decoding for DLC messages produced by `node-dlc`.
//!
//! Lygos's tooling serializes messages with [`node-dlc`], which appends an optional
//! `dlc_input` field to every funding input (`0x00` absent / `0x01` present, followed by
//! two funding pubkeys and a contract id). `rust-dlc` 0.8's `FundingInput` has no such
//! field, so its derived `Readable` impl cannot read these messages.
//!
//! This matters more than it looks: because `read_vec` writes no per-element framing,
//! feeding a node-dlc offer to `rust-dlc`'s own parser does not reliably fail. On a
//! single-input offer it *succeeds* and silently yields garbage for every field after
//! the funding inputs (observed: `fee_rate_per_vb` of 5263947935078877696 instead of 3).
//! Everything downstream — fee math, fund transaction, CETs, adaptor signatures — is then
//! computed from nonsense. So the offer must go through [`read_offer`] rather than
//! `OfferDlc::read`, and the tests in this module lock that behavior down.
//!
//! `AcceptDlc` and `SignDlc` contain no funding inputs in the Lygos fixtures (their
//! contracts are single-funded, so the accepter contributes none) and decode with the
//! upstream implementation.
//!
//! [`node-dlc`]: https://github.com/AtomicFinance/node-dlc

use bitcoin::{Amount, ScriptBuf};
use dlc_messages::contract_msgs::ContractInfo;
use dlc_messages::{AcceptDlc, FundingInput, OfferDlc, SignDlc};
use lightning::ln::msgs::DecodeError;
use lightning::util::ser::{BigSize, Readable};
use secp256k1_zkp::PublicKey;
use std::io::Cursor;

/// A funding input that is itself the output of another DLC, as encoded by node-dlc.
///
/// Only the contract id is retained; the funding pubkeys are read to advance the cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlcInputInfo {
    /// Contract id of the DLC whose fund output is being spent.
    pub contract_id: [u8; 32],
}

/// An offer plus the node-dlc-specific `dlc_input` data that `OfferDlc` cannot hold.
#[derive(Debug, Clone)]
pub struct DecodedOffer {
    /// The offer, with fields laid out as `rust-dlc` expects.
    pub offer: OfferDlc,
    /// Per-funding-input `dlc_input`, positionally aligned with `offer.funding_inputs`.
    pub dlc_inputs: Vec<Option<DlcInputInfo>>,
}

/// Strip the 2-byte message type prefix, checking it against `expected`.
fn strip_type(bytes: &[u8], expected: u16) -> Result<&[u8], DecodeError> {
    let (prefix, rest) = bytes.split_at_checked(2).ok_or(DecodeError::ShortRead)?;
    let found = u16::from_be_bytes([prefix[0], prefix[1]]);
    if found != expected {
        return Err(DecodeError::InvalidValue);
    }
    Ok(rest)
}

/// Read one funding input in node-dlc's layout: the `rust-dlc` fields followed by an
/// optional `dlc_input`.
fn read_funding_input<R: lightning::io::Read>(
    reader: &mut R,
) -> Result<(FundingInput, Option<DlcInputInfo>), DecodeError> {
    let input_serial_id: u64 = Readable::read(reader)?;
    let prev_tx_len: BigSize = Readable::read(reader)?;
    let len = usize::try_from(prev_tx_len.0).map_err(|_| DecodeError::InvalidValue)?;
    let mut prev_tx = vec![0u8; len];
    reader
        .read_exact(&mut prev_tx)
        .map_err(|_| DecodeError::ShortRead)?;
    let prev_tx_vout: u32 = Readable::read(reader)?;
    let sequence: u32 = Readable::read(reader)?;
    let max_witness_len: u16 = Readable::read(reader)?;
    let redeem_script: ScriptBuf = Readable::read(reader)?;

    let mut flag = [0u8; 1];
    reader
        .read_exact(&mut flag)
        .map_err(|_| DecodeError::ShortRead)?;
    let dlc_input = match flag[0] {
        0 => None,
        1 => {
            let _local_fund_pubkey: PublicKey = Readable::read(reader)?;
            let _remote_fund_pubkey: PublicKey = Readable::read(reader)?;
            let contract_id: [u8; 32] = Readable::read(reader)?;
            Some(DlcInputInfo { contract_id })
        }
        _ => return Err(DecodeError::InvalidValue),
    };

    Ok((
        FundingInput {
            input_serial_id,
            prev_tx,
            prev_tx_vout,
            sequence,
            max_witness_len,
            redeem_script,
        },
        dlc_input,
    ))
}

/// Decode a hex-encoded node-dlc `DlcOffer`.
///
/// # Errors
///
/// Returns an error if the hex is malformed, the type prefix is not `0xa71a`, or the
/// body does not match node-dlc's offer layout.
pub fn read_offer(hex_str: &str) -> Result<DecodedOffer, DecodeError> {
    let bytes = qos_hex::decode(hex_str.trim()).map_err(|_| DecodeError::InvalidValue)?;
    let body = strip_type(&bytes, dlc_messages::OFFER_TYPE)?;
    let reader = &mut Cursor::new(body);

    let protocol_version: u32 = Readable::read(reader)?;
    let contract_flags: u8 = Readable::read(reader)?;
    let chain_hash: [u8; 32] = Readable::read(reader)?;
    let temporary_contract_id: [u8; 32] = Readable::read(reader)?;
    let contract_info: ContractInfo = Readable::read(reader)?;
    let funding_pubkey: PublicKey = Readable::read(reader)?;
    let payout_spk: ScriptBuf = Readable::read(reader)?;
    let payout_serial_id: u64 = Readable::read(reader)?;
    let offer_collateral: u64 = Readable::read(reader)?;

    let count: BigSize = Readable::read(reader)?;
    let count = usize::try_from(count.0).map_err(|_| DecodeError::InvalidValue)?;
    let mut funding_inputs = Vec::with_capacity(count);
    let mut dlc_inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let (input, dlc_input) = read_funding_input(reader)?;
        funding_inputs.push(input);
        dlc_inputs.push(dlc_input);
    }

    let change_spk: ScriptBuf = Readable::read(reader)?;
    let change_serial_id: u64 = Readable::read(reader)?;
    let fund_output_serial_id: u64 = Readable::read(reader)?;
    let fee_rate_per_vb: u64 = Readable::read(reader)?;
    let cet_locktime: u32 = Readable::read(reader)?;
    let refund_locktime: u32 = Readable::read(reader)?;

    Ok(DecodedOffer {
        offer: OfferDlc {
            protocol_version,
            contract_flags,
            chain_hash,
            temporary_contract_id,
            contract_info,
            funding_pubkey,
            payout_spk,
            payout_serial_id,
            offer_collateral: Amount::from_sat(offer_collateral),
            funding_inputs,
            change_spk,
            change_serial_id,
            fund_output_serial_id,
            fee_rate_per_vb,
            cet_locktime,
            refund_locktime,
        },
        dlc_inputs,
    })
}

/// Decode a hex-encoded `DlcAccept`.
///
/// # Errors
///
/// Returns an error if the hex is malformed or the message does not decode.
pub fn read_accept(hex_str: &str) -> Result<AcceptDlc, DecodeError> {
    let bytes = qos_hex::decode(hex_str.trim()).map_err(|_| DecodeError::InvalidValue)?;
    let body = strip_type(&bytes, dlc_messages::ACCEPT_TYPE)?;
    Readable::read(&mut Cursor::new(body))
}

/// Decode a hex-encoded `DlcSign`.
///
/// # Errors
///
/// Returns an error if the hex is malformed or the message does not decode.
pub fn read_sign(hex_str: &str) -> Result<SignDlc, DecodeError> {
    let bytes = qos_hex::decode(hex_str.trim()).map_err(|_| DecodeError::InvalidValue)?;
    let body = strip_type(&bytes, dlc_messages::SIGN_TYPE)?;
    Readable::read(&mut Cursor::new(body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn decodes_offer_with_a_dlc_funded_input() {
        let decoded = read_offer(fixtures::SAMPLE_OFFER).expect("offer should decode");

        assert_eq!(decoded.offer.protocol_version, 1);
        assert_eq!(decoded.offer.fee_rate_per_vb, 10);
        assert_eq!(decoded.offer.cet_locktime, 1_781_734_876);
        assert_eq!(decoded.offer.refund_locktime, 1_790_352_000);
        assert_eq!(decoded.offer.offer_collateral, Amount::from_sat(10_000));
        assert_eq!(decoded.offer.funding_inputs.len(), 2);

        // The first input is funded by another DLC; the second is an ordinary UTXO.
        assert_eq!(
            decoded.dlc_inputs[0]
                .as_ref()
                .map(|d| qos_hex::encode(&d.contract_id)),
            Some("1bfb5a41e4597462a2b9250dd9c86fe60b0b28baa815caeb4448f50cb37bc0b8".to_string())
        );
        assert!(decoded.dlc_inputs[1].is_none());
    }

    #[test]
    fn decodes_offer_without_dlc_funded_inputs() {
        let decoded = read_offer(fixtures::MATURED_OFFER).expect("offer should decode");

        assert_eq!(decoded.offer.fee_rate_per_vb, 3);
        assert_eq!(decoded.offer.cet_locktime, 1_767_138_836);
        assert_eq!(decoded.offer.funding_inputs.len(), 1);
        assert!(decoded.dlc_inputs[0].is_none());
    }

    /// The reason this module exists. `rust-dlc`'s own parser does not merely fail on a
    /// node-dlc offer, it can succeed with corrupt values, so a "successful" upstream
    /// decode is not evidence of a correct decode.
    #[test]
    fn upstream_parser_would_silently_corrupt_a_single_input_offer() {
        let bytes = qos_hex::decode(fixtures::MATURED_OFFER).unwrap();
        let upstream: OfferDlc = Readable::read(&mut Cursor::new(&bytes[2..]))
            .expect("upstream decode of a 1-input offer succeeds despite the extra byte");
        let ours = read_offer(fixtures::MATURED_OFFER).unwrap().offer;

        assert_eq!(ours.fee_rate_per_vb, 3);
        assert_ne!(upstream.fee_rate_per_vb, ours.fee_rate_per_vb);
        assert_ne!(upstream.cet_locktime, ours.cet_locktime);
    }

    #[test]
    fn decodes_accept_and_sign() {
        let accept = read_accept(fixtures::SAMPLE_ACCEPT).expect("accept should decode");
        assert_eq!(accept.accept_collateral, Amount::ZERO);
        assert!(accept.funding_inputs.is_empty());
        assert_eq!(
            accept.cet_adaptor_signatures.ecdsa_adaptor_signatures.len(),
            5
        );

        let sign = read_sign(fixtures::SAMPLE_SIGN).expect("sign should decode");
        assert_eq!(
            qos_hex::encode(&sign.contract_id),
            "817e5025e0218d798d868f846f0a958ac5716bdfe341096a7aa8714fb6521d6d"
        );
    }

    #[test]
    fn rejects_wrong_type_prefix() {
        assert!(read_offer(fixtures::SAMPLE_ACCEPT).is_err());
        assert!(read_accept(fixtures::SAMPLE_OFFER).is_err());
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(read_offer("not-hex").is_err());
        assert!(read_offer("").is_err());
    }
}
