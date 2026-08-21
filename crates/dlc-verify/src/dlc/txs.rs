//! Deterministic reconstruction of a DLC's fund transaction and CETs.
//!
//! Lygos's loans are **single-funded**: the offerer supplies all collateral and all
//! funding inputs, and the accepter supplies neither. `rust-dlc`'s
//! `create_dlc_transactions` rejects that shape, because it requires each party's inputs
//! to cover that party's share of the fees and the accepter has no inputs at all
//! (`PartyParams::get_change_output_and_fees` returns `InvalidArgument`). Lygos's
//! `dlc-verify` gets around this by calling DDK, a modified `rust-dlc` distributed only
//! as a prebuilt native addon, so it cannot be used from this enclave.
//!
//! This module reimplements the construction DDK performs for the single-funded case.
//! Three details differ from a symmetric two-party DLC, all of them derived by matching
//! DDK's output byte-for-byte on the Lygos fixtures (see the tests in [`super::verify`]):
//!
//! 1. The offerer alone bears the *whole* fund-transaction base weight, not half of it.
//! 2. The CET fee is prepaid into the fund output, so the fund output holds
//!    `total_collateral + cet_fee` and each CET pays out the full, unreduced payout.
//! 3. A CET has one output per non-dust payout. Lygos's payouts are all-or-nothing, so
//!    in practice each CET has exactly one output.
//!
//! The reconstruction has to be exact: an adaptor signature commits to the CET's sighash,
//! so a single wrong byte anywhere in either transaction makes every signature fail.

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// Weight of a fund transaction excluding inputs, change outputs, and the fund output.
/// Matches `rust-dlc`'s `FUND_TX_BASE_WEIGHT`.
const FUND_TX_BASE_WEIGHT: u64 = 214;
/// Weight of a CET excluding its payout outputs. Matches `rust-dlc`'s `CET_BASE_WEIGHT`.
const CET_BASE_WEIGHT: u64 = 500;
/// Weight of a transaction input excluding its witness. Matches `rust-dlc`'s
/// `TX_INPUT_BASE_WEIGHT`.
const TX_INPUT_BASE_WEIGHT: u64 = 164;
/// Outputs at or below this value are omitted rather than created.
const DUST_LIMIT: Amount = Amount::from_sat(1000);
/// Weight contributed by the fund output itself, charged to the funding party.
const FUND_OUTPUT_WEIGHT: u64 = 36;
/// Sequence that leaves the CET's locktime enforced.
const CET_SEQUENCE: Sequence = Sequence(0xffff_fffe);

/// Errors that can arise while rebuilding a DLC's transactions.
#[derive(Debug, thiserror::Error)]
pub enum TxError {
    /// A funding input referenced a previous transaction that could not be decoded.
    #[error("funding input {index} has an undecodable prev_tx: {source}")]
    PrevTx {
        /// Index of the offending funding input.
        index: usize,
        /// Underlying consensus decoding error.
        source: bitcoin::consensus::encode::Error,
    },
    /// A funding input pointed at a vout that its previous transaction does not have.
    #[error("funding input {index} references vout {vout}, which does not exist")]
    MissingVout {
        /// Index of the offending funding input.
        index: usize,
        /// The out-of-range vout.
        vout: u32,
    },
    /// Arithmetic over satoshi amounts overflowed.
    #[error("amount overflow while computing {what}")]
    Overflow {
        /// Which quantity overflowed.
        what: &'static str,
    },
    /// The offerer's inputs cannot cover the collateral plus fees.
    #[error(
        "funding inputs total {input_amount} sat but {required} sat is required \
         (collateral {collateral} + cet fee {cet_fee} + fund fee {fund_fee})"
    )]
    InsufficientFunds {
        /// Sum of the offerer's input values.
        input_amount: u64,
        /// Total required.
        required: u64,
        /// Collateral locked in the contract.
        collateral: u64,
        /// Prepaid CET fee.
        cet_fee: u64,
        /// Fund transaction fee.
        fund_fee: u64,
    },
    /// The fund output was not found in the transaction that was just built.
    #[error("could not locate the fund output in the reconstructed fund transaction")]
    MissingFundOutput,
}

/// One party's contribution to the contract.
pub struct PartyInputs {
    /// Key used in the 2-of-2 fund script.
    pub funding_pubkey: secp256k1_zkp::PublicKey,
    /// Where this party receives change from the fund transaction.
    pub change_spk: ScriptBuf,
    /// Orders the change output within the fund transaction.
    pub change_serial_id: u64,
    /// Where this party receives its CET payout.
    pub payout_spk: ScriptBuf,
    /// Orders the payout output within each CET.
    pub payout_serial_id: u64,
    /// Collateral contributed.
    pub collateral: Amount,
}

/// A single outcome's split of the total collateral.
pub struct Payout {
    /// Amount paid to the offerer.
    pub offer: Amount,
    /// Amount paid to the accepter.
    pub accept: Amount,
}

/// The rebuilt transactions plus the values needed to check signatures against them.
pub struct DlcTransactions {
    /// The fund transaction.
    pub fund: Transaction,
    /// Index of the 2-of-2 output within [`Self::fund`].
    pub fund_vout: u32,
    /// Value held by the fund output: collateral plus the prepaid CET fee.
    pub fund_output_value: Amount,
    /// The 2-of-2 redeem script (**not** its P2WSH wrapper) — the script an adaptor
    /// signature's sighash is computed over.
    pub funding_script: ScriptBuf,
    /// One CET per payout, in the same order as the contract's outcomes.
    pub cets: Vec<Transaction>,
    /// Fee paid by the fund transaction.
    pub fund_fee: Amount,
    /// CET fee, prepaid into the fund output.
    pub cet_fee: Amount,
    /// Change returned to the offerer.
    pub change: Amount,
}

/// Convert a weight to a fee at `fee_rate_per_vb`, rounding the weight up to whole vbytes.
fn weight_to_fee(weight: u64, fee_rate_per_vb: u64) -> Result<Amount, TxError> {
    let vbytes = weight.div_ceil(4);
    vbytes
        .checked_mul(fee_rate_per_vb)
        .map(Amount::from_sat)
        .ok_or(TxError::Overflow { what: "fee" })
}

/// Contract-level terms that shape the transactions.
pub struct ContractTerms {
    /// Total collateral the contract locks.
    pub total_collateral: Amount,
    /// Fee rate the contract was negotiated at.
    pub fee_rate_per_vb: u64,
    /// Orders the fund output within the fund transaction.
    pub fund_output_serial_id: u64,
    /// Locktime applied to every CET.
    pub cet_locktime: u32,
}

/// Build the fund transaction and CETs for a single-funded DLC.
///
/// `funding_inputs` are the offerer's; the accepter is expected to have none.
///
/// # Errors
///
/// Returns [`TxError`] if a funding input cannot be decoded, if amounts overflow, or if
/// the offerer's inputs do not cover the collateral plus fees.
pub fn build_single_funded(
    offer: &PartyInputs,
    accept: &PartyInputs,
    funding_inputs: &[dlc_messages::FundingInput],
    payouts: &[Payout],
    terms: &ContractTerms,
) -> Result<DlcTransactions, TxError> {
    use bitcoin::consensus::Decodable;

    let ContractTerms {
        total_collateral,
        fee_rate_per_vb,
        fund_output_serial_id,
        cet_locktime,
    } = *terms;

    let mut input_amount = Amount::ZERO;
    let mut inputs_weight: u64 = 0;
    let mut tx_ins = Vec::with_capacity(funding_inputs.len());

    for (index, input) in funding_inputs.iter().enumerate() {
        let prev_tx = Transaction::consensus_decode(&mut std::io::Cursor::new(&input.prev_tx))
            .map_err(|source| TxError::PrevTx { index, source })?;
        let vout = usize::try_from(input.prev_tx_vout).map_err(|_| TxError::MissingVout {
            index,
            vout: input.prev_tx_vout,
        })?;
        let prev_out = prev_tx.output.get(vout).ok_or(TxError::MissingVout {
            index,
            vout: input.prev_tx_vout,
        })?;
        input_amount = input_amount
            .checked_add(prev_out.value)
            .ok_or(TxError::Overflow {
                what: "funding input total",
            })?;
        inputs_weight = inputs_weight
            .checked_add(TX_INPUT_BASE_WEIGHT + u64::from(input.max_witness_len))
            .ok_or(TxError::Overflow {
                what: "input weight",
            })?;
        tx_ins.push(TxIn {
            previous_output: OutPoint {
                txid: prev_tx.compute_txid(),
                vout: input.prev_tx_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(input.sequence),
            witness: Witness::new(),
        });
    }

    let funding_script =
        dlc::make_funding_redeemscript(&offer.funding_pubkey, &accept.funding_pubkey);
    let funding_spk = funding_script.to_p2wsh();

    // Each CET spends the fund output and pays out to a single non-dust payout script,
    // so its fee is charged against the whole CET base weight plus one output script.
    let payout_spk_weight = payout_script_weight(offer, accept);
    let cet_fee = weight_to_fee(CET_BASE_WEIGHT + payout_spk_weight, fee_rate_per_vb)?;

    // The offerer is the only funder, so it carries the entire fund-tx base weight.
    let fund_weight = FUND_TX_BASE_WEIGHT
        + inputs_weight
        + offer.change_spk.len() as u64 * 4
        + FUND_OUTPUT_WEIGHT;
    let fund_fee = weight_to_fee(fund_weight, fee_rate_per_vb)?;

    let fund_output_value = total_collateral
        .checked_add(cet_fee)
        .ok_or(TxError::Overflow {
            what: "fund output value",
        })?;
    let required = fund_output_value
        .checked_add(fund_fee)
        .ok_or(TxError::Overflow {
            what: "required funds",
        })?;
    let change = input_amount
        .checked_sub(required)
        .ok_or(TxError::InsufficientFunds {
            input_amount: input_amount.to_sat(),
            required: required.to_sat(),
            collateral: total_collateral.to_sat(),
            cet_fee: cet_fee.to_sat(),
            fund_fee: fund_fee.to_sat(),
        })?;

    let mut fund_outputs = vec![(
        fund_output_serial_id,
        TxOut {
            value: fund_output_value,
            script_pubkey: funding_spk.clone(),
        },
    )];
    if change > DUST_LIMIT {
        fund_outputs.push((
            offer.change_serial_id,
            TxOut {
                value: change,
                script_pubkey: offer.change_spk.clone(),
            },
        ));
    }
    fund_outputs.sort_by_key(|(serial_id, _)| *serial_id);

    let fund = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_ins,
        output: fund_outputs.into_iter().map(|(_, out)| out).collect(),
    };

    let fund_vout = fund
        .output
        .iter()
        .position(|out| out.script_pubkey == funding_spk)
        .and_then(|i| u32::try_from(i).ok())
        .ok_or(TxError::MissingFundOutput)?;
    let fund_outpoint = OutPoint {
        txid: fund.compute_txid(),
        vout: fund_vout,
    };

    let cets = payouts
        .iter()
        .map(|payout| build_cet(payout, offer, accept, fund_outpoint, cet_locktime))
        .collect();

    Ok(DlcTransactions {
        fund,
        fund_vout,
        fund_output_value,
        funding_script,
        cets,
        fund_fee,
        cet_fee,
        change,
    })
}

/// Weight of the payout script a CET will carry. Both parties' payout scripts are the
/// same length in every Lygos contract; the larger is used so the fee is never short.
fn payout_script_weight(offer: &PartyInputs, accept: &PartyInputs) -> u64 {
    let offer_len = offer.payout_spk.len() as u64;
    let accept_len = accept.payout_spk.len() as u64;
    offer_len.max(accept_len) * 4
}

/// Build the CET for one outcome, omitting dust payouts and ordering outputs by serial id.
fn build_cet(
    payout: &Payout,
    offer: &PartyInputs,
    accept: &PartyInputs,
    fund_outpoint: OutPoint,
    cet_locktime: u32,
) -> Transaction {
    let mut outputs = Vec::with_capacity(2);
    if payout.offer > DUST_LIMIT {
        outputs.push((
            offer.payout_serial_id,
            TxOut {
                value: payout.offer,
                script_pubkey: offer.payout_spk.clone(),
            },
        ));
    }
    if payout.accept > DUST_LIMIT {
        outputs.push((
            accept.payout_serial_id,
            TxOut {
                value: payout.accept,
                script_pubkey: accept.payout_spk.clone(),
            },
        ));
    }
    outputs.sort_by_key(|(serial_id, _)| *serial_id);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(cet_locktime),
        input: vec![TxIn {
            previous_output: fund_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: CET_SEQUENCE,
            witness: Witness::new(),
        }],
        output: outputs.into_iter().map(|(_, out)| out).collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn weight_to_fee_rounds_weight_up_to_whole_vbytes() {
        // 588 weight units = 147 vbytes exactly.
        assert_eq!(weight_to_fee(588, 10).unwrap(), Amount::from_sat(1470));
        // 589 rounds up to 148 vbytes rather than truncating to 147.
        assert_eq!(weight_to_fee(589, 10).unwrap(), Amount::from_sat(1480));
        assert_eq!(weight_to_fee(0, 10).unwrap(), Amount::ZERO);
    }

    #[test]
    fn weight_to_fee_reports_overflow_rather_than_wrapping() {
        assert!(matches!(
            weight_to_fee(u64::MAX, u64::MAX),
            Err(TxError::Overflow { .. })
        ));
    }
}
