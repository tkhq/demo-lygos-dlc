//! Combining contract verification and on-chain inclusion into one verdict.
//!
//! A loan gate wants a single answer, but it also needs to know *why* the answer was no.
//! Every check that can fail contributes a distinct [`FailureReason`], so a caller can
//! tell "the contract is fine but the collateral has not confirmed yet" from "this
//! contract references the wrong oracle".

use serde::Serialize;

use crate::btc::{Inclusion, InclusionError, MIN_CONFIRMATIONS};
use crate::dlc::verify::DlcVerification;

/// Why a verification failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureReason {
    /// A message could not be parsed.
    MalformedInput,
    /// The contract's own cryptography did not check out.
    DlcVerificationFailed,
    /// The oracle key, or another expected value, did not match the contract.
    MismatchExpectedVsParsed,
    /// The collateral transaction is not on chain, or is not yet confirmed enough.
    TxNotFound,
    /// The chain could not be consulted.
    ExplorerRequestFailed,
}

/// Overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Every check passed.
    Verified,
    /// At least one check failed.
    Failed,
}

/// The full response returned to a caller.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    /// Whether the loan may progress.
    pub status: Status,
    /// Everything learned about the contract.
    pub dlc: DlcVerification,
    /// What the chain says, when an inclusion check was requested and succeeded.
    pub bitcoin: Option<Inclusion>,
    /// Why an inclusion check could not be completed.
    pub bitcoin_error: Option<InclusionError>,
    /// Confirmations required for this verdict.
    pub min_confirmations: u32,
    /// Every reason the verdict is `failed`, in the order the checks ran.
    pub failure_reasons: Vec<FailureReason>,
}

/// Combine contract verification with an optional inclusion result.
///
/// `inclusion` is `None` when the caller did not ask for an on-chain check, in which case
/// the verdict rests on the contract alone.
pub fn decide(
    dlc: DlcVerification,
    inclusion: Option<Result<Inclusion, InclusionError>>,
) -> Decision {
    let mut reasons = Vec::new();

    if dlc.error.is_some() || !dlc.structurally_valid {
        reasons.push(FailureReason::MalformedInput);
    } else {
        // Only judge the cryptography once we know the messages parsed, so a malformed
        // input is not also reported as a verification failure.
        if !dlc.oracle_sig_valid {
            reasons.push(FailureReason::DlcVerificationFailed);
        }
        if dlc.adaptor_sigs_valid != Some(true) {
            reasons.push(FailureReason::DlcVerificationFailed);
        }
        if dlc.sign_available && dlc.sign_contract_id_matches == Some(false) {
            reasons.push(FailureReason::DlcVerificationFailed);
        }
        if dlc.oracle_pubkey_matches_expected == Some(false) {
            reasons.push(FailureReason::MismatchExpectedVsParsed);
        }
    }

    let (bitcoin, bitcoin_error) = match inclusion {
        None => (None, None),
        Some(Ok(found)) => {
            if !found.confirmed || found.confirmations.unwrap_or(0) < MIN_CONFIRMATIONS {
                reasons.push(FailureReason::TxNotFound);
            }
            (Some(found), None)
        }
        Some(Err(error)) => {
            reasons.push(match error {
                InclusionError::NotFound | InclusionError::MalformedTxid(_) => {
                    FailureReason::TxNotFound
                }
                InclusionError::ExplorerUnavailable(_) => FailureReason::ExplorerRequestFailed,
            });
            (None, Some(error))
        }
    };

    reasons.dedup();

    Decision {
        status: if reasons.is_empty() {
            Status::Verified
        } else {
            Status::Failed
        },
        dlc,
        bitcoin,
        bitcoin_error,
        min_confirmations: MIN_CONFIRMATIONS,
        failure_reasons: reasons,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A contract that passed every check.
    fn good_dlc() -> DlcVerification {
        DlcVerification {
            structurally_valid: true,
            oracle_sig_valid: true,
            adaptor_sigs_valid: Some(true),
            adaptor_valid_count: 5,
            adaptor_total_count: 5,
            ..DlcVerification::default()
        }
    }

    /// A confirmed transaction.
    fn confirmed(confirmations: u32) -> Inclusion {
        Inclusion {
            txid: "a".repeat(64),
            network: "testnet".to_string(),
            included: true,
            confirmed: confirmations > 0,
            block_height: Some(100),
            confirmations: Some(confirmations),
            funding_output_match: None,
            funding_output_value: None,
        }
    }

    #[test]
    fn everything_passing_verifies() {
        let decision = decide(good_dlc(), Some(Ok(confirmed(3))));
        assert_eq!(decision.status, Status::Verified);
        assert!(decision.failure_reasons.is_empty());
    }

    #[test]
    fn contract_alone_can_verify_when_no_chain_check_was_requested() {
        let decision = decide(good_dlc(), None);
        assert_eq!(decision.status, Status::Verified);
        assert!(decision.bitcoin.is_none());
        assert!(decision.bitcoin_error.is_none());
    }

    #[test]
    fn a_parse_failure_is_reported_once_and_does_not_cascade() {
        let dlc = DlcVerification {
            error: Some("bad offer".to_string()),
            ..DlcVerification::default()
        };
        let decision = decide(dlc, None);

        assert_eq!(decision.status, Status::Failed);
        assert_eq!(
            decision.failure_reasons,
            vec![FailureReason::MalformedInput]
        );
    }

    #[test]
    fn invalid_adaptor_signatures_fail_the_contract() {
        let dlc = DlcVerification {
            adaptor_sigs_valid: Some(false),
            ..good_dlc()
        };
        let decision = decide(dlc, Some(Ok(confirmed(3))));

        assert_eq!(decision.status, Status::Failed);
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::DlcVerificationFailed)
        );
    }

    #[test]
    fn unverified_adaptor_signatures_are_not_treated_as_valid() {
        // `None` means the check never ran, which must not pass a loan gate.
        let dlc = DlcVerification {
            adaptor_sigs_valid: None,
            ..good_dlc()
        };
        assert_eq!(decide(dlc, None).status, Status::Failed);
    }

    #[test]
    fn a_bad_oracle_signature_fails_the_contract() {
        let dlc = DlcVerification {
            oracle_sig_valid: false,
            ..good_dlc()
        };
        assert_eq!(decide(dlc, None).status, Status::Failed);
    }

    #[test]
    fn an_unexpected_oracle_is_distinguished_from_a_broken_contract() {
        let dlc = DlcVerification {
            oracle_pubkey_matches_expected: Some(false),
            ..good_dlc()
        };
        let decision = decide(dlc, Some(Ok(confirmed(3))));

        assert_eq!(
            decision.failure_reasons,
            vec![FailureReason::MismatchExpectedVsParsed],
            "the contract itself is sound; only the caller's expectation was violated"
        );
    }

    #[test]
    fn a_mismatched_sign_contract_id_fails() {
        let dlc = DlcVerification {
            sign_available: true,
            sign_contract_id_matches: Some(false),
            ..good_dlc()
        };
        assert_eq!(decide(dlc, None).status, Status::Failed);
    }

    #[test]
    fn an_unconfirmed_transaction_is_not_yet_locked_collateral() {
        let decision = decide(good_dlc(), Some(Ok(confirmed(0))));

        assert_eq!(decision.status, Status::Failed);
        assert_eq!(decision.failure_reasons, vec![FailureReason::TxNotFound]);
        assert!(
            decision.bitcoin.is_some(),
            "the mempool state is still worth reporting"
        );
    }

    #[test]
    fn a_missing_transaction_and_an_unreachable_explorer_are_different_failures() {
        let missing = decide(good_dlc(), Some(Err(InclusionError::NotFound)));
        assert_eq!(missing.failure_reasons, vec![FailureReason::TxNotFound]);

        let unreachable = decide(
            good_dlc(),
            Some(Err(InclusionError::ExplorerUnavailable(
                "timeout".to_string(),
            ))),
        );
        assert_eq!(
            unreachable.failure_reasons,
            vec![FailureReason::ExplorerRequestFailed],
            "an explorer outage must not look like a missing transaction"
        );
        assert!(unreachable.bitcoin_error.is_some());
    }

    #[test]
    fn independent_failures_are_all_reported() {
        let dlc = DlcVerification {
            oracle_pubkey_matches_expected: Some(false),
            adaptor_sigs_valid: Some(false),
            ..good_dlc()
        };
        let decision = decide(dlc, Some(Err(InclusionError::NotFound)));

        assert_eq!(decision.status, Status::Failed);
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::DlcVerificationFailed)
        );
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::MismatchExpectedVsParsed)
        );
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::TxNotFound)
        );
    }
}
