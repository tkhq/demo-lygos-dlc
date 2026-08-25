//! Turning the checks into a verdict for a particular caller.
//!
//! A loan gate wants one answer, but it also needs to know *why* the answer was no, and
//! different callers gate on different things. So the verdict is assembled from the
//! structured [`Report`] rather than from a pile of booleans, and a [`Profile`] decides
//! which checks are allowed to block.
//!
//! The profile changes only what gates. The cryptography is identical either way — an
//! institutional lender and the Morpho Midnight flow get the same verification, they just
//! need different things proven before they act.

use serde::{Deserialize, Serialize};

use crate::btc::{Inclusion, InclusionError, MIN_CONFIRMATIONS};
use crate::checks::{Check, Report, Severity, Status as CheckStatus};
use crate::dlc::verify::DlcVerification;
use crate::event_id;
use crate::terms::ExpectedTerms;

/// Which use case a request is for.
///
/// The profile shapes how a report reads, and decides one thing about gating: whether a
/// verdict may be reached *without consulting the chain at all*. Minting a collateral
/// representation cannot be, so Morpho Midnight always needs funding confirmed. A lender may
/// legitimately review terms before the borrower has posted collateral, so a term-only check
/// is a valid answer for them.
///
/// Once the chain *is* consulted, funding gates for both: a lender advancing money against
/// Bitcoin collateral needs it locked just as much as the minting side does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// A lender deciding whether to advance funds. The contract and the agreed terms must
    /// check out; the collateral may not be funded yet, so the chain is not consulted.
    #[default]
    InstitutionalLender,
    /// The cross-chain flow: the contract must match the expected terms **and** the
    /// collateral must be funded on Bitcoin, because the resulting attestation is what the
    /// Midnight contracts rely on before minting a collateral representation.
    MorphoMidnight,
}

impl Profile {
    /// Whether this use case can be satisfied without consulting the chain.
    ///
    /// Only true for a lender doing a pre-collateral term review. Minting always needs the
    /// collateral confirmed.
    #[must_use]
    pub fn allows_term_only_verdict(self) -> bool {
        matches!(self, Self::InstitutionalLender)
    }

    /// A short description for a report.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::InstitutionalLender => "Institutional lender",
            Self::MorphoMidnight => "Morpho Midnight",
        }
    }
}

/// Why a verification failed. Retained alongside the check list because a caller gating a
/// loan wants a small set of reasons to branch on, not to interpret every check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailureReason {
    /// A message could not be parsed.
    MalformedInput,
    /// The contract's own cryptography did not check out.
    DlcVerificationFailed,
    /// A decoded value did not match what the caller expected.
    MismatchExpectedVsParsed,
    /// The collateral transaction is not on chain, or is not confirmed enough.
    TxNotFound,
    /// The chain could not be consulted.
    ExplorerRequestFailed,
    /// A check this profile requires could not be answered either way.
    CheckNotVerifiable,
}

/// What happened with the on-chain collateral check.
///
/// Three states rather than an `Option`, because "this endpoint does not consult the chain"
/// and "we were asked to and had nothing to look up" are different situations and must not
/// produce the same verdict. Flattening them is how a lender gets a pass on a loan whose
/// collateral was never checked.
pub enum Onchain {
    /// The caller used an endpoint that performs no chain lookup, so the check does not
    /// apply. Never blocks.
    NotRequested,
    /// A lookup was expected but no transaction was supplied or derivable. Blocks wherever
    /// funding is required.
    NoTransaction,
    /// The chain was consulted.
    Looked(Result<Inclusion, InclusionError>),
}

/// Overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Every required check passed.
    Verified,
    /// At least one required check did not pass.
    Failed,
}

/// The full response returned to a caller.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    /// Whether the loan may progress.
    pub status: Status,
    /// Which use case this was evaluated for.
    pub profile: Profile,
    /// Human-readable profile name.
    pub profile_label: &'static str,
    /// Everything learned about the contract.
    pub dlc: DlcVerification,
    /// What the chain says, when an inclusion check ran and succeeded.
    pub bitcoin: Option<Inclusion>,
    /// Why an inclusion check could not be completed.
    pub bitcoin_error: Option<InclusionError>,
    /// Confirmations required for this verdict.
    pub min_confirmations: u32,
    /// Every check considered, with its own status and severity.
    pub checks: Vec<Check>,
    /// Ids of the required checks that did not pass.
    pub blocking_checks: Vec<&'static str>,
    /// Digest over the expected terms, so another system can bind to what was checked.
    pub terms_digest: Option<String>,
    /// Coarse reasons the verdict is `failed`.
    pub failure_reasons: Vec<FailureReason>,
}

/// Assemble the verdict.
///
/// `inclusion` is `None` when no on-chain check was performed. For a profile that requires
/// funding, that absence is itself a failure rather than something to pass over.
#[must_use]
pub fn decide(
    profile: Profile,
    dlc: DlcVerification,
    expected: &ExpectedTerms,
    onchain: Onchain,
) -> Decision {
    let mut checks = Vec::new();
    let mut reasons = Vec::new();

    // Parsing first: nothing downstream means anything if the messages did not decode.
    let parsed = dlc.error.is_none() && dlc.structurally_valid;
    checks.push(
        Check::new(
            "messages_decoded",
            "DLC messages decoded",
            if parsed {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            Severity::Required,
        )
        .with_detail(dlc.error.clone().unwrap_or_default()),
    );

    if parsed {
        checks.push(Check::new(
            "oracle_announcement_signature",
            "Oracle announcement signature",
            if dlc.oracle_sig_valid {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            Severity::Required,
        ));
        checks.push(Check::from_option(
            "cet_adaptor_signatures",
            "CET adaptor signatures",
            dlc.adaptor_sigs_valid,
            Severity::Required,
        ));
        checks.push(Check::from_option(
            "accepter_refund_signature",
            "Lender refund signature",
            dlc.accepter_refund_sig_valid,
            Severity::Required,
        ));
        // The offerer's refund signature only exists once the contract reaches the sign
        // stage, so requiring it would fail every pre-sign contract.
        checks.push(Check::from_option(
            "offerer_refund_signature",
            "Borrower refund signature",
            dlc.offerer_refund_sig_valid,
            Severity::Informational,
        ));
        checks.push(Check::from_option(
            "sign_contract_id",
            "Sign message contract id",
            if dlc.sign_available {
                dlc.sign_contract_id_matches
            } else {
                None
            },
            Severity::Informational,
        ));

        // When the caller stated no expectations at all, `compare` emits one clear
        // "no terms supplied" failure. Adding per-term checks on top of that would bury
        // the actual reason under a list of things nobody asked for.
        if !expected.is_empty() {
            checks.push(event_id::exact_match_check(
                expected.oracle_event_id.as_deref(),
                dlc.oracle_event_id.as_deref(),
            ));
            checks.push(event_id::recompute_check(
                &expected.loan_terms,
                dlc.oracle_event_id.as_deref(),
            ));
        }
        checks.extend(expected.compare(&dlc));
    }

    // On-chain funding. Both use cases care: a lender advancing money against Bitcoin
    // collateral needs it locked just as much as the minting side does, so this is required
    // wherever the chain was actually consulted.
    let (bitcoin, bitcoin_error) = match onchain {
        Onchain::NotRequested => {
            // A lender may be reviewing terms before collateral exists, which is a real
            // answer. Minting cannot proceed on that basis, so for the cross-chain profile
            // an unconsulted chain is a missing requirement rather than a non-applicable one.
            let severity = if profile.allows_term_only_verdict() {
                Severity::Informational
            } else {
                Severity::Required
            };
            checks.push(
                Check::new(
                    "onchain_funding",
                    "Collateral confirmed on Bitcoin",
                    CheckStatus::NotChecked,
                    severity,
                )
                .with_detail(
                    "this endpoint does not consult the chain. Use /dlc/verify_loan to \
                     confirm the collateral is locked before advancing funds.",
                ),
            );
            if severity == Severity::Required {
                reasons.push(FailureReason::TxNotFound);
            }
            (None, None)
        }
        Onchain::NoTransaction => {
            checks.push(
                Check::new(
                    "onchain_funding",
                    "Collateral confirmed on Bitcoin",
                    CheckStatus::NotChecked,
                    Severity::Required,
                )
                .with_detail(
                    "no collateral transaction was supplied, and none could be derived from \
                     the contract, so the collateral was never checked",
                ),
            );
            reasons.push(FailureReason::TxNotFound);
            (None, None)
        }
        Onchain::Looked(Ok(found)) => {
            let confirmations = found.confirmations.unwrap_or(0);
            let confirmed_enough = found.confirmed && confirmations >= MIN_CONFIRMATIONS;
            checks.push(
                Check::new(
                    "onchain_funding",
                    "Collateral confirmed on Bitcoin",
                    if confirmed_enough {
                        CheckStatus::Pass
                    } else {
                        CheckStatus::Fail
                    },
                    Severity::Required,
                )
                .with_values(
                    format!("at least {MIN_CONFIRMATIONS} confirmation(s)"),
                    format!("{confirmations} confirmation(s)"),
                ),
            );
            // Reported but never blocking: in the demo the transaction is deliberately
            // unrelated to the sample contract, so this is context rather than a verdict.
            if let Some(matched) = found.funding_output_match {
                checks.push(
                    Check::new(
                        "funding_output_match",
                        "Transaction pays this contract's funding output",
                        if matched {
                            CheckStatus::Pass
                        } else {
                            CheckStatus::Fail
                        },
                        Severity::Informational,
                    )
                    .with_detail(
                        "informational: a demo transaction is usually unrelated to the \
                         sample contract, so a mismatch here is expected",
                    ),
                );
            }
            if !confirmed_enough {
                reasons.push(FailureReason::TxNotFound);
            }
            (Some(found), None)
        }
        Onchain::Looked(Err(error)) => {
            let (status_detail, reason) = match &error {
                InclusionError::NotFound => ("not found on chain", FailureReason::TxNotFound),
                InclusionError::MalformedTxid(_) => {
                    ("the txid was malformed", FailureReason::TxNotFound)
                }
                InclusionError::ExplorerUnavailable(_) => (
                    "the explorer could not be reached",
                    FailureReason::ExplorerRequestFailed,
                ),
            };
            checks.push(
                Check::new(
                    "onchain_funding",
                    "Collateral confirmed on Bitcoin",
                    CheckStatus::Fail,
                    Severity::Required,
                )
                .with_detail(format!("{status_detail}: {error}")),
            );
            reasons.push(reason);
            (None, Some(error))
        }
    };

    let report = Report::new(checks);

    // Derive the coarse reasons from what actually blocked, so the two can never disagree.
    if !parsed {
        reasons.push(FailureReason::MalformedInput);
    }
    for check in &report.checks {
        if check.severity != Severity::Required || check.status.is_satisfied() {
            continue;
        }
        let reason = match (check.id, check.status) {
            ("onchain_funding", _) => continue, // already recorded above with its cause
            (_, CheckStatus::NotVerifiable) => FailureReason::CheckNotVerifiable,
            ("messages_decoded", _) => FailureReason::MalformedInput,
            (
                "oracle_announcement_signature"
                | "cet_adaptor_signatures"
                | "accepter_refund_signature",
                _,
            ) => FailureReason::DlcVerificationFailed,
            _ => FailureReason::MismatchExpectedVsParsed,
        };
        reasons.push(reason);
    }
    reasons.dedup();

    let status = if report.all_required_satisfied() {
        Status::Verified
    } else {
        Status::Failed
    };

    Decision {
        status,
        profile,
        profile_label: profile.label(),
        dlc,
        bitcoin,
        bitcoin_error,
        min_confirmations: MIN_CONFIRMATIONS,
        blocking_checks: report.blocking(),
        checks: report.checks,
        terms_digest: expected.digest().ok(),
        failure_reasons: reasons,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::terms::{AddressAmount, ExpectedOutcome, RefundTerms};

    /// A contract that passed every cryptographic check.
    fn good_dlc() -> DlcVerification {
        DlcVerification {
            structurally_valid: true,
            oracle_sig_valid: true,
            adaptor_sigs_valid: Some(true),
            adaptor_valid_count: 5,
            adaptor_total_count: 5,
            accepter_refund_sig_valid: Some(true),
            offerer_refund_sig_valid: Some(true),
            total_collateral: Some(10_000),
            accepter_funding_pubkey: Some("02aa".to_string()),
            offerer_funding_pubkey: Some("03bb".to_string()),
            extracted_oracle_pubkey: Some("8731".to_string()),
            oracle_event_id: Some("loan-matured-aa".to_string()),
            offerer_payout_address: Some("tb1qborrower".to_string()),
            accepter_payout_address: Some("tb1qlender".to_string()),
            refund_locktime: Some(1_790_352_000),
            cet_locktime: Some(1_781_734_876),
            fee_rate_per_vb: Some(10),
            outcomes: vec![crate::dlc::verify::Outcome {
                label: "repaid".to_string(),
                offerer_sats: 10_000,
                accepter_sats: 0,
            }],
            ..DlcVerification::default()
        }
    }

    /// Terms that match `good_dlc`.
    fn matching_terms() -> ExpectedTerms {
        ExpectedTerms {
            lender_pubkey: Some("02aa".to_string()),
            borrower_pubkey: Some("03bb".to_string()),
            oracle_pubkey: Some("8731".to_string()),
            oracle_event_id: Some("loan-matured-aa".to_string()),
            total_collateral_sats: Some(10_000),
            repayment: AddressAmount {
                address: Some("tb1qborrower".to_string()),
                sats: Some(10_000),
            },
            liquidation: AddressAmount {
                address: Some("tb1qlender".to_string()),
                sats: None,
            },
            refund: RefundTerms {
                address: Some("tb1qborrower".to_string()),
                locktime: Some(1_790_352_000),
            },
            cet_locktime: Some(1_781_734_876),
            fee_rate_per_vb: Some(10),
            outcomes: vec![ExpectedOutcome {
                label: "repaid".to_string(),
                offerer_sats: Some(10_000),
                accepter_sats: Some(0),
            }],
            ..ExpectedTerms::default()
        }
    }

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
    fn a_lender_verifies_without_any_chain_check() {
        let decision = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(
            decision.status,
            Status::Verified,
            "{:?}",
            decision.blocking_checks
        );
        assert!(decision.failure_reasons.is_empty());
        assert!(decision.terms_digest.is_some());
    }

    /// A verdict of `failed` must always carry a reason a caller can branch on.
    #[test]
    fn every_failure_carries_at_least_one_reason() {
        for (name, decision) in [
            (
                "midnight without funding",
                decide(
                    Profile::MorphoMidnight,
                    good_dlc(),
                    &matching_terms(),
                    Onchain::NotRequested,
                ),
            ),
            (
                "lender with no expectations",
                decide(
                    Profile::InstitutionalLender,
                    good_dlc(),
                    &ExpectedTerms::default(),
                    Onchain::NotRequested,
                ),
            ),
        ] {
            assert_eq!(decision.status, Status::Failed, "{name}");
            assert!(
                !decision.failure_reasons.is_empty(),
                "{name}: failed with no reason, leaving a caller nothing to branch on"
            );
            assert!(!decision.blocking_checks.is_empty(), "{name}");
        }
    }

    #[test]
    fn midnight_requires_the_collateral_to_be_funded() {
        // Same contract and terms, but no chain result: fine for a lender, not for Midnight.
        let lender = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(lender.status, Status::Verified);

        let midnight = decide(
            Profile::MorphoMidnight,
            good_dlc(),
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(midnight.status, Status::Failed);
        assert!(midnight.blocking_checks.contains(&"onchain_funding"));
    }

    #[test]
    fn midnight_verifies_when_the_collateral_is_confirmed() {
        let decision = decide(
            Profile::MorphoMidnight,
            good_dlc(),
            &matching_terms(),
            Onchain::Looked(Ok(confirmed(6))),
        );
        assert_eq!(
            decision.status,
            Status::Verified,
            "{:?}",
            decision.blocking_checks
        );
    }

    #[test]
    fn an_unconfirmed_transaction_blocks_midnight() {
        let decision = decide(
            Profile::MorphoMidnight,
            good_dlc(),
            &matching_terms(),
            Onchain::Looked(Ok(confirmed(0))),
        );
        assert_eq!(decision.status, Status::Failed);
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::TxNotFound)
        );
    }

    #[test]
    fn a_single_wrong_term_fails_and_is_named() {
        let mut terms = matching_terms();
        terms.liquidation.address = Some("tb1qattacker".to_string());
        let decision = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &terms,
            Onchain::NotRequested,
        );

        assert_eq!(decision.status, Status::Failed);
        assert_eq!(decision.blocking_checks, vec!["liquidation_address"]);
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::MismatchExpectedVsParsed)
        );
    }

    #[test]
    fn broken_cryptography_is_reported_separately_from_a_term_mismatch() {
        let dlc = DlcVerification {
            adaptor_sigs_valid: Some(false),
            ..good_dlc()
        };
        let decision = decide(
            Profile::InstitutionalLender,
            dlc,
            &matching_terms(),
            Onchain::NotRequested,
        );

        assert_eq!(decision.status, Status::Failed);
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::DlcVerificationFailed)
        );
        assert!(
            !decision
                .failure_reasons
                .contains(&FailureReason::MismatchExpectedVsParsed)
        );
    }

    #[test]
    fn a_missing_refund_signature_blocks_the_lender() {
        let dlc = DlcVerification {
            accepter_refund_sig_valid: None,
            ..good_dlc()
        };
        let decision = decide(
            Profile::InstitutionalLender,
            dlc,
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(decision.status, Status::Failed);
        assert!(
            decision
                .blocking_checks
                .contains(&"accepter_refund_signature")
        );
    }

    #[test]
    fn a_pre_sign_contract_still_verifies() {
        // No sign message yet, so the borrower's refund signature and the sign contract id
        // are absent. Neither should block: this is the normal pre-sign state.
        let dlc = DlcVerification {
            offerer_refund_sig_valid: None,
            sign_available: false,
            sign_contract_id_matches: None,
            ..good_dlc()
        };
        let decision = decide(
            Profile::InstitutionalLender,
            dlc,
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(
            decision.status,
            Status::Verified,
            "{:?}",
            decision.blocking_checks
        );
    }

    #[test]
    fn a_caller_who_expects_nothing_does_not_get_a_pass() {
        let decision = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &ExpectedTerms::default(),
            Onchain::NotRequested,
        );
        assert_eq!(
            decision.status,
            Status::Failed,
            "verifying against no expectations must not report success"
        );
    }

    #[test]
    fn malformed_input_is_reported_and_does_not_cascade() {
        let dlc = DlcVerification {
            error: Some("bad offer".to_string()),
            ..DlcVerification::default()
        };
        let decision = decide(
            Profile::InstitutionalLender,
            dlc,
            &ExpectedTerms::default(),
            Onchain::NotRequested,
        );
        assert_eq!(decision.status, Status::Failed);
        assert_eq!(
            decision.failure_reasons,
            vec![FailureReason::MalformedInput],
            "a parse failure should not also be reported as a term mismatch"
        );
    }

    #[test]
    fn an_explorer_outage_is_distinct_from_a_missing_transaction() {
        let decision = decide(
            Profile::MorphoMidnight,
            good_dlc(),
            &matching_terms(),
            Onchain::Looked(Err(InclusionError::ExplorerUnavailable(
                "timeout".to_string(),
            ))),
        );
        assert!(
            decision
                .failure_reasons
                .contains(&FailureReason::ExplorerRequestFailed)
        );
        assert!(
            !decision
                .failure_reasons
                .contains(&FailureReason::TxNotFound)
        );
    }

    #[test]
    fn the_placeholder_event_id_derivation_never_blocks() {
        let mut terms = matching_terms();
        terms.loan_terms = crate::event_id::LoanTerms {
            loan_id: Some("loan-1".to_string()),
            ..crate::event_id::LoanTerms::default()
        };
        let decision = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &terms,
            Onchain::NotRequested,
        );

        // It is reported, and it has no verdict, but it must not fail the loan.
        let check = decision
            .checks
            .iter()
            .find(|c| c.id == "oracle_event_id_recomputed")
            .unwrap();
        assert_eq!(check.status, CheckStatus::NotVerifiable);
        assert_eq!(decision.status, Status::Verified);
    }

    #[test]
    fn evm_terms_do_not_gate_the_midnight_verdict() {
        let mut terms = matching_terms();
        terms.evm = crate::terms::EvmTerms {
            position: Some("morpho-1".to_string()),
            collateral_sats: Some(10_000),
            note: None,
        };
        let decision = decide(
            Profile::MorphoMidnight,
            good_dlc(),
            &terms,
            Onchain::Looked(Ok(confirmed(6))),
        );
        assert_eq!(
            decision.status,
            Status::Verified,
            "{:?}",
            decision.blocking_checks
        );
    }

    /// The case this whole design exists for: a lending partner advancing money against
    /// Bitcoin collateral. Once they ask for the chain to be consulted, unconfirmed
    /// collateral must block — being a lender does not make it optional.
    #[test]
    fn a_lender_who_consults_the_chain_is_gated_on_confirmed_collateral() {
        let unconfirmed = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &matching_terms(),
            Onchain::Looked(Ok(confirmed(0))),
        );
        assert_eq!(unconfirmed.status, Status::Failed);
        assert!(unconfirmed.blocking_checks.contains(&"onchain_funding"));

        let confirmed_enough = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &matching_terms(),
            Onchain::Looked(Ok(confirmed(3))),
        );
        assert_eq!(
            confirmed_enough.status,
            Status::Verified,
            "{:?}",
            confirmed_enough.blocking_checks
        );
    }

    /// Asking for a chain check and having nothing to look up is not the same as not asking.
    /// It must never read as a pass for either use case.
    #[test]
    fn a_missing_collateral_transaction_blocks_both_use_cases() {
        for profile in [Profile::InstitutionalLender, Profile::MorphoMidnight] {
            let decision = decide(
                profile,
                good_dlc(),
                &matching_terms(),
                Onchain::NoTransaction,
            );
            assert_eq!(
                decision.status,
                Status::Failed,
                "{:?} should not pass without a collateral transaction",
                profile
            );
            assert!(decision.blocking_checks.contains(&"onchain_funding"));
            assert!(!decision.failure_reasons.is_empty());
        }
    }

    /// A term-only review is a legitimate answer for a lender before collateral is posted,
    /// but never for minting a collateral representation.
    #[test]
    fn only_a_lender_may_reach_a_verdict_without_consulting_the_chain() {
        let lender = decide(
            Profile::InstitutionalLender,
            good_dlc(),
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(
            lender.status,
            Status::Verified,
            "{:?}",
            lender.blocking_checks
        );

        let midnight = decide(
            Profile::MorphoMidnight,
            good_dlc(),
            &matching_terms(),
            Onchain::NotRequested,
        );
        assert_eq!(midnight.status, Status::Failed);
        assert!(midnight.blocking_checks.contains(&"onchain_funding"));
    }
}
