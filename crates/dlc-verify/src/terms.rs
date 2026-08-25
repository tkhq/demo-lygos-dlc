//! Comparing a decoded contract against the terms a caller expected.
//!
//! Cryptographic validity is necessary but not sufficient. A DLC can be perfectly signed
//! and still pay the wrong party, mature on the wrong date, or reference the wrong oracle.
//! What a lender actually needs before advancing funds is that the contract encodes *the
//! terms they agreed to*, so this module turns each term into a [`Check`].
//!
//! Every field is optional. An expectation the caller did not supply becomes
//! [`Status::NotChecked`] rather than a pass — see [`crate::checks`] for why that
//! distinction is load-bearing.
//!
//! In these loans the **offerer is the borrower** (single-funded: it posts all the
//! collateral) and the **accepter is the lender**. So the offerer's payout address is where
//! collateral returns on repayment, and the accepter's is where it goes on liquidation.

use serde::{Deserialize, Serialize};

use crate::checks::{Check, Severity, Status};
use crate::dlc::verify::DlcVerification;
use crate::event_id::LoanTerms;

/// An amount paid to an address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressAmount {
    /// Destination address.
    pub address: Option<String>,
    /// Amount in satoshis.
    pub sats: Option<u64>,
}

/// A refund destination and the locktime after which it becomes spendable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefundTerms {
    /// Where the collateral returns if the oracle never attests.
    pub address: Option<String>,
    /// Unix timestamp or block height after which the refund is valid.
    pub locktime: Option<u32>,
}

/// One outcome the caller requires the contract to contain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedOutcome {
    /// The outcome label the oracle will attest to.
    pub label: String,
    /// Satoshis this outcome must pay the offerer (borrower).
    pub offerer_sats: Option<u64>,
    /// Satoshis this outcome must pay the accepter (lender).
    pub accepter_sats: Option<u64>,
}

/// EVM-side loan terms, carried through for the cross-chain flow.
///
/// These are **not verified** by this service — it verifies the Bitcoin and DLC side. They
/// are echoed into the report and the signed payload so the EVM side can bind an on-chain
/// action to the same terms that were presented here, and every check derived from them is
/// [`Severity::Informational`] and says so.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmTerms {
    /// Identifier of the position on the EVM side.
    pub position: Option<String>,
    /// Collateral the EVM side expects to be represented, in satoshis.
    pub collateral_sats: Option<u64>,
    /// Free-form note carried into the attestation.
    pub note: Option<String>,
}

/// Everything a caller can require of the contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedTerms {
    /// The lender's key in the 2-of-2 fund script (the accepter's funding key).
    pub lender_pubkey: Option<String>,
    /// The borrower's key in the 2-of-2 fund script (the offerer's funding key).
    pub borrower_pubkey: Option<String>,
    /// The oracle's x-only public key.
    pub oracle_pubkey: Option<String>,
    /// The oracle event id the contract must reference.
    pub oracle_event_id: Option<String>,
    /// Total collateral the contract must lock.
    pub total_collateral_sats: Option<u64>,
    /// Where and how much the borrower is repaid on settlement.
    #[serde(default)]
    pub repayment: AddressAmount,
    /// Where collateral goes when the position liquidates.
    #[serde(default)]
    pub liquidation: AddressAmount,
    /// The refund destination and locktime.
    #[serde(default)]
    pub refund: RefundTerms,
    /// Locktime on the CETs, i.e. loan maturity.
    pub cet_locktime: Option<u32>,
    /// Fee rate the contract must have been built at.
    pub fee_rate_per_vb: Option<u64>,
    /// Outcomes the contract must contain, with their payouts.
    #[serde(default)]
    pub outcomes: Vec<ExpectedOutcome>,
    /// Loan parameters the event id is derived from.
    #[serde(default)]
    pub loan_terms: LoanTerms,
    /// EVM-side terms, echoed rather than verified.
    #[serde(default)]
    pub evm: EvmTerms,
}

impl ExpectedTerms {
    /// A digest over the expectations, so another system can bind to exactly what was
    /// checked here rather than re-deriving the terms and hoping they agree.
    ///
    /// Computed over the canonical JSON encoding, which is stable for a given set of terms.
    ///
    /// # Errors
    ///
    /// Returns an error if the terms cannot be serialized.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        use bitcoin::hashes::{Hash, sha256};
        let canonical = qos_json::to_vec(self).map_err(serde::de::Error::custom)?;
        Ok(qos_hex::encode(
            &sha256::Hash::hash(&canonical).to_byte_array(),
        ))
    }

    /// Whether the caller stated any expectation at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Compare every supplied expectation against the decoded contract.
    #[must_use]
    pub fn compare(&self, dlc: &DlcVerification) -> Vec<Check> {
        // A caller who supplied nothing gets one clear reason rather than a dozen
        // `not_checked` rows, which is easy to skim past as though it were fine. Both
        // profiles exist to verify terms, so having none is a failure with a cause.
        if self.is_empty() {
            return vec![
                Check::new(
                    "expected_terms_supplied",
                    "Expected terms supplied",
                    Status::Fail,
                    Severity::Required,
                )
                .with_detail(
                    "no expected terms were supplied, so there was nothing to check the \
                     contract against. Cryptographic validity alone does not show that a \
                     contract encodes the agreed terms.",
                ),
            ];
        }

        let mut checks = vec![Check::compare(
            "lender_pubkey",
            "Lender funding key",
            normalize(self.lender_pubkey.as_deref()),
            normalize(dlc.accepter_funding_pubkey.as_deref()),
            Severity::Required,
        )];
        checks.push(Check::compare(
            "borrower_pubkey",
            "Borrower funding key",
            normalize(self.borrower_pubkey.as_deref()),
            normalize(dlc.offerer_funding_pubkey.as_deref()),
            Severity::Required,
        ));
        checks.push(Check::compare(
            "oracle_pubkey",
            "Oracle public key",
            normalize(self.oracle_pubkey.as_deref()),
            normalize(dlc.extracted_oracle_pubkey.as_deref()),
            Severity::Required,
        ));
        checks.push(Check::compare(
            "total_collateral",
            "Total collateral",
            self.total_collateral_sats,
            dlc.total_collateral,
            Severity::Required,
        ));
        checks.push(Check::compare(
            "repayment_address",
            "Repayment destination",
            self.repayment.address.clone(),
            dlc.offerer_payout_address.clone(),
            Severity::Required,
        ));
        checks.push(Check::compare(
            "liquidation_address",
            "Liquidation destination",
            self.liquidation.address.clone(),
            dlc.accepter_payout_address.clone(),
            Severity::Required,
        ));
        // The refund returns collateral to the borrower, so it lands at the same payout
        // address as repayment.
        checks.push(Check::compare(
            "refund_address",
            "Refund destination",
            self.refund.address.clone(),
            dlc.offerer_payout_address.clone(),
            Severity::Required,
        ));
        checks.push(Check::compare(
            "refund_locktime",
            "Refund locktime",
            self.refund.locktime,
            dlc.refund_locktime,
            Severity::Required,
        ));
        checks.push(Check::compare(
            "cet_locktime",
            "Maturity (CET locktime)",
            self.cet_locktime,
            dlc.cet_locktime,
            Severity::Required,
        ));
        checks.push(Check::compare(
            "fee_rate",
            "Fee rate (sat/vB)",
            self.fee_rate_per_vb,
            dlc.fee_rate_per_vb,
            Severity::Required,
        ));

        checks.extend(self.compare_repayment_amount(dlc));
        checks.extend(self.compare_outcomes(dlc));
        checks.extend(self.echo_evm_terms());

        checks
    }

    /// Check that some outcome pays the borrower the expected repayment amount.
    fn compare_repayment_amount(&self, dlc: &DlcVerification) -> Option<Check> {
        let expected = self.repayment.sats?;
        let matching: Vec<&str> = dlc
            .outcomes
            .iter()
            .filter(|outcome| outcome.offerer_sats == expected)
            .map(|outcome| outcome.label.as_str())
            .collect();

        let check = Check::new(
            "repayment_amount",
            "Repayment amount appears in the payouts",
            if matching.is_empty() {
                Status::Fail
            } else {
                Status::Pass
            },
            Severity::Required,
        )
        .with_values(
            format!("{expected} sat to the borrower"),
            if matching.is_empty() {
                "no outcome pays this amount".to_string()
            } else {
                format!("paid by [{}]", matching.join(", "))
            },
        );
        Some(check)
    }

    /// Check each required outcome exists with the expected payouts.
    fn compare_outcomes(&self, dlc: &DlcVerification) -> Vec<Check> {
        if self.outcomes.is_empty() {
            return vec![Check::new(
                "outcomes",
                "Required outcomes present",
                Status::NotChecked,
                Severity::Required,
            )];
        }

        let mut mismatches = Vec::new();
        for expected in &self.outcomes {
            match dlc
                .outcomes
                .iter()
                .find(|actual| actual.label == expected.label)
            {
                None => mismatches.push(format!("{} is absent", expected.label)),
                Some(actual) => {
                    if let Some(sats) = expected.offerer_sats
                        && actual.offerer_sats != sats
                    {
                        mismatches.push(format!(
                            "{} pays the borrower {} sat, expected {sats}",
                            expected.label, actual.offerer_sats
                        ));
                    }
                    if let Some(sats) = expected.accepter_sats
                        && actual.accepter_sats != sats
                    {
                        mismatches.push(format!(
                            "{} pays the lender {} sat, expected {sats}",
                            expected.label, actual.accepter_sats
                        ));
                    }
                }
            }
        }

        let labels: Vec<&str> = self
            .outcomes
            .iter()
            .map(|outcome| outcome.label.as_str())
            .collect();
        let check = Check::new(
            "outcomes",
            "Required outcomes present with expected payouts",
            if mismatches.is_empty() {
                Status::Pass
            } else {
                Status::Fail
            },
            Severity::Required,
        )
        .with_values(
            labels.join(", "),
            if mismatches.is_empty() {
                "all present with matching payouts".to_string()
            } else {
                mismatches.join("; ")
            },
        );
        vec![check]
    }

    /// Echo the EVM terms into the report, explicitly unverified.
    fn echo_evm_terms(&self) -> Vec<Check> {
        if self.evm == EvmTerms::default() {
            return Vec::new();
        }
        let mut described = Vec::new();
        if let Some(position) = &self.evm.position {
            described.push(format!("position={position}"));
        }
        if let Some(sats) = self.evm.collateral_sats {
            described.push(format!("collateralSats={sats}"));
        }
        if let Some(note) = &self.evm.note {
            described.push(format!("note={note}"));
        }

        vec![
            Check::new(
                "evm_terms_echoed",
                "EVM-side terms carried into the attestation",
                Status::NotVerifiable,
                Severity::Informational,
            )
            .with_values(described.join(", "), "not verified here".to_string())
            .with_detail(
                "this service verifies the Bitcoin and DLC side. These terms are attested \
                 as received so the EVM side can bind to the same values, and are not \
                 checked against anything.",
            ),
        ]
    }
}

/// Lowercase and strip an optional `0x` so hex comparisons are not defeated by formatting.
fn normalize(value: Option<&str>) -> Option<String> {
    value.map(|v| {
        v.trim()
            .trim_start_matches("0x")
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::dlc::verify::Outcome;

    fn decoded() -> DlcVerification {
        DlcVerification {
            structurally_valid: true,
            total_collateral: Some(10_000),
            accepter_funding_pubkey: Some("02aa".to_string()),
            offerer_funding_pubkey: Some("03bb".to_string()),
            extracted_oracle_pubkey: Some("8731".to_string()),
            offerer_payout_address: Some("tb1qborrower".to_string()),
            accepter_payout_address: Some("tb1qlender".to_string()),
            refund_locktime: Some(1_790_352_000),
            cet_locktime: Some(1_781_734_876),
            fee_rate_per_vb: Some(10),
            outcomes: vec![
                Outcome {
                    label: "repaid".to_string(),
                    offerer_sats: 10_000,
                    accepter_sats: 0,
                },
                Outcome {
                    label: "liquidated-by-price-threshold".to_string(),
                    offerer_sats: 0,
                    accepter_sats: 10_000,
                },
            ],
            ..DlcVerification::default()
        }
    }

    fn matching_terms() -> ExpectedTerms {
        ExpectedTerms {
            lender_pubkey: Some("02aa".to_string()),
            borrower_pubkey: Some("03bb".to_string()),
            oracle_pubkey: Some("8731".to_string()),
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

    fn status_of<'a>(checks: &'a [Check], id: &str) -> &'a Check {
        checks.iter().find(|c| c.id == id).expect("check present")
    }

    #[test]
    fn matching_terms_all_pass() {
        let checks = matching_terms().compare(&decoded());
        let failed: Vec<_> = checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .map(|c| c.id)
            .collect();
        assert!(failed.is_empty(), "unexpected failures: {failed:?}");
    }

    /// Supplying no terms is reported as a single, self-explaining failure rather than a
    /// wall of `not_checked` rows that is easy to skim past as though it were fine.
    #[test]
    fn empty_terms_fail_with_one_clear_reason() {
        let checks = ExpectedTerms::default().compare(&decoded());
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].id, "expected_terms_supplied");
        assert_eq!(checks[0].status, Status::Fail);
        assert_eq!(checks[0].severity, Severity::Required);
        assert!(
            checks[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("nothing to check")
        );
    }

    /// A partially-supplied set still checks what was given, so a typo in one field name
    /// cannot quietly disable the rest.
    #[test]
    fn partial_terms_still_check_what_was_supplied() {
        let terms = ExpectedTerms {
            total_collateral_sats: Some(10_000),
            ..ExpectedTerms::default()
        };
        let checks = terms.compare(&decoded());
        assert_eq!(status_of(&checks, "total_collateral").status, Status::Pass);
        assert_eq!(
            status_of(&checks, "lender_pubkey").status,
            Status::NotChecked
        );
    }

    #[test]
    fn a_wrong_lender_key_is_caught() {
        let mut terms = matching_terms();
        terms.lender_pubkey = Some("02ff".to_string());
        assert_eq!(
            status_of(&terms.compare(&decoded()), "lender_pubkey").status,
            Status::Fail
        );
    }

    #[test]
    fn key_comparison_ignores_prefix_and_case() {
        let mut terms = matching_terms();
        terms.lender_pubkey = Some("0x02AA".to_string());
        assert_eq!(
            status_of(&terms.compare(&decoded()), "lender_pubkey").status,
            Status::Pass
        );
    }

    #[test]
    fn a_wrong_liquidation_destination_is_caught() {
        let mut terms = matching_terms();
        terms.liquidation.address = Some("tb1qattacker".to_string());
        let checks = terms.compare(&decoded());
        let check = status_of(&checks, "liquidation_address");
        assert_eq!(check.status, Status::Fail);
        assert_eq!(check.actual.as_deref(), Some("tb1qlender"));
    }

    #[test]
    fn a_wrong_maturity_is_caught() {
        let mut terms = matching_terms();
        terms.cet_locktime = Some(1_781_734_877);
        assert_eq!(
            status_of(&terms.compare(&decoded()), "cet_locktime").status,
            Status::Fail
        );
    }

    #[test]
    fn a_repayment_amount_no_outcome_pays_is_caught() {
        let mut terms = matching_terms();
        terms.repayment.sats = Some(9_999);
        let checks = terms.compare(&decoded());
        let check = status_of(&checks, "repayment_amount");
        assert_eq!(check.status, Status::Fail);
        assert!(check.actual.as_deref().unwrap().contains("no outcome"));
    }

    #[test]
    fn a_missing_required_outcome_is_caught_and_named() {
        let mut terms = matching_terms();
        terms.outcomes.push(ExpectedOutcome {
            label: "liquidated-by-maturation-date".to_string(),
            offerer_sats: None,
            accepter_sats: None,
        });
        let checks = terms.compare(&decoded());
        let check = status_of(&checks, "outcomes");
        assert_eq!(check.status, Status::Fail);
        assert!(
            check
                .actual
                .as_deref()
                .unwrap()
                .contains("liquidated-by-maturation-date is absent")
        );
    }

    #[test]
    fn an_outcome_with_the_wrong_payout_is_caught() {
        let mut terms = matching_terms();
        terms.outcomes[0].offerer_sats = Some(5_000);
        let checks = terms.compare(&decoded());
        let check = status_of(&checks, "outcomes");
        assert_eq!(check.status, Status::Fail);
        assert!(check.actual.as_deref().unwrap().contains("expected 5000"));
    }

    #[test]
    fn evm_terms_are_echoed_but_never_gate() {
        let mut terms = matching_terms();
        terms.evm = EvmTerms {
            position: Some("morpho-1".to_string()),
            collateral_sats: Some(10_000),
            note: None,
        };
        let checks = terms.compare(&decoded());
        let check = status_of(&checks, "evm_terms_echoed");
        assert_eq!(check.severity, Severity::Informational);
        assert_eq!(check.status, Status::NotVerifiable);
        assert!(check.expected.as_deref().unwrap().contains("morpho-1"));
    }

    #[test]
    fn no_evm_check_appears_when_no_evm_terms_are_given() {
        let checks = matching_terms().compare(&decoded());
        assert!(checks.iter().all(|c| c.id != "evm_terms_echoed"));
    }

    #[test]
    fn the_digest_is_stable_and_term_sensitive() {
        let a = matching_terms().digest().unwrap();
        assert_eq!(a, matching_terms().digest().unwrap());

        let mut changed = matching_terms();
        changed.total_collateral_sats = Some(10_001);
        assert_ne!(a, changed.digest().unwrap());
    }
}
