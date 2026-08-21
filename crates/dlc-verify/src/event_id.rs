//! Checking the oracle event id a contract commits to.
//!
//! The oracle event id matters because it is what ties the DLC to a *specific* loan. The
//! adaptor signatures commit to the oracle's announced nonce for one event, so if the event
//! id is not the one the lender agreed to, the contract settles on something else entirely
//! — no matter how cryptographically sound it looks.
//!
//! There are two ways to check it, and this module deliberately keeps them separate because
//! only one of them is real today.
//!
//! # Exact match
//!
//! The caller supplies the event id they were told to expect and we confirm the DLC encodes
//! exactly that. This is a genuine check and is what a lender can rely on now.
//!
//! # Recomputation — placeholder
//!
//! The stronger check is to *derive* the event id from the loan terms and confirm the
//! contract's id matches, which proves the DLC encodes the terms the lender thinks it does
//! without having to trust any id handed to them.
//!
//! Lygos's real derivation is not implemented here, and is not guessed at. Their event ids
//! are `loan-matured-` followed by a 32-byte hash, and that hash is not derived from
//! anything inside the DLC (the temporary contract id and its variants were checked), so it
//! is computed over off-chain loan parameters whose fields, ordering, and encoding are not
//! published. Three sample contracts are not enough to recover it.
//!
//! So [`derive_event_id`] implements a **documented placeholder** and
//! [`recompute_check`] reports [`Status::NotVerifiable`] — never a pass, and never a
//! failure that would look like the contract's fault. The placeholder is still worth
//! having: it demonstrates the mechanic, and because the derivation is sensitive to every
//! term, changing any one of them visibly changes the derived id, which is exactly why the
//! real check is valuable.
//!
//! To make this a real check, replace the body of [`derive_event_id`] with Lygos's
//! derivation and change [`recompute_check`] to compare for real. Nothing else needs to
//! move.

use serde::{Deserialize, Serialize};

use crate::checks::{Check, Severity, Status};

/// Marker returned alongside a recomputed id so no caller mistakes it for the real rule.
pub const PLACEHOLDER_DERIVATION: &str = "DEMO_PLACEHOLDER";

/// Prefix Lygos uses on loan maturity event ids.
const EVENT_ID_PREFIX: &str = "loan-matured-";

/// The loan parameters an event id is derived from.
///
/// Field names follow the loan terms a lender would already have on paper. Every field is
/// optional so a caller can supply what they have; the derivation covers whatever is
/// present, and the response says which fields it used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoanTerms {
    /// Lygos's identifier for the loan.
    pub loan_id: Option<String>,
    /// Principal advanced, in the loan's unit of account.
    pub principal: Option<String>,
    /// Amount required to repay.
    pub repayment_amount: Option<String>,
    /// Maturity as a unix timestamp.
    pub maturity_timestamp: Option<u64>,
    /// Collateral locked, in satoshis.
    pub collateral_sats: Option<u64>,
    /// Price at which the position liquidates.
    pub liquidation_price: Option<String>,
}

impl LoanTerms {
    /// Whether the caller supplied anything to derive from.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The fields that were supplied, in derivation order.
    #[must_use]
    pub fn supplied_fields(&self) -> Vec<&'static str> {
        let mut fields = Vec::new();
        if self.loan_id.is_some() {
            fields.push("loanId");
        }
        if self.principal.is_some() {
            fields.push("principal");
        }
        if self.repayment_amount.is_some() {
            fields.push("repaymentAmount");
        }
        if self.maturity_timestamp.is_some() {
            fields.push("maturityTimestamp");
        }
        if self.collateral_sats.is_some() {
            fields.push("collateralSats");
        }
        if self.liquidation_price.is_some() {
            fields.push("liquidationPrice");
        }
        fields
    }
}

/// Derive an event id from loan terms.
///
/// **This is a placeholder, not Lygos's derivation.** See the module documentation. It
/// hashes a canonical `key=value` encoding of the supplied terms, which gives the property
/// the demonstration needs — every term affects the result — without pretending to match
/// any real contract.
#[must_use]
pub fn derive_event_id(terms: &LoanTerms) -> String {
    use bitcoin::hashes::{Hash, sha256};

    // Fixed field order and explicit separators, so the same terms always produce the same
    // id and no two distinct term sets can collide by concatenation.
    let mut preimage = String::new();
    let mut push = |key: &str, value: &str| {
        preimage.push_str(key);
        preimage.push('=');
        preimage.push_str(value);
        preimage.push(';');
    };
    if let Some(v) = &terms.loan_id {
        push("loanId", v);
    }
    if let Some(v) = &terms.principal {
        push("principal", v);
    }
    if let Some(v) = &terms.repayment_amount {
        push("repaymentAmount", v);
    }
    if let Some(v) = terms.maturity_timestamp {
        push("maturityTimestamp", &v.to_string());
    }
    if let Some(v) = terms.collateral_sats {
        push("collateralSats", &v.to_string());
    }
    if let Some(v) = &terms.liquidation_price {
        push("liquidationPrice", v);
    }

    let digest = sha256::Hash::hash(preimage.as_bytes());
    format!(
        "{EVENT_ID_PREFIX}{}",
        qos_hex::encode(&digest.to_byte_array())
    )
}

/// Confirm the contract's event id is the one the caller expected.
///
/// This is a real check: an exact comparison against the id in the DLC.
#[must_use]
pub fn exact_match_check(expected: Option<&str>, actual: Option<&str>) -> Check {
    Check::compare(
        "oracle_event_id",
        "Oracle event id matches expected",
        expected.map(str::to_string),
        actual.map(str::to_string),
        Severity::Required,
    )
}

/// Report what the placeholder derivation produces, without claiming a verdict.
///
/// Always [`Status::NotVerifiable`] when terms were supplied, because the derivation is not
/// Lygos's. Reporting a mismatch as a failure would blame the contract for our missing
/// rule; reporting a match as a pass would be worse.
#[must_use]
pub fn recompute_check(terms: &LoanTerms, actual_event_id: Option<&str>) -> Check {
    if terms.is_empty() {
        return Check::new(
            "oracle_event_id_recomputed",
            "Oracle event id recomputed from loan terms",
            Status::NotChecked,
            Severity::Informational,
        )
        .with_detail("no loan terms were supplied to derive an event id from");
    }

    let derived = derive_event_id(terms);
    Check::new(
        "oracle_event_id_recomputed",
        "Oracle event id recomputed from loan terms",
        Status::NotVerifiable,
        Severity::Informational,
    )
    .with_values(
        derived,
        actual_event_id.unwrap_or("not present").to_string(),
    )
    .with_detail(format!(
        "derivation={PLACEHOLDER_DERIVATION}: this demonstrates the mechanic but is not \
         Lygos's rule, so no verdict is claimed. Derived from [{}]. Substituting the real \
         derivation makes this a hard pass/fail.",
        terms.supplied_fields().join(", ")
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn terms() -> LoanTerms {
        LoanTerms {
            loan_id: Some("loan-1".to_string()),
            principal: Some("50000".to_string()),
            repayment_amount: Some("52500".to_string()),
            maturity_timestamp: Some(1_790_352_000),
            collateral_sats: Some(10_000),
            liquidation_price: Some("45000".to_string()),
        }
    }

    #[test]
    fn derivation_is_deterministic() {
        assert_eq!(derive_event_id(&terms()), derive_event_id(&terms()));
    }

    #[test]
    fn derivation_has_the_expected_shape() {
        let id = derive_event_id(&terms());
        assert!(id.starts_with(EVENT_ID_PREFIX));
        assert_eq!(id.len(), EVENT_ID_PREFIX.len() + 64);
    }

    /// The whole point of the demonstration: any change to any term changes the id.
    #[test]
    fn every_term_affects_the_derived_id() {
        let baseline = derive_event_id(&terms());

        let mut changed = terms();
        changed.repayment_amount = Some("52501".to_string());
        assert_ne!(derive_event_id(&changed), baseline);

        let mut changed = terms();
        changed.maturity_timestamp = Some(1_790_352_001);
        assert_ne!(derive_event_id(&changed), baseline);

        let mut changed = terms();
        changed.collateral_sats = Some(10_001);
        assert_ne!(derive_event_id(&changed), baseline);

        let mut changed = terms();
        changed.liquidation_price = Some("45001".to_string());
        assert_ne!(derive_event_id(&changed), baseline);
    }

    /// Delimiters must prevent two different term sets encoding to the same preimage.
    #[test]
    fn adjacent_fields_cannot_be_confused() {
        let a = LoanTerms {
            loan_id: Some("ab".to_string()),
            principal: Some("c".to_string()),
            ..LoanTerms::default()
        };
        let b = LoanTerms {
            loan_id: Some("a".to_string()),
            principal: Some("bc".to_string()),
            ..LoanTerms::default()
        };
        assert_ne!(derive_event_id(&a), derive_event_id(&b));
    }

    #[test]
    fn recomputation_never_claims_a_verdict() {
        let check = recompute_check(&terms(), Some("loan-matured-abc"));
        assert_eq!(check.status, Status::NotVerifiable);
        assert_eq!(check.severity, Severity::Informational);
        assert!(check.detail.unwrap().contains(PLACEHOLDER_DERIVATION));
    }

    #[test]
    fn recomputation_without_terms_is_not_checked() {
        let check = recompute_check(&LoanTerms::default(), Some("loan-matured-abc"));
        assert_eq!(check.status, Status::NotChecked);
    }

    #[test]
    fn exact_match_is_a_real_check() {
        assert_eq!(
            exact_match_check(Some("loan-matured-aa"), Some("loan-matured-aa")).status,
            Status::Pass
        );
        assert_eq!(
            exact_match_check(Some("loan-matured-aa"), Some("loan-matured-bb")).status,
            Status::Fail
        );
        assert_eq!(
            exact_match_check(None, Some("loan-matured-aa")).status,
            Status::NotChecked
        );
    }

    #[test]
    fn supplied_fields_reports_only_what_was_given() {
        assert!(LoanTerms::default().supplied_fields().is_empty());
        let partial = LoanTerms {
            loan_id: Some("x".to_string()),
            collateral_sats: Some(1),
            ..LoanTerms::default()
        };
        assert_eq!(partial.supplied_fields(), vec!["loanId", "collateralSats"]);
    }
}
