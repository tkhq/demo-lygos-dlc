//! The structured report a caller gates on.
//!
//! Every question the service answers becomes a [`Check`] rather than a loose boolean, for
//! two reasons. A caller needs to know *which* check failed, not just that something did;
//! and different callers gate on different things, so whether a check is blocking is a
//! property of the request rather than of the check itself.
//!
//! The distinction that matters most here is between [`Status::Fail`],
//! [`Status::NotChecked`], and [`Status::NotVerifiable`]. Collapsing them into a boolean is
//! how a gate ends up passing something it never actually verified: an expectation the
//! caller never supplied looks identical to one that was satisfied. So a required check
//! only passes on [`Status::Pass`] — everything else blocks.

use serde::Serialize;

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The check ran and the value matched.
    Pass,
    /// The check ran and the value did not match.
    Fail,
    /// The caller supplied no expectation, so there was nothing to compare against.
    NotChecked,
    /// The check cannot be answered by this service. Distinct from a failure: it means
    /// "no verdict", and a required check in this state blocks rather than passes.
    NotVerifiable,
}

impl Status {
    /// Whether this status satisfies a required check.
    #[must_use]
    pub fn is_satisfied(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Whether a check gates the overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// A non-passing result blocks the verdict.
    Required,
    /// Reported for the reader's benefit; never blocks.
    Informational,
}

/// One question, its answer, and the values behind it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    /// Stable machine-readable identifier.
    pub id: &'static str,
    /// Human-readable label for a report.
    pub label: &'static str,
    /// What the check concluded.
    pub status: Status,
    /// Whether the conclusion gates the verdict.
    pub severity: Severity,
    /// What the caller said to expect, when they said anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// What the contract or chain actually says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    /// Extra context, especially the reason for a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Check {
    /// A check with no expected/actual pair, e.g. a signature that either verified or did not.
    #[must_use]
    pub fn new(id: &'static str, label: &'static str, status: Status, severity: Severity) -> Self {
        Self {
            id,
            label,
            status,
            severity,
            expected: None,
            actual: None,
            detail: None,
        }
    }

    /// Attach the values that were compared, so a report can show the mismatch.
    #[must_use]
    pub fn with_values(mut self, expected: impl Into<String>, actual: impl Into<String>) -> Self {
        self.expected = Some(expected.into());
        self.actual = Some(actual.into());
        self
    }

    /// Attach context, typically why a check failed or could not be answered.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Build a check from a boolean that may not have been evaluated.
    ///
    /// `None` becomes [`Status::NotChecked`], which is why a caller who supplies no
    /// expectation never accidentally gets a pass.
    #[must_use]
    pub fn from_option(
        id: &'static str,
        label: &'static str,
        value: Option<bool>,
        severity: Severity,
    ) -> Self {
        let status = match value {
            Some(true) => Status::Pass,
            Some(false) => Status::Fail,
            None => Status::NotChecked,
        };
        Self::new(id, label, status, severity)
    }

    /// Compare an expectation against an actual value, when the caller supplied one.
    #[must_use]
    pub fn compare<T: PartialEq + std::fmt::Display>(
        id: &'static str,
        label: &'static str,
        expected: Option<T>,
        actual: Option<T>,
        severity: Severity,
    ) -> Self {
        match (expected, actual) {
            (None, _) => Self::new(id, label, Status::NotChecked, severity),
            (Some(expected), None) => Self::new(id, label, Status::Fail, severity)
                .with_values(expected.to_string(), "not present".to_string())
                .with_detail("the contract does not carry this value"),
            (Some(expected), Some(actual)) => {
                let status = if expected == actual {
                    Status::Pass
                } else {
                    Status::Fail
                };
                Self::new(id, label, status, severity)
                    .with_values(expected.to_string(), actual.to_string())
            }
        }
    }
}

/// A whole report, and the verdict derived from it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Every check that was considered, in the order they were run.
    pub checks: Vec<Check>,
}

impl Report {
    /// Build a report from its checks.
    #[must_use]
    pub fn new(checks: Vec<Check>) -> Self {
        Self { checks }
    }

    /// Whether every required check passed.
    ///
    /// A required check that is `not_checked` or `not_verifiable` blocks, because neither
    /// means "satisfied".
    #[must_use]
    pub fn all_required_satisfied(&self) -> bool {
        self.checks
            .iter()
            .filter(|check| check.severity == Severity::Required)
            .all(|check| check.status.is_satisfied())
    }

    /// The ids of required checks that did not pass, for a caller that wants to report why.
    #[must_use]
    pub fn blocking(&self) -> Vec<&'static str> {
        self.checks
            .iter()
            .filter(|check| check.severity == Severity::Required && !check.status.is_satisfied())
            .map(|check| check.id)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_expectation_is_not_a_pass() {
        let check = Check::compare::<u64>("x", "X", None, Some(5), Severity::Required);
        assert_eq!(check.status, Status::NotChecked);
        assert!(!check.status.is_satisfied());
    }

    #[test]
    fn a_matching_expectation_passes_and_records_both_values() {
        let check = Check::compare("x", "X", Some(5_u64), Some(5), Severity::Required);
        assert_eq!(check.status, Status::Pass);
        assert_eq!(check.expected.as_deref(), Some("5"));
        assert_eq!(check.actual.as_deref(), Some("5"));
    }

    #[test]
    fn a_mismatch_fails_and_shows_what_differed() {
        let check = Check::compare("x", "X", Some(5_u64), Some(6), Severity::Required);
        assert_eq!(check.status, Status::Fail);
        assert_eq!(check.expected.as_deref(), Some("5"));
        assert_eq!(check.actual.as_deref(), Some("6"));
    }

    #[test]
    fn expecting_a_value_the_contract_lacks_is_a_failure() {
        let check = Check::compare("x", "X", Some(5_u64), None, Severity::Required);
        assert_eq!(check.status, Status::Fail);
        assert_eq!(check.actual.as_deref(), Some("not present"));
    }

    #[test]
    fn from_option_maps_an_unevaluated_check_to_not_checked() {
        assert_eq!(
            Check::from_option("x", "X", None, Severity::Required).status,
            Status::NotChecked
        );
        assert_eq!(
            Check::from_option("x", "X", Some(true), Severity::Required).status,
            Status::Pass
        );
        assert_eq!(
            Check::from_option("x", "X", Some(false), Severity::Required).status,
            Status::Fail
        );
    }

    #[test]
    fn a_required_check_that_could_not_be_answered_blocks_the_verdict() {
        let report = Report::new(vec![Check::new(
            "event_id_recomputed",
            "Event id recomputed from terms",
            Status::NotVerifiable,
            Severity::Required,
        )]);
        assert!(
            !report.all_required_satisfied(),
            "no verdict must not be treated as a passing verdict"
        );
        assert_eq!(report.blocking(), vec!["event_id_recomputed"]);
    }

    #[test]
    fn informational_checks_never_block() {
        let report = Report::new(vec![
            Check::new("a", "A", Status::Pass, Severity::Required),
            Check::new("b", "B", Status::Fail, Severity::Informational),
            Check::new("c", "C", Status::NotVerifiable, Severity::Informational),
        ]);
        assert!(report.all_required_satisfied());
        assert!(report.blocking().is_empty());
    }

    #[test]
    fn blocking_lists_every_unsatisfied_required_check() {
        let report = Report::new(vec![
            Check::new("a", "A", Status::Fail, Severity::Required),
            Check::new("b", "B", Status::Pass, Severity::Required),
            Check::new("c", "C", Status::NotChecked, Severity::Required),
        ]);
        assert_eq!(report.blocking(), vec!["a", "c"]);
    }
}
