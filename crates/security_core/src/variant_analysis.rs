//! Typed records for variant-analysis follow-up after a security finding.
//!
//! A variant-analysis report captures what related bug classes were searched,
//! where the search ran, and whether related findings were discovered. The
//! shape is intentionally small so it can be serialized into issue comments,
//! security review artifacts, or SLO evidence logs without free-form parsing.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Disposition for one variant-analysis search.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VariantDisposition {
    /// A related variant was found.
    Found,
    /// No related variant was found in the searched locations.
    NotFound,
    /// The bug class does not apply to the searched locations.
    NotApplicable,
    /// A human reviewer must inspect the candidate manually.
    NeedsHumanReview,
}

/// One variant-analysis finding or search result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantAnalysisFinding {
    /// Stable bug-class label, such as `prompt-injection-boundary`.
    pub bug_class: String,
    /// The query, rule, or manual search that was executed.
    pub query: String,
    /// Files, crates, services, or packages included in the search.
    pub searched_locations: Vec<String>,
    /// Outcome of the search.
    pub disposition: VariantDisposition,
    /// Evidence references, such as test names, rule IDs, or code locations.
    pub evidence: Vec<String>,
    /// Optional human-readable reviewer notes.
    pub notes: Option<String>,
}

impl VariantAnalysisFinding {
    /// Creates a validated variant-analysis finding.
    ///
    /// # Errors
    ///
    /// Returns [`VariantAnalysisError`] when the bug class, query, or searched
    /// locations are empty.
    pub fn new(
        bug_class: impl Into<String>,
        query: impl Into<String>,
        searched_locations: Vec<String>,
        disposition: VariantDisposition,
    ) -> Result<Self, VariantAnalysisError> {
        let bug_class = bug_class.into();
        if bug_class.trim().is_empty() {
            return Err(VariantAnalysisError::EmptyBugClass);
        }

        let query = query.into();
        if query.trim().is_empty() {
            return Err(VariantAnalysisError::EmptyQuery);
        }

        if searched_locations.is_empty()
            || searched_locations
                .iter()
                .any(|location| location.trim().is_empty())
        {
            return Err(VariantAnalysisError::EmptySearchedLocations);
        }

        Ok(Self {
            bug_class,
            query,
            searched_locations,
            disposition,
            evidence: Vec::new(),
            notes: None,
        })
    }

    /// Adds one evidence reference and returns the updated finding.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    /// Adds reviewer notes and returns the updated finding.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// A complete variant-analysis report for one source finding or change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariantAnalysisReport {
    /// Source finding, issue, PR, or evidence row that triggered analysis.
    pub source: String,
    /// Variant-analysis findings.
    pub findings: Vec<VariantAnalysisFinding>,
    /// Notes describing coverage boundaries and residual blind spots.
    pub coverage_notes: Vec<String>,
}

impl VariantAnalysisReport {
    /// Creates an empty validated report.
    ///
    /// # Errors
    ///
    /// Returns [`VariantAnalysisError::EmptySource`] when `source` is blank.
    pub fn new(source: impl Into<String>) -> Result<Self, VariantAnalysisError> {
        let source = source.into();
        if source.trim().is_empty() {
            return Err(VariantAnalysisError::EmptySource);
        }

        Ok(Self {
            source,
            findings: Vec::new(),
            coverage_notes: Vec::new(),
        })
    }

    /// Appends a finding to the report.
    pub fn push_finding(&mut self, finding: VariantAnalysisFinding) {
        self.findings.push(finding);
    }

    /// Appends a coverage note to the report.
    pub fn push_coverage_note(&mut self, note: impl Into<String>) {
        self.coverage_notes.push(note.into());
    }
}

/// Validation errors for typed variant-analysis records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VariantAnalysisError {
    /// The source field is empty.
    EmptySource,
    /// The bug class field is empty.
    EmptyBugClass,
    /// The query field is empty.
    EmptyQuery,
    /// No searched locations were provided, or at least one location is blank.
    EmptySearchedLocations,
}

impl fmt::Display for VariantAnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySource => f.write_str("variant-analysis source is empty"),
            Self::EmptyBugClass => f.write_str("variant-analysis bug class is empty"),
            Self::EmptyQuery => f.write_str("variant-analysis query is empty"),
            Self::EmptySearchedLocations => {
                f.write_str("variant-analysis searched locations are empty")
            }
        }
    }
}

impl std::error::Error for VariantAnalysisError {}
