use security_core::variant_analysis::{
    VariantAnalysisFinding, VariantAnalysisReport, VariantDisposition,
};

#[test]
fn builds_typed_variant_analysis_report() {
    let finding = VariantAnalysisFinding::new(
        "prompt-injection-boundary",
        "rg \"render_untrusted\" crates skills",
        vec!["crates/secure_boundary".to_string(), "skills".to_string()],
        VariantDisposition::NeedsHumanReview,
    )
    .expect("valid finding")
    .with_evidence("secure_boundary::prompt_boundary")
    .with_notes("Manual review required for generated prompt templates.");

    let mut report = VariantAnalysisReport::new("issue #49").expect("valid source");
    report.push_finding(finding);
    report.push_coverage_note("Search covered first-party Rust crates and skill prompts.");

    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].disposition,
        VariantDisposition::NeedsHumanReview
    );
    assert_eq!(report.coverage_notes.len(), 1);
}

#[test]
fn rejects_blank_core_fields() {
    assert!(VariantAnalysisReport::new(" ").is_err());
    assert!(VariantAnalysisFinding::new(
        "",
        "rg path",
        vec!["src".to_string()],
        VariantDisposition::NotFound
    )
    .is_err());
    assert!(VariantAnalysisFinding::new(
        "path-traversal",
        " ",
        vec!["src".to_string()],
        VariantDisposition::NotFound
    )
    .is_err());
    assert!(VariantAnalysisFinding::new(
        "path-traversal",
        "rg SafePath",
        vec![],
        VariantDisposition::NotFound
    )
    .is_err());
}

#[test]
fn serializes_disposition_as_kebab_case() {
    let serialized = serde_json::to_string(&VariantDisposition::NeedsHumanReview)
        .expect("disposition should serialize");

    assert_eq!(serialized, "\"needs-human-review\"");
}
