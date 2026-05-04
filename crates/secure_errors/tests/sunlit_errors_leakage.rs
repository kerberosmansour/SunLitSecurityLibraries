//! BDD acceptance tests proving no internal details leak into public responses.
//!
//! Feature: No internal leakage
//! Every response body is scanned for forbidden strings.

use secure_errors::{http::into_response_parts, kind::AppError, report::ErrorReport};

// Strings that must never appear in a public response body.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "WHERE",
    "FROM",
    "db-prod-03",
    "at src/",
    "frame",
    ".rs:",
];

fn assert_no_leakage(body: &serde_json::Value) {
    let body_str = body.to_string();
    for pattern in FORBIDDEN_PATTERNS {
        assert!(
            !body_str.contains(pattern),
            "Response body must not contain '{pattern}': {body_str}"
        );
    }
}

// ---------------------------------------------------------------------------
// Scenario: No SQL in response
// ---------------------------------------------------------------------------
#[test]
fn no_sql_in_response() {
    // The dep name is a SQL snippet — it must not leak.
    let err = AppError::Dependency {
        dep: "SELECT * FROM users WHERE id=1",
    };
    let (_status, public_err) = into_response_parts(&err);
    let body = serde_json::to_value(&public_err).unwrap();
    assert_no_leakage(&body);
}

// ---------------------------------------------------------------------------
// Scenario: No hostname in response
// ---------------------------------------------------------------------------
#[test]
fn no_hostname_in_response() {
    let err = AppError::Dependency {
        dep: "db-prod-03.internal",
    };
    let (_status, public_err) = into_response_parts(&err);
    let body = serde_json::to_value(&public_err).unwrap();
    let body_str = body.to_string();
    assert!(
        !body_str.contains("db-prod-03"),
        "hostname must not appear in response: {body_str}"
    );
}

// ---------------------------------------------------------------------------
// Scenario: No stack trace in response
// ---------------------------------------------------------------------------
#[test]
fn no_stack_trace_in_response() {
    let err = AppError::Internal;
    let (_status, public_err) = into_response_parts(&err);
    let body = serde_json::to_value(&public_err).unwrap();
    let body_str = body.to_string();
    assert!(!body_str.contains("at src/"), "stack trace must not leak");
    assert!(!body_str.contains(".rs:"), "file paths must not leak");
}

// ---------------------------------------------------------------------------
// Scenario: No authn differential — "user not found" vs "wrong password" both 401
// ---------------------------------------------------------------------------
#[test]
fn no_authn_differential() {
    let err_user_not_found = AppError::Forbidden {
        policy: "user_not_found",
    };
    let err_wrong_password = AppError::Forbidden {
        policy: "wrong_password",
    };

    let (status1, body1) = into_response_parts(&err_user_not_found);
    let (status2, body2) = into_response_parts(&err_wrong_password);

    assert_eq!(
        status1, status2,
        "both authn failures must have same status"
    );
    let json1 = serde_json::to_value(&body1).unwrap();
    let json2 = serde_json::to_value(&body2).unwrap();
    assert_eq!(
        json1["code"], json2["code"],
        "both authn failures must have identical code field"
    );
    // Neither must contain internal policy names
    assert!(!json1.to_string().contains("user_not_found"));
    assert!(!json2.to_string().contains("wrong_password"));
}

// ---------------------------------------------------------------------------
// Scenario: Internal report retains details
// ---------------------------------------------------------------------------
#[test]
fn internal_report_retains_details() {
    let sql_text = "SELECT * FROM accounts WHERE id = 99";
    let hostname = "db-prod-03.internal";
    let report = ErrorReport::builder()
        .component("auth-service")
        .cause(format!("query failed: {sql_text} on host {hostname}"))
        .build();

    let report_str = format!("{report:?}");
    assert!(
        report_str.contains(sql_text) || report.cause().contains(sql_text),
        "ErrorReport must preserve SQL cause text"
    );
    assert!(
        report_str.contains(hostname) || report.cause().contains(hostname),
        "ErrorReport must preserve hostname"
    );
}
