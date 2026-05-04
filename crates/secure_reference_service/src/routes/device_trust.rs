//! Device-trust demonstration routes.

use axum::body::Body;
use axum::Extension;
use http::{Response, StatusCode};
use secure_authz::action::Action;
use secure_authz::decision::Decision;
use secure_authz::device_trust::{
    DeviceTrustContext, DeviceTrustRequirement, DeviceTrustRoutePolicy,
};
use secure_authz::resource::ResourceRef;
use serde_json::json;

/// `GET /device-trust/hardware` - requires hardware-backed trust.
pub async fn hardware_route(context: Option<Extension<DeviceTrustContext>>) -> Response<Body> {
    device_trust_response(
        DeviceTrustRoutePolicy::new(
            Action::Admin,
            ResourceRef::new("device-trust-hardware"),
            DeviceTrustRequirement::hardware_backed(),
        ),
        context.map(|Extension(context)| context),
    )
}

/// `GET /device-trust/ci` - allows software-bound trust only in test profile.
pub async fn ci_route(context: Option<Extension<DeviceTrustContext>>) -> Response<Body> {
    device_trust_response(
        DeviceTrustRoutePolicy::new(
            Action::Read,
            ResourceRef::new("device-trust-ci"),
            DeviceTrustRequirement::software_bound_test_only(),
        ),
        context.map(|Extension(context)| context),
    )
}

fn device_trust_response(
    policy: DeviceTrustRoutePolicy,
    context: Option<DeviceTrustContext>,
) -> Response<Body> {
    match policy.evaluate(context.as_ref()) {
        Decision::Allow { obligations } => json_response(
            StatusCode::OK,
            json!({"ok": true, "obligations": obligations}).to_string(),
        ),
        Decision::Deny { reason } => json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": {
                    "code": "forbidden",
                    "reason": format!("{reason:?}")
                }
            })
            .to_string(),
        ),
        _ => json_response(
            StatusCode::FORBIDDEN,
            json!({
                "error": {
                    "code": "forbidden",
                    "reason": "unknown-device-trust-decision"
                }
            })
            .to_string(),
        ),
    }
}

fn json_response(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        })
}
