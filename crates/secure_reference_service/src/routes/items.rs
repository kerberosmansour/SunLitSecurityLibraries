//! Item CRUD routes demonstrating `SecureJson`, validation, and authorization.

use axum::body::Body;
use axum::extract::{Path, State};
use http::{Response, StatusCode};
use secure_authz::action::Action;
use secure_authz::decision::Decision;
use secure_authz::enforcer::Authorizer;
use secure_authz::resolver::{DefaultSubjectResolver, SubjectResolver};
use secure_authz::resource::ResourceRef;
use secure_boundary::extract::SecureJson;
use security_core::identity::AuthenticatedIdentity;
use serde_json::json;
use uuid::Uuid;

use crate::dto::{CreateItemRequest, ItemResponse, UpdateItemRequest};
use crate::error::not_found_response;
use crate::state::AppState;

fn forbidden_json() -> Response<Body> {
    let body = json!({"error": {"code": "forbidden", "message": "Access denied."}}).to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::FORBIDDEN;
            r
        })
}

fn json_response(status: StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            let mut r = Response::new(Body::empty());
            *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            r
        })
}

/// `POST /items` — create a new item.
pub async fn create_item(
    State(state): State<AppState>,
    axum::Extension(identity): axum::Extension<AuthenticatedIdentity>,
    payload: SecureJson<CreateItemRequest>,
) -> Response<Body> {
    let req = payload.into_inner();
    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items");
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Create, &resource)
        .await;
    if matches!(decision, Decision::Deny { .. }) {
        return forbidden_json();
    }

    let id = Uuid::new_v4();
    let item = ItemResponse {
        id,
        name: req.name,
        description: req.description,
        owner_id: subject.actor_id.clone(),
        tenant_id: subject.tenant_id.clone(),
    };

    state.items.write().await.insert(id, item.clone());

    let body = serde_json::to_string(&item).unwrap_or_default();
    json_response(StatusCode::CREATED, body)
}

/// `GET /items/:id` — retrieve an item by ID.
pub async fn get_item(
    State(state): State<AppState>,
    axum::Extension(identity): axum::Extension<AuthenticatedIdentity>,
    Path(id): Path<Uuid>,
) -> Response<Body> {
    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items").with_id(id.to_string());
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Read, &resource)
        .await;
    if matches!(decision, Decision::Deny { .. }) {
        return forbidden_json();
    }

    let items = state.items.read().await;
    match items.get(&id) {
        Some(item) => {
            // Tenant isolation: subject tenant must match item tenant (if set)
            if let Some(item_tenant) = &item.tenant_id {
                if subject.tenant_id.as_deref() != Some(item_tenant.as_str()) {
                    return forbidden_json();
                }
            }
            let body = serde_json::to_string(item).unwrap_or_default();
            json_response(StatusCode::OK, body)
        }
        None => not_found_response(),
    }
}

/// `PUT /items/:id` — update an existing item.
pub async fn update_item(
    State(state): State<AppState>,
    axum::Extension(identity): axum::Extension<AuthenticatedIdentity>,
    Path(id): Path<Uuid>,
    payload: SecureJson<UpdateItemRequest>,
) -> Response<Body> {
    let req = payload.into_inner();
    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items").with_id(id.to_string());
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Write, &resource)
        .await;
    if matches!(decision, Decision::Deny { .. }) {
        return forbidden_json();
    }

    let mut items = state.items.write().await;
    match items.get_mut(&id) {
        Some(item) => {
            item.name = req.name;
            item.description = req.description;
            let body = serde_json::to_string(item).unwrap_or_default();
            json_response(StatusCode::OK, body)
        }
        None => not_found_response(),
    }
}

/// `DELETE /items/:id` — delete an item.
pub async fn delete_item(
    State(state): State<AppState>,
    axum::Extension(identity): axum::Extension<AuthenticatedIdentity>,
    Path(id): Path<Uuid>,
) -> Response<Body> {
    let subject = DefaultSubjectResolver::resolve(&identity);
    let resource = ResourceRef::new("items").with_id(id.to_string());
    let decision = state
        .authorizer
        .authorize(&subject, &Action::Delete, &resource)
        .await;
    if matches!(decision, Decision::Deny { .. }) {
        return forbidden_json();
    }

    let mut items = state.items.write().await;
    if items.remove(&id).is_some() {
        json_response(StatusCode::OK, r#"{"deleted":true}"#.to_string())
    } else {
        not_found_response()
    }
}
