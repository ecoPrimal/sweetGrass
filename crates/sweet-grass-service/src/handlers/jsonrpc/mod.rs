// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! JSON-RPC 2.0 handler.
//!
//! Implements the wateringHole `UNIVERSAL_IPC_STANDARD_V3` required protocol.
//! Method names follow the `{domain}.{operation}` semantic naming standard
//! from `SEMANTIC_METHOD_NAMING_STANDARD.md`.
//!
//! ## Domain Mapping
//!
//! | Domain | Operations |
//! |--------|------------|
//! | `braid` | `create`, `get`, `get_by_hash`, `query`, `list`, `delete`, `commit`, `batch_create`, `batch_commit` |
//! | `anchoring` | `anchor`, `verify` |
//! | `convergence` | `check`, `batch_check` (provenance chain verification) |
//! | `provenance` | `graph`, `export_provo`, `export_graph_provo` |
//! | `attribution` | `chain`, `calculate_rewards`, `top_contributors`, `witness` |
//! | `compression` | `compress_session`, `create_meta_braid` |
//! | `contribution` | `record`, `record_session`, `record_dehydration` |
//! | `pipeline` | `attribute` (provenance trio coordination) |
//! | `health` | `check`, `liveness`, `readiness` |
//! | `identity` | `get` (biomeOS Neural API: primal name + version) |
//! | `composition` | `tower_health`, `node_health`, `nest_health`, `nucleus_health` |
//! | `rootpulse` | `attribute`, `query` (rootPulse graph step handlers) |
//! | `trust` | `event` (cross-gate trust braid weaving) |
//! | `lifecycle` | `status` (public surface — running state, version, gate mode) |
//! | `capabilities` | `list` (canonical per wateringHole v2.1) |
//! | `capability` | `list` (alias), `call` (Neural API routing envelope) |
//! | `tools` | `list`, `call` (MCP exposure for Squirrel AI coordination) |
//! | `auth` | `mode`, `check`, `peer_info` (JH-0 method gate introspection) |
//!
//! ## Wire-Name Aliases (GAP-36 Reconciliation)
//!
//! Downstream springs and integration guides reference method names that
//! diverge from the canonical wire. The dispatch table resolves these
//! aliases transparently — see `ALIASES` table for the full mapping.

mod anchoring;
mod attribution;
mod braid;
mod braid_batch;
mod braid_verify;
mod capability;
mod composition;
mod compression;
mod contribution;
mod convergence;
mod health;
mod lifecycle;
mod provenance;
mod registry;
mod rootpulse;
mod trust;

use std::future::Future;
use std::pin::Pin;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tracing::instrument;

use crate::state::AppState;

use registry::{METHODS, find_handler, find_handler_normalized, normalize_method, resolve_alias};

/// JSON-RPC 2.0 error codes per specification.
pub(crate) mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    /// Resource not found (braid, anchor, etc.).
    pub const NOT_FOUND: i32 = -32004;
    /// Caller lacks required capability token (JH-0 method gate).
    /// Issued by `method_gate::MethodGate`; re-exported here for test assertions.
    #[cfg(test)]
    pub const PERMISSION_DENIED: i32 = -32001;
    /// Caller identity could not be established.
    #[cfg(test)]
    pub const UNAUTHORIZED: i32 = -32000;
}

/// JSON-RPC 2.0 types — canonical forms from `cellmembrane-types`.
pub use cellmembrane_types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

/// Extension methods for `JsonRpcResponse` beyond the canonical API.
pub(crate) trait JsonRpcResponseExt {
    /// Create an error response with optional structured data.
    fn error_with_data(
        id: serde_json::Value,
        code: i32,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> JsonRpcResponse;
}

impl JsonRpcResponseExt for JsonRpcResponse {
    fn error_with_data(
        id: serde_json::Value,
        code: i32,
        message: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
            id,
        }
    }
}

// ==================== Dispatch Table ====================

/// A JSON-RPC dispatch error with structured code and message.
#[derive(Debug)]
pub(crate) struct DispatchError {
    pub code: i32,
    pub message: String,
    pub source_detail: Option<String>,
}

impl From<(i32, String)> for DispatchError {
    fn from((code, message): (i32, String)) -> Self {
        Self {
            code,
            message,
            source_detail: None,
        }
    }
}

pub(crate) type DispatchResult = Result<serde_json::Value, DispatchError>;
pub(super) type DispatchFn =
    for<'a> fn(
        &'a AppState,
        serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = DispatchResult> + Send + 'a>>;

/// Outcome of a JSON-RPC dispatch, separating protocol errors from
/// application-level errors (aligned with rhizoCrypt `DispatchOutcome`).
///
/// Protocol errors (parse, invalid version, method not found) are
/// handled before the handler runs. Application errors come from
/// the handler itself and carry domain-specific codes.
#[derive(Debug)]
pub(crate) enum DispatchOutcome {
    /// Handler executed and returned a JSON result.
    Success(serde_json::Value),
    /// Protocol violation — the request never reached a handler.
    ProtocolError { code: i32, message: String },
    /// Handler ran but returned a domain error.
    ApplicationError {
        code: i32,
        message: String,
        source_detail: Option<String>,
    },
}

impl DispatchOutcome {
    /// Whether this outcome represents a protocol-level failure (retriable
    /// at the transport layer, not the application layer).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_protocol_error(&self) -> bool {
        matches!(self, Self::ProtocolError { .. })
    }

    /// Whether this outcome represents an application-level error
    /// (handler ran but failed).
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn is_application_error(&self) -> bool {
        matches!(self, Self::ApplicationError { .. })
    }

    fn into_response(self, id: serde_json::Value) -> JsonRpcResponse {
        match self {
            Self::Success(value) => JsonRpcResponse::success(id, value),
            Self::ProtocolError { code, message } => JsonRpcResponse::error(id, code, message),
            Self::ApplicationError {
                code,
                message,
                source_detail,
            } => {
                let data =
                    source_detail.map(|detail| serde_json::json!({ "source_detail": detail }));
                <JsonRpcResponse as JsonRpcResponseExt>::error_with_data(id, code, message, data)
            },
        }
    }
}

/// Process a single JSON-RPC request, returning `None` for notifications.
///
/// A notification is a request without an `id` field (per JSON-RPC 2.0 spec,
/// Section 4.1). The server MUST NOT reply to a notification. Note that
/// `"id": null` is a valid request identifier, not a notification.
///
/// Used by both the HTTP handler and the UDS transport.
pub(crate) async fn process_single(
    state: &AppState,
    raw: serde_json::Value,
) -> Option<JsonRpcResponse> {
    let is_notification = raw.as_object().is_some_and(|obj| !obj.contains_key("id"));

    let parsed: JsonRpcRequest = match serde_json::from_value(raw) {
        Ok(r) => r,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                serde_json::Value::Null,
                error_code::PARSE_ERROR,
                format!("Parse error: {e}"),
            ));
        },
    };

    if is_notification {
        return None;
    }

    let id = parsed.id.unwrap_or(serde_json::Value::Null);

    if parsed.jsonrpc != "2.0" {
        return Some(
            DispatchOutcome::ProtocolError {
                code: error_code::INVALID_REQUEST,
                message: "Invalid JSON-RPC version, expected \"2.0\"".into(),
            }
            .into_response(id),
        );
    }

    let params = parsed.params.unwrap_or(serde_json::Value::Null);
    let outcome = dispatch_classified(state, &parsed.method, params).await;
    Some(outcome.into_response(id))
}

/// `POST /jsonrpc` — JSON-RPC 2.0 dispatcher with batch and notification support.
///
/// Per JSON-RPC 2.0 spec:
/// - **Single request** (object): dispatched to the appropriate handler.
/// - **Batch request** (array): each element processed independently;
///   responses collected into an array.
/// - **Notifications** (absent `id`): executed but produce no response.
/// - **All-notification batch**: returns `204 No Content`.
/// - **Empty batch**: returns an `Invalid Request` error.
#[instrument(skip_all)]
pub async fn handle_jsonrpc(
    State(state): State<AppState>,
    Json(request): Json<serde_json::Value>,
) -> Response {
    if let serde_json::Value::Array(batch) = request {
        if batch.is_empty() {
            return Json(JsonRpcResponse::error(
                serde_json::Value::Null,
                error_code::INVALID_REQUEST,
                "Invalid Request: empty batch",
            ))
            .into_response();
        }

        let mut responses = Vec::with_capacity(batch.len());
        for req in batch {
            if let Some(resp) = process_single(&state, req).await {
                responses.push(resp);
            }
        }

        if responses.is_empty() {
            return StatusCode::NO_CONTENT.into_response();
        }

        return Json(responses).into_response();
    }

    (process_single(&state, request).await).map_or_else(
        || StatusCode::NO_CONTENT.into_response(),
        |resp| Json(resp).into_response(),
    )
}

#[cfg(test)]
async fn dispatch(state: &AppState, method: &str, params: serde_json::Value) -> DispatchResult {
    match find_handler(method) {
        Some(handler) => handler(state, params).await,
        None => Err(DispatchError {
            code: error_code::METHOD_NOT_FOUND,
            message: format!("Method not found: {method}"),
            source_detail: None,
        }),
    }
}

/// Extract `_bearer_token` from JSON-RPC params (if present).
///
/// Per the ecosystem convention, callers attach an ionic token as
/// `"_bearer_token": "<token>"` inside the `params` object. This is
/// a non-destructive read — the token field is *not* stripped from
/// `params` before forwarding to the handler.
fn extract_bearer_token(params: &serde_json::Value) -> Option<String> {
    params
        .get("_bearer_token")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

/// Build a [`CallerContext`] from the request params.
///
/// Currently extracts only `_bearer_token`; connection origin defaults
/// to `Loopback` until transport-layer callers thread real peer info.
pub(crate) fn caller_context_from_params(
    params: &serde_json::Value,
) -> crate::method_gate::CallerContext {
    crate::method_gate::CallerContext {
        bearer_token: extract_bearer_token(params),
        peer: None,
        origin: crate::method_gate::ConnectionOrigin::Loopback,
    }
}

/// Extract `_caller_did` from JSON-RPC params (if present).
pub(crate) fn caller_did_from_params(
    params: &serde_json::Value,
) -> Option<sweet_grass_core::agent::Did> {
    params
        .get("_caller_did")
        .and_then(serde_json::Value::as_str)
        .map(sweet_grass_core::agent::Did::new)
}

/// Dispatch with protocol/application error classification.
///
/// Runs the JH-0 method gate before handler lookup. Extracts
/// `_bearer_token` from params and threads it through the gate.
/// Alias resolution (GAP-36) maps downstream wire names to canonical
/// names before the gate check.
async fn dispatch_classified(
    state: &AppState,
    method: &str,
    params: serde_json::Value,
) -> DispatchOutcome {
    let normalized = normalize_method(method);
    let effective = resolve_alias(&normalized).unwrap_or(normalized.as_str());
    let caller = caller_context_from_params(&params);

    if let Err(gate_err) = state.method_gate.check(effective, &caller) {
        return DispatchOutcome::ProtocolError {
            code: gate_err.0,
            message: gate_err.1,
        };
    }

    let Some(handler) = find_handler_normalized(&normalized) else {
        return DispatchOutcome::ProtocolError {
            code: error_code::METHOD_NOT_FOUND,
            message: format!("Method not found: {method}"),
        };
    };

    match handler(state, params).await {
        Ok(value) => DispatchOutcome::Success(value),
        Err(e) => DispatchOutcome::ApplicationError {
            code: e.code,
            message: e.message,
            source_detail: e.source_detail,
        },
    }
}

// ==================== Helpers (used by domain modules) ====================

pub(crate) fn internal(e: impl std::fmt::Display) -> DispatchError {
    DispatchError {
        code: error_code::INTERNAL_ERROR,
        message: e.to_string(),
        source_detail: Some(format!("{e:#}")),
    }
}

/// # Errors
///
/// Returns an error if JSON deserialization of params fails.
pub(crate) fn parse_params<T: serde::de::DeserializeOwned>(
    params: serde_json::Value,
) -> Result<T, DispatchError> {
    serde_json::from_value(params).map_err(|e| DispatchError {
        code: error_code::INVALID_PARAMS,
        message: format!("Invalid params: {e}"),
        source_detail: None,
    })
}

/// # Errors
///
/// Returns an error if JSON serialization fails.
pub(crate) fn to_value<T: Serialize>(v: &T) -> DispatchResult {
    serde_json::to_value(v).map_err(|e| DispatchError {
        code: error_code::INTERNAL_ERROR,
        message: format!("Serialization error: {e}"),
        source_detail: None,
    })
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_anchoring;
#[cfg(test)]
mod tests_attribution;
#[cfg(test)]
mod tests_braid_verify;
#[cfg(test)]
mod tests_composition;
#[cfg(test)]
mod tests_compression;
#[cfg(test)]
mod tests_contribution;
#[cfg(test)]
mod tests_convergence;
#[cfg(test)]
mod tests_cross_gate;
#[cfg(test)]
mod tests_privacy;
#[cfg(test)]
mod tests_protocol;
#[cfg(test)]
mod tests_provenance;
#[cfg(test)]
mod tests_rootpulse;
