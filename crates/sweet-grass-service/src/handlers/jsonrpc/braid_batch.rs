// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! Batch braid operations (G31 pipeline): `braid.batch_create`, `braid.batch_commit`.
//!
//! Amortizes connection and serialization overhead across hundreds of braids,
//! reducing per-object latency from ~30ms to ~3ms for bulk ingestion.

use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;
use sweet_grass_core::braid::{BraidId, BraidMetadata, ContentHash};
use sweet_grass_store::BraidStore;

use crate::state::AppState;

use super::{DispatchError, DispatchResult, parse_params, to_value};

#[derive(Debug, Deserialize)]
pub(super) struct BatchCreateParams {
    braids: Vec<BatchCreateItem>,
    #[serde(default = "default_batch_concurrency")]
    concurrency: usize,
}

#[derive(Debug, Deserialize)]
struct BatchCreateItem {
    data_hash: ContentHash,
    mime_type: String,
    size: u64,
    #[serde(default)]
    metadata: Option<BraidMetadata>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    source_gate: Option<String>,
}

const fn default_batch_concurrency() -> usize {
    sweet_grass_store::DEFAULT_BATCH_CONCURRENCY
}

const MAX_BATCH_SIZE: usize = 5_000;

const JSONRPC_INVALID_PARAMS: i32 = -32_602;

/// Batch-create multiple braids in a single request.
///
/// Accepts an array of braid specs, creates each via the factory, then
/// stores them all via `put_batch` with bounded concurrency. Returns an
/// array of results (one per input) with braid IDs and creation status.
///
/// For G31 bulk ingestion: 38 datasets / 220K PDB structures at ~3ms/object
/// (10x faster than sequential `braid.create` calls at ~30ms/object).
pub(super) async fn handle_braid_batch_create(
    state: &AppState,
    params: serde_json::Value,
) -> DispatchResult {
    let p: BatchCreateParams = parse_params(params)?;

    if p.braids.is_empty() {
        return to_value(&serde_json::json!({
            "created": 0,
            "results": [],
        }));
    }

    if p.braids.len() > MAX_BATCH_SIZE {
        return Err(DispatchError {
            code: JSONRPC_INVALID_PARAMS,
            message: format!(
                "batch size {} exceeds maximum {MAX_BATCH_SIZE}; split into smaller batches",
                p.braids.len()
            ),
            source_detail: None,
        });
    }

    let mut braids = Vec::with_capacity(p.braids.len());
    let mut results = Vec::with_capacity(p.braids.len());

    for item in p.braids {
        let metadata = item.metadata.map(|mut m| {
            if m.title.is_none()
                && let Some(name) = item.name
            {
                m.title = Some(name.into());
            }
            m
        });

        match state
            .factory
            .from_hash(item.data_hash, item.mime_type, item.size, metadata)
        {
            Ok(mut braid) => {
                if let Some(gate) = item.source_gate {
                    braid.ecop.source_gate = Some(Arc::from(gate.as_str()));
                }
                let id = braid.id.as_str().to_owned();
                braids.push(braid);
                results.push(serde_json::json!({ "id": id, "status": "created" }));
            },
            Err(e) => {
                results.push(serde_json::json!({
                    "id": null,
                    "status": "error",
                    "error": e.to_string(),
                }));
            },
        }
    }

    let (success_count, errors) = state.store.put_batch(&braids, Some(p.concurrency)).await;

    for err in &errors {
        tracing::warn!("batch_create store error: {err}");
    }

    to_value(&serde_json::json!({
        "created": success_count,
        "total": results.len(),
        "errors": errors.len(),
        "results": results,
    }))
}

#[derive(Debug, Deserialize)]
pub(super) struct BatchCommitParams {
    braid_ids: Vec<BraidId>,
    #[serde(default = "super::braid::default_spine_id")]
    spine_id: String,
    #[serde(default = "default_batch_concurrency")]
    concurrency: usize,
}

/// Dispatch commit payloads to loamSpine concurrently via `join_all`.
async fn dispatch_commits(
    client: &Arc<crate::ledger_client::LedgerClient>,
    payloads: Vec<(String, Option<serde_json::Value>)>,
) -> Vec<serde_json::Value> {
    let futs: Vec<_> = payloads
        .into_iter()
        .map(|(braid_id, maybe_payload)| {
            let client = Arc::clone(client);
            async move {
                let Some(payload) = maybe_payload else {
                    return serde_json::json!({
                        "braid_id": braid_id,
                        "status": "not_found",
                    });
                };
                match client.commit_braid(payload).await {
                    Ok(commit_ref) => serde_json::json!({
                        "braid_id": braid_id,
                        "status": "committed",
                        "ledger_commit": commit_ref,
                    }),
                    Err(e) => serde_json::json!({
                        "braid_id": braid_id,
                        "status": "local_only",
                        "error": e.to_string(),
                    }),
                }
            }
        })
        .collect();
    futures::future::join_all(futs).await
}

/// Batch-commit multiple braids to loamSpine in a single request.
///
/// Retrieves each braid, packages the commit payload, and forwards all to
/// loamSpine's `braid.commit` concurrently via `join_all`.
/// Returns an array of commit results. When loamSpine is unavailable,
/// returns the packaged payloads without `committed` status (local-only).
///
/// For G31 bulk ingestion: amortizes connection overhead across hundreds
/// of commits, reducing per-object latency from ~30ms to ~3ms.
pub(super) async fn handle_braid_batch_commit(
    state: &AppState,
    params: serde_json::Value,
) -> DispatchResult {
    let p: BatchCommitParams = parse_params(params)?;

    if p.braid_ids.is_empty() {
        return to_value(&serde_json::json!({
            "committed": 0,
            "results": [],
        }));
    }

    if p.braid_ids.len() > MAX_BATCH_SIZE {
        return Err(DispatchError {
            code: JSONRPC_INVALID_PARAMS,
            message: format!(
                "batch size {} exceeds maximum {MAX_BATCH_SIZE}; split into smaller batches",
                p.braid_ids.len()
            ),
            source_detail: None,
        });
    }

    let (found_braids, _errors) = state
        .store
        .get_batch(&p.braid_ids, Some(p.concurrency))
        .await;

    let payloads: Vec<_> = found_braids
        .into_iter()
        .enumerate()
        .map(|(i, maybe_braid)| {
            let Some(braid) = maybe_braid else {
                return (p.braid_ids[i].as_str().to_owned(), None);
            };

            let uuid = braid.id.to_uuid();
            let hash_bytes = braid
                .data_hash
                .to_bytes32()
                .map(|b| base64::engine::general_purpose::STANDARD.encode(b));

            let payload = serde_json::json!({
                "braid_id": braid.id.as_str(),
                "uuid": uuid,
                "data_hash": braid.data_hash.as_str(),
                "data_hash_bytes": hash_bytes,
                "spine_id": p.spine_id,
                "mime_type": braid.mime_type,
                "size": braid.size,
                "attributed_to": braid.was_attributed_to.as_str(),
                "generated_at": braid.generated_at_time,
                "is_signed": braid.is_signed(),
            });

            (braid.id.as_str().to_owned(), Some(payload))
        })
        .collect();

    let results = if let Some(ref client) = state.ledger_client {
        dispatch_commits(client, payloads).await
    } else {
        payloads
            .into_iter()
            .map(|(braid_id, maybe_payload)| {
                maybe_payload.map_or_else(
                    || serde_json::json!({ "braid_id": braid_id, "status": "not_found" }),
                    |payload| {
                        serde_json::json!({
                            "braid_id": braid_id,
                            "status": "local_only",
                            "payload": payload,
                        })
                    },
                )
            })
            .collect()
    };

    let committed_count = results
        .iter()
        .filter(|r| r.get("status").and_then(|s| s.as_str()) == Some("committed"))
        .count();

    to_value(&serde_json::json!({
        "committed": committed_count,
        "total": results.len(),
        "results": results,
    }))
}
