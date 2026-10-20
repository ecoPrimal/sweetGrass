// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! Pure Rust RPC service definition using tarpc.
//!
//! No gRPC, no protobuf, no vendor lock-in.
//! The Rust compiler is our code generator.

use serde::{Deserialize, Serialize};
use sweet_grass_compression::{CompressionResult, Session};
use sweet_grass_core::{
    Activity, AgentRole,
    agent::Did,
    braid::{Braid, BraidId, BraidMetadata, ContentHash, SummaryType, Timestamp},
    entity::EntityReference,
};
use sweet_grass_factory::{AttributionChain, AttributionConfig};
use sweet_grass_query::ProvenanceGraph;
use sweet_grass_store::{QueryFilter, QueryOrder, QueryResult};

/// Service error type - serializable for RPC transport.
#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum RpcError {
    /// Entity not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Invalid input.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Store error.
    #[error("store error: {0}")]
    Store(String),

    /// Query error.
    #[error("query error: {0}")]
    Query(String),

    /// Compression error.
    #[error("compression error: {0}")]
    Compression(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Create Braid request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateBraidRequest {
    /// Content hash of the data.
    pub data_hash: ContentHash,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Attributed agent DID.
    pub attributed_to: Did,
    /// Optional activity that generated this Braid.
    pub activity: Option<Activity>,
    /// Sources this Braid was derived from.
    pub derived_from: Vec<EntityReference>,
    /// Optional metadata.
    pub metadata: Option<BraidMetadata>,
}

/// Time range for queries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimeRange {
    /// Start timestamp (nanoseconds).
    pub start: Timestamp,
    /// End timestamp (nanoseconds).
    pub end: Timestamp,
}

/// Reward share for an agent.
///
/// **Note on precision**: `share` and `amount` are informational ratios,
/// not settlement-grade monetary values. For production payment flows
/// (sunCloud v0.9.0+), evolve to integer basis points (share as parts
/// per 1,000,000) and atomic units (amount in smallest currency unit).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RewardShare {
    /// Agent DID.
    pub agent: Did,
    /// Share fraction (0.0–1.0). Informational — not for settlement.
    pub share: f64,
    /// Amount (share * `total_value`). Informational — not for settlement.
    pub amount: f64,
    /// Role that earned this share.
    pub role: AgentRole,
}

/// Agent contributions summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentContributions {
    /// Agent DID.
    pub agent: Did,
    /// Total number of contributions.
    pub total_count: usize,
    /// Total share value.
    pub total_share: f64,
    /// Braids contributed to.
    pub braids: Vec<BraidId>,
}

/// Health status — canonical form from `cellmembrane-types`.
///
/// Organism-specific fields (store_status, braid_count, version) are
/// carried in `details`.
pub use cellmembrane_types::HealthStatus;

/// Service status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// Whether service is healthy.
    pub healthy: bool,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
    /// Number of Braids.
    pub braid_count: usize,
    /// Store type.
    pub store_type: String,
    /// Version.
    pub version: String,
}

/// JSON-LD document for PROV-O export.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonLdDocument {
    /// The JSON-LD content.
    pub content: serde_json::Value,
}

impl RpcError {
    /// Check if this is a not-found error.
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Check if this is a validation error.
    #[must_use]
    pub const fn is_validation(&self) -> bool {
        matches!(self, Self::InvalidInput(_))
    }
}

/// `SweetGrass` RPC Service - Pure Rust, no protobuf.
///
/// This trait defines all RPC operations. The `#[tarpc::service]` macro
/// generates client and server code at compile time using Rust macros,
/// not external code generators.
#[tarpc::service]
pub trait SweetGrassRpc {
    // ==================== Braid Operations ====================

    /// Create a new Braid.
    async fn create_braid(request: CreateBraidRequest) -> Result<Braid, RpcError>;

    /// Get Braid by ID.
    async fn get_braid(id: BraidId) -> Result<Option<Braid>, RpcError>;

    /// Get Braid by content hash.
    async fn get_braid_by_hash(hash: ContentHash) -> Result<Option<Braid>, RpcError>;

    /// Query Braids with filter.
    async fn query_braids(filter: QueryFilter, order: QueryOrder) -> Result<QueryResult, RpcError>;

    /// Delete Braid.
    async fn delete_braid(id: BraidId) -> Result<bool, RpcError>;

    // ==================== Provenance ====================

    /// Get provenance graph for an entity.
    async fn provenance_graph(
        entity: EntityReference,
        max_depth: u32,
        include_activities: bool,
    ) -> Result<ProvenanceGraph, RpcError>;

    /// Get attribution chain.
    async fn attribution_chain(
        hash: ContentHash,
        config: AttributionConfig,
    ) -> Result<AttributionChain, RpcError>;

    /// Calculate reward distribution.
    async fn calculate_rewards(
        hash: ContentHash,
        total_value: f64,
    ) -> Result<Vec<RewardShare>, RpcError>;

    /// Get top contributors for an entity by content hash.
    async fn top_contributors(hash: ContentHash, limit: u32) -> Result<Vec<RewardShare>, RpcError>;

    // ==================== Agent Queries ====================

    /// Get agent's contributions.
    async fn agent_contributions(
        agent: Did,
        time_range: Option<TimeRange>,
    ) -> Result<AgentContributions, RpcError>;

    /// Get Braids by agent.
    async fn braids_by_agent(agent: Did) -> Result<Vec<Braid>, RpcError>;

    // ==================== Compression ====================

    /// Compress session events to Braids.
    async fn compress_session(session: Session) -> Result<CompressionResult, RpcError>;

    /// Create meta-Braid (summary).
    async fn create_meta_braid(
        braid_ids: Vec<BraidId>,
        summary_type: SummaryType,
    ) -> Result<Braid, RpcError>;

    // ==================== Anchoring ====================

    /// Anchor a Braid to `LoamSpine` (via integration client).
    async fn anchor_braid(
        braid_id: BraidId,
        spine_id: String,
    ) -> Result<serde_json::Value, RpcError>;

    /// Verify a Braid's anchor status.
    async fn verify_anchor(braid_id: BraidId) -> Result<serde_json::Value, RpcError>;

    // ==================== Export ====================

    /// Export to PROV-O JSON-LD.
    async fn export_provo(hash: ContentHash) -> Result<JsonLdDocument, RpcError>;

    /// Export provenance graph as PROV-O JSON-LD.
    async fn export_graph_provo(
        entity: EntityReference,
        depth: u32,
    ) -> Result<JsonLdDocument, RpcError>;

    // ==================== Convergence ====================

    /// Check provenance convergence depth for a content hash.
    async fn convergence_check(data_hash: ContentHash) -> Result<serde_json::Value, RpcError>;

    /// Backpressure signal: convergence lag as a throttling gate.
    async fn convergence_pressure(scan_limit: u32) -> Result<serde_json::Value, RpcError>;

    // ==================== Health ====================

    /// Health check.
    async fn health_check() -> Result<HealthStatus, RpcError>;

    /// Lightweight liveness probe (wateringHole protocol v3.0).
    async fn health_liveness() -> bool;

    /// Readiness probe — ready to accept work (wateringHole protocol v3.0).
    async fn health_readiness() -> bool;

    /// Get service status.
    async fn status() -> Result<ServiceStatus, RpcError>;
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test module: expect is standard in tests"
)]
mod tests {
    use super::*;
    use sweet_grass_core::Timestamp;

    #[test]
    fn test_rpc_error_display() {
        let err = RpcError::NotFound("braid-123".to_string());
        assert_eq!(err.to_string(), "not found: braid-123");

        let err = RpcError::InvalidInput("bad hash".to_string());
        assert_eq!(err.to_string(), "invalid input: bad hash");

        let err = RpcError::Store("connection timeout".to_string());
        assert_eq!(err.to_string(), "store error: connection timeout");

        let err = RpcError::Query("invalid filter".to_string());
        assert_eq!(err.to_string(), "query error: invalid filter");

        let err = RpcError::Compression("buffer too small".to_string());
        assert_eq!(err.to_string(), "compression error: buffer too small");

        let err = RpcError::Internal("unexpected state".to_string());
        assert_eq!(err.to_string(), "internal error: unexpected state");
    }

    #[test]
    fn test_rpc_error_predicates() {
        assert!(RpcError::NotFound("x".to_string()).is_not_found());
        assert!(!RpcError::Store("x".to_string()).is_not_found());

        assert!(RpcError::InvalidInput("x".to_string()).is_validation());
        assert!(!RpcError::Store("x".to_string()).is_validation());
    }

    #[test]
    fn test_rpc_error_serialization() {
        let err = RpcError::NotFound("test-id".to_string());
        let json = serde_json::to_string(&err).expect("should serialize");
        let parsed: RpcError = serde_json::from_str(&json).expect("should deserialize");
        assert!(matches!(parsed, RpcError::NotFound(s) if s == "test-id"));
    }

    #[test]
    fn test_create_braid_request_serialization() {
        use sweet_grass_core::agent::Did;

        let request = CreateBraidRequest {
            data_hash: "sha256:abc123".to_string().into(),
            mime_type: "application/json".to_string(),
            size: 1024,
            attributed_to: Did::new("did:key:z6MkTest"),
            activity: None,
            derived_from: vec![],
            metadata: None,
        };

        let json = serde_json::to_string(&request).expect("should serialize");
        let parsed: CreateBraidRequest = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed.data_hash.as_str(), "sha256:abc123");
        assert_eq!(parsed.size, 1024);
    }

    #[test]
    fn test_time_range_serialization() {
        let range = TimeRange {
            start: Timestamp::new(1000),
            end: Timestamp::new(2000),
        };

        let json = serde_json::to_string(&range).expect("should serialize");
        let parsed: TimeRange = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed.start, Timestamp::new(1000));
        assert_eq!(parsed.end, Timestamp::new(2000));
    }

    #[test]
    fn test_reward_share_serialization() {
        use sweet_grass_core::agent::Did;

        let share = RewardShare {
            agent: Did::new("did:key:z6MkTest"),
            share: 0.25,
            amount: 100.0,
            role: AgentRole::Creator,
        };

        let json = serde_json::to_string(&share).expect("should serialize");
        let parsed: RewardShare = serde_json::from_str(&json).expect("should deserialize");
        assert!((parsed.share - 0.25).abs() < f64::EPSILON);
        assert!((parsed.amount - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_agent_contributions_serialization() {
        use sweet_grass_core::agent::Did;
        use sweet_grass_core::braid::BraidId;

        let contrib = AgentContributions {
            agent: Did::new("did:key:z6MkTest"),
            total_count: 5,
            total_share: 0.5,
            braids: vec![
                BraidId::from_string("braid:1".to_string()),
                BraidId::from_string("braid:2".to_string()),
            ],
        };

        let json = serde_json::to_string(&contrib).expect("should serialize");
        let parsed: AgentContributions = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(parsed.total_count, 5);
        assert_eq!(parsed.braids.len(), 2);
    }

    #[test]
    fn test_health_status_serialization() {
        let status = HealthStatus::ok()
            .with_detail("status", "healthy")
            .with_detail("store_status", "connected")
            .with_detail("braid_count", 42)
            .with_detail("version", "0.2.0");

        let json = serde_json::to_string(&status).expect("should serialize");
        let parsed: HealthStatus = serde_json::from_str(&json).expect("should deserialize");
        assert!(parsed.healthy);
        assert_eq!(parsed.details.get("braid_count").and_then(|v| v.as_i64()), Some(42));
    }

    #[test]
    fn test_service_status_serialization() {
        let status = ServiceStatus {
            healthy: true,
            uptime_seconds: 3600,
            braid_count: 100,
            store_type: "memory".to_string(),
            version: "0.2.0".to_string(),
        };

        let json = serde_json::to_string(&status).expect("should serialize");
        let parsed: ServiceStatus = serde_json::from_str(&json).expect("should deserialize");
        assert!(parsed.healthy);
        assert_eq!(parsed.uptime_seconds, 3600);
    }

    #[test]
    fn test_json_ld_document_serialization() {
        let doc = JsonLdDocument {
            content: serde_json::json!({
                "@context": "https://www.w3.org/ns/prov",
                "@type": "Entity"
            }),
        };

        let json = serde_json::to_string(&doc).expect("should serialize");
        let parsed: JsonLdDocument = serde_json::from_str(&json).expect("should deserialize");
        assert!(parsed.content.get("@context").is_some());
    }
}
