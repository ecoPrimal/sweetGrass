// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! Braid titration — gradual on-read repair of legacy data structures.
//!
//! Inspired by the toxin/antidote pattern: detect legacy braids on read,
//! classify what's outdated, repair to the current schema, and track
//! repair metrics. When all braids have been upgraded, the legacy compat
//! shims become dead code and can be removed.
//!
//! # Schema Versions
//!
//! | Version | Introduced | Changes |
//! |---------|-----------|---------|
//! | 0 | pre-versioning | No `schema_version` field. Uses `rhizo_session`, `loam_commit`, `signature`, plain string certs. |
//! | 1 | Wave 167k | Capability-based field names (`session_ref`, `ledger_commit`), structured `CertificateRef`, `Witness` type, transport-bound BTSP sessions. |

use super::{Braid, types::BRAID_SCHEMA_VERSION};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

/// Counters for titration observability.
///
/// Track legacy reads vs repairs to know when a compat shim can be removed.
pub static LEGACY_READS: AtomicU64 = AtomicU64::new(0);
pub static REPAIRS_APPLIED: AtomicU64 = AtomicU64::new(0);
pub static V0_BRAIDS_SEEN: AtomicU64 = AtomicU64::new(0);
pub static WITNESSES_EVOLVED: AtomicU64 = AtomicU64::new(0);
pub static CERTS_ENRICHED: AtomicU64 = AtomicU64::new(0);
pub static FIELD_ALIASES_CONSUMED: AtomicU64 = AtomicU64::new(0);

/// Result of a titration scan on a single braid.
#[derive(Debug, Clone, Default)]
pub struct TitrationReport {
    /// Schema version before titration.
    pub original_version: u8,
    /// Schema version after titration.
    pub upgraded_version: u8,
    /// Whether any repairs were applied.
    pub repaired: bool,
    /// Individual repair actions taken.
    pub actions: Vec<RepairAction>,
}

/// A single repair action applied during titration.
#[derive(Debug, Clone)]
pub enum RepairAction {
    /// Schema version stamped (was 0, now N).
    VersionStamped { from: u8, to: u8 },
    /// Certificate ref upgraded from plain string to structured.
    CertificateEnriched,
    /// source_gate field populated from context.
    SourceGateInferred { gate: String },
    /// Witness evolved: old `signature` field deserialized into Witness struct.
    /// Tracked when `ecop.witnesses` is empty and the primary witness has
    /// kind="signature" with non-empty evidence (came from legacy `signature` field).
    WitnessEvolved,
    /// Legacy field alias consumed during deserialization.
    /// Tracks `rhizo_session` → `session_ref`, `loam_commit` → `ledger_commit`.
    FieldAliasConsumed { field: String },
}

/// Scan a braid and determine if it needs titration.
///
/// Returns `true` if the braid is below the current schema version.
#[must_use]
pub fn needs_titration(braid: &Braid) -> bool {
    braid.ecop.schema_version < BRAID_SCHEMA_VERSION
}

/// Apply titration repairs to a braid, upgrading it to the current schema version.
///
/// This is an in-place mutation — the braid is modified to the current schema.
/// Returns a report of what was changed. If the braid is already at the current
/// version, no changes are made.
///
/// # Design: Antidote Pattern
///
/// Each version bump has a corresponding repair function. Repairs are applied
/// sequentially: v0→v1, v1→v2, etc. This means a very old braid (v0) gets
/// every repair in order, ensuring no step is skipped.
pub fn titrate(braid: &mut Braid) -> TitrationReport {
    let original_version = braid.ecop.schema_version;

    if original_version >= BRAID_SCHEMA_VERSION {
        return TitrationReport {
            original_version,
            upgraded_version: original_version,
            repaired: false,
            actions: vec![],
        };
    }

    LEGACY_READS.fetch_add(1, Ordering::Relaxed);

    let mut actions = Vec::new();

    // ── v0 → v1 repairs ────────────────────────────────────────────────
    if braid.ecop.schema_version == 0 {
        V0_BRAIDS_SEEN.fetch_add(1, Ordering::Relaxed);

        // 1. Stamp the version
        actions.push(RepairAction::VersionStamped {
            from: 0,
            to: BRAID_SCHEMA_VERSION,
        });

        // 2. Enrich certificate from plain string (if present but not structured)
        if let Some(ref cert) = braid.ecop.certificate {
            if cert.issuing_gate.is_none() && cert.minting_authority.is_none() {
                // Infer issuing gate from source_gate if available
                if let Some(ref gate) = braid.ecop.source_gate {
                    let mut enriched = cert.clone();
                    enriched.issuing_gate = Some(gate.clone());
                    braid.ecop.certificate = Some(enriched);
                    actions.push(RepairAction::CertificateEnriched);
                    CERTS_ENRICHED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // 3. Infer source_gate from source_primal if missing
        if braid.ecop.source_gate.is_none() {
            if let Some(ref primal) = braid.ecop.source_primal {
                // Default gate inference: primal name → "*Gate"
                let gate = infer_gate_from_primal(primal);
                if let Some(g) = gate {
                    braid.ecop.source_gate = Some(g.to_string().into());
                    actions.push(RepairAction::SourceGateInferred {
                        gate: g.to_string(),
                    });
                }
            }
        }

        // 4. Track witness evolution — if the primary witness has evidence
        // but came through the `signature` serde alias, it's a legacy
        // witness that was deserialized into the new Witness struct.
        if !braid.witness.evidence.is_empty()
            && braid.witness.kind.as_ref() == "signature"
            && braid.ecop.witnesses.is_empty()
        {
            actions.push(RepairAction::WitnessEvolved);
            WITNESSES_EVOLVED.fetch_add(1, Ordering::Relaxed);
        }

        // 5. Track field alias consumption (rhizo_session → session_ref,
        // loam_commit → ledger_commit). These are handled by serde `alias`
        // attributes, but we count them so we know when all callers have
        // migrated and the aliases can be removed.
        if braid.ecop.session_ref.is_some() {
            // Can't distinguish alias vs canonical at this point —
            // the counter is a lower bound on alias usage.
            FIELD_ALIASES_CONSUMED.fetch_add(1, Ordering::Relaxed);
        }

        braid.ecop.schema_version = BRAID_SCHEMA_VERSION;
    }

    // Future: v1 → v2 repairs would go here

    let repaired = !actions.is_empty();
    if repaired {
        REPAIRS_APPLIED.fetch_add(1, Ordering::Relaxed);
        debug!(
            braid_id = %braid.id,
            from = original_version,
            to = BRAID_SCHEMA_VERSION,
            repairs = actions.len(),
            "Braid titrated"
        );
    }

    TitrationReport {
        original_version,
        upgraded_version: braid.ecop.schema_version,
        repaired,
        actions,
    }
}

/// Get titration metrics for observability.
#[must_use]
pub fn metrics() -> TitrationMetrics {
    TitrationMetrics {
        legacy_reads: LEGACY_READS.load(Ordering::Relaxed),
        repairs_applied: REPAIRS_APPLIED.load(Ordering::Relaxed),
        v0_braids_seen: V0_BRAIDS_SEEN.load(Ordering::Relaxed),
        witnesses_evolved: WITNESSES_EVOLVED.load(Ordering::Relaxed),
        certs_enriched: CERTS_ENRICHED.load(Ordering::Relaxed),
        field_aliases_consumed: FIELD_ALIASES_CONSUMED.load(Ordering::Relaxed),
        current_version: BRAID_SCHEMA_VERSION,
    }
}

/// Titration metrics snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TitrationMetrics {
    pub legacy_reads: u64,
    pub repairs_applied: u64,
    pub v0_braids_seen: u64,
    pub witnesses_evolved: u64,
    pub certs_enriched: u64,
    pub field_aliases_consumed: u64,
    pub current_version: u8,
}

/// Infer the gate name from a primal name.
///
/// Maps known primals to their canonical gate:
/// - sweetGrass → strandGate (provenance)
/// - loamSpine → ironGate (permanence)
/// - rhizoCrypt → deepGate (session events)
fn infer_gate_from_primal(primal: &str) -> Option<&'static str> {
    match primal.to_lowercase().as_str() {
        "sweetgrass" | "sweet-grass" | "sweet_grass" => Some("strandGate"),
        "loamspine" | "loam-spine" | "loam_spine" => Some("ironGate"),
        "rhizocrypt" | "rhizo-crypt" | "rhizo_crypt" => Some("deepGate"),
        "beardog" | "bear-dog" | "bear_dog" => Some("guardGate"),
        "songbird" | "song-bird" | "song_bird" => Some("echoGate"),
        "skunkbat" | "skunk-bat" | "skunk_bat" => Some("shieldGate"),
        "squirrel" => Some("cacheGate"),
        "petaltongue" | "petal-tongue" | "petal_tongue" => Some("lensGate"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Did;
    use crate::braid::{BraidBuilder, CertificateRef, ContentHash};

    fn make_v0_braid() -> Braid {
        let mut braid = BraidBuilder::default()
            .data_hash(ContentHash::new("sha256:test"))
            .mime_type("text/plain")
            .size(42)
            .attributed_to(Did::new("did:eco:test-agent"))
            .build()
            .unwrap();
        braid.ecop.schema_version = 0;
        braid.ecop.source_primal = Some("sweetGrass".into());
        braid
    }

    #[test]
    fn v0_braid_needs_titration() {
        let braid = make_v0_braid();
        assert!(needs_titration(&braid));
    }

    #[test]
    fn current_version_does_not_need_titration() {
        let mut braid = make_v0_braid();
        braid.ecop.schema_version = BRAID_SCHEMA_VERSION;
        assert!(!needs_titration(&braid));
    }

    #[test]
    fn titrate_stamps_version() {
        let mut braid = make_v0_braid();
        let report = titrate(&mut braid);
        assert!(report.repaired);
        assert_eq!(report.original_version, 0);
        assert_eq!(report.upgraded_version, BRAID_SCHEMA_VERSION);
        assert_eq!(braid.ecop.schema_version, BRAID_SCHEMA_VERSION);
    }

    #[test]
    fn titrate_infers_source_gate() {
        let mut braid = make_v0_braid();
        assert!(braid.ecop.source_gate.is_none());

        let report = titrate(&mut braid);
        assert!(report.repaired);
        assert_eq!(braid.ecop.source_gate.as_deref(), Some("strandGate"));

        let gate_action = report
            .actions
            .iter()
            .find(|a| matches!(a, RepairAction::SourceGateInferred { .. }));
        assert!(gate_action.is_some());
    }

    #[test]
    fn titrate_enriches_certificate() {
        let mut braid = make_v0_braid();
        braid.ecop.source_gate = Some("strandGate".into());
        braid.ecop.certificate = Some(CertificateRef::new("cert-001"));

        let report = titrate(&mut braid);
        assert!(report.repaired);

        let cert = braid.ecop.certificate.unwrap();
        assert_eq!(cert.issuing_gate.as_deref(), Some("strandGate"));
    }

    #[test]
    fn titrate_idempotent() {
        let mut braid = make_v0_braid();
        let r1 = titrate(&mut braid);
        assert!(r1.repaired);

        let r2 = titrate(&mut braid);
        assert!(!r2.repaired);
        assert_eq!(r2.original_version, BRAID_SCHEMA_VERSION);
    }

    #[test]
    fn titrate_no_op_on_current() {
        let mut braid = make_v0_braid();
        braid.ecop.schema_version = BRAID_SCHEMA_VERSION;
        let report = titrate(&mut braid);
        assert!(!report.repaired);
        assert!(report.actions.is_empty());
    }

    #[test]
    fn infer_gate_known_primals() {
        assert_eq!(infer_gate_from_primal("sweetGrass"), Some("strandGate"));
        assert_eq!(infer_gate_from_primal("loamSpine"), Some("ironGate"));
        assert_eq!(infer_gate_from_primal("bearDog"), Some("guardGate"));
        assert_eq!(infer_gate_from_primal("unknown"), None);
    }

    #[test]
    fn metrics_increment() {
        let before = metrics();
        let mut braid = make_v0_braid();
        titrate(&mut braid);
        let after = metrics();
        assert!(after.legacy_reads > before.legacy_reads);
        assert!(after.repairs_applied > before.repairs_applied);
    }

    #[test]
    fn titrate_tracks_witness_evolution() {
        use crate::dehydration::Witness;
        let mut braid = make_v0_braid();
        braid.witness = Witness {
            agent: Did::new("did:eco:signer"),
            kind: "signature".into(),
            evidence: "deadbeef".into(),
            witnessed_at: crate::braid::Timestamp::now(),
            encoding: "hex".into(),
            algorithm: Some("ed25519".into()),
            tier: None,
            context: None,
        };
        let report = titrate(&mut braid);
        assert!(report.repaired);
        let evolved = report
            .actions
            .iter()
            .any(|a| matches!(a, RepairAction::WitnessEvolved));
        assert!(evolved, "should track witness evolution from legacy signature");
    }

    #[test]
    fn titrate_cert_enrichment_increments_counter() {
        let before = metrics();
        let mut braid = make_v0_braid();
        braid.ecop.source_gate = Some("strandGate".into());
        braid.ecop.certificate = Some(CertificateRef::new("cert-002"));
        titrate(&mut braid);
        let after = metrics();
        assert!(after.certs_enriched > before.certs_enriched);
    }

    #[test]
    fn titrate_metrics_include_all_counters() {
        let m = metrics();
        // All counters should be present and serializable
        let json = serde_json::to_value(&m).unwrap();
        assert!(json.get("witnesses_evolved").is_some());
        assert!(json.get("certs_enriched").is_some());
        assert!(json.get("field_aliases_consumed").is_some());
        assert!(json.get("current_version").is_some());
    }
}
