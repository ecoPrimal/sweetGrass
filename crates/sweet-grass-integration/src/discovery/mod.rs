// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! Capability-based primal discovery.
//!
//! `SweetGrass` discovers other primals at runtime based on the capabilities
//! they offer, not hardcoded addresses. This module provides the discovery
//! infrastructure.
//!
//! ## Design Principles
//!
//! - **No hardcoded addresses**: Primals are discovered, not configured
//! - **Capability-based**: Find primals by what they can do, not who they are
//! - **Fault-tolerant**: Handle primal availability changes gracefully
//! - **Self-knowledge only**: A primal knows its own capabilities, discovers others

mod cached;
mod capabilities;
mod registry;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sweet_grass_core::config::Capability;
use thiserror::Error;
use tokio::sync::RwLock;

pub use cached::CachedDiscovery;
pub use capabilities::extract_capabilities;
pub use registry::{RegistryDiscovery, RegistryRpc, RegistryRpcClient, ServiceInfo, ServiceInfoExt};

/// Discovery error types.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiscoveryError {
    /// No primal found offering the required capability.
    #[error("no primal found offering capability: {0:?}")]
    CapabilityNotFound(Capability),

    /// Connection to discovered primal failed.
    #[error("connection failed to {address}: {reason}")]
    ConnectionFailed {
        /// Socket or network address that was unreachable.
        address: String,
        /// Underlying connection failure detail.
        reason: String,
    },

    /// Discovery service unavailable.
    #[error("discovery service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Timeout during discovery.
    #[error("discovery timeout after {0:?}")]
    Timeout(Duration),
}

/// Structured error for registry RPC operations.
#[derive(Clone, Debug, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Requested service is not registered.
    #[error("service not found: {0}")]
    NotFound(String),
    /// Registration RPC or persistence failed.
    #[error("registration failed: {0}")]
    RegistrationFailed(String),
    /// Unexpected internal failure.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Information about a discovered primal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredPrimal {
    /// Unique primal instance ID.
    pub instance_id: String,

    /// Human-readable primal name.
    pub name: String,

    /// Capabilities this primal offers.
    pub capabilities: Vec<Capability>,

    /// tarpc endpoint address (primary protocol).
    pub tarpc_address: Option<String>,

    /// REST endpoint address (fallback).
    pub rest_address: Option<String>,

    /// When this primal was last seen.
    pub last_seen: std::time::SystemTime,

    /// Health status.
    pub healthy: bool,
}

impl DiscoveredPrimal {
    /// Check if this primal offers a capability.
    #[must_use]
    pub fn offers(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Get the preferred connection address.
    #[must_use]
    pub fn preferred_address(&self) -> Option<&str> {
        self.tarpc_address
            .as_deref()
            .or(self.rest_address.as_deref())
    }
}

/// Trait for primal discovery services.
///
/// Implementations may use various discovery mechanisms:
/// - mDNS/DNS-SD for local networks
/// - Bootstrap nodes for wider networks
/// - Static configuration for testing
pub trait PrimalDiscovery: Send + Sync {
    /// Find primals offering a specific capability.
    fn find_by_capability(
        &self,
        capability: &Capability,
    ) -> impl Future<Output = Result<Vec<DiscoveredPrimal>, DiscoveryError>> + Send;

    /// Find a single primal offering a capability (first healthy one).
    fn find_one(
        &self,
        capability: &Capability,
    ) -> impl Future<Output = Result<DiscoveredPrimal, DiscoveryError>> + Send {
        async {
            let primals = self.find_by_capability(capability).await?;
            primals
                .into_iter()
                .find(|p| p.healthy)
                .ok_or_else(|| DiscoveryError::CapabilityNotFound(capability.clone()))
        }
    }

    /// Announce this primal's capabilities to the network.
    fn announce(
        &self,
        primal: &DiscoveredPrimal,
    ) -> impl Future<Output = Result<(), DiscoveryError>> + Send;

    /// Check if discovery service is available.
    fn health(&self) -> impl Future<Output = bool> + Send;
}

/// In-memory discovery registry for testing and single-node deployments.
///
/// This is NOT a stub — it's a complete implementation suitable for:
/// - Testing
/// - Single-node deployments
/// - Local development
///
/// For production multi-node deployments, use a distributed discovery
/// implementation.
pub struct LocalDiscovery {
    primals: Arc<RwLock<HashMap<String, DiscoveredPrimal>>>,
}

impl LocalDiscovery {
    /// Create a new local discovery registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            primals: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a primal directly (for testing or single-node).
    pub async fn register(&self, primal: DiscoveredPrimal) {
        let mut primals = self.primals.write().await;
        primals.insert(primal.instance_id.clone(), primal);
    }

    /// Unregister a primal.
    pub async fn unregister(&self, instance_id: &str) {
        let mut primals = self.primals.write().await;
        primals.remove(instance_id);
    }

    /// Get all registered primals.
    pub async fn all(&self) -> Vec<DiscoveredPrimal> {
        let primals = self.primals.read().await;
        primals.values().cloned().collect()
    }
}

impl Default for LocalDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for LocalDiscovery {
    fn clone(&self) -> Self {
        Self {
            primals: Arc::clone(&self.primals),
        }
    }
}

impl PrimalDiscovery for LocalDiscovery {
    async fn find_by_capability(
        &self,
        capability: &Capability,
    ) -> Result<Vec<DiscoveredPrimal>, DiscoveryError> {
        let primals = self.primals.read().await;
        let matching: Vec<_> = primals
            .values()
            .filter(|p| p.offers(capability))
            .cloned()
            .collect();
        drop(primals);
        Ok(matching)
    }

    async fn announce(&self, primal: &DiscoveredPrimal) -> Result<(), DiscoveryError> {
        self.register(primal.clone()).await;
        Ok(())
    }

    async fn health(&self) -> bool {
        true
    }
}

/// Unified primal discovery backend (local registry, remote registry, or cached wrapper).
#[derive(Clone)]
pub enum DiscoveryBackend {
    /// In-memory registry for tests and single-node deployments.
    Local(LocalDiscovery),
    /// Remote registry via tarpc.
    Registry(RegistryDiscovery),
    /// TTL cache over another backend.
    Cached(CachedDiscovery),
}

impl PrimalDiscovery for DiscoveryBackend {
    fn find_by_capability(
        &self,
        capability: &Capability,
    ) -> impl Future<Output = Result<Vec<DiscoveredPrimal>, DiscoveryError>> + Send {
        let this = self.clone();
        let capability = capability.clone();
        async move {
            match this {
                Self::Local(d) => d.find_by_capability(&capability).await,
                Self::Registry(d) => d.find_by_capability(&capability).await,
                Self::Cached(d) => d.find_by_capability(&capability).await,
            }
        }
    }

    fn find_one(
        &self,
        capability: &Capability,
    ) -> impl Future<Output = Result<DiscoveredPrimal, DiscoveryError>> + Send {
        let this = self.clone();
        let capability = capability.clone();
        async move {
            match this {
                Self::Local(d) => d.find_one(&capability).await,
                Self::Registry(d) => d.find_one(&capability).await,
                Self::Cached(d) => d.find_one(&capability).await,
            }
        }
    }

    fn announce(
        &self,
        primal: &DiscoveredPrimal,
    ) -> impl Future<Output = Result<(), DiscoveryError>> + Send {
        let this = self.clone();
        let primal = primal.clone();
        async move {
            match this {
                Self::Local(d) => d.announce(&primal).await,
                Self::Registry(d) => d.announce(&primal).await,
                Self::Cached(d) => d.announce(&primal).await,
            }
        }
    }

    fn health(&self) -> impl Future<Output = bool> + Send {
        let this = self.clone();
        async move {
            match this {
                Self::Local(d) => d.health().await,
                Self::Registry(d) => d.health().await,
                Self::Cached(d) => d.health().await,
            }
        }
    }
}

/// Create a discovery client based on environment.
///
/// If discovery address is set (via `DISCOVERY_ADDRESS`, `UNIVERSAL_ADAPTER_ADDRESS`,
/// or `DISCOVERY_BOOTSTRAP`), connects to that universal adapter service.
///
/// Otherwise, returns a local discovery instance for single-node deployments.
pub async fn create_discovery() -> Arc<DiscoveryBackend> {
    create_discovery_with_reader(|key| std::env::var(key).ok()).await
}

/// Create a discovery client using an injectable key reader (DI-friendly).
pub async fn create_discovery_with_reader(
    reader: impl Fn(&str) -> Option<String>,
) -> Arc<DiscoveryBackend> {
    match RegistryDiscovery::from_reader(reader).await {
        Ok(discovery) => {
            tracing::info!(
                "Using network discovery service (universal adapter) for primal coordination"
            );
            Arc::new(DiscoveryBackend::Registry(discovery))
        },
        Err(e) => {
            tracing::info!(
                "Using local discovery for single-node deployment \
                 (network discovery unavailable: {})",
                e
            );
            Arc::new(DiscoveryBackend::Local(LocalDiscovery::new()))
        },
    }
}

#[cfg(test)]
mod tests;
