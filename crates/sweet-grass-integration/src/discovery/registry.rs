// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! Registry-based remote discovery via tarpc.
//!
//! Connects to any primal offering `Capability::Discovery` — the interface
//! is vendor-agnostic.  Falls back to [`LocalDiscovery`] when the registry
//! is unreachable.

use sweet_grass_core::config::Capability;
use sweet_grass_core::primal_names::env_vars;

use super::{DiscoveredPrimal, DiscoveryError, LocalDiscovery, PrimalDiscovery, RegistryError};

/// tarpc service definition for registry-based discovery.
///
/// Any primal offering `Capability::Discovery` can implement this interface.
/// The name is deliberately vendor-agnostic — primals discover registries
/// by capability, not by name.
#[tarpc::service]
pub trait RegistryRpc {
    /// Discover services by capability.
    async fn discover_services(
        capability: String,
    ) -> std::result::Result<Vec<ServiceInfo>, RegistryError>;

    /// Register a service.
    async fn register_service(info: ServiceInfo) -> std::result::Result<String, RegistryError>;

    /// Unregister a service.
    async fn unregister_service(service_id: String) -> std::result::Result<(), RegistryError>;

    /// Health check.
    async fn health() -> std::result::Result<bool, RegistryError>;
}

/// Service information — canonical form from `cellmembrane-types`.
///
/// Organism-specific fields (tarpc_address, rest_address, last_seen) are
/// mapped to/from the canonical `endpoints` and `metadata` fields.
pub use cellmembrane_types::ServiceInfo;

/// Extension trait for converting canonical `ServiceInfo` to sweetGrass's
/// `DiscoveredPrimal`.
pub trait ServiceInfoExt {
    /// Convert to [`DiscoveredPrimal`].
    fn to_primal(&self) -> DiscoveredPrimal;
}

impl ServiceInfoExt for ServiceInfo {
    fn to_primal(&self) -> DiscoveredPrimal {
        let tarpc_address = self
            .endpoints
            .iter()
            .find(|e| e.starts_with("tarpc:"))
            .map(|e| e.strip_prefix("tarpc:").unwrap_or(e).to_string());
        let rest_address = self
            .endpoints
            .iter()
            .find(|e| e.starts_with("rest:") || e.starts_with("http"))
            .map(|e| e.strip_prefix("rest:").unwrap_or(e).to_string());
        let last_seen_secs: u64 = self
            .metadata
            .get("last_seen")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        DiscoveredPrimal {
            instance_id: self.id.clone(),
            name: self.name.clone(),
            capabilities: self
                .capabilities
                .iter()
                .filter_map(|c| Capability::from_string(c))
                .collect(),
            tarpc_address,
            rest_address,
            last_seen: std::time::SystemTime::UNIX_EPOCH
                + std::time::Duration::from_secs(last_seen_secs),
            healthy: self.is_healthy(),
        }
    }
}

/// Discovery implementation backed by a remote registry service.
///
/// Connects to any primal offering `Capability::Discovery` via tarpc.
/// Falls back to `LocalDiscovery` when the registry is unreachable.
#[derive(Clone)]
pub struct RegistryDiscovery {
    client: RegistryRpcClient,
    fallback: LocalDiscovery,
}

impl RegistryDiscovery {
    /// Connect to a discovery registry service.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(addr: &str) -> Result<Self, DiscoveryError> {
        use tarpc::serde_transport::tcp;
        use tarpc::tokio_serde::formats::Bincode;

        let transport = tcp::connect(addr, Bincode::default).await.map_err(|e| {
            DiscoveryError::ConnectionFailed {
                address: addr.to_string(),
                reason: e.to_string(),
            }
        })?;

        let client = RegistryRpcClient::new(tarpc::client::Config::default(), transport).spawn();

        Ok(Self {
            client,
            fallback: LocalDiscovery::new(),
        })
    }

    /// Create from environment configuration.
    ///
    /// Looks for discovery address in environment variables (in order of preference):
    /// 1. `DISCOVERY_ADDRESS` — generic discovery service
    /// 2. `UNIVERSAL_ADAPTER_ADDRESS` — universal adapter (e.g., service mesh)
    /// 3. `DISCOVERY_BOOTSTRAP` — bootstrap node address
    ///
    /// # Errors
    ///
    /// Returns an error if no environment variable is set or connection fails.
    pub async fn from_env() -> Result<Self, DiscoveryError> {
        Self::from_reader(|key| std::env::var(key).ok()).await
    }

    /// Create from an injectable key reader (DI-friendly).
    ///
    /// # Errors
    ///
    /// Returns an error if no address is found or connection fails.
    pub async fn from_reader(
        reader: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, DiscoveryError> {
        let addr = reader(env_vars::DISCOVERY_ADDRESS)
            .or_else(|| reader(env_vars::UNIVERSAL_ADAPTER_ADDRESS))
            .or_else(|| reader(env_vars::DISCOVERY_BOOTSTRAP))
            .ok_or_else(|| {
                DiscoveryError::ServiceUnavailable(
                    "No discovery address found. Set DISCOVERY_ADDRESS or \
                     UNIVERSAL_ADAPTER_ADDRESS environment variable"
                        .to_string(),
                )
            })?;
        Self::connect(&addr).await
    }

    /// Register local fallback primals (for hybrid discovery).
    pub async fn register_fallback(&self, primal: DiscoveredPrimal) {
        self.fallback.register(primal).await;
    }
}

impl PrimalDiscovery for RegistryDiscovery {
    async fn find_by_capability(
        &self,
        capability: &Capability,
    ) -> Result<Vec<DiscoveredPrimal>, DiscoveryError> {
        let cap_string = capability.to_string();

        match self
            .client
            .discover_services(tarpc::context::current(), cap_string)
            .await
        {
            Ok(Ok(services)) => {
                let primals: Vec<_> = services.iter().map(ServiceInfoExt::to_primal).collect();
                if !primals.is_empty() {
                    return Ok(primals);
                }
            },
            Ok(Err(e)) => {
                tracing::warn!("Registry discovery error: {e}");
            },
            Err(e) => {
                tracing::warn!("Registry RPC error: {}", e);
            },
        }

        self.fallback.find_by_capability(capability).await
    }

    async fn announce(&self, primal: &DiscoveredPrimal) -> Result<(), DiscoveryError> {
        let mut info = ServiceInfo::new(&primal.instance_id, &primal.name)
            .with_version(env!("CARGO_PKG_VERSION"));
        if let Some(tarpc) = &primal.tarpc_address {
            info = info.with_endpoint(format!("tarpc:{tarpc}"));
        }
        if let Some(rest) = &primal.rest_address {
            info = info.with_endpoint(format!("rest:{rest}"));
        }
        for cap in &primal.capabilities {
            info = info.with_capability(cap.to_string());
        }
        info.status = if primal.healthy {
            cellmembrane_types::EcosystemServiceStatus::Running
        } else {
            cellmembrane_types::EcosystemServiceStatus::Error
        };
        let last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        info.metadata.insert("last_seen".into(), last_seen.to_string());

        match self
            .client
            .register_service(tarpc::context::current(), info)
            .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(DiscoveryError::ServiceUnavailable(e.to_string())),
            Err(e) => {
                self.fallback.announce(primal).await?;
                tracing::warn!("Registry unavailable, registered locally: {}", e);
                Ok(())
            },
        }
    }

    async fn health(&self) -> bool {
        match self.client.health(tarpc::context::current()).await {
            Ok(Ok(healthy)) => healthy,
            _ => self.fallback.health().await,
        }
    }
}
