// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! Pre-dispatch capability gate for JSON-RPC methods (JH-0).
//!
//! Every incoming RPC call passes through [`MethodGate::check`] *before*
//! reaching the dispatch table. The gate classifies methods into
//! [`MethodAccessLevel::Public`] (health probes, identity, capability
//! advertisement, auth introspection) and [`MethodAccessLevel::Protected`]
//! (require a valid capability token once enforcement is activated).
//!
//! Two enforcement modes control behavior:
//! - **Permissive** (default): protected methods are logged but allowed,
//!   preserving backward compatibility during ecosystem rollout.
//! - **Enforced**: protected methods without a valid token are rejected
//!   with `PERMISSION_DENIED` (-32001).
//!
//! Adopted from primalSpring's `ipc/method_gate.rs` reference implementation.

use sweet_grass_core::primal_names::env_vars;

/// Access level for a JSON-RPC method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodAccessLevel {
    /// Health probes, identity, capability advertisement — always allowed.
    Public,
    /// Requires a valid capability token when enforcement is active.
    Protected,
}

/// Method prefixes that are always public.
const PUBLIC_METHOD_PREFIXES: &[&str] = &["health.", "auth."];

/// Individual methods that are always public.
const PUBLIC_METHODS: &[&str] = &[
    "identity.get",
    "capabilities.list",
    "capability.list",
    "capability.call",
    "lifecycle.status",
    "tools.list",
];

/// Classify a method string into its access level.
#[must_use]
pub fn classify_method(method: &str) -> MethodAccessLevel {
    if PUBLIC_METHODS.contains(&method) {
        return MethodAccessLevel::Public;
    }
    for prefix in PUBLIC_METHOD_PREFIXES {
        if method.starts_with(prefix) {
            return MethodAccessLevel::Public;
        }
    }
    MethodAccessLevel::Protected
}

/// Peer credentials extracted from `SO_PEERCRED` on Unix sockets.
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// Process ID of the caller (if available).
    pub pid: Option<u32>,
    /// User ID of the caller.
    pub uid: u32,
}

/// How the caller connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOrigin {
    /// Local Unix domain socket.
    Unix,
    /// TCP loopback (127.0.0.1 / `::1`).
    Loopback,
    /// Remote TCP connection.
    Remote,
}

/// Identity and authorization context for an incoming RPC call.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// Optional bearer / capability token sent in the request.
    pub bearer_token: Option<String>,
    /// Peer credentials from `SO_PEERCRED` (Unix socket only).
    pub peer: Option<PeerCredentials>,
    /// Where the connection came from.
    pub origin: ConnectionOrigin,
}

impl CallerContext {
    /// Build a caller context for loopback TCP with no peer credentials.
    #[must_use]
    pub const fn loopback() -> Self {
        Self {
            bearer_token: None,
            peer: None,
            origin: ConnectionOrigin::Loopback,
        }
    }

    /// Build a caller context for a Unix domain socket connection.
    ///
    /// `SO_PEERCRED` extraction deferred until `peer_credentials_unix_socket`
    /// stabilizes (or a safe wrapper like `rustix` is adopted).
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "will extract peer_cred() when the API stabilizes"
    )]
    pub fn unix() -> Self {
        Self {
            bearer_token: None,
            peer: None,
            origin: ConnectionOrigin::Unix,
        }
    }

    /// Build a caller context for a remote TCP connection.
    #[must_use]
    pub const fn remote() -> Self {
        Self {
            bearer_token: None,
            peer: None,
            origin: ConnectionOrigin::Remote,
        }
    }
}

/// Enforcement mode for the method gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Log violations but allow all calls (backward-compatible default).
    Permissive,
    /// Reject unauthenticated calls to protected methods.
    Enforced,
}

impl EnforcementMode {
    /// Resolve from `SWEETGRASS_AUTH_MODE` env var.
    /// Defaults to `Permissive` if unset or unrecognized.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var(env_vars::SWEETGRASS_AUTH_MODE)
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "enforced" | "enforce" | "strict" => Self::Enforced,
            _ => Self::Permissive,
        }
    }

    /// Human-readable label for diagnostics and `auth.mode` responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permissive => "permissive",
            Self::Enforced => "enforced",
        }
    }
}

/// Pre-dispatch gate that checks caller authorization before method execution.
#[derive(Debug)]
pub struct MethodGate {
    mode: EnforcementMode,
}

/// JSON-RPC error codes for method gate rejections.
pub mod error_codes {
    /// Caller identity could not be established.
    pub const UNAUTHORIZED: i32 = -32_000;
    /// Caller lacks a valid capability token for the requested method.
    pub const PERMISSION_DENIED: i32 = -32_001;
}

impl MethodGate {
    /// Create a gate with the given enforcement mode.
    #[must_use]
    pub const fn new(mode: EnforcementMode) -> Self {
        Self { mode }
    }

    /// Create a gate from the environment (`SWEETGRASS_AUTH_MODE`).
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(EnforcementMode::from_env())
    }

    /// Current enforcement mode.
    #[must_use]
    pub const fn enforcement_mode(&self) -> EnforcementMode {
        self.mode
    }

    /// Pre-dispatch authorization check.
    ///
    /// Returns `Ok(())` if the call should proceed.
    ///
    /// # Errors
    ///
    /// Returns `Err((code, message))` with `PERMISSION_DENIED` when a
    /// protected method is called without a valid capability token and
    /// the gate is in `Enforced` mode.
    pub fn check(&self, method: &str, caller: &CallerContext) -> Result<(), (i32, String)> {
        let level = classify_method(method);

        if level == MethodAccessLevel::Public {
            return Ok(());
        }

        if caller.bearer_token.is_some() {
            return Ok(());
        }

        match self.mode {
            EnforcementMode::Permissive => {
                tracing::warn!(
                    method,
                    caller_uid = caller.peer.as_ref().map(|p| p.uid),
                    caller_pid = caller.peer.as_ref().and_then(|p| p.pid),
                    "method gate: unauthenticated call to protected method (permissive — allowing)"
                );
                Ok(())
            },
            EnforcementMode::Enforced => {
                tracing::warn!(
                    method,
                    caller_uid = caller.peer.as_ref().map(|p| p.uid),
                    caller_pid = caller.peer.as_ref().and_then(|p| p.pid),
                    "method gate: REJECTED unauthenticated call to protected method"
                );
                Err((
                    error_codes::PERMISSION_DENIED,
                    format!("permission denied: method '{method}' requires a capability token"),
                ))
            },
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test module: unwrap is standard in tests"
)]
mod tests {
    use super::*;

    #[test]
    fn health_methods_are_public() {
        assert_eq!(classify_method("health.check"), MethodAccessLevel::Public);
        assert_eq!(
            classify_method("health.liveness"),
            MethodAccessLevel::Public
        );
        assert_eq!(
            classify_method("health.readiness"),
            MethodAccessLevel::Public
        );
    }

    #[test]
    fn identity_is_public() {
        assert_eq!(classify_method("identity.get"), MethodAccessLevel::Public);
    }

    #[test]
    fn capabilities_list_is_public() {
        assert_eq!(
            classify_method("capabilities.list"),
            MethodAccessLevel::Public
        );
        assert_eq!(
            classify_method("capability.list"),
            MethodAccessLevel::Public
        );
    }

    #[test]
    fn auth_introspection_is_public() {
        assert_eq!(classify_method("auth.check"), MethodAccessLevel::Public);
        assert_eq!(classify_method("auth.mode"), MethodAccessLevel::Public);
        assert_eq!(classify_method("auth.peer_info"), MethodAccessLevel::Public);
    }

    #[test]
    fn lifecycle_status_is_public() {
        assert_eq!(
            classify_method("lifecycle.status"),
            MethodAccessLevel::Public
        );
    }

    #[test]
    fn tools_list_is_public() {
        assert_eq!(classify_method("tools.list"), MethodAccessLevel::Public);
    }

    #[test]
    fn braid_methods_are_protected() {
        assert_eq!(
            classify_method("braid.create"),
            MethodAccessLevel::Protected
        );
        assert_eq!(classify_method("braid.query"), MethodAccessLevel::Protected);
    }

    #[test]
    fn anchoring_methods_are_protected() {
        assert_eq!(
            classify_method("anchoring.anchor"),
            MethodAccessLevel::Protected
        );
        assert_eq!(
            classify_method("anchoring.verify"),
            MethodAccessLevel::Protected
        );
    }

    #[test]
    fn provenance_methods_are_protected() {
        assert_eq!(
            classify_method("provenance.graph"),
            MethodAccessLevel::Protected
        );
    }

    #[test]
    fn attribution_methods_are_protected() {
        assert_eq!(
            classify_method("attribution.chain"),
            MethodAccessLevel::Protected
        );
        assert_eq!(
            classify_method("attribution.calculate_rewards"),
            MethodAccessLevel::Protected
        );
    }

    #[test]
    fn tools_call_is_protected() {
        assert_eq!(classify_method("tools.call"), MethodAccessLevel::Protected);
    }

    #[test]
    fn empty_method_is_protected() {
        assert_eq!(classify_method(""), MethodAccessLevel::Protected);
    }

    #[test]
    fn unknown_method_is_protected() {
        assert_eq!(
            classify_method("bonding.propose"),
            MethodAccessLevel::Protected
        );
    }

    #[test]
    fn loopback_context() {
        let ctx = CallerContext::loopback();
        assert!(ctx.peer.is_none());
        assert!(ctx.bearer_token.is_none());
        assert_eq!(ctx.origin, ConnectionOrigin::Loopback);
    }

    #[test]
    fn unix_context() {
        let ctx = CallerContext::unix();
        assert_eq!(ctx.origin, ConnectionOrigin::Unix);
    }

    #[test]
    fn remote_context() {
        let ctx = CallerContext::remote();
        assert_eq!(ctx.origin, ConnectionOrigin::Remote);
    }

    #[test]
    fn enforcement_mode_as_str() {
        assert_eq!(EnforcementMode::Permissive.as_str(), "permissive");
        assert_eq!(EnforcementMode::Enforced.as_str(), "enforced");
    }

    #[test]
    fn public_method_always_passes_enforced() {
        let gate = MethodGate::new(EnforcementMode::Enforced);
        let caller = CallerContext::loopback();
        assert!(gate.check("health.check", &caller).is_ok());
        assert!(gate.check("identity.get", &caller).is_ok());
        assert!(gate.check("capabilities.list", &caller).is_ok());
        assert!(gate.check("auth.mode", &caller).is_ok());
    }

    #[test]
    fn protected_method_passes_in_permissive_mode() {
        let gate = MethodGate::new(EnforcementMode::Permissive);
        let caller = CallerContext::loopback();
        assert!(gate.check("braid.create", &caller).is_ok());
    }

    #[test]
    fn protected_method_rejected_in_enforced_mode_without_token() {
        let gate = MethodGate::new(EnforcementMode::Enforced);
        let caller = CallerContext::loopback();
        let result = gate.check("braid.create", &caller);
        assert!(result.is_err());
        let (code, msg) = result.unwrap_err();
        assert_eq!(code, error_codes::PERMISSION_DENIED);
        assert!(msg.contains("braid.create"));
    }

    #[test]
    fn protected_method_passes_in_enforced_mode_with_token() {
        let gate = MethodGate::new(EnforcementMode::Enforced);
        let caller = CallerContext {
            bearer_token: Some("valid-token".to_owned()),
            peer: None,
            origin: ConnectionOrigin::Unix,
        };
        assert!(gate.check("braid.create", &caller).is_ok());
    }
}
