// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project
//! `SweetGrass` `UniBin` — single binary, multiple modes.
//!
//! Follows the wateringHole `UNIBIN_ARCHITECTURE_STANDARD`:
//! - `sweetgrass server` — start REST + tarpc + JSON-RPC
//! - `sweetgrass status` — check running instance
//! - `sweetgrass --version` / `sweetgrass --help`
//!
//! Exit codes per standard:
//! - 0: success
//! - 1: general error
//! - 2: configuration error
//! - 3: network error

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

use clap::{Parser, Subcommand};
use sweet_grass_service::cli;
use sweet_grass_service::exit::exit_code;
use sweet_grass_service::{
    BootstrapConfig, StorageConfig, SweetGrassServer, create_router, infant_bootstrap_with_config,
    start_tarpc_server, start_tcp_jsonrpc_listener,
};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "sweetgrass")]
#[command(
    version,
    about = "SweetGrass — semantic provenance and attribution layer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the `SweetGrass` service (REST + JSON-RPC + tarpc).
    Server {
        /// TCP JSON-RPC bind address (newline-delimited framing, opt-in).
        ///
        /// Per Tower Atomic portability standard: TCP is opt-in only.
        /// UDS is the default transport. Accepts `host:port` (e.g.
        /// `0.0.0.0:9850`) or just a port number (e.g. `9850`, binds
        /// `127.0.0.1` — localhost-only). Pass `0` for OS-assigned on
        /// localhost. Omit to run UDS-only. Use `0.0.0.0:PORT` for
        /// all-interfaces binding in Docker/production.
        #[arg(long, env = "SWEETGRASS_PORT")]
        port: Option<String>,

        /// HTTP port shorthand (sets HTTP bind to `127.0.0.1:<PORT>`).
        ///
        /// Convenience alternative to `--http-address`. If both are given,
        /// `--http-port` takes precedence. HTTP is the primary integration
        /// surface for health probes and JSON-RPC. Use
        /// `--http-address 0.0.0.0:PORT` for all-interfaces binding.
        #[arg(long, env = "SWEETGRASS_HTTP_PORT")]
        http_port: Option<u16>,

        /// REST/JSON-RPC bind address in `host:port` format (HTTP-wrapped).
        ///
        /// Defaults to localhost-only per Tower Atomic security posture.
        /// Use `0.0.0.0:PORT` for all-interfaces binding in
        /// Docker/production. Port `0` = OS-assigned ephemeral port.
        /// The resolved address is logged at startup.
        #[arg(long, env = "SWEETGRASS_HTTP_ADDRESS", default_value = "127.0.0.1:0")]
        http_address: String,

        /// tarpc bind address (localhost-only by default).
        #[arg(long, env = "SWEETGRASS_TARPC_ADDRESS", default_value = "127.0.0.1:0")]
        tarpc_address: String,

        /// Storage backend: memory, redb.
        #[arg(short, long, env = "STORAGE_BACKEND", default_value = "memory")]
        storage: String,

        /// Storage path (if storage=redb).
        #[arg(long, env = "STORAGE_PATH")]
        storage_path: Option<String>,

        /// Log level.
        #[arg(short, long, env = "RUST_LOG", default_value = "info")]
        log_level: String,

        /// Disable tarpc server (REST/JSON-RPC only).
        #[arg(long)]
        no_tarpc: bool,

        /// Unix domain socket path override.
        ///
        /// When omitted, the socket path is resolved via the standard
        /// 5-tier fallback: `SWEETGRASS_SOCKET` → `BIOMEOS_SOCKET_DIR` →
        /// `XDG_RUNTIME_DIR/biomeos/` → `biomeos-{USER}/` → `{temp_dir}/biomeos/`.
        #[arg(long, env = "SWEETGRASS_SOCKET")]
        socket: Option<String>,

        /// Launcher-injected transport endpoint (JSON).
        ///
        /// When set, overrides `--socket` and `--port`. The launcher or
        /// Tower Atomic decides the transport — the primal doesn't self-bind.
        /// Format: `{"transport":"uds","path":"/run/membrane/sweetgrass.sock"}`
        /// or `{"transport":"tcp","host":"127.0.0.1","port":9100}`.
        #[arg(long, env = "TRANSPORT_ENDPOINT")]
        transport_endpoint: Option<String>,
    },

    /// Check status of a running `SweetGrass` instance.
    Status {
        /// Address of the running instance (discovered from env or explicit).
        #[arg(long, env = "SWEETGRASS_HTTP_ADDRESS")]
        address: String,
    },

    /// Print all capabilities this primal offers (offline, no network).
    Capabilities,

    /// Print the resolved Unix domain socket path.
    Socket,

    /// Run comprehensive health diagnostics (`ecoBin` standard).
    Doctor,
}

/// Parse `--port` argument: accepts `host:port` (e.g. `0.0.0.0:9850`)
/// or a bare port number (e.g. `9850`, binds `127.0.0.1` — localhost-only
/// by default per PG-55 security hardening). Use `0.0.0.0:PORT` for
/// all-interfaces binding in Docker/production.
fn parse_tcp_port_arg(arg: &str) -> Result<std::net::SocketAddr, String> {
    if let Ok(port) = arg.parse::<u16>() {
        return Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
    }
    cli::parse_socket_addr(arg)
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let code = match cli.command {
        Commands::Server {
            port,
            http_port,
            http_address,
            tarpc_address,
            storage,
            storage_path,
            log_level,
            no_tarpc,
            socket,
            transport_endpoint,
        } => {
            let tcp_only =
                std::env::var(sweet_grass_core::primal_names::env_vars::PRIMAL_BIND_MODE)
                    .is_ok_and(|v| v.eq_ignore_ascii_case("tcp_only"));

            let effective_http_address =
                http_port.map_or(http_address, |p| format!("127.0.0.1:{p}"));
            let tcp_address = port.map(|p| parse_tcp_port_arg(&p)).transpose();
            let tcp_address = match tcp_address {
                Ok(a) => a,
                Err(msg) => {
                    let _ = writeln!(std::io::stderr(), "Error: --port {msg}");
                    std::process::exit(exit_code::CONFIG_ERROR);
                },
            };

            let resolved_endpoint = transport_endpoint
                .as_deref()
                .map(sweet_grass_core::transport::parse_transport_endpoint)
                .transpose();
            let resolved_endpoint = match resolved_endpoint {
                Ok(ep) => ep,
                Err(e) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "Error: TRANSPORT_ENDPOINT invalid JSON: {e}"
                    );
                    std::process::exit(exit_code::CONFIG_ERROR);
                },
            };

            let effective_socket = match &resolved_endpoint {
                Some(sweet_grass_core::transport::TransportEndpoint::Uds { path }) => {
                    Some(path.clone())
                },
                _ => socket,
            };

            run_server(ServerConfig {
                tcp_address,
                http_address: effective_http_address,
                tarpc_address,
                storage,
                storage_path,
                log_level,
                no_tarpc,
                socket: effective_socket,
                transport_endpoint: resolved_endpoint,
                tcp_only,
            })
            .await
        },
        Commands::Status { address } => run_status(&address).await,
        Commands::Capabilities => run_capabilities(),
        Commands::Socket => run_socket(),
        Commands::Doctor => run_doctor(),
    };

    std::process::exit(code);
}

struct ServerConfig {
    tcp_address: Option<std::net::SocketAddr>,
    http_address: String,
    tarpc_address: String,
    storage: String,
    storage_path: Option<String>,
    log_level: String,
    no_tarpc: bool,
    #[cfg_attr(not(unix), allow(dead_code))]
    socket: Option<String>,
    tcp_only: bool,
    transport_endpoint: Option<sweet_grass_core::transport::TransportEndpoint>,
}

async fn run_server(config: ServerConfig) -> i32 {
    let level = config
        .log_level
        .parse::<tracing::Level>()
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();

    #[cfg(unix)]
    if !config.tcp_only && sweet_grass_service::uds::validate_insecure_guard().is_err() {
        tracing::error!("BIOMEOS_INSECURE not set with FAMILY_ID — refusing to start");
        return exit_code::CONFIG_ERROR;
    }

    info!("SweetGrass starting — semantic provenance and attribution layer");

    if let Some(ref ep) = config.transport_endpoint {
        info!(transport = %ep, "Transport endpoint injected by launcher");
    }

    let storage_config = StorageConfig {
        backend: config.storage.clone(),
        redb_path: config.storage_path.clone(),
        ..Default::default()
    };

    let bootstrap_config = BootstrapConfig {
        storage: storage_config,
        ..Default::default()
    };

    let bootstrap = match infant_bootstrap_with_config(bootstrap_config).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Bootstrap failed: {e}");
            return exit_code::CONFIG_ERROR;
        },
    };

    let state = bootstrap.app_state;
    info!(
        primal = %bootstrap.self_knowledge.name,
        storage = %config.storage,
        "Service initialized"
    );

    let app = create_router(state.clone());

    let http_addr = match cli::parse_socket_addr(&config.http_address).map_err(|msg| {
        tracing::error!("HTTP {msg}");
        exit_code::CONFIG_ERROR
    }) {
        Ok(a) => a,
        Err(code) => return code,
    };

    let http_listener = match tokio::net::TcpListener::bind(http_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind HTTP on {http_addr}: {e}");
            return exit_code::NETWORK_ERROR;
        },
    };

    let actual_http_addr = http_listener.local_addr().unwrap_or(http_addr);
    info!("REST + JSON-RPC 2.0 listening on http://{actual_http_addr}");
    info!("  Health: http://{actual_http_addr}/health");
    info!("  JSON-RPC: POST http://{actual_http_addr}/jsonrpc");
    info!("  REST API: http://{actual_http_addr}/api/v1/");

    serve_all(config, state, app, http_listener).await
}

#[cfg(unix)]
fn spawn_uds_listener(
    state: sweet_grass_service::AppState,
    socket: Option<&String>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) -> (Option<std::path::PathBuf>, tokio::task::JoinHandle<()>) {
    let uds_socket_path = socket.map(std::path::PathBuf::from);
    let uds_state = state;
    let shutdown_rx = shutdown_tx.subscribe();
    let explicit_path = uds_socket_path.clone();
    let handle = tokio::spawn(async move {
        let result = if let Some(ref path) = explicit_path {
            sweet_grass_service::uds::start_uds_listener_at(uds_state, path, shutdown_rx).await
        } else {
            sweet_grass_service::uds::start_uds_listener(uds_state, shutdown_rx).await
        };
        if let Err(e) = result {
            tracing::warn!("UDS listener error: {e}");
        }
    });
    (uds_socket_path, handle)
}

fn spawn_neural_announce(config: &ServerConfig, uds_socket_path: Option<&std::path::PathBuf>) {
    let own_endpoint = if config.tcp_only {
        config.tcp_address.map(|addr| {
            sweet_grass_core::transport::TransportEndpoint::tcp(addr.ip().to_string(), addr.port())
        })
    } else {
        #[cfg(unix)]
        {
            let sock = uds_socket_path.map_or_else(
                || {
                    sweet_grass_service::uds::resolve_socket_path(None)
                        .to_string_lossy()
                        .to_string()
                },
                |path| path.to_string_lossy().to_string(),
            );
            Some(sweet_grass_core::transport::TransportEndpoint::uds(sock))
        }
        #[cfg(not(unix))]
        {
            let _ = uds_socket_path;
            config.tcp_address.map(|addr| {
                sweet_grass_core::transport::TransportEndpoint::tcp(
                    addr.ip().to_string(),
                    addr.port(),
                )
            })
        }
    };

    if let Some(endpoint) = own_endpoint {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            sweet_grass_service::neural_announce::announce_to_neural_api(
                &endpoint,
                env!("CARGO_PKG_VERSION"),
            )
            .await;
        });
    }
}

async fn serve_all(
    config: ServerConfig,
    state: sweet_grass_service::AppState,
    app: axum::Router,
    http_listener: tokio::net::TcpListener,
) -> i32 {
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    let tarpc_handle = if config.no_tarpc {
        None
    } else {
        let tarpc_addr = match cli::parse_socket_addr(&config.tarpc_address).map_err(|msg| {
            tracing::error!("tarpc {msg}");
            exit_code::CONFIG_ERROR
        }) {
            Ok(a) => a,
            Err(code) => return code,
        };
        let shutdown_rx = shutdown_tx.subscribe();
        Some(spawn_tarpc_server(tarpc_addr, &state, shutdown_rx))
    };

    let tcp_jsonrpc_handle = config.tcp_address.map(|addr| {
        let tcp_state = state.clone();
        let shutdown_rx = shutdown_tx.subscribe();
        tracing::info!(%addr, "TCP JSON-RPC opt-in enabled");
        tokio::spawn(async move {
            if let Err(e) = start_tcp_jsonrpc_listener(tcp_state, addr, shutdown_rx).await {
                tracing::warn!("TCP JSON-RPC listener error: {e}");
            }
        })
    });
    if config.tcp_address.is_none() && !config.tcp_only {
        tracing::info!("TCP JSON-RPC disabled (UDS-only mode — pass --port to enable)");
    }

    #[cfg(unix)]
    let (uds_socket_path, uds_handle) = if config.tcp_only {
        tracing::info!("PRIMAL_BIND_MODE=tcp_only — UDS listener disabled");
        (None, None)
    } else {
        let (path, h) = spawn_uds_listener(state.clone(), config.socket.as_ref(), &shutdown_tx);
        (path, Some(h))
    };

    #[cfg(unix)]
    let tarpc_uds_path = if config.tcp_only || config.no_tarpc {
        None
    } else {
        let path = sweet_grass_service::tarpc_uds::resolve_tarpc_socket_path(None);
        let server = SweetGrassServer::from_app_state(&state);
        let shutdown_rx = shutdown_tx.subscribe();
        let p = path.clone();
        tokio::spawn(async move {
            if let Err(e) =
                sweet_grass_service::tarpc_uds::start_tarpc_uds_server(server, &p, shutdown_rx)
                    .await
            {
                tracing::warn!("tarpc UDS server error: {e}");
            }
        });
        Some(path)
    };

    #[cfg(unix)]
    spawn_neural_announce(&config, uds_socket_path.as_ref());
    #[cfg(not(unix))]
    spawn_neural_announce(&config, None);

    let result = axum::serve(http_listener, app)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        })
        .await;

    if let Some(h) = tarpc_handle {
        let _ = h.await;
    }
    if let Some(h) = tcp_jsonrpc_handle {
        let _ = h.await;
    }
    #[cfg(unix)]
    if let Some(h) = uds_handle {
        let _ = h.await;
    }

    #[cfg(unix)]
    if !config.tcp_only {
        if let Some(ref path) = uds_socket_path {
            sweet_grass_service::uds::cleanup_socket_at(path);
        } else {
            sweet_grass_service::uds::cleanup_socket();
        }
        if let Some(ref path) = tarpc_uds_path {
            sweet_grass_service::tarpc_uds::cleanup_tarpc_socket(path);
        }
    }

    result.map_or_else(
        |e| {
            tracing::error!("Server error: {e}");
            exit_code::GENERAL_ERROR
        },
        |()| {
            info!("SweetGrass shut down cleanly");
            exit_code::SUCCESS
        },
    )
}

fn spawn_tarpc_server(
    tarpc_addr: std::net::SocketAddr,
    state: &sweet_grass_service::AppState,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let server = SweetGrassServer::from_app_state(state);
    tokio::spawn(async move {
        info!("tarpc server starting on {tarpc_addr}");
        if let Err(e) = start_tarpc_server(tarpc_addr, server, shutdown).await {
            tracing::error!("tarpc server error: {e}");
        }
    })
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            () = async { let _ = ctrl_c.await; } => info!("Received SIGINT, shutting down gracefully"),
            () = async {
                if let Some(s) = sigterm.as_mut() {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Received SIGTERM, shutting down gracefully");
            },
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
        info!("Received shutdown signal");
    }
}

fn run_capabilities() -> i32 {
    let report = cli::capabilities_report(env!("CARGO_PKG_VERSION"));
    let output = cli::format_capabilities_report(&report);
    let _ = std::io::stdout().lock().write_all(output.as_bytes());
    exit_code::SUCCESS
}

fn run_socket() -> i32 {
    #[cfg(unix)]
    {
        let path = sweet_grass_service::uds::resolve_socket_path(None);
        let _ = writeln!(std::io::stdout().lock(), "{}", path.display());
        exit_code::SUCCESS
    }
    #[cfg(not(unix))]
    {
        tracing::error!("Unix domain sockets are not available on this platform");
        exit_code::GENERAL_ERROR
    }
}

fn run_doctor() -> i32 {
    println!("🏥 SweetGrass Health Diagnostics");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("📦 Binary Information");
    println!("   Name: sweetgrass");
    println!("   Version: {}", env!("CARGO_PKG_VERSION"));
    println!("   Role: Knowledge graph — semantic provenance & attribution");
    println!();
    #[cfg(unix)]
    {
        let path = sweet_grass_service::uds::resolve_socket_path(None);
        println!("🔌 IPC Configuration");
        println!("   Socket path: {}", path.display());
        println!();
    }
    println!("📋 Capabilities");
    let report = cli::capabilities_report(env!("CARGO_PKG_VERSION"));
    let output = cli::format_capabilities_report(&report);
    print!("{output}");
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ Health check complete!");
    exit_code::SUCCESS
}

async fn run_status(address: &str) -> i32 {
    let _ = writeln!(
        std::io::stdout().lock(),
        "Checking SweetGrass at http://{address}/health..."
    );

    match cli::http_health_check(address).await {
        Ok(body) => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let _ = writeln!(out, "SweetGrass is healthy at {address}");
            let _ = writeln!(out, "  {body}");
            exit_code::SUCCESS
        },
        Err(e) => {
            tracing::error!("Cannot reach SweetGrass at {address}: {e}");
            exit_code::NETWORK_ERROR
        },
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test module: expect/unwrap are standard in tests"
)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_port_bare_number_binds_localhost() {
        let addr = parse_tcp_port_arg("9850").expect("bare port");
        assert_eq!(addr, "127.0.0.1:9850".parse().unwrap());
    }

    #[test]
    fn parse_tcp_port_zero() {
        let addr = parse_tcp_port_arg("0").expect("ephemeral");
        assert_eq!(addr.port(), 0);
        assert!(addr.ip().is_loopback(), "bare port 0 should bind localhost");
    }

    #[test]
    fn parse_tcp_port_all_interfaces_explicit() {
        let addr = parse_tcp_port_arg("0.0.0.0:9850").expect("all-interfaces");
        assert_eq!(addr, "0.0.0.0:9850".parse().unwrap());
    }

    #[test]
    fn parse_tcp_port_host_port() {
        let addr = parse_tcp_port_arg("127.0.0.1:9850").expect("host:port");
        assert_eq!(addr, "127.0.0.1:9850".parse().unwrap());
    }

    #[test]
    fn parse_tcp_port_ipv6() {
        let addr = parse_tcp_port_arg("[::1]:9850").expect("ipv6");
        assert_eq!(addr.port(), 9850);
    }

    #[test]
    fn parse_tcp_port_invalid() {
        let err = parse_tcp_port_arg("not-valid");
        assert!(err.is_err());
    }
}
