// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project

use std::sync::atomic::Ordering;

use sweet_grass_core::agent::Did;
use sweet_grass_store::{QueryFilter, QueryOrder};
use tarpc::context;
use tarpc::serde_transport::tcp;
use tarpc::tokio_serde::formats::Bincode;

use crate::rpc::{CreateBraidRequest, SweetGrassRpcClient};
use crate::server::run_tarpc_server;
use crate::server::tests::{COUNTER, make_server};

/// Bind `:0`, keep the listener, return (listener, addr).
async fn bind_ephemeral() -> (tokio::net::TcpListener, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let addr = listener.local_addr().expect("local_addr");
    (listener, addr)
}

/// Spawn tarpc server on a pre-bound listener — no port-rebind race.
fn spawn_server(
    listener: tokio::net::TcpListener,
    server: crate::server::SweetGrassServer,
) -> (
    tokio::task::JoinHandle<std::result::Result<(), crate::ServiceError>>,
    tokio::sync::watch::Sender<bool>,
) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move { run_tarpc_server(listener, server, shutdown_rx).await });
    (handle, shutdown_tx)
}

#[tokio::test]
async fn test_start_tarpc_server_binds_and_accepts() {
    let (listener, addr) = bind_ephemeral().await;
    let server = make_server();
    let (handle, _shutdown_tx) = spawn_server(listener, server);

    let transport = tcp::connect(addr, Bincode::default).await.expect("connect");
    let client = SweetGrassRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let status = client
        .health_check(context::current())
        .await
        .expect("tarpc transport")
        .expect("rpc call");
    assert!(status.healthy);

    handle.abort();
}

#[tokio::test]
async fn test_tarpc_roundtrip_braid_crud() {
    let (listener, addr) = bind_ephemeral().await;
    let server = make_server();
    let (handle, _shutdown_tx) = spawn_server(listener, server);

    let transport = tcp::connect(addr, Bincode::default).await.expect("connect");
    let client = SweetGrassRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let request = CreateBraidRequest {
        data_hash: format!("sha256:tarpc{}", COUNTER.fetch_add(1, Ordering::SeqCst)).into(),
        mime_type: "text/plain".to_string(),
        size: 1024,
        attributed_to: Did::new("did:key:z6MkTest"),
        activity: None,
        derived_from: vec![],
        metadata: None,
    };

    let braid = client
        .create_braid(context::current(), request)
        .await
        .expect("tarpc transport")
        .expect("rpc call");

    let retrieved = client
        .get_braid(context::current(), braid.id.clone())
        .await
        .expect("tarpc transport")
        .expect("rpc call");
    assert_eq!(retrieved.as_ref().map(|b| &b.id), Some(&braid.id));

    let query_result = client
        .query_braids(
            context::current(),
            QueryFilter::new(),
            QueryOrder::NewestFirst,
        )
        .await
        .expect("tarpc transport")
        .expect("rpc call");
    assert!(query_result.total_count >= 1);

    let deleted = client
        .delete_braid(context::current(), braid.id.clone())
        .await
        .expect("tarpc transport")
        .expect("rpc call");
    assert!(deleted);

    let after = client
        .get_braid(context::current(), braid.id)
        .await
        .expect("tarpc transport")
        .expect("rpc call");
    assert!(after.is_none());

    handle.abort();
}

#[tokio::test]
async fn test_tarpc_health_liveness_and_readiness() {
    let (listener, addr) = bind_ephemeral().await;
    let server = make_server();
    let (handle, _shutdown_tx) = spawn_server(listener, server);

    let transport = tcp::connect(addr, Bincode::default).await.expect("connect");
    let client = SweetGrassRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let live = client
        .health_liveness(context::current())
        .await
        .expect("tarpc transport");
    assert!(live);

    let ready = client
        .health_readiness(context::current())
        .await
        .expect("tarpc transport");
    assert!(ready);

    handle.abort();
}

#[tokio::test]
async fn test_tarpc_status() {
    let (listener, addr) = bind_ephemeral().await;
    let server = make_server();
    let (handle, _shutdown_tx) = spawn_server(listener, server);

    let transport = tcp::connect(addr, Bincode::default).await.expect("connect");
    let client = SweetGrassRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let svc = client
        .status(context::current())
        .await
        .expect("tarpc transport")
        .expect("rpc call");

    assert!(svc.healthy);
    assert_eq!(svc.store_type, "memory");
    assert_eq!(svc.braid_count, 0);
    assert_eq!(svc.version, env!("CARGO_PKG_VERSION"));

    handle.abort();
}

#[tokio::test]
async fn test_tarpc_health_readiness_count_failing_store() {
    let (listener, addr) = bind_ephemeral().await;
    let server = super::make_count_failing_server();
    let (handle, _shutdown_tx) = spawn_server(listener, server);

    let transport = tcp::connect(addr, Bincode::default).await.expect("connect");
    let client = SweetGrassRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let ready = client
        .health_readiness(context::current())
        .await
        .expect("tarpc transport");
    assert!(!ready);

    let health = client
        .health_check(context::current())
        .await
        .expect("tarpc transport");
    assert!(health.is_err());

    handle.abort();
}

#[tokio::test]
async fn test_tarpc_create_braid_propagates_store_error() {
    let (listener, addr) = bind_ephemeral().await;
    let (server, fault) = super::make_fault_injection_server();
    fault.set_fail_puts(true);
    let (handle, _shutdown_tx) = spawn_server(listener, server);

    let transport = tcp::connect(addr, Bincode::default).await.expect("connect");
    let client = SweetGrassRpcClient::new(tarpc::client::Config::default(), transport).spawn();

    let request = CreateBraidRequest {
        data_hash: format!(
            "sha256:tarpc-fault{}",
            COUNTER.fetch_add(1, Ordering::SeqCst)
        )
        .into(),
        mime_type: "text/plain".to_string(),
        size: 1024,
        attributed_to: Did::new("did:key:z6MkTest"),
        activity: None,
        derived_from: vec![],
        metadata: None,
    };

    let result = client
        .create_braid(context::current(), request)
        .await
        .expect("tarpc transport");
    assert!(result.is_err());

    handle.abort();
}

#[tokio::test]
async fn test_start_tarpc_server_shutdown_exits() {
    let (listener, _addr) = bind_ephemeral().await;
    let server = make_server();
    let (handle, shutdown_tx) = spawn_server(listener, server);

    shutdown_tx.send(true).expect("signal shutdown");

    let join_result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("server should exit within timeout");

    let server_result = join_result.expect("join server task");
    assert!(server_result.is_ok());
}
