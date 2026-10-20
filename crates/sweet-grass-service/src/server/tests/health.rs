// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project

use super::*;
use crate::rpc::RpcError;
use tarpc::context;

#[tokio::test]
async fn test_health_liveness_always_true() {
    let server = make_server();
    assert!(server.clone().health_liveness(context::current()).await);
}

#[tokio::test]
async fn test_health_readiness_healthy_store() {
    let server = make_server();
    assert!(server.health_readiness(context::current()).await);
}

#[tokio::test]
async fn test_health_readiness_count_failing_store() {
    let server = make_count_failing_server();
    assert!(!server.health_readiness(context::current()).await);
}

#[tokio::test]
async fn test_health_check_count_failing_store() {
    let server = make_count_failing_server();
    let result = server.health_check(context::current()).await;
    assert!(matches!(result, Err(RpcError::Store(_))));
}

#[tokio::test]
async fn test_status_count_failing_store() {
    let server = make_count_failing_server();
    let result = server.status(context::current()).await;
    assert!(matches!(result, Err(RpcError::Store(_))));
}

#[tokio::test]
async fn test_health_check_reports_braid_count() {
    let server = make_server();
    create_test_braid(&server).await;
    create_test_braid(&server).await;

    let status = server.health_check(context::current()).await.unwrap();
    assert!(status.healthy);
    assert_eq!(status.details.get("store_status").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(status.details.get("braid_count").and_then(|v| v.as_i64()), Some(2));
    assert_eq!(status.details.get("version").and_then(|v| v.as_str()), Some(env!("CARGO_PKG_VERSION")));
}

#[tokio::test]
async fn test_status_reports_uptime_and_braid_count() {
    let server = make_server();
    create_test_braid(&server).await;

    let status = server.status(context::current()).await.unwrap();
    assert!(status.healthy);
    assert_eq!(status.store_type, "memory");
    assert_eq!(status.braid_count, 1);
    assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
}
