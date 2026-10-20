// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project

use super::*;
use crate::rpc::TimeRange;
use sweet_grass_core::Timestamp;

#[tokio::test]
async fn test_health_check() {
    let server = make_server();
    let status = server.health_check(context::current()).await.unwrap();
    assert!(status.healthy);
    assert_eq!(status.details.get("braid_count").and_then(|v| v.as_i64()), Some(0));
}

#[tokio::test]
async fn test_status() {
    let server = make_server();
    let status = server.status(context::current()).await.unwrap();
    assert!(status.healthy);
    assert_eq!(status.store_type, "memory");
    assert_eq!(status.braid_count, 0);
}

#[tokio::test]
async fn test_create_and_get_braid() {
    let server = make_server();

    let request = CreateBraidRequest {
        data_hash: "sha256:abc123".to_string().into(),
        mime_type: "text/plain".to_string(),
        size: 1024,
        attributed_to: Did::new("did:key:z6MkTest"),
        activity: None,
        derived_from: vec![],
        metadata: None,
    };

    let braid = server
        .clone()
        .create_braid(context::current(), request)
        .await
        .unwrap();

    assert_eq!(braid.data_hash.as_str(), "sha256:abc123");

    let retrieved = server
        .get_braid(context::current(), braid.id.clone())
        .await
        .unwrap();

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().data_hash.as_str(), "sha256:abc123");
}

#[tokio::test]
async fn test_get_braid_not_found() {
    let server = make_server();
    let result = server
        .get_braid(context::current(), BraidId::new())
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_braid_by_hash() {
    let server = make_server();
    let braid = create_test_braid(&server).await;

    let retrieved = server
        .clone()
        .get_braid_by_hash(context::current(), braid.data_hash.clone())
        .await
        .unwrap();

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().id, braid.id);
}

#[tokio::test]
async fn test_get_braid_by_hash_not_found() {
    let server = make_server();
    let result = server
        .get_braid_by_hash(context::current(), "sha256:nonexistent".to_string().into())
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_query_braids() {
    let server = make_server();
    create_test_braid(&server).await;
    create_test_braid(&server).await;

    let result = server
        .query_braids(
            context::current(),
            QueryFilter::new(),
            QueryOrder::NewestFirst,
        )
        .await
        .unwrap();

    assert_eq!(result.total_count, 2);
    assert_eq!(result.braids.len(), 2);
}

#[tokio::test]
async fn test_query_braids_with_filter() {
    let server = make_server();
    let braid = create_test_braid(&server).await;

    let filter = QueryFilter::new().with_hash(braid.data_hash.clone());
    let result = server
        .query_braids(context::current(), filter, QueryOrder::NewestFirst)
        .await
        .unwrap();

    assert_eq!(result.total_count, 1);
}

#[tokio::test]
async fn test_query_braids_with_order_variants() {
    let server = make_server();
    create_test_braid(&server).await;
    create_test_braid(&server).await;

    let result_oldest = server
        .clone()
        .query_braids(
            context::current(),
            QueryFilter::new(),
            QueryOrder::OldestFirst,
        )
        .await
        .unwrap();
    assert_eq!(result_oldest.total_count, 2);

    let result_largest = server
        .clone()
        .query_braids(
            context::current(),
            QueryFilter::new(),
            QueryOrder::LargestFirst,
        )
        .await
        .unwrap();
    assert_eq!(result_largest.total_count, 2);

    let result_smallest = server
        .clone()
        .query_braids(
            context::current(),
            QueryFilter::new(),
            QueryOrder::SmallestFirst,
        )
        .await
        .unwrap();
    assert_eq!(result_smallest.total_count, 2);
}

#[tokio::test]
async fn test_delete_braid() {
    let server = make_server();
    let braid = create_test_braid(&server).await;

    let deleted = server
        .clone()
        .delete_braid(context::current(), braid.id.clone())
        .await
        .unwrap();

    assert!(deleted);

    let retrieved = server
        .get_braid(context::current(), braid.id)
        .await
        .unwrap();
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn test_delete_braid_nonexistent_returns_ok() {
    let server = make_server();

    let deleted = server
        .delete_braid(context::current(), BraidId::new())
        .await
        .unwrap();

    assert!(deleted);
}

#[tokio::test]
async fn test_braids_by_agent() {
    let server = make_server();
    create_test_braid(&server).await;

    let agent = Did::new("did:key:z6MkTest");
    let braids = server
        .braids_by_agent(context::current(), agent)
        .await
        .unwrap();

    assert_eq!(braids.len(), 1);
}

#[tokio::test]
async fn test_agent_contributions() {
    let server = make_server();
    create_test_braid(&server).await;
    create_test_braid(&server).await;

    let agent = Did::new("did:key:z6MkTest");
    let contributions = server
        .agent_contributions(context::current(), agent.clone(), None)
        .await
        .unwrap();

    assert_eq!(contributions.agent, agent);
    assert_eq!(contributions.total_count, 2);
    assert_eq!(contributions.braids.len(), 2);
}

#[tokio::test]
async fn test_agent_contributions_with_time_range() {
    let server = make_server();
    create_test_braid(&server).await;

    let agent = Did::new("did:key:z6MkTest");
    let range = TimeRange {
        start: Timestamp::ZERO,
        end: Timestamp::new(u64::MAX),
    };
    let contributions = server
        .agent_contributions(context::current(), agent, Some(range))
        .await
        .unwrap();

    assert_eq!(contributions.total_count, 1);
}

#[tokio::test]
async fn test_agent_contributions_empty_time_range() {
    let server = make_server();
    create_test_braid(&server).await;

    let agent = Did::new("did:key:z6MkTest");
    let range = TimeRange {
        start: Timestamp::ZERO,
        end: Timestamp::ZERO,
    };
    let contributions = server
        .agent_contributions(context::current(), agent, Some(range))
        .await
        .unwrap();

    assert_eq!(contributions.total_count, 0);
}

#[tokio::test]
async fn test_server_with_max_concurrent_requests() {
    let store = Arc::new(crate::backend::BraidBackend::Memory(MemoryStore::new()));
    let did = Did::new("did:key:z6MkTest");
    let factory = Arc::new(BraidFactory::new(did));
    let query = Arc::new(QueryEngine::new(store.clone()));
    let compression = Arc::new(CompressionEngine::new(factory.clone()));
    let attribution = Arc::new(AttributionCalculator::new());

    let server = SweetGrassServer::new(store, factory, query, compression, attribution)
        .with_max_concurrent_requests(42);

    let status = server.health_check(context::current()).await.unwrap();
    assert!(status.healthy);
}

#[tokio::test]
async fn test_server_with_explicit_max_concurrent_requests() {
    let store = Arc::new(crate::backend::BraidBackend::Memory(MemoryStore::new()));
    let did = Did::new("did:key:z6MkTest");
    let factory = Arc::new(BraidFactory::new(did));
    let query = Arc::new(QueryEngine::new(store.clone()));
    let compression = Arc::new(CompressionEngine::new(factory.clone()));
    let attribution = Arc::new(AttributionCalculator::new());

    let server = SweetGrassServer::new(store, factory, query, compression, attribution)
        .with_max_concurrent_requests(99);

    let status = server.health_check(context::current()).await.unwrap();
    assert!(status.healthy);
}

#[tokio::test]
async fn test_server_default_max_concurrent_requests() {
    let server = make_server();
    let status = server.health_check(context::current()).await.unwrap();
    assert!(status.healthy);
}

#[tokio::test]
async fn test_sweet_grass_server_from_app_state() {
    let state = AppState::new_memory(Did::new("did:key:z6MkTest"));
    let server = SweetGrassServer::from_app_state(&state);

    let svc = server.status(context::current()).await.expect("status");
    assert!(svc.healthy);
    assert_eq!(svc.store_type, "memory");
    assert_eq!(svc.braid_count, 0);
    assert_eq!(svc.version, env!("CARGO_PKG_VERSION"));
}
