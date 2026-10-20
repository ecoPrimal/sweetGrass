// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024–2026 ecoPrimals Project

use super::*;

#[tokio::test]
async fn test_service_info_to_primal() {
    use super::ServiceInfo;
    use super::ServiceInfoExt;

    let info = ServiceInfo::new("svc-1", "test-service")
        .with_version("1.0.0")
        .with_endpoint(format!("tarpc:{}", crate::testing::TEST_TARPC_URI))
        .with_endpoint(format!("rest:{}", crate::testing::TEST_REST_URL))
        .with_capability("signing")
        .with_capability("anchoring");

    let primal = info.to_primal();
    assert_eq!(primal.instance_id, "svc-1");
    assert_eq!(primal.name, "test-service");
    assert!(primal.offers(&Capability::Signing));
    assert!(primal.offers(&Capability::Anchoring));
    assert!(primal.healthy);
}

#[tokio::test]
async fn test_service_info_to_primal_empty_capabilities() {
    use super::ServiceInfo;
    use super::ServiceInfoExt;

    let info = ServiceInfo::new("empty-svc", "empty")
        .with_version("1.0.0");

    let primal = info.to_primal();
    assert_eq!(primal.instance_id, "empty-svc");
    assert!(primal.capabilities.is_empty());
}

#[tokio::test]
async fn test_service_info_to_primal_mixed_capabilities() {
    use super::ServiceInfo;
    use super::ServiceInfoExt;

    let info = ServiceInfo::new("mixed-svc", "mixed")
        .with_version("1.0.0")
        .with_capability("signing")
        .with_capability("unknown_xyz");

    let primal = info.to_primal();
    assert!(primal.offers(&Capability::Signing));
    assert!(primal.offers(&Capability::Custom("unknown_xyz".to_string())));
}

#[tokio::test]
async fn test_service_info_to_primal_filters_invalid_capability_strings() {
    use super::ServiceInfo;
    use super::ServiceInfoExt;

    let mut info = ServiceInfo::new("filter-svc", "filter")
        .with_version("1.0.0")
        .with_capability("signing");
    info.capabilities.push(String::new());

    let primal = info.to_primal();
    assert_eq!(primal.capabilities.len(), 1);
    assert!(primal.offers(&Capability::Signing));
}

#[tokio::test]
async fn test_service_info_to_primal_custom_capability() {
    use super::ServiceInfo;
    use super::ServiceInfoExt;

    let mut info = ServiceInfo::new("custom-svc", "custom")
        .with_version("1.0.0")
        .with_capability("custom:my_feature");
    info.status = cellmembrane_types::EcosystemServiceStatus::Error;
    info.metadata.insert("last_seen".into(), "1700000000".into());

    let primal = info.to_primal();
    assert!(primal.offers(&Capability::Custom("my_feature".to_string())));
    assert!(!primal.healthy);
}
