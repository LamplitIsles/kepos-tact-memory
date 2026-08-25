//! End-to-end protocol tests through the HTTP router, simulating exactly what a Kepos
//! publisher injects: `Authorization: Kepos <subscriber-public-key>` plus the caller's
//! `x-tact-memory-namespace` assertion. Response shapes are validated against the constraints
//! the tact client enforces (see `crates/memory/src/store/remote/client.rs`).

use std::collections::HashSet;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kepos_tact_memory::auth::{Binding, KeposPolicy};
use kepos_tact_memory::router::{ServerState, router};
use serde_json::{Value, json};
use tact_memory::RemoteRole;
use tower::ServiceExt;

fn key(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn writer_binding(namespace: &str, keys: Vec<String>) -> Binding {
    Binding::new(namespace.to_owned(), RemoteRole::Writer, keys).unwrap()
}

fn app(policy: KeposPolicy) -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let state = ServerState::new(dir.path().join("memory.sqlite3"), policy);
    (dir, router(state))
}

fn headers(public_key: &str, namespace: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Kepos {public_key}").parse().unwrap(),
    );
    headers.insert("x-tact-memory-namespace", namespace.parse().unwrap());
    headers
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    headers: HeaderMap,
    body: Option<Value>,
) -> (StatusCode, Value, HeaderMap) {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in headers.iter() {
        builder = builder.header(name, value);
    }
    let json_body = body.map(|value| serde_json::to_vec(&value).unwrap());
    if json_body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let body = json_body.map(Body::from).unwrap_or_else(Body::empty);
    let request = builder.body(body).unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let response_headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value, response_headers)
}

#[tokio::test]
async fn session_reports_protocol_namespace_and_writer_role() {
    let writer = key(0x01);
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());
    let (status, body, _) =
        request(&app, "GET", "/v1/session", headers(&writer, "neil"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["protocol_version"], json!(1));
    assert_eq!(body["namespace"], json!("neil"));
    assert_eq!(body["role"], json!("writer"));
}

#[tokio::test]
async fn put_read_scan_list_export_delete_round_trip() {
    let writer = key(0x02);
    let namespace = "neil".to_owned();
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());
    let auth_headers = headers(&writer, &namespace);

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "The team uses cargo nextest in CI."})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let put_memory = body["memory"].clone();
    assert_eq!(put_memory["key"]["namespace"], json!(namespace));
    assert_eq!(put_memory["key"]["version"], json!(1));
    assert_eq!(
        put_memory["content"],
        json!("The team uses cargo nextest in CI.")
    );
    let id = put_memory["key"]["id"].as_i64().unwrap();

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/scan",
        auth_headers.clone(),
        Some(json!({"query": "cargo nextest", "limit": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let candidates = body["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(candidates[0]["preview"].as_str().unwrap().len() <= 64);
    assert!(candidates[0]["score"].as_f64().unwrap() >= 0.0);

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/read",
        auth_headers.clone(),
        Some(json!({"ids": [id]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let memories = body["memories"].as_array().unwrap();
    assert_eq!(memories.len(), 1);
    assert_eq!(memories[0]["key"]["id"], json!(id));
    assert_eq!(memories[0]["use_count"], json!(1));
    assert!(memories[0]["probation_until_ms"].is_null());

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/list",
        auth_headers.clone(),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["memories"].as_array().unwrap().len(), 1);

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/export",
        auth_headers.clone(),
        Some(json!({"namespaces": null, "limit": 128})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["memories"].as_array().unwrap().len(), 1);
    assert!(body["next_cursor"].is_null());

    let (status, _, _) = request(
        &app,
        "POST",
        "/v1/memories/delete",
        auth_headers.clone(),
        Some(json!({"key": {"namespace": namespace, "id": id, "version": 1}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/list",
        auth_headers.clone(),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["memories"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn replace_increments_version_and_conflicts_on_stale_keys() {
    let writer = key(0x03);
    let namespace = "neil".to_owned();
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());
    let auth_headers = headers(&writer, &namespace);

    let (_, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "v1"})),
    )
    .await;
    let id = body["memory"]["key"]["id"].as_i64().unwrap();

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "v2 replacement", "replacement": {"namespace": namespace, "id": id, "version": 1}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["memory"]["key"]["version"], json!(2));

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "stale replacement", "replacement": {"namespace": namespace, "id": id, "version": 1}})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], json!("conflict"));
}

#[tokio::test]
async fn namespace_assertion_mismatch_is_forbidden() {
    let writer = key(0x04);
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());
    let mut wrong = headers(&writer, "neil");
    wrong.insert("x-tact-memory-namespace", "alice".parse().unwrap());
    let (status, body, _) = request(&app, "GET", "/v1/session", wrong, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], json!("namespace_mismatch"));
}

#[tokio::test]
async fn missing_or_unknown_authorization_is_unauthorized() {
    let writer = key(0x05);
    let stranger = key(0x06);
    let namespace = "neil".to_owned();
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());

    let (status, body, response_headers) =
        request(&app, "GET", "/v1/session", HeaderMap::new(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
    assert_eq!(
        response_headers.get(header::WWW_AUTHENTICATE).unwrap(),
        "Kepos"
    );

    let (status, _, _) = request(
        &app,
        "GET",
        "/v1/session",
        headers(&stranger, "stranger"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let mut forged = HeaderMap::new();
    forged.insert(header::AUTHORIZATION, "Bearer something".parse().unwrap());
    forged.insert("x-tact-memory-namespace", namespace.parse().unwrap());
    let (status, body, _) = request(&app, "GET", "/v1/session", forged, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], json!("unauthorized"));
}

#[tokio::test]
async fn readonly_devices_cannot_mutate() {
    let observer = key(0x07);
    let namespace = "observer".to_owned();
    let binding = Binding::new(
        "observer".to_owned(),
        RemoteRole::Reader,
        vec![observer.clone()],
    )
    .unwrap();
    let (_, app) = app(KeposPolicy::new([binding]).unwrap());
    let auth_headers = headers(&observer, &namespace);

    let (status, body, _) = request(&app, "GET", "/v1/session", auth_headers.clone(), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], json!("reader"));

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "nope"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], json!("forbidden"));
}

#[tokio::test]
async fn bounds_and_shape_errors_map_to_stable_codes() {
    let writer = key(0x08);
    let namespace = "neil".to_owned();
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());
    let auth_headers = headers(&writer, &namespace);

    let long_query = "x".repeat(513);
    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/scan",
        auth_headers.clone(),
        Some(json!({"query": long_query, "limit": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["code"], json!("query_too_large"));

    let long_content = "x".repeat(1025);
    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": long_content})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["code"], json!("content_too_large"));

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "   "})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], json!("bad_request"));

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/scan",
        auth_headers.clone(),
        Some(json!({"query": "ok", "limit": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], json!("bad_request"));
}

#[tokio::test]
async fn scan_spans_all_visible_namespaces() {
    let alice = key(0x09);
    let bob = key(0x0a);
    let alice_ns = "alice".to_owned();
    let bob_ns = "bob".to_owned();
    let (_, app) = app(KeposPolicy::new([
        writer_binding("alice", vec![alice.clone()]),
        writer_binding("bob", vec![bob.clone()]),
    ])
    .unwrap());

    for (pk, ns, content) in [
        (&alice, &alice_ns, "alice shared fact"),
        (&bob, &bob_ns, "bob shared fact"),
    ] {
        let (status, _, _) = request(
            &app,
            "POST",
            "/v1/memories/put",
            headers(pk, ns),
            Some(json!({"content": content})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/scan",
        headers(&alice, &alice_ns),
        Some(json!({"query": "shared fact", "limit": 5})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let namespaces = body["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| candidate["key"]["namespace"].as_str().unwrap().to_owned())
        .collect::<HashSet<_>>();
    assert!(namespaces.contains(&alice_ns));
    assert!(namespaces.contains(&bob_ns));
}

#[tokio::test]
async fn sync_reconciles_a_namespace_snapshot() {
    let writer = key(0x0b);
    let namespace = "neil".to_owned();
    let (_, app) = app(KeposPolicy::new([writer_binding("neil", vec![writer.clone()])]).unwrap());
    let auth_headers = headers(&writer, &namespace);

    let snapshot = json!({
        "memories": [
            {"key": {"id": 1, "version": 1}, "content": "snapshot one", "created_at_ms": 1, "updated_at_ms": 1,
             "last_scanned_at_ms": null, "scan_count": 0, "last_used_at_ms": null, "use_count": 0, "probation_until_ms": null}
        ]
    });
    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/sync",
        auth_headers.clone(),
        Some(snapshot),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["inserted"], json!(1));
    assert_eq!(body["deleted"], json!(0));

    let empty = json!({"memories": []});
    let (status, body, _) = request(
        &app,
        "POST",
        "/v1/memories/sync",
        auth_headers.clone(),
        Some(empty),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], json!(1));

    // IDs observed in snapshots are not reused by later inserts.
    let (_, body, _) = request(
        &app,
        "POST",
        "/v1/memories/put",
        auth_headers.clone(),
        Some(json!({"content": "fresh"})),
    )
    .await;
    assert!(body["memory"]["key"]["id"].as_i64().unwrap() > 1);
}
