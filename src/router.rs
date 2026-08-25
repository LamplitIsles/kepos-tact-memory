//! Authenticated HTTP routing for the Tact remote-memory protocol.
//!
//! Routes and validation mirror the reference `MemoryServer` wrapper, with one difference:
//! authentication derives the principal from the Kepos publisher-injected `Authorization:
//! Kepos <subscriber-public-key>` header instead of a bearer-token table. The authenticated
//! namespace is passed to the store factory; a request can never select a namespace itself.

use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use tact_memory::{
    MemoryError, MemoryKey, MemoryLimits, MemoryStore, RemoteRole,
    server::protocol::{
        self, DeleteRequest, ErrorResponse, ExportRequest, ExportResponse, ListResponse,
        PutRequest, PutResponse, ReadRequest, ReadResponse, RemoteErrorCode, ScanRequest,
        ScanResponse, SessionResponse, SyncRequest,
    },
};
use tokio::time::timeout;
use tower::limit::ConcurrencyLimitLayer;
use tracing::info;

use crate::{
    auth::{self, KeposPolicy, KeposPrincipal},
    store::SqliteMemoryStore,
};

/// Covers worst-case JSON escaping for a full local corpus while bounding allocation.
const MAX_JSON_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_IN_FLIGHT_REQUESTS: usize = 64;
const STORE_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Shared router state: the database and the Kepos role policy.
#[derive(Clone)]
pub struct ServerState {
    db_path: Arc<PathBuf>,
    policy: Arc<KeposPolicy>,
}

impl ServerState {
    pub fn new(db_path: impl Into<PathBuf>, policy: KeposPolicy) -> Self {
        Self {
            db_path: Arc::new(db_path.into()),
            policy: Arc::new(policy),
        }
    }
}

/// Builds the Tact remote-memory router with Kepos device authentication.
pub fn router(state: ServerState) -> Router {
    Router::new()
        .route(&route(protocol::SESSION_PATH), get(session))
        .route(&route(protocol::SCAN_PATH), post(scan))
        .route(&route(protocol::READ_PATH), post(read))
        .route(&route(protocol::LIST_PATH), post(list))
        .route(&route(protocol::PUT_PATH), post(put))
        .route(&route(protocol::DELETE_PATH), post(delete))
        .route(&route(protocol::SYNC_PATH), post(sync))
        .route(&route(protocol::EXPORT_PATH), post(export))
        .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_IN_FLIGHT_REQUESTS))
        .with_state(state)
}

fn route(path: &str) -> String {
    format!("/{path}")
}

fn store_for(state: &ServerState, principal: &KeposPrincipal) -> SqliteMemoryStore {
    SqliteMemoryStore::new(state.db_path.as_path(), principal.namespace.clone())
}

async fn session(State(state): State<ServerState>, headers: HeaderMap) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let response = Json(SessionResponse {
        protocol_version: tact_memory::VERSION,
        namespace: principal.namespace.clone(),
        role: principal.role,
    })
    .into_response();
    info!(operation = "session", namespace = %principal.namespace, role = ?principal.role, success = true, "remote memory operation");
    response
}

async fn scan(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<ScanRequest>, JsonRejection>,
) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if request.query.len() > MemoryLimits::PRODUCTION.query_bytes
        || request.limit == 0
        || request.limit > MemoryLimits::PRODUCTION.scan_results
    {
        let error = if request.query.len() > MemoryLimits::PRODUCTION.query_bytes {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                RemoteErrorCode::QueryTooLarge,
            )
        } else {
            ApiError::bad_request()
        };
        return error.into_response();
    }
    let store = store_for(&state, &principal);
    match run_store(
        &principal,
        "scan",
        store.scan(&request.query, request.limit),
    )
    .await
    {
        Ok(scan) => Json(ScanResponse {
            candidates: scan.candidates,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn read(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<ReadRequest>, JsonRejection>,
) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if request.ids.len().saturating_add(request.keys.len()) > MemoryLimits::PRODUCTION.records
        || request.ids.iter().any(|id| *id <= 0)
        || request.keys.iter().any(|key| !valid_key(key))
    {
        return ApiError::bad_request().into_response();
    }
    let store = store_for(&state, &principal);
    match run_store(&principal, "read", store.read(&request.ids, &request.keys)).await {
        Ok(memories) => Json(ReadResponse { memories }).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn list(State(state): State<ServerState>, headers: HeaderMap) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let store = store_for(&state, &principal);
    match run_store(&principal, "list", store.list()).await {
        Ok(memories) => Json(ListResponse { memories }).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn put(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<PutRequest>, JsonRejection>,
) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    if principal.role != RemoteRole::Writer {
        return ApiError::new(StatusCode::FORBIDDEN, RemoteErrorCode::Forbidden).into_response();
    }
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if request.content.trim().is_empty() {
        return ApiError::bad_request().into_response();
    }
    if request.content.len() > MemoryLimits::PRODUCTION.content_bytes {
        return ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            RemoteErrorCode::ContentTooLarge,
        )
        .into_response();
    }
    if request.replacement.as_ref().is_some_and(|key| {
        !valid_key(key) || key.namespace.as_deref() != Some(principal.namespace.as_str())
    }) {
        return ApiError::new(StatusCode::FORBIDDEN, RemoteErrorCode::Forbidden).into_response();
    }
    let store = store_for(&state, &principal);
    match run_store(
        &principal,
        "put",
        store.put(&request.content, request.replacement),
    )
    .await
    {
        Ok(memory) => Json(PutResponse { memory }).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn delete(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<DeleteRequest>, JsonRejection>,
) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    if principal.role != RemoteRole::Writer {
        return ApiError::new(StatusCode::FORBIDDEN, RemoteErrorCode::Forbidden).into_response();
    }
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if !valid_key(&request.key)
        || request.key.namespace.as_deref() != Some(principal.namespace.as_str())
    {
        return ApiError::new(StatusCode::FORBIDDEN, RemoteErrorCode::Forbidden).into_response();
    }
    let store = store_for(&state, &principal);
    match run_store(&principal, "delete", store.delete(request.key)).await {
        Ok(()) => Json(serde_json::json!({})).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn sync(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<SyncRequest>, JsonRejection>,
) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    if principal.role != RemoteRole::Writer {
        return ApiError::new(StatusCode::FORBIDDEN, RemoteErrorCode::Forbidden).into_response();
    }
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if !valid_snapshot(&request.memories) {
        return ApiError::bad_request().into_response();
    }
    let store = store_for(&state, &principal);
    match run_store(&principal, "sync", store.sync(&request.memories)).await {
        Ok(report) => Json(report).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn export(
    State(state): State<ServerState>,
    headers: HeaderMap,
    payload: Result<Json<ExportRequest>, JsonRejection>,
) -> Response<Body> {
    let principal = match authenticate(&state, &headers) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let request = match json_payload(payload) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    if request.limit == 0
        || request.limit > protocol::MAX_EXPORT_PAGE_RECORDS
        || request.namespaces.as_ref().is_some_and(|namespaces| {
            namespaces.is_empty()
                || namespaces.len() > MemoryLimits::PRODUCTION.records
                || namespaces
                    .iter()
                    .any(|namespace| !protocol::is_valid_namespace(namespace))
        })
        || request.cursor.as_ref().is_some_and(|cursor| {
            !protocol::is_valid_namespace(&cursor.namespace) || cursor.id <= 0
        })
    {
        return ApiError::bad_request().into_response();
    }
    let store = store_for(&state, &principal);
    match run_store(
        &principal,
        "export",
        store.export_page(
            request.namespaces.as_deref(),
            request.cursor.as_ref(),
            request.limit,
        ),
    )
    .await
    {
        Ok((memories, next_cursor)) => Json(ExportResponse {
            memories,
            next_cursor,
        })
        .into_response(),
        Err(error) => error.into_response(),
    }
}

fn json_payload<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    payload.map(|Json(value)| value).map_err(|rejection| {
        let status = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        ApiError::new(status, RemoteErrorCode::BadRequest)
    })
}

fn authenticate(state: &ServerState, headers: &HeaderMap) -> Result<KeposPrincipal, ApiError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::unauthorized)?;
    let public_key =
        auth::parse_authorization(authorization).map_err(|_| ApiError::unauthorized())?;
    let (namespace, role) = state
        .policy
        .resolve(&public_key)
        .ok_or_else(ApiError::unauthorized)?;
    let asserted = headers
        .get(protocol::NAMESPACE_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(ApiError::namespace_mismatch)?;
    if asserted != namespace {
        return Err(ApiError::namespace_mismatch());
    }
    Ok(KeposPrincipal {
        public_key,
        namespace: namespace.to_owned(),
        role,
    })
}

fn valid_key(key: &MemoryKey) -> bool {
    key.id > 0
        && key.version > 0
        && key
            .namespace
            .as_deref()
            .is_none_or(protocol::is_valid_namespace)
}

fn valid_snapshot(memories: &[tact_memory::MemoryRecord]) -> bool {
    let mut ids = std::collections::HashSet::with_capacity(memories.len());
    memories.len() <= MemoryLimits::PRODUCTION.records
        && memories.iter().all(|memory| {
            memory.key.is_local()
                && valid_key(&memory.key)
                && ids.insert(memory.key.id)
                && !memory.content.trim().is_empty()
                && memory.content.len() <= MemoryLimits::PRODUCTION.content_bytes
                && memory.created_at_ms >= 0
                && memory.updated_at_ms >= memory.created_at_ms
        })
        && memories
            .iter()
            .map(|memory| memory.content.len())
            .try_fold(0usize, usize::checked_add)
            .is_some_and(|bytes| bytes <= MemoryLimits::PRODUCTION.total_content_bytes)
}

/// Applies the 30-second store deadline and maps store failures to protocol errors.
async fn run_store<T>(
    principal: &KeposPrincipal,
    operation: &'static str,
    future: impl Future<Output = Result<T, MemoryError>> + Send,
) -> Result<T, ApiError>
where
    T: Send + 'static,
{
    match timeout(STORE_OPERATION_TIMEOUT, future).await {
        Err(_) => {
            let error = ApiError::unavailable();
            info!(operation, namespace = %principal.namespace, role = ?principal.role, success = false, status = error.status.as_u16(), error_code = ?error.code, "remote memory operation");
            Err(error)
        }
        Ok(Ok(value)) => {
            info!(operation, namespace = %principal.namespace, role = ?principal.role, success = true, "remote memory operation");
            Ok(value)
        }
        Ok(Err(source)) => {
            let error = ApiError::from(source);
            info!(operation, namespace = %principal.namespace, role = ?principal.role, success = false, status = error.status.as_u16(), error_code = ?error.code, "remote memory operation");
            Err(error)
        }
    }
}

#[derive(Clone, Copy)]
struct ApiError {
    status: StatusCode,
    code: RemoteErrorCode,
}

impl ApiError {
    const fn new(status: StatusCode, code: RemoteErrorCode) -> Self {
        Self { status, code }
    }
    const fn bad_request() -> Self {
        Self::new(StatusCode::BAD_REQUEST, RemoteErrorCode::BadRequest)
    }
    const fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, RemoteErrorCode::Unauthorized)
    }
    const fn namespace_mismatch() -> Self {
        Self::new(StatusCode::FORBIDDEN, RemoteErrorCode::NamespaceMismatch)
    }
    const fn unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            RemoteErrorCode::Unavailable,
        )
    }
}

impl From<MemoryError> for ApiError {
    fn from(error: MemoryError) -> Self {
        if error.is_retryable() {
            return Self::unavailable();
        }
        match error {
            MemoryError::EmptyContent => Self::bad_request(),
            MemoryError::ContentTooLarge { .. } => Self::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                RemoteErrorCode::ContentTooLarge,
            ),
            MemoryError::QueryTooLarge { .. } => Self::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                RemoteErrorCode::QueryTooLarge,
            ),
            MemoryError::RecordCapacity { .. } => Self::new(
                StatusCode::INSUFFICIENT_STORAGE,
                RemoteErrorCode::RecordCapacity,
            ),
            MemoryError::ContentCapacity { .. } | MemoryError::StorageCapacity => Self::new(
                StatusCode::INSUFFICIENT_STORAGE,
                RemoteErrorCode::ContentCapacity,
            ),
            MemoryError::SecretRejected => Self::bad_request(),
            MemoryError::Duplicate => Self::new(StatusCode::CONFLICT, RemoteErrorCode::Duplicate),
            MemoryError::NotFound => Self::new(StatusCode::NOT_FOUND, RemoteErrorCode::NotFound),
            MemoryError::Conflict => Self::new(StatusCode::CONFLICT, RemoteErrorCode::Conflict),
            MemoryError::RemoteReadOnly => {
                Self::new(StatusCode::FORBIDDEN, RemoteErrorCode::Forbidden)
            }
            MemoryError::UnsupportedSchemaVersion { .. }
            | MemoryError::InvalidPagination
            | MemoryError::Backend { .. }
            | MemoryError::Unavailable { .. } => {
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, RemoteErrorCode::Internal)
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response<Body> {
        let mut response = (self.status, Json(ErrorResponse { code: self.code })).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(auth::AUTH_SCHEME),
            );
        }
        response
    }
}
