//! Namespaced SQLite storage for the Tact remote-memory protocol.
//!
//! One database file holds every device namespace. Reads span all visible namespaces — an
//! author can scan, read, and list their own records as well as records from other authors —
//! while mutations are bound to the authenticated namespace of each store instance. This
//! mirrors the reference server-side stores: the namespace-bound `MemoryStore` factory is the
//! only namespace source a request can influence.
//!
//! Bounds follow the shared contract: 1 KiB per record, 512 records per namespace, 256 KiB of
//! content per namespace, seven days of unread probation. Every mutation, telemetry update,
//! bound check, and snapshot reconcile runs in one Immediate transaction.

use std::{
    collections::HashSet,
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use tact_memory::{
    MemoryError, MemoryKey, MemoryLimits, MemoryRecord, MemoryScan, MemoryStore,
    normalize_identity,
    server::protocol::{self, ExportCursor, SyncReport},
};
use thiserror::Error;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SCHEMA_VERSION: i64 = 1;

const RECORD_COLUMNS: &str = "namespace, id, version, content, created_at_ms, updated_at_ms, last_scanned_at_ms, scan_count, last_used_at_ms, use_count, probation_until_ms";

/// Schema v1, the namespaced analogue of the reference D1 migration.
const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS memory_namespaces (
    namespace TEXT PRIMARY KEY NOT NULL,
    next_id INTEGER NOT NULL DEFAULT 1 CHECK (next_id > 0)
);
CREATE TABLE IF NOT EXISTS memories (
    namespace TEXT NOT NULL,
    id INTEGER NOT NULL CHECK (id > 0),
    version INTEGER NOT NULL CHECK (version > 0),
    content TEXT NOT NULL,
    identity TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    last_scanned_at_ms INTEGER,
    scan_count INTEGER NOT NULL DEFAULT 0 CHECK (scan_count >= 0),
    last_used_at_ms INTEGER,
    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    probation_until_ms INTEGER,
    PRIMARY KEY (namespace, id),
    UNIQUE (namespace, identity),
    FOREIGN KEY (namespace) REFERENCES memory_namespaces(namespace) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS memories_probation ON memories(probation_until_ms)
    WHERE probation_until_ms IS NOT NULL AND use_count = 0;
"#;

/// Namespace-bound SQLite memory store.
#[derive(Clone, Debug)]
pub struct SqliteMemoryStore {
    path: Arc<PathBuf>,
    namespace: Arc<str>,
    limits: MemoryLimits,
}

impl SqliteMemoryStore {
    /// Opens or creates the shared database and binds the store to one writer namespace.
    pub fn new(path: impl Into<PathBuf>, namespace: String) -> Self {
        Self {
            path: Arc::new(path.into()),
            namespace: Arc::from(namespace),
            limits: MemoryLimits::PRODUCTION,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_limits(
        path: impl Into<PathBuf>,
        namespace: String,
        limits: MemoryLimits,
    ) -> Self {
        Self {
            path: Arc::new(path.into()),
            namespace: Arc::from(namespace),
            limits,
        }
    }

    /// Opens a connection and ensures the schema exists.
    fn open(&self) -> Result<Connection, MemoryError> {
        prepare_private_parent(self.path.as_path())?;
        let connection = Connection::open(self.path.as_path()).map_err(sqlite_error)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "journal_mode", "DELETE")
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(sqlite_error)?;
        let found: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        if !matches!(found, 0 | SCHEMA_VERSION) {
            return Err(MemoryError::UnsupportedSchemaVersion {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        connection
            .execute_batch(SCHEMA_SQL)
            .map_err(sqlite_write_error)?;
        if found == 0 {
            connection
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(sqlite_write_error)?;
        }
        Ok(connection)
    }

    fn scan_local(
        &self,
        query: &str,
        limit: usize,
        now_ms: i64,
    ) -> Result<MemoryScan, MemoryError> {
        if query.len() > self.limits.query_bytes {
            return Err(MemoryError::QueryTooLarge {
                maximum_bytes: self.limits.query_bytes,
            });
        }
        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        prune_expired(&transaction, now_ms)?;
        let memories = load_visible(&transaction, now_ms)?
            .into_iter()
            .map(MemoryRecord::from)
            .collect::<Vec<_>>();
        let scan = MemoryScan::rank(query, &memories, limit.min(self.limits.scan_results));
        for candidate in &scan.candidates {
            let Some(namespace) = candidate.key.namespace.as_deref() else {
                continue;
            };
            transaction
                .execute(
                    "UPDATE memories
                     SET last_scanned_at_ms = ?1, scan_count = scan_count + 1
                     WHERE namespace = ?2 AND id = ?3 AND version = ?4",
                    params![
                        now_ms,
                        namespace,
                        candidate.key.id,
                        candidate.key.version as i64
                    ],
                )
                .map_err(sqlite_error)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(scan)
    }

    fn read_local(
        &self,
        ids: &[i64],
        keys: &[MemoryKey],
        now_ms: i64,
    ) -> Result<Vec<MemoryRecord>, MemoryError> {
        // Versioned keys first (any namespace), then unversioned IDs in the authenticated
        // namespace, deduplicated by logical key and preserved in caller order.
        let mut seen = HashSet::new();
        let mut references = Vec::new();
        for key in keys {
            let Some(namespace) = key.namespace.clone() else {
                continue;
            };
            if seen.insert((namespace.clone(), key.id)) {
                references.push((namespace, key.id, Some(key.version)));
            }
        }
        for id in ids {
            if seen.insert((self.namespace.to_string(), *id)) {
                references.push((self.namespace.to_string(), *id, None));
            }
        }
        if references.is_empty() {
            return Ok(Vec::new());
        }

        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        prune_expired(&transaction, now_ms)?;
        let mut records = Vec::with_capacity(references.len());
        for (namespace, id, version) in references {
            let Some(mut memory) = load_one(&transaction, &namespace, id)? else {
                continue;
            };
            if version.is_some_and(|expected| expected != memory.version) {
                continue;
            }
            transaction
                .execute(
                    "UPDATE memories
                     SET last_used_at_ms = ?1, use_count = use_count + 1, probation_until_ms = NULL
                     WHERE namespace = ?2 AND id = ?3",
                    params![now_ms, namespace, id],
                )
                .map_err(sqlite_error)?;
            memory.last_used_at_ms = Some(now_ms);
            memory.use_count = memory.use_count.saturating_add(1);
            memory.probation_until_ms = None;
            records.push(memory.into());
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(records)
    }

    fn list_local(&self, now_ms: i64) -> Result<Vec<MemoryRecord>, MemoryError> {
        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        prune_expired(&transaction, now_ms)?;
        let memories = load_visible_limit(&transaction, now_ms, self.limits.records as i64)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(memories.into_iter().map(MemoryRecord::from).collect())
    }

    fn put_local(
        &self,
        content: &str,
        replacement: Option<MemoryKey>,
        now_ms: i64,
    ) -> Result<MemoryRecord, MemoryError> {
        validate_content(content, &self.limits)?;
        let identity = normalize_identity(content);
        if identity.is_empty() {
            return Err(MemoryError::EmptyContent);
        }
        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        prune_expired(&transaction, now_ms)?;
        let result = match replacement {
            Some(key) => self.replace(&transaction, content, &identity, key, now_ms)?,
            None => self.insert(&transaction, content, &identity, now_ms)?,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(result.into())
    }

    fn insert(
        &self,
        transaction: &Transaction<'_>,
        content: &str,
        identity: &str,
        now_ms: i64,
    ) -> Result<StoredMemory, MemoryError> {
        let namespace = self.namespace.as_ref();
        if identity_exists(transaction, namespace, identity, None)? {
            return Err(MemoryError::Duplicate);
        }
        let totals = totals(transaction, namespace)?;
        if totals.records >= self.limits.records as u64 {
            return Err(MemoryError::RecordCapacity {
                maximum: self.limits.records,
            });
        }
        if totals.content_bytes.saturating_add(content.len() as u64)
            > self.limits.total_content_bytes as u64
        {
            return Err(MemoryError::ContentCapacity {
                maximum_bytes: self.limits.total_content_bytes,
            });
        }
        ensure_namespace(transaction, namespace)?;
        let probation_until_ms = now_ms.saturating_add(self.limits.probation_duration_ms);
        let id = allocate_id(transaction, namespace)?;
        transaction
            .execute(
                "INSERT INTO memories (
                    namespace, id, version, content, identity, created_at_ms, updated_at_ms,
                    last_scanned_at_ms, scan_count, last_used_at_ms, use_count, probation_until_ms
                 ) VALUES (?1, ?2, 1, ?3, ?4, ?5, ?5, NULL, 0, NULL, 0, ?6)",
                params![namespace, id, content, identity, now_ms, probation_until_ms],
            )
            .map_err(sqlite_write_error)?;
        load_one(transaction, namespace, id)?.ok_or(MemoryError::NotFound)
    }

    fn replace(
        &self,
        transaction: &Transaction<'_>,
        content: &str,
        identity: &str,
        key: MemoryKey,
        now_ms: i64,
    ) -> Result<StoredMemory, MemoryError> {
        let namespace = self.namespace.as_ref();
        if key.namespace.as_deref() != Some(namespace) {
            return Err(MemoryError::RemoteReadOnly);
        }
        let current = transaction
            .query_row(
                "SELECT version, length(CAST(content AS BLOB)) FROM memories WHERE namespace = ?1 AND id = ?2",
                params![namespace, key.id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((current_version, previous_content_bytes)) = current else {
            return Err(MemoryError::NotFound);
        };
        if current_version as u64 != key.version {
            return Err(MemoryError::Conflict);
        }
        if identity_exists(transaction, namespace, identity, Some(key.id))? {
            return Err(MemoryError::Duplicate);
        }
        let totals = totals(transaction, namespace)?;
        let resulting_bytes = totals
            .content_bytes
            .saturating_sub(previous_content_bytes as u64)
            .saturating_add(content.len() as u64);
        if resulting_bytes > self.limits.total_content_bytes as u64 {
            return Err(MemoryError::ContentCapacity {
                maximum_bytes: self.limits.total_content_bytes,
            });
        }
        let next_version = key.version.checked_add(1).ok_or(MemoryError::Conflict)?;
        let probation_until_ms = now_ms.saturating_add(self.limits.probation_duration_ms);
        transaction
            .execute(
                "UPDATE memories
                 SET version = ?1, content = ?2, identity = ?3, updated_at_ms = ?4,
                     last_scanned_at_ms = NULL, scan_count = 0,
                     last_used_at_ms = NULL, use_count = 0, probation_until_ms = ?5
                 WHERE namespace = ?6 AND id = ?7 AND version = ?8",
                params![
                    next_version as i64,
                    content,
                    identity,
                    now_ms,
                    probation_until_ms,
                    namespace,
                    key.id,
                    key.version as i64,
                ],
            )
            .map_err(sqlite_write_error)?;
        load_one(transaction, namespace, key.id)?.ok_or(MemoryError::NotFound)
    }

    fn delete_local(&self, key: MemoryKey) -> Result<(), MemoryError> {
        let namespace = self.namespace.as_ref();
        if key.namespace.as_deref() != Some(namespace) {
            return Err(MemoryError::RemoteReadOnly);
        }
        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let current_version = transaction
            .query_row(
                "SELECT version FROM memories WHERE namespace = ?1 AND id = ?2",
                params![namespace, key.id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some(current_version) = current_version else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(());
        };
        if current_version as u64 != key.version {
            return Err(MemoryError::Conflict);
        }
        transaction
            .execute(
                "DELETE FROM memories WHERE namespace = ?1 AND id = ?2",
                params![namespace, key.id],
            )
            .map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(())
    }

    fn sync_local(
        &self,
        memories: &[MemoryRecord],
        now_ms: i64,
    ) -> Result<SyncReport, MemoryError> {
        validate_snapshot(memories, &self.limits)?;
        let namespace = self.namespace.as_ref();
        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        prune_expired(&transaction, now_ms)?;
        ensure_namespace(&transaction, namespace)?;
        let previous = load_namespace(&transaction, namespace)?
            .into_iter()
            .map(MemoryRecord::from)
            .collect::<Vec<_>>();
        let incoming_ids = memories
            .iter()
            .map(|memory| memory.key.id)
            .collect::<HashSet<_>>();
        transaction
            .execute("DELETE FROM memories WHERE namespace = ?1", [namespace])
            .map_err(sqlite_write_error)?;
        let mut report = SyncReport {
            deleted: previous
                .iter()
                .filter(|record| !incoming_ids.contains(&record.key.id))
                .count(),
            ..SyncReport::default()
        };
        for memory in memories {
            let mut normalized = memory.clone();
            normalized.key.namespace = Some(namespace.to_owned());
            match previous.iter().find(|old| old.key.id == memory.key.id) {
                Some(old) if old == &normalized => report.unchanged += 1,
                Some(_) => report.replaced += 1,
                None => report.inserted += 1,
            }
            transaction
                .execute(
                    "INSERT INTO memories (
                        namespace, id, version, content, identity, created_at_ms, updated_at_ms,
                        last_scanned_at_ms, scan_count, last_used_at_ms, use_count, probation_until_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                    params![
                        namespace,
                        memory.key.id,
                        memory.key.version as i64,
                        memory.content,
                        normalize_identity(&memory.content),
                        memory.created_at_ms,
                        memory.updated_at_ms,
                        memory.last_scanned_at_ms,
                        memory.scan_count as i64,
                        memory.last_used_at_ms,
                        memory.use_count as i64,
                        memory.probation_until_ms,
                    ],
                )
                .map_err(sqlite_write_error)?;
            observe_id(&transaction, namespace, memory.key.id)?;
        }
        transaction.commit().map_err(sqlite_write_error)?;
        Ok(report)
    }

    fn export_local_page(
        &self,
        namespaces: Option<&[String]>,
        cursor: Option<&ExportCursor>,
        limit: usize,
        now_ms: i64,
    ) -> Result<(Vec<MemoryRecord>, Option<ExportCursor>), MemoryError> {
        let bounded = limit.clamp(1, protocol::MAX_EXPORT_PAGE_RECORDS);
        if namespaces.is_some_and(|selected| selected.is_empty()) {
            return Ok((Vec::new(), None));
        }
        let mut connection = self.open()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;

        let mut sql = format!(
            "SELECT {RECORD_COLUMNS} FROM memories
             WHERE (probation_until_ms IS NULL OR probation_until_ms > ?1 OR use_count != 0)",
        );
        let mut values: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now_ms)];
        if let Some(selected) = namespaces {
            sql.push_str(" AND namespace IN (");
            for (index, namespace) in selected.iter().enumerate() {
                if index > 0 {
                    sql.push_str(", ");
                }
                sql.push('?');
                values.push(Box::new(namespace.as_str()));
            }
            sql.push(')');
        }
        if let Some(cursor) = cursor {
            sql.push_str(" AND (namespace > ? OR (namespace = ? AND id > ?))");
            values.push(Box::new(cursor.namespace.as_str()));
            values.push(Box::new(cursor.namespace.as_str()));
            values.push(Box::new(cursor.id));
        }
        sql.push_str(" ORDER BY namespace, id LIMIT ?");
        values.push(Box::new(bounded as i64 + 1));

        let mut records = {
            let mut statement = transaction.prepare(&sql).map_err(sqlite_error)?;
            let rows = statement
                .query_map(
                    rusqlite::params_from_iter(values.iter().map(|value| value.as_ref())),
                    row_to_memory,
                )
                .map_err(sqlite_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)?
        };
        let has_more = records.len() > bounded;
        records.truncate(bounded);
        transaction.commit().map_err(sqlite_error)?;

        let next_cursor = has_more.then(|| {
            let last = records.last().expect("a page with more rows is non-empty");
            ExportCursor {
                namespace: last.namespace.clone(),
                id: last.id,
            }
        });
        Ok((
            records.into_iter().map(MemoryRecord::from).collect(),
            next_cursor,
        ))
    }
}

impl MemoryStore for SqliteMemoryStore {
    fn scan(
        &self,
        query: &str,
        limit: usize,
    ) -> impl Future<Output = Result<MemoryScan, MemoryError>> + Send {
        let store = self.clone();
        let query = query.to_owned();
        let now_ms = current_time_ms();
        async move { run_blocking(move || store.scan_local(&query, limit, now_ms)).await }
    }
    fn read(
        &self,
        ids: &[i64],
        keys: &[MemoryKey],
    ) -> impl Future<Output = Result<Vec<MemoryRecord>, MemoryError>> + Send {
        let store = self.clone();
        let ids = ids.to_vec();
        let keys = keys.to_vec();
        let now_ms = current_time_ms();
        async move { run_blocking(move || store.read_local(&ids, &keys, now_ms)).await }
    }
    fn list(&self) -> impl Future<Output = Result<Vec<MemoryRecord>, MemoryError>> + Send {
        let store = self.clone();
        let now_ms = current_time_ms();
        async move { run_blocking(move || store.list_local(now_ms)).await }
    }
    fn put(
        &self,
        content: &str,
        replacement: Option<MemoryKey>,
    ) -> impl Future<Output = Result<MemoryRecord, MemoryError>> + Send {
        let store = self.clone();
        let content = content.to_owned();
        let now_ms = current_time_ms();
        async move { run_blocking(move || store.put_local(&content, replacement, now_ms)).await }
    }
    fn delete(&self, key: MemoryKey) -> impl Future<Output = Result<(), MemoryError>> + Send {
        let store = self.clone();
        async move { run_blocking(move || store.delete_local(key)).await }
    }
    fn sync(
        &self,
        memories: &[MemoryRecord],
    ) -> impl Future<Output = Result<SyncReport, MemoryError>> + Send {
        let store = self.clone();
        let memories = memories.to_vec();
        let now_ms = current_time_ms();
        async move { run_blocking(move || store.sync_local(&memories, now_ms)).await }
    }
    fn export_page(
        &self,
        namespaces: Option<&[String]>,
        cursor: Option<&ExportCursor>,
        limit: usize,
    ) -> impl Future<Output = Result<(Vec<MemoryRecord>, Option<ExportCursor>), MemoryError>> + Send
    {
        let store = self.clone();
        let namespaces = namespaces.map(<[String]>::to_vec);
        let cursor = cursor.cloned();
        let now_ms = current_time_ms();
        async move {
            run_blocking(move || {
                store.export_local_page(namespaces.as_deref(), cursor.as_ref(), limit, now_ms)
            })
            .await
        }
    }
}

/// One persisted memory row with its owning namespace.
#[derive(Clone, Debug)]
struct StoredMemory {
    namespace: String,
    id: i64,
    version: u64,
    content: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    last_scanned_at_ms: Option<i64>,
    scan_count: u64,
    last_used_at_ms: Option<i64>,
    use_count: u64,
    probation_until_ms: Option<i64>,
}

impl StoredMemory {
    fn key(&self) -> MemoryKey {
        MemoryKey::remote(self.namespace.clone(), self.id, self.version)
    }
}

impl From<StoredMemory> for MemoryRecord {
    fn from(memory: StoredMemory) -> Self {
        Self {
            key: memory.key(),
            content: memory.content,
            created_at_ms: memory.created_at_ms,
            updated_at_ms: memory.updated_at_ms,
            last_scanned_at_ms: memory.last_scanned_at_ms,
            scan_count: memory.scan_count,
            last_used_at_ms: memory.last_used_at_ms,
            use_count: memory.use_count,
            probation_until_ms: memory.probation_until_ms,
        }
    }
}

async fn run_blocking<T>(
    operation: impl FnOnce() -> Result<T, MemoryError> + Send + 'static,
) -> Result<T, MemoryError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|source| MemoryError::backend(StoreTask(source)))?
}

#[derive(Debug, Error)]
#[error("memory storage task stopped unexpectedly")]
struct StoreTask(tokio::task::JoinError);

struct Totals {
    records: u64,
    content_bytes: u64,
}

fn current_time_ms() -> i64 {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(milliseconds).unwrap_or(i64::MAX)
}

fn prepare_private_parent(path: &Path) -> Result<(), MemoryError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|source| MemoryError::backend(IoError(source)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| MemoryError::backend(IoError(source)))?;
    }
    Ok(())
}

#[derive(Debug, Error)]
#[error("memory storage I/O failed")]
struct IoError(std::io::Error);

fn ensure_namespace(transaction: &Transaction<'_>, namespace: &str) -> Result<(), MemoryError> {
    transaction
        .execute(
            "INSERT INTO memory_namespaces (namespace, next_id) VALUES (?1, 1) ON CONFLICT(namespace) DO NOTHING",
            [namespace],
        )
        .map_err(sqlite_write_error)?;
    Ok(())
}

fn allocate_id(transaction: &Transaction<'_>, namespace: &str) -> Result<i64, MemoryError> {
    let recorded: i64 = transaction
        .query_row(
            "SELECT next_id FROM memory_namespaces WHERE namespace = ?1",
            [namespace],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let maximum: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(id), 0) FROM memories WHERE namespace = ?1",
            [namespace],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let id = recorded.max(maximum.checked_add(1).ok_or(MemoryError::StorageCapacity)?);
    let next_id = id.checked_add(1).ok_or(MemoryError::StorageCapacity)?;
    transaction
        .execute(
            "UPDATE memory_namespaces SET next_id = MAX(next_id, ?1) WHERE namespace = ?2",
            params![next_id, namespace],
        )
        .map_err(sqlite_write_error)?;
    Ok(id)
}

fn observe_id(transaction: &Transaction<'_>, namespace: &str, id: i64) -> Result<(), MemoryError> {
    let next_id = id.checked_add(1).ok_or(MemoryError::StorageCapacity)?;
    transaction
        .execute(
            "UPDATE memory_namespaces SET next_id = MAX(next_id, ?1) WHERE namespace = ?2",
            params![next_id, namespace],
        )
        .map_err(sqlite_write_error)?;
    Ok(())
}

fn totals(transaction: &Transaction<'_>, namespace: &str) -> Result<Totals, MemoryError> {
    transaction
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(content AS BLOB))), 0) FROM memories WHERE namespace = ?1",
            [namespace],
            |row| {
                Ok(Totals {
                    records: row.get::<_, i64>(0)? as u64,
                    content_bytes: row.get::<_, i64>(1)? as u64,
                })
            },
        )
        .map_err(sqlite_error)
}

fn identity_exists(
    transaction: &Transaction<'_>,
    namespace: &str,
    identity: &str,
    excluded_id: Option<i64>,
) -> Result<bool, MemoryError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM memories
                WHERE namespace = ?1 AND identity = ?2 AND (?3 IS NULL OR id != ?3)
             )",
            params![namespace, identity, excluded_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn prune_expired(transaction: &Transaction<'_>, now_ms: i64) -> Result<(), MemoryError> {
    transaction
        .execute(
            "DELETE FROM memories
             WHERE probation_until_ms IS NOT NULL
               AND probation_until_ms <= ?1
               AND use_count = 0",
            [now_ms],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn load_visible(
    transaction: &Transaction<'_>,
    now_ms: i64,
) -> Result<Vec<StoredMemory>, MemoryError> {
    let mut statement = transaction
        .prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM memories
             WHERE probation_until_ms IS NULL OR probation_until_ms > ?1 OR use_count != 0
             ORDER BY namespace, id",
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([now_ms], row_to_memory)
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn load_visible_limit(
    transaction: &Transaction<'_>,
    now_ms: i64,
    limit: i64,
) -> Result<Vec<StoredMemory>, MemoryError> {
    let mut statement = transaction
        .prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM memories
             WHERE probation_until_ms IS NULL OR probation_until_ms > ?1 OR use_count != 0
             ORDER BY namespace, id LIMIT ?2",
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(params![now_ms, limit], row_to_memory)
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn load_namespace(
    transaction: &Transaction<'_>,
    namespace: &str,
) -> Result<Vec<StoredMemory>, MemoryError> {
    let mut statement = transaction
        .prepare(&format!(
            "SELECT {RECORD_COLUMNS} FROM memories WHERE namespace = ?1 ORDER BY id",
        ))
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([namespace], row_to_memory)
        .map_err(sqlite_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
}

fn load_one(
    transaction: &Transaction<'_>,
    namespace: &str,
    id: i64,
) -> Result<Option<StoredMemory>, MemoryError> {
    transaction
        .query_row(
            &format!("SELECT {RECORD_COLUMNS} FROM memories WHERE namespace = ?1 AND id = ?2"),
            params![namespace, id],
            row_to_memory,
        )
        .optional()
        .map_err(sqlite_error)
}

fn row_to_memory(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMemory> {
    Ok(StoredMemory {
        namespace: row.get(0)?,
        id: row.get(1)?,
        version: row.get::<_, i64>(2)? as u64,
        content: row.get(3)?,
        created_at_ms: row.get(4)?,
        updated_at_ms: row.get(5)?,
        last_scanned_at_ms: row.get(6)?,
        scan_count: row.get::<_, i64>(7)? as u64,
        last_used_at_ms: row.get(8)?,
        use_count: row.get::<_, i64>(9)? as u64,
        probation_until_ms: row.get(10)?,
    })
}

fn validate_content(content: &str, limits: &MemoryLimits) -> Result<(), MemoryError> {
    if content.trim().is_empty() {
        return Err(MemoryError::EmptyContent);
    }
    if content.len() > limits.content_bytes {
        return Err(MemoryError::ContentTooLarge {
            maximum_bytes: limits.content_bytes,
        });
    }
    Ok(())
}

fn validate_snapshot(memories: &[MemoryRecord], limits: &MemoryLimits) -> Result<(), MemoryError> {
    if memories.len() > limits.records {
        return Err(MemoryError::RecordCapacity {
            maximum: limits.records,
        });
    }
    let mut ids = HashSet::new();
    let mut identities = HashSet::new();
    let mut bytes = 0usize;
    for memory in memories {
        if !memory.key.is_local()
            || memory.key.id <= 0
            || memory.key.version == 0
            || memory.key.version > i64::MAX as u64
            || memory.scan_count > i64::MAX as u64
            || memory.use_count > i64::MAX as u64
            || memory.created_at_ms < 0
            || memory.updated_at_ms < memory.created_at_ms
            || !ids.insert(memory.key.id)
        {
            return Err(MemoryError::Conflict);
        }
        validate_content(&memory.content, limits)?;
        if !identities.insert(normalize_identity(&memory.content)) {
            return Err(MemoryError::Duplicate);
        }
        bytes = bytes
            .checked_add(memory.content.len())
            .ok_or(MemoryError::ContentCapacity {
                maximum_bytes: limits.total_content_bytes,
            })?;
    }
    if bytes > limits.total_content_bytes {
        return Err(MemoryError::ContentCapacity {
            maximum_bytes: limits.total_content_bytes,
        });
    }
    Ok(())
}

fn sqlite_error(source: rusqlite::Error) -> MemoryError {
    let retryable = matches!(
        &source,
        rusqlite::Error::SqliteFailure(error, _)
            if matches!(error.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    );
    if retryable {
        MemoryError::unavailable(source)
    } else {
        MemoryError::backend(source)
    }
}

fn sqlite_write_error(source: rusqlite::Error) -> MemoryError {
    match &source {
        rusqlite::Error::SqliteFailure(error, _) if error.code == rusqlite::ErrorCode::DiskFull => {
            MemoryError::StorageCapacity
        }
        _ => sqlite_error(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(id: i64, content: &str) -> MemoryRecord {
        MemoryRecord {
            key: MemoryKey::local(id, 1),
            content: content.to_owned(),
            created_at_ms: 1,
            updated_at_ms: 1,
            last_scanned_at_ms: None,
            scan_count: 0,
            last_used_at_ms: None,
            use_count: 0,
            probation_until_ms: None,
        }
    }

    fn store(dir: &tempfile::TempDir, namespace: &str) -> SqliteMemoryStore {
        SqliteMemoryStore::new(dir.path().join("memory.sqlite3"), namespace.to_owned())
    }

    #[tokio::test]
    async fn put_read_replace_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir, "kepos-a");
        let memory = MemoryStore::put(&store, "The team uses cargo nextest in CI.", None)
            .await
            .unwrap();
        assert_eq!(memory.key.namespace.as_deref(), Some("kepos-a"));
        assert_eq!(memory.key.version, 1);
        assert!(memory.probation_until_ms.is_some());

        let read = MemoryStore::read(&store, &[memory.key.id], &[])
            .await
            .unwrap();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].content, memory.content);
        assert_eq!(read[0].use_count, 1);
        assert!(read[0].probation_until_ms.is_none());

        let replaced = MemoryStore::put(
            &store,
            "The team uses cargo nextest for integration tests.",
            Some(memory.key.clone()),
        )
        .await
        .unwrap();
        assert_eq!(replaced.key.version, 2);
        assert_eq!(replaced.use_count, 0);
        assert!(replaced.probation_until_ms.is_some());

        MemoryStore::delete(&store, replaced.key.clone())
            .await
            .unwrap();
        assert!(
            MemoryStore::read(&store, &[replaced.key.id], &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cas_conflicts_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir, "kepos-a");
        let memory = MemoryStore::put(&store, "original", None).await.unwrap();
        let stale = MemoryKey::remote("kepos-a".to_owned(), memory.key.id, 1);
        // A CAS against the current version succeeds.
        let current = MemoryStore::put(&store, "replacement", Some(stale.clone()))
            .await
            .unwrap();
        assert_eq!(current.key.version, 2);
        // The same CAS now conflicts, as does a delete with the stale version.
        assert!(matches!(
            MemoryStore::put(&store, "replacement", Some(stale.clone())).await,
            Err(MemoryError::Conflict)
        ));
        assert!(matches!(
            MemoryStore::delete(&store, stale).await,
            Err(MemoryError::Conflict)
        ));
        assert!(matches!(
            MemoryStore::delete(&store, current.key.clone()).await,
            Ok(())
        ));
    }

    #[tokio::test]
    async fn duplicate_identity_is_rejected_per_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir, "kepos-a");
        MemoryStore::put(&store, "The team uses cargo nextest in CI.", None)
            .await
            .unwrap();
        let duplicate =
            MemoryStore::put(&store, "  the team   USES cargo  nextest in ci. ", None).await;
        assert!(matches!(duplicate, Err(MemoryError::Duplicate)));
    }

    #[tokio::test]
    async fn namespaces_are_isolated_for_writes_and_shared_for_reads() {
        let dir = tempfile::tempdir().unwrap();
        let alice = store(&dir, "kepos-alice");
        let bob = store(&dir, "kepos-bob");
        let alice_record = MemoryStore::put(&alice, "alice fact", None).await.unwrap();
        MemoryStore::put(&bob, "bob fact", None).await.unwrap();

        let scan = MemoryStore::scan(&alice, "fact", 5).await.unwrap();
        assert_eq!(scan.candidates.len(), 2);
        let keys = scan
            .candidates
            .iter()
            .map(|candidate| candidate.key.namespace.clone().unwrap())
            .collect::<std::collections::HashSet<_>>();
        assert!(keys.contains("kepos-alice") && keys.contains("kepos-bob"));

        let foreign_read = MemoryStore::read(&alice, &[], &[bob_key_from(&scan)])
            .await
            .unwrap();
        assert_eq!(foreign_read.len(), 1);
        assert_eq!(foreign_read[0].key.namespace.as_deref(), Some("kepos-bob"));

        // Bob cannot mutate Alice's record.
        let bob_delete = MemoryStore::delete(&bob, alice_record.key.clone()).await;
        assert!(matches!(bob_delete, Err(MemoryError::RemoteReadOnly)));
    }

    fn bob_key_from(scan: &MemoryScan) -> MemoryKey {
        scan.candidates
            .iter()
            .find(|candidate| candidate.key.namespace.as_deref() == Some("kepos-bob"))
            .unwrap()
            .key
            .clone()
    }

    #[tokio::test]
    async fn sync_reconciles_a_namespace_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir, "kepos-alice");
        let incoming = vec![memory(1, "existing"), memory(2, "new fact")];
        let report = MemoryStore::sync(&store, &incoming).await.unwrap();
        assert_eq!(report.inserted, 2);
        assert_eq!(report.unchanged, 0);
        assert_eq!(report.deleted, 0);

        // An identical snapshot is fully unchanged.
        let again = MemoryStore::sync(&store, &incoming).await.unwrap();
        assert_eq!(again.unchanged, 2);

        // One changed record counts as replaced.
        let changed = vec![memory(1, "existing updated"), memory(2, "new fact")];
        let report = MemoryStore::sync(&store, &changed).await.unwrap();
        assert_eq!(report.replaced, 1);
        assert_eq!(report.unchanged, 1);

        // IDs observed in a snapshot are not reused.
        let third = MemoryStore::sync(&store, &[memory(1, "existing updated")])
            .await
            .unwrap();
        assert_eq!(third.deleted, 1);
        let inserted = MemoryStore::put(&store, "fresh", None).await.unwrap();
        assert!(inserted.key.id > 2);
    }

    #[tokio::test]
    async fn export_pages_without_omission_or_repetition() {
        let dir = tempfile::tempdir().unwrap();
        let alice = store(&dir, "kepos-alice");
        let bob = store(&dir, "kepos-bob");
        for id in 1..=3 {
            MemoryStore::put(&alice, &format!("alice {id}"), None)
                .await
                .unwrap();
        }
        MemoryStore::put(&bob, "bob fact", None).await.unwrap();

        let mut cursor = None;
        let mut collected = Vec::new();
        loop {
            let (page, next) = MemoryStore::export_page(&alice, None, cursor.as_ref(), 2)
                .await
                .unwrap();
            assert!(page.len() <= 2);
            collected.extend(page);
            match next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        assert_eq!(collected.len(), 4);
        let logical = collected
            .iter()
            .map(|m| (m.key.namespace.clone().unwrap(), m.key.id))
            .collect::<Vec<_>>();
        let mut sorted = logical.clone();
        sorted.sort();
        assert_eq!(logical, sorted);

        let (page, _) = MemoryStore::export_page(&alice, Some(&["kepos-bob".to_owned()]), None, 10)
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].key.namespace.as_deref(), Some("kepos-bob"));
    }

    #[tokio::test]
    async fn scan_graduates_only_after_read_and_records_telemetry() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir, "kepos-a");
        let memory = MemoryStore::put(&store, "sqlite facts", None)
            .await
            .unwrap();

        let scan = MemoryStore::scan(&store, "sqlite", 5).await.unwrap();
        assert_eq!(scan.candidates.len(), 1);
        assert!(scan.candidates[0].preview.len() <= 64);
        let scanned = MemoryStore::read(&store, &[memory.key.id], &[])
            .await
            .unwrap();
        assert_eq!(scanned[0].scan_count, 1);
        assert_eq!(scanned[0].use_count, 1);
        assert!(scanned[0].probation_until_ms.is_none());
    }

    #[tokio::test]
    async fn expired_unread_probation_is_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let mut limits = MemoryLimits::PRODUCTION;
        limits.probation_duration_ms = 0;
        let store = SqliteMemoryStore::with_limits(
            dir.path().join("memory.sqlite3"),
            "kepos-a".to_owned(),
            limits,
        );
        let memory = MemoryStore::put(&store, "transient", None).await.unwrap();
        // A zero probation duration is already expired at the next operation's now.
        MemoryStore::put(&store, "another", None).await.unwrap();
        let read = MemoryStore::read(&store, &[memory.key.id], &[])
            .await
            .unwrap();
        assert!(read.is_empty());
    }

    #[tokio::test]
    async fn record_capacity_is_enforced_per_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let mut limits = MemoryLimits::PRODUCTION;
        limits.records = 2;
        let store = SqliteMemoryStore::with_limits(
            dir.path().join("memory.sqlite3"),
            "kepos-a".to_owned(),
            limits,
        );
        for index in 1..=2 {
            MemoryStore::put(&store, &format!("record {index}"), None)
                .await
                .unwrap();
        }
        let result = MemoryStore::put(&store, "third record", None).await;
        assert!(matches!(
            result,
            Err(MemoryError::RecordCapacity { maximum: 2 })
        ));
    }
}
