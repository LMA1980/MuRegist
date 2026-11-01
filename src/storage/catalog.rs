use chrono::Utc;
use duckdb::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("DuckDB error: {0}")]
    DuckDb(#[from] duckdb::Error),

    #[error("Duplicate crate version: {name} v{vers}")]
    DuplicateVersion { name: String, vers: String },

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Lock error: {0}")]
    Lock(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenScope {
    #[serde(rename = "publish")]
    Publish,
    #[serde(rename = "yank")]
    Yank,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "canary:manage")]
    CanaryManage,
}

impl TokenScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenScope::Publish => "publish",
            TokenScope::Yank => "yank",
            TokenScope::Read => "read",
            TokenScope::CanaryManage => "canary:manage",
        }
    }
}

impl fmt::Display for TokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for TokenScope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "publish" => Ok(TokenScope::Publish),
            "yank" => Ok(TokenScope::Yank),
            "read" => Ok(TokenScope::Read),
            "canary:manage" => Ok(TokenScope::CanaryManage),
            other => Err(format!("Unknown token scope: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateRecord {
    pub name: String,
    pub created_at: i64,
    pub description: Option<String>,
    pub repository: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateVersionRecord {
    pub name: String,
    pub vers: String,
    pub cksum: String,
    pub features_json: String,
    pub yanked: bool,
    pub links: Option<String>,
    pub published_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrateDepRecord {
    pub crate_name: String,
    pub crate_vers: String,
    pub dep_name: String,
    pub req: String,
    pub features_json: String,
    pub optional: bool,
    pub default_features: bool,
    pub target: Option<String>,
    pub kind: Option<String>,
    pub registry: Option<String>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryBundleRecord {
    pub bundle_id: String,
    pub service_name: String,
    pub binary_digest: String,
    pub it_archive_digest: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintedDigestRecord {
    pub digest: String,
    pub service_name: String,
    pub node_id: String,
    pub reason: String,
    pub tainted_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenRecord {
    pub token_id: String,
    pub token_hash: String,
    pub scopes_json: String,
    pub created_at: i64,
}

impl ApiTokenRecord {
    pub fn scopes(&self) -> Result<HashSet<TokenScope>, CatalogError> {
        let list: Vec<String> = serde_json::from_str(&self.scopes_json)?;
        let mut set = HashSet::new();
        for s in list {
            if let Ok(scope) = TokenScope::from_str(&s) {
                set.insert(scope);
            }
        }
        Ok(set)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryStatusSummary {
    pub status: String,
    pub active_canary_digest: Option<String>,
    pub last_promoted_digest: Option<String>,
    pub tainted_count: u32,
    pub updated_at: i64,
}

#[derive(Clone)]
pub struct DuckDbCatalog {
    conn: Arc<Mutex<Connection>>,
}

pub type Catalog = DuckDbCatalog;

impl DuckDbCatalog {
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, CatalogError> {
        let path = db_path.as_ref();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        let catalog = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        catalog.init_schema()?;
        Ok(catalog)
    }

    pub fn in_memory() -> Result<Self, CatalogError> {
        let conn = Connection::open_in_memory()?;
        let catalog = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        catalog.init_schema()?;
        Ok(catalog)
    }

    fn init_schema(&self) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS crates (
                name TEXT PRIMARY KEY,
                created_at BIGINT,
                description TEXT,
                repository TEXT
            );

            CREATE TABLE IF NOT EXISTS crate_versions (
                name TEXT,
                vers TEXT,
                cksum TEXT,
                features_json TEXT,
                yanked BOOLEAN DEFAULT FALSE,
                links TEXT,
                published_at BIGINT,
                PRIMARY KEY (name, vers)
            );

            CREATE TABLE IF NOT EXISTS crate_deps (
                crate_name TEXT,
                crate_vers TEXT,
                dep_name TEXT,
                req TEXT,
                features_json TEXT,
                optional BOOLEAN,
                default_features BOOLEAN,
                target TEXT,
                kind TEXT,
                registry TEXT,
                package TEXT
            );

            CREATE TABLE IF NOT EXISTS canary_bundles (
                bundle_id TEXT PRIMARY KEY,
                service_name TEXT,
                binary_digest TEXT,
                it_archive_digest TEXT,
                status TEXT,
                created_at BIGINT,
                updated_at BIGINT
            );

            CREATE TABLE IF NOT EXISTS tainted_digests (
                digest TEXT PRIMARY KEY,
                service_name TEXT,
                node_id TEXT,
                reason TEXT,
                tainted_at BIGINT
            );

            CREATE TABLE IF NOT EXISTS api_tokens (
                token_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                created_at BIGINT
            );
            "#,
        )?;

        Ok(())
    }

    pub fn insert_crate(
        &self,
        name: &str,
        description: Option<&str>,
        repository: Option<&str>,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();

        let mut stmt = conn.prepare(
            "INSERT OR IGNORE INTO crates (name, created_at, description, repository) VALUES (?1, ?2, ?3, ?4)"
        )?;
        stmt.execute(params![name, now, description, repository])?;
        Ok(())
    }

    pub fn get_crate(&self, name: &str) -> Result<Option<CrateRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT name, created_at, description, repository FROM crates WHERE name = ?1",
        )?;
        let mut rows = stmt.query_map(params![name], |row| {
            Ok(CrateRecord {
                name: row.get(0)?,
                created_at: row.get(1)?,
                description: row.get(2)?,
                repository: row.get(3)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_crate_version(
        &self,
        name: &str,
        vers: &str,
        cksum: &str,
        features_json: &str,
        yanked: bool,
        links: Option<&str>,
        deps: &[CrateDepRecord],
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        // Check if duplicate
        let mut check_stmt =
            conn.prepare("SELECT 1 FROM crate_versions WHERE name = ?1 AND vers = ?2")?;
        let mut existing = check_stmt.query(params![name, vers])?;
        if existing.next()?.is_some() {
            return Err(CatalogError::DuplicateVersion {
                name: name.to_string(),
                vers: vers.to_string(),
            });
        }

        let now = Utc::now().timestamp_millis();

        // Ensure crate row exists
        let mut crate_stmt = conn.prepare(
            "INSERT OR IGNORE INTO crates (name, created_at, description, repository) VALUES (?1, ?2, NULL, NULL)"
        )?;
        crate_stmt.execute(params![name, now])?;

        // Insert version
        let mut ver_stmt = conn.prepare(
            "INSERT INTO crate_versions (name, vers, cksum, features_json, yanked, links, published_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        ver_stmt.execute(params![
            name,
            vers,
            cksum,
            features_json,
            yanked,
            links,
            now
        ])?;

        // Insert deps
        let mut dep_stmt = conn.prepare(
            "INSERT INTO crate_deps (crate_name, crate_vers, dep_name, req, features_json, optional, default_features, target, kind, registry, package)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        for dep in deps {
            dep_stmt.execute(params![
                name,
                vers,
                dep.dep_name,
                dep.req,
                dep.features_json,
                dep.optional,
                dep.default_features,
                dep.target,
                dep.kind,
                dep.registry,
                dep.package,
            ])?;
        }

        Ok(())
    }

    pub fn set_crate_yanked(
        &self,
        name: &str,
        vers: &str,
        yanked: bool,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt =
            conn.prepare("UPDATE crate_versions SET yanked = ?1 WHERE name = ?2 AND vers = ?3")?;
        let count = stmt.execute(params![yanked, name, vers])?;
        if count == 0 {
            return Err(CatalogError::NotFound(format!("Crate {name} v{vers}")));
        }
        Ok(())
    }

    pub fn get_crate_versions(&self, name: &str) -> Result<Vec<CrateVersionRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT name, vers, cksum, features_json, yanked, links, published_at
             FROM crate_versions WHERE name = ?1 ORDER BY published_at ASC",
        )?;
        let rows = stmt.query_map(params![name], |row| {
            Ok(CrateVersionRecord {
                name: row.get(0)?,
                vers: row.get(1)?,
                cksum: row.get(2)?,
                features_json: row.get(3)?,
                yanked: row.get(4)?,
                links: row.get(5)?,
                published_at: row.get(6)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_crate_deps(
        &self,
        name: &str,
        vers: &str,
    ) -> Result<Vec<CrateDepRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT crate_name, crate_vers, dep_name, req, features_json, optional, default_features, target, kind, registry, package
             FROM crate_deps WHERE crate_name = ?1 AND crate_vers = ?2",
        )?;
        let rows = stmt.query_map(params![name, vers], |row| {
            Ok(CrateDepRecord {
                crate_name: row.get(0)?,
                crate_vers: row.get(1)?,
                dep_name: row.get(2)?,
                req: row.get(3)?,
                features_json: row.get(4)?,
                optional: row.get(5)?,
                default_features: row.get(6)?,
                target: row.get(7)?,
                kind: row.get(8)?,
                registry: row.get(9)?,
                package: row.get(10)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn insert_canary_bundle(&self, bundle: &CanaryBundleRecord) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "INSERT INTO canary_bundles (bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        stmt.execute(params![
            bundle.bundle_id,
            bundle.service_name,
            bundle.binary_digest,
            bundle.it_archive_digest,
            bundle.status,
            bundle.created_at,
            bundle.updated_at
        ])?;
        Ok(())
    }

    pub fn get_canary_bundle(
        &self,
        bundle_id: &str,
    ) -> Result<Option<CanaryBundleRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at
             FROM canary_bundles WHERE bundle_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![bundle_id], |row| {
            Ok(CanaryBundleRecord {
                bundle_id: row.get(0)?,
                service_name: row.get(1)?,
                binary_digest: row.get(2)?,
                it_archive_digest: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn find_bundle_by_binary_digest(
        &self,
        binary_digest: &str,
    ) -> Result<Option<CanaryBundleRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT bundle_id, service_name, binary_digest, it_archive_digest, status, created_at, updated_at
             FROM canary_bundles WHERE binary_digest = ?1 ORDER BY created_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map(params![binary_digest], |row| {
            Ok(CanaryBundleRecord {
                bundle_id: row.get(0)?,
                service_name: row.get(1)?,
                binary_digest: row.get(2)?,
                it_archive_digest: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn update_canary_bundle_status(
        &self,
        bundle_id: &str,
        status: &str,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();
        let mut stmt = conn.prepare(
            "UPDATE canary_bundles SET status = ?1, updated_at = ?2 WHERE bundle_id = ?3",
        )?;
        let updated = stmt.execute(params![status, now, bundle_id])?;
        if updated == 0 {
            return Err(CatalogError::NotFound(format!("Bundle {bundle_id}")));
        }
        Ok(())
    }

    pub fn update_bundle_status_by_binary_digest(
        &self,
        binary_digest: &str,
        status: &str,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();
        let mut stmt = conn.prepare(
            "UPDATE canary_bundles SET status = ?1, updated_at = ?2 WHERE binary_digest = ?3",
        )?;
        stmt.execute(params![status, now, binary_digest])?;
        Ok(())
    }

    pub fn taint_digest(
        &self,
        digest: &str,
        service_name: &str,
        node_id: &str,
        reason: &str,
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();
        let mut stmt = conn.prepare(
            "INSERT OR REPLACE INTO tainted_digests (digest, service_name, node_id, reason, tainted_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        stmt.execute(params![digest, service_name, node_id, reason, now])?;

        // Update corresponding canary bundle status to tainted
        let mut b_stmt = conn.prepare(
            "UPDATE canary_bundles SET status = 'tainted', updated_at = ?1 WHERE binary_digest = ?2",
        )?;
        b_stmt.execute(params![now, digest])?;

        Ok(())
    }

    pub fn is_digest_tainted(&self, digest: &str) -> Result<bool, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare("SELECT 1 FROM tainted_digests WHERE digest = ?1")?;
        let mut rows = stmt.query(params![digest])?;
        Ok(rows.next()?.is_some())
    }

    pub fn get_tainted_digest(
        &self,
        digest: &str,
    ) -> Result<Option<TaintedDigestRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT digest, service_name, node_id, reason, tainted_at FROM tainted_digests WHERE digest = ?1",
        )?;
        let mut rows = stmt.query_map(params![digest], |row| {
            Ok(TaintedDigestRecord {
                digest: row.get(0)?,
                service_name: row.get(1)?,
                node_id: row.get(2)?,
                reason: row.get(3)?,
                tainted_at: row.get(4)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn list_tainted_digests(&self) -> Result<Vec<TaintedDigestRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT digest, service_name, node_id, reason, tainted_at FROM tainted_digests ORDER BY tainted_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaintedDigestRecord {
                digest: row.get(0)?,
                service_name: row.get(1)?,
                node_id: row.get(2)?,
                reason: row.get(3)?,
                tainted_at: row.get(4)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn get_canary_status_summary(&self) -> Result<CanaryStatusSummary, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;

        // Active canary: bundle in "testing" status
        let mut test_stmt = conn.prepare(
            "SELECT binary_digest FROM canary_bundles WHERE status = 'testing' ORDER BY created_at DESC LIMIT 1",
        )?;
        let mut test_rows = test_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let active_canary_digest = test_rows.next().transpose()?;

        // Last promoted: bundle in "healthy" status
        let mut prom_stmt = conn.prepare(
            "SELECT binary_digest FROM canary_bundles WHERE status = 'healthy' ORDER BY updated_at DESC LIMIT 1",
        )?;
        let mut prom_rows = prom_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let last_promoted_digest = prom_rows.next().transpose()?;

        // Count tainted
        let mut taint_stmt = conn.prepare("SELECT COUNT(*) FROM tainted_digests")?;
        let tainted_count: i64 = taint_stmt.query_row([], |row| row.get(0))?;

        // Overall status
        // Priority:
        // If the latest bundle is testing -> "testing"
        // Else if the latest bundle is tainted -> "tainted"
        // Else if the latest bundle is healthy -> "healthy"
        // Else if there are any bundles at all -> status of most recently updated bundle
        // Default -> "healthy"
        let mut latest_stmt =
            conn.prepare("SELECT status FROM canary_bundles ORDER BY updated_at DESC LIMIT 1")?;
        let mut latest_rows = latest_stmt.query_map([], |row| row.get::<_, String>(0))?;
        let latest_status = latest_rows.next().transpose()?;

        let status = match latest_status {
            Some(s) => s,
            None => "healthy".to_string(),
        };

        let now = Utc::now().timestamp_millis();

        Ok(CanaryStatusSummary {
            status,
            active_canary_digest,
            last_promoted_digest,
            tainted_count: tainted_count as u32,
            updated_at: now,
        })
    }

    pub fn insert_api_token(
        &self,
        token_id: &str,
        token_hash: &str,
        scopes: &[TokenScope],
    ) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let now = Utc::now().timestamp_millis();
        let scopes_strings: Vec<&'static str> = scopes.iter().map(|s| s.as_str()).collect();
        let scopes_json = serde_json::to_string(&scopes_strings)?;

        let mut stmt = conn.prepare(
            "INSERT INTO api_tokens (token_id, token_hash, scopes_json, created_at) VALUES (?1, ?2, ?3, ?4)",
        )?;
        stmt.execute(params![token_id, token_hash, scopes_json, now])?;
        Ok(())
    }

    pub fn get_api_tokens(&self) -> Result<Vec<ApiTokenRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT token_id, token_hash, scopes_json, created_at FROM api_tokens ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ApiTokenRecord {
                token_id: row.get(0)?,
                token_hash: row.get(1)?,
                scopes_json: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    pub fn find_token_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<ApiTokenRecord>, CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT token_id, token_hash, scopes_json, created_at FROM api_tokens WHERE token_hash = ?1",
        )?;
        let mut rows = stmt.query_map(params![token_hash], |row| {
            Ok(ApiTokenRecord {
                token_id: row.get(0)?,
                token_hash: row.get(1)?,
                scopes_json: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;

        if let Some(r) = rows.next() {
            Ok(Some(r?))
        } else {
            Ok(None)
        }
    }

    pub fn delete_api_token(&self, token_id: &str) -> Result<(), CatalogError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| CatalogError::Lock(e.to_string()))?;
        let mut stmt = conn.prepare("DELETE FROM api_tokens WHERE token_id = ?1")?;
        stmt.execute(params![token_id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duckdb_catalog_crud_and_sql_injection_defense() {
        let catalog = DuckDbCatalog::in_memory().unwrap();

        // 1. Crate insertion
        catalog
            .insert_crate(
                "my-pkg",
                Some("A test package"),
                Some("https://example.com/repo"),
            )
            .unwrap();
        let pkg = catalog
            .get_crate("my-pkg")
            .unwrap()
            .expect("crate should exist");
        assert_eq!(pkg.name, "my-pkg");
        assert_eq!(pkg.description.as_deref(), Some("A test package"));

        // 2. Crate version and deps
        let dep = CrateDepRecord {
            crate_name: "my-pkg".to_string(),
            crate_vers: "0.1.0".to_string(),
            dep_name: "serde".to_string(),
            req: "^1.0".to_string(),
            features_json: "[]".to_string(),
            optional: false,
            default_features: true,
            target: None,
            kind: Some("normal".to_string()),
            registry: None,
            package: None,
        };
        catalog
            .insert_crate_version("my-pkg", "0.1.0", "abcdef123456", "{}", false, None, &[dep])
            .unwrap();

        // 3. Duplicate version detection
        let dup =
            catalog.insert_crate_version("my-pkg", "0.1.0", "abcdef123456", "{}", false, None, &[]);
        assert!(matches!(dup, Err(CatalogError::DuplicateVersion { .. })));

        // 4. Query versions and deps
        let versions = catalog.get_crate_versions("my-pkg").unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].vers, "0.1.0");
        assert!(!versions[0].yanked);

        let deps = catalog.get_crate_deps("my-pkg", "0.1.0").unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].dep_name, "serde");

        // 5. Yanking
        catalog.set_crate_yanked("my-pkg", "0.1.0", true).unwrap();
        let versions_after_yank = catalog.get_crate_versions("my-pkg").unwrap();
        assert!(versions_after_yank[0].yanked);

        // 6. SQL injection resistance on adversarial inputs
        let malicious_input = "' OR '1'='1'; DROP TABLE crates; --";
        catalog
            .insert_crate(malicious_input, Some("evil"), None)
            .unwrap();
        let found = catalog.get_crate(malicious_input).unwrap();
        assert!(found.is_some());

        // Verify the crates table is NOT dropped
        let original = catalog.get_crate("my-pkg").unwrap();
        assert!(original.is_some());

        // 7. Canary bundle & Taint lifecycle
        let now = Utc::now().timestamp_millis();
        let bundle = CanaryBundleRecord {
            bundle_id: "bundle-1".to_string(),
            service_name: "test-service".to_string(),
            binary_digest: "bin-digest-1".to_string(),
            it_archive_digest: "it-digest-1".to_string(),
            status: "testing".to_string(),
            created_at: now,
            updated_at: now,
        };
        catalog.insert_canary_bundle(&bundle).unwrap();

        let summary1 = catalog.get_canary_status_summary().unwrap();
        assert_eq!(summary1.status, "testing");
        assert_eq!(
            summary1.active_canary_digest.as_deref(),
            Some("bin-digest-1")
        );

        // Taint digest
        catalog
            .taint_digest(
                "bin-digest-1",
                "test-service",
                "node-a",
                "Integration test failed",
            )
            .unwrap();
        assert!(catalog.is_digest_tainted("bin-digest-1").unwrap());

        let summary2 = catalog.get_canary_status_summary().unwrap();
        assert_eq!(summary2.status, "tainted");
        assert_eq!(summary2.tainted_count, 1);

        // API Token CRUD
        catalog
            .insert_api_token(
                "tok-1",
                "hash-12345",
                &[TokenScope::Publish, TokenScope::Read],
            )
            .unwrap();
        let token = catalog.find_token_by_hash("hash-12345").unwrap().unwrap();
        let scopes = token.scopes().unwrap();
        assert!(scopes.contains(&TokenScope::Publish));
        assert!(scopes.contains(&TokenScope::Read));
        assert!(!scopes.contains(&TokenScope::Yank));
    }
}
