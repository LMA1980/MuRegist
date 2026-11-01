use std::path::PathBuf;
use std::sync::Arc;

use crate::telemetry::{MuObserveRegistrySink, RegistryTelemetrySink};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub root_dir: PathBuf,
    pub base_url: String,
    pub tls_ca_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub listen_addr: String,
    pub node_id: String,
    pub telemetry_sink: Arc<dyn RegistryTelemetrySink>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("/var/lib/muregist"),
            base_url: "https://registry.ci.ci.internal:8444".to_string(),
            tls_ca_path: PathBuf::from("/etc/muregist/tls/ca.crt"),
            tls_cert_path: PathBuf::from("/etc/muregist/tls/server.crt"),
            tls_key_path: PathBuf::from("/etc/muregist/tls/server.key"),
            listen_addr: "0.0.0.0:8444".to_string(),
            node_id: "node-a".to_string(),
            telemetry_sink: Arc::new(MuObserveRegistrySink::from_env()),
        }
    }
}

impl AppConfig {
    pub fn new(root_dir: impl Into<PathBuf>, base_url: impl Into<String>) -> Self {
        let root = root_dir.into();
        Self {
            root_dir: root,
            base_url: base_url.into(),
            ..Default::default()
        }
    }

    /// Attaches a custom [`RegistryTelemetrySink`] for OpenTelemetry span and audit log emission.
    #[must_use]
    pub fn with_telemetry_sink(mut self, sink: Arc<dyn RegistryTelemetrySink>) -> Self {
        self.telemetry_sink = sink;
        self
    }

    /// Sets the logical node identifier emitted on OpenTelemetry records.
    #[must_use]
    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = node_id.into();
        self
    }

    pub fn catalog_path(&self) -> PathBuf {
        self.root_dir.join("catalog.duckdb")
    }

    pub fn cargo_index_dir(&self) -> PathBuf {
        self.root_dir.join("index").join("cargo")
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root_dir.join("blobs").join("sha256")
    }

    pub fn tmp_dir(&self) -> PathBuf {
        self.root_dir.join("tmp")
    }

    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(val) = std::env::var("MUREGIST_ROOT_DIR") {
            cfg.root_dir = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_BASE_URL") {
            cfg.base_url = val;
        }
        if let Ok(val) = std::env::var("MUREGIST_TLS_CA") {
            cfg.tls_ca_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_TLS_CERT") {
            cfg.tls_cert_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_TLS_KEY") {
            cfg.tls_key_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("MUREGIST_LISTEN_ADDR") {
            cfg.listen_addr = val;
        }
        cfg
    }
}
