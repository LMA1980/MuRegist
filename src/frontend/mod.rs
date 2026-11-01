pub mod cargo;

use crate::api::canary::AppState;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};

/// Trait defining pluggable artifact & package registry frontends (Cargo, NuGet, Maven, etc.)
pub trait RegistryFrontend: Send + Sync {
    fn name(&self) -> &'static str;
    fn router(&self) -> Router<AppState>;
}

/// Extensible NuGet v3 protocol frontend stub (/v3/index.json)
pub struct NuGetV3Frontend;

impl RegistryFrontend for NuGetV3Frontend {
    fn name(&self) -> &'static str {
        "nuget-v3"
    }

    fn router(&self) -> Router<AppState> {
        Router::new().route(
            "/v3/index.json",
            get(|state: axum::extract::State<AppState>| async move {
                let base_url = &state.config.base_url;
                Json(serde_json::json!({
                    "version": "3.0.0",
                    "resources": [
                        {
                            "@id": format!("{base_url}/v3/registration/"),
                            "@type": "RegistrationsBaseUrl/3.6.0",
                            "comment": "Base URL of package registration info"
                        },
                        {
                            "@id": format!("{base_url}/v3/flatcontainer/"),
                            "@type": "PackageBaseAddress/3.0.0",
                            "comment": "Base URL of flat container .nupkgs"
                        }
                    ]
                }))
            }),
        )
    }
}

/// Extensible Maven 2 protocol frontend stub (/maven2/)
pub struct Maven2Frontend;

impl RegistryFrontend for Maven2Frontend {
    fn name(&self) -> &'static str {
        "maven-2"
    }

    fn router(&self) -> Router<AppState> {
        Router::new().route(
            "/maven2/{*path}",
            get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    "Maven 2 repository frontend stub: artifact not found",
                )
                    .into_response()
            }),
        )
    }
}
