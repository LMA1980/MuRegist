pub mod canary;

use crate::api::canary::AppState;
use crate::frontend::cargo::CargoSparseFrontend;
use crate::frontend::{Maven2Frontend, NuGetV3Frontend, RegistryFrontend};
use axum::Router;

pub use canary::canary_router;

/// Assembles all routes across Frontends and APIs into a unified Axum Router.
pub fn build_app_router(state: AppState) -> Router {
    let cargo_fe = CargoSparseFrontend;
    let nuget_fe = NuGetV3Frontend;
    let maven_fe = Maven2Frontend;

    Router::new()
        .merge(cargo_fe.router())
        .merge(nuget_fe.router())
        .merge(maven_fe.router())
        .merge(canary_router())
        .with_state(state)
}
