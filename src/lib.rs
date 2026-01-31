pub mod cache;
pub mod config;
pub mod disk;
pub mod normalize;
pub mod purge;

use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<config::Config>,
    pub cache: Arc<cache::Cache>,
    pub client: reqwest::Client,
}
