mod normalize;
mod config;
mod cache;
mod purge;

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, Method, Request, StatusCode, Uri},
    response::IntoResponse,
    routing::any,
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

use crate::{cache::Cache, config::Config, purge::is_purger_allowed};

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    cache: Arc<Cache>,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Arc::new(Config::from_env().expect("config"));
    let cache = Arc::new(Cache::new());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("reqwest client");

    let state = AppState { cfg, cache, client };

    let app = Router::new()
        .route("/*path", any(handle))
        .with_state(state);

    info!(listen = %app_state_listen(&app), "starting");

    // bind + serve
    let listener = tokio::net::TcpListener::bind(&state.cfg.listen).await.expect("bind");
    info!(listen = %state.cfg.listen, origin = %state.cfg.origin, "CodyCache listening");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("serve");
}

fn app_state_listen(_app: &Router) -> &'static str { "(see logs)" }

async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // PURGE/BAN handling (Shopware VCL parity)
    if method == Method::from_bytes(b"PURGE").unwrap() || method == Method::from_bytes(b"BAN").unwrap() {
        if !is_purger_allowed(peer.ip(), &state.cfg.purgers) {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }

        if method == Method::from_bytes(b"PURGE").unwrap() {
            return purge::handle_purge(state.cache.clone(), &uri, req.headers()).into_response();
        } else {
            return purge::handle_ban(state.cache.clone(), &uri).into_response();
        }
    }

    // Only handle relevant methods; others: "pipe" (we just proxy without caching)
    let allowed = matches!(
        method,
        Method::GET | Method::HEAD | Method::PUT | Method::POST | Method::PATCH | Method::TRACE | Method::OPTIONS | Method::DELETE
    );
    if !allowed {
        return proxy_only(state, peer, req).await;
    }

    // Authorization => pass
    if req.headers().get(http::header::AUTHORIZATION).is_some() {
        return proxy_only(state, peer, req).await;
    }

    // Only cache GET/HEAD
    if !(method == Method::GET || method == Method::HEAD) {
        return proxy_only(state, peer, req).await;
    }

    // Pass these paths
    if let Some(path) = uri.path_and_query().map(|pq| pq.path()) {
        if normalize::is_pass_path(path) {
            return proxy_only(state, peer, req).await;
        }
    }

    // Special-case widgets checkout info
    if uri.path() == "/widgets/checkout/info" {
        if normalize::should_short_circuit_widgets_checkout_info(&req) {
            return (StatusCode::NO_CONTENT, "").into_response();
        }
    }

    // Cacheable path: normalize + lookup
    match cache::handle_cached(state, peer, req).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(error = %e, %uri, "cache handler error; proxying");
            proxy_only(state, peer, e.into_request()).await
        }
    }
}

async fn proxy_only(
    state: AppState,
    peer: SocketAddr,
    req: Request<axum::body::Body>,
) -> axum::response::Response {
    let mut headers = req.headers().clone();
    normalize::apply_forwarded_for(&mut headers, peer.ip());
    headers.insert(
        http::header::HeaderName::from_static("surrogate-capability"),
        http::HeaderValue::from_static("shopware=ESI/1.0"),
    );

    let (parts, body) = req.into_parts();
    let upstream_url = normalize::build_upstream_url(&state.cfg.origin, &parts.uri);

    let mut upstream = state.client.request(parts.method, upstream_url);
    upstream = upstream.headers(headers);

    // For now: we buffer bodies to keep implementation simple.
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default();
    upstream = upstream.body(body_bytes);

    let res = upstream.send().await;
    match res {
        Ok(up) => normalize::reqwest_to_axum_response(up, &parts.uri),
        Err(err) => {
            warn!(error = %err, "upstream error");
            (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
        }
    }
}

// Small helper for error plumbing
trait IntoRequest {
    fn into_request(self) -> Request<axum::body::Body>;
}
