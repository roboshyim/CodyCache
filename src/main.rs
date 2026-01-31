use axum::{
    extract::{ConnectInfo, State},
    http::{Method, Request, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{info, warn};

use codycache::{cache, config::Config, normalize, purge, AppState};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cfg = Arc::new(Config::from_env().expect("config"));
    let cache = Arc::new(codycache::cache::Cache::new(&cfg.cache_dir).expect("cache"));

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("reqwest client");

    let state = AppState { cfg, cache, client };

    let app = Router::new().route("/*path", any(handle)).with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&state.cfg.listen).await.expect("bind");
    info!(listen = %state.cfg.listen, origin = %state.cfg.origin, cache_dir = %state.cfg.cache_dir, "CodyCache listening");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("serve");
}

async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // PURGE/BAN handling
    if method == Method::from_bytes(b"PURGE").unwrap() || method == Method::from_bytes(b"BAN").unwrap() {
        if !purge::is_purger_allowed(peer.ip(), &state.cfg.purgers) {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }

        if method == Method::from_bytes(b"PURGE").unwrap() {
            return purge::handle_purge(state.cache.clone(), &uri, req.headers()).into_response();
        } else {
            return purge::handle_ban(state.cache.clone(), &uri).into_response();
        }
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
    if normalize::is_pass_path(uri.path()) {
        return proxy_only(state, peer, req).await;
    }

    // Special-case widgets checkout info
    if uri.path() == "/widgets/checkout/info" {
        if normalize::should_short_circuit_widgets_checkout_info(&req) {
            return (StatusCode::NO_CONTENT, "").into_response();
        }
    }

    match cache::handle_cached(state.clone(), peer, req).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(error = %e, %uri, "cache handler error; proxying");
            // fall back to a direct proxy using the original URI
            proxy_only(state, peer, Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap()).await
        }
    }
}

async fn proxy_only(state: AppState, peer: SocketAddr, req: Request<axum::body::Body>) -> axum::response::Response {
    let mut headers = req.headers().clone();
    normalize::apply_forwarded_for(&mut headers, peer.ip());
    headers.insert(
        http::header::HeaderName::from_static("surrogate-capability"),
        http::HeaderValue::from_static("shopware=ESI/1.0"),
    );

    let (parts, body) = req.into_parts();
    let upstream_url = normalize::build_upstream_url(&state.cfg.origin, &parts.uri);

    // Buffering for now (later: streaming)
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default();

    match state
        .client
        .request(parts.method, upstream_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(up) => {
            let status = up.status();
            let mut headers = up.headers().clone();
            let bytes = up.bytes().await.unwrap_or_default();

            normalize::apply_client_cache_policy(&parts.uri, &mut headers);
            normalize::strip_internal_headers(&mut headers);

            let mut resp = axum::response::Response::builder()
                .status(status)
                .body(axum::body::Body::from(bytes))
                .unwrap();
            *resp.headers_mut() = headers;
            resp
        }
        Err(err) => {
            warn!(error = %err, "upstream error");
            (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
        }
    }
}
