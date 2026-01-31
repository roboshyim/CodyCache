use crate::normalize;
use axum::http::{HeaderMap, Request, StatusCode, Uri};
use axum::response::IntoResponse;
use bytes::Bytes;
use parking_lot::RwLock;
use std::{collections::{HashMap, HashSet}, sync::Arc, time::{Duration, Instant}};

use crate::AppState;

#[derive(Clone)]
pub struct Cache {
    inner: Arc<RwLock<CacheInner>>,
}

struct CacheInner {
    entries: HashMap<String, CacheEntry>,
    tag_index: HashMap<String, HashSet<String>>, // tag -> set(cache_key)
}

struct CacheEntry {
    stored_at: Instant,
    ttl: Duration,
    grace: Duration,
    status: http::StatusCode,
    headers: HeaderMap,
    body: Bytes,
    tags: Vec<String>,
    invalidation_states: Option<String>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheInner {
                entries: HashMap::new(),
                tag_index: HashMap::new(),
            })),
        }
    }

    pub fn purge_key(&self, key: &str) -> bool {
        let mut inner = self.inner.write();
        if let Some(entry) = inner.entries.remove(key) {
            for t in entry.tags {
                if let Some(set) = inner.tag_index.get_mut(&t) {
                    set.remove(key);
                    if set.is_empty() {
                        inner.tag_index.remove(&t);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    pub fn purge_tags(&self, tags: &[String]) -> usize {
        let mut inner = self.inner.write();
        let mut keys: HashSet<String> = HashSet::new();
        for tag in tags {
            if let Some(set) = inner.tag_index.get(tag) {
                keys.extend(set.iter().cloned());
            }
        }

        let mut gone = 0;
        for key in keys {
            if let Some(entry) = inner.entries.remove(&key) {
                gone += 1;
                for t in entry.tags {
                    if let Some(set) = inner.tag_index.get_mut(&t) {
                        set.remove(&key);
                        if set.is_empty() {
                            inner.tag_index.remove(&t);
                        }
                    }
                }
            }
        }
        gone
    }
}

pub enum CacheError {
    Upstream,
    BadRequest,
}

impl CacheError {
    pub fn into_request(self) -> Request<axum::body::Body> {
        // placeholder; main.rs uses this only in the fallback path
        Request::builder().uri("/").body(axum::body::Body::empty()).unwrap()
    }
}

pub async fn handle_cached(
    state: AppState,
    _peer: std::net::SocketAddr,
    req: Request<axum::body::Body>,
) -> Result<axum::response::Response, CacheError> {
    let (parts, body) = req.into_parts();
    let norm_uri = normalize::normalize_uri(&parts.uri);

    // Build cache key from URL + context cookies
    let cache_key = build_cache_key(&norm_uri, &parts.headers);

    // lookup
    if let Some(resp) = lookup(&state.cache, &cache_key, &parts.headers) {
        return Ok(resp);
    }

    // miss: fetch upstream
    let upstream_url = normalize::build_upstream_url(&state.cfg.origin, &norm_uri);

    let mut headers = parts.headers.clone();
    headers.insert(
        http::header::HeaderName::from_static("surrogate-capability"),
        http::HeaderValue::from_static("shopware=ESI/1.0"),
    );

    // remove internal hashing headers from upstream
    headers.remove("currency");
    headers.remove("states");

    let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap_or_default();

    let up = state
        .client
        .request(parts.method.clone(), upstream_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|_| CacheError::Upstream)?;

    let status = up.status();
    let mut resp_headers = up.headers().clone();
    let bytes = up.bytes().await.map_err(|_| CacheError::Upstream)?;

    // cache decision
    let ttl = ttl_from_headers(&resp_headers).unwrap_or(Duration::from_secs(0));
    let cacheable = ttl.as_secs() > 0 && (parts.method == http::Method::GET || parts.method == http::Method::HEAD);

    // VCL: dynamic-cache-bypass => hit-for-miss 1s
    if resp_headers.get("sw-dynamic-cache-bypass").and_then(|v| v.to_str().ok()) == Some("1") {
        resp_headers.remove("sw-dynamic-cache-bypass");
        // not caching (but could mark as uncacheable 1s). For now, just bypass.
        return Ok(build_response(status, resp_headers, bytes, &norm_uri));
    }

    if cacheable {
        // Strip Set-Cookie on cacheable responses
        resp_headers.remove(http::header::SET_COOKIE);

        // store
        store(&state.cache, cache_key, status, resp_headers.clone(), bytes.clone(), ttl);
    }

    Ok(build_response(status, resp_headers, bytes, &norm_uri))
}

fn build_cache_key(uri: &Uri, headers: &HeaderMap) -> String {
    // VCL hash:
    // - prefer sw-cache-hash header if non-empty
    // - else if currency cookie present
    let base = uri.to_string();

    let ctx = headers.get("sw-cache-hash").and_then(|v| v.to_str().ok()).unwrap_or("");
    let cur = extract_cookie(headers, "sw-currency").unwrap_or_default();

    let mut key = base;
    if !ctx.is_empty() {
        key.push_str("|context=");
        key.push_str(ctx);
    } else if !cur.is_empty() {
        key.push_str("|currency=");
        key.push_str(&cur);
    }

    let hash = blake3::hash(key.as_bytes());
    hash.to_hex().to_string()
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(http::header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let p = part.trim();
        if let Some((k, v)) = p.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn lookup(cache: &Cache, key: &str, req_headers: &HeaderMap) -> Option<axum::response::Response> {
    let now = Instant::now();
    let inner = cache.inner.read();
    let entry = inner.entries.get(key)?;

    let age = now.duration_since(entry.stored_at);
    let fresh = age <= entry.ttl;
    let within_grace = age <= (entry.ttl + entry.grace);

    if !(fresh || within_grace) {
        return None;
    }

    // VCL hit logic: pass if client states matches invalidation states
    if let (Some(req_states), Some(obj_states)) = (
        extract_cookie(req_headers, "sw-states"),
        entry.invalidation_states.as_ref().map(|s| s.as_str().to_string()),
    ) {
        if req_states.contains("logged-in") && obj_states.contains("logged-in") {
            return None;
        }
        if req_states.contains("cart-filled") && obj_states.contains("cart-filled") {
            return None;
        }
    }

    let mut headers = entry.headers.clone();
    normalize::apply_client_cache_policy(&"/".parse::<Uri>().unwrap(), &mut headers);
    normalize::strip_internal_headers(&mut headers);

    Some(
        axum::response::Response::builder()
            .status(entry.status)
            .body(axum::body::Body::from(entry.body.clone()))
            .unwrap()
            .tap(|resp| {
                *resp.headers_mut() = headers;
            }),
    )
}

fn store(cache: &Cache, key: String, status: http::StatusCode, headers: HeaderMap, body: Bytes, ttl: Duration) {
    let grace = Duration::from_secs(60 * 60 * 24 * 3); // 3d

    let tags = headers
        .get("xkey")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split_whitespace().map(|t| t.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let invalidation_states = headers
        .get("sw-invalidation-states")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let entry = CacheEntry {
        stored_at: Instant::now(),
        ttl,
        grace,
        status,
        headers: headers.clone(),
        body,
        tags: tags.clone(),
        invalidation_states,
    };

    let mut inner = cache.inner.write();
    inner.entries.insert(key.clone(), entry);
    for tag in tags {
        inner.tag_index.entry(tag).or_default().insert(key.clone());
    }
}

fn ttl_from_headers(headers: &HeaderMap) -> Option<Duration> {
    // Simple parse for Cache-Control: max-age
    let cc = headers.get(http::header::CACHE_CONTROL)?.to_str().ok()?;
    for part in cc.split(',') {
        let p = part.trim();
        if let Some(v) = p.strip_prefix("max-age=") {
            if let Ok(secs) = v.parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
        }
    }
    None
}

fn build_response(status: http::StatusCode, mut headers: HeaderMap, bytes: Bytes, uri: &Uri) -> axum::response::Response {
    // Apply deliver-stage rules
    normalize::apply_client_cache_policy(uri, &mut headers);
    normalize::strip_internal_headers(&mut headers);

    axum::response::Response::builder()
        .status(status)
        .body(axum::body::Body::from(bytes))
        .unwrap()
        .tap(|resp| {
            *resp.headers_mut() = headers;
        })
}

trait Tap: Sized {
    fn tap(self, f: impl FnOnce(&mut Self)) -> Self {
        let mut s = self;
        f(&mut s);
        s
    }
}
impl<T> Tap for T {}
