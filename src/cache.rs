use crate::{disk, normalize, AppState};
use axum::http::{HeaderMap, Request, Uri};
use bytes::Bytes;
use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct Cache {
    inner: Arc<RwLock<CacheInner>>,
}

struct CacheInner {
    // Small in-memory hot index for quick negatives + stats. Bodies live on disk.
    known: HashMap<String, ()>,
    disk: disk::DiskStore,

    // BAN patterns; if request URL contains any pattern, treat as miss.
    bans: Vec<String>,
}

impl Cache {
    pub fn new(cache_dir: &str) -> Result<Self, String> {
        let disk = disk::DiskStore::open(cache_dir)?;
        let bans = disk.list_bans().unwrap_or_default();
        Ok(Self {
            inner: Arc::new(RwLock::new(CacheInner {
                known: HashMap::new(),
                disk,
                bans,
            })),
        })
    }

    pub fn purge_key(&self, key: &str) -> Result<bool, String> {
        let mut inner = self.inner.write();
        inner.known.remove(key);
        inner.disk.remove_key(key)
    }

    pub fn purge_tags(&self, tags: &[String]) -> Result<usize, String> {
        let inner = self.inner.read();
        inner.disk.remove_by_tags(tags)
    }

    pub fn purge_url(&self, normalized_url: &str) -> Result<usize, String> {
        let inner = self.inner.read();
        inner.disk.remove_by_url(normalized_url)
    }

    pub fn add_ban(&self, pattern: &str) -> Result<u64, String> {
        let mut inner = self.inner.write();
        let id = inner.disk.add_ban(pattern)?;
        inner.bans.push(pattern.to_string());
        Ok(id)
    }

    pub fn is_banned(&self, normalized_url: &Uri) -> bool {
        let inner = self.inner.read();
        let u = normalized_url.to_string();
        inner.bans.iter().any(|p| !p.is_empty() && u.contains(p))
    }
}

pub async fn handle_cached(
    state: AppState,
    _peer: std::net::SocketAddr,
    req: Request<axum::body::Body>,
) -> Result<axum::response::Response, String> {
    let (parts, body) = req.into_parts();
    let norm_uri = normalize::normalize_uri(&parts.uri);

    let cache_key = build_cache_key(&norm_uri, &parts.headers);

    // BAN logic: if URL is banned, skip cache.
    if state.cache.is_banned(&norm_uri) {
        // fall through to upstream
    } else if let Some(resp) = lookup(&state.cache, &cache_key, &parts.headers, &norm_uri)? {
        return Ok(resp);
    }

    // miss: fetch upstream
    let upstream_url = normalize::build_upstream_url(&state.cfg.origin, &norm_uri);

    let mut headers = parts.headers.clone();
    headers.insert(
        http::header::HeaderName::from_static("surrogate-capability"),
        http::HeaderValue::from_static("shopware=ESI/1.0"),
    );

    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();

    let up = state
        .client
        .request(parts.method.clone(), upstream_url)
        .headers(headers)
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| format!("upstream: {e}"))?;

    let status = up.status();
    let mut resp_headers = up.headers().clone();
    let bytes = up
        .bytes()
        .await
        .map_err(|e| format!("upstream body: {e}"))?;

    // Decide TTL
    let ttl = ttl_from_headers(&resp_headers).unwrap_or(Duration::from_secs(0));
    let cacheable = ttl.as_secs() > 0
        && (parts.method == http::Method::GET || parts.method == http::Method::HEAD);

    // VCL: sw-dynamic-cache-bypass => hit-for-miss 1s
    if resp_headers
        .get("sw-dynamic-cache-bypass")
        .and_then(|v| v.to_str().ok())
        == Some("1")
    {
        resp_headers.remove("sw-dynamic-cache-bypass");
        return Ok(build_response(status, resp_headers, bytes, &norm_uri));
    }

    if cacheable {
        // Strip Set-Cookie on cacheable responses
        resp_headers.remove(http::header::SET_COOKIE);

        store(
            &state.cache,
            &cache_key,
            &norm_uri,
            status,
            &resp_headers,
            &bytes,
            ttl,
        )?;
    }

    Ok(build_response(status, resp_headers, bytes, &norm_uri))
}

fn build_cache_key(uri: &Uri, headers: &HeaderMap) -> String {
    let mut key = uri.to_string();

    let ctx = headers
        .get("sw-cache-hash")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cur = extract_cookie(headers, "sw-currency").unwrap_or_default();

    if !ctx.is_empty() {
        key.push_str("|context=");
        key.push_str(ctx);
    } else if !cur.is_empty() {
        key.push_str("|currency=");
        key.push_str(&cur);
    }

    blake3::hash(key.as_bytes()).to_hex().to_string()
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

fn lookup(
    cache: &Cache,
    key: &str,
    req_headers: &HeaderMap,
    uri: &Uri,
) -> Result<Option<axum::response::Response>, String> {
    let inner = cache.inner.read();
    let Some((meta, body)) = inner.disk.get(key)? else {
        return Ok(None);
    };

    // Expiration / grace
    let now_ms = disk::now_ms();
    let age_ms = now_ms.saturating_sub(meta.stored_at_ms);
    let fresh = age_ms <= meta.ttl_ms;
    let within_grace = age_ms <= meta.ttl_ms.saturating_add(meta.grace_ms);
    if !(fresh || within_grace) {
        return Ok(None);
    }

    // VCL hit logic: pass if client states matches invalidation states
    if let (Some(req_states), Some(obj_states)) = (
        extract_cookie(req_headers, "sw-states"),
        meta.invalidation_states.as_deref(),
    ) {
        if req_states.contains("logged-in") && obj_states.contains("logged-in") {
            return Ok(None);
        }
        if req_states.contains("cart-filled") && obj_states.contains("cart-filled") {
            return Ok(None);
        }
    }

    let mut headers = disk::pairs_to_headers(&meta.headers);
    normalize::apply_client_cache_policy(uri, &mut headers);
    normalize::strip_internal_headers(&mut headers);

    let resp = axum::response::Response::builder()
        .status(meta.status)
        .body(axum::body::Body::from(body))
        .unwrap();

    let mut resp = resp;
    *resp.headers_mut() = headers;

    Ok(Some(resp))
}

fn store(
    cache: &Cache,
    key: &str,
    url: &Uri,
    status: http::StatusCode,
    headers: &HeaderMap,
    body: &Bytes,
    ttl: Duration,
) -> Result<(), String> {
    let grace = Duration::from_secs(60 * 60 * 24 * 3);

    let tags = headers
        .get("xkey")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split_whitespace()
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let invalidation_states = headers
        .get("sw-invalidation-states")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let meta = disk::StoredMeta {
        url: url.to_string(),
        stored_at_ms: disk::now_ms(),
        ttl_ms: ttl.as_millis() as u64,
        grace_ms: grace.as_millis() as u64,
        status: status.as_u16(),
        headers: disk::headers_to_pairs(headers),
        tags,
        invalidation_states,
    };

    let mut inner = cache.inner.write();
    inner.known.insert(key.to_string(), ());
    inner.disk.put(key, &meta, body)
}

fn ttl_from_headers(headers: &HeaderMap) -> Option<Duration> {
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

fn build_response(
    status: http::StatusCode,
    mut headers: HeaderMap,
    bytes: Bytes,
    uri: &Uri,
) -> axum::response::Response {
    normalize::apply_client_cache_policy(uri, &mut headers);
    normalize::strip_internal_headers(&mut headers);

    let mut resp = axum::response::Response::builder()
        .status(status)
        .body(axum::body::Body::from(bytes))
        .unwrap();
    *resp.headers_mut() = headers;
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_varies_by_context_hash_when_present() {
        let uri: Uri = "/foo?a=1".parse().unwrap();
        let mut h1 = HeaderMap::new();
        h1.insert("sw-cache-hash", http::HeaderValue::from_static("abc"));
        h1.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("sw-currency=EUR"),
        );

        let mut h2 = HeaderMap::new();
        h2.insert("sw-cache-hash", http::HeaderValue::from_static("def"));
        h2.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("sw-currency=EUR"),
        );

        let k1 = build_cache_key(&uri, &h1);
        let k2 = build_cache_key(&uri, &h2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_falls_back_to_currency_when_no_context_hash() {
        let uri: Uri = "/foo?a=1".parse().unwrap();

        let mut h1 = HeaderMap::new();
        h1.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("sw-currency=EUR"),
        );

        let mut h2 = HeaderMap::new();
        h2.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("sw-currency=USD"),
        );

        let k1 = build_cache_key(&uri, &h1);
        let k2 = build_cache_key(&uri, &h2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn extract_cookie_parses_simple_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("a=1; sw-currency=EUR; b=2"),
        );
        assert_eq!(
            extract_cookie(&headers, "sw-currency").as_deref(),
            Some("EUR")
        );
        assert_eq!(extract_cookie(&headers, "missing"), None);
    }
}
