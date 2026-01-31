use axum::http::{HeaderMap, StatusCode, Uri};
use ipnet::IpNet;

use crate::cache::Cache;

pub fn is_purger_allowed(ip: std::net::IpAddr, purgers: &[IpNet]) -> bool {
    purgers.iter().any(|net| net.contains(&ip))
}

pub fn handle_purge(cache: std::sync::Arc<Cache>, uri: &Uri, headers: &HeaderMap) -> (StatusCode, String) {
    if let Some(xkey) = headers.get("xkey").and_then(|v| v.to_str().ok()) {
        let tags: Vec<String> = xkey.split_whitespace().map(|s| s.to_string()).collect();
        let gone = cache.purge_tags(&tags);
        return (StatusCode::OK, format!("Invalidated {gone} objects"));
    }

    // Purge-by-URL: best-effort (we don't currently have a reverse index from URL->keys)
    // So we just purge by normalized URL key without context, as a starting point.
    let key = blake3::hash(uri.to_string().as_bytes()).to_hex().to_string();
    let ok = cache.purge_key(&key);
    if ok {
        (StatusCode::OK, "Purged".to_string())
    } else {
        (StatusCode::NOT_FOUND, "Not found".to_string())
    }
}

pub fn handle_ban(_cache: std::sync::Arc<Cache>, uri: &Uri) -> (StatusCode, String) {
    // Varnish BAN is pattern-based. We can implement later with a ban list evaluated at lookup.
    // For now, return 501 so users know it's not implemented.
    (StatusCode::NOT_IMPLEMENTED, format!("BAN not implemented (requested ban on URLs containing {})", uri.path()))
}
