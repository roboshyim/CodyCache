use axum::http::{HeaderMap, StatusCode, Uri};
use ipnet::IpNet;

use crate::cache::Cache;

pub fn is_purger_allowed(ip: std::net::IpAddr, purgers: &[IpNet]) -> bool {
    purgers.iter().any(|net| net.contains(&ip))
}

pub fn handle_purge(cache: std::sync::Arc<Cache>, uri: &Uri, headers: &HeaderMap) -> (StatusCode, String) {
    if let Some(xkey) = headers.get("xkey").and_then(|v| v.to_str().ok()) {
        let tags: Vec<String> = xkey.split_whitespace().map(|s| s.to_string()).collect();
        match cache.purge_tags(&tags) {
            Ok(gone) => return (StatusCode::OK, format!("Invalidated {gone} objects")),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }

    // TODO: implement URL->keys index (respect variants). For now: return 501 so it isn't misleading.
    (StatusCode::NOT_IMPLEMENTED, format!("PURGE-by-URL not implemented (requested {})", uri.path()))
}

pub fn handle_ban(_cache: std::sync::Arc<Cache>, uri: &Uri) -> (StatusCode, String) {
    // Varnish BAN is pattern-based. We can implement later with a ban list evaluated at lookup.
    // For now, return 501 so users know it's not implemented.
    (StatusCode::NOT_IMPLEMENTED, format!("BAN not implemented (requested ban on URLs containing {})", uri.path()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purge_with_xkey_is_ok_even_if_no_objects_match() {
        let dir = tempfile::tempdir().unwrap();
        let cache = std::sync::Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

        let uri: Uri = "/foo".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("xkey", http::HeaderValue::from_static("a b c"));

        let (status, body) = handle_purge(cache, &uri, &headers);
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Invalidated"));
    }

    #[test]
    fn purge_without_xkey_returns_not_implemented() {
        let dir = tempfile::tempdir().unwrap();
        let cache = std::sync::Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

        let uri: Uri = "/foo".parse().unwrap();
        let headers = HeaderMap::new();

        let (status, body) = handle_purge(cache, &uri, &headers);
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(body.contains("PURGE-by-URL not implemented"));
    }
}
