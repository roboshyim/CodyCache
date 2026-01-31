use axum::http::{HeaderMap, StatusCode, Uri};
use ipnet::IpNet;

use crate::cache::Cache;

pub fn is_purger_allowed(ip: std::net::IpAddr, purgers: &[IpNet]) -> bool {
    purgers.iter().any(|net| net.contains(&ip))
}

pub fn handle_purge(
    cache: std::sync::Arc<Cache>,
    uri: &Uri,
    headers: &HeaderMap,
) -> (StatusCode, String) {
    if let Some(xkey) = headers.get("xkey").and_then(|v| v.to_str().ok()) {
        let tags: Vec<String> = xkey.split_whitespace().map(|s| s.to_string()).collect();
        match cache.purge_tags(&tags) {
            Ok(gone) => return (StatusCode::OK, format!("Invalidated {gone} objects")),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }

    let normalized = crate::normalize::normalize_uri(uri);
    match cache.purge_url(&normalized.to_string()) {
        Ok(gone) => (
            StatusCode::OK,
            format!("Invalidated {gone} objects for {normalized}"),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

pub fn handle_ban(cache: std::sync::Arc<Cache>, uri: &Uri) -> (StatusCode, String) {
    // Minimal Varnish-like BAN: store a substring pattern and check it during cache lookup.
    // We store the path component as the pattern by default.
    let pattern = uri.path();
    match cache.add_ban(pattern) {
        Ok(id) => (
            StatusCode::OK,
            format!("Added ban #{id} for URLs containing '{pattern}'"),
        ),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_marks_matching_urls_as_banned() {
        let dir = tempfile::tempdir().unwrap();
        let cache = std::sync::Arc::new(Cache::new(dir.path().to_str().unwrap()).unwrap());

        let uri: Uri = "/foo".parse().unwrap();
        let (status, body) = handle_ban(cache.clone(), &uri);
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Added ban"));

        let norm: Uri = "/foo?a=1".parse().unwrap();
        let norm = crate::normalize::normalize_uri(&norm);
        assert!(cache.is_banned(&norm));

        let other: Uri = "/bar".parse().unwrap();
        let other = crate::normalize::normalize_uri(&other);
        assert!(!cache.is_banned(&other));
    }
}
