use axum::response::IntoResponse;
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use url::Url;

/// Paths that must always bypass cache (Shopware VCL parity)
pub fn is_pass_path(path: &str) -> bool {
    // VCL: ^/(checkout|account|admin|api)(/.*)?$
    matches!(path, "/checkout" | "/account" | "/admin" | "/api")
        || path.starts_with("/checkout/")
        || path.starts_with("/account/")
        || path.starts_with("/admin/")
        || path.starts_with("/api/")
}

pub fn apply_forwarded_for(headers: &mut HeaderMap, ip: std::net::IpAddr) {
    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("");
    let new_val = if xff.is_empty() {
        ip.to_string()
    } else {
        format!("{xff}, {ip}")
    };
    headers.insert("x-forwarded-for", HeaderValue::from_str(&new_val).unwrap());
}

pub fn build_upstream_url(origin: &str, uri: &Uri) -> String {
    // origin like http://host:port
    let mut base = origin.trim_end_matches('/').to_string();
    base.push_str(uri.path());
    if let Some(q) = uri.query() {
        base.push('?');
        base.push_str(q);
    }
    base
}

/// Determine if we should return 204 for /widgets/checkout/info
///
/// VCL logic:
/// if (req.url == "/widgets/checkout/info" && (req.http.sw-cache-hash == "" || (cookie.isset("sw-states") && req.http.states !~ "cart-filled"))) {
///   return (synth(204, ""));
/// }
pub fn should_short_circuit_widgets_checkout_info(req: &http::Request<axum::body::Body>) -> bool {
    let headers = req.headers();

    // sw-cache-hash header overrides cookie value; if missing/empty => short-circuit
    let sw_cache_hash = headers.get("sw-cache-hash").and_then(|v| v.to_str().ok()).unwrap_or("");
    if sw_cache_hash.is_empty() {
        // We might still have a cookie, but VCL sets header from cookie only in vcl_recv.
        // In our implementation, we treat missing header as "missing" to keep behavior explicit.
        // (We will likely move cookie->header extraction into request normalization.)
        return true;
    }

    // states cookie exists but does not contain cart-filled
    if let Some(cookie) = headers.get(http::header::COOKIE).and_then(|v| v.to_str().ok()) {
        if cookie.contains("sw-states=") {
            // cheap parse: just check substring
            if !cookie.contains("cart-filled") {
                return true;
            }
        }
    }

    false
}

/// Normalize URL: remove tracking params and sort query.
pub fn normalize_uri(uri: &Uri) -> Uri {
    let raw = uri.to_string();
    // Url needs a base; use dummy
    let base = "http://localhost";
    let mut url = Url::parse(base).unwrap();
    url.set_path(uri.path());
    url.set_query(uri.query());

    // drop tracking params listed in VCL regex
    let drop_prefixes = [
        "pk_campaign", "piwik_campaign", "pk_kwd", "piwik_kwd", "pk_keyword",
        "pixelId", "kwid", "kw", "adid", "chl", "dv", "nk", "pa", "camid",
        "adgid", "cx", "ie", "cof", "siteurl",
        "_ga", "gclid",
    ];

    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .filter(|(k, _)| {
            if k.starts_with("utm_") {
                return false;
            }
            !drop_prefixes.contains(&k.as_str())
        })
        .collect();

    pairs.sort();

    url.query_pairs_mut().clear().extend_pairs(pairs.iter().map(|(k, v)| (&k[..], &v[..])));

    // Rebuild Uri
    let mut out = url.path().to_string();
    if let Some(q) = url.query() {
        if !q.is_empty() {
            out.push('?');
            out.push_str(q);
        }
    }
    out.parse().unwrap_or_else(|_| raw.parse().unwrap())
}

// NOTE: moved response conversion into request handlers to keep this module sync-only.

pub fn strip_internal_headers(headers: &mut HeaderMap) {
    headers.remove("sw-invalidation-states");
    headers.remove("xkey");
    headers.remove("x-varnish");
    headers.remove("via");
    headers.remove("link");
}

pub fn apply_client_cache_policy(uri: &Uri, headers: &mut HeaderMap) {
    let path = uri.path();
    let cache_control = headers.get(http::header::CACHE_CONTROL).and_then(|v| v.to_str().ok()).unwrap_or("");

    // VCL: if not private and not assets/store-api => no-store
    let is_asset = path.starts_with("/theme/")
        || path.starts_with("/media/")
        || path.starts_with("/thumbnail/")
        || path.starts_with("/bundles/")
        || path.starts_with("/store-api/");

    if !cache_control.contains("private") && !is_asset {
        headers.insert("pragma", HeaderValue::from_static("no-cache"));
        headers.insert("expires", HeaderValue::from_static("-1"));
        headers.insert("cache-control", HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"));
    }
}

pub fn synth(code: StatusCode, body: &'static str) -> impl IntoResponse {
    (code, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_uri_drops_tracking_and_sorts_query() {
        let uri: Uri = "/search?utm_source=x&_ga=1&b=2&a=1&gclid=zzz".parse().unwrap();
        let out = normalize_uri(&uri);
        // utm_* / _ga / gclid are removed
        assert_eq!(out.to_string(), "/search?a=1&b=2");
    }

    #[test]
    fn pass_paths_match_shopware_rules() {
        assert!(is_pass_path("/checkout"));
        assert!(is_pass_path("/checkout/confirm"));
        assert!(is_pass_path("/account"));
        assert!(is_pass_path("/admin/api"));
        assert!(is_pass_path("/api"));
        assert!(is_pass_path("/api/foo"));

        assert!(!is_pass_path("/"));
        assert!(!is_pass_path("/listing"));
        assert!(!is_pass_path("/store-api/search"));
    }

    #[test]
    fn widgets_checkout_info_short_circuit_rules() {
        // missing header => short circuit
        let req = http::Request::builder().uri("/widgets/checkout/info").body(axum::body::Body::empty()).unwrap();
        assert!(should_short_circuit_widgets_checkout_info(&req));

        // header present and no sw-states cookie => do not short circuit
        let req = http::Request::builder()
            .uri("/widgets/checkout/info")
            .header("sw-cache-hash", "abc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!should_short_circuit_widgets_checkout_info(&req));

        // header present and sw-states exists but missing cart-filled => short circuit
        let req = http::Request::builder()
            .uri("/widgets/checkout/info")
            .header("sw-cache-hash", "abc")
            .header(http::header::COOKIE, "sw-states=logged-in")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(should_short_circuit_widgets_checkout_info(&req));

        // header present and sw-states includes cart-filled => do not short circuit
        let req = http::Request::builder()
            .uri("/widgets/checkout/info")
            .header("sw-cache-hash", "abc")
            .header(http::header::COOKIE, "sw-states=logged-in,cart-filled")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(!should_short_circuit_widgets_checkout_info(&req));
    }
}
