# CodyCache

A Rust-based HTTP reverse-proxy cache intended as a replacement for the Shopware Varnish setup.

## Goals (parity with current VCL)

From: `shopware/varnish-shopware` default.vcl

- Reverse proxy cache in front of Shopware
- Cache key normalization
  - Strip common tracking query params, then sort query
  - Vary by `sw-cache-hash` cookie (`sw-cache-hash` header override supported)
  - Fallback vary by `sw-currency` cookie
- Bypass cache for
  - `Authorization` requests
  - Non-GET/HEAD
  - Paths: `/checkout`, `/account`, `/admin`, `/api` (and subpaths)
- Special case
  - `GET /widgets/checkout/info` => 204 when `sw-cache-hash` missing or cart state not filled (see VCL)
- PURGE support with allowlisted purger IPs
  - `PURGE` with `xkey` header: purge by tag(s) (Shopware-style)
  - `PURGE` without `xkey`: purge by URL
- BAN support with allowlisted purger IPs
- Response handling
  - Grace/stale serving (3 days) after TTL expiration (Varnish grace analog)
  - Strip `Set-Cookie` on cacheable responses
  - Force client no-store for non-asset responses (assets + `store-api` are allowed)

## Non-goals (initially)

- Full ESI implementation (we’ll design for it, but may ship later)

## Running (dev)

This repo includes a Dockerfile so you can build without having Rust installed locally.

```bash
docker build -t codycache .
docker run --rm -p 8080:8080 \
  -e CODYCACHE_ORIGIN=http://127.0.0.1:8000 \
  -e CODYCACHE_PURGERS=127.0.0.1/32,::1/128 \
  -e CODYCACHE_CACHE_DIR=/var/lib/codycache \
  -v $PWD/.codycache:/var/lib/codycache \
  codycache
```

## Config (env)

- `CODYCACHE_LISTEN` (default `0.0.0.0:8080`)
- `CODYCACHE_ORIGIN` (required) e.g. `http://shopware:8000`
- `CODYCACHE_PURGERS` comma-separated CIDRs/IPs allowed to PURGE/BAN
- `CODYCACHE_CACHE_DIR` directory for the disk cache (default `./cache`)

## License

MIT
