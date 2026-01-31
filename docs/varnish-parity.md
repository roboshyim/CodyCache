# Varnish parity notes

Source VCL:
https://raw.githubusercontent.com/shopware/varnish-shopware/refs/heads/main/rootfs/etc/varnish/default.vcl

Implemented / planned mapping:

## vcl_recv
- PURGE: allowlist, xkey purge ✔ (implemented)
- BAN: allowlist, pattern ban ◐ (stubbed: 501)
- Method handling: unknown => pipe ✔ (proxy-only)
- Authorization => pass ✔
- Only cache GET/HEAD ✔
- Pass paths: ^/(checkout|account|admin|api) ✔
- Cookie parse + sw-cache-hash header from cookie ◐ (planned: improve parsing)
- currency + states extracted from cookies ◐ (partial)
- /widgets/checkout/info 204 ◐ (current impl is header-biased; needs parity)
- Strip tracking params + querysort ✔
- Surrogate-Capability header ✔
- X-Forwarded-For ✔

## vcl_hash
- hash by sw-cache-hash else currency ✔

## vcl_hit
- pass for logged-in/cart-filled state invalidations ◐ (currently reads cookie only)

## vcl_backend_response
- grace 3d ✔
- ESI do_esi ◐ (not implemented)
- sw-dynamic-cache-bypass hit-for-miss 1s ◐ (treated as bypass)
- gzip ◐ (reqwest does decompression; we may want to forward + recompress)
- Strip Set-Cookie on cacheable responses ✔

## vcl_deliver
- client no-store except assets/store-api ✔
- strip internal headers ✔

Next steps:
- Correct cookie parsing and sw-cache-hash extraction
- Implement ban list & evaluation
- Proper hit-for-miss caching
- Streaming (avoid buffering full bodies)
- Configurable storage backend (in-memory vs disk)
