# ADR 0002: SSRF, DNS Rebinding, Symlink Traversal, and Reply-To Reflection Protections

## Status

Accepted

## Context

A `dtnbasket` responder exposes outbound HTTP(S)/Gemini fetching, restricted local file serving, and asynchronous DTN bundle responses to remote DTN endpoints:

- Standard HTTP clients that validate URL strings before resolution remain vulnerable to time-of-check-to-time-of-use (TOCTOU) DNS rebinding, dual-record DNS answers mixing public and loopback/private IPs, HTTP `Location` redirects into internal/local schemes (`http://127.0.0.1`, `file://`), and obfuscated IPv6 encodings (such as `::ffff:127.0.0.1`, NAT64 `64:ff9b::`, ULA, or CGNAT).
- Lexical `Path::starts_with` checks can be bypassed when symlinks inside `allowed_dirs` point to sensitive files outside the configured roots.
- Accepting arbitrary `reply_to` EIDs in `BasketRequest` enables cross-node traffic amplification/reflection, and unauthenticated `CANCEL` requests keyed solely by caller-chosen `request_id` allow third-party cancellation DoS.

Because `dtnpm-app-basket` is also used in isolated lab topologies and pre-secured DTN links, operators need explicit configuration opt-ins without weakening default deployments.

## Decision

1. **Fail-Closed `SecurityConfig` Opt-Ins (`src/config.rs`)**:
   - Add `SecurityConfig { allow_private_ips: false, allow_third_party_reply_to: false }`.
   - Secure deployments require zero extra configuration; lab/pre-secured deployments explicitly opt in via `[security]` in TOML.
2. **Resolution-Time DNS Pinning & SSRF Validation (`src/fetcher.rs`)**:
   - Enforce `is_safe_ip` across loopback, unspecified, multicast, broadcast, `0.0.0.0/8`, RFC 1918 private, link-local, CGNAT (`100.64.0.0/10`), RFC 6890 (`192.0.0.0/24`), benchmarking (`198.18.0.0/15`, `2001:2::/48`), reserved `240.0.0.0/4`, ULA (`fc00::/7`), site-local, discard-only, documentation ranges, and IPv4-mapped/compatible/translated/NAT64 IPv6 forms.
   - Require `check_url_ssrf` to return `false` when `parsed.host_str()` is `None` or for disallowed schemes.
   - Inject `SafeDnsResolver` (`reqwest::dns::Resolve`) into `reqwest::Client::builder()` and reject resolution in `validate_resolved_addrs` if `!allow_private_ips` and *any* resolved address is unsafe.
   - Use `reqwest::redirect::Policy::none()` and validate each redirect target manually with scheme checks and `check_url_ssrf`.
   - In `fetch_gemini`, resolve and validate addresses once upfront, then pass the validated `SocketAddr` directly to `TcpStream::connect(*addr)`.
3. **Canonical Symlink Containment (`src/fetcher.rs`)**:
   - Implement `check_file_path` / `resolve_safe_file_path` using canonicalized `allowed_dirs` roots and canonicalized target paths (falling back to the deepest existing canonicalized ancestor plus remaining components for non-existent paths), verifying `.starts_with(canon_root)`. Skip out-of-root symlinks cleanly during `perform_search`.
4. **Authority-Bound `reply_to` & `CANCEL` Ownership (`src/service.rs`)**:
   - In `validate_reply_to`, parse `reply_to` with `normalize_eid`, reject `Eid::Null` / `Eid::Unknown`, and verify `reply_eid.to_node_id() == bundle.source.to_node_id()` unless `security.allow_third_party_reply_to = true`.
   - Record `owner_node: Option<NodeId>` in `ActiveTask` and reject `CANCEL` requests (`cancel_request`) with CoAP `FORBIDDEN` if the requester's `NodeId` does not match `owner_node`, returning `NOT_FOUND` with an accurate diagnostic (`"Request {} not found"`) when absent.

## Consequences

- Dual-record DNS rebinding, private IPv4/IPv6 bypasses, redirect SSRF, symlink escapes outside `allowed_dirs`, cross-node reply reflection, and unauthenticated job cancellation are blocked by default.
- Operators testing against loopback endpoints or multi-node reply topologies in isolated testbeds retain deterministic opt-in behavior via `security.allow_private_ips = true` and `security.allow_third_party_reply_to = true`.
