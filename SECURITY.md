# Security Policy

## Supported Versions

Security updates and EU Cyber Resilience Act (CRA) vulnerability handling apply to the current development branch and tagged releases:

| Version | Supported |
| ------- | --------- |
| `0.2.x` (`main`) | Yes |
| `< 0.2.0` | No |

## Security Architecture & Hardening Controls

`dtnpm-app-basket` (`dtnbasket` responder daemon and `dtnbasket-cli` client) implements the DTN Basket Protocol (`draft-f4jxq-dtn-basket-00`) with fail-closed defaults:

- **SSRF & DNS Rebinding Mitigation (`src/fetcher.rs`)**:
  - `SafeDnsResolver` implements `reqwest::dns::Resolve` for outbound HTTP(S) requests and rejects the entire resolution if *any* returned IP address violates `is_safe_ip` (defeating dual-record DNS rebinding) unless `security.allow_private_ips = true` is explicitly configured.
  - `fetch_gemini` pre-resolves hostnames, validates every address with `is_safe_ip`, and dials the validated `SocketAddr` directly via `TcpStream::connect(*addr)` rather than re-resolving DNS.
  - `is_safe_ip` blocks loopback, unspecified, multicast, broadcast, `0.0.0.0/8`, RFC 1918 private networks, link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), RFC 6890 assignments (`192.0.0.0/24`), benchmarking (`198.18.0.0/15`, `2001:2::/48`), reserved `240.0.0.0/4`, ULA (`fc00::/7`), site-local (`fec0::/10`), discard-only (`100::/64`), documentation ranges, and IPv4-mapped/compatible/translated/NAT64 IPv6 encodings targeting unsafe IPv4 ranges.
  - `check_url_ssrf` rejects hostless URLs and disallowed schemes; HTTP redirects use `Policy::none()` with hop-by-hop scheme and SSRF re-validation.
- **Reply-To Reflection & Cancellation Ownership (`src/service.rs`)**:
  - `security.allow_third_party_reply_to` defaults to `false`; `validate_reply_to` requires the `NodeId` authority of `reply_to` to match `bundle.source.to_node_id()`.
  - `CANCEL` (`op = 3`) requests are bound to the originating requester `NodeId` and return CoAP `FORBIDDEN` if invoked from a different node or null/unroutable source.
- **Bounded Network, File, & Regex Processing (`src/fetcher.rs`, `src/service.rs`, `src/config.rs`)**:
  - HTTP(S) and Gemini connections enforce `10s` connect timeouts and `30s` total timeouts; Gemini status headers are capped at `1027` bytes (`(&mut reader).take(1027).read_until(b'\n', ...)`).
  - HTTP(S), Gemini, and `file://` fetches stream incrementally and abort immediately upon exceeding `item.max_size` (capped at `limits.max_item_size`, default `50 MiB`) or the cumulative per-request budget (`limits.max_bundle_size`, default `100 MiB`).
  - `check_file_path` / `resolve_safe_file_path` canonicalize allowed directory roots and resolved paths (including deepest existing ancestors) to prevent symlink traversal; `perform_search` limits compiled regex size to `1 MiB` (`1 << 20`) and caps results at `100` matches.
- **Credential Hygiene & Supply Chain (`src/lib.rs`, `src/bin_dtnbasket.rs`, `src/bin_dtnbasket_cli.rs`)**:
  - `--token-file` / `DTN_HDY_TOKEN_FILE` allows passing BPA bearer tokens from restricted files instead of process command-line arguments.
  - Release and CI workflows generate CycloneDX/SPDX SBOMs (`anchore/sbom-action`), enforce pinned GitHub Action commit SHAs with minimal `permissions`, and forbid `.unwrap()` / `panic!` in production code via Clippy lints (`scripts/check-security.sh`).

## Dependency Advisory & VEX Status

Per CRA Annex I vulnerability-handling documentation:

- **`RUSTSEC-2024-0449` (`unsafe-libyaml` / `serde_yaml`)**: **Resolved / Not Present**. Upstream `dtnpm-core` migrated to `yaml_serde` (`libyaml-rs`), eliminating `unsafe-libyaml` from `Cargo.lock`. No advisory suppression remains for this ID.
- **`RUSTSEC-2026-0459` (`libsqlite3-sys` <= `0.38.2`, CVE-2026-119375)**: **VEX Status: `not_affected` (`component_not_reachable`)**.
  - *Justification*: `libsqlite3-sys v0.38.2` is pulled transitively through `dtnpm-core` -> `rusqlite v0.40.2`. `dtnpm-app-basket` never invokes `rusqlite` or SQLite APIs and never opens SQLite database or `-wal` files, so the mismatched WAL page-size memory-disclosure condition is unreachable. Tracked in `.cargo/audit.toml` and `deny.toml`.

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately rather than opening a public issue:

1. Contact the project maintainers via GitHub Security Advisories ("Report a vulnerability" on this repository) or direct maintainer email (`f4jxq` / repository owner).
2. Include the affected version or commit, reproduction steps or proof of concept, and any suggested mitigation.
3. Maintainers aim to acknowledge reports within 72 hours and coordinate remediation, VEX/advisory publication, and release timing with the reporter.
