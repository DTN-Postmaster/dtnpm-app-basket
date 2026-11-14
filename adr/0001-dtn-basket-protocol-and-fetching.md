# ADR 0001: DTN Basket Protocol Service Architecture and Bounded Resource Fetching

## Status

Accepted

## Context

`dtnpm-app-basket` implements the responder daemon (`dtnbasket`, `src/bin_dtnbasket.rs`) and client CLI (`dtnbasket-cli`, `src/bin_dtnbasket_cli.rs`) for `draft-f4jxq-dtn-basket-00` over Hardy BPA (`hardy-bpa` / `hardy-bpv7` / `hardy-cbor`).

DTN links are bandwidth-constrained and store-and-forward bundles can carry arbitrarily large resource requests, slow-loris remote endpoints, oversized local files, or expensive regex searches. Unbounded buffering in `dtnbasket` could exhaust memory, stall worker tasks indefinitely, or exceed bundle-layer limits.

## Decision

1. **Modular Responder Separation**: Separate `dtnbasket` responsibilities into three focused modules compiled into `src/bin_dtnbasket.rs`:
   - `src/config.rs`: typed configuration schema (`Config`, `SecurityConfig`, `LimitsConfig`) loaded by `load_config` with explicit fail-closed defaults.
   - `src/fetcher.rs`: protocol fetching (`http`/`https`, `gemini`, `file`, static `mappings`), DNS/SSRF validation, canonical filesystem confinement, and `SEARCH`/`LIST` indexing.
   - `src/service.rs`: CBOR basket request decoding, BPSec policy verification/signing via `dtnpm-core::cli_security`, request dispatch (`GET`, `CHECK`, `CANCEL`, `SEARCH`, `LIST`), task lifecycle tracking (`ActiveTaskGuard`), and bundle transmission.
2. **Timeouts & Bounded Header Parsing**:
   - Configure `reqwest::Client::builder()` with `CONNECT_TIMEOUT` (`10s`) and `REQUEST_TIMEOUT` (`30s`).
   - Wrap Gemini TCP connect, TLS handshake, and response I/O in `tokio::time::timeout`, and bound status header reads using `(&mut reader).take(GEMINI_HEADER_MAX_BYTES)` (`1027` bytes), rejecting truncated headers missing `\n`.
3. **Incremental Streaming Size Caps & Cumulative Basket Budget**:
   - Read HTTP bodies (`res.chunk().await`), Gemini payloads (`read_async_bounded`), and local files (`read_file_bounded`) incrementally, aborting immediately with `FetchError::PayloadTooLarge` before allocating beyond the effective item cap.
   - Enforce `limits.max_item_size` (default `50 MiB`) as a hard ceiling over per-item `max_size`, and enforce `limits.max_bundle_size` (default `100 MiB`) cumulatively across all items (`GET`, `CHECK`, `SEARCH`, `LIST`) in a single basket request.
4. **Regex & Search Bounding**:
   - Build `perform_search` patterns with `regex::RegexBuilder::size_limit(REGEX_SIZE_LIMIT)` (`1 MiB`) and stop traversal/collection at `MAX_SEARCH_RESULTS` (`100`) entries.
5. **CLI Token Hygiene**:
   - Provide `--token-file` (`DTN_HDY_TOKEN_FILE`) resolved via `dtnpm_app_basket::resolve_auth_token` in both `dtnbasket` and `dtnbasket-cli` to keep gRPC bearer tokens out of process argument lists.

## Consequences

- Memory growth per request item and per basket bundle is strictly bounded, preventing OOM and slow-loris exhaustion on remote or local fetches.
- Callers requesting `item.max_size` larger than the node administrator's configured `limits.max_item_size` or total basket budget receive deterministic CoAP `PAYLOAD_TOO_LARGE` / truncation handling rather than unbounded allocation.
- Production library/binary crates forbid `.unwrap()` and `panic!` via CI Clippy enforcement (`-D clippy::unwrap_used -D clippy::panic`).
