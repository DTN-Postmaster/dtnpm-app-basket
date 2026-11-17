# Agent Guide — `dtnpm-app-basket`

## 🎯 Mission
Provide the DTN Basket proxy service (`dtnbasket`) and its companion command-line utility (`dtnbasket-cli`) according to the `draft-f4jxq-dtn-basket-00` specification, enabling asynchronous, delay- and disruption-tolerant retrieval of remote (HTTP, HTTPS, Gemini) and local resources across the DTN network.

---

## 🛡️ Security Frameworks and Requirements

### 1. Cyber Resilience Act (CRA) & Secure-by-Default
- **DNS Resolution & Anti-SSRF (Server-Side Request Forgery) Protection**:
  - Every external fetcher MUST use the `SafeDnsResolver` security resolver, which inspects IP addresses before establishing a TCP connection.
  - Private address ranges (RFC 1918), link-local addresses (RFC 3927 / APIPA), loopbacks (`127.0.0.0/8`, `::1`), broadcast addresses, and cloud metadata endpoints (`169.254.169.254`) are STRICTLY BLOCKED by default.
  - Automatic redirects are disabled: each HTTP redirect is intercepted and re-evaluated by `SafeDnsResolver` to neutralize any DNS rebinding attack (DNS Rebinding / TOCTOU).
  - For the Gemini protocol, the connection is established directly on the pre-validated `SocketAddr`.
- **Explicit Opt-In for Intranet / Lab Deployments**:
  - Access to servers or services located on private networks IS ONLY POSSIBLE if the user explicitly authorizes it via the configuration option `allow_private_ips = true`.
- **DTN Amplification Attack Prevention (`reply_to`)**:
  - The response destination authority (`reply_to`) must strictly match the requesting node (`source`), unless the administrator has explicitly enabled `allow_third_party_reply_to = true`.
- **Supply-Chain & VEX**:
  - `cargo-audit` and `cargo-deny` audits; VEX `not_affected` statement for `RUSTSEC-2026-0459`.
  - CI actions pinned by full 40-character SHA-1.
- **Security Policy**: Documented in [SECURITY.md](SECURITY.md).

### 2. Network Bounds and Filesystem Security
- **Timeouts and Memory Caps**:
  - Strict timeouts on HTTP/Gemini connections and transfers.
  - Gemini header read bounded via `.take(1027)` to prevent any hang or memory denial-of-service.
  - Maximum streaming size cap per resource and per-batch allocation budget.
- **Secure File Search (`perform_search`)**:
  - Systematic metadata check (`symlink_metadata`) to refuse following symlinks pointing outside the approved directory.
  - Asynchronous computation of file digests (`tokio::task::spawn_blocking`).
  - No sensitive system path (such as `/var/log` or `/etc`) may appear in the provided configuration examples.

---

## 🦀 Rust Engineering Standards

1. **Zero Panic / Zero Unwrap Rule**:
   - All code under `src/` must be 100% free of `.unwrap()`, `.expect()`, and the `panic!` macro.
   - Strict linter: `-D warnings -D clippy::unwrap_used -D clippy::panic`.
2. **Mandatory ADRs**:
   - Any Basket architectural decision must be recorded under `adr/` and indexed in [adr/README.md](adr/README.md).
3. **Documentation Language**:
   - English must be used as the language for all documentation, unless the file is suffixed with `.fr.md` or another language is explicitly requested in the prompt.

---

## ⚡ Critical Verification Commands

- `cargo fmt --all -- --check`
- `cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic`
- `cargo test --offline --all-features`
- `./scripts/check-security.sh --strict`
- `./scripts/check-coverage.sh --summary-only`
