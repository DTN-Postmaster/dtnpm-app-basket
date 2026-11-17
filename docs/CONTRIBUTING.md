# Contributing Guide — `dtnpm-app-basket`

This guide outlines the development rules and security requirements for the DTN Basket application in `dtnpm-app-basket`.

---

## 1. Core Principles

- **Zero Panic / Zero Unwrap**: No `.unwrap()` or `.expect()` calls in production code.
- **Network Security and Anti-SSRF**:
  - All external network access must go through the `SafeDnsResolver` security resolver.
  - Redirects must be resolved manually to block DNS Rebinding.
  - Access to private networks requires the explicit opt-in `allow_private_ips = true`.
- **Architectural Traceability (ADR)**:
  - Any protocol or service architecture change must be documented in an ADR file under `adr/` and indexed in `adr/README.md`.

---

## 2. Local Verification

```bash
cargo fmt --all -- --check
cargo clippy --offline --workspace --lib --bins -- -D warnings -D clippy::unwrap_used -D clippy::panic
cargo test --offline --all-features
./scripts/check-security.sh --strict
```
