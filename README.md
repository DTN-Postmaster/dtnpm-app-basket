# dtnpm-app-basket

DTN Basket Protocol (RFC draft-f4jxq-dtn-basket-00) proxy service (`dtnbasket`) and client CLI (`dtnbasket-cli`) for **DTN Postmaster** (`dtnpm`).

## Overview

`dtnpm-app-basket` provides an asynchronous, delay-tolerant web/resource retrieval application for DTN networks:

- **`dtnbasket`**: Background gateway/proxy service that listens for basket requests, fetches resources over HTTP(S) or local storage, validates and packages responses according to draft-f4jxq-dtn-basket-00, and returns signed or verified response bundles.
- **`dtnbasket-cli`**: Command-line interface to forge basket requests, configure fetch targets, and inject request bundles into a local or remote BPA.

## Binaries

- `dtnbasket`: DTN Basket service daemon
- `dtnbasket-cli`: DTN Basket client CLI

## Build and Test

Requires sibling checkouts of `../dtnpm-core` and `../../hardy/*`.

```bash
cargo test
```

## Security & Compliance

- **SSRF & DNS Rebinding Mitigation**: `SafeDnsResolver` pre-validates resolved IPs, blocks loopback/link-local/RFC1918/cloud metadata endpoints by default, and re-resolves manual redirects without relying on automated follower logic.
- **Explicit Permissive Mode (Opt-in)**: Private network access is available only when explicitly enabled via `allow_private_ips = true`.
- **DTN Amplification Prevention**: `reply_to` destination must match the request bundle source node authority unless `allow_third_party_reply_to = true` is configured.
- **Cyber Resilience Act (CRA)**: Token file security (`--token-file`), VEX audit documentation (`RUSTSEC-2026-0459`), and SHA-pinned CI actions.
- **Rust Quality Standards**: 100% `unwrap`-free and `panic!`-free production codebase.
- **Documentation**: See [`AGENTS.md`](AGENTS.md), [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md), and Architectural Decision Records in [`adr/`](adr/).

## Documentation & Specification

- Internet Draft: [`docs/draft-f4jxq-dtn-basket-00.txt`](docs/draft-f4jxq-dtn-basket-00.txt)
- Example configuration: [`examples/dtnbasket.toml`](examples/dtnbasket.toml)
- Test script: [`examples/test_basket.py`](examples/test_basket.py)

## License

Dual-licensed under the Apache License, Version 2.0 or the MIT License. See [LICENSE.md](LICENSE.md).
