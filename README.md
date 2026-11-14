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

## Documentation & Specification

- Internet Draft: [`docs/draft-f4jxq-dtn-basket-00.txt`](docs/draft-f4jxq-dtn-basket-00.txt)
- Example configuration: [`examples/dtnbasket.toml`](examples/dtnbasket.toml)
- Test script: [`examples/test_basket.py`](examples/test_basket.py)

## License

Dual-licensed under the Apache License, Version 2.0 or the MIT License. See [LICENSE.md](LICENSE.md).
