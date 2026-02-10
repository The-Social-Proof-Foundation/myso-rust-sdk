# MySocial Rust SDK

The MySocial Rust SDK for integrating with the [MySocial blockchain](https://docs.mysocial.network/).

> [!NOTE]
> This is project is under development and many features may still be under
> development or missing.

## Overview

This repository contains a collection of libraries for integrating with the MySocial blockchain.

A few of the project's high-level goals are as follows:

* **Be modular** - user's should only need to pay the cost (in terms of dependencies/compilation time) for the features that they use.
* **Be light** - strive to have a minimal dependency footprint.
* **Support developers** - provide all needed types, abstractions and APIs to enable developers to build robust applications on MySocial.
* **Support wasm** - where possible, libraries should be usable in wasm environments.

## Crates

In an effort to be modular, functionality is split between a number of crates.

* [`myso-sdk-types`](crates/myso-sdk-types)
    [![myso-sdk-types on crates.io](https://img.shields.io/crates/v/myso-sdk-types)](https://crates.io/crates/myso-sdk-types)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/myso-sdk-types)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://mystenlabs.github.io/myso-rust-sdk/myso_sdk_types/)
* [`myso-crypto`](crates/myso-crypto)
    [![myso-crypto on crates.io](https://img.shields.io/crates/v/myso-crypto)](https://crates.io/crates/myso-crypto)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/myso-crypto)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://mystenlabs.github.io/myso-rust-sdk/myso_crypto/)
* [`myso-graphql-client`](crates/myso-crypto)
    [![myso-graphql-client on crates.io](https://img.shields.io/crates/v/myso-graphql-client)](https://crates.io/crates/myso-graphql-client)
    [![Documentation (latest release)](https://img.shields.io/badge/docs-latest-brightgreen)](https://docs.rs/myso-graphql-client)
    [![Documentation (master)](https://img.shields.io/badge/docs-master-59f)](https://mystenlabs.github.io/myso-rust-sdk/myso-graphql-client/)

## License

This project is available under the terms of the [Apache 2.0 license](LICENSE).
