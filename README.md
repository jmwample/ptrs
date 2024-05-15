# Pluggable Transports in Rust (PTRS)

<p>
  <a href="https://github.com/jmwample/ptrs/actions/workflows/rust.yml">
    <img src="https://github.com/jmwample/ptrs/actions/workflows/rust.yml/badge.svg?branch=main" alt="Build Status">
  <a href="https://codecov.io/gh/jmwample/ptrs" >
    <img src="https://codecov.io/gh/jmwample/ptrs/graph/badge.svg?token=0lMlrA32xd"/>
  </a>
  <a href="https://deps.rs/repo/github/jmwample/ptrs">
    <img src="https://deps.rs/repo/github/jmwample/ptrs/status.svg">
  </a>
  <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>

This repository contains multiple related crates implementing the lyrebird (obfs4) library,
lyrebird binary, and Pluggable Transports in Rust (PTRS) library.


|                 Crate                    |   Description  | Crates.io | Docs | MSRV |
-------------------------------------------|----------------|-----------|------|------|
| [`ptrs`](./crates/ptrs) | A library supporting implementation and integration of Pluggable Transport protocols. | [![](https://img.shields.io/crates/v/ptrs.svg)](https://crates.io/crates/ptrs) | [![](https://img.shields.io/docsrs/ptrs)](https://docs.rs/ptrs) | 1.63 |
| [`lyrebird`](./crates/lyrebird) | Implementation of the `Lyrebird` Tor bridge and a forward proxy compatible with `ptrs`. | [![](https://img.shields.io/crates/v/lyrebird.svg)](https://crates.io/crates/lyrebird) | [![](https://docs.rs/lyrebird/badge.svg)](https://docs.rs/lyrebird) | 1.70 |
| [`obfs4`](./crates/obfs4) | An implementation of obfs4 pluggable transport library in pure rust. | [![](https://img.shields.io/crates/v/obfs4.svg)](https://crates.io/crates/obfs4) | [![](https://docs.rs/obfs4/badge.svg)](https://docs.rs/obfs4) | 1.70 |

## MSRV

The planned Minimum Supported Rust Version (MSRV) is 1.60, however there is no
current testing to ensure that this is working currently.

MSRV can be changed in the future, but it will be done with a minor version bump.

## Related

Things to keep an eye on:

- [ ] PR implementating elligator2 for the `dalek` ed25519 library. [PR Here](https://github.com/dalek-cryptography/curve25519-dalek/pull/612)

## Open Source License

Dual licensing under both MIT and Apache-2.0 is the currently accepted standard by the Rust language
community and has been used for both the compiler and many public libraries since (see
[Why dual MIT/ASL2license?](https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license)).
In order to match the community standards, ptrs is using the dual MIT+Apache-2.0 license.

## Contributing

Contributions, Issues, and Pull Requests are welcome!

## Potential logos?

These logos were generated using DALLE-3

<div style="display:inline-block;">
<img src="doc/dalle3/DALLE_crab_logo_1.webp" alt="logo 1"  width="200">
<img src="doc/dalle3/DALLE_crab_logo_2.webp" alt="logo 2"  width="200">
<img src="doc/dalle3/DALLE_crab_logo_3.webp" alt="logo 3"  width="200">
<img src="doc/dalle3/DALLE_crab_logo_4.webp" alt="logo 4"  width="200">
<img src="doc/dalle3/DALLE_crab_logo_5.webp" alt="logo 5"  width="200">
</div>
