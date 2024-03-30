# o7 Proxy

<p>
  <a href="https://github.com/jmwample/o7/actions/workflows/rust.yml">
    <img src="https://github.com/jmwample/o7/actions/workflows/rust.yml/badge.svg?branch=main" alt="Build Status">
  <a href="https://codecov.io/gh/jmwample/o7" > 
    <img src="https://codecov.io/gh/jmwample/o7/graph/badge.svg?token=0lMlrA32xd"/> 
  </a>
  <a href="https://deps.rs/repo/github/jmwample/o7">
    <img src="https://deps.rs/repo/github/jmwample/o7/status.svg">
  </a>
  <a href="https://crates.io/crates/o7">
    <img src="https://img.shields.io/crates/v/o7.svg">
  </a>
  <a href="https://docs.rs/o7">
    <img src="https://docs.rs/o7/badge.svg">
  </a>
  <a href="https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license">
    <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue" alt="License: MIT/Apache 2.0">
  </a>
</p>


This repository contains multiple related crates implementing the lyrebird (obfs4) library,
lyrebird binary, and Pluggable Transports in Rust (PTRS) library. 

Things to keep an eye on:

- [ ] PR implementating elligator2 for the `dalek` ed25519 library. [PR Here](https://github.com/dalek-cryptography/curve25519-dalek/pull/612)


## Examples

<details>
<summary>Obfs4 Client Example</summary>

```rs
let client = Client::from_param_str("");

let mut conn = tokio::net::TcpStream::Connect();

c = client.wrap(&mut conn);

```

</details>

## Command Line Interface


<details>
<summary>CLI Options</summary>

can be compiled and run, or run using the rust binary

```sh
cargo install .....
```

</details>

## FAQ

* Why shift from the obfs4 style naming and use o7? 

    I wrote the library and I like it that way. Don't like the name? Fork it
    and maintain it yourself.

* What happened to o6? 

    See the answer above.

## Open Source License

Dual licensing under both MIT and Apache-2.0 is the currently accepted standard by the Rust language
community and has been used for both the compiler and many public libraries since (see
[Why dual MIT/ASL2license?](https://doc.rust-lang.org/1.6.0/complement-project-faq.html#why-dual-mitasl2-license)).
In order to match the community standards, o7 is using the dual MIT+Apache-2.0 license.

## MSRV Policy

Minimum Supported Rust Version (MSRV) can be changed in the future, but it will be done with a minor version bump.

## Contributing

Contributors, Issues, and Pull Requests are Welcome!
