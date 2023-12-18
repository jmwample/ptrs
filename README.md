# o7 Proxy

things I would like to do:

- [ ] elligator2 implementation using `dalek` ed25519 library.


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

## Contributing

Contributors, Issues, and Pull Requests are Welcome!
