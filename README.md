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

Because I want to and I wrote the library. Don't like the name? Fork it and maintain it yourself.

* What happened to o6? 

See the answer above.
