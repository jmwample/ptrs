# Obfs4 - The obfourscator - Pluggable Transport


An implementation of obfs4 in pure rust



## Installation

To install, add the following to your project's Cargo.toml:

```
[dependencies]
obfs4 = "0.1.0"
```

## Integration Examples


Client example using [ptrs](../ptrs)

```rs
use ptrs::{Args, ClientBuilder as _, ClientTransport as _};
use obfs4;
use tokio::net::TcpStream;

let args = Args::from_str("")?;
let client = ClientBuilder::default()
    .options(args)?
    .build();

// future that opens a tcp connection when awaited
let conn_future = TcpStream::connect("127.0.0.1:9000");

// await (create) the tcp conn, attempt to handshake, and return a wrapped Read/Write object on success.
let obfs4_conn = client.wrap(box::pin(conn_future)).await?;

// ...
```


Server example

```rs
let message = b"Hello universe";
let (mut c, mut s) = tokio::io::duplex(65_536);
let mut rng = rand::thread_rng();

let o4_server = Server::new_from_random(&mut rng);

tokio::spawn(async move {
    let mut o4s_stream = o4_server.wrap(&mut s).await.unwrap();

    let mut buf = [0_u8; 50];
    let n = o4s_stream.read(&mut buf).await.unwrap();

    // echo the message back over the tunnel
    o4s_stream.write_all(&buf[..n]).await.unwrap();
});
```

Server example using [ptrs](../ptrs)

```rs
use ptrs::{ServerBuilder, ServerTransport};
...

// TODO fill out example
```

### Loose Ends:

- [X] server / client compatibility test go-to-rust and rust-to-go.
- [ ] end-to-end socks proxy
- [ ] length distribution things
- [ ] iat mode handling
- [ ] tracking resets / injections / replays


## Performance

- comparison to golang
- comparison when kyber is enabled
- NaCl encryption library(s)

