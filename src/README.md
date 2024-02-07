
Features for o7

* Fully Encrypted
* quantum forward secrecy (i.e. ed25519 + Kyber)
* reliability layer inside encryption layer
* if outer transport is reliable (i.e. TCP) inner reliability can be disabled
* if reliability is not required in general, it can be disabled


operates as:

Wrap (send, or recv)

Dialer

Listener

Peer?

---

TODO:

- double check the bit randomization and clearing for high two bits in the `dalek` representative
- ntor interface & handshake implementation
- end-to-end socks proxy
- server / client compatibility test go-to-rust and rust-to-go.

---

Obfs4

Loose Ends:
- length distribution things
- iat mode handling
- tracking resets / injections / replays
- geoip for obvious signs of censorship
- kyber negotiation frames
- params frame

Performance
- comparison to golang
- comparison when kyber is enabled

