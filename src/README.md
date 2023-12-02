
Features for o7

* Fully Encrypted
* prime field group
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

- crate feature for `c_impl` vs `dalek` elligator2.
- double check the bit randomization and clearing for high two bits in the `c_impl`
- ntor interface & handshake implementation
- end-to-end socks proxy
- server / client compatibility test go-to-rust and rust-to-go.

