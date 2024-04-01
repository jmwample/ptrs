# o7 Pluggable Transport

Experimental randomizing look-like-nothing pluggable transport library in the spirit of obfs4.

### Features for o7

* Fully Encrypted
* quantum forward secrecy (i.e. ed25519 + Kyber)
* reliability layer inside encryption layer
* if outer transport is reliable (i.e. TCP) inner reliability can be disabled
* if reliability is not required in general, it can be disabled
* operates as:
  - Wrap (client, or server)
  - Dialer
  - Peer


**Supporting**

- kcp / quic / sctp for ordering / reliability
    - trim quiche down to just quic (no tls / H3)

- kyber (512 / 768 / 1024) keys mapping to uniform random? i.e. elligator2 for kyber

- browser extension for capturing traffic shapes.

- multi-path transport (multipath quic / kcp) with modern congestion control options

- water wasm transport integration


### Changes from o5

* Designed for udp
    - or any transport really, just don't require our reliability layer to be the outermost
* allow reliable or unreliable traffic modes
* multiple streams per tunnel
    - reliability set per stream not per tunnel
* connection resumption + tickets
* traffic shaping driven send rates & padding
    - browser extension for capturing traffic shapes of real sessions securely.

---

* Why shift from the obfs4 style naming and use o7? 

    I am writing the library and I like it that way.

* What happened to o6? 

    See the answer above.

