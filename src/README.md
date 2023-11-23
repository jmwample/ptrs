
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
