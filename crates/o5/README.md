# o5 Pluggable Transport Library

A randomizing look like nothing pluggable transport library, spiritually a successor
to `obfs4`.


⚠️  🚧 WARNING This crate is still under construction 🚧 ⚠️
- protocol under development
- interface subject to change at any time 
- Not production ready
  - do not rely on this for any security critical applications


## Changes from obfs4:


* adds `Kyber1024` to the Key exchange making it hybrid `Kyber1024X25519` (or `Kyber1024X`)
    * Are Kyber1024 keys uniform random? I assume not.
* aligns algorithm with vanilla ntor
    - obfs4 does an extra hash
* change mark and MAC from sha256-128 to sha256
    - not sure why this was done in the first place
* padding change (/fix?)
* padding is a frame type, not just appended bytes
* version / params frame for negotiating (non-forward secret in the first exchange alongside PRNG seed)
* might add
    - session tickets and resumption
    - bidirectional heartbeats
    - handshake complete frame type 


### Goals
* Stick closer to Codec / Framed implementation for all packets (hadshake included)
* use the tor/arti ntor v3 implementation


### Features to keep
- once a session is established, unrecognized frame types are ignored

