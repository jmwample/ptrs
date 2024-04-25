# o5 Pluggable Transport Library

This is a spiritual successor to `obfs4` updating some of the more annoying / out of
date elements without worrying about being backward compatible.


⚠️  🚧 WARNING This crate is still under construction 🚧 ⚠️
- protocol under development
- interface subject to change at any time 
- Not production ready
  - do not rely on this for any security critical applications

## Differences from obfs4

- Frame / Packet / Message construction
  - In obfs4 a "frame" consists of a signle "packet", encoded using xsalsa20Poly1305.
  we use the same frame construction, but change a few key elements:
    - the concept of "packets" is now called "messages"
    - a frame can contain multiple messages
    - update from xsalsa20poly1305 -> chacha20poly1305
    - padding is given an explicit message type different than that of a payload and uses the mesage length header field
      - (In obfs4 a frame that decodes to a payload packet type `\x00` with packet length 0 is asummed to all be padding)
      - move payload to message type `\x01`
      - padding takes message type `\x00`
    - (Maybe) add bidirectional heartbeat messages
- Handshake
  - x25519 key-exchange -> Kyber1024X25519 key-exchange
    - the overhead padding of the current obfs4 handshake (resulting in paket length in [4096:8192]) is mostly unused
    we exchange some of this unused padding for a kyber key to provide post-quantum security to the handshake.
    - Are Kyber1024 keys uniform random? I assume not.
  - NTor V3 handshake
    - the obfs4 handshake uses (a custom version of) the ntor handshake to derive key materials
  - (Maybe) change mark and MAC from sha256-128 to sha256
  - handshake parameters encrypted under the key exchange public keys
    - the client can provide initial parameters during the handshake, knowing that they are not forward secure.
    - the server can provide messages with parameters / extensions in the handshake response (like prngseed)
    - like the kyber key, this takes space out of the padding already used in the client handshake.
  - (Maybe) session tickets and resumption
  - (Maybe) handshake complete frame type

### Goals
* Stick closer to Codec / Framed implementation for all packets (hadshake included)
* use the tor/arti ntor v3 implementation

### Features to keep
- once a session is established, unrecognized frame types are ignored

