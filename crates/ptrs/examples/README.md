
# Minimal Example Transports.


**Passthrough** - Does nothing but forward traffic.


**Split** - (TODO) There's no protocol obfuscation, no
encryption, but the link between the client and server uses *two* TCP
connections, both of which are unidirectional: one is used only for
upstream and the other is used only for downstream. The server listens
on two ports, and when the client connects, it connects to both ports.


**UDP** - (TODO) Demonstrate that the ptrs model works for transports wrapping
unreliable channels (if they are designed to be).
