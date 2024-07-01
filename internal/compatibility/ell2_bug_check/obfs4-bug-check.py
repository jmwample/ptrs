#!/usr/bin/env python3


# Usage: obfs4-bug-check 192.95.36.142:443 qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ

import base64
import getopt
import hmac
import os
import socket
import re
import sys
import time

NUM_TRIALS = 20 # control with -n option
TIMEOUT = 5     # control with -t option

opts, (addr, cert) = getopt.gnu_getopt(sys.argv[1:], "n:t:")
for o, a in opts:
    if o == "-n":
        NUM_TRIALS = int(a)
    elif o == "-t":
        TIMEOUT = float(a)
host, port = re.match(r'^\[?(.*?)\]?:(\d+)$', addr).groups()
port = int(port)
cert = base64.b64decode(cert + "==="[:(4-len(cert)%4)%4])
nodeid = cert[:20]
pubkey = cert[20:]
assert len(nodeid) == 20
assert len(pubkey) == 32

def mac(msg):
    return hmac.digest(pubkey + nodeid, msg, "sha256")[0:16]

def trial():
    # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/doc/obfs4-spec.txt#L156-163
    repr = os.urandom(32)
    padding = os.urandom(85)
    mark = mac(repr)
    epoch_hours = str(int(time.time()) // 3600).encode()
    s = socket.create_connection((host, port), TIMEOUT)
    try:
        s.send(repr + padding + mark + mac(repr + padding + mark + epoch_hours))
        r = s.recv(32)
        return (r[31] & 0x80) != 0
    finally:
        s.close()

num_ones = 0
err = None
try:
    for _ in range(NUM_TRIALS):
        if trial():
            dot = "1"
            num_ones += 1
        else:
            dot = "."
        print(dot, flush = True, end = "")
except Exception as e:
    print("X", flush = True, end = "")
    err = e
    report = ("ERROR", str(err))
else:
    report = ("PASS" if num_ones > 0 else "FAIL", f"{num_ones}/{NUM_TRIALS}")
print(*(("", addr) + report))
if err is not None:
    sys.exit(2)
elif num_ones == 0:
    sys.exit(1)
else:
    sys.exit(0)

