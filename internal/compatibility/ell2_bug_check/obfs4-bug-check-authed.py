#!/usr/bin/env python3

# Usage: obfs4-bug-check-authed [-t TIMEOUT] [-v] 192.95.36.142:443 qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ
# The second argument is the "cert" parameter from the bridge line.
#
# Deterministic remote check for the obfs4proxy Elligator public key
# representative distinguishability issues that were fixed in this commit, which
# was released in version v0.0.12:
# https://gitlab.com/yawning/obfs4/-/commit/393aca86cc3b1a5263018c10f87ece09ac3fd5ed
#
# The test takes advantage of an interoperability issue that arose as a side
# effect of the distinguishability fix. By sending a public key representative
# that has the high bit set, we force the authentication error to happen every
# time, not just 3/4 of the time.
# https://bugs.torproject.org/tpo/applications/tor-browser/40804
# https://gitlab.com/yawning/obfs4/-/issues/15
#
# The test output is deterministic: a PASS result means a patched (post-v0.0.12)
# obfs4proxy server; FAIL means an unpatched obfs4proxy; ERROR means a runtime
# error (such as a timeout which can be caused by an incorrect "cert"
# parameter); and NOTOBFS4 means a non-obfs4 service. The test uses information
# that would not be available to a naive passive adversary, namely the server's
# NODEID and PUBKEY (which are encoded in the "cert"). However, such an
# adversary can do a passive check that is probabilistic but nearly as
# effective.
#
# Exit status
#   0 for PASS: server is post-v0.0.12 obfs4proxy
#   1 for FAIL: server is pre-v0.0.12 obfs4proxy
#   2 for a runtime error
#   3 for NOTOBFS4: server's response does not look like obfs4

import base64
import getopt
import hmac
import io
import math
import os
import re
import socket
import sys
import time
import traceback


# Elligator reference implementation by Loup Vaillant
# https://elligator.org/src/core

####################
# Field arithmetic #
####################
class GF():
    """Finite field over some prime number.

    Only prime fields are supported.
    No extension field here.
    This class is supposed to be derived,
    so the prime number p is defined

    the fowlowing is not implemented, and must be defined
    with inheritance or monkey patching:
    - p                 : characteristic of the field
    - is_negative(self) : set of negative field elements
    """

    def __init__(self, x):
        GF.msb         = round(math.log(GF.p, 2)) - 1
        GF.nb_bytes    = math.ceil((GF.msb + 1) / 8)
        GF.nb_pad_bits = GF.nb_bytes * 8 - GF.msb - 1
        GF.max_pad     = 2**GF.nb_pad_bits
        self.val       = x % self.p

    # Basic arithmetic operations
    def __neg__     (self   ): return GF(-self.val                            )
    def __add__     (self, o): return GF( self.val +  o.val                   )
    def __sub__     (self, o): return GF( self.val -  o.val                   )
    def __mul__     (self, o): return GF((self.val *  o.val         ) % self.p)
    def __truediv__ (self, o): return GF((self.val *  o.invert().val) % self.p)
    def __floordiv__(self, o): return GF( self.val // o) # same as __truediv__
    def __pow__     (self, s): return GF(pow(self.val, s       , self.p))
    def invert      (self   ): return GF(pow(self.val, self.p-2, self.p))

    def __eq__(self, other): return self.val % self.p == other.val % self.p
    def __ne__(self, other): return self.val % self.p != other.val % self.p

    def is_positive(self)  : return not self.is_negative()
    def abs(self):
        if self.is_positive(): return  self
        else                 : return -self

    def to_num(self):
        return self.val % self.p

    def __str__ (self): return str(self.to_num())
    def __repr__(self): return str(self.to_num())

##################################
# Scalar clamping (X25519, X448) #
##################################
def clamp(scalar):
    clamped = scalar - scalar % Mt.cofactor
    clamped = clamped % 2**GF.msb
    clamped = clamped + 2**GF.msb
    return clamped

################################
# Basic square root operations #
################################
def legendre(n):
    """Legendre symbol:

    returns  0 if n is zero
    returns  1 if n is a non-zero square
    returns -1 if n is not a square
    """
    return n**((GF.p-1)//2)

def is_square(n):
    c = legendre(n)
    return c == GF(0) or c == GF(1)

###########################
# Constant time selection #
###########################
def cswap(a, b, swap):
    """Conditionnal swapping

    Usage:
        a, b = cswap(a, b, swap)

    Swaps a and b if swap is true,
    does nothing otherwise.

    Production code is supposed to run in constant time.
    Be aware that this code does not.
    """
    if swap: return b, a
    else   : return a, b

def cmove(a, b, move):
    """Conditionnal assignment

    Usage:
        a = cmove(a, b, move)

    Assigns the value of b to a if move is true,
    does nothing otherwise.

    Production code is supposed to run in constant time.
    Be aware that this code does not.
    """
    if move: return b
    else   : return a

####################
# Montgomery curve #
####################
class Mt():
    """Montgomery curve

    The following must be defined with monkey patching:
    - A     : curve constant
    - base_c: special base point that covers the whole curve

    The curve constant B is assumed equal to 1 (it has to be for the
    Montgomery curve to be compatible with Elligator2).
    """
    def scalarmult(u, scalar):
        """Scalar multiplication in Montgomery space

        This is an "X-only" laddder, that only uses the u coordinate.
        This conflates points (u, v) and (u, -v).
        """
        u2, z2 = GF(1), GF(0) # "zero" point
        u3, z3 = u    , GF(1) # "one"  point
        binary = [int(c) for c in list(format(scalar, 'b'))]
        for b in binary:
            # Montgomery ladder step:
            # if b == 0, then (P2, P3) == (P2*2 , P2+P3)
            # if b == 1, then (P2, P3) == (P2+P3, P3*2 )
            swap   = b == 1  # Use constant time comparison
            u2, u3 = cswap(u2, u3, swap)
            z2, z3 = cswap(z2, z3, swap)
            u3, z3 = ((u2*u3 - z2*z3)**2, (u2*z3 - z2*u3)**2 * u)
            u2, z2 = ((u2**2 - z2**2)**2,
                      GF(4)*u2*z2*(u2**2 + Mt.A*u2*z2 + z2**2))
            u2, u3 = cswap(u2, u3, swap)
            z2, z3 = cswap(z2, z3, swap)
        return u2 / z2

# Elligator reference implementation by Loup Vaillant
# https://elligator.org/src/curve25519

####################
# field parameters #
####################
GF.p = 2**255 - 19

def is_negative(self):
    """True iff self is in [p.+1 / 2.. p-1]

    An alternative definition is to just test whether self is odd.
    """
    dbl = (self.val * 2) % GF.p
    return dbl % 2 == 1

GF.is_negative = is_negative

#########################
# Square root functions #
#########################
sqrt_m1 = (GF(2)**((GF.p-1) // 4)).abs() # sqrt(-1)

def sqrt(n):
    """ Non-negative square root of n

    If n is not a square, the behaviour is undefined.

    To know how it works, refer to https//elligator.org/sqrt
    """
    root = n**((GF.p+3) // 8)
    root = cmove(root, root * sqrt_m1, root * root != n)
    return root.abs() # returns the non-negative square root

def inv_sqrt(x):
    """Inverse square root of x

    Returns (0               , True ) if x is zero.
    Returns (sqrt(1/x)       , True ) if x is non-zero square.
    Returns (sqrt(sqrt(-1)/x), False) if x is not a square.

    The return value is *not* guaranteed to be non-negative.
    """
    isr       = x**((GF.p - 5) // 8)
    quartic   = x * isr**2
    # Use constant time comparisons in production code
    m_sqrt_m1 = quartic == GF(-1) or quartic == -sqrt_m1
    is_square = quartic == GF(-1) or quartic == GF(1) or x == GF(0)
    isr       = cmove(isr, isr * sqrt_m1, m_sqrt_m1)
    return isr, is_square

####################
# Curve parameters #
####################

# Montgomery constants (We already assume B = 1)
Mt.A = GF(486662)

# curve order and cofactor
Mt.order    = 2**252 + 27742317777372353535851937790883648493
Mt.cofactor = 8

# Standard base point, that generates the prime order sub-group
Mt.base = GF(9)                # Montgomery base point

########################
# Elligator parameters #
########################
Z       = GF(2)          # sqrt(-1) is sometimes faster...
ufactor = -Z * sqrt_m1   # ...because then both ufactor
vfactor = sqrt(ufactor)  # and vfactor are equal to 1

# Elligator reference implementation by Loup Vaillant
# https://elligator.org/src/elligator

###########################################
# Fast Implementation (explicit formulas) #
###########################################
def elligator_dir_map(r):
    """Computes a point (u, v) from the representative r in GF(p)

    Always succeeds
    """
    u  = r**2
    t1 = u * Z
    v  = t1 + GF(1)
    t2 = v**2
    t3 = Mt.A**2
    t3 = t3 * t1
    t3 = t3 - t2
    t3 = t3 * Mt.A
    t1 = t2 * v
    t1, is_square = inv_sqrt(t3 * t1)
    u  = u * ufactor  # no-op if ufactor == 1
    v  = r * vfactor  # copy  if vfactor == 1
    u  = cmove(u, GF(1), is_square)
    v  = cmove(v, GF(1), is_square)
    v  = v * t3
    v  = v * t1
    t1 = t1**2
    u  = u * -Mt.A
    u  = u * t3
    u  = u * t2
    u  = u * t1
    t1 = -v
    v  = cmove(v, t1, is_square != v.is_negative()) # use constant time XOR
    return (u, v)

def elligator_rev_map(u, v_is_negative):
    """Computes the representative of the point (u, v), if possible

    Returns None if the point cannot be mapped.
    """
    t = u + Mt.A
    r = -Z * u
    r = r * t
    r, is_square = inv_sqrt(r)
    if not is_square:
        return None
    u = cmove(u, t, v_is_negative)
    r = u * r
    t = -r
    r = cmove(r, t, r.is_negative()) # abs(rep)
    return r

# Checker starts here.

TIMEOUT = 5     # control with -t option
VERBOSE = False # control with -v option

def print_verbose(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def from_bytes(b):
    """Convert a little-endian byte string into a GF field element."""
    n = 0
    for x in reversed(b):
        n *= 256
        n += x
    return GF(n)

def from_bytes_254(b):
    """Convert a little-endian byte string of length 32 into a GF field element,
    ignoring the two most significant bits."""
    if len(b) != 32: raise AssertionError
    return from_bytes(b[:31] + bytes([b[31] & 0b00111111]))

def to_bytes(n):
    """Convert a GF field element into a little-endian byte string of
    length 32."""
    n = n.to_num()
    b = []
    for _ in range(32):
        b.append(n % 256)
        n //= 256
    if n != 0: raise AssertionError(n)
    return bytes(b)

def recv_until_delim(s, delim, deadline, limit = 10000):
    """Call recv on s until the time deadline, until at least limit bytes have
    been received, or until the given delimiter is found. Return True if and
    only if the delimiter was found."""
    buf = io.BytesIO()
    while len(buf.getvalue()) < limit:
        s.settimeout(deadline - time.time())
        data = s.recv(1024)
        if not data:
            break
        buf.write(data)
        if delim in buf.getvalue():
            return True
    return False

def ntor_client(x, X, Y, B, ID):
    """Compute the client's obfs4-flavored ntor AUTH string."""
    PROTOID = b"ntor-curve25519-sha256-1"
    # tor-spec.txt (and the earlier proposal 216) specify ntor inputs as:
    # https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt?id=79da008392caed38736c73d839df7aa80628b645#n1220
    # https://gitweb.torproject.org/torspec.git/tree/proposals/216-ntor-handshake.txt?id=d48eaa7db2b165b2e1f5817381d978f498806525#n42
    #   secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
    #   verify = H(secret_input, PROTOID|":verify")
    #   auth_input = verify | ID | B | Y | X | PROTOID | "Server"
    #   AUTH == H(auth_input, PROTOID|":mac")
    # obfs4proxy does it differently. Notice duplicate B inputs, swapped order
    # of X and Y in auth_input, ID moved to after PROTOID, and ":key_verify"
    # instead of ":verify":
    # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/common/ntor/ntor.go#L382
    # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/common/ntor/ntor.go#L80
    #   secret_input = EXP(Y,x) | EXP(B,x) | B | B | X | Y | PROTOID | ID
    #   verify = H(secret_input, PROTOID|":key_verify")
    #   auth_input = verify | ID | B | B | X | Y | PROTOID | ID | "Server"
    #   AUTH == H(auth_input, PROTOID|":mac")
    # For reference, the specification from the ntor paper (Section 6):
    # https://www.cypherpunks.ca/~iang/pubs/ntor.pdf#page=18
    def H(msg, context):
        return hmac.digest(PROTOID + b":" + context, msg, "sha256")
    verify = H(b"".join([
        to_bytes(Mt.scalarmult(Y, x.to_num())),
        to_bytes(Mt.scalarmult(from_bytes(B), x.to_num())),
        B,
        B,
        to_bytes(X),
        to_bytes(Y),
        PROTOID,
        ID,
    ]), b"key_verify")
    return H(b"".join([
        verify,
        B,
        B,
        to_bytes(X),
        to_bytes(Y),
        PROTOID,
        ID,
        b"Server",
    ]), b"mac")

def check(x, server_nodeid, server_pubkey, Yrb, server_auth):
    """Check the locally computed ntor AUTH string against the server's reported
    AUTH, given a client private key, server NODEID and PUBKEY, and the first 64
    bytes of a server handshake."""
    X = Mt.scalarmult(Mt.base, x.to_num())

    print_verbose("Y'  ", Yrb.hex())
    Yr = from_bytes_254(Yrb)
    Y = elligator_dir_map(Yr)[0]
    print_verbose("Y ", "0x{:064x}".format(Y.to_num()))

    client_auth = ntor_client(x, X, Y, server_pubkey, server_nodeid)
    print_verbose("server auth", server_auth.hex())
    print_verbose("client auth", client_auth.hex())
    return server_auth == client_auth

class NotObfs4Error(Exception):
    def __str__(self):
        return "not obfs4"

def trial(addr, server_nodeid, server_pubkey):
    """Connect to the remote host addr, send a public key representative that is
    designed to provoke an authentication failure in services other than patched
    obfs4, and return a boolean indicating whether the authentication strings
    matched.

    Besides returning True or False, this function may raise a NotObfs4Error if
    the server's response does not resemble obfs4, given server_nodeid and
    server_pubkey."""
    # We need an Elligator-mappable public key. It happens that the secret key
    # that results from clamping 256 zero bits yields such a public key. The
    # randomness of client padding is enough to avoid getting caught in the
    # server's replay filter.
    s = 0
    x = GF(clamp(s))
    print_verbose("x ", "0x{:064x}".format(x.to_num()))
    X = Mt.scalarmult(Mt.base, x.to_num())
    print_verbose("X ", "0x{:064x}".format(X.to_num()))
    Xr = elligator_rev_map(X, False)
    if Xr is None: raise AssertionError

    Xrb = to_bytes(Xr)
    # The interoperability problem between versions of obfs4proxy before and
    # after v0.0.12 arises whenever *either* side has bit 254 set in the
    # serialized form of its Elligator public key representative. We guarantee a
    # failure by ensure that bit 254 in our serialized representative is always
    # set. Pre-v0.0.12 obfs4proxy will interpret bit 254 rather than ignore it,
    # which means it will derive an incorrect value for the client's public key
    # and the ntor authentication check will fail. If we did not set this bit,
    # the ntor check would fail only half the time; i.e., when the server's
    # representative has bit 254 set.
    if not (Xrb[31] & 0x11000000) == 0: raise AssertionError(Xrb)
    Xrb = Xrb[0:31] + bytes([(Xrb[31] & 0b00111111) | 0b01000000])
    print_verbose("X'  ", Xrb.hex())

    def mac(msg):
        return hmac.digest(server_pubkey + server_nodeid, msg, "sha256")[0:16]
    padding = os.urandom(85)
    mark = mac(Xrb)
    epoch_hours = str(int(time.time()) // 3600).encode()
    deadline = time.time() + TIMEOUT
    s = socket.create_connection((host, port), TIMEOUT)
    try:
        # Client handshake
        # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/doc/obfs4-spec.txt#L156-163
        s.send(Xrb + padding + mark + mac(Xrb + padding + mark + epoch_hours))
        data = s.recv(64)
        if len(data) != 64: raise AssertionError(data)
        # Server handshake
        # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/doc/obfs4-spec.txt#L211-216
        Yrb = data[0:32]
        server_auth = data[32:64]
        # Besides the ntor auth check which is the main point of this function,
        # we also consume more of the handshake looking for the "mark"
        # HMAC-SHA256-128(B | NODEID, Y'). This allows us to provide distinct
        # output for non-obfs4 services, rather than just "FAIL".
        try:
            is_obfs4 = recv_until_delim(s, mac(Yrb), deadline)
            if not is_obfs4:
                raise NotObfs4Error
        except socket.timeout:
            raise NotObfs4Error
    finally:
        s.close()

    return check(x, server_nodeid, server_pubkey, Yrb, server_auth)

opts, (addr, cert) = getopt.gnu_getopt(sys.argv[1:], "t:v")
for o, a in opts:
    if o == "-t":
        TIMEOUT = float(a)
    elif o == "-v":
        VERBOSE = True
host, port = re.match(r'^\[?(.*?)\]?:(\d+)$', addr).groups()
port = int(port)
cert = base64.b64decode(cert + "==="[:(4-len(cert)%4)%4])
if len(cert) != 52:
    raise ValueError(cert)
server_nodeid = cert[ 0:20]
server_pubkey = cert[20:52]

try:
    result = trial((host, port), server_nodeid, server_pubkey)
except NotObfs4Error:
    print(addr, "NOTOBFS4")
    sys.exit(3)
except Exception as e:
    print(addr, "ERROR", str(e))
    traceback.print_exc()
    sys.exit(2)
else:
    print(addr, "PASS" if result else "FAIL")
    sys.exit(0 if result else 1)
