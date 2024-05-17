#!/usr/bin/env python3

# Usage: obfs4-subgroup-check [-n NUM_TRIALS] [-t TIMEOUT] 192.95.36.142:443 qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ
# The second argument is the "cert" parameter from the bridge line.
#
# Probabilistic remote check for the obfs4proxy subgroup-only public key
# distinguishability issue. This issue makes all versions of obfs4proxy up to
# and including v0.0.13 distinguishable from random. Information about the
# general class of the bug:
#   https://elligator.org/key-exchange heading "Step 2"
#   https://loup-vaillant.fr/articles/implementing-elligator heading "Dodging a bullet"
#   https://www.reddit.com/r/crypto/comments/fd9t3m/elligator_with_x25519_is_broken_what_workaround/
#
# The program runs multiple trials. The number of trials can be controlled by
# the -n command line option. If any trial returns a representative that can
# *not* have been computed by an affected obfs4proxy, then the test is a PASS.
# Otherwise, the test is a FAIL.
#
# This check does not use information about the server's NODEID or PUBKEY except
# to elicit a response from the server; after getting the response, the check
# function only takes as input 32 bytes from the server handshake. In other
# words, it only uses information that would be available to a passive
# unauthenticated eavesdropper, watching an authenticated connection.
#
# Exit status
#   0 for PASS: server is random or not obfs4proxy
#   1 for FAIL: server is obfs4proxy
#   2 for a runtime error

import base64
import getopt
import hmac
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

NUM_TRIALS = 15 # control with -n option
TIMEOUT = 5     # control with -t option

def from_bytes(b):
    """Convert a little-endian byte string into a GF field element."""
    n = 0
    for x in reversed(b):
        n *= 256
        n += x
    return GF(n)

def from_bytes_255(b):
    """Convert a little-endian byte string of length 32 into a GF field element,
    ignoring the two most significant bits."""
    if len(b) != 32: raise AssertionError
    return from_bytes(b[:31] + bytes([b[31] & 0b01111111]))

def from_bytes_254(b):
    """Convert a little-endian byte string of length 32 into a GF field element,
    ignoring the two most significant bits."""
    if len(b) != 32: raise AssertionError
    return from_bytes(b[:31] + bytes([b[31] & 0b00111111]))

def check(Yrb):
    """Check the first 32 bytes of a server handshake (the server's serialized
    Elligator public key representative) and return a boolean indicating whether
    they represent a public key that is off the prime-order subgroup of
    Curve25519, regardless of whether the representative is interpreted
    according to pre-v0.0.12 conventions or post-v0.0.12 conventions."""
    # We don't know whether we are dealing with a pre-v0.0.12 obfs4proxy (which
    # uses 255 bits of the representative) or a post-v0.0.12
    # obfs4proxy (which uses 254 bits of the representative). Try it both ways,
    # and convervatively return True only if the point is off the subgroup in
    # both cases.
    #
    # When bit 254 is 0, these two interpretations are the same, and the
    # probability of a random string being off the subgroup is 3/4. When bit 255
    # is 1, then the two interpretations each have probability 3/4 of
    # being off the subgroup; they are both off the subgroup with probability
    # 9/16. Since bit 254 is either 0 or 1 with probability 1/2, the probability
    # that a random string represents a point off the subgroup is the average of
    # 3/4 and 9/16, or 21/32.

    Yr_255 = from_bytes_255(Yrb)
    Y_255 = elligator_dir_map(Yr_255)[0]
    # Multiply the point by the order of the prime-order subgroup, check if it
    # is the identity.
    off_subgroup_255 = Mt.scalarmult(Y_255, Mt.order).to_num() != 0

    Yr_254 = from_bytes_254(Yrb)
    Y_254 = elligator_dir_map(Yr_254)[0]
    off_subgroup_254 = Mt.scalarmult(Y_254, Mt.order).to_num() != 0

    return off_subgroup_255 and off_subgroup_254

def trial(addr, server_nodeid, server_pubkey):
    """Connect to the remote host addr, do a partial obfs4 handshake, and return
    an boolean indicating whether the remote server sent a string that maps to a
    public key that is off the prime-order subgroup of Curve25519."""
    def mac(msg):
        return hmac.digest(server_pubkey + server_nodeid, msg, "sha256")[0:16]
    Xrb = os.urandom(32)
    padding = os.urandom(85)
    mark = mac(Xrb)
    epoch_hours = str(int(time.time()) // 3600).encode()
    s = socket.create_connection((host, port), TIMEOUT)
    try:
        # Client handshake
        # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/doc/obfs4-spec.txt#L156-163
        s.send(Xrb + padding + mark + mac(Xrb + padding + mark + epoch_hours))
        # Server handshake
        # https://gitlab.com/yawning/obfs4/-/blob/obfs4proxy-0.0.13/doc/obfs4-spec.txt#L211-216
        Yrb = s.recv(32)
        if len(Yrb) != 32: raise AssertionError(Yrb)
    finally:
        s.close()
    return check(Yrb)

opts, (addr, cert) = getopt.gnu_getopt(sys.argv[1:], "n:t:")
for o, a in opts:
    if o == "-n":
        NUM_TRIALS = int(a)
    elif o == "-t":
        TIMEOUT = float(a)
host, port = re.match(r'^\[?(.*?)\]?:(\d+)$', addr).groups()
port = int(port)
cert = base64.b64decode(cert + "==="[:(4-len(cert)%4)%4])
if len(cert) != 52:
    raise ValueError(cert)
server_nodeid = cert[ 0:20]
server_pubkey = cert[20:52]

num_successes = 0
err = None
try:
    for _ in range(NUM_TRIALS):
        if trial((host, port), server_nodeid, server_pubkey):
            dot = f"#"
            num_successes += 1
        else:
            dot = "."
        print(dot, flush = True, end = "")
except Exception as e:
    print("X", flush = True, end = "")
    print("", addr, "ERROR", str(e))
    traceback.print_exc()
    sys.exit(2)
else:
    print("", addr, "PASS" if num_successes > 0 else "FAIL", f"{num_successes}/{NUM_TRIALS}")
    sys.exit(0 if num_successes > 0 else 1)
