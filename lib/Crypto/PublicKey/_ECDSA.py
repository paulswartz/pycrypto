
#
#   ECECDSA.py : Elliptic Curve Digital Signature Algorithm
#
#  Part of the Python Cryptography Toolkit
#
#  Written by Andrew Kuchling, Paul Swartz, and others
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================
#

__revision__ = "$Id$"

import math

from Crypto.Util import number


class error (Exception):
    pass


class _ECDSAKey(object):
    def size(self):
        """Return the maximum number of bits that can be encrypted"""
        return number.size(self.Q.T.p) - 1

    def has_private(self):
        return hasattr(self, 'd')

    def _sign(self, e, k):   # alias for _decrypt
        R = self.Q.T.G * k
        if R.x == 0:
            raise ValueError('invalid k value')
        s_num = (e + self.d * R.x) % self.Q.T.n
        s = (s_num * number.inverse(k, self.Q.T.n)) % self.Q.T.n
        if s == 0:
            raise ValueError('invalid k value')
        return (R.x, s)

    def _verify(self, e, r, s):
        if r < 0 or r > self.Q.T.n:
            return 0
        if s < 0 or s > self.Q.T.n:
            return 0
        w = number.inverse(s, self.Q.T.n)
        u1 = (e * w) % self.Q.T.n
        u2 = (r * w) % self.Q.T.n
        P1 = self.Q.T.G * u1
        P2 = self.Q * u2
        P = P1 + P2
        return P.x == r


def generate_py(T, randfunc, progress_func=None):
    """generate(curve:CurveDomain, randfunc:callable, progress_func:callable)

    Generate a ECDSA key on curve 'T', using 'randfunc' to get random
    data and 'progress_func', if present, to display the progress of the key
    generation.
    """
    if not T.verify():
        raise ValueError('Invalid curve')

    # Generate private key d and public key Q = dg
    if progress_func:
        progress_func('d\n')
    d = number.getRandomRange(1, T.n - 1, randfunc)
    if progress_func:
        progress_func('Q\n')
    Q = T.G * d
    return construct(Q, d)


def construct(Q, d=None):
    assert isinstance(Q, Point)
    assert Q.verify()
    obj = _ECDSAKey()
    obj.Q = Q

    if d:
        obj.d = d
        assert Q.T.G * d == Q

    return obj


def decode_point(bs, T):
    """
    Decode a string encoded version of a Point into a Point.
    """
    if not bs:
        raise error("can't decode a blank Point")
    if bs[0] == '\x00':
        return INFINITY
    elif bs[0] == '\x04':  # uncompressed point
        if len(bs) % 2 == 0:  # should be two even strings, plus 1 byte
            raise error('wrong length for uncompressed point')
        length = (len(bs) - 1) / 2 + 1
        x = number.bytes_to_long(bs[1:length])
        y = number.bytes_to_long(bs[length:])
    else:
        x = number.bytes_to_long(bs[1:])
        y_prime = (bs[0] == '\x03')
        alpha = (x ** 3 + T.a * x + T.b) % T.p
        beta = number.sqrt(alpha, T.p)
        if beta % 2 == y_prime:
            y = beta
        else:
            y = T.p - beta
    p = Point(x, y, T)
    if not p.verify():
        raise error("decoded an invalid point")
    return p


class Point:
    """
    Class representing a point on an elliptic curve.
    """
    def __init__(self, x, y, T):
        self.x = x
        self.y = y
        self.T = T

    def __repr__(self):
        if self.x is None and self.y is None:
            return u"Point(infinity)"
        return u"Point(%i, %i, %r)" % (self.x, self.y, self.T)

    def __eq__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        # XXX short-circuit; possible timing issue?
        return self.x == other.x and self.y == other.y and \
            self.T == other.T

    def encode(self, compress=True):
        if self.x is None:  # INFINITY:
            return '\x00'
        x_encoded = number.long_to_bytes(self.x)
        if not compress:
            y_encoded = number.long_to_bytes(self.y)
            return ''.join(('\x04', x_encoded, y_encoded))
        else:
            odd = self.y % 2
            if odd:
                return '\x03' + x_encoded
            else:
                return '\x02' + x_encoded

    def verify(self):
        """
        Verify that this point is on the curve.
        """
        if self.x is None and self.y is None:
            return True
        if self.x >= self.T.p or self.y >= self.T.p:
            return False
        left = pow(self.y, 2, self.T.p)
        right = (pow(self.x, 3, self.T.p) + (
                 self.T.a * self.x + self.T.b)) % self.T.p
        return left == right

    def __add__(self, other):
        # XXX use implementation on T instead of on this when we support 2**m
        # curves
        if not isinstance(other, Point):
            raise NotImplementedError
        if other.x is None and other.y is None:
            return self
        if self.x is None and self.y is None:
            return other
        if self.T != other.T:
            raise NotImplementedError
        if other.x == self.x:
            if other.y == self.y and self.y != 0:
                # double
                s_num = (3 * self.x ** 2 + self.T.a) % self.T.p
                s_dem = (2 * self.y) % self.T.p
                s = s_num * number.inverse(s_dem, self.T.p)
                x = (s ** 2 - (2 * self.x)) % self.T.p
                y = (s * (self.x - x) - self.y) % self.T.p
                return Point(x, y, self.T)
            else:
                return INFINITY
        else:
            # add
            s_num = (self.y - other.y) % self.T.p
            s_dem = (self.x - other.x) % self.T.p
            s = s_num * number.inverse(s_dem, self.T.p)
            x = (s ** 2 - self.x - other.x) % self.T.p
            y = s * (self.x - x) - self.y
            return Point(x, y % self.T.p, self.T)

    def __mul__(self, other):
        if not isinstance(other, (int, long)):
            raise NotImplementedError
        if not other:
            return INFINITY
        # implement scalar multiplication based on addition using the
        # add/double&add algorithm.  We also use a Montgomery ladder to avoid a
        # side-channel attack:
        # http://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
        bit_length = int(math.ceil(math.log(other, 2)))
        r0 = INFINITY
        r1 = self
        for i in range(bit_length, -1, -1):
            if (other & 2 ** i) == 2 ** i:
                r0 = r0 + r1
                r1 = r1 + r1
            else:
                r1 = r0 + r1
                r0 = r0 + r0
        return r0


INFINITY = Point(None, None, None)  # Infinity is on every curve


class CurveDomain:
    """
    Represents the variables necessary to describe an elliptic curve.  It has
    two classes, representing curves specified by Fp (PrimeCurveDomain) and
    F2**m (TwoPowerCurveDomain) respectively.

    * a and b are the curve domain parameters.

    * G is the generator point for the curve.  It is passed in as a tuple (Gx,
      Gy) and converted to a Point internally.

    * n is a prime which is the order of G

    * h is the cofactor which is #E(curve) / n
    """
    def __init__(self, a, b, G, n, h):
        self.a = a
        self.b = b
        self.G = Point(G[0], G[1], self)
        self.n = n
        self.h = h
        assert self.G.verify()
        assert self.verify()

    def verify(self):
        raise NotImplementedError


class PrimeCurveDomain(CurveDomain):
    """
    An elliptic curve domain specified by a prime number p.
    """
    def __init__(self, p, a, b, G, n, h):
        self.p = p
        CurveDomain.__init__(self, a, b, G, n, h)

    def __repr__(self):
        return u"<PrimeDomain: %i>" % self.p

    def verify(self, t=None):
        # Specified in SEC1 3.1.1.2.1
        if t is not None:
            log2_ceil = math.ceil(math.log(self.p, 2))
            if 80 < t < 256:
                if log2_ceil != 2 * t:
                    return False
            elif t == 80:
                if log2_ceil != 192:
                    return False
            elif t == 256:
                if log2_ceil != 521:
                    return False

        # verify P is prime
        if not number.isPrime(self.p):
            return False

        # verify attributes are in the range [0, p-1]
        if self.a >= self.p:
            return False
        if self.b >= self.p:
            return False
        if self.G.x >= self.p:
            return False
        if self.G.y >= self.p:
            return False

        # check curve parameters
        if (4 * pow(self.a, 3, self.p) +
            27 * pow(
                self.b, 2, self.p)) % self.p == 0:
            return False
        if not self.G.verify():
            return False

        # verify N is prime
        if not number.isPrime(self.n):
            return False

        return True


class TwoPowerCurveDomain(CurveDomain):
    """
    An elliptic curve domain specified by a power of two 2**m and an
    irreducible binary polynomial f(x) of degree m specifying the polynomial
    basis representation of F2**m.
    """
    def __init__(self, m, fx, a, b, G, n, h):
        self.m = m
        self.fx = fx
        CurveDomain.__init__(self, a, b, G, n, h)

    def __repr__(self):
        return u"<TwoPowerDomain: 2**%i>" % self.m

    def verify(self):
        raise NotImplementedError
