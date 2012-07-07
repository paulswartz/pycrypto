
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


def generate_py(curve, randfunc, progress_func=None):
    """generate(curve:CurveDomain, randfunc:callable, progress_func:callable)

    Generate a ECDSA key on curve 'curve', using 'randfunc' to get random
    data and 'progress_func', if present, to display the progress of the key
    generation.
    """
    if not curve.verify():
        raise ValueError('Invalid curve')
    obj = ECDSAobj()
    obj.curve = curve
    # Generate private key d and public key Q = dg
    if progress_func:
        progress_func('d\n')
    obj.d = number.getRandomRange(1, curve.n - 1, randfunc)
    if progress_func:
        progress_func('Q\n')
    obj.Q = curve.G * obj.d
    return obj


class ECDSAobj:
    pass


class Point:
    """
    Class representing a point on an elliptic curve.
    """
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def __repr__(self):
        if self.x is None and self.y is None:
            return u"Point(infinity)"
        return u"Point(%i, %i, %r)" % (self.x, self.y, self.curve)

    def __eq__(self, other):
        if not isinstance(other, Point):
            return NotImplemented
        # XXX short-circuit; possible timing issue?
        return self.x == other.x and self.y == other.y and \
            self.curve == other.curve

    def verify(self):
        """
        Verify that this point is on the curve.
        """
        if self.x is None and self.y is None:
            return True
        if self.x >= self.curve.p or self.y >= self.curve.p:
            return False
        left = pow(self.y, 2, self.curve.p)
        right = pow(self.x, 3, self.curve.p) + (
            self.curve.a * self.x + self.curve.b) % self.curve.p
        return left == right

    def __add__(self, other):
        if not isinstance(other, Point):
            raise NotImplementedError
        if other.x is None and other.y is None:
            return self
        if self.x is None and self.y is None:
            return other
        if self.curve != other.curve:
            raise NotImplementedError
        if other.x == self.x:
            if other.y == self.y and self.y != 0:
                # double
                s = (3 * pow(self.x, 2, self.curve.p) +
                     self.curve.a) / (2 * self.y)
                x = (pow(s, 2, self.curve.p) - (2 * self.x)) % self.curve.p
                y = (s * (self.x - x) - self.y) % self.curve.p
                return Point(x, y, self.curve)
            else:
                return INFINITY
        else:
            # add
            s = (self.y - other.y) / (self.x - other.x)
            x = (pow(s, 2, self.curve.p) - self.x - other.x) % self.curve.p
            y = (s * (self.x - x) - self.y) % self.curve.p
            return Point(x, y, self.curve)

    def __mul__(self, other):
        if not isinstance(other, int):
            raise NotImplementedError
        if not other:
            return INFINITY
        # implement scalar multiplication based on addition
        bit_length = int(math.ceil(math.log(other, 2)))
        n = self
        r = INFINITY
        for i in range(1, bit_length + 1):
            if (other & 2 ** i) == 2 ** i:
                r = r + n
            n = n + n
        return r


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
            print 'p'
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
        if pow(self.G.y, 2, self.p) != (pow(self.G.x, 3, self.p) +
                                        self.a * self.G.x + self.b) % self.p:
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

# These curves are specified in SEC2.
secp192k1 = PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37,  # p
    0, 3,  # a, b
    (0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,  # Gx
     0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D),  # Gy
    0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D,  # n
    1)  # h
