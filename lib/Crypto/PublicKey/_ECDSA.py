
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


def generate_py(T, randfunc, progress_func=None):
    """generate(curve:CurveDomain, randfunc:callable, progress_func:callable)

    Generate a ECDSA key on curve 'T', using 'randfunc' to get random
    data and 'progress_func', if present, to display the progress of the key
    generation.
    """
    if not T.verify():
        raise ValueError('Invalid curve')
    obj = ECDSAobj()
    obj.T = T
    # Generate private key d and public key Q = dg
    if progress_func:
        progress_func('d\n')
    obj.d = number.getRandomRange(1, T.n - 1, randfunc)
    if progress_func:
        progress_func('Q\n')
    obj.Q = T.G * obj.d
    assert T.G.verify()
    assert obj.Q.verify()
    #print hex(obj.d)
    #print hex(obj.Q.x)
    #print hex(obj.Q.y)
    return obj


class ECDSAobj:
    pass


class Point:
    """
    Class representing a point on an elliptic curve.
    """
    # XXX use methods on T instead of on this when we support 2**m curves
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
        # add/double&add algorithm
        bit_length = int(math.ceil(math.log(other, 2)))
        r = INFINITY
        for i in range(bit_length, -1, -1):
            r = r + r
            if (other & 2 ** i) == 2 ** i:
                r = r + self
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