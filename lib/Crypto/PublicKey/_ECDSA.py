
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

from Crypto.PublicKey.pubkey import *
from Crypto.Util import number
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA
from Crypto.Util.py3compat import *


class error (Exception):
    pass


def generateQ(randfunc):
    S=randfunc(20)
    hash1=SHA.new(S).digest()
    hash2=SHA.new(long_to_bytes(bytes_to_long(S)+1)).digest()
    q = bignum(0)
    for i in range(0,20):
        c=bord(hash1[i])^bord(hash2[i])
        if i==0:
            c=c | 128
        if i==19:
            c= c | 1
        q=q*256+c
    while (not isPrime(q)):
        q=q+2
    if pow(2,159L) < q < pow(2,160L):
        return S, q
    raise RuntimeError('Bad q value generated')

def generate_py(domain, randfunc, progress_func=None):
    """generate(domain:CurveDomain, randfunc:callable, progress_func:callable)

    Generate a ECDSA key from domain 'domain', using 'randfunc' to get random
    data and 'progress_func', if present, to display the progress of the key
    generation.
    """
    if not domain.valid():
        raise ValueError('Invalid domain')
    obj=ECDSAobj()
    # Generate string S and prime q
    if progress_func:
        progress_func('p,q\n')
    while (1):
        S, obj.q = generateQ(randfunc)
        n=divmod(bits-1, 160)[0]
        C, N, V = 0, 2, {}
        b=(obj.q >> 5) & 15
        powb=pow(bignum(2), b)
        powL1=pow(bignum(2), bits-1)
        while C<4096:
            for k in range(0, n+1):
                V[k]=bytes_to_long(SHA.new(S+bstr(N)+bstr(k)).digest())
            W=V[n] % powb
            for k in range(n-1, -1, -1):
                W=(W<<160L)+V[k]
            X=W+powL1
            p=X-(X%(2*obj.q)-1)
            if powL1<=p and isPrime(p):
                break
            C, N = C+1, N+n+1
        if C<4096:
            break
        if progress_func:
            progress_func('4096 multiples failed\n')

    obj.p = p
    power=divmod(p-1, obj.q)[0]
    if progress_func:
        progress_func('h,g\n')
    while (1):
        h=bytes_to_long(randfunc(bits)) % (p-1)
        g=pow(h, power, p)
        if 1<h<p-1 and g>1:
            break
    obj.g=g
    if progress_func:
        progress_func('x,y\n')
    while (1):
        x=bytes_to_long(randfunc(20))
        if 0 < x < obj.q:
            break
    obj.x, obj.y = x, pow(g, x, p)
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
    """
    def __init__(self, a, b, G, n, h):
        self.a = a
        self.b = b
        self.G = G
        self.n = n
        self.h = h

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

    def verify(self):
        raise NotImplementedError


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
