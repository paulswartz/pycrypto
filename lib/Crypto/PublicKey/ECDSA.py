# -*- coding: utf-8 -*-
#
#  PublicKey/ECDSA.py : Elliptic Curve DSA signature primitive
#
# Written in 2012 by Paul Swartz <paulswartz@gmail.com>
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

"""ECDSA public-key signature algorithm.

ECDSA_ is a widespread public-key signature algorithm. Its security is based on
the ellipitic curve discrete logarithm problem (ECDLP_).  Given a curve, a
generator point *G*, and another point *Q*, if it hard to find an integer *x*
such that *G^x = Q*.

The strength of the key is based on the size of the curve; the private key *d*
is in the range *[1, n-1]* where *n* is the order of the curve.  The signer
holds *d* and publishes *Q = G^d* as the public key.

In 2012, a sufficient size is 192 bits, but curves have been standardized up to
521 bits.  Many curves have been published, by NIST_, SECG_, and ECC_.

ECDSA is secure for new designs.

The algorithm can only be used for authentication (digital signature) as well
as for confidentiality (encryption).

The curve *T* i not sensitive but must be shared by both parties (the signer
and the verifier).  Different signers can share the same curve with
no security concerns.

The ECDSA signature is twice as large as the order of the curve (64 bytes for a
256-bit prime curve).

This module provides facilities for generating new ECDSA keys and for
constructing them from known components. ECDSA keys allows you to perform basic
signing and verification.

    >>> from Crypto.Random import random
    >>> from Crypto.PublicKey import DSA
    >>> from Crypto.Hash import SHA256
    >>>
    >>> message = "Hello"
    >>> key = ECDSA.generate(ECDSA.secp192r1)
    >>> h = SHA256.new(message).digest()
    >>> k = random.StrongRandom().randint(1,key.Q.T.n-1)
    >>> sig = key.sign(h,k)
    >>> ...
    >>> if key.verify(h,sig):
    >>>     print "OK"
    >>> else:
    >>>     print "Incorrect signature"

.. _DSA: http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
.. _NIST: http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
.. _SECG: http://www.secg.org/download/aid-386/sec2_final.pdf
.. _ECC: http://www.ecc-brainpool.org/download/Domain-parameters.pdf
"""

__revision__ = "$Id$"

__all__ = ['generate', 'construct', 'error', 'ECDSAImplementation',
           '_ECDSAobj']

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from Crypto.PublicKey import _ECDSA,  pubkey
from Crypto import Random

# try:
#     from Crypto.PublicKey import _fastmath
# except ImportError:
#     _fastmath = None


class _ECDSAobj(pubkey.pubkey):
    """Class defining an actual ECDSA key.

    :undocumented: __getstate__, __setstate__, __repr__, __getattr__
    """
    #: Dictionary of ECDSA parameters.
    #:
    #: A public key will only have the following entries:
    #:
    #:  - **Q**, the public key
    #:  - **T**, the curve the key was generated with
    #:
    #: A private key will also have:
    #:
    #:  - **d**, the private key.
    keydata = ['Q', 'T', 'd']

    def __init__(self, implementation, key):
        self.implementation = implementation
        self.key = key

    def __getattr__(self, attrname):
        if attrname in self.keydata:
            # For backward compatibility, allow the user to get (not set) the
            # ECDSA key parameters directly from this object.
            return getattr(self.key, attrname)
        else:
            raise AttributeError("%s object has no %r attribute" % (
                self.__class__.__name__, attrname,))

    def sign(self, e, k):
        """Sign a piece of data with ECDSA.

        :Parameter e: The hash of the piece of data to sign with ECDSA. It may
         not be longer in bit size than the curve order **n**.
         :Type e: byte string or long

        :Parameter k: A secret number, chosen randomly in the closed
         range *[1,n-1]*.
        :Type k: long (recommended) or byte string (not recommended)

        :attention: selection of *k* is crucial for security. Generating a
         random number larger than *n* and taking the modulus by *n* is **not**
         secure, since smaller values will occur more frequently.  Generating a
         random number systematically smaller than *n-1* (e.g. *floor((n-1)/8)*
         random bytes) is also **not** secure. In general, it shall not be
         possible for an attacker to know the value of any bit of k.

        :attention: The number *k* shall not be reused for any other
         operation and shall be discarded immediately.

        :attention: e must be a digest cryptographic hash, otherwise
         an attacker may mount an existential forgery attack.

        :Return: A tuple with 2 longs.
        """
        return pubkey.pubkey.sign(self, e, k)

    def verify(self, e, signature):
        """Verify the validity of a ECDSA signature.

        :Parameter e: The hash of the expected message.
        :Type e: byte string or long

        :Parameter signature: The ECDSA signature to verify.
        :Type signature: A tuple as return by `sign`

        :Return: True if the signature is correct, False otherwise.
        """
        return pubkey.pubkey.verify(self, e, signature)

    def _encrypt(self, c, K):
        raise TypeError("ECDSA cannot encrypt")

    def _decrypt(self, c):
        raise TypeError("ECDSA cannot decrypt")

    def _blind(self, m, r):
        raise TypeError("ECDSA cannot blind")

    def _unblind(self, m, r):
        raise TypeError("ECDSA cannot unblind")

    def _sign(self, m, k):
        return self.key._sign(m, k)

    def _verify(self, m, sig):
        (r, s) = sig
        return self.key._verify(m, r, s)

    def has_private(self):
        return self.key.has_private()

    def size(self):
        return self.key.size()

    def can_blind(self):
        return False

    def can_encrypt(self):
        return False

    def can_sign(self):
        return True

    def publickey(self):
        return self.implementation.construct((self.key.Q,))

    def __getstate__(self):
        d = {}
        for k in self.keydata:
            try:
                d[k] = getattr(self.key, k)
            except AttributeError:
                pass
        return d

    def __setstate__(self, d):
        if not hasattr(self, 'implementation'):
            self.implementation = ECDSAImplementation()
        t = []
        for k in self.keydata:
            if not d.has_key(k):
                break
            t.append(d[k])
        self.key = self.implementation._math.dsa_construct(*tuple(t))

    def __repr__(self):
        attrs = []
        for k in self.keydata:
            if k == 'p':
                attrs.append("p(%d)" % (self.size()+1,))
            elif hasattr(self.key, k):
                attrs.append(k)
        if self.has_private():
            attrs.append("private")
        # PY3K: This is meant to be text, do not change to bytes (data)
        return "<%s @0x%x %s>" % (self.__class__.__name__, id(self), ",".join(attrs))


class ECDSAImplementation(object):
    """
    A ECDSA key factory.

    This class is only internally used to implement the methods of the
    `Crypto.PublicKey.ECDSA` module.
    """
 
    def __init__(self, **kwargs):
        """Create a new ECDSA key factory.

        :Keywords:
         default_randfunc : callable
                                Specify how to collect random data:

                                - *None* (default). Use Random.new().read().
                                - not *None* . Use the specified function directly.
        :Raise RuntimeError:
            When **use_fast_math** =True but fast math is not available.
        """
        # 'default_randfunc' parameter:
        #   None (default) - use Random.new().read
        #   not None       - use the specified function
        self._default_randfunc = kwargs.get('default_randfunc', None)
        self._current_randfunc = None
        self._error = _ECDSA.error

    def _get_randfunc(self, randfunc):
        if randfunc is not None:
            return randfunc
        elif self._current_randfunc is None:
            self._current_randfunc = Random.new().read
        return self._current_randfunc

    def generate(self, T, randfunc=None, progress_func=None):
        """Randomly generate a fresh, new ECDSA key.

        :Parameters:
         T : Curve to use

         randfunc : callable
                            Random number generation function; it should accept
                            a single integer N and return a string of random data
                            N bytes long.
                            If not specified, a new one will be instantiated
                            from ``Crypto.Random``.
         progress_func : callable
                            Optional function that will be called with a short string
                            containing the key parameter currently being generated;
                            it's useful for interactive applications where a user is
                            waiting for a key to be generated.

        :attention: You should always use a cryptographically secure random number generator,
            such as the one defined in the ``Crypto.Random`` module; **don't** just use the
            current time and the ``random`` module.

        :Return: A ECDSA key object (`_ECDSAobj`).

        :Raise ValueError:
            When **T** is not a valid curve.
        """
        if T.verify():
            return self._generate(T, randfunc, progress_func)

        raise ValueError("Given curve %r is not valid" % T)

    def _generate(self, T, randfunc=None, progress_func=None):
        rf = self._get_randfunc(randfunc)
        obj = _ECDSA.generate_py(T, rf, progress_func)
        key = _ECDSA.construct(obj.Q, obj.d)
        return _ECDSAobj(self, key)

    def construct(self, tup):
        """Construct a ECDSA key from a tuple of valid ECDSA components.

        The curve T must be valid.

        :Parameters:
         tup : tuple
                    A tuple of long integers, with 1 or 2 items
                    in the following order:

                    1. Public key (*Q*).
                    2. Private key (*d*). Optional.

        :Return: A ECDSA key object (`_ECDSAobj`).
        """
        key = _ECDSA.construct(*tup)
        return _ECDSAobj(self, key)

_impl = ECDSAImplementation()
generate = _impl.generate
construct = _impl.construct
error = _impl._error


# This curve is only used for testing.
secp160r1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC,
    0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45,
    (0x4A96B5688EF573284664698968C38BB913CBFC82,
     0x23A628553168947D59DCC912042351377AC5FB32),
    0x0100000000000000000001F4C8F927AED3CA752257,
    1)

# These curves are specified in SEC2.
secp192k1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37,  # p
    0, 3,  # a, b
    (0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,  # Gx
     0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D),  # Gy
    0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D,  # n
    1)  # h
secp192r1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
    0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
    (0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
     0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811),
    0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
    1)
secp224k1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D,
    0, 5,
    (0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C,
     0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5),
    0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7,
    1)
secp224r1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
    0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
    (0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
     0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34),
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
    1)
secp256k1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    0, 7,
    (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    1)
secp256r1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    1)
secp384r1 = _ECDSA.PrimeCurveDomain(
    long("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFF"
         "FFFF0000000000000000FFFFFFFF", 16),
    long("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFF"
         "FFFF0000000000000000FFFFFFFC", 16),
    long("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656"
         "398D8A2ED19D2A85C8EDD3EC2AEF", 16),
    (long("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38550"
          "2F25DBF55296C3A545E3872760AB7", 16),
     long("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A6"
          "0B1CE1D7E819D7A431D7C90EA0E5F", 16)),
    long("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A"
         "0DB248B0A77AECEC196ACCC52973", 16),
    1)
secp521r1 = _ECDSA.PrimeCurveDomain(
    long("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
         16),
    long("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
         "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
         16),
    long("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E1"
         "56193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
         16),
    (long("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DB"
          "AA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
          16),
     long("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662"
          "C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
          16)),
    long("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA"
         "51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
         16),
    1)

# vim:set ts=4 sw=4 sts=4 expandtab:
