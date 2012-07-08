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

ECDSA_ is a widespread public-key signature algorithm. Its security is
based on the XXX description of ECDSA XXX

In 2012, a sufficient size is deemed to be XXX size of ECDSA keys XXX
For more information, see the most recent ECRYPT_ report.

ECDSA is secure for new designs.

The algorithm can only be used for authentication (digital signature).
ECDSA cannot be used for confidentiality (encryption).

The values XXX ECDSA params XXX are called *domain parameters*; they are not
sensitive but must be shared by both parties (the signer and the verifier).
Different signers can share the same domain parameters with no security
concerns.

XXX ECDSA result size XXX

This module provides facilities for generating new ECDSA keys and for
constructing them from known components. ECDSA keys allows you to perform basic
signing and verification.

    >>> from Crypto.Random import random
    >>> from Crypto.PublicKey import DSA
    >>> from Crypto.Hash import SHA256
    >>>
    >>> message = "Hello"
    >>> key = ECDSA.generate(256)
    >>> h = SHA256.new(message).digest()
    >>> k = random.StrongRandom().randint(1,key.q-1)
    >>> sig = key.sign(h,k)
    >>> ...
    >>> if key.verify(h,sig):
    >>>     print "OK"
    >>> else:
    >>>     print "Incorrect signature"

.. _DSA: http://en.wikipedia.org/wiki/Digital_Signature_Algorithm
.. _DLP: http://www.cosic.esat.kuleuven.be/publications/talk-78.pdf
.. _ECRYPT: http://www.ecrypt.eu.org/documents/D.SPA.17.pdf
"""

__revision__ = "$Id$"

__all__ = ['generate', 'construct', 'error', 'ECDSAImplementation',
           '_ECDSAobj']

import sys
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *

from Crypto.PublicKey import _ECDSA, _slowmath, pubkey
from Crypto import Random

try:
    from Crypto.PublicKey import _fastmath
except ImportError:
    _fastmath = None


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
        :Type m: byte string or long

        :Parameter signature: The ECDSA signature to verify.
        :Type signature: A tuple with 2 longs as return by `sign`

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
         use_fast_math : bool
                                Specify which mathematic library to use:

                                - *None* (default). Use fastest math available.
                                - *True* . Use fast math.
                                - *False* . Use slow math.
         default_randfunc : callable
                                Specify how to collect random data:

                                - *None* (default). Use Random.new().read().
                                - not *None* . Use the specified function directly.
        :Raise RuntimeError:
            When **use_fast_math** =True but fast math is not available.
        """
        use_fast_math = kwargs.get('use_fast_math', None)
        if use_fast_math is None:   # Automatic
            if _fastmath is not None:
                self._math = _fastmath
            else:
                self._math = _slowmath

        elif use_fast_math:     # Explicitly select fast math
            if _fastmath is not None:
                self._math = _fastmath
            else:
                raise RuntimeError("fast math module not available")

        else:   # Explicitly select slow math
            self._math = _slowmath

        self.error = self._math.error

        # 'default_randfunc' parameter:
        #   None (default) - use Random.new().read
        #   not None       - use the specified function
        self._default_randfunc = kwargs.get('default_randfunc', None)
        self._current_randfunc = None

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
        key = self._math.ecdsa_construct(obj.Q, obj.d)
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
        key = self._math.ecdsa_construct(*tup)
        return _ECDSAobj(self, key)

_impl = ECDSAImplementation()
generate = _impl.generate
construct = _impl.construct
error = _impl.error

# These curves are specified in SEC2.
secp192k1 = _ECDSA.PrimeCurveDomain(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37,  # p
    0, 3,  # a, b
    (0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,  # Gx
     0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D),  # Gy
    0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D,  # n
    1)  # h


# vim:set ts=4 sw=4 sts=4 expandtab:

