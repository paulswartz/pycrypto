# -*- coding: utf-8 -*-
#
#  SelfTest/PublicKey/test_ECDSA.py: Self-test for the ECDSA primitive
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

"""Self-test suite for Crypto.PublicKey.ECDSA"""

__revision__ = "$Id$"

import sys
import os
if sys.version_info[0] == 2 and sys.version_info[1] == 1:
    from Crypto.Util.py21compat import *
from Crypto.Util.py3compat import *

import unittest
from Crypto.SelfTest.st_common import list_test_cases, a2b_hex, b2a_hex

def _sws(s):
    """Remove whitespace from a text or byte string"""
    if isinstance(s,str):
        return "".join(s.split())
    else:
        return b("").join(s.split())

class ECDSATest(unittest.TestCase):
    # Test vector from "Appendix 5. Example of the ECDSA" of
    # "Digital Signature Standard (DSS)",
    # U.S. Department of Commerce/National Institute of Standards and Technology
    # FIPS 186-2 (+Change Notice), 2000 January 27.
    # http://csrc.nist.gov/publications/fips/fips186-2/fips186-2-change1.pdf

    y = _sws("""19131871 d75b1612 a819f29d 78d1b0d7 346f7aa7 7bb62a85
                9bfd6c56 75da9d21 2d3a36ef 1672ef66 0b8c7c25 5cc0ec74
                858fba33 f44c0669 9630a76b 030ee333""")

    g = _sws("""626d0278 39ea0a13 413163a5 5b4cb500 299d5522 956cefcb
                3bff10f3 99ce2c2e 71cb9de5 fa24babf 58e5b795 21925c9c
                c42e9f6f 464b088c c572af53 e6d78802""")

    p = _sws("""8df2a494 492276aa 3d25759b b06869cb eac0d83a fb8d0cf7
                cbb8324f 0d7882e5 d0762fc5 b7210eaf c2e9adac 32ab7aac
                49693dfb f83724c2 ec0736ee 31c80291""")

    q = _sws("""c773218c 737ec8ee 993b4f2d ed30f48e dace915f""")

    x = _sws("""2070b322 3dba372f de1c0ffc 7b2e3b49 8b260614""")

    k = _sws("""358dad57 1462710f 50e254cf 1a376b2b deaadfbf""")
    k_inverse = _sws("""0d516729 8202e49b 4116ac10 4fc3f415 ae52f917""")
    m = b2a_hex(b("abc"))
    m_hash = _sws("""a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d""")
    r = _sws("""8bac1ab6 6410435c b7181f95 b16ab97c 92b341c0""")
    s = _sws("""41e2345f 1f56df24 58f426d1 55b4ba2d b6dcd8c8""")

    def setUp(self):
        global ECDSA, Random, bytes_to_long, size
        from Crypto.PublicKey import ECDSA
        from Crypto import Random
        from Crypto.Util.number import bytes_to_long, inverse, size

        self.dsa = ECDSA

    def test_generate_1arg(self):
        """ECDSA (default implementation) generated key (1 argument)"""
        dsaObj = self.dsa.generate(1024)
        self._check_private_key(dsaObj)
        pub = dsaObj.publickey()
        self._check_public_key(pub)

    def test_generate_2arg(self):
        """ECDSA (default implementation) generated key (2 arguments)"""
        dsaObj = self.dsa.generate(1024, Random.new().read)
        self._check_private_key(dsaObj)
        pub = dsaObj.publickey()
        self._check_public_key(pub)

    def test_construct_4tuple(self):
        """ECDSA (default implementation) constructed key (4-tuple)"""
        (y, g, p, q) = [bytes_to_long(a2b_hex(param)) for param in (self.y, self.g, self.p, self.q)]
        dsaObj = self.dsa.construct((y, g, p, q))
        self._test_verification(dsaObj)

    def test_construct_5tuple(self):
        """ECDSA (default implementation) constructed key (5-tuple)"""
        (y, g, p, q, x) = [bytes_to_long(a2b_hex(param)) for param in (self.y, self.g, self.p, self.q, self.x)]
        dsaObj = self.dsa.construct((y, g, p, q, x))
        self._test_signing(dsaObj)
        self._test_verification(dsaObj)

    def _check_private_key(self, dsaObj):
        # Check capabilities
        self.assertEqual(1, dsaObj.has_private())
        self.assertEqual(1, dsaObj.can_sign())
        self.assertEqual(0, dsaObj.can_encrypt())
        self.assertEqual(0, dsaObj.can_blind())

        # Check dsaObj.[ygpqx] -> dsaObj.key.[ygpqx] mapping
        self.assertEqual(dsaObj.y, dsaObj.key.y)
        self.assertEqual(dsaObj.g, dsaObj.key.g)
        self.assertEqual(dsaObj.p, dsaObj.key.p)
        self.assertEqual(dsaObj.q, dsaObj.key.q)
        self.assertEqual(dsaObj.x, dsaObj.key.x)

        # Sanity check key data
        self.assertEqual(1, dsaObj.p > dsaObj.q)            # p > q
        self.assertEqual(160, size(dsaObj.q))               # size(q) == 160 bits
        self.assertEqual(0, (dsaObj.p - 1) % dsaObj.q)      # q is a divisor of p-1
        self.assertEqual(dsaObj.y, pow(dsaObj.g, dsaObj.x, dsaObj.p))     # y == g**x mod p
        self.assertEqual(1, 0 < dsaObj.x < dsaObj.q)       # 0 < x < q

    def _check_public_key(self, dsaObj):
        k = a2b_hex(self.k)
        m_hash = a2b_hex(self.m_hash)

        # Check capabilities
        self.assertEqual(0, dsaObj.has_private())
        self.assertEqual(1, dsaObj.can_sign())
        self.assertEqual(0, dsaObj.can_encrypt())
        self.assertEqual(0, dsaObj.can_blind())

        # Check dsaObj.[ygpq] -> dsaObj.key.[ygpq] mapping
        self.assertEqual(dsaObj.y, dsaObj.key.y)
        self.assertEqual(dsaObj.g, dsaObj.key.g)
        self.assertEqual(dsaObj.p, dsaObj.key.p)
        self.assertEqual(dsaObj.q, dsaObj.key.q)

        # Check that private parameters are all missing
        self.assertEqual(0, hasattr(dsaObj, 'x'))
        self.assertEqual(0, hasattr(dsaObj.key, 'x'))

        # Sanity check key data
        self.assertEqual(1, dsaObj.p > dsaObj.q)            # p > q
        self.assertEqual(160, size(dsaObj.q))               # size(q) == 160 bits
        self.assertEqual(0, (dsaObj.p - 1) % dsaObj.q)      # q is a divisor of p-1

        # Public-only key objects should raise an error when .sign() is called
        self.assertRaises(TypeError, dsaObj.sign, m_hash, k)

        # Check __eq__ and __ne__
        self.assertEqual(dsaObj.publickey() == dsaObj.publickey(),True) # assert_
        self.assertEqual(dsaObj.publickey() != dsaObj.publickey(),False) # failIf

    def _test_signing(self, dsaObj):
        k = a2b_hex(self.k)
        m_hash = a2b_hex(self.m_hash)
        r = bytes_to_long(a2b_hex(self.r))
        s = bytes_to_long(a2b_hex(self.s))
        (r_out, s_out) = dsaObj.sign(m_hash, k)
        self.assertEqual((r, s), (r_out, s_out))

    def _test_verification(self, dsaObj):
        m_hash = a2b_hex(self.m_hash)
        r = bytes_to_long(a2b_hex(self.r))
        s = bytes_to_long(a2b_hex(self.s))
        self.assertEqual(1, dsaObj.verify(m_hash, (r, s)))
        self.assertEqual(0, dsaObj.verify(m_hash + b("\0"), (r, s)))

class ECDSAFastMathTest(ECDSATest):
    def setUp(self):
        ECDSATest.setUp(self)
        self.dsa = ECDSA.ECDSAImplementation(use_fast_math=True)

    def test_generate_1arg(self):
        """ECDSA (_fastmath implementation) generated key (1 argument)"""
        ECDSATest.test_generate_1arg(self)

    def test_generate_2arg(self):
        """ECDSA (_fastmath implementation) generated key (2 arguments)"""
        ECDSATest.test_generate_2arg(self)

    def test_construct_4tuple(self):
        """ECDSA (_fastmath implementation) constructed key (4-tuple)"""
        ECDSATest.test_construct_4tuple(self)

    def test_construct_5tuple(self):
        """ECDSA (_fastmath implementation) constructed key (5-tuple)"""
        ECDSATest.test_construct_5tuple(self)

class ECDSASlowMathTest(ECDSATest):
    def setUp(self):
        ECDSATest.setUp(self)
        self.dsa = ECDSA.ECDSAImplementation(use_fast_math=False)

    def test_generate_1arg(self):
        """ECDSA (_slowmath implementation) generated key (1 argument)"""
        ECDSATest.test_generate_1arg(self)

    def test_generate_2arg(self):
        """ECDSA (_slowmath implementation) generated key (2 arguments)"""
        ECDSATest.test_generate_2arg(self)

    def test_construct_4tuple(self):
        """ECDSA (_slowmath implementation) constructed key (4-tuple)"""
        ECDSATest.test_construct_4tuple(self)

    def test_construct_5tuple(self):
        """ECDSA (_slowmath implementation) constructed key (5-tuple)"""
        ECDSATest.test_construct_5tuple(self)


class PointTestCase(unittest.TestCase):
    def setUp(self):
        global _ECDSA
        from Crypto.PublicKey import _ECDSA
        # values from http://www.johannes-bauer.com/compsci/ecc/?menuid=4
        self.curve = _ECDSA.PrimeCurveDomain(263, 2, 3, (111, 247), 263, 1)
        self.point = _ECDSA.Point(19, 59, self.curve)
        self.point2 = _ECDSA.Point(175, 83, self.curve)

    def test_verify(self):
        self.assertTrue(self.point.verify())
        self.assertTrue(self.point2.verify())
        self.assertTrue(_ECDSA.INFINITY.verify())
        # not on the curve
        self.assertFalse(_ECDSA.Point(0, 239, self.curve).verify())
        # outside the range
        self.assertFalse(_ECDSA.Point(0, 286, self.curve).verify())
        self.assertFalse(_ECDSA.Point(264, 100, self.curve).verify())

    def test_add_infinity(self):
        self.assertEqual(self.point + _ECDSA.INFINITY, self.point)
        self.assertEqual(_ECDSA.INFINITY + self.point, self.point)
        self.assertEqual(_ECDSA.INFINITY + _ECDSA.INFINITY, _ECDSA.INFINITY)

    def test_add_point(self):
        point3 = self.point + self.point2
        self.assertEqual(point3,
                         _ECDSA.Point(13, 124, self.curve))
        self.assertTrue(point3.verify())

        point3 = self.point2 + self.point
        self.assertEqual(point3,
                         _ECDSA.Point(13, 124, self.curve))

    def test_add_negative(self):
        self.assertEqual(self.point + _ECDSA.Point(19, 204, self.curve),
                         _ECDSA.INFINITY)

    def test_double_point(self):
        point3 = self.point + self.point
        self.assertEqual(point3,
                         _ECDSA.Point(205, 45, self.curve))
        self.assertTrue(point3.verify())

        point3 = self.point2 + self.point2
        self.assertTrue(point3,
                        _ECDSA.Point(61, 20, self.curve))
        self.assertTrue(point3.verify())

    def test_multiply(self):
        point3_multiply = self.point2 * 3
        point3_add = (self.point2 + self.point2) + self.point2
        point3_add_reverse = self.point2 + (self.point2 + self.point2)
        self.assertEqual(point3_add,
                         _ECDSA.Point(61, 243, self.curve))
        self.assertEqual(point3_multiply, point3_add)
        self.assertEqual(point3_add, point3_add_reverse)
        self.assertTrue(point3_multiply.verify())

        point3_multiply = self.point2 * 4
        point3_add = self.point2 + self.point2
        point3_add = point3_add + point3_add  # 4x is two doubles
        self.assertTrue(point3_add,
                        _ECDSA.Point(175, 180, self.curve))
        self.assertEqual(point3_multiply, point3_add)
        self.assertTrue(point3_multiply.verify())

        self.assertTrue(self.point2 * 0, _ECDSA.INFINITY)


def get_tests(config={}):
    tests = []
    tests += list_test_cases(PointTestCase)
    try:
        from Crypto.PublicKey import _fastmath
        tests += list_test_cases(ECDSAFastMathTest)
    except ImportError:
        from distutils.sysconfig import get_config_var
        import inspect
        _fm_path = os.path.normpath(os.path.dirname(os.path.abspath(
            inspect.getfile(inspect.currentframe())))
            +"/../../PublicKey/_fastmath"+get_config_var("SO"))
        if os.path.exists(_fm_path):
            raise ImportError("While the _fastmath module exists, importing "+
                "it failed. This may point to the gmp or mpir shared library "+
                "not being in the path. _fastmath was found at "+_fm_path)
    #tests += list_test_cases(ECDSASlowMathTest)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
