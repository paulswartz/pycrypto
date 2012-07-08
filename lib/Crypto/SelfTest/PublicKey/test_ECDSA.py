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

    # Test vectors come from GEC2:
    # http://www.secg.org/download/aid-390/gec2.pdf
    d = 971761939728640320549601132085879836204587084162
    Q = (466448783855397898016055842232266600516272889280,
         1110706324081757720403272427311003102474457754220)
    k = 702232148019446860144825009548118511996283736794
    e = 968236873715988614170569073515315707566766479517
    r = 1176954224688105769566774212902092897866168635793
    s = 299742580584132926933316745664091704165278518100

    def setUp(self):
        global ECDSA, Random, bytes_to_long, size
        from Crypto.PublicKey import ECDSA
        from Crypto import Random

        self.T = ECDSA.secp160r1
        self.Q = _ECDSA.Point(self.Q[0], self.Q[1], self.T)
        self.ecdsa = ECDSA

    def test_generate_1arg(self):
        """ECDSA (default implementation) generated key (1 argument)"""
        ecdsaObj = self.ecdsa.generate(self.T)
        self._check_private_key(ecdsaObj)
        pub = ecdsaObj.publickey()
        self._check_public_key(pub)

    def test_generate_2arg(self):
        """ECECDSA (default implementation) generated key (2 arguments)"""
        ecdsaObj = self.ecdsa.generate(self.T, Random.new().read)
        self._check_private_key(ecdsaObj)
        pub = ecdsaObj.publickey()
        self._check_public_key(pub)

    def test_construct_1tuple(self):
        """ECECDSA (default implementation) constructed key (1-tuple)"""
        ecdsaObj = self.ecdsa.construct((self.Q,))
        self._test_verification(ecdsaObj)

    def test_construct_2tuple(self):
        """ECECDSA (default implementation) constructed key (2-tuple)"""
        ecdsaObj = self.ecdsa.construct((self.Q, self.d))
        self._test_signing(ecdsaObj)
        self._test_verification(ecdsaObj)

    def _check_private_key(self, ecdsaObj):
        # Check capabilities
        self.assertEqual(1, ecdsaObj.has_private())
        self.assertEqual(1, ecdsaObj.can_sign())
        self.assertEqual(0, ecdsaObj.can_encrypt())
        self.assertEqual(0, ecdsaObj.can_blind())

        # Check ecdsaObj.[dQT] -> ecdsaObj.key.[dQT] mapping
        self.assertEqual(ecdsaObj.d, ecdsaObj.key.d)
        self.assertEqual(ecdsaObj.Q, ecdsaObj.key.Q)

        # Sanity check key data
        self.assertTrue(0 < ecdsaObj.d < ecdsaObj.Q.T.n)  # 0 < d < T.n
        self.assertTrue(ecdsaObj.Q.verify())
        self.assertTrue(ecdsaObj.Q.T.verify())

    def _check_public_key(self, ecdsaObj):
        # Check capabilities
        self.assertEqual(0, ecdsaObj.has_private())
        self.assertEqual(1, ecdsaObj.can_sign())
        self.assertEqual(0, ecdsaObj.can_encrypt())
        self.assertEqual(0, ecdsaObj.can_blind())

        # Check ecdsaObj.[QT] -> ecdsaObj.key.[QT] mapping
        self.assertEqual(ecdsaObj.Q, ecdsaObj.key.Q)

        # Check that private parameters are all missing
        self.assertFalse(hasattr(ecdsaObj, 'd'))
        self.assertFalse(hasattr(ecdsaObj.key, 'd'))

        # Sanity check key data
        self.assertTrue(ecdsaObj.Q.verify())

        # Public-only key objects should raise an error when .sign() is called
        self.assertRaises(TypeError, ecdsaObj.sign, 0x12345, 0x12345)

        # Check __eq__ and __ne__
        self.assertEqual(ecdsaObj.publickey() == ecdsaObj.publickey(), True) # assert_
        self.assertEqual(ecdsaObj.publickey() != ecdsaObj.publickey(), False) # failIf

    def _test_signing(self, ecdsaObj):
        (r_out, s_out) = ecdsaObj.sign(self.e, self.k)
        self.assertEqual((self.r, self.s), (r_out, s_out))

    def _test_verification(self, ecdsaObj):
        self.assertEqual(1, ecdsaObj.verify(self.e, (self.r, self.s)))
        self.assertEqual(0, ecdsaObj.verify(self.e + 1, (self.r, self.s)))


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

    def test_construct_1tuple(self):
        """ECDSA (_fastmath implementation) constructed key (1-tuple)"""
        ECDSATest.test_construct_1tuple(self)

    def test_construct_2tuple(self):
        """ECDSA (_fastmath implementation) constructed key (2-tuple)"""
        ECDSATest.test_construct_2tuple(self)


class ECDSASlowMathTest(ECDSATest):
    def setUp(self):
        ECDSATest.setUp(self)
        self.ecdsa = ECDSA.ECDSAImplementation(use_fast_math=False)

    def test_generate_1arg(self):
        """ECDSA (_slowmath implementation) generated key (1 argument)"""
        ECDSATest.test_generate_1arg(self)

    def test_generate_2arg(self):
        """ECDSA (_slowmath implementation) generated key (2 arguments)"""
        ECDSATest.test_generate_2arg(self)

    def test_construct_1tuple(self):
        """ECDSA (_slowmath implementation) constructed key (2-tuple)"""
        ECDSATest.test_construct_1tuple(self)

    def test_construct_2tuple(self):
        """ECDSA (_slowmath implementation) constructed key (2-tuple)"""
        ECDSATest.test_construct_2tuple(self)


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
    # try:
    #     from Crypto.PublicKey import _fastmath
    #     tests += list_test_cases(ECDSAFastMathTest)
    # except ImportError:
    #     from distutils.sysconfig import get_config_var
    #     import inspect
    #     _fm_path = os.path.normpath(os.path.dirname(os.path.abspath(
    #         inspect.getfile(inspect.currentframe())))
    #         +"/../../PublicKey/_fastmath"+get_config_var("SO"))
    #     if os.path.exists(_fm_path):
    #         raise ImportError("While the _fastmath module exists, importing "+
    #             "it failed. This may point to the gmp or mpir shared library "+
    #             "not being in the path. _fastmath was found at "+_fm_path)
    tests += list_test_cases(ECDSASlowMathTest)
    return tests

if __name__ == '__main__':
    suite = lambda: unittest.TestSuite(get_tests())
    unittest.main(defaultTest='suite')

# vim:set ts=4 sw=4 sts=4 expandtab:
