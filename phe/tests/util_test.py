#!/usr/bin/env python3.4

# This file is part of pyphe.
#
# Pyphe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Pyphe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyphe.  If not, see <http://www.gnu.org/licenses/>.

import unittest
import random
import math
try:
    from math import gcd  # new in Python 3.5
except ImportError:
    from fractions import gcd  # deprecated since Python 3.5

from phe import util


class PaillierUtilTest(unittest.TestCase):

    def testPowMod(self):
        self.assertEqual(util.powmod(5, 3, 3), 2)
        self.assertEqual(util.powmod(2, 10, 1000), 24)

    def testInvert(self):
        p = 101
        for i in range(1, p):
            iinv = util.invert(i, p)
            self.assertEqual((iinv * i) % p, 1)

    def testInvertNonPrime(self):
        a = 3
        p = 4
        self.assertEqual(a * util.invert(a, p) % p, 1)

    def testPrimeOverN(self):
        self.assertIn(util.getprimeover(3), {5, 7, 11, 13})
        # Test we get at least a N-bit prime
        for n in range(2, 50):
            p = util.getprimeover(n)
            self.assertGreaterEqual(p, 1 << (n-1))

    def testIsqrt(self):
        for _ in range(100):
            n = random.randint(2, 10000000)
            nsq = n*n
            self.assertEqual(int(math.floor(math.sqrt(n))), util.isqrt(n))
            self.assertEqual(util.isqrt(nsq), util.improved_i_sqrt(nsq))


# same tests as above, but with gmpy2 and Crypto libraries disabled
class PaillierUtilFallbacksTest(PaillierUtilTest):

    def setUp(self):
        # save presence of libraries
        self.HAVE_GMP = util.HAVE_GMP
        self.HAVE_CRYPTO = util.HAVE_CRYPTO
        # disable libraties
        util.HAVE_GMP = False
        util.HAVE_CRYPTO = False

    def tearDown(self):
        # restore presence of libraries
        util.HAVE_GMP = self.HAVE_GMP
        util.HAVE_CRYPTO = self.HAVE_CRYPTO

    def testExtendedEuclieanAlgorithm(self):
        # from <https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm>
        self.assertEqual(util.extended_euclidean_algorithm(240, 46), (2, -9, 47))

        # tests with arbirary values
        for a, b in [(77, 99), (45, 127)]:  # non-coprime pair, coprime pair
            r, s, t = util.extended_euclidean_algorithm(a, b)
            self.assertEqual(r, s*a + t*b)
            self.assertEqual(r, gcd(a, b))

    def testMillerRabin(self):
        a = 2  # witness, enough by itself for checking n < 2047
        self.assertFalse(util.miller_rabin(4, a))
        self.assertTrue(util.miller_rabin(127, a))
        composite = util.first_primes[-1] * util.first_primes[-2]
        self.assertFalse(util.miller_rabin(composite, a))

    def testIsPrime(self):
        self.assertTrue(util.is_prime(17881))  # first not in first_primes
        self.assertFalse(util.is_prime(-17881))

        self.assertFalse(util.is_prime(-4))
        self.assertFalse(util.is_prime(-2))
        self.assertFalse(util.is_prime(-1))
        self.assertFalse(util.is_prime(0))
        self.assertFalse(util.is_prime(1))
        self.assertTrue(util.is_prime(2))
        self.assertTrue(util.is_prime(3))

        # same tests as for miller_rabin()
        self.assertFalse(util.is_prime(4))
        self.assertTrue(util.is_prime(127))
        composite = util.first_primes[-1] * util.first_primes[-2]
        self.assertFalse(util.is_prime(composite))


class Base64UtilTest(unittest.TestCase):

    def testEncodeDecodePositiveNonZeroInt(self):
        for a in range(1, 1000000, 100):

            self.assertEqual(a, util.base64_to_int(util.int_to_base64(a)))

    def testFailToEncodeZero(self):
        with self.assertRaises(AssertionError):
            util.int_to_base64(0)


if __name__ == "__main__":
    unittest.main()
