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


class Base64UtilTest(unittest.TestCase):

    def testEncodeDecodePositiveNonZeroInt(self):
        for a in range(1, 1000000, 100):

            self.assertEqual(a, util.base64_to_int(util.int_to_base64(a)))

    def testFailToEncodeZero(self):
        with self.assertRaises(AssertionError):
            util.int_to_base64(0)


if __name__ == "__main__":
    unittest.main()