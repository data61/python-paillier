#!/usr/bin/env python

"""Unittest for maths involving the paillier module."""

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
import numpy as np

from phe import paillier


class PaillierTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Could move this into setUpModule() if we get too many classes
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair()

        enc_flt = cls.public_key.encrypt

        cls.vec4_1_non_neg = [0.3, 1.7, 6857.6, 1e-6]
        cls.vec4_2         = [-68, 1.8, 34, 1.5e6]

        cls.e_vec4_1 = [enc_flt(x) for x in cls.vec4_1_non_neg]
        cls.e_vec4_2 = [enc_flt(x) for x in cls.vec4_2]


class ArithmeticTest(PaillierTest):

    def testMean(self):
        # Check that we can take an average as good as numpy
        e_mean4_1 = np.mean(self.e_vec4_1)
        self.assertAlmostEqual(np.mean(self.vec4_1_non_neg),
                               self.private_key.decrypt(e_mean4_1))

        emean4_2 = np.mean(self.e_vec4_2)
        self.assertAlmostEqual(np.mean(self.vec4_2),
                               self.private_key.decrypt(emean4_2))

    def testDot(self):
        # Check that our dot product is as good as numpy's
        e_dot_4_2_4_1 = np.dot(self.e_vec4_2, self.vec4_1_non_neg)
        self.assertAlmostEqual(np.dot(self.vec4_2, self.vec4_1_non_neg),
                               self.private_key.decrypt(e_dot_4_2_4_1))


if __name__ == '__main__':
    unittest.main()
