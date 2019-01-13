#!/usr/bin/env python
# Portions Copyright 2012 Google Inc. All Rights Reserved.
# This file has been modified by NICTA
import phe.encoding
from phe.paillier import PaillierPrivateKey, PaillierPublicKey

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

"""Unittest for paillier module."""

import logging
import unittest
import sys
import math

from phe import paillier


class PaillierGeneric(unittest.TestCase):

    def testDefaultCreateKeypair(self):
        public_key, private_key = paillier.generate_paillier_keypair()

        self.assertTrue(hasattr(public_key, 'g'))
        self.assertTrue(hasattr(public_key, 'n'))

        self.assertTrue(hasattr(private_key, 'p'))
        self.assertTrue(hasattr(private_key, 'q'))
        self.assertTrue(hasattr(private_key, 'public_key'))

        self.assertTrue(str(public_key).startswith('<PaillierPublicKey '))
        self.assertTrue(str(private_key).startswith('<PaillierPrivateKey '))

    def testCreateKeypairLengths(self):

        for key_length in [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 3072, 4096]:
            public_key, private_key = paillier.generate_paillier_keypair(n_length=key_length)

            self.assertTrue(hasattr(public_key, 'g'))
            self.assertTrue(hasattr(public_key, 'n'))

            self.assertTrue(hasattr(private_key, 'p'))
            self.assertTrue(hasattr(private_key, 'q'))

            # Check that no exceptions are raised representing these keys
            repr(public_key)
            repr(private_key)

    def testKeyUniqueness(self):
        repeats = 100
        public_keys = set()
        private_keys = set()
        for _ in range(repeats):
            public_key, private_key = paillier.generate_paillier_keypair(n_length=256)
            self.assertNotIn(public_key, public_keys, "Managed to generate the same public key")
            self.assertNotIn(private_key, private_keys, "Managed to generate the same private key")
            public_keys.add(public_key)
            private_keys.add(private_key)

    def testStaticPrivateKeyConstructor(self):
        public_key, private_key = paillier.generate_paillier_keypair()
        p = private_key.p
        q = private_key.q
        private_key_from_static = PaillierPrivateKey.from_totient(public_key, (p-1) * (q-1))
        c = public_key.encrypt(4242)
        self.assertEqual(private_key, private_key_from_static, "The private keys should be the same.")
        self.assertEqual(private_key_from_static.decrypt(c), 4242, "Result of the decryption should be 4242")

    def testPrivateKeyEquality(self):
        pk = PaillierPublicKey(2537)
        p1 = PaillierPrivateKey(pk, 43, 59)
        p2 = PaillierPrivateKey(pk, 59, 43)
        self.assertEqual(p1, p2, "These private keys should be equal")

class PaillierTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Could move this into setUpModule() if we get too many classes
        cls.public_key, cls.private_key = paillier.generate_paillier_keypair()
        cls.other_public_key, cls.other_private_key = paillier.generate_paillier_keypair()

    def assertInRange(self, value, a, b):
        """Assert that a <= value <= b or a >= value >= b.

        Useful when python floats suffer rounding errors and Paillier
        floats are at least as good as the python floats
        """
        if not ((a <= value <= b) or (a >= value >= b)):
            self.fail("%s is not between %s and %s" % (value, a, b))


class PaillierTestRawEncryption(PaillierTest):

    def testEncryptDecrypt(self):
        data = 123456789123456789123456789123456789
        ciphertext = self.public_key.raw_encrypt(data)
        decryption = self.private_key.raw_decrypt(ciphertext)
        self.assertEqual(data, decryption)

    def testModuloN(self):
        # Check decryption works for n -1
        plaintext1 = self.public_key.n - 1
        ciphertext1 = self.public_key.raw_encrypt(plaintext1)
        self.assertEqual(plaintext1, self.private_key.raw_decrypt(ciphertext1))
        # Check decryption wraps for n to 0
        plaintext2 = self.public_key.n
        ciphertext2 = self.public_key.raw_encrypt(plaintext2)
        self.assertEqual(0, self.private_key.raw_decrypt(ciphertext2))
        # Check decryption wraps for n + 1 to 1
        plaintext3 = self.public_key.n + 1
        ciphertext3 = self.public_key.raw_encrypt(plaintext3)
        self.assertEqual(1, self.private_key.raw_decrypt(ciphertext3))

    def testRawEncryptDecryptRegression0(self):

        public_key = paillier.PaillierPublicKey(126869)
        private_key = paillier.PaillierPrivateKey(public_key, 293, 433)

        ciphertext = public_key.raw_encrypt(10100, 74384)
        self.assertEqual(935906717, ciphertext)
        decryption = private_key.raw_decrypt(935906717)
        self.assertEqual(10100, decryption)

    def testEncryptRegression(self):
        public_key = paillier.PaillierPublicKey(126869)

        enc_num = public_key.encrypt(10100, r_value=74384)
        self.assertEqual(935906717, enc_num.ciphertext(False))

    def testEncryptIsRandom(self):
        # Check for semantic security
        public_key = paillier.PaillierPublicKey(126869)

        enc_num = public_key.encrypt(1, r_value=1)
        self.assertEqual(126870, enc_num.ciphertext(False))
        # r_value should be random
        enc_num2 = public_key.encrypt(1)
        enc_num3 = public_key.encrypt(1)
        self.assertNotEqual(126870, enc_num2.ciphertext(False))
        self.assertNotEqual(enc_num2.ciphertext(False),
                            enc_num3.ciphertext(False))

    def testEncryptInvalidType(self):
        data = "123"
        self.assertRaises(TypeError, self.public_key.raw_encrypt, data)

    def testDecryptInvalidType(self):
        data = 123456789123456789123456789123456789
        ciphertext = self.public_key.raw_encrypt(data)
        self.assertRaises(TypeError, self.private_key.raw_decrypt, str(ciphertext))


class PaillierTestEncodedNumber(PaillierTest):


    def setUp(self):
        super().setUp()
        self.EncodedNumberCls = phe.encoding.EncodedNumber


    def testEncodeInt0(self):
        # A small positive number
        enc = self.EncodedNumberCls.encode(self.public_key, 15)
        self.assertEqual(0, enc.exponent)
        self.assertEqual(15, enc.encoding)

    def testEncodeInt1(self):
        # A small negative number
        enc = self.EncodedNumberCls.encode(self.public_key, -15)
        self.assertEqual(0, enc.exponent)
        self.assertNotEqual(-15, enc.encoding)
        self.assertEqual(-15 % self.public_key.n, enc.encoding)

    def testDecodeInt0(self):
        enc = self.EncodedNumberCls(self.public_key, 15, 0)
        self.assertEqual(15, enc.decode())

    def testDecodeInt1(self):
        enc = self.EncodedNumberCls(self.public_key, -15 % self.public_key.n, 0)
        self.assertEqual(-15, enc.decode())

    def testEncodeIntDecodeInt2(self):
        # large positive number
        encoded = self.EncodedNumberCls.encode(self.public_key, 2 ** 140)
        self.assertEqual(0, encoded.exponent)
        decoded = encoded.decode()
        self.assertEqual(2 ** 140, decoded)

    def testEncodeIntDecodeInt3(self):
        # large negative number
        encoded = self.EncodedNumberCls.encode(self.public_key, -2 ** 140)
        self.assertEqual(0, encoded.exponent)
        decoded = encoded.decode()
        self.assertEqual(-2 ** 140, decoded)

    def testEncodeIntDecodeInt4(self):
        # largest positive number
        encoded = self.EncodedNumberCls.encode(self.public_key,
                                                self.public_key.max_int)
        self.assertEqual(0, encoded.exponent)
        decoded = encoded.decode()
        self.assertEqual(self.public_key.max_int, decoded)

    def testEncodeIntDecodeInt5(self):
        # largest negative number
        encoded = self.EncodedNumberCls.encode(self.public_key,
                                                -self.public_key.max_int)
        decoded = encoded.decode()
        self.assertEqual(-self.public_key.max_int, decoded)

    def testEncodeIntTooLargePositive(self):
        # check value error is raised on too large a positive input
        self.assertRaises(ValueError, self.EncodedNumberCls.encode,
                          self.public_key, self.public_key.max_int + 1)
        self.assertRaises(ValueError, self.EncodedNumberCls.encode,
                          self.public_key, 2 ** (paillier.DEFAULT_KEYSIZE-1))

    def testEncodeIntTooLargeNegative(self):
        # check value error is raised on too large a positive input
        self.assertRaises(ValueError, self.EncodedNumberCls.encode,
                          self.public_key, -self.public_key.max_int - 1)
        self.assertRaises(ValueError, self.EncodedNumberCls.encode,
                          self.public_key, -2 ** (paillier.DEFAULT_KEYSIZE-1))

    def testDecodeCorruptEncodedNumber(self):
        encoded = self.EncodedNumberCls.encode(self.public_key, 10)
        encoded.encoding += self.public_key.n
        self.assertRaises(ValueError, encoded.decode)

    def testDecodeWithOverflowEncodedNumber(self):
        encoded = self.EncodedNumberCls.encode(self.public_key, 10)
        encoded.encoding += self.public_key.max_int
        self.assertRaises(OverflowError, encoded.decode)

    def testEncodeFloat0(self):
        enc = self.EncodedNumberCls.encode(self.public_key, 15.1)
        negexp = self.EncodedNumberCls.BASE ** enc.exponent
        dec = self.EncodedNumberCls.BASE ** enc.exponent * enc.encoding
        self.assertAlmostEqual(15.1, dec)

    def testEncodeFloatDecodeFloat0(self):
        enc = self.EncodedNumberCls.encode(self.public_key, 15.1)
        self.assertAlmostEqual(15.1, enc.decode())

    def testEncodeFloatDecodeFloat1(self):
        enc = self.EncodedNumberCls.encode(self.public_key, -15.1)
        self.assertAlmostEqual(-15.1, enc.decode())

    def testEncryptFloatDecryptFloat2(self):
        # large positive number
        encoded = self.EncodedNumberCls.encode(self.public_key, 2.1 ** 20)
        self.assertEqual(2.1 ** 20, encoded.decode())

        encrypted = self.public_key.encrypt(encoded)

        decrypted_but_encoded = self.private_key.decrypt_encoded(encrypted, self.EncodedNumberCls)

        self.assertAlmostEqual(2.1 ** 20, decrypted_but_encoded.decode())

    def testEncryptFloatDecryptFloat3(self):
        # large negative number
        encoded = self.EncodedNumberCls.encode(self.public_key, -2.1 ** 63)
        self.assertAlmostEqual(-2.1 ** 63, encoded.decode())
        encrypted = self.public_key.encrypt(encoded)
        decrypted_but_encoded = self.private_key.decrypt_encoded(encrypted, self.EncodedNumberCls)
        self.assertAlmostEqual(-2.1 ** 63, decrypted_but_encoded.decode())

    def testEncodedDecreaseExponentTo0(self):
        # Check that decrease_exponent_to does what it says
        enc1 = self.EncodedNumberCls.encode(self.public_key, 3.14)
        new_exponent = enc1.exponent - 10
        assert new_exponent < enc1.exponent # So the next part is meaningful
        enc2 = enc1.decrease_exponent_to(new_exponent)

        self.assertLess(new_exponent, enc1.exponent)
        self.assertEqual(new_exponent, enc2.exponent)
        self.assertAlmostEqual(3.14, enc2.decode())

    def testEncodedDecreaseExponentTo1(self):
        # Check that decrease_exponent_to does what it says
        enc1 = self.EncodedNumberCls.encode(self.public_key, -3.14)
        new_exponent = enc1.exponent - 10

        assert new_exponent < enc1.exponent # So the next part is meaningful
        enc2 = enc1.decrease_exponent_to(new_exponent)
        self.assertLess(new_exponent, enc1.exponent)
        self.assertEqual(new_exponent, enc2.exponent)
        self.assertAlmostEqual(-3.14, enc2.decode())

    def testEncodedDecreaseInvalidExponent(self):
        # Check that decrease_exponent_to does what it says
        enc1 = self.EncodedNumberCls.encode(self.public_key, 3.14)
        assert enc1.exponent < -8
        self.assertRaises(ValueError, enc1.decrease_exponent_to, -8)


class PaillierTestEncodedNumberDefaultBase(PaillierTestEncodedNumber):
    """Encoded Number tests with a default encoding base.
    """

    def testManualPrecision0(self):
        # Check that the encoded +ve number is precise enough...
        val, prec = 3.171234e-7, 1e-8
        encoding = self.EncodedNumberCls.encode(self.public_key, val, precision=prec)
        decoded = encoding.decode()
        self.assertInRange(decoded, val - prec, val + prec)

        # Well, that didn't actually prove much - what if val happens
        # to be conveniently representable in BASE?
        # `decoded` *is* conveniently representable in BASE, so let's
        # play with that a little
        encoding2 = self.EncodedNumberCls.encode(self.public_key,
                                                  decoded + 0.500001 * prec,
                                                  precision=prec)
        decoded2 = encoding2.decode()
        self.assertNotEqual(decoded, decoded2)
        self.assertInRange(decoded2, val - prec/2, val + prec*1.5001)

        # Check it's not too precise:
        val3 = decoded + prec / self.EncodedNumberCls.BASE
        encoding3 = self.EncodedNumberCls.encode(self.public_key, val3, precision=prec)
        decoded3 = encoding3.decode()
        self.assertEqual(decoded, decoded3)

    def testManualPrecision1(self):
        # Check that the encoded -ve number is precise enough...
        val, prec = -3.171234e-7, 1e-8
        encoding = self.EncodedNumberCls.encode(self.public_key, val, precision=prec)
        decoded = encoding.decode()
        self.assertInRange(decoded, val - prec, val + prec)

        # Well, that didn't actually prove much - what if val happens
        # to be conveniently representable in BASE?
        # `decoded` *is* conveniently representable in BASE, so let's
        # play with that a little
        encoding2 = self.EncodedNumberCls.encode(self.public_key,
                                                  decoded + 0.500001 * prec,
                                                  precision=prec)
        decoded2 = encoding2.decode()
        self.assertNotEqual(decoded, decoded2)
        self.assertInRange(decoded2, val, val + prec)

        # Check it's not too precise:
        val3 = decoded + prec / self.EncodedNumberCls.BASE
        encoding3 = self.EncodedNumberCls.encode(self.public_key, val3, precision=prec)
        decoded3 = encoding3.decode()
        self.assertEqual(decoded, decoded3)

    def testAutomaticPrecisionAgreesWithEpsilon(self):
        # Check that automatic precision is equivalent to precision=eps
        eps = sys.float_info.epsilon

        # There's a math.floor in _encode, we want to test that
        # bin_lsb_exponent is correct and not off by some fraction that
        # sometimes gets rounded down. The " * 2" in the next line is excessive.
        floor_happy = math.ceil(self.EncodedNumberCls.LOG2_BASE) * 2

        for i in range(-floor_happy, floor_happy + 1):
            enc1 = self.EncodedNumberCls.encode(self.public_key, 2.**i)
            enc2 = self.EncodedNumberCls.encode(self.public_key, 2.**i,
                                                          precision=eps * 2**i)
            self.assertEqual(enc1.exponent, enc2.exponent, i)

            # Check the max val for a given eps
            rel_eps = eps * 2 ** (i - 1)
            val = 2. ** i - rel_eps
            assert val != 2. ** i
            enc3 = self.EncodedNumberCls.encode(self.public_key, val)
            enc4 = self.EncodedNumberCls.encode(self.public_key, val,
                                                        precision=rel_eps)
            self.assertEqual(enc3.exponent, enc4.exponent, i)


class PaillierTestEncodedNumberAlternativeBaseLarge(PaillierTestEncodedNumber):
    """Encoded Number tests with a different encoding base.
    """

    def setUp(self):
        super().setUp()

        class AltEncodedNumber(phe.encoding.EncodedNumber):
            BASE = 64
            LOG2_BASE = math.log(BASE, 2)

        self.EncodedNumberCls = AltEncodedNumber


class PaillierTestEncodedNumberAlternativeBaseSmall(PaillierTestEncodedNumber):
    """Encoded Number tests with a different encoding base.
    """

    def setUp(self):
        super().setUp()

        class AltEncodedNumber(phe.encoding.EncodedNumber):
            BASE = 2
            LOG2_BASE = math.log(BASE, 2)

        self.EncodedNumberCls = AltEncodedNumber


class PaillierTestEncodedNumberAlternativeBaseOdd(PaillierTestEncodedNumber):
    """Encoded Number tests with an odd encoding base.
    """

    def setUp(self):
        super().setUp()

        class AltEncodedNumber(phe.encoding.EncodedNumber):
            BASE = 13
            LOG2_BASE = math.log(BASE, 2)

        self.EncodedNumberCls = AltEncodedNumber


class PaillierTestEncryptedNumber(PaillierTest):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.p_n = [123456789, 314159265359,
                    271828182846, -987654321,
                    -161803398874, -1414213562373095]
        cls.c_n = [cls.public_key.encrypt(n) for n in cls.p_n]

    def testCreateEncryptedNumber(self):
        paillier.EncryptedNumber(self.public_key, 5)

    def testEncryptIntDecryptInt0(self):
        # A small positive number
        ciphertext = self.public_key.encrypt(15)
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(15, decryption)

    def testEncryptIntDecryptInt1(self):
        # A small negative number
        ciphertext = self.public_key.encrypt(-15)
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(-15, decryption)

    def testEncryptIntDecryptInt4(self):
        # largest positive number
        ciphertext = self.public_key.encrypt(self.public_key.max_int)
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(self.public_key.max_int, decryption)

    def testEncryptIntDecryptInt5(self):
        # largest negative number
        ciphertext = self.public_key.encrypt(-self.public_key.max_int)
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(-self.public_key.max_int, decryption)

    def testCantEncryptDecryptIntWithDifferentKey(self):
        data = 1564
        ciphertext = self.public_key.encrypt(data)
        self.assertRaises(ValueError, self.other_private_key.decrypt, ciphertext)

    def testCantEncryptDecryptIntWithDifferentSizeKey(self):
        public_key, private_key = paillier.generate_paillier_keypair(n_length=128)
        data = 1564
        ciphertext = self.public_key.encrypt(data)
        self.assertRaises(ValueError, private_key.decrypt, ciphertext)

    def testCantAddWithDifferentKey(self):
        ciphertext1 = self.public_key.encrypt(-15)
        ciphertext2 = self.other_public_key.encrypt(1)
        self.assertRaises(ValueError, ciphertext1.__add__, ciphertext2)

    def testCantAddEncodedWithDifferentKey(self):
        ciphertext1 = self.public_key.encrypt(-15)
        ciphertext2 = phe.encoding.EncodedNumber(self.other_public_key, 1, ciphertext1.exponent)
        self.assertRaises(ValueError, ciphertext1.__add__, ciphertext2)

    def testAddWithEncryptDecryptInt0(self):
        # Add 1 to a small negative number
        ciphertext1 = self.public_key.encrypt(-15)
        ciphertext2 = self.public_key.encrypt(1)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(-14, decryption)

    def testAddWithEncryptDecryptInt1(self):
        # Add 1 to a small positive number
        ciphertext1 = self.public_key.encrypt(15)
        ciphertext2 = self.public_key.encrypt(1)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(16, decryption)

    def testAddWithEncryptDecryptInt2(self):
        # Add -1 to a small negative number
        ciphertext1 = self.public_key.encrypt(-15)
        ciphertext2 = self.public_key.encrypt(-1)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(-16, decryption)

    def testSubWithEncryptDecryptInt0(self):
        # Subtract two encrypted integers
        ciphertext1 = self.public_key.encrypt(15)
        ciphertext2 = self.public_key.encrypt(1)
        ciphertext3 = ciphertext1 - ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(14, decryption)

    def testSubScalarWithEncryptDecryptInt0(self):
        # Subtract two encrypted integers
        ciphertext1 = self.public_key.encrypt(15)
        ciphertext2 = ciphertext1 - 2
        decryption = self.private_key.decrypt(ciphertext2)
        self.assertEqual(13, decryption)

    def testSubScalarWithEncryptDecryptInt0Right(self):
        # Subtract two encrypted integers
        ciphertext1 = self.public_key.encrypt(15)
        ciphertext2 = 20 - ciphertext1
        decryption = self.private_key.decrypt(ciphertext2)
        self.assertEqual(5, decryption)

    def testMultipleAddWithEncryptDecryptInt0(self):
        # Add many positive numbers
        ciphertext = self.c_n[0] + self.c_n[1] + self.c_n[2]
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(sum(self.p_n[0:3]), decryption)

    def testMultipleAddWithEncryptDecryptInt1(self):
        # Add many negative numbers
        ciphertext = self.c_n[3] + self.c_n[4] + self.c_n[5]
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(sum(self.p_n[3:6]), decryption)

    def testMultipleAddWithEncryptDecryptInt2(self):
        # Add many positive and negative numbers with aggregate being positive
        ciphertext = sum(self.c_n[:5])
        decryption = self.private_key.decrypt(ciphertext)
        sum_3pos_2neg = sum(self.p_n[:5])
        self.assertEqual(sum_3pos_2neg, decryption)

    def testMultipleAddWithEncryptDecryptInt3(self):
        # Add many positive and negative numbers with aggregate being negative
        ciphertext = sum(self.c_n)
        decryption = self.private_key.decrypt(ciphertext)
        sum_3pos_3neg = sum(self.p_n)
        self.assertEqual(sum_3pos_3neg, decryption)

    def testMultipleAddWithEncryptDecryptIntLimits(self):
        sum_3pos_2neg = sum(self.p_n[:5])
        sum_3pos_3neg = sum(self.p_n)
        ciphertext_3pos_2neg = sum(self.c_n[:5])
        ciphertext_3pos_3neg = sum(self.c_n)

        # Add many positive and negative numbers to reach max_int.
        ciphertext = self.public_key.encrypt(self.public_key.max_int - sum_3pos_2neg)
        ciphertext = ciphertext_3pos_2neg + ciphertext
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(self.public_key.max_int, decryption)

        # Add many positive and negative numbers to reach -max_int.
        ciphertext = self.public_key.encrypt(-self.public_key.max_int - sum_3pos_3neg)
        ciphertext = ciphertext_3pos_3neg + ciphertext
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(-self.public_key.max_int, decryption)


    def testAffineWithEncryptDecryptInt(self):
        logging.debug('Running testAffineWithEncryptDecryptInt method.')
        plaintext1 = 123456789123456789123456789123456789
        for plaintext in (plaintext1, -plaintext1):
            ciphertext1 = self.public_key.encrypt(plaintext)
            # tests a = 2
            a = 2
            b = 111111110111111110111111110111111110
            ciphertext3 = ciphertext1 * a + b
            decryption3 = self.private_key.decrypt(ciphertext3)
            self.assertEqual(a * plaintext + b, decryption3)
            # tests a = 0
            ciphertext4 = ciphertext1 * 0 + b
            decryption4 = self.private_key.decrypt(ciphertext4)
            self.assertEqual(b, decryption4)
            # tests a = 1
            ciphertext5 = ciphertext1 * 1 + b
            decryption5 = self.private_key.decrypt(ciphertext5)
            self.assertEqual(plaintext + b, decryption5)
            # tests b = 0
            ciphertext6 = ciphertext1 * 2 + 0
            decryption6 = self.private_key.decrypt(ciphertext6)
            self.assertEqual(2 * plaintext, decryption6)
            # tests a=0, b = 0
            ciphertext7 = ciphertext1 * 0 + 0
            decryption7 = self.private_key.decrypt(ciphertext7)
            self.assertEqual(0, decryption7)

    def testEncryptIntPositiveOverflowAdd(self):
        # positive overflow as a result of adding
        ciphertext1 = self.public_key.encrypt(self.public_key.max_int)
        ciphertext2 = self.public_key.encrypt(1)
        ciphertext3 = ciphertext1 + ciphertext2
        self.assertRaises(OverflowError, self.private_key.decrypt, ciphertext3)

    def testEncryptIntNegativeOverflowAdd(self):
        # negative overflow as a result of adding
        ciphertext1 = self.public_key.encrypt(-self.public_key.max_int)
        ciphertext2 = self.public_key.encrypt(-1)
        ciphertext3 = ciphertext1 + ciphertext2
        self.assertRaises(OverflowError, self.private_key.decrypt,ciphertext3)

    def testUndetectableAddOverflow(self):
        # Prove the ring does wrap
        ciphertext1 = self.public_key.encrypt(0)
        ciphertext2 = self.public_key.encrypt(self.public_key.max_int)
        ciphertext3 = self.public_key.encrypt(self.public_key.max_int)
        ciphertext4 = self.public_key.encrypt(self.public_key.max_int)
        cipher_sum = ciphertext1 + ciphertext2 + ciphertext3 + ciphertext4

        plain_sum = self.private_key.decrypt(cipher_sum)
        # plain_sum = 3 * max_int = 3 * ((n//3) - 1)
        # due to residues of the // function,
        # -5 < plain_sum < -3 (modulo n)
        self.assertLessEqual(-5, plain_sum)
        self.assertGreaterEqual(-3, plain_sum)

    def testCantAddWithDifferentKeys(self):
        ciphertext1 = self.public_key.encrypt(0, r_value=1)
        # Let's not and say we did
        ciphertext2 = self.public_key.encrypt(20, r_value=1)
        public_key_2 = paillier.PaillierPublicKey(126869)
        ciphertext2.public_key = public_key_2  # Suuuper dodgy

        self.assertRaises(ValueError, ciphertext1.__add__, ciphertext2)

    def testAddWithEncryptedIntAndEncodedNumber(self):
        # Add 1 to a small positive number
        ciphertext1 = self.public_key.encrypt(15)
        encoded2 = phe.encoding.EncodedNumber.encode(self.public_key, 1)
        ciphertext3 = ciphertext1 + encoded2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(16, decryption)

    def testAddWithEncryptedIntAndEncodedNumberDiffExp0(self):
        # Add 1 to a small positive number
        ciphertext1 = self.public_key.encrypt(15)
        encoded2 = phe.encoding.EncodedNumber.encode(self.public_key, 1, max_exponent=-50)
        assert encoded2.exponent > -200
        assert ciphertext1.exponent > -200

        encoded2 = encoded2.decrease_exponent_to(-200)
        ciphertext3 = ciphertext1 + encoded2
        self.assertEqual(16, self.private_key.decrypt(ciphertext3))

    def testAddWithEncryptedIntAndEncodedNumberDiffExp1(self):
        # Try with the EncryptedNumber having the smaller exponent
        ciphertext1 = self.public_key.encrypt(15)
        ciphertext2 = ciphertext1.decrease_exponent_to(-10)
        encoded1 = phe.encoding.EncodedNumber.encode(self.public_key, 1)
        encoded2 = encoded1.decrease_exponent_to(-10)
        ciphertext = ciphertext1.decrease_exponent_to(-200)
        assert encoded2.exponent == -10
        assert ciphertext.exponent == -200
        ciphertext2 = ciphertext + encoded2

        self.assertEqual(16, self.private_key.decrypt(ciphertext2))

    def testMulWithEncryptedIntAndEncodedNumber(self):
        # Multiply two negative integers
        ciphertext1 = self.public_key.encrypt(-3)
        encoded2 = phe.encoding.EncodedNumber.encode(self.public_key, -25)
        ciphertext3 = ciphertext1 * encoded2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(75, decryption)

    def testEncryptFloatDecryptFloat4(self):
        # A small positive float
        ciphertext = self.public_key.encrypt(0.005743)
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(0.005743, decryption)

    def testEncryptFloatDecryptFloat5(self):
        # A small negative float
        ciphertext = self.public_key.encrypt(-0.05743)
        decryption = self.private_key.decrypt(ciphertext)
        self.assertEqual(-0.05743, decryption)

    def testAutomaticPrecision0(self):
        eps = sys.float_info.epsilon
        one_plus_eps = 1. + eps
        assert one_plus_eps > 1. # If this is false, we have trouble!

        ciphertext1 = self.public_key.encrypt(one_plus_eps)
        decryption1 = self.private_key.decrypt(ciphertext1)
        self.assertEqual(one_plus_eps, decryption1)

        ciphertext2 = ciphertext1 + eps
        self.assertGreater(ciphertext1.exponent, ciphertext2.exponent)
        decryption2 = self.private_key.decrypt(ciphertext2)
        self.assertEqual(one_plus_eps + eps, decryption2)

        # 1. + eps/5 == 1. for a python float...
        ciphertext3 = ciphertext1 + eps / 5
        decryption3 = self.private_key.decrypt(ciphertext3)
        self.assertEqual(one_plus_eps, decryption3)

        # ...but not for our 'arbitrary-precision' Paillier floats
        ciphertext4 = ciphertext3 + eps * 4. / 5
        decryption4 = self.private_key.decrypt(ciphertext4)
        self.assertNotEqual(one_plus_eps, decryption4)
        self.assertEqual(one_plus_eps + eps, decryption4)

    def testDecreaseExponentTo(self):
        # Decrease an exponent to -30 without affecting the plaintext number
        ciphertext1 = self.public_key.encrypt(1.01, precision=1e-8)
        assert -30 < ciphertext1.exponent # So the next part is meaningful
        ciphertext2 = ciphertext1.decrease_exponent_to(-30)

        self.assertLess(-30, ciphertext1.exponent)
        self.assertEqual(-30, ciphertext2.exponent)
        self.assertAlmostEqual(1.01, self.private_key.decrypt(ciphertext2),
                               places=8)

    def testDecreaseInvalidExponent(self):
        ciphertext = self.public_key.encrypt(1.01, precision=1e-8)
        assert ciphertext.exponent < 20
        self.assertRaises(ValueError, ciphertext.decrease_exponent_to, 20)


    def testAddWithEncryptDecryptFloat0(self):
        # Add 1 to a small negative number
        ciphertext1 = self.public_key.encrypt(-15.)
        ciphertext2 = self.public_key.encrypt(1.)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(-14., decryption)

    def testAddWithEncryptDecryptFloat0Right(self):
        # Add 1 to a small negative number
        ciphertext1 = self.public_key.encrypt(-15.)
        ciphertext2 = self.public_key.encrypt(1.)
        ciphertext3 = ciphertext2 + ciphertext1
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(-14., decryption)

    def testAddWithEncryptDecryptFloat1(self):
        # Add 1 to a small positive number
        ciphertext1 = self.public_key.encrypt(15.)
        ciphertext2 = self.public_key.encrypt(1.)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(16., decryption)

    def testAddWithEncryptDecryptFloat2(self):
        # Add -1 to a small negative number
        ciphertext1 = self.public_key.encrypt(-15.)
        ciphertext2 = self.public_key.encrypt(-1.)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertEqual(-16., decryption)

    def testAddWithEncryptDecryptFloat3(self):
        # Add two floats with the same precision
        ciphertext1 = self.public_key.encrypt(1.3842)
        ciphertext2 = self.public_key.encrypt(-0.4)
        ciphertext3 = ciphertext1 + ciphertext2
        decryption = self.private_key.decrypt(ciphertext3)
        self.assertInRange(decryption, 0.9842, 1.3842 - 0.4)

    def testAddWithEncryptDecryptFloat4(self):
        # Add two floats with different precisions
        ciphertext1 = self.public_key.encrypt(0.1, precision=1e-3)
        ciphertext2 = self.public_key.encrypt(0.2, precision=1e-20)
        self.assertNotEqual(ciphertext1.exponent, ciphertext2.exponent)
        old_exponent = ciphertext1.exponent

        ciphertext3 = ciphertext1 + ciphertext2
        self.assertEqual(ciphertext2.exponent, ciphertext3.exponent)
        # Add should not have changed ciphertext1
        self.assertEqual(old_exponent, ciphertext1.exponent)

        decryption = self.private_key.decrypt(ciphertext3)
        self.assertAlmostEqual(0.3, decryption, places=3)

    def testSubWithEncryptDecryptFloat0(self):
        # Subtract two floats with different precisions
        ciphertext1 = self.public_key.encrypt(0.1, precision=1e-3)
        ciphertext2 = self.public_key.encrypt(0.2, precision=1e-20)
        self.assertNotEqual(ciphertext1.exponent, ciphertext2.exponent)

        ciphertext3 = ciphertext1 - ciphertext2
        self.assertEqual(ciphertext2.exponent, ciphertext3.exponent)

        decryption = self.private_key.decrypt(ciphertext3)
        self.assertAlmostEqual(-0.1, decryption, places=3) # Assumes base 10

    def testAddScalarWithEncryptDecryptFloat0(self):
        # Add a positive integer
        ciphertext1 = self.public_key.encrypt(-1.98)
        self.assertIsInstance(ciphertext1.ciphertext(False), int)
        ciphertext2 = ciphertext1 + 4

        self.assertEqual(2.02, self.private_key.decrypt(ciphertext2))

    def testAddScalarWithEncryptDecryptFloat0Right(self):
        # Add a positive integer
        ciphertext1 = self.public_key.encrypt(-1.98)
        self.assertIsInstance(ciphertext1.ciphertext(False), int)
        ciphertext2 = 4 + ciphertext1

        self.assertEqual(2.02, self.private_key.decrypt(ciphertext2))

    def testAddScalarWithEncryptDecryptFloat1(self):
        # Add a positive float
        ciphertext1 = self.public_key.encrypt(1.98)
        ciphertext2 = ciphertext1 + 4.3
        decryption = self.private_key.decrypt(ciphertext2)

        self.assertInRange(decryption, 1.98 + 4.3, 6.28)

    def testAddScalarWithEncryptDecryptFloat2(self):
        # Add a negative float
        ciphertext1 = self.public_key.encrypt(240.9)
        ciphertext2 = ciphertext1 +(- 40.8)
        decryption = self.private_key.decrypt(ciphertext2)

        self.assertInRange(decryption, 240.9 - 40.8, 200.1)

    def testAddScalarWithEncryptDecryptFloat3(self):
        # Add a negative integer
        ciphertext1 = self.public_key.encrypt(3.9)
        ciphertext2 = ciphertext1 +(- 40)

        self.assertEqual(-36.1, self.private_key.decrypt(ciphertext2))

    def testSubScalarWithEncryptDecryptFloat0(self):
        # Subtract a negative integer
        ciphertext1 = self.public_key.encrypt(-1.98)
        self.assertIsInstance(ciphertext1.ciphertext(False), int)
        ciphertext2 = ciphertext1 - (-4)

        self.assertEqual(2.02, self.private_key.decrypt(ciphertext2))

    def testSubScalarWithEncryptDecryptFloat0Right(self):
        # Subtract a negative integer
        ciphertext1 = self.public_key.encrypt(1.98)
        self.assertIsInstance(ciphertext1.ciphertext(False), int)
        ciphertext2 = 4 - ciphertext1

        self.assertEqual(2.02, self.private_key.decrypt(ciphertext2))

    def testSubScalarWithEncryptDecryptFloat1(self):
        # Subtract a negative float
        ciphertext1 = self.public_key.encrypt(1.98)
        ciphertext2 = ciphertext1 - (-4.3)

        decryption = self.private_key.decrypt(ciphertext2)
        self.assertInRange(decryption, 6.28, 1.98 -(-4.3))

    def testSubScalarWithEncryptDecryptFloat1Right(self):
        # Subtract a negative float
        ciphertext1 = self.public_key.encrypt(-1.98)
        ciphertext2 = (4.3) - ciphertext1

        decryption = self.private_key.decrypt(ciphertext2)
        self.assertInRange(decryption, 6.28, 1.98 -(-4.3))

    def testSubScalarWithEncryptDecryptFloat2(self):
        # Subtract a positive float
        ciphertext1 = self.public_key.encrypt(240.9)
        ciphertext2 = ciphertext1 - 40.8
        decryption = self.private_key.decrypt(ciphertext2)

        self.assertInRange(decryption, 200.1, 240.9 - 40.8)

    def testSubScalarWithEncryptDecryptFloat3(self):
        # Subtract a positive integer
        ciphertext1 = self.public_key.encrypt(3.9)
        ciphertext2 = ciphertext1 - 40

        self.assertEqual(-36.1, self.private_key.decrypt(ciphertext2))

    def testMulWithEncryptDecryptFloat0(self):
        # Multiply a floatish by one
        ciphertext1 = self.public_key.encrypt(-1.3)
        ciphertext2 = ciphertext1 * 1
        self.assertEqual(ciphertext1.exponent, ciphertext2.exponent)
        self.assertEqual(ciphertext1.ciphertext(False), ciphertext2.ciphertext(False))
        self.assertEqual(-1.3, self.private_key.decrypt(ciphertext2))

    def testMulWithEncryptDecryptFloat1(self):
        # Multiply a floatish by two
        ciphertext1 = self.public_key.encrypt(2.3)
        ciphertext2 = ciphertext1 * 2
        self.assertEqual(ciphertext1.exponent, ciphertext2.exponent)
        self.assertEqual(4.6, self.private_key.decrypt(ciphertext2))

    def testMulWithEncryptDecryptFloat2(self):
        # Multiply a floatish by a positive float
        ciphertext1 = self.public_key.encrypt(-0.1)
        ciphertext2 = ciphertext1 * 31.4
        self.assertEqual(-3.14, self.private_key.decrypt(ciphertext2))
        self.assertNotEqual(ciphertext2.exponent, ciphertext1.exponent)
        exp_of_314 = phe.encoding.EncodedNumber.encode(self.public_key, -31.4).exponent
        self.assertEqual(ciphertext2.exponent, ciphertext1.exponent +exp_of_314)

    def testMulWithEncryptedFloatAndEncodedNumber0(self):
        # Multiply a floatish with custom precision by a positive float
        ciphertext1 = self.public_key.encrypt(1.2345678e-12, precision=1e-14)
        encoded1 = phe.encoding.EncodedNumber.encode(self.public_key, 1.38734864,
                                                     precision=1e-2)
        ciphertext2 = ciphertext1 * encoded1
        self.assertAlmostEqual(1.71e-12, self.private_key.decrypt(ciphertext2), places=3)

    def testMulWithEncryptDecryptFloat4(self):
        # Multiply a floatish by minus one
        ciphertext1 = self.public_key.encrypt(-1.3)
        ciphertext2 = ciphertext1 * -1
        self.assertEqual(ciphertext1.exponent, ciphertext2.exponent)
        self.assertEqual(1.3, self.private_key.decrypt(ciphertext2))

    def testMulWithEncryptDecryptFloat5(self):
        # Multiply a floatish by minus two
        ciphertext1 = self.public_key.encrypt(2.3)
        ciphertext2 = ciphertext1 * -2
        self.assertEqual(ciphertext1.exponent, ciphertext2.exponent)
        self.assertEqual(-4.6, self.private_key.decrypt(ciphertext2))

    def testMulWithEncryptDecryptFloat6(self):
        # Multiply a floatish by a negative float
        ciphertext1 = self.public_key.encrypt(-0.1)
        ciphertext2 = ciphertext1 * -31.4
        self.assertEqual(3.14, self.private_key.decrypt(ciphertext2))
        self.assertNotEqual(ciphertext2.exponent, ciphertext1.exponent)
        exp_of_314 = phe.encoding.EncodedNumber.encode(self.public_key, -31.4).exponent
        self.assertEqual(ciphertext2.exponent, ciphertext1.exponent +exp_of_314)

    def testMulWithEncryptedFloatAndEncodedNumber1(self):
        # Multiply a floatish with custom precision by a negative float
        ciphertext1 = self.public_key.encrypt(1.2345678e-12, precision=1e-14)
        encoded1 = phe.encoding.EncodedNumber.encode(self.public_key, -1.38734864,
                                                     precision=1e-2)
        ciphertext2 = ciphertext1 * encoded1
        self.assertAlmostEqual(-1.71e-12, self.private_key.decrypt(ciphertext2), places=3)

    def testMulRight(self):
        # Check that it doesn't matter which side the real float is on
        ciphertext1 = self.public_key.encrypt(0.1)
        ciphertext2 = ciphertext1 * 31.4
        ciphertext3 = 31.4 * ciphertext1

        self.assertEqual(self.private_key.decrypt(ciphertext3), self.private_key.decrypt(ciphertext2))
        self.assertEqual(3.14, self.private_key.decrypt(ciphertext2))

    def testMulZero(self):
        # Check that multiplying by zero does something sensible
        ciphertext1 = self.public_key.encrypt(3.)
        ciphertext2 = ciphertext1 * 0
        self.assertEqual(0, self.private_key.decrypt(ciphertext2))

    def testMulZeroRight(self):
        # Check that multiplying by zero does something sensible
        ciphertext1 = self.public_key.encrypt(3.)
        ciphertext2 = 0 * ciphertext1
        self.assertEqual(0, self.private_key.decrypt(ciphertext2))

    def testDiv(self):
        # Check division works as well as multiplication does
        ciphertext1 = self.public_key.encrypt(6.28)
        ciphertext2 = ciphertext1 / 2
        self.assertEqual(3.14, self.private_key.decrypt(ciphertext2))

        ciphertext3 = ciphertext1 / 3.14
        self.assertEqual(2., self.private_key.decrypt(ciphertext3))

    def testAddWithEncryptedFloatAndEncodedNumber(self):
        # Add two floats with different precisions
        ciphertext1 = self.public_key.encrypt(0.1, precision=1e-3)
        encoded1 = phe.encoding.EncodedNumber.encode(self.public_key, 0.2,
                                                     precision=1e-20)
        self.assertNotEqual(ciphertext1.exponent, encoded1.exponent)
        old_exponent = ciphertext1.exponent

        ciphertext3 = ciphertext1 + encoded1
        self.assertEqual(encoded1.exponent, ciphertext3.exponent)
        # Add should not have changed ciphertext1
        self.assertEqual(old_exponent, ciphertext1.exponent)

        decryption = self.private_key.decrypt(ciphertext3)
        self.assertAlmostEqual(0.3, decryption, places=3)

    def testMulWithEncryptedFloatAndEncodedNumber(self):
        # Multiply a floatish by an encoded negative float
        ciphertext1 = self.public_key.encrypt(-0.1)
        encoded1 = phe.encoding.EncodedNumber.encode(self.public_key, -31.4)
        ciphertext2 = ciphertext1 * encoded1
        self.assertEqual(3.14, self.private_key.decrypt(ciphertext2))
        self.assertNotEqual(ciphertext2.exponent, ciphertext1.exponent)
        exp_of_314 = phe.encoding.EncodedNumber.encode(self.public_key, -31.4).exponent
        self.assertEqual(ciphertext2.exponent, ciphertext1.exponent +exp_of_314)

    def testObfuscate(self):
        ciphertext = self.public_key.encrypt(3.14)
        self.assertTrue(ciphertext._EncryptedNumber__is_obfuscated)
        c1 = ciphertext.ciphertext(False)
        ciphertext.obfuscate()
        self.assertTrue(ciphertext._EncryptedNumber__is_obfuscated)
        c2 = ciphertext.ciphertext(False)
        self.assertNotEqual(c1, c2)
        c3 = ciphertext.ciphertext(True)
        self.assertEqual(c2, c3)

    def testNotObfuscated(self):
        ciphertext = self.public_key.encrypt(3.14, r_value = 103)
        self.assertFalse(ciphertext._EncryptedNumber__is_obfuscated)
        c1 = ciphertext.ciphertext(be_secure=False)
        self.assertFalse(ciphertext._EncryptedNumber__is_obfuscated)
        c2 = ciphertext.ciphertext(be_secure=True)
        self.assertTrue(ciphertext._EncryptedNumber__is_obfuscated)
        c3 = ciphertext.ciphertext(be_secure=False)
        self.assertTrue(ciphertext._EncryptedNumber__is_obfuscated)
        c4 = ciphertext.ciphertext(be_secure=True)
        self.assertTrue(ciphertext._EncryptedNumber__is_obfuscated)

        self.assertNotEqual(c1, c2)
        self.assertEqual(c2, c3)
        self.assertEqual(c3, c4)
        dec = self.private_key.decrypt(ciphertext)
        self.assertEqual(3.14, dec)

    def testAddObfuscated(self):
        ciphertext1 = self.public_key.encrypt(94.5)
        ciphertext2 = self.public_key.encrypt(107.3)
        self.assertTrue(ciphertext1._EncryptedNumber__is_obfuscated)
        self.assertTrue(ciphertext2._EncryptedNumber__is_obfuscated)
        ciphertext3 = ciphertext1 + ciphertext2
        self.assertFalse(ciphertext3._EncryptedNumber__is_obfuscated)
        ciphertext3.ciphertext()
        self.assertTrue(ciphertext3._EncryptedNumber__is_obfuscated)

    def testEncryptInvalidType(self):
        data = "123"
        self.assertRaises(TypeError, self.public_key.encrypt, data)

    def testDecryptInvalidType(self):
        data = 123456789123456789123456789123456789
        ciphertext = self.public_key.encrypt(data)
        self.assertRaises(TypeError, self.private_key.decrypt, str(ciphertext))


class TestKeyring(unittest.TestCase):
    """Test adding and retrieving keys from a keyring."""
    def testKeyring(self):
        keyring1 = paillier.PaillierPrivateKeyring()
        public_key1, private_key1 = paillier.generate_paillier_keypair(keyring1)
        public_key2, private_key2 = paillier.generate_paillier_keypair(keyring1)
        self.assertEqual(private_key1, keyring1[public_key1])
        self.assertEqual(private_key2, keyring1[public_key2])

        ciphertext1 = public_key1.encrypt(5318008)
        ciphertext2 = public_key2.encrypt(1337)
        self.assertEqual(5318008, keyring1.decrypt(ciphertext1))
        self.assertEqual(1337,    keyring1.decrypt(ciphertext2))

        keyring2 = paillier.PaillierPrivateKeyring([private_key1, private_key2])
        self.assertEqual(keyring1, keyring2)
        self.assertRaises(TypeError, keyring1.add, public_key1)

        keyring1.add(private_key1)
        self.assertEqual(2, len(keyring1))

        del keyring1[public_key1]
        self.assertEqual(1, len(keyring1))

        self.assertRaises(KeyError, keyring1.decrypt, ciphertext1)


class TestIssue62(unittest.TestCase):
    def testIssue62(self):
        pub, priv = paillier.generate_paillier_keypair()
        a = pub.encrypt(445)
        # Force big exponent.
        b = pub.encrypt(0.16413409062205825) + pub.encrypt(2 ** -965)
        # This will raise OverflowError without bugfix #73.
        priv.decrypt(a + b)


def main():
    unittest.main()


if __name__ == '__main__':
    main()
