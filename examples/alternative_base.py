#!/usr/bin/env python3.4
import math

import phe.encoding
from phe import paillier


class ExampleEncodedNumber(phe.encoding.EncodedNumber):
    BASE = 64
    LOG2_BASE = math.log(BASE, 2)


print("Generating paillier keypair")
public_key, private_key = paillier.generate_paillier_keypair()


def encode_and_encrypt_example():
    print("Encoding a large positive number. With a BASE {} encoding scheme".format(ExampleEncodedNumber.BASE))
    encoded = ExampleEncodedNumber.encode(public_key, 2.1 ** 20)
    print("Checking that decoding gives the same number...")
    assert 2.1 ** 20 == encoded.decode()

    print("Encrypting the encoded number")
    encrypted = public_key.encrypt(encoded)

    print("Decrypting...")
    decrypted_but_encoded = \
        private_key.decrypt_encoded(encrypted, ExampleEncodedNumber)

    print("Checking the decrypted number is what we started with")
    assert abs(2.1 ** 20 - decrypted_but_encoded.decode()) < 1e-12


def math_example():
    print("Encoding two large positive numbers. BASE={}".format(ExampleEncodedNumber.BASE))

    a = 102545 + (64 ** 8)
    b = 123 + (8 ** 20)

    encoded_a = ExampleEncodedNumber.encode(public_key, a)
    encoded_b = ExampleEncodedNumber.encode(public_key, b)

    print("Checking that decoding gives the same number...")
    assert a == encoded_a.decode()
    assert b == encoded_b.decode()

    print("Encrypting the encoded numbers")
    encrypted_a = public_key.encrypt(encoded_a)
    encrypted_b = public_key.encrypt(encoded_b)

    print("Adding the encrypted numbers")
    encrypted_c = encrypted_a + encrypted_b

    print("Decrypting the one encrypted sum")
    decrypted_but_encoded = \
        private_key.decrypt_encoded(encrypted_c, ExampleEncodedNumber)

    print("Checking the decrypted number is what we started with")

    print("Decrypted: {}".format(decrypted_but_encoded.decode()))
    assert abs((a + b) - decrypted_but_encoded.decode()) < 1e-15


if __name__ == "__main__":
    encode_and_encrypt_example()

    math_example()
