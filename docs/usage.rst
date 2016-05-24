.. _usage:

Usage
=====

There are two roles that use this library. In the first, you control the private keys. In the
second, you don't. This guide shows you how to play either role.

In either case, you of course begin by importing the library::

    from phe import paillier


Role #1
-------

This party holds the private keys and typically will generate the keys and do the decryption.

Key generation
^^^^^^^^^^^^^^

First, you're going to have to generate a public and private key pair::

    >>> public_key, private_key = paillier.generate_paillier_keypair()

If you're going to have lots of private keys lying around, then perhaps you should invest in
a keyring on which to store your :class:`~phe.paillier.PaillierPrivateKey` instances::

    >>> keyring = paillier.PaillierPrivateKeyring()
    >>> keyring.add(private_key)
    >>> public_key1, private_key1 = paillier.generate_paillier_keypair(keyring)
    >>> public_key2, private_key2 = paillier.generate_paillier_keypair(keyring)

In any event, you can then start encrypting numbers::

    >>> secret_number_list = [3.141592653, 300, -4.6e-12]
    >>> encrypted_number_list = [public_key.encrypt(x) for x in secret_number_list]

Presumably, you would now share the ciphertext with whoever is playing Role 2
(see `Serialisation`_ and :ref:`compatibility`).


Decryption
^^^^^^^^^^

To decrypt an :class:`~phe.paillier.EncryptedNumber`, use the relevant
:class:`~phe.paillier.PaillierPrivateKey`::

    >>> [private_key.decrypt(x) for x in encrypted_number_list]
    [3.141592653, 300, -4.6e-12]

If you have multiple key pairs stored in a :class:`~phe.paillier.PaillierPrivateKeyring`,
then you don't need to manually find the relevant :class:`~phe.paillier.PaillierPrivateKey`::

    >>> [keyring.decrypt(x) for x in encrypted_number_list]
    [3.141592653, 300, -4.6e-12]


Role #2
-------

This party does not have access to the private keys, and typically performs operations on
supplied encrypted data with their own, unencrypted data.

Once this party has received some :class:`~phe.paillier.EncryptedNumber` instances (e.g. see
`Serialisation`_), it can perform basic mathematical operations supported by the Paillier
encryption:

1. Addition of an :class:`~phe.paillier.EncryptedNumber` to a scalar
2. Addition of two :class:`~phe.paillier.EncryptedNumber` instances
3. Multiplication of an :class:`~phe.paillier.EncryptedNumber` by a scalar

::

    >>> a, b, c = encrypted_number_list
    >>> a
    <phe.paillier.EncryptedNumber at 0x7f60a28c90b8>

    >>> a_plus_5 = a + 5
    >>> a_plus_b = a + b
    >>> a_times_3_5 = a * 3.5

as well as some simple extensions::

    >>> a_minus_1_3 = a - 1             # = a + (-1)
    >>> a_div_minus_3_1 = a / -3.1      # = a * (-1 / 3.1)
    >>> a_minus_b = a - b               # = a + (b * -1)

Numpy operations that rely only on these operations are allowed::

    >>> import numpy as np
    >>> enc_mean = np.mean(encrypted_number_list)
    >>> enc_dot = np.dot(encrypted_number_list, [2, -400.1, 5318008])

Operations that aren't supported by Paillier's *partially* homomorphic scheme raise an error::

    >>> a * b
    NotImplementedError: Good luck with that...

    >>> 1 / a
    TypeError: unsupported operand type(s) for /: 'int' and 'EncryptedNumber'


Once the necessary computations have been done, this party would send the resulting
:class:`~phe.paillier.EncryptedNumber` instances back to the holder of the private keys for
decryption.

In some cases it might be possible to boost performance by reducing the precision of floating point numbers::

    >>> a_times_3_5_lp = a * paillier.EncodedNumber.encode(a.public_key, 3.5, 1e-2)


