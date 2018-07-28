Version 1.4.1
=============

Remove support for Python 3.3.

Version 1.4.0 (2018-04-19)
=====

Complete pure Python fallback implementation.

Features
----

- `invert` now available without `gmpy2`, implemented using the extended
  Euclidean algorithm (`extended_euclidean_algorithm`)
- `getprimeover` now available without `gmpy2`, along with a probabilitic
  primality test `isprime` based on the Miller-Rabin test (`miller_rabin`)

Version 1.3.0 (2017-02-08)
=====

Changes to enhance performance. Using Chinese Remainder Theorem for faster
decryption. Exploit property of the generator to speed up encryption.

Note both the api and the serialisation has changed.

- A private key now has a `p` and `q` attribute instead of `lambda` and `mu`. To
continue being able to create a private key using the totient use the
`PaillierPrivateKey.from_totient` static constructor.
- The serialization and constructor of a public key now only requires `n`.

Version 1.2.3 (2015-06-02)
=====

Documentation and bugfix release.

Features
----

- Better support for alternative encoding schemes (including a new example). Public key now has
  an `encrypt_encoded` method. `decrypt_encoded` optionally takes an `Encoding` class.
- Command line tool documentation.
- Much expanded notes on key serialisation.

Bug Fixes
----

- Several tests for encrypt/decrypt only encoded/decoded.


Version 1.2.0 (2015-01-12)
=====

Features
----

-  Command line tool


Version 1.1 (2015-01-08)
=====

Bug Fixes
----

PaillierPrivateKeyring used mutable default argument.

Features
----


-  Support for Python 3.5
-  Default keysize increased to 2048
-  Allow use of alternative base for EncodedNumber
