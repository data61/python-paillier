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
