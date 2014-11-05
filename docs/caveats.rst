================
Security Caveats
================

-------------------
Information leakage
-------------------

The :attr:`~phe.paillier.EncryptedNumber.exponent` of an
:class:`~phe.paillier.EncryptedNumber` is not encrypted. By default, for floating
point numbers this leads to some information leakage about the magnitude of the
encrypted value. This leakage can be patched up by deciding on a fixed value for
all exponents as part of the protocol; then for each
:class:`~phe.paillier.EncryptedNumber`,
:meth:`~phe.paillier.EncryptedNumber.decrease_exponent_to` can be called before
sharing. In practice this exponent should be a lower bound for any exponent that
would naturally arise.


--------
No audit
--------

This code has neither been written nor vetted by any sort of crypto expert. The crypto
parts are mercifully short, however.

