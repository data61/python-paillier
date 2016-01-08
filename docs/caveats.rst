================
Security Caveats
================

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

.. _alternative-base:

Alternative Base for EncodedNumber
----------------------------------

*If* you need to interact with a library using another base, create a simple subclass
of :class:`paillier.EncodedNumber` and ensure you include the `BASE` and `LOG2_BASE`
attributes::

    class AltEncodedNumber(paillier.EncodedNumber):
        BASE = 2
        LOG2_BASE = math.log(BASE, 2)


.. warning::

    Be careful when designing protocols with `BASE = 2`. If you don't require specific a
    specific value for the unencrypted exponents after an operation then you're potentially
    leaking a lot of information about what happened.


No audit
--------

This code has neither been written nor vetted by any sort of crypto expert. The crypto
parts are mercifully short, however.

