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

    As always, if you don't require a specific value for the unencrypted exponents after
    an operation, you might be leaking information about what happened - but with smaller
    bases this problem is exacerbated.


No audit
--------

This code has neither been written nor vetted by any sort of crypto expert. The crypto
parts are mercifully short, however.


Number Encoding Scheme
----------------------

Represents a float or int encoded for Paillier encryption.

For end users, this class is mainly useful for specifying precision
when adding/multiplying an :class:`EncryptedNumber` by a scalar.

Any custom encoding scheme that results in an unsigned integer is
supported.

Notes:
  Paillier encryption is only defined for non-negative integers less
  than :attr:`PaillierPublicKey.n`. Since we frequently want to use
  signed integers and/or floating point numbers (luxury!), values
  should be encoded as a valid integer before encryption.

  The operations of addition and multiplication [1]_ must be
  preserved under this encoding. Namely:

  1. Decode(Encode(a) + Encode(b)) = a + b
  2. Decode(Encode(a) * Encode(b)) = a * b

  for any real numbers a and b.

  Representing signed integers is relatively easy: we exploit the
  modular arithmetic properties of the Paillier scheme. We choose to
  represent only integers between
  +/-:attr:`~PaillierPublicKey.max_int`, where `max_int` is
  approximately :attr:`~PaillierPublicKey.n`/3 (larger integers may
  be treated as floats). The range of values between `max_int` and
  `n` - `max_int` is reserved for detecting overflows. This encoding
  scheme supports properties #1 and #2 above.

  Representing floating point numbers as integers is a harder task.
  Here we use a variant of fixed-precision arithmetic. In fixed
  precision, you encode by multiplying every float by a large number
  (e.g. 1e6) and rounding the resulting product. You decode by
  dividing by that number. However, this encoding scheme does not
  satisfy property #2 above: upon every multiplication, you must
  divide by the large number. In a Paillier scheme, this is not
  possible to do without decrypting. For some tasks, this is
  acceptable or can be worked around, but for other tasks this can't
  be worked around.

  In our scheme, the "large number" is allowed to vary, and we keep
  track of it. It is:

    :attr:`BASE` ** :attr:`exponent`

  One number has many possible encodings; this property can be used
  to mitigate the leak of information due to the fact that
  :attr:`exponent` is never encrypted.

  For more details, see :meth:`~PaillierPublicKey.encode`.

.. rubric:: Footnotes

..  [1] Technically, since Paillier encryption only supports
  multiplication by a scalar, it may be possible to define a
  secondary encoding scheme `Encode'` such that property #2 is
  relaxed to:

    Decode(Encode(a) * Encode'(b)) = a * b

  We don't do this.
