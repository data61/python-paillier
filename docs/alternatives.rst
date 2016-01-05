.. _alternatives:

Alternative Libraries
=====================

These are brief notes on the libraries that we looked at before embarking on
writing our own.


Python Libraries
----------------

charm-crypto
~~~~~~~~~~~~

> Charm is a framework for rapidly prototyping advanced cryptosystems.  Based on
> the Python language, it was designed from the ground up to minimize development
> time and code complexity while promoting the reuse of components.
>
> Charm uses a hybrid design: performance intensive mathematical operations are
> implemented in native C modules, while cryptosystems themselves are written in
> a readable, high-level language.  Charm additionally provides a number of new
> components to facilitate the rapid development of new schemes and protocols.


http://charm-crypto.com/Main.html


Paillier Code, Pascal Paillier (Public-Key)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

https://github.com/JHUISI/charm/blob/master/charm/schemes/pkenc/pkenc_paillier99.py

Worth looking at their object hierarchy, e.g., http://jhuisi.github.io/charm/toolbox/PKEnc.html
They use a Ciphertext class which has the `__add__` and `__mul__` methods overridden.


Example:
^^^^^^^^


    >>> from charm.toolbox.integergroup import RSAGroup
    >>> group = RSAGroup()
    >>> pai = Pai99(group)
    >>> (public_key, secret_key) = pai.keygen()
    >>> msg_1=12345678987654321
    >>> msg_2=12345761234123409
    >>> msg_3 = msg_1 + msg_2
    >>> msg_1 = pai.encode(public_key['n'], msg_1)
    >>> msg_2 = pai.encode(public_key['n'], msg_2)
    >>> msg_3 = pai.encode(public_key['n'], msg_3)
    >>> cipher_1 = pai.encrypt(public_key, msg_1)
    >>> cipher_2 = pai.encrypt(public_key, msg_2)
    >>> cipher_3 = cipher_1 + cipher_2
    >>> decrypted_msg_3 = pai.decrypt(public_key, secret_key, cipher_3)
    >>> decrypted_msg_3 == msg_3
    True


They have even got it going on Android: http://jhuisi.github.io/charm/mobile.html

mikeivanov/paillier
~~~~~~~~~~~~~~~~~~~

> Pure Python Paillier Homomorphic Cryptosystem

Very simple easy to understand code. Doesn't use a Paillier object. No external dependencies.
Based on the java library: https://code.google.com/p/thep/

https://github.com/mikeivanov/paillier

Example Usage::
    
    >>> from paillier import *
    >>> priv, pub = generate_keypair(128)
    >>> x = encrypt(pub, 2)
    >>> y = encrypt(pub, 3)
    >>> x,y
    (72109737005643982735171545918..., 9615446835366886883470187...)
    >>> z = e_add(pub, x, y)
    >>> z
    71624230283745591274688669...
    >>> decrypt(priv, pub, z)
    5


Tests:
^^^^^^

Could easily be reused.

https://github.com/mikeivanov/paillier/blob/master/tests/test_paillier.py


encrypted-bigquery-client
~~~~~~~~~~~~~~~~~~~~~~~~~

License: **Apache 2.0**

> Paillier encryption to perform homomorphic addition on encrypted data

The ebq client is an experimental client which encrypts data in the specified fields
before loading to Bigquery service. Currently there are various limitations including
support for only a subset of query types on encrypted data.

Paillier specific code:

http://pydoc.net/Python/encrypted_bigquery/1.0/paillier/

Uses openssl via `ctypes`.

Features a **Paillier** object with the following methods:

* `__init__(seed=None, g=None, n=None, Lambda=None, mu=None)`
* `Encrypt(plaintext, r_value=None)`
* `Decrypt(ciphertext)`
* `Add(ciphertext1, ciphertext2)` - returns E(m1 + m2) given E(m1) and E(m2)
* `Affine(self, ciphertext, a=1, b=0)` - Returns E(a*m + b) given E(m), a and b
* `EncryptInt64`/`DecryptInt64` - twos complement to allow negative addition
* `EncryptFloat`/`DecryptFloat` - IEEE754 binary64bit where exponent <= 389


Code is well documented python2. Most arguments are `long` or `int` types.
There is also a comprehensive unit test at http://pydoc.net/Python/encrypted_bigquery/1.0/paillier_test/

Even if we don't reuse any of their code the tests would be great.

#### Floating point notes in code:

Paillier homomorphic addition only directly adds positive binary values,
however, we would like to add both positive and negative float values
of different magnitudes. To achieve this, we will:

- represent the mantissa and exponent as one long binary value. This means
  that with 1024 bit n in paillier, the maximum exponent value is 389 bits.

- represent negative values with twos complement representation.

- Nan, +inf, -inf are each indicated by values in there own 32 bit region,
  so that when one of them is added, the appropriate region would be
  incremented and we would know this in the final aggregated value, assuming
  less than 2^32 values were aggregated.

- We limit the number of numbers that can be added to be less than 2^32
  otherwise we would not be able to detect overflows properly, etc.

- Also, in order to detect overflow after adding multiple values,
  the 64 sign bit is extended (or replicated) for an additional 64 bits.
  This allows us to detect if an overflow happened and knowing whether the
  most significant 32 bits out of 64 is zeroes or ones, we would know if the
  result should be a +inf or -inf.

Project Home: https://code.google.com/p/encrypted-bigquery-client/


C/C++
-----

Encounter
~~~~~~~~~

> Encounter is a software library aimed at providing a production-grade
> implementation of cryptographic counters

To date, Encounter implements a cryptocounter based on the Paillier
public-key cryptographic scheme

https://github.com/secYOUre/Encounter

FNP privacy-preserving set intersection protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A toolchain and library for privacy-preserving set intersection

It comes with rudimentary command-line interface: client, server, and
key-generation tool.  Extension and reuse is possible through C++ interfaces.
The implementation is fully thread-aware and multi-core ready, thus
computation time can be shortened by modern many-core machines.  We have verified
significant performance gains with quad-core Xeons and Opterons, through the
use of bucket allocation in the algorithm.

For homomorphic encryption and decryption, both modified ElGamal cryptosystem and
**Paillier cryptosystem** have been implemented on top of gmp.  And yes, the source
of randomness is always a headache for cryptosystem implementers; we have
keyboard, file and network packet as the sources of entropy.

It requires OpenSSL, gmp, gmpxx, boost, pthread, and pcap to build.
It currently runs on Linux.

http://fnp.sourceforge.net/


libpaillier
~~~~~~~~~~~

Library written in C and uses GMP.
The privss toolkit for private stream searching is built on libpaillier.

http://hms.isi.jhu.edu/acsc/libpaillier/

### HElib
~~~~~~~~~

> HElib is a software library that implements homomorphic encryption (HE).
> Currently available is an implementation of the Brakerski-Gentry-Vaikuntanathan
> (BGV) scheme, along with many optimizations to make homomorphic evaluation runs
> faster, focusing mostly on effective use of the Smart-Vercauteren ciphertext
> packing techniques and the Gentry-Halevi-Smart optimizations.
>
> At its present state, this library is mostly meant for researchers working on
> HE and its uses. Also currently it is fairly low-level, and is best thought of
> as "assembly language for HE". That is, it provides low-level routines (set, add,
> multiply, shift, etc.), with as much access to optimizations as we can give.
> Hopefully in time we will be able to provide higher-level routines.


https://github.com/shaih/HElib

Must read: http://tommd.github.io/posts/HELib-Intro.html

rinon/Simple-Homomorphic-Encryption
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Another C++ fully homomorphic encryption implementation.

https://github.com/rinon/Simple-Homomorphic-Encryption

Javascript
----------

*Javascript Cryptography Considered Harmful* - http://www.matasano.com/articles/javascript-cryptography/

mhe/jspaillier
~~~~~~~~~~~~~~

Adds the methods to the Public and Private keys.

Dependencies: jsbn
Demo Site: http://mhe.github.io/jspaillier/

p2p-paillier
~~~~~~~~~~~~

> allows a peer to add two numbers over a peer-to-peer network. Peers add
> these two numbers without even knowing what they are. It uses Firebase
> (which is centralized) in order to push commands to the peers.

Demo: http://9ac345a5509a.github.io/p2p-paillier/
Code: https://github.com/9ac345a5509a/p2p-paillier

Haskell
-------

There is a decent-looking haskell paillier library:
https://github.com/onemouth/HsPaillier

**BSD license**

There's just one test, which encrypts 37, decrypts it, and checks that it's still 37.


Java
----

There are a bunch of paillier libraries for java.

Are there any tests? 

UT Dallas
~~~~~~~~~

This one has documentation and two implementations:

https://www.utdallas.edu/~mxk093120/paillier/javadoc/paillierp/package-summary.html

    Provides the structures and methods to encrypt data with the Paillier encryption scheme with thresholding. This package a simplified implementation of what is specified in the paper A Generalization of Paillier's Public-Key System with Applications to Electronic Voting by Damgård et al. Within this paper, the authors generalize the Paillier encryption scheme to permit computations modulo ns+1, allowing block length for encryption to be chosen freely. In addition to this undertaking, Damgård et al. also constructed a threshold variant of the scheme.

    This package provides the following features of the paper
        - The degree of n is fixed to 1.
        - A fully functional simple Paillier encryption scheme with separate key classes for easy keysharing.
        - Proper Thresholding for an arbitrary number of decryption servers and threshold needed to decrypt.
        - Non-interactive zero knowledge proofs to ensure proper encryption and decryption.

    Of particular note, this implementation is simple as s is fixed to be 1. This allows for simplicity at this stage of the design. Further, we hope to have added methods which would make the actual use of this package to be easy and flexible.

    Future features would include support for encrypting arbitrary length strings/byte arrays to avoid padding issues. 

BGU Crypto course
~~~~~~~~~~~~~~~~~

This one is also documented but is for a crypto course so I'm not sure
how complete/practical it is intended to be. For example, it does its own keygen using `java.util.Random`.
https://code.google.com/p/paillier-cryptosystem/

UMBC
~~~~

This one is mercifully short but doesn't implement add, multiply as functions or methods. Also it uses `java.util.Random`.

http://www.csee.umbc.edu/~kunliu1/research/Paillier.html
