# This file is part of pyphe.
#
# pyphe is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# pyphe is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with pyphe.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import random
import base64

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

try:
    from Crypto.Util import number
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# GMP's powmod has greater overhead than Python's pow, but is faster.
# From a quick experiment on our machine, this seems to be the break even:
_USE_MOD_FROM_GMP_SIZE = (1 << (8*2))


def powmod(a, b, c):
    """
    Uses GMP, if available, to do a^b mod c where a, b, c
    are integers.

    :return int: (a ** b) % c
    """

    if not HAVE_GMP or max(a, b, c) < _USE_MOD_FROM_GMP_SIZE:
        return pow(a, b, c)
    else:
        return int(gmpy2.powmod(a, b, c))


def invert(a, b):
    """
    The multiplicitive inverse of a in the integers modulo b.

    :return int: x, where a * x == 1 mod b
    """
    if HAVE_GMP:
        return int(gmpy2.invert(a, b))
    else:
        # http://code.activestate.com/recipes/576737-inverse-modulo-p/
        for d in range(1, b):
            r = (d * a) % b
            if r == 1:
                break
        else:
            raise ValueError('%d has no inverse mod %d' % (a, b))
        return d


def getprimeover(N):
    """Return a random N-bit prime number using the System's best
    Cryptographic random source.

    Use GMP if available, otherwise fallback to PyCrypto
    """
    if HAVE_GMP:
        randfunc = random.SystemRandom()
        r = gmpy2.mpz(randfunc.getrandbits(N))
        r = gmpy2.bit_set(r, N - 1)
        return int(gmpy2.next_prime(r))
    elif HAVE_CRYPTO:
        return number.getPrime(N, os.urandom)
    else:
        raise NotImplementedError("No pure python implementation sorry")


# b64 utils from https://github.com/GehirnInc/python-jwt/blob/master/jwt/utils.py
if sys.version_info[0] == 3:
    ord = lambda i: i


def b64_encode(source):
    if not isinstance(source, bytes):
        source = source.encode('ascii')

    encoded = base64.urlsafe_b64encode(source).replace(b'=', b'')
    return str(encoded.decode('ascii'))


def b64_decode(source):
    if not isinstance(source, bytes):
        source = source.encode('ascii')

    source += b'=' * (4 - (len(source) % 4))
    return base64.urlsafe_b64decode(source)


def base64_to_int(source):
    if not isinstance(source, bytes):
        source = source.encode('ascii')

    result = 0
    for b in b64_decode(source):
        result = (result << 8) + ord(b)

    return result


def int_to_base64(source):
    result_reversed = []
    while source:
        source, remainder = divmod(source, 256)
        result_reversed.append(remainder)

    return b64_encode(bytes(bytearray(reversed(result_reversed))))
