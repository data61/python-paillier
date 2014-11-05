"""
Benchmark key generation, encryption and decryption.

Also compares the speed of modexp and invert between OpenSSL and libGMP.
"""

import random
import resource
import os
import time
import phe.paillier as paillier
from gmpy2 import powmod

def bench_encrypt(pubkey, nums):
    for num in nums:
        pubkey.encrypt(num)


def bench_decrypt(prikey, nums):
    for num in nums:
        prikey.decrypt(num)


def bench_add(nums1, nums2):
    for num1, num2 in zip(nums1, nums2):
        num1 + num2


def bench_mul(nums1, nums2):
    for num1, num2 in zip(nums1, nums2):
        num1 * num2

def time_method(method, *args):
    start = time.time()
    method(*args)
    return time.time() - start

def bench_time(test_size, key_size=128):

    print('Paillier Benchmarks with key size of {} bits'.format(key_size))
    pubkey, prikey = paillier.generate_paillier_keypair(n_length=key_size)
    nums1 = [random.random() for _ in range(test_size)]
    nums2 = [random.random() for _ in range(test_size)]
    nums1_enc = [pubkey.encrypt(n) for n in nums1]
    nums2_enc = [pubkey.encrypt(n) for n in nums2]
    ones = [1.0 for _ in range(test_size)]

    times = [
        time_method(bench_encrypt, pubkey, nums1),
        time_method(bench_decrypt, prikey, nums1_enc),
        time_method(bench_add, nums1_enc, nums2),
        time_method(bench_add, nums1_enc, nums2_enc),
        time_method(bench_add, nums1_enc, ones),
        time_method(bench_mul, nums1_enc, nums2)
    ]
    times = [t / test_size for t in times]
    ops = [int(1.0 / t) for t in times]

    print(
        'operation: time in seconds (# operations per second)\n'
        'encrypt: {:.6f} s ({} ops/s)\n'
        'decrypt: {:.6f} s ({} ops/s)\n'
        'add unencrypted and encrypted: {:.6f} s ({} ops/s)\n'
        'add encrypted and encrypted: {:.6f} s ({} ops/s)\n'
        'add encrypted and 1: {:.6f} s ({} ops/s)\n'
        'multiply encrypted and unencrypted: {:.6f}  s ({} ops/s)'.format(
            times[0], ops[0], times[1], ops[1], times[2], ops[2],
            times[3], ops[3], times[4], ops[4], times[5], ops[5]
        )
    )
    return times


def bench_mem(test_size):
    r_init = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    pubkey, prikey = paillier.generate_paillier_keypair()
    nums = []
    for i in range(test_size):
        if not i % 10000:
            # This is probably KB (i.e. 1000 bytes) when run on linux
            r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - r_init
            print('Memory usage for {:,} encrypted numbers = {:,} ({:.4f} per number)'.format(
                i, r, i and r / i
            ))
        nums.append(pubkey.encrypt(random.random()))

def bench_mod_exp():
    def large_random_number(size):
        return int.from_bytes(os.urandom(size), byteorder='little')


    # OpenSSL version
    # -- openssl function args and return types
    import platform, math

    import ctypes
    import ctypes.util
    _FOUND_SSL = False
    if platform.system() == 'Windows':
        ssl_libpath = ctypes.util.find_library('libeay32')
    else:
        ssl_libpath = ctypes.util.find_library('ssl')
    if ssl_libpath:
        ssl = ctypes.cdll.LoadLibrary(ssl_libpath)
        _FOUND_SSL = True

    if _FOUND_SSL:
        ssl.BN_new.restype = ctypes.c_void_p
        ssl.BN_new.argtypes = []
        ssl.BN_free.argtypes = [ctypes.c_void_p]
        ssl.BN_num_bits.restype = ctypes.c_int
        ssl.BN_num_bits.argtypes = [ctypes.c_void_p]
        ssl.BN_bin2bn.restype = ctypes.c_void_p
        ssl.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        ssl.BN_bn2bin.restype = ctypes.c_int
        ssl.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        ssl.BN_CTX_new.restype = ctypes.c_void_p
        ssl.BN_CTX_new.argtypes = []
        ssl.BN_CTX_free.restype = ctypes.c_int
        ssl.BN_CTX_free.argtypes = [ctypes.c_void_p]
        ssl.BN_mod_exp.restype = ctypes.c_int
        ssl.BN_mod_exp.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p]



    def _NumBytesBn(bn):
        """Returns the number of bytes in the Bignum."""
        if not _FOUND_SSL:
            raise RuntimeError('Cannot evaluate _NumBytesBn because ssl library was '
                               'not found')
        size_in_bits = ssl.BN_num_bits(bn)
        return int(math.ceil(size_in_bits / 8.0))

    def ModExp(a, b, c):
        """Uses openssl, if available, to do a^b mod c where a,b,c are longs."""

        # convert arbitrary int args to bytes
        bytes_a = a.to_bytes(math.ceil(a.bit_length()/8), 'big')
        bytes_b = b.to_bytes(math.ceil(b.bit_length()/8), 'big')
        bytes_c = c.to_bytes(math.ceil(c.bit_length()/8), 'big')

        # convert bytes to (pointer to) Bignums.
        bn_a = ssl.BN_bin2bn(bytes_a, len(bytes_a), 0)
        bn_b = ssl.BN_bin2bn(bytes_b, len(bytes_b), 0)
        bn_c = ssl.BN_bin2bn(bytes_c, len(bytes_c), 0)

        bn_result = ssl.BN_new()
        ctx = ssl.BN_CTX_new()

        # exponentiate and convert result to int
        ssl.BN_mod_exp(bn_result, bn_a, bn_b, bn_c, ctx)
        num_bytes_in_result = _NumBytesBn(bn_result)
        bytes_result = ctypes.create_string_buffer(num_bytes_in_result)
        ssl.BN_bn2bin(bn_result, bytes_result)

        result = int.from_bytes(bytes_result.raw, 'big')

        # clean up
        ssl.BN_CTX_free(ctx)
        ssl.BN_free(bn_a)
        ssl.BN_free(bn_b)
        ssl.BN_free(bn_c)
        ssl.BN_free(bn_result)

        return result

    def gmpmethod(a, b, c):
        return int(powmod(a, b, c))

    print("Modulo Exponent:")
    print("Size (bytes)|    Python  |   GMP      |   OpenSSL  | winner")
    nums = [1] + list(range(2, 30, 2)) + [2**i for i in range(6, 12)]

    for num_bytes in nums:
        a, b, c = map(large_random_number, [num_bytes]*3)
        #c = large_random_number(2)
        pure_python_time = time_method(pow, a, b, c)
        gmp_time = time_method(gmpmethod, a, b, c)
        openssl_time = time_method(ModExp, a, b, c)

        assert ModExp(a, b, c) == powmod(a, b, c)

        winner = 'pow'
        if gmp_time < pure_python_time and gmp_time < openssl_time:
            winner = "GMP"
        elif openssl_time < pure_python_time and openssl_time < gmp_time:
            winner = "OPENSSL"

        print("{:>11d} | {:10.6f} | {:10.6f} | {:10.6f} | {}".format(num_bytes, pure_python_time, gmp_time, openssl_time, winner))


def bench_invert():
    import gmpy2
    from Crypto.Util import number
    a = 9692203755419362706443688640367782553353403449939735913976640842074887419511930064667543546433463612148149096853642604762192756822511466605871512353326121930781064556520135960318269216983059313717087746726963176661095124556763575590056948444821227485018292320109353940667846310705515875282012567330970663289982670092544827187904973857187464949724130816407687863973796521711808619088073139638310712174582671147651931357172500020385026640186076242499265525377364248431284414837289026263907667248980385401812721149596620808484801965822628603612108620137185137793987518110957876092643839872562734471333175894919458240744
    b = 10710242736965941735033651668323075385668937175523770473497656900171579417394724419905596641614980011453633932277660560605369043356646866390856924866120373272893211251643114647660737549713233617413790183550629875693437618408446870898160235366804608380235402961089196772472733348689369011648810802147940257028117599431149343176142453726709573333068496106564439509752602743405246815890296672824544198605398560656197870671934035028377748499263747063641536916159058480047730875665396345143043335926094010018933117391303447884085758959419537659752430879993455200054780085962748647658670414333272517467726417379100965226249

    def gmpinvert(a, b):
        return int(gmpy2.invert(a, b))

    def openssl(a, b):
        return number.inverse(a, b)

    assert gmpinvert(a, b) == openssl(a, b)
    print("Modulo Inversion:")
    print("GMP:     {:.6f} s".format(time_method(gmpinvert, a, b)))
    print("OpenSSL: {:.6f} s".format(time_method(openssl, a, b)))

#bench_mem(1000000)  # NOTE: this will take a long time

times = []
key_sizes = [128, 256, 512, 1024, 2048]
for key_size in key_sizes:
    times.append(bench_time(10000, key_size))

bench_mod_exp()
bench_invert()
