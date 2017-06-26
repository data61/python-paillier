"""
Benchmark key generation, encryption and decryption.

"""

import random
import resource
import time
import phe.paillier as paillier


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
            print('Memory usage for {:,} encrypted numbers = {:,} ({:.4f} per '
                  'number)'.format(i, r, i and r / i))
        nums.append(pubkey.encrypt(random.random()))

# bench_mem(1000000)  # NOTE: this will take a long time


times = []
key_sizes = [128, 256, 512, 1024, 2048, 4096, 8192]
for key_size in key_sizes:
    times.append(bench_time(1000, key_size))
