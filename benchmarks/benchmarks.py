# Benchmarks using https://asv.readthedocs.io/en/latest/index.html

import random
import phe.paillier as paillier

class PaillierKeygenBenchSuite:
    params = [256, 512, 1024, 2048, 4096]
    param_names = ['keylength']

    def time_key_generation(self, n):
        pubkey, prikey = paillier.generate_paillier_keypair(n_length=n)


class PaillierMathBenchSuite:

    params = [10, 100, 1000]

    def setup(self, test_size):
        self.pk, self.sk = paillier.generate_paillier_keypair()

        self.nums1 = [random.random() for _ in range(test_size)]
        self.nums2 = [random.random() for _ in range(test_size)]

        self.enc_nums1 = [self.pk.encrypt(n) for n in self.nums1]
        self.enc_nums2 = [self.pk.encrypt(n) for n in self.nums2]

        self.ones = [1.0 for _ in range(test_size)]

    def time_key_generation_default(self, n):
        pubkey, prikey = paillier.generate_paillier_keypair()

    def time_encrypt(self, n):
        for num in self.nums1:
            self.pk.encrypt(num)

    def time_decrypt(self, n):
        for num in self.enc_nums1:
            self.sk.decrypt(num)

    def time_add_both_enc(self, n):
        for num1, num2 in zip(self.enc_nums1, self.enc_nums2):
            num1 + num2

    def time_add_enc_scalar(self, n):
        for num1, num2 in zip(self.enc_nums1, self.nums2):
            num1 + num2

    def time_mul(self, n):
        for num1, num2 in zip(self.enc_nums1, self.nums2):
            num1 * num2


class MemSuite:

    def peakmem_key_generation(self):
        paillier.generate_paillier_keypair()

