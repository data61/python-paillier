import json
import random
import unittest
from unittest import TestCase
import tempfile

import io

import sys
import click
from click.testing import CliRunner

import phe.command_line
from phe.command_line import cli


class TestConsoleBasics(TestCase):

    def test_cli_includes_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0

        assert 'Usage' in result.output
        assert 'Options' in result.output
        assert 'Commands' in result.output

    def test_generate_keypair_to_file(self):
        runner = CliRunner()

        with tempfile.NamedTemporaryFile() as outfile:
            result = runner.invoke(cli, ['genpkey', '--keysize', '256', outfile.name])
            print(result.output)
            assert result.exit_code == 0

            outfile.seek(0)
            written_data = outfile.read()

            priv_key = json.loads(written_data.decode('utf-8'))

        assert 'pub' in priv_key
        assert 'kty' in priv_key
        assert 'p' in priv_key

    def test_generate_keypair_to_stdout(self):
        runner = CliRunner()

        result = runner.invoke(cli, ['genpkey', '--keysize', '256', '-'])

        assert 'pub' in result.output
        assert 'kty' in result.output
        assert 'p' in result.output

    def test_extract_public_key(self):
        runner = CliRunner()

        with tempfile.NamedTemporaryFile() as private_keyfile:
            runner.invoke(cli, ['genpkey', '--keysize', '256', private_keyfile.name])

            with tempfile.NamedTemporaryFile() as public_keyfile:
                result = runner.invoke(cli, ['extract', private_keyfile.name, public_keyfile.name])
                assert result.exit_code == 0

                public_keyfile.seek(0)
                written_data = public_keyfile.read().decode('utf-8')

                assert '"kty":' in written_data
                assert '"n":' in written_data
                assert '"alg":' in written_data

                assert '"p":' not in written_data
                assert '"q":' not in written_data


class TestConsoleEncryption(TestCase):

    @classmethod
    def setUpClass(cls):
        """Generate a keypair and extract the public key.
        """
        cls.private_keyfile = tempfile.NamedTemporaryFile()
        cls.public_keyfile = tempfile.NamedTemporaryFile()

        cls.runner = CliRunner()
        cls.runner.invoke(cli, ['genpkey', '--keysize', '256', cls.private_keyfile.name])
        cls.runner.invoke(cli, ['extract', cls.private_keyfile.name, cls.public_keyfile.name])

    @classmethod
    def tearDownClass(cls):
        cls.private_keyfile.close()
        cls.public_keyfile.close()

    def test_encrypt_positive_integers(self):
        numbers = [0, 1, 2, 5, 10, '1', '10550']

        for num in numbers:
            result = self.runner.invoke(cli, ['encrypt', self.public_keyfile.name, str(num)])
            assert result.exit_code == 0

    def test_encrypt_signed_integers(self):
        """encrypting positive and negative integer"""
        numbers = [0, 1, -1, 10, '1', '-10550']

        for num in numbers:
            result = self.runner.invoke(cli, ['encrypt', self.public_keyfile.name, "--", str(num)])
            assert result.exit_code == 0

    def test_encrypt_float(self):
        numbers = [0.0, 1.1, -0.0001, 100000.01, '1e-20', '-10550e20']

        for num in numbers:
            result = self.runner.invoke(cli, ['encrypt', self.public_keyfile.name, "--", str(num)])
            assert result.exit_code == 0

    def test_encrypt_to_stdout(self):
        """Test encrypting and writing output to a file"""
        numbers = [0.0, 1.1, -0.0001, 100000.01, '1e-20', '-10550e20']

        for num in numbers:
            result = self.runner.invoke(cli, ['encrypt', self.public_keyfile.name, "--", str(num)])
            assert result.exit_code == 0

    def test_decrypt_positive_integers(self):
        numbers = [0, 1, 2, 5, 10, '1', '10550']

        for num in numbers:
            with tempfile.NamedTemporaryFile() as encfile:
                fname = encfile.name

                self.runner.invoke(cli, [
                    'encrypt', self.public_keyfile.name, str(num), '--output', fname
                ])

                result = self.runner.invoke(cli, [
                    'decrypt', self.private_keyfile.name, fname
                ])
                assert result.exit_code == 0

                assert "{}".format(num) in result.output

    def test_decrypt_signed_integers(self):
        numbers = [0, 1, -1, 10, '1', '-10550']

        for num in numbers:
            with tempfile.NamedTemporaryFile() as encfile:
                fname = encfile.name
                self.runner.invoke(cli, [
                    'encrypt', self.public_keyfile.name, '--output', fname, '--', str(num),
                ])

                result = self.runner.invoke(cli, [
                    'decrypt', self.private_keyfile.name, fname
                ])
                assert result.exit_code == 0

                print(result.output)
                assert "{}".format(num) in result.output

    def test_decrypt_float(self):
        numbers = [0.0, 1.1, -0.0001, 100000.01, '1e-20', '-10550e20']

        for num in numbers:
            with tempfile.NamedTemporaryFile() as encfile:
                fname = encfile.name
                self.runner.invoke(cli, [
                    'encrypt', self.public_keyfile.name, '--output', fname, '--', str(num),
                ])

                with tempfile.NamedTemporaryFile() as outfile:
                    result = self.runner.invoke(cli, [
                        'decrypt', self.private_keyfile.name, fname, '--output', outfile.name
                    ])
                    assert result.exit_code == 0

                    out = outfile.read()
                    self.assertAlmostEqual(float(num), float(out))


class TestConsoleHelpers(TestCase):

    @classmethod
    def setUpClass(cls):
        """Generate a keypair, extract the public key, and encrypt
        a list of numbers

        """
        cls.private_keyfile = tempfile.NamedTemporaryFile()
        cls.public_keyfile = tempfile.NamedTemporaryFile()


        cls.runner = CliRunner()
        cls.runner.invoke(cli, ['genpkey', '--keysize', '256', cls.private_keyfile.name])
        cls.runner.invoke(cli, ['extract', cls.private_keyfile.name, cls.public_keyfile.name])

    def setUp(self):
        self.enc_a_file = tempfile.NamedTemporaryFile()
        self.enc_b_file = tempfile.NamedTemporaryFile()
        self.enc_result_file = tempfile.NamedTemporaryFile()

    def encrypt_and_add(self, a, b):
        self.runner.invoke(cli,
                           ['encrypt', self.public_keyfile.name, '--output', self.enc_a_file.name, '--', str(a)])
        self.runner.invoke(cli,
                           ['encrypt', self.public_keyfile.name, '--output', self.enc_b_file.name, '--', str(b)])

        result = self.runner.invoke(cli, [
            'addenc',
            self.public_keyfile.name,
            self.enc_a_file.name,
            self.enc_b_file.name,
            '--output',
            self.enc_result_file.name
        ])

        assert result.exit_code == 0

        with tempfile.NamedTemporaryFile() as outfile:
            result = self.runner.invoke(cli, [
                'decrypt', self.private_keyfile.name, self.enc_result_file.name, '--output', outfile.name
            ])
            assert result.exit_code == 0

            out = outfile.read()
            return float(out)

    def _a_b_encrypt_helper(self, a, b, operation):
        self.runner.invoke(cli,
                           [
                               'encrypt',
                               self.public_keyfile.name,
                                '--output',
                               self.enc_a_file.name,
                               '--',
                                str(a)
                           ])

        result = self.runner.invoke(cli, [
            operation,
            '--output',
            self.enc_result_file.name,
            self.public_keyfile.name,
            self.enc_a_file.name,
            '--',
            str(b)
        ])

        assert result.exit_code == 0, "Problem carrying out the {} operation".format(operation)

        with tempfile.NamedTemporaryFile() as outfile:
            result = self.runner.invoke(cli, [
                'decrypt', self.private_keyfile.name, self.enc_result_file.name, '--output', outfile.name
            ])
            assert result.exit_code == 0

            out = outfile.read()
            return float(out)

    def encrypt_a_and_add_b(self, a, b):
        return self._a_b_encrypt_helper(a, b, 'add')

    def encrypt_a_and_multiply_b(self, a, b):
        return self._a_b_encrypt_helper(a, b, 'multiply')


class TestConsoleAddition(TestConsoleHelpers):

    def test_addenc_int(self):
        a, b = 12345, 6789
        out = self.encrypt_and_add(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_add_int(self):
        a, b = 12345, 6789
        out = self.encrypt_a_and_add_b(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_addenc_large_ints(self):
        """Test adding large integers.
        """
        a, b = int(1.2e10), int(1e15)
        out = self.encrypt_and_add(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_add_large_ints(self):
        """Test adding large integers.
        """
        a, b = int(1.2e10), int(1e15)
        out = self.encrypt_a_and_add_b(a, b)
        self.assertAlmostEqual(float(a + b), float(out))


    def test_addenc_signed_int(self):
        a, b = 12345, -6789
        out = self.encrypt_and_add(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_add_signed_int(self):
        a, b = 12345, -6789
        out = self.encrypt_a_and_add_b(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_addenc_floats(self):
        a, b = 123.45, 67.89
        out = self.encrypt_and_add(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_add_floats(self):
        a, b = 123.45, 67.89
        out = self.encrypt_a_and_add_b(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_addenc_large_floats(self):
        """Test adding large integers.
        """
        a, b = 2.3e32, 1.4e32
        out = self.encrypt_and_add(a, b)
        self.assertAlmostEqual(float(a + b), float(out))

    def test_add_large_floats(self):
        """Test adding large integers.
        """
        a, b = 2.3e32, 1.4e32
        out = self.encrypt_a_and_add_b(a, b)
        self.assertAlmostEqual(float(a + b), float(out))


class TestConsoleMultiplication(TestConsoleHelpers):
    """
    Expected to fail until we decide if encrypted numbers with different
    exponents are allowed for this CLI...
    """
    def test_multiply_ints(self):
        a, b = 15, 6
        out = self.encrypt_a_and_multiply_b(a, b)
        self.assertAlmostEqual(int(a * b), int(out))

    def test_multiply_floats(self):
        a, b = 1.2345, 0.6
        out = self.encrypt_a_and_multiply_b(a, b)
        self.assertAlmostEqual(float(a * b), float(out))

    def test_multiply_random_ints(self):
        """
        """
        MAX = 100000000000
        MIN = -MAX

        for _ in range(50):
            a, b = random.randrange(MIN, MAX), random.randrange(MIN, MAX)
            out = self.encrypt_a_and_multiply_b(a, b)
            self.assertAlmostEqual(float(a * b), float(out))


class TestFuzz(TestConsoleHelpers):

    def test_addenc_random_ints(self):
        """Test adding random ints
        """
        MAX = 1000000000000000
        MIN = -MAX

        for _ in range(20):
            a, b = random.randrange(MIN, MAX), random.randrange(MIN, MAX)
            out = self.encrypt_and_add(a, b)
            self.assertAlmostEqual(float(a + b), float(out))

    def test_add_random_ints(self):
        """Test adding random ints
        """
        MAX = 1000000000000000
        MIN = -MAX

        for _ in range(20):
            a, b = random.randrange(MIN, MAX), random.randrange(MIN, MAX)
            out = self.encrypt_a_and_add_b(a, b)
            self.assertAlmostEqual(float(a + b), float(out))

    def test_addenc_random_floats(self):
        """Test adding random floating point numbers from the range [0.0, 1.0)
        """
        for _ in range(20):
            a, b = random.random(), random.random()
            out = self.encrypt_and_add(a, b)
            self.assertAlmostEqual(float(a + b), float(out))

    def test_add_random_floats(self):
        """Test adding random floating point numbers from the range [0.0, 1.0)
        """
        for _ in range(20):
            a, b = random.random(), random.random()
            out = self.encrypt_a_and_add_b(a, b)
            self.assertAlmostEqual(float(a + b), float(out))


    def test_multiply_random_ints(self):
        """
        """
        MAX = 10000
        MIN = -MAX

        for _ in range(20):
            a, b = random.randrange(MIN, MAX), random.randrange(MIN, MAX)
            out = self.encrypt_a_and_multiply_b(a, b)
            self.assertAlmostEqual(float(a * b), float(out))


