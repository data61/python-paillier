import json
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
        assert 'lambda' in priv_key

    def test_generate_keypair_to_stdout(self):
        runner = CliRunner()

        result = runner.invoke(cli, ['genpkey', '--keysize', '256', '-'])

        assert 'pub' in result.output
        assert 'kty' in result.output
        assert 'lambda' in result.output

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

                assert '"mu":' not in written_data
                assert '"lamdba":' not in written_data


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
