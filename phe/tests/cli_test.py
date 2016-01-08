import json
from unittest import TestCase
import tempfile
from contextlib import redirect_stdout, redirect_stderr

import io

import sys
import click
from click.testing import CliRunner

from phe.command_line import cli


class TestConsole(TestCase):

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
            result = runner.invoke(cli, ['generate', '--keysize', '256', outfile.name])
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

        result = runner.invoke(cli, ['generate', '--keysize', '256', '-'])

        assert 'pub' in result.output
        assert 'kty' in result.output
        assert 'lambda' in result.output

    def test_extract_public_key(self):
        runner = CliRunner()

        with tempfile.NamedTemporaryFile() as private_keyfile:
            runner.invoke(cli, ['generate', '--keysize', '256', private_keyfile.name])

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


    def test_encrypt_basic(self):
        """Test encrypting an integer"""
        runner = CliRunner()

        numbers = [0, 1, -5, 10, '1', '1e5']

        with tempfile.NamedTemporaryFile() as private_keyfile:
            with tempfile.NamedTemporaryFile() as public_keyfile:
                runner.invoke(cli, ['generate', '--keysize', '256', private_keyfile.name])
                runner.invoke(cli, ['extract', private_keyfile.name, public_keyfile.name])

                for num in numbers:
                    print("num:", num)
                    result = runner.invoke(cli, ['encrypt', public_keyfile.name, str(num)])
                    assert result.exit_code == 0
