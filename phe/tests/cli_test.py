import json
from unittest import TestCase
import tempfile
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

    def test_generate_keypair(self):
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