.. _cli:

Command Line Utility
====================

The command line utility is not installed by default. When installing with pip you
must specify the optional extra eg::

    pip install "phe[cli]" --upgrade


After :ref:`installation`, the **pheutil** command line program will be installed on your path.
This interface allows a user to:

- generate and serialize key pairs (of different key sizes)
- encrypt and serialize given a public key and a plaintext number
- decrypt given a private key and the ciphertext
- add two encrypted numbers together
- add an encrypted number to a plaintext number
- multiply an encrypted number to a plaintext number


For commands, and examples call `--help`::

    $ pheutil --help

    Usage: pheutil [OPTIONS] COMMAND [ARGS]...

      CLI for interacting with python-paillier

    Options:
      --version      Show the version and exit.
      -v, --verbose  Enables verbose mode.
      --help         Show this message and exit.

    Commands:
      add       Add encrypted number to unencrypted number.
      addenc    Add two encrypted numbers together.
      decrypt   Decrypt ciphertext with private key.
      encrypt   Encrypt a number with public key.
      extract   Extract public key from private key.
      genpkey   Generate a paillier private key.
      multiply  Multiply encrypted num with unencrypted num.


Each command also includes more detail, e.g. for `genpkey`::

    $ pheutil genpkey --help
    Usage: pheutil genpkey [OPTIONS] OUTPUT

      Generate a paillier private key.

      Output as JWK to given output file. Use "-" to output the private key to
      stdout. See the extract command to extract the public component of the
      private key.

      Note:     The default ID text includes the current time.

    Options:
      --keysize INTEGER  The keysize in bits. Defaults to 2048
      --id TEXT          Add an identifying comment to the key



To use the command line client without installing `python-paillier`, run the
:mod:`phe.command_line` module from the project root::

    python -m phe.command_line

Bash completion can be enabled by adding the following to your `.bashrc` file::

    eval "$(_PHEUTIL_COMPLETE=source pheutil)"

