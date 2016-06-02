.. _cli:

====================
Command Line Utility
====================

This cli interface allows a user to:

- generate and serialize key pairs (of different key sizes)
- encrypt and serialize given a public key and a plaintext number
- decrypt given a private key and the ciphertext
- add two encrypted numbers together
- add an encrypted number to a plaintext number
- multiply an encrypted number to a plaintext number


Installation
------------

The command line utility is not installed by default. When installing with pip you
must specify the optional extra eg::

    pip install "phe[cli]" --upgrade


After :ref:`installation`, the **pheutil** command line program will be installed on your path.


To use the command line client without installing `python-paillier`, run the
:mod:`phe.command_line` module from the project root::

    python -m phe.command_line


Usage Help
----------

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


Example Session
---------------

::

    $ pheutil genpkey --keysize 1024 example_private_key.json
    Generating a paillier keypair with keysize of 1024
    Keys generated
    Private key written to example_private_key.json
    $ pheutil extract example_private_key.json example_public_key.json
    Loading paillier keypair
    Public key written to example_public_key.json
    $ pheutil encrypt --output test.enc example_public_key.json 5000
    Loading public key
    Encrypting: +5000.0000000000000000
    $ cat test.enc | python -m json.tool
    {
        "e": -32,
        "v": "8945468961282852256778220989238222172150456425808373953578229301775803205409565637223688006899379858518150634149268673387123813092667724639715011697847472787020974697972558733184395004744948252959649660835719161407306407854534355718203796283103451456746682405859634010362011442548072273622024024463167923466056606817150074423359137917704381669997696942809271828714079014827677816707229329379573217492868913536374239033718507818834874942682659422972598117458546894148344090333255242329686475806834331038677335462130194428967083103705644514152785933564702168267063628303275275994362218144323611010911197842705253655015"
    }
    $ pheutil add --output result.enc example_public_key.json test.enc 100
    Loading public key
    Loading encrypted number
    Loading unencrypted number
    Adding
    Exponent is less than -32
    $ pheutil decrypt example_private_key.json result.enc
    Loading private key
    Decrypting ciphertext
    5100.0



Bash Completion
---------------

Bash completion can be enabled by adding the following to your `.bashrc` file::

    eval "$(_PHEUTIL_COMPLETE=source pheutil)"

Further information on bash completion can be found in the `click <http://click.pocoo.org/5/bashcomplete/>`_
documentation.
