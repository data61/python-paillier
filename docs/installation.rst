.. _installation:

Installation
============

The python-paillier library requires a minimum Python version of
at least 3.3.

.. note::

    A Big integer math library is used to increase the speed of
    python-paillier and to access a Cryptographic random source.
    All big integer math has been implemented with
    `GMP <https://gmplib.org/>`_ - the GNU Multiple Precision
    arithmetic library. This dependency should be installed for
    your operating system.

    On Ubuntu systems the following packages should be installed::

        libmpc-dev libmpfr-dev libmpfr4 libgmp3-dev


Using pip
---------

Using pip at the command line, to install the base library from `PyPi <https://pypi.python.org/pypi/phe/>`_::

    $ pip install phe


To also install the :ref:`command line utility <cli>`, introduced at version 1.2::

    pip install "phe[cli]>1.2"

Examples have been written which have their own additional requirements such as sklearn.
To also install those::

    pip install "phe[cli,examples]"


Or, if you have `virtualenvwrapper <https://virtualenvwrapper.readthedocs.org/en/latest/>`_
installed::

    $ mkvirtualenv phe
    $ pip install -e ".[CLI]"


Manual installation
-------------------

To install from the source package, first install any of the (optional)
dependencies (eg Crypto, gmpy2). A list can be found in
``requirements.txt``.

Then install as normal::

    $ python setup.py install


Docker
------

A minimal Docker file based on alpine linux::

    FROM python:3-alpine
    RUN ["apk", "add", "--no-cache",    \
            "g++",                      \
            "musl-dev",                 \
            "gmp-dev",                  \
            "mpfr-dev",                 \
            "mpc1-dev"                  \
        ]
    RUN pip install phe

