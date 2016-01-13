.. _installation:

Installation
============

.. note::

    This library requires a minimum Python version of at least 3.3.

Using pip
---------

Using pip at the command line, to install the base library from `PyPi <https://pypi.python.org/pypi/phe/>`_::

    $ pip install phe


To also install the :ref:`command line utility <cli>`, introduced at version 1.2::

    pip install "phe[cli]>1.2"



Manual installation
-------------------

To install from the source package, first install the optional dependencies (eg Crypto)::

    $ pip install -r requirements.txt

Then install as normal::

    $ python setup.py install


Or, if you have `virtualenvwrapper <https://virtualenvwrapper.readthedocs.org/en/latest/>`_
installed::

    $ mkvirtualenv phe
    $ pip install -e ".[CLI]"
