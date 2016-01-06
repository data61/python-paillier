# pyphe

A library for Partially Homomorphic Encryption in Python.

The homomorphic properties of the paillier crypto system are:

- Encrypted numbers can be multiplied by a non encrypted scalar.
- Encrypted numbers can be added together.
- Encrypted numbers can be added to non encrypted scalars.

[![Documentation Status](https://readthedocs.org/projects/python-paillier/badge/?version=latest)](https://python-paillier.readthedocs.org/en/latest/)
[![Build Status](https://travis-ci.org/NICTA/python-paillier.svg?branch=master)](https://travis-ci.org/NICTA/python-paillier)
[![Requirements Status](https://requires.io/github/NICTA/python-paillier/requirements.svg?branch=master)](https://requires.io/github/NICTA/python-paillier/requirements/?branch=master)


## Running unit tests

    python3 setup.py test

## Code History

Parts derived from the Apache licensed Google project: https://code.google.com/p/encrypted-bigquery-client/

## No audit

This code has neither been written nor vetted by any sort of crypto expert. The crypto parts are mercifully short, however.
