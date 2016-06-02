python-paillier  |release|
===============

+---------------------+-----------------+
|       master        |    develop      |
+=====================+=================+
|      |travisM|      |   |travisD|     |
+---------------------+-----------------+
|      |rtdM|         |   |rtdD|        |
+---------------------+-----------------+
|      |coverageM|    |   |coverageD|   |
+---------------------+-----------------+
|      |reqM|         |   |reqD|        |
+---------------------+-----------------+

A library for Partially Homomorphic Encryption in Python.

The homomorphic properties of the paillier crypto system are:

-  Encrypted numbers can be multiplied by a non encrypted scalar.
-  Encrypted numbers can be added together.
-  Encrypted numbers can be added to non encrypted scalars.

Running unit tests
------------------

::

    python setup.py test

Or use nose::

   nosetests


Code History
------------

Developed at `Data61 | CSIRO <http://data61.csiro.au>`_.

Parts derived from the Apache licensed Google project:
https://code.google.com/p/encrypted-bigquery-client/

No audit
--------

This code has neither been written nor vetted by any sort of crypto
expert. The crypto parts are mercifully short, however.


.. |release| image:: https://img.shields.io/pypi/v/phe.svg
    :target: https://pypi.python.org/pypi/phe/
    :alt: Latest released version on PyPi


.. |travisM| image:: https://travis-ci.org/NICTA/python-paillier.svg?branch=master
    :target: https://travis-ci.org/NICTA/python-paillier
    :alt: CI status of Master

.. |travisD| image:: https://travis-ci.org/NICTA/python-paillier.svg?branch=develop
    :target: https://travis-ci.org/NICTA/python-paillier
    :alt: CI status of develop

.. |reqM| image:: https://requires.io/github/NICTA/python-paillier/requirements.svg?branch=master
    :target: https://requires.io/github/NICTA/python-paillier/requirements/?branch=master
    :alt: Requirements Status of master

.. |reqD| image:: https://requires.io/github/NICTA/python-paillier/requirements.svg?branch=develop
    :target: https://requires.io/github/NICTA/python-paillier/requirements/?branch=develop
    :alt: Requirements Status of develop

.. |rtdM| image:: https://readthedocs.org/projects/python-paillier/badge/?version=stable
   :target: http://python-paillier.readthedocs.org/en/latest/?badge=stable
   :alt: Documentation Status

.. |rtdD| image:: https://readthedocs.org/projects/python-paillier/badge/?version=develop
   :target: http://python-paillier.readthedocs.org/en/latest/?badge=develop
   :alt: Documentation Status
    
.. |coverageM| image:: https://coveralls.io/repos/NICTA/python-paillier/badge.svg?branch=master&service=github
    :target: https://coveralls.io/github/NICTA/python-paillier?branch=master
  
.. |coverageD| image:: https://coveralls.io/repos/NICTA/python-paillier/badge.svg?branch=develop&service=github
    :target: https://coveralls.io/github/NICTA/python-paillier?branch=develop


