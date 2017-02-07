.. _compatibility:

Compatibility with other libraries
==================================

This library may, with *care*, be used with other Paillier implementations. Keep in mind, that in this library 
the generator g of the public key is fixed to g = n + 1 (for efficiency reasons) and cannot arbitrarily be 
chosen as described in the Paillier paper.

- `Javallier <https://github.com/NICTA/javallier/>`_ - library for Java/Scala also maintained by NICTA. Somewhat
  different Encoding scheme. Base of 2 is fixed (see :ref:`alternative-base`)
- `paillier.js <https://github.com/hardbyte/paillier.js>`_ - Early prototype library for Javascript/Typescript




.. toctree::
   :maxdepth: 2

   alternatives