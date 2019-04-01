python-shamir-mnemonic
===============

Reference implementation of SLIP-0039: Shamir's Secret-Sharing for Mnemonic
Codes

Abstract
--------

This SLIP describes a standard and interoperable implementation of Shamir's
secret sharing (SSS). SSS splits a secret into unique parts which can be
distributed among participants, and requires a specified minimum number of
parts to be supplied in order to reconstruct the original secret. Knowledge of
fewer than the required number of parts does not leak information about the
secret.

Specification
-------------

See https://github.com/satoshilabs/slips/blob/master/slip-0039.md for full
specification.

Installation
------------

With pip from GitHub:

.. code_block:: console

    $ pip3 install https://github.com/trezor/python-shamir-mnemonic

From local checkout for development:

.. code_block:: console

    $ python3 setup.py develop
