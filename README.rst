python-shamir-mnemonic
======================

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

.. code-block:: console

    $ pip3 install https://github.com/trezor/python-shamir-mnemonic

From local checkout for development:

.. code-block:: console

    $ python3 setup.py develop

CLI usage
---------

CLI tool is included as a reference and UX testbed. It is **very obviously insecure**.
DO NOT USE it for generating or decoding any sort of serious secrets.

When the :code:`shamir_mnemonic` package is installed, you can use the :code:`shamir` command:

.. code-block:: console

    $ shamir create 3of5   # create a 3-of-5 set of shares

Use :code:`shamir --help` or :code:`shamir <command> --help` to get detailed help.

If you want to run the CLI from a local checkout without installing, use the following
command:

.. code-block:: console

    $ python3 -m shamir_mnemonic.cli
