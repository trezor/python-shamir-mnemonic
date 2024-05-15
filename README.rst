python-shamir-mnemonic
======================

.. image:: https://badge.fury.io/py/shamir-mnemonic.svg
    :target: https://badge.fury.io/py/shamir-mnemonic

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

Security
--------

This implementation is not using any hardening techniques. Secrets are passed in the
open, and calculations are most likely trivially vulnerable to side-channel attacks.

The purpose of this code is to verify correctness of other implementations. **It should
not be used for handling sensitive secrets**.

Installation
------------

With pip from PyPI:

.. code-block:: console

    $ pip3 install shamir-mnemonic[cli]  # for CLI tool

From local checkout for development:

Install the [Poetry](https://python-poetry.org/) tool, checkout
`python-shamir-mnemonic` from git, and enter the poetry shell:

.. code-block:: console

    $ pip3 install poetry
    $ git clone https://github.com/trezor/python-shamir-mnemonic
    $ cd python-shamir-mnemonic
    $ poetry install
    $ poetry shell

CLI usage
---------

CLI tool is included as a reference and UX testbed.

**Warning:** this tool makes no attempt to protect sensitive data! Use at your own risk.
If you need this to recover your wallet seeds, make sure to do it on an air-gapped
computer, preferably running a live system such as Tails.

When the :code:`shamir_mnemonic` package is installed, you can use the :code:`shamir`
command:

.. code-block:: console

    $ shamir create 3of5   # create a 3-of-5 set of shares
    $ shamir recover       # interactively recombine shares to get the master secret

You can supply your own master secret as a hexadecimal string:

.. code-block:: console

    $ shamir create 3of5 --master-secret=cb21904441dfd01a392701ecdc25d61c

You can specify a custom scheme. For example, to create three groups, with 2-of-3,
2-of-5, and 4-of-5, and require completion of all three groups, use:

.. code-block:: console

    $ shamir create custom --group-threshold 3 --group 2 3 --group 2 5 --group 4 5

Use :code:`shamir --help` or :code:`shamir create --help` to see all available options.

If you want to run the CLI from a local checkout without installing, use the following
command:

.. code-block:: console

    $ python3 -m shamir_mnemonic.cli

Test vectors
------------

The test vectors in vectors.json are given as a list of quadruples:
* The first member is a description of the test vector.
* The second member is a list of mnemonics.
* The third member is the master secret which results from combining the mnemonics.
* The fourth member is the BIP32 master extended private key derived from the master secret.

The master secret is encoded as a string containing two hexadecimal digits for each byte. If
the string is empty, then attempting to combine the given set of mnemonics should result
in error. The passphrase "TREZOR" is used for all valid sets of mnemonics.
