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

Extendable encrypted master secrets
-----------------------------------

When you SLIP-39 encode a master secret with a password, you can always recover the original secret
with the same password.  You of course get a **different** secret (ie. a different wallet) with a
different password; this is by design: you can (for example) have a master password for your true
wallet containing your funds, and a "decoy" password for a valid wallet that contains funds to
satisfy an attacker.  Or, you may simply derive multiple wallets for different purposes with
different passwords.

The mnemonics are by default "extendable", meaning that you can re-encode the same master secret
again (with different SLIP-39 group specs), and get the same decrypted secret back with the original
password, and the **same** wallets with your other passwords.

If desired, you can produce **--no-extendable** encrypted master secrets (which used to be the
SLIP-39 standard), which always recover the original secret with the original password -- but
produce **different** secrets for all other passwords.  This only causes surprises when you want to
re-encrypt the same master secret again: you can't re-obtain the **other** passwords' wallets using
the newly encoded mnemonics!

To reduce surprises, SLIP-39 now produces **--extendable** encrypted master secrets by default.

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

Alternatively, install [Nix](https://nixos.org/download/), and (assuming you have GNU `make` available), run:

.. code-block:: console

    $ make nix-venv-test

to install a Python environment, create a Python `venv`, enter it and run the `make test` target.  To enter
the `venv` in an interactive shell, run `make nix-venv`.

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

CLI usage: expand an existing mnemonic group
--------------------------------------------

If you wish to increase the number of mnemonics in an existing multi-mnemonic group, you can now do
this.  All existing mnemonics remain valid.

To expand an existing group 3 to include 10 mnemonics, use:

.. code-block:: console

    $ shamir expand --change 3 10

Enter mnemonics sufficient to recover the master secret, including all of the group(s) you desire to
:code:`--change`.  However, you may elect to replace a missing group with a new single-Share group
(if you don't specify :code:`--strict`).

Use :code:`shamir --help` or :code:`shamir expand --help` to see all available options.

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
