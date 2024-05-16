Changelog
=========

.. default-role:: code

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog`_, and this project adheres to
`Semantic Versioning`_.

`0.3.1`_ - Unreleased
---------------------

(no changes yet)

.. _0.3.1: https://github.com/trezor/python-shamir-mnemonic/compare/v0.3.0...HEAD

`0.3.0`_ - 2024-05-15
---------------------

Incompatible
~~~~~~~~~~~~

- The `shamir` command no longer works out of the box. It is necessary to install the
  `cli` extra while installing the package. See README for instructions.

Added
~~~~~

- Added BIP32 master extended private key to test vectors.
- Added support for extendable backup flag.

Changed
~~~~~~~

- The `shamir_mnemonic` package now has zero extra dependencies on Python 3.7 and up,
  making it more suitable as a dependency of other projects.
- The `shamir` CLI still requires `click`. A new extra `cli` was introduced to handle
  this dependency. Use the command `pip install shamir-mnemonic[cli]` to install the CLI
  dependencies along with the package.

Removed
~~~~~~~

- Removed dependency on `attrs`.

.. _0.3.0: https://github.com/trezor/python-shamir-mnemonic/compare/v0.2.2...v0.3.0


`0.2.2`_ - 2021-12-07
---------------------

Changed
~~~~~~~

- Relaxed Click constraint so that Click 8.x is allowed
- Applied `black` and `flake8` code style

.. _0.2.2: https://github.com/trezor/python-shamir-mnemonic/compare/v0.2.1...v0.2.2


`0.2.1`_ - 2021-02-03
---------------------

.. _0.2.1: https://github.com/trezor/python-shamir-mnemonic/compare/v0.1.0...v0.2.1

Fixed
~~~~~

- Re-released on the correct commit


`0.2.0`_ - 2021-02-03
---------------------

.. _0.2.0: https://github.com/trezor/python-shamir-mnemonic/compare/v0.1.0...v0.2.0

Added
~~~~~

- Introduce `split_ems` and `recover_ems` to separate password-based encryption from the Shamir Secret recovery
- Introduce classes representing a share and group-common parameters
- Introduce `RecoveryState` class that allows reusing the logic of the `shamir recover` command

Changed
~~~~~~~

- Use `secrets` module instead of `os.urandom`
- Refactor and restructure code into separate modules


0.1.0 - 2019-07-19
------------------

Added
~~~~~

- Initial implementation


.. _Keep a Changelog: https://keepachangelog.com/en/1.0.0/
.. _Semantic Versioning: https://semver.org/spec/v2.0.0.html
