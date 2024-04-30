Changelog
=========

.. default-role:: code

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog`_, and this project adheres to
`Semantic Versioning`_.

`Unreleased`_
-------------

- Added BIP32 master extended private key to test vectors.

.. _Unreleased: https://github.com/trezor/python-shamir-mnemonic/compare/v0.2.2...HEAD


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

- Introduce `slip_ems` and `recover_ems` to separate password-based encryption from the Shamir Secret recovery
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
