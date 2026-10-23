from click.testing import CliRunner

import shamir_mnemonic as shamir
from shamir_mnemonic.cli import cli

MS = b"ABCDEFGHIJKLMNOP"


def test_create_non_ascii_passphrase():
    args = ["create", "single", "-S", MS.hex(), "-p", "café"]
    result = CliRunner().invoke(cli, args)
    assert result.exit_code == 1
    assert "Passphrase must be ASCII only" in result.output


def test_recover_non_ascii_passphrase():
    [[mnemonic]] = shamir.generate_mnemonics(1, [(1, 1)], MS, b"TREZOR")
    user_input = f"{mnemonic}\ncafé\ncafé\nTREZOR\nTREZOR\n"
    result = CliRunner().invoke(cli, ["recover", "-p"], input=user_input)
    assert result.exit_code == 0
    assert "Passphrase must be ASCII. Please try again." in result.output
    assert f"Your master secret is: {MS.hex()}" in result.output
