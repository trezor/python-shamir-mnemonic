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


def test_create_invalid_iteration_exponents():
    for exponent in [-1, 16, 32, 256]:
        result = CliRunner().invoke(cli, ["create", "single", "-E", str(exponent)])
        assert result.exit_code != 0
        assert "The iteration exponent must be between 0 and 15." in result.output


def test_create_strength_too_low():
    for strength in [-16, 0, 112]:
        result = CliRunner().invoke(cli, ["create", "single", "-s", str(strength)])
        assert result.exit_code != 0
        assert "master secret must be at least 128 bits." in result.output


def test_create_strength_not_multiple_of_16():
    for strength in [-8, 136, 257]:
        result = CliRunner().invoke(cli, ["create", "single", "-s", str(strength)])
        assert result.exit_code != 0
        assert "Secret strength must be a multiple of 16 bits." in result.output


def test_create_strength():
    for strength in [128, 144, 256]:
        result = CliRunner().invoke(cli, ["create", "single", "-s", str(strength)])
        assert result.exit_code == 0
        secret_hex = result.output.splitlines()[0].removeprefix("Using master secret: ")
        assert len(bytes.fromhex(secret_hex)) * 8 == strength


def test_create_invalid_master_secret_length():
    for length, error in [
        (0, "master secret must be at least 128 bits."),
        (14, "master secret must be at least 128 bits."),
        (17, "master secret in bytes must be an even number."),
    ]:
        result = CliRunner().invoke(cli, ["create", "single", "-S", "00" * length])
        assert result.exit_code != 0
        assert error in result.output
