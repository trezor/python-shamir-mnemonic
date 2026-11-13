import functools
import json
import operator
import secrets
from itertools import combinations
from random import shuffle

import pytest
from bip32utils import BIP32Key

import shamir_mnemonic as shamir
from shamir_mnemonic import MnemonicError
from shamir_mnemonic.constants import ID_LENGTH_BITS, ITERATION_EXP_LENGTH_BITS

MS = b"ABCDEFGHIJKLMNOP"


def test_basic_sharing_random():
    secret = secrets.token_bytes(16)
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], secret)[0]
    assert shamir.combine_mnemonics(mnemonics[:3]) == shamir.combine_mnemonics(
        mnemonics[2:]
    )


def test_basic_sharing_fixed():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[:3])
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[1:3])


def test_passphrase():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_non_extendable():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, extendable=False)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])


def test_iteration_exponent():
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=1
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=2
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_group_sharing():
    group_threshold = 2
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for groups in combinations(zip(mnemonics, member_thresholds), group_threshold):
        for group1_subset in combinations(groups[0][0], groups[0][1]):
            for group2_subset in combinations(groups[1][0], groups[1][1]):
                mnemonic_subset = list(group1_subset + group2_subset)
                shuffle(mnemonic_subset)
                assert MS == shamir.combine_mnemonics(mnemonic_subset)

    # Minimal sets of mnemonics.
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][0], mnemonics[2][2], mnemonics[3][0]]
    )
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][3], mnemonics[3][0], mnemonics[2][4]]
    )

    # One complete group and one incomplete group out of two groups required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics([*mnemonics[0][2:], mnemonics[1][0]])

    # One group of two required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][1:4])


def test_group_sharing_threshold_1():
    group_threshold = 1
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for group, member_threshold in zip(mnemonics, member_thresholds):
        for group_subset in combinations(group, member_threshold):
            mnemonic_subset = list(group_subset)
            shuffle(mnemonic_subset)
            assert MS == shamir.combine_mnemonics(mnemonic_subset)


def test_all_groups_exist():
    for group_threshold in (1, 2, 5):
        mnemonics = shamir.generate_mnemonics(
            group_threshold, [(3, 5), (1, 1), (2, 3), (2, 5), (3, 5)], MS
        )
        assert len(mnemonics) == 5
        assert len(functools.reduce(operator.iadd, mnemonics, [])) == 19


def test_invalid_sharing():
    # Short master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS[:14])

    # Odd length master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS + b"X")

    # Group threshold exceeds number of groups.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(3, [(3, 5), (2, 5)], MS)

    # Invalid group threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(0, [(3, 5), (2, 5)], MS)

    # Member threshold exceeds number of members.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 2), (2, 5)], MS)

    # Invalid member threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(0, 2), (2, 5)], MS)

    # Group with multiple members and member threshold 1.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 5), (1, 3), (2, 5)], MS)


def test_vectors():
    with open("vectors.json") as f:
        vectors = json.load(f)
    for description, mnemonics, secret_hex, xprv in vectors:
        if secret_hex:
            secret = bytes.fromhex(secret_hex)
            assert secret == shamir.combine_mnemonics(mnemonics, b"TREZOR"), (
                f'Incorrect secret for test vector "{description}".'
            )
            assert BIP32Key.fromEntropy(secret).ExtendedKey() == xprv, (
                f'Incorrect xprv for test vector "{description}".'
            )
        else:
            with pytest.raises(MnemonicError):
                shamir.combine_mnemonics(mnemonics)
                pytest.fail(
                    f'Failed to raise exception for test vector "{description}".'
                )


def test_split_ems():
    encrypted_master_secret = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"TREZOR", identifier=42, extendable=True, iteration_exponent=1
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], encrypted_master_secret)
    mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    recovered = shamir.combine_mnemonics(mnemonics[:3], b"TREZOR")
    assert recovered == MS


def test_non_ascii_passphrase():
    passphrase = "café".encode()
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(3, 5)], MS, passphrase)
    with pytest.raises(ValueError):
        shamir.EncryptedMasterSecret.from_master_secret(
            MS, passphrase, identifier=42, extendable=True, iteration_exponent=1
        )
    with pytest.raises(ValueError):
        shamir.encrypt(MS, passphrase, 1, 42, True)


def test_recover_non_ascii_passphrase():
    # Made by version 0.3.0 with EncryptedMasterSecret.from_master_secret and
    # split_ems, which accepted the passphrase "café".
    mnemonic = (
        "acid fawn academic academic company fridge picture cage pecan glance "
        "privacy carpet should public pharmacy eclipse percent python together flavor"
    )
    assert shamir.combine_mnemonics([mnemonic], "café".encode()) == MS


def test_recover_ems():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]

    groups = shamir.decode_mnemonics(mnemonics[:3])
    encrypted_master_secret = shamir.recover_ems(groups)
    recovered = encrypted_master_secret.decrypt(b"TREZOR")
    assert recovered == MS


def test_repr_hides_secret():
    encrypted_master_secret = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier=42, extendable=True, iteration_exponent=1
    )
    assert repr(encrypted_master_secret.ciphertext) not in repr(encrypted_master_secret)

    share = shamir.split_ems(1, [(3, 5)], encrypted_master_secret)[0][0]
    assert repr(share.value) not in repr(share)


@pytest.mark.parametrize("exponent", [-1, 16, 32, 256])
def test_invalid_iteration_exponent_rejected_before_encryption(monkeypatch, exponent):
    def unexpected_round(*args):
        pytest.fail("Invalid exponent reached the expensive key derivation")

    monkeypatch.setattr(shamir.cipher, "_round_function", unexpected_round)
    with pytest.raises(ValueError, match=r"iteration exponent.*0.*15"):
        shamir.generate_mnemonics(1, [(1, 1)], MS, iteration_exponent=exponent)


@pytest.mark.parametrize("extendable", [False, True])
@pytest.mark.parametrize("exponent", [0, 1, 15])
def test_iteration_exponent_metadata_boundaries(monkeypatch, extendable, exponent):
    # Metadata boundary coverage only: keep the high valid exponent inexpensive.
    # Existing round-trip and vector tests exercise the real encryption function.
    monkeypatch.setattr(
        shamir.cipher, "_round_function", lambda *args: bytes(len(MS) // 2)
    )
    [[mnemonic]] = shamir.generate_mnemonics(
        1, [(1, 1)], MS, extendable=extendable, iteration_exponent=exponent
    )
    share = shamir.Share.from_mnemonic(mnemonic)
    assert share.iteration_exponent == exponent
    assert share.extendable is extendable
    assert shamir.combine_mnemonics([mnemonic]) == MS


@pytest.mark.parametrize(
    ("identifier", "iteration_exponent", "error"),
    [
        (-1, 0, "identifier"),
        (2**ID_LENGTH_BITS, 0, "identifier"),
        (0, -1, "iteration exponent"),
        (0, 2**ITERATION_EXP_LENGTH_BITS, "iteration exponent"),
    ],
)
def test_split_ems_rejects_out_of_range_metadata(identifier, iteration_exponent, error):
    ems = shamir.EncryptedMasterSecret(identifier, True, iteration_exponent, bytes(16))
    with pytest.raises(ValueError, match=error):
        shamir.split_ems(1, [(1, 1)], ems)
