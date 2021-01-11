#
# Copyright (c) 2018 Andrew R. Kozlik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import hmac
import secrets
from typing import Dict, Iterable, List, NamedTuple, Sequence, Set, Tuple

from . import cipher
from .constants import (
    DIGEST_INDEX,
    DIGEST_LENGTH_BYTES,
    GROUP_PREFIX_LENGTH_WORDS,
    ID_EXP_LENGTH_WORDS,
    ID_LENGTH_BITS,
    MAX_SHARE_COUNT,
    MIN_STRENGTH_BITS,
    SECRET_INDEX,
)
from .share import Share, ShareSetParameters
from .utils import MnemonicError, bits_to_bytes


class RawShare(NamedTuple):
    idx: int
    data: bytes


class ShamirGroup(NamedTuple):
    threshold: int
    shares: Set[Share]

    def to_raw_shares(self) -> List[RawShare]:
        return [RawShare(s.index, s.value) for s in self.shares]


RANDOM_BYTES = secrets.token_bytes
"""Source of random bytes. Can be overriden for deterministic testing."""


def _precompute_exp_log() -> Tuple[List[int], List[int]]:
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]

    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i

        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly

        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log


EXP_TABLE, LOG_TABLE = _precompute_exp_log()


def _interpolate(shares: Sequence[RawShare], x: int) -> bytes:
    """
    Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
    :param shares: The Shamir shares.
    :type shares: A list of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
        bytes representing the evaluations of the polynomials in x_i.
    :param int x: The x coordinate of the result.
    :return: Evaluations of the polynomials in x.
    :rtype: Array of bytes.
    """

    x_coordinates = set(share[0] for share in shares)

    if len(x_coordinates) != len(shares):
        raise MnemonicError("Invalid set of shares. Share indices must be unique.")

    share_value_lengths = set(len(share[1]) for share in shares)
    if len(share_value_lengths) != 1:
        raise MnemonicError(
            "Invalid set of shares. All share values must have the same length."
        )

    if x in x_coordinates:
        for share in shares:
            if share[0] == x:
                return share[1]

    # Logarithm of the product of (x_i - x) for i = 1, ... , k.
    log_prod = sum(LOG_TABLE[share[0] ^ x] for share in shares)

    result = bytes(share_value_lengths.pop())
    for share in shares:
        # The logarithm of the Lagrange basis polynomial evaluated at x.
        log_basis_eval = (
            log_prod
            - LOG_TABLE[share[0] ^ x]
            - sum(LOG_TABLE[share[0] ^ other[0]] for other in shares)
        ) % 255

        result = bytes(
            intermediate_sum
            ^ (
                EXP_TABLE[(LOG_TABLE[share_val] + log_basis_eval) % 255]
                if share_val != 0
                else 0
            )
            for share_val, intermediate_sum in zip(share[1], result)
        )

    return result


def _create_digest(random_data: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(random_data, shared_secret, "sha256").digest()[:DIGEST_LENGTH_BYTES]


def _split_secret(
    threshold: int, share_count: int, shared_secret: bytes
) -> List[RawShare]:
    if threshold < 1:
        raise ValueError("The requested threshold must be a positive integer.")

    if threshold > share_count:
        raise ValueError(
            "The requested threshold must not exceed the number of shares."
        )

    if share_count > MAX_SHARE_COUNT:
        raise ValueError(
            f"The requested number of shares must not exceed {MAX_SHARE_COUNT}."
        )

    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return [RawShare(i, shared_secret) for i in range(share_count)]

    random_share_count = threshold - 2

    shares = [
        RawShare(i, RANDOM_BYTES(len(shared_secret))) for i in range(random_share_count)
    ]

    random_part = RANDOM_BYTES(len(shared_secret) - DIGEST_LENGTH_BYTES)
    digest = _create_digest(random_part, shared_secret)

    base_shares = shares + [
        RawShare(DIGEST_INDEX, digest + random_part),
        RawShare(SECRET_INDEX, shared_secret),
    ]

    for i in range(random_share_count, share_count):
        shares.append(RawShare(i, _interpolate(base_shares, i)))

    return shares


def _recover_secret(threshold: int, shares: Sequence[RawShare]) -> bytes:
    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return next(iter(shares))[1]

    shared_secret = _interpolate(shares, SECRET_INDEX)
    digest_share = _interpolate(shares, DIGEST_INDEX)
    digest = digest_share[:DIGEST_LENGTH_BYTES]
    random_part = digest_share[DIGEST_LENGTH_BYTES:]

    if digest != _create_digest(random_part, shared_secret):
        raise MnemonicError("Invalid digest of the shared secret.")

    return shared_secret


def _decode_mnemonics(
    mnemonics: Iterable[str],
) -> Tuple[ShareSetParameters, Dict[int, ShamirGroup]]:
    all_group_params = set()
    groups: Dict[int, ShamirGroup] = {}
    for mnemonic in mnemonics:
        share = Share.from_mnemonic(mnemonic)
        all_group_params.add(share.common_parameters())
        group = groups.setdefault(
            share.group_index, ShamirGroup(share.threshold, set())
        )
        if group.threshold != share.threshold:
            raise MnemonicError(
                "Invalid set of mnemonics. All mnemonics in a group must have "
                "the same member threshold."
            )
        group.shares.add(share)

    if len(all_group_params) != 1:
        raise MnemonicError(
            "Invalid set of mnemonics. "
            f"All mnemonics must begin with the same {ID_EXP_LENGTH_WORDS} words, "
            "must have the same group threshold and the same group count."
        )

    return all_group_params.pop(), groups


def split_ems(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    identifier: int,
    iteration_exponent: int,
    encrypted_master_secret: bytes,
) -> List[List[str]]:
    """
    Split an Encrypted Master Secret into mnemonic shares.

    This function is a counterpart to `recover_ems`, and it is used as a subroutine in
    `generate_mnemonics`. The input is an *already encrypted* Master Secret (EMS), so it
    is possible to encrypt the Master Secret in advance and perform the splitting later.

    Decryption of the MS depends on the identifier and iteration exponent, so the same
    values used for `cipher.encrypt` must also be used here. Otherwise it will be
    impossible to recover the original MS from the generated shares.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param identifier: The identifier used when encrypting the master secret.
    :param iteration_exponent: The encryption iteration exponent.
    :param encrypted_master_secret: The encrypted master secret to split.
    :return: List of groups of mnemonics.
    """
    if len(encrypted_master_secret) * 8 < MIN_STRENGTH_BITS:
        raise ValueError(
            "The length of the master secret must be "
            f"at least {bits_to_bytes(MIN_STRENGTH_BITS)} bytes."
        )

    if group_threshold > len(groups):
        raise ValueError(
            "The requested group threshold must not exceed the number of groups."
        )

    if any(
        member_threshold == 1 and member_count > 1
        for member_threshold, member_count in groups
    ):
        raise ValueError(
            "Creating multiple member shares with member threshold 1 is not allowed. "
            "Use 1-of-1 member sharing instead."
        )

    group_shares = _split_secret(group_threshold, len(groups), encrypted_master_secret)

    return [
        [
            Share(
                identifier,
                iteration_exponent,
                group_index,
                group_threshold,
                len(groups),
                member_index,
                member_threshold,
                value,
            ).mnemonic()
            for member_index, value in _split_secret(
                member_threshold, member_count, group_secret
            )
        ]
        for (member_threshold, member_count), (group_index, group_secret) in zip(
            groups, group_shares
        )
    ]


def _random_identifier() -> int:
    """Returns a random identifier with the given bit length."""
    identifier = int.from_bytes(RANDOM_BYTES(bits_to_bytes(ID_LENGTH_BITS)), "big")
    return identifier & ((1 << ID_LENGTH_BITS) - 1)


def generate_mnemonics(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    master_secret: bytes,
    passphrase: bytes = b"",
    iteration_exponent: int = 1,
) -> List[List[str]]:
    """
    Split a master secret into mnemonic shares using Shamir's secret sharing scheme.

    The supplied Master Secret is encrypted by the passphrase (empty passphrase is used
    if none is provided) and split into a set of mnemonic shares.

    This is the user-friendly method to back up a pre-existing secret with the Shamir
    scheme, optionally protected by a passphrase.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param master_secret: The master secret to split.
    :param passphrase: The passphrase used to encrypt the master secret.
    :param int iteration_exponent: The encryption iteration exponent.
    :return: List of groups mnemonics.
    """
    if not all(32 <= c <= 126 for c in passphrase):
        raise ValueError(
            "The passphrase must contain only printable ASCII characters (code points 32-126)."
        )

    identifier = _random_identifier()
    encrypted_master_secret = cipher.encrypt(
        master_secret, passphrase, iteration_exponent, identifier
    )

    return split_ems(
        group_threshold, groups, identifier, iteration_exponent, encrypted_master_secret
    )


def recover_ems(mnemonics: Iterable[str]) -> Tuple[int, int, bytes]:
    """
    Combine mnemonic shares, recover metadata and the Encrypted Master Secret.

    This function is a counterpart to `split_ems`, and it is used as a subroutine in
    `combine_mnemonics`. It returns the EMS itself and data required for its decryption,
    except for the passphrase. It is thus possible to defer decryption of the Master
    Secret to a later time.

    :param mnemonics: List of mnemonics.
    :return: Identifier, iteration exponent, and Encrypted Master Secret
    """

    if not mnemonics:
        raise MnemonicError("The list of mnemonics is empty.")

    params, groups = _decode_mnemonics(mnemonics)

    if len(groups) < params.group_threshold:
        raise MnemonicError(
            "Insufficient number of mnemonic groups. "
            f"The required number of groups is {params.group_threshold}."
        )

    if len(groups) != params.group_threshold:
        raise MnemonicError(
            "Wrong number of mnemonic groups. "
            f"Expected {params.group_threshold} groups, "
            f"but {len(groups)} were provided."
        )

    for threshold, shares in groups.values():
        if len(shares) != threshold:
            share_words = next(iter(shares)).words()
            prefix = " ".join(share_words[:GROUP_PREFIX_LENGTH_WORDS])
            raise MnemonicError(
                "Wrong number of mnemonics. "
                f'Expected {threshold} mnemonics starting with "{prefix} ...", '
                f"but {len(shares)} were provided."
            )

    group_shares = [
        RawShare(group_index, _recover_secret(group.threshold, group.to_raw_shares()))
        for group_index, group in groups.items()
    ]

    encrypted_master_secret = _recover_secret(params.group_threshold, group_shares)
    return params.identifier, params.iteration_exponent, encrypted_master_secret


def combine_mnemonics(mnemonics: Iterable[str], passphrase: bytes = b"") -> bytes:
    """
    Combine mnemonic shares to obtain the master secret which was previously split
    using Shamir's secret sharing scheme.

    This is the user-friendly method to recover a backed-up secret optionally protected
    by a passphrase.

    :param mnemonics: List of mnemonics.
    :param passphrase: The passphrase used to encrypt the master secret.
    :return: The master secret.
    """

    if not mnemonics:
        raise MnemonicError("The list of mnemonics is empty.")

    identifier, iteration_exponent, encrypted_master_secret = recover_ems(mnemonics)
    return cipher.decrypt(
        encrypted_master_secret,
        passphrase,
        iteration_exponent,
        identifier,
    )
