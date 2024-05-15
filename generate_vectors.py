#!/usr/bin/env python3
import json
import random
from dataclasses import astuple

from bip32utils import BIP32Key

from shamir_mnemonic import constants, rs1024, shamir, wordlist
from shamir_mnemonic.share import Share


def random_bytes(n):
    return bytes(random.randrange(256) for _ in range(n))


def output(description, mnemonics, secret):
    output.i += 1
    xprv = BIP32Key.fromEntropy(secret).ExtendedKey() if secret else ""
    output.data.append((f"{output.i}. {description}", mnemonics, secret.hex(), xprv))


def encode_mnemonic(*args):
    return Share(*args).mnemonic()


def decode_mnemonic(mnemonic):
    return list(astuple(Share.from_mnemonic(mnemonic)))


def generate_mnemonics_random(group_threshold, groups):
    secret = random_bytes(16)
    return shamir.generate_mnemonics(
        group_threshold, groups, secret, extendable=False, iteration_exponent=0
    )


output.i = 0
output.data = []

shamir.RANDOM_BYTES = random_bytes

if __name__ == "__main__":
    random.seed(1337)

    for n in [16, 32]:
        description = "Valid mnemonic without sharing ({} bits)"
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            1, [(1, 1)], secret, b"TREZOR", extendable=False, iteration_exponent=0
        )
        output(description.format(8 * n), groups[0], secret)

        description = "Mnemonic with invalid checksum ({} bits)"
        indices = wordlist.mnemonic_to_indices(groups[0][0])
        indices[-1] ^= 1
        mnemonic = wordlist.mnemonic_from_indices(indices)
        output(description.format(8 * n), [mnemonic], b"")

        description = "Mnemonic with invalid padding ({} bits)"
        overflowing_bits = (8 * n) % constants.RADIX_BITS
        if overflowing_bits:
            indices = wordlist.mnemonic_to_indices(groups[0][0])
            indices[4] += 1 << overflowing_bits
            indices = indices[: -constants.CHECKSUM_LENGTH_WORDS]
            mnemonic = wordlist.mnemonic_from_indices(
                indices
                + rs1024.create_checksum(indices, constants.CUSTOMIZATION_STRING_ORIG)
            )
            output(description.format(8 * n), [mnemonic], b"")

        description = "Basic sharing 2-of-3 ({} bits)"
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            1, [(2, 3)], secret, b"TREZOR", extendable=False, iteration_exponent=2
        )
        output(description.format(8 * n), random.sample(groups[0], 2), secret)
        output(description.format(8 * n), random.sample(groups[0], 1), b"")

        description = "Mnemonics with different identifiers ({} bits)"
        groups = generate_mnemonics_random(1, [(2, 2)])
        data = decode_mnemonic(groups[0][0])
        data[0] ^= 1  # modify the identifier
        mnemonics = [encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with different iteration exponents ({} bits)"
        groups = generate_mnemonics_random(1, [(2, 2)])
        data = decode_mnemonic(groups[0][0])
        data[2] = 3  # change iteration exponent from 0 to 3
        mnemonics = [encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with mismatching group thresholds ({} bits)"
        groups = generate_mnemonics_random(2, [(1, 1), (2, 2)])
        data = decode_mnemonic(groups[0][0])
        data[4] = 1  # change group threshold from 2 to 1
        mnemonics = groups[1] + [encode_mnemonic(*data)]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with mismatching group counts ({} bits)"
        groups = generate_mnemonics_random(1, [(2, 2)])
        data = decode_mnemonic(groups[0][0])
        data[5] = 3  # change group count from 1 to 3
        mnemonics = [encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = (
            "Mnemonics with greater group threshold than group counts ({} bits)"
        )
        groups = generate_mnemonics_random(2, [(2, 2), (1, 1)])
        mnemonics = []
        for group in groups:
            for mnemonic in group:
                data = decode_mnemonic(mnemonic)
                data[5] = 1  # change group count from 2 to 1
                mnemonics.append(encode_mnemonic(*data))
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with duplicate member indices ({} bits)"
        groups = generate_mnemonics_random(1, [(2, 3)])
        data = decode_mnemonic(groups[0][0])
        data[6] = 2  # change member index from 0 to 2
        mnemonics = [encode_mnemonic(*data), groups[0][2]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with mismatching member thresholds ({} bits)"
        groups = generate_mnemonics_random(1, [(2, 2)])
        data = decode_mnemonic(groups[0][0])
        data[7] = 1  # change member threshold from 2 to 1
        mnemonics = [encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics giving an invalid digest ({} bits)"
        groups = generate_mnemonics_random(1, [(2, 2)])
        data = decode_mnemonic(groups[0][0])
        data[8] = bytes((data[8][0] ^ 1,)) + data[8][1:]  # modify the share value
        mnemonics = [encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        # Group sharing.
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            2,
            [(1, 1), (1, 1), (3, 5), (2, 6)],
            secret,
            b"TREZOR",
            extendable=False,
            iteration_exponent=0,
        )

        description = "Insufficient number of groups ({} bits, case {})"
        output(description.format(8 * n, 1), [groups[1][0]], b"")
        output(description.format(8 * n, 2), random.sample(groups[3], 2), b"")

        description = "Threshold number of groups, but insufficient number of members in one group ({} bits)"
        output(description.format(8 * n), [groups[3][2], groups[1][0]], b"")

        description = (
            "Threshold number of groups and members in each group ({} bits, case {})"
        )
        mnemonics = random.sample(groups[2], 3) + random.sample(groups[3], 2)
        random.shuffle(mnemonics)
        output(description.format(8 * n, 1), mnemonics, secret)

        mnemonics = groups[1] + random.sample(groups[3], 2)
        random.shuffle(mnemonics)
        output(description.format(8 * n, 2), mnemonics, secret)

        output(description.format(8 * n, 3), [groups[1][0], groups[0][0]], secret)

    description = "Mnemonic with insufficient length"
    secret = random_bytes((shamir.MIN_STRENGTH_BITS // 8) - 2)
    identifier = random.randrange(1 << shamir.ID_LENGTH_BITS)
    mnemonic = encode_mnemonic(identifier, False, 0, 0, 1, 1, 0, 1, secret)
    output(description, [mnemonic], b"")

    description = "Mnemonic with invalid master secret length"
    secret = b"\xff" + random_bytes(shamir.MIN_STRENGTH_BITS // 8)
    identifier = random.randrange(1 << shamir.ID_LENGTH_BITS)
    mnemonic = encode_mnemonic(identifier, False, 0, 0, 1, 1, 0, 1, secret)
    output(description, [mnemonic], b"")

    description = "Valid mnemonics which can detect some errors in modular arithmetic"
    secret = b"\xado*\xd8\xb5\x9b\xbb\xaa\x016\x9b\x90\x06 \x8d\x9a"
    mnemonics = [
        "herald flea academic cage avoid space trend estate dryer hairy evoke eyebrow improve airline artwork garlic premium duration prevent oven",
        "herald flea academic client blue skunk class goat luxury deny presence impulse graduate clay join blanket bulge survive dish necklace",
        "herald flea academic acne advance fused brother frozen broken game ranked ajar already believe check install theory angry exercise adult",
    ]
    output(description, mnemonics, secret)

    for n in [16, 32]:
        description = "Valid extendable mnemonic without sharing ({} bits)"
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            1, [(1, 1)], secret, b"TREZOR", extendable=True, iteration_exponent=3
        )
        output(description.format(8 * n), groups[0], secret)

        description = "Extendable basic sharing 2-of-3 ({} bits)"
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            1, [(2, 3)], secret, b"TREZOR", extendable=True, iteration_exponent=0
        )
        output(description.format(8 * n), random.sample(groups[0], 2), secret)

    with open("vectors.json", "w") as f:
        json.dump(
            output.data,
            f,
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
            ensure_ascii=False,
        )
