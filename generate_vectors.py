#!/usr/bin/env python3
import json
import random

import shamir_mnemonic as shamir


def random_bytes(n):
    return bytes(random.randrange(256) for _ in range(n))


def output(description, mnemonics, secret):
    output.i += 1
    output.data.append(("{}. {}".format(output.i, description), mnemonics, secret.hex()))


output.i = 0
output.data = []

shamir.RANDOM_BYTES = random_bytes

if __name__ == "__main__":
    random.seed(1337)

    for n in [16, 32]:
        description = "Valid mnemonic without sharing ({} bits)"
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(1, [(1, 1)], secret, b"TREZOR")
        output(description.format(8 * n), groups[0], secret)

        description = "Mnemonic with invalid checksum ({} bits)"
        indices = list(shamir.mnemonic_to_indices(groups[0][0]))
        indices[-1] ^= 1
        mnemonic = shamir.mnemonic_from_indices(indices)
        output(description.format(8 * n), [mnemonic], b"")

        description = "Mnemonic with invalid padding ({} bits)"
        overflowing_bits = (8 * n) % shamir.RADIX_BITS
        if overflowing_bits:
            indices = list(shamir.mnemonic_to_indices(groups[0][0]))
            indices[4] += 1 << overflowing_bits
            indices = tuple(indices[: -shamir.CHECKSUM_LENGTH_WORDS])
            mnemonic = shamir.mnemonic_from_indices(
                indices + shamir.rs1024_create_checksum(indices)
            )
            output(description.format(8 * n), [mnemonic], b"")

        description = "Basic sharing 2-of-3 ({} bits)"
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(1, [(2, 3)], secret, b"TREZOR", 2)
        output(description.format(8 * n), random.sample(groups[0], 2), secret)
        output(description.format(8 * n), random.sample(groups[0], 1), b"")

        description = "Mnemonics with different identifiers ({} bits)"
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[0] ^= 1  # modify the identifier
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with different iteration exponents ({} bits)"
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[1] = 3  # change iteration exponent from 0 to 3
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with mismatching group thresholds ({} bits)"
        groups = shamir.generate_mnemonics_random(2, [(1, 1), (2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[3] = 1  # change group threshold from 2 to 1
        mnemonics = groups[1] + [shamir.encode_mnemonic(*data)]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with mismatching group counts ({} bits)"
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[4] = 3  # change group count from 1 to 3
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = (
            "Mnemonics with greater group threshold than group counts ({} bits)"
        )
        groups = shamir.generate_mnemonics_random(2, [(2, 2), (1, 1)])
        mnemonics = []
        for group in groups:
            for mnemonic in group:
                data = list(shamir.decode_mnemonic(mnemonic))
                data[4] = 1  # change group count from 2 to 1
                mnemonics.append(shamir.encode_mnemonic(*data))
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with duplicate member indices ({} bits)"
        groups = shamir.generate_mnemonics_random(1, [(2, 3)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[5] = 2  # change member index from 0 to 2
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][2]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics with mismatching member thresholds ({} bits)"
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[6] = 1  # change member threshold from 2 to 1
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        description = "Mnemonics giving an invalid digest ({} bits)"
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[7] = bytes((data[7][0] ^ 1,)) + data[7][1:]  # modify the share value
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output(description.format(8 * n), mnemonics, b"")

        # Group sharing.
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            2, [(1, 1), (1, 1), (3, 5), (2, 6)], secret, b"TREZOR"
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
    mnemonic = shamir.encode_mnemonic(identifier, 0, 0, 1, 1, 0, 1, secret)
    output(description, [mnemonic], b"")

    description = "Mnemonic with invalid master secret length"
    secret = b"\xff" + random_bytes(shamir.MIN_STRENGTH_BITS // 8)
    identifier = random.randrange(1 << shamir.ID_LENGTH_BITS)
    mnemonic = shamir.encode_mnemonic(identifier, 0, 0, 1, 1, 0, 1, secret)
    output(description, [mnemonic], b"")

    with open("vectors.json", "w") as f:
        json.dump(
            output.data,
            f,
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
            ensure_ascii=False,
        )
