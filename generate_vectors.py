#!/usr/bin/env python3
import json
import random

from shamir_mnemonic import ShamirMnemonic


def random_bytes(n):
    return bytes(random.randrange(256) for _ in range(n))


if __name__ == "__main__":
    output = []
    shamir = ShamirMnemonic(random_bytes)
    random.seed(1337)

    for n in [16, 32]:
        # Valid mnemonic without sharing.
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(1, [(1, 1)], secret, b"TREZOR")
        output.append((groups[0], secret.hex()))

        # Mnemonic with invalid checksum.
        indices = list(shamir.mnemonic_to_indices(groups[0][0]))
        indices[-1] ^= 1
        mnemonic = shamir.mnemonic_from_indices(indices)
        output.append(([mnemonic], ""))

        # Mnemonic with invalid padding.
        overflowing_bits = (8 * n) % shamir.RADIX_BITS
        if overflowing_bits:
            indices = list(shamir.mnemonic_to_indices(groups[0][0]))
            indices[5] += 1 << overflowing_bits
            mnemonic = shamir.mnemonic_from_indices(indices)
            output.append(([mnemonic], ""))

        # Basic sharing 2-of-3.
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(1, [(2, 3)], secret, b"TREZOR", 2)
        output.append((random.sample(groups[0], 3), secret.hex()))
        output.append((random.sample(groups[0], 2), secret.hex()))
        output.append((random.sample(groups[0], 1), ""))

        # Mnemonics with different identifiers.
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[0] ^= 1  # modify the identifier
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output.append((mnemonics, ""))

        # Mnemonics with different iteration exponents.
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[1] = 3  # change iteration exponent from 0 to 3
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output.append((mnemonics, ""))

        # Mnemonics with mismatching group thresholds.
        groups = shamir.generate_mnemonics_random(2, [(1, 3), (2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][2]))
        data[3] = 1  # change group threshold from 2 to 1
        mnemonics = [shamir.encode_mnemonic(*data)] + groups[1]
        output.append((mnemonics, ""))

        # Mnemonics with mismatching member thresholds.
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[5] = 1  # change member threshold from 2 to 1
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output.append((mnemonics, ""))

        # Mnemonics giving an invalid digest.
        groups = shamir.generate_mnemonics_random(1, [(2, 2)])
        data = list(shamir.decode_mnemonic(groups[0][0]))
        data[6] = bytes((data[6][0] ^ 1,)) + data[6][1:]  # modify the share value
        mnemonics = [shamir.encode_mnemonic(*data), groups[0][1]]
        output.append((mnemonics, ""))

        # Group sharing.
        secret = random_bytes(n)
        groups = shamir.generate_mnemonics(
            2, [(1, 1), (1, 1), (3, 5), (2, 6)], secret, b"TREZOR"
        )

        # Insufficient number of groups.
        output.append(([groups[1][0]], ""))
        output.append((random.sample(groups[3], 2), ""))

        # Threshold number of groups, but insufficient number of members in one group.
        output.append(([groups[3][2], groups[1][0]], ""))

        # Threshold number of groups and members in each group.
        mnemonics = random.sample(groups[2], 3) + random.sample(groups[3], 2)
        random.shuffle(mnemonics)
        output.append((mnemonics, secret.hex()))
        output.append(([groups[1][0], groups[0][0]], secret.hex()))

        # All mnemonics.
        mnemonics = [mnemonic for group in groups for mnemonic in group]
        random.shuffle(mnemonics)
        output.append((mnemonics, secret.hex()))

    # Mnemonic with insufficient length.
    secret = random_bytes((shamir.MIN_STRENGTH_BITS // 8) - 2)
    identifier = random.randrange(1 << shamir.ID_LENGTH_BITS)
    mnemonic = shamir.encode_mnemonic(identifier, 0, 0, 1, 0, 1, secret)
    output.append(([mnemonic], ""))

    # Mnemonic with invalid length.
    secret = b"\xff" + random_bytes(shamir.MIN_STRENGTH_BITS // 8)
    identifier = random.randrange(1 << shamir.ID_LENGTH_BITS)
    mnemonic = shamir.encode_mnemonic(identifier, 0, 0, 1, 0, 1, secret)
    output.append(([mnemonic], ""))

    with open("vectors.json", "w") as f:
        json.dump(
            output,
            f,
            sort_keys=True,
            indent=2,
            separators=(",", ": "),
            ensure_ascii=False,
        )
