#!/usr/bin/python3
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

import os
import hashlib
import math


class ConfigurationError(Exception):
    pass


class InterpolationError(Exception):
    pass


class MnemonicError(Exception):
    pass


class ShamirMnemonic(object):
    ID_LENGTH_WORDS = 2
    """The length of the random identifier in words."""

    RADIX_BITS = 10
    """The length of the radix in bits."""

    RADIX = 2 ** RADIX_BITS
    """The number of words in the wordlist."""

    MAX_SHARE_COUNT = 2 ** (RADIX_BITS // 2)
    """The maximum number of shares that can be created."""

    CHECKSUM_LENGTH_WORDS = 3
    """The length of the RS1024 checksum in words."""

    PMS_CHECKSUM_LENGTH_BYTES = 4
    """The length of the pre-master secret checksum in bytes."""

    CUSTOMIZATION_STRING = b"slip0039"
    """The customization string used in the RS1024 checksum and in the PBKDF2 salt."""

    METADATA_LENGTH_WORDS = ID_LENGTH_WORDS + 1 + CHECKSUM_LENGTH_WORDS
    """The length of the mnemonic in words without the share value."""

    MIN_STRENGTH_BITS = 128
    """The minimum allowed entropy of the master secret."""

    MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + math.ceil(
        MIN_STRENGTH_BITS / 10
    )
    """The minimum allowed length of the mnemonic in words."""

    ITERATION_COUNT = 20000
    """The total number of iterations to use in PBKDF2."""

    ROUND_COUNT = 4
    """The number of rounds to use in the Feistel cipher."""

    PMS_INDEX = 255
    """The index of the share containing the pre-master secret."""

    PMS_CHECKSUM_INDEX = 254
    """The index of the share containing the checksum of the pre-master secret."""

    def __init__(self):
        # Generate a table of discrete logarithms and exponents in GF(256) using the polynomial
        # x + 1 as the base.

        self.exp = [0 for i in range(255)]
        self.log = [0 for i in range(256)]

        poly = 1
        for i in range(255):
            self.exp[i] = poly
            self.log[poly] = i

            # Multiply poly by the polynomial x + 1.
            poly = (poly << 1) ^ poly

            # Reduce poly by x^8 + x^4 + x^3 + x + 1.
            if poly & 0x100:
                poly ^= 0x11B

        # Load the word list.

        with open(os.path.join(os.path.dirname(__file__), "wordlist.txt"), "r") as f:
            self.wordlist = [word.strip() for word in f.readlines()]

        if len(self.wordlist) != self.RADIX:
            raise ConfigurationError(
                "The wordlist should contain {} words, but it contains {} words.".format(
                    self.RADIX, len(self.wordlist)
                )
            )

        self.word_index_map = {word: i for i, word in enumerate(self.wordlist)}

    def _interpolate(self, shares, x, out_length=-1):
        """
        Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
        :param shares: The Shamir shares.
        :type shares: A list of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
            bytes representing the evaluations of the polynomials in x_i.
        :param int x: The x coordinate of the result.
        :param int out_length: The length of the result in bytes.
        :return: Evaluations of the polynomials in x.
        :rtype: Array of bytes.
        """

        x_coordinates = set(share[0] for share in shares)

        if len(x_coordinates) != len(shares):
            raise InterpolationError(
                "Invalid set of shares. Share indices must be unique."
            )

        share_value_lengths = set(len(share[1]) for share in shares)
        if len(share_value_lengths) != 1:
            raise InterpolationError(
                "Invalid set of shares. All share values must have the same length."
            )

        if x in x_coordinates:
            for share in shares:
                if share[0] == x:
                    return share[1]

        # Logarithm of the product of (x_i - x) for i = 1, ... , k.
        log_prod = sum(self.log[share[0] ^ x] for share in shares)

        result = bytes(share_value_lengths.pop() if out_length < 0 else out_length)
        for share in shares:
            # The logarithm of the Lagrange basis polynomial evaluated at x.
            log_basis_eval = (
                log_prod
                - self.log[share[0] ^ x]
                - sum(self.log[share[0] ^ other[0]] for other in shares)
            ) % 255

            result = bytes(
                intermediate_sum
                ^ (
                    self.exp[(self.log[share_val] + log_basis_eval) % 255]
                    if share_val != 0
                    else 0
                )
                for share_val, intermediate_sum in zip(share[1], result)
            )

        return result

    @classmethod
    def _rs1024_polymod(cls, values):
        GEN = (
            0xE0E040,
            0x1C1C080,
            0x3838100,
            0x7070200,
            0xE0E0009,
            0x1C0C2412,
            0x38086C24,
            0x3090FC48,
            0x21B1F890,
            0x3F3F120,
        )
        chk = 1
        for v in values:
            b = chk >> 20
            chk = (chk & 0xFFFFF) << 10 ^ v
            for i in range(10):
                chk ^= GEN[i] if ((b >> i) & 1) else 0
        return chk

    @classmethod
    def _rs1024_create_checksum(cls, data):
        values = (
            tuple(cls.CUSTOMIZATION_STRING) + data + cls.CHECKSUM_LENGTH_WORDS * (0,)
        )
        polymod = cls._rs1024_polymod(values) ^ 1
        return tuple(
            (polymod >> 10 * i) & 1023
            for i in reversed(range(cls.CHECKSUM_LENGTH_WORDS))
        )

    @classmethod
    def _rs1024_verify_checksum(cls, data):
        return cls._rs1024_polymod(tuple(cls.CUSTOMIZATION_STRING) + data) == 1

    @staticmethod
    def xor(a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    @classmethod
    def _round_function(cls, i, passphrase, salt, r):
        """The round function used internally by the Feistel cipher."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            bytes([i]) + passphrase,
            salt + r,
            cls.ITERATION_COUNT // cls.ROUND_COUNT,
            dklen=len(r),
        )

    @classmethod
    def _get_salt(cls, identifier):
        return cls.CUSTOMIZATION_STRING + bytes(
            b for i in identifier for b in (i >> 8, i & 0xFF)
        )

    @classmethod
    def _encrypt(cls, master_secret, passphrase, identifier):
        l = master_secret[: len(master_secret) // 2]
        r = master_secret[len(master_secret) // 2 :]
        salt = cls._get_salt(identifier)
        for i in range(cls.ROUND_COUNT):
            (l, r) = (r, cls.xor(l, cls._round_function(i, passphrase, salt, r)))
        return r + l

    @classmethod
    def _decrypt(cls, pre_master_secret, passphrase, identifier):
        l = pre_master_secret[: len(pre_master_secret) // 2]
        r = pre_master_secret[len(pre_master_secret) // 2 :]
        salt = cls._get_salt(identifier)
        for i in reversed(range(cls.ROUND_COUNT)):
            (l, r) = (r, cls.xor(l, cls._round_function(i, passphrase, salt, r)))
        return r + l

    @classmethod
    def _create_pms_checksum(cls, pre_master_secret):
        return hashlib.sha256(hashlib.sha256(pre_master_secret).digest()).digest()[
            : cls.PMS_CHECKSUM_LENGTH_BYTES
        ]

    def _generate_shares(
        self, threshold, share_count, pre_master_secret, starter_shares=[]
    ):
        assert 0 < threshold <= share_count <= self.MAX_SHARE_COUNT

        # If the threshold is 1, then the PMS checksum is not used.
        if threshold == 1:
            return [(i, pre_master_secret) for i in range(share_count)]

        random_share_count = threshold - 2 - len(starter_shares)
        assert random_share_count >= 0

        next_index = max((share[0] for share in starter_shares), default=-1) + 1
        max_share_count = self.MAX_SHARE_COUNT + len(starter_shares) - next_index
        if share_count > max_share_count:
            raise ValueError(
                "The requested number of shares ({}) must not exceed {}.".format(
                    share_count, max_share_count
                )
            )

        shares = [
            (next_index + i, os.urandom(len(pre_master_secret)))
            for i in range(random_share_count)
        ]

        pms_checksum = self._create_pms_checksum(pre_master_secret) + os.urandom(
            len(pre_master_secret) - self.PMS_CHECKSUM_LENGTH_BYTES
        )

        base_shares = (
            shares
            + list(starter_shares)
            + [
                (self.PMS_CHECKSUM_INDEX, pms_checksum),
                (self.PMS_INDEX, pre_master_secret),
            ]
        )

        for i in range(
            next_index + random_share_count,
            next_index + share_count - len(starter_shares),
        ):
            shares.append((i, self._interpolate(base_shares, i)))

        return shares

    def _combine_shares(self, shares, thresholds):
        pre_master_secret = self._interpolate(shares, self.PMS_INDEX)

        # If the threshold is 1, then the PMS checksum is not used.
        if thresholds != {1}:
            pms_checksum = self._interpolate(
                shares, self.PMS_CHECKSUM_INDEX, self.PMS_CHECKSUM_LENGTH_BYTES
            )

            if pms_checksum != self._create_pms_checksum(pre_master_secret):
                if len(shares) < min(thresholds):
                    raise MnemonicError(
                        "Insufficient number of mnemonics. The required number of mnemonics is {}.".format(
                            " or ".join(str(i) for i in sorted(thresholds))
                        )
                    )
                else:
                    raise MnemonicError(
                        "Invalid pre-master secret checksum. The required number of mnemonics is {}.".format(
                            " or ".join(str(i) for i in sorted(thresholds))
                        )
                    )

        return pre_master_secret

    def _encode_mnemonic(self, identifier, threshold, index, value):
        """
        Converts share data to a share mnemonic.
        :param identifier: The random identifier.
        :type identifier: A tuple of integers in the range 0, ... , RADIX - 1.
        :param int threshold: The threshold value.
        :param int index: The x coordinate of the share.
        :param value: The share value representing the y coordinates of the share.
        :type value: Array of bytes.
        :return: The share mnemonic.
        :rtype: Array of bytes.
        """

        # Convert the share value from bytes to wordlist indices.
        value_word_count = math.ceil(len(value) * 8 / self.RADIX_BITS)
        value_int = int.from_bytes(value, "big")
        value_data = tuple(
            (value_int >> (i * self.RADIX_BITS)) % self.RADIX
            for i in reversed(range(value_word_count))
        )

        share_data = (
            identifier + ((threshold - 1) * self.MAX_SHARE_COUNT + index,) + value_data
        )
        checksum = self._rs1024_create_checksum(share_data)

        return " ".join(self.wordlist[i] for i in share_data + checksum)

    def _decode_mnemonic(self, mnemonic):
        """Converts a share mnemonic to share data."""

        try:
            mnemonic_data = tuple(
                self.word_index_map[word.lower()] for word in mnemonic.split()
            )
        except KeyError as key_error:
            raise MnemonicError("Invalid mnemonic word {}.".format(key_error)) from None

        if len(mnemonic_data) < self.MIN_MNEMONIC_LENGTH_WORDS:
            raise MnemonicError(
                "Invalid mnemonic length. The length of each mnemonic must be at least {} words.".format(
                    self.MIN_MNEMONIC_LENGTH_WORDS
                )
            )

        if (len(mnemonic_data) - self.METADATA_LENGTH_WORDS) % 8 not in (0, 2, 4, 5, 7):
            raise MnemonicError("Invalid mnemonic length.")

        if not self._rs1024_verify_checksum(mnemonic_data):
            raise MnemonicError(
                'Invalid mnemonic checksum for "{} ...".'.format(
                    " ".join(mnemonic.split()[: self.ID_LENGTH_WORDS + 1])
                )
            )

        identifier = mnemonic_data[: self.ID_LENGTH_WORDS]
        index = mnemonic_data[self.ID_LENGTH_WORDS] % self.MAX_SHARE_COUNT
        threshold = (mnemonic_data[self.ID_LENGTH_WORDS] // self.MAX_SHARE_COUNT) + 1
        value_data = mnemonic_data[
            self.ID_LENGTH_WORDS + 1 : -self.CHECKSUM_LENGTH_WORDS
        ]

        # The length of the master secret in bytes is required to be even, so find the largest even
        # integer, which is less than or equal to value_word_count * 10 / 8.
        value_byte_count = 2 * math.floor(len(value_data) * 5 / 8)

        value_int = 0
        for i in value_data:
            value_int = value_int * self.RADIX + i

        try:
            value = value_int.to_bytes(value_byte_count, "big")
        except OverflowError:
            raise MnemonicError("Invalid mnemonic padding.") from None

        return identifier, threshold, index, value

    def _decode_mnemonics(self, mnemonics):
        identifiers = set()
        thresholds = set()
        shares = set()
        for mnemonic in mnemonics:
            identifier, threshold, index, share_value = self._decode_mnemonic(mnemonic)
            identifiers.add(identifier)
            thresholds.add(threshold)
            shares.add((index, share_value))

        if len(identifiers) != 1:
            raise MnemonicError(
                "Invalid set of mnemonics. All mnemonics must begin with the same {} words.".format(
                    self.ID_LENGTH_WORDS
                )
            )

        return identifiers.pop(), thresholds, shares

    @classmethod
    def _generate_random_identifier(cls):
        """Returns a tuple of randomly generated integers in the range 0, ... , RADIX - 1."""

        identifier_int = int.from_bytes(
            os.urandom(math.ceil(cls.ID_LENGTH_WORDS * cls.RADIX_BITS / 8)), "big"
        )
        return tuple(
            (identifier_int >> (i * cls.RADIX_BITS)) % cls.RADIX
            for i in range(cls.ID_LENGTH_WORDS)
        )

    def generate_mnemonics(
        self,
        threshold,
        share_count,
        master_secret,
        passphrase=b"",
        starter_mnemonics=[],
    ):
        """
        Splits a master secret into mnemonic shares using Shamir's secret sharing scheme.
        :param int threshold: The number of shares that will be required to reconstruct the master
            secret.
        :param int share_count: The number of shares to generate.
        :param master_secret: The master secret to split.
        :type master_secret: Array of bytes.
        :param passphrase: The passphrase used to encrypt the master secret.
        :type passphrase: Array of bytes.
        :param starter_mnemonics: List of existing mnemonics to extend.
        :type starter_mnemonics: List of byte arrays.
        :return: List of mnemonics.
        :rtype: List of byte arrays.
        """

        if starter_mnemonics:
            identifier, _, starter_shares = self._decode_mnemonics(starter_mnemonics)
            min_threshold = len(starter_shares) + 2
        else:
            identifier = self._generate_random_identifier()
            starter_shares = []
            min_threshold = 1

        if len(master_secret) * 8 < self.MIN_STRENGTH_BITS:
            raise ValueError(
                "The length of the master secret ({} bytes) must be at least {} bytes.".format(
                    len(master_secret), math.ceil(self.MIN_STRENGTH_BITS / 8)
                )
            )

        if len(master_secret) % 2 != 0:
            raise ValueError(
                "The length of the master secret in bytes must be an even number."
            )

        if threshold > share_count:
            raise ValueError(
                "The requested threshold ({}) must not exceed the number of shares ({}).".format(
                    threshold, share_count
                )
            )

        if threshold < min_threshold:
            raise ValueError(
                "The requested threshold ({}) must be at least {}.".format(
                    threshold, min_threshold
                )
            )

        pre_master_secret = self._encrypt(master_secret, passphrase, identifier)
        shares = self._generate_shares(
            threshold, share_count, pre_master_secret, starter_shares
        )

        return [
            self._encode_mnemonic(identifier, threshold, index, value)
            for index, value in shares
        ]

    def generate_mnemonics_random(
        self, threshold, share_count, strength_bits=128, passphrase=b""
    ):
        """
        Generates a random master secret and splits it into mnemonic shares using Shamir's secret
        sharing scheme.
        :param int threshold: The number of shares that will be required to reconstruct the master
            secret.
        :param int share_count: The number of shares to generate.
        :param int strength_bits: The entropy of the randomly generated master secret in bits.
        :param passphrase: The passphrase used to encrypt the master secret.
        :type passphrase: Array of bytes.
        :return: List of mnemonics.
        :rtype: List of byte arrays.
        """

        if len(master_secret) * 8 < self.MIN_STRENGTH_BITS:
            raise ValueError(
                "The requested strength of the master secret ({} bits) must be at least {} bits.".format(
                    strength_bits, self.MIN_STRENGTH_BITS
                )
            )

        if strength_bits % 16 != 0:
            raise ValueError(
                "The requested strength of the master secret ({} bits) must be a multiple of 16 bits.".format(
                    strength_bits
                )
            )

        return self.generate_mnemonics(
            threshold, share_count, os.urandom(strength_bits // 8), passphrase
        )

    def combine_mnemonics(self, mnemonics, passphrase=b""):
        """
        Combines mnemonic shares to obtain the master secret which was previously split using
        Shamir's secret sharing scheme.
        :param mnemonics: List of mnemonics.
        :type mnemonics: List of byte arrays.
        :param passphrase: The passphrase used to encrypt the master secret.
        :type passphrase: Array of bytes.
        :return: The master secret.
        :rtype: Array of bytes.
        """

        if not mnemonics:
            raise MnemonicError("The list of mnemonics is empty.")

        identifier, thresholds, shares = self._decode_mnemonics(mnemonics)

        return self._decrypt(
            self._combine_shares(shares, thresholds), passphrase, identifier
        )
