from dataclasses import dataclass
from typing import Iterable, List, NamedTuple

from . import rs1024, wordlist
from .constants import (
    CUSTOMIZATION_STRING_EXTENDABLE,
    CUSTOMIZATION_STRING_ORIG,
    EXTENDABLE_FLAG_LENGTH_BITS,
    ID_EXP_LENGTH_WORDS,
    ITERATION_EXP_LENGTH_BITS,
    METADATA_LENGTH_WORDS,
    MIN_MNEMONIC_LENGTH_WORDS,
    RADIX,
    RADIX_BITS,
)
from .utils import MnemonicError, bits_to_bytes, bits_to_words, int_to_indices

WordIndex = int


def _int_to_word_indices(value: int, length: int) -> List[WordIndex]:
    """Converts an integer value to a list of base 1024 indices in big endian order."""
    return list(int_to_indices(value, length, radix_bits=RADIX_BITS))


def _int_from_word_indices(indices: Iterable[WordIndex]) -> int:
    """Converts a list of base 1024 indices in big endian order to an integer value."""
    value = 0
    for index in indices:
        value = value * RADIX + index
    return value


def _customization_string(extendable: bool) -> bytes:
    if extendable:
        return CUSTOMIZATION_STRING_EXTENDABLE
    else:
        return CUSTOMIZATION_STRING_ORIG


class ShareCommonParameters(NamedTuple):
    """Parameters that are common to all shares of a master secret."""

    identifier: int
    extendable: bool
    iteration_exponent: int
    group_threshold: int
    group_count: int


class ShareGroupParameters(NamedTuple):
    """Parameters that are common to all shares of a master secret, which belong to the same group."""

    identifier: int
    extendable: bool
    iteration_exponent: int
    group_index: int
    group_threshold: int
    group_count: int
    member_threshold: int


@dataclass(frozen=True)
class Share:
    """Represents a single mnemonic share and its metadata"""

    identifier: int
    extendable: bool
    iteration_exponent: int
    group_index: int
    group_threshold: int
    group_count: int
    index: int
    member_threshold: int
    value: bytes

    def common_parameters(self) -> ShareCommonParameters:
        """Return values that uniquely identify a matching set of shares."""
        return ShareCommonParameters(
            self.identifier,
            self.extendable,
            self.iteration_exponent,
            self.group_threshold,
            self.group_count,
        )

    def group_parameters(self) -> ShareGroupParameters:
        """Return values that uniquely identify shares belonging to the same group."""
        return ShareGroupParameters(
            self.identifier,
            self.extendable,
            self.iteration_exponent,
            self.group_index,
            self.group_threshold,
            self.group_count,
            self.member_threshold,
        )

    def _encode_id_exp(self) -> List[WordIndex]:
        id_exp_int = self.identifier << (
            ITERATION_EXP_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS
        )
        id_exp_int += self.extendable << ITERATION_EXP_LENGTH_BITS
        id_exp_int += self.iteration_exponent
        return _int_to_word_indices(id_exp_int, ID_EXP_LENGTH_WORDS)

    def _encode_share_params(self) -> List[WordIndex]:
        # each value is 4 bits, for 20 bits total
        val = self.group_index
        val <<= 4
        val += self.group_threshold - 1
        val <<= 4
        val += self.group_count - 1
        val <<= 4
        val += self.index
        val <<= 4
        val += self.member_threshold - 1
        # group parameters are 2 words
        return _int_to_word_indices(val, 2)

    def words(self) -> List[str]:
        """Convert share data to a share mnemonic."""

        value_word_count = bits_to_words(len(self.value) * 8)
        value_int = int.from_bytes(self.value, "big")
        value_data = _int_to_word_indices(value_int, value_word_count)

        share_data = self._encode_id_exp() + self._encode_share_params() + value_data
        checksum = rs1024.create_checksum(
            share_data, _customization_string(self.extendable)
        )

        return list(wordlist.words_from_indices(share_data + checksum))

    def mnemonic(self) -> str:
        """Convert share data to a share mnemonic."""
        return " ".join(self.words())

    def __str__(self) -> str:
        return self.mnemonic()

    @classmethod
    def from_mnemonic(cls, mnemonic: str) -> "Share":
        """Convert a share mnemonic to share data."""

        mnemonic_data = wordlist.mnemonic_to_indices(mnemonic)

        if len(mnemonic_data) < MIN_MNEMONIC_LENGTH_WORDS:
            raise MnemonicError(
                "Invalid mnemonic length. The length of each mnemonic "
                f"must be at least {MIN_MNEMONIC_LENGTH_WORDS} words."
            )

        padding_len = (RADIX_BITS * (len(mnemonic_data) - METADATA_LENGTH_WORDS)) % 16
        if padding_len > 8:
            raise MnemonicError("Invalid mnemonic length.")

        id_exp_data = mnemonic_data[:ID_EXP_LENGTH_WORDS]
        id_exp_int = _int_from_word_indices(id_exp_data)

        identifier = id_exp_int >> (
            EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS
        )
        extendable = bool((id_exp_int >> ITERATION_EXP_LENGTH_BITS) & 1)
        iteration_exponent = id_exp_int & ((1 << ITERATION_EXP_LENGTH_BITS) - 1)

        if not rs1024.verify_checksum(mnemonic_data, _customization_string(extendable)):
            raise MnemonicError(
                'Invalid mnemonic checksum for "{} ...".'.format(
                    " ".join(mnemonic.split()[: ID_EXP_LENGTH_WORDS + 2])
                )
            )

        share_params_data = mnemonic_data[ID_EXP_LENGTH_WORDS : ID_EXP_LENGTH_WORDS + 2]
        share_params_int = _int_from_word_indices(share_params_data)
        share_params = int_to_indices(share_params_int, 5, 4)
        (
            group_index,
            group_threshold,
            group_count,
            index,
            member_threshold,
        ) = share_params

        if group_count < group_threshold:
            raise MnemonicError(
                'Invalid mnemonic "{} ...". Group threshold cannot be greater than group count.'.format(
                    " ".join(mnemonic.split()[: ID_EXP_LENGTH_WORDS + 2])
                )
            )

        value_data = mnemonic_data[
            ID_EXP_LENGTH_WORDS + 2 : -rs1024.CHECKSUM_LENGTH_WORDS
        ]
        value_byte_count = bits_to_bytes(RADIX_BITS * len(value_data) - padding_len)
        value_int = _int_from_word_indices(value_data)
        try:
            value = value_int.to_bytes(value_byte_count, "big")
        except OverflowError:
            raise MnemonicError(
                'Invalid mnemonic padding for "{} ...".'.format(
                    " ".join(mnemonic.split()[: ID_EXP_LENGTH_WORDS + 2])
                )
            ) from None

        return cls(
            identifier,
            extendable,
            iteration_exponent,
            group_index,
            group_threshold + 1,
            group_count + 1,
            index,
            member_threshold + 1,
            value,
        )
