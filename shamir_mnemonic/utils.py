from typing import Iterable


class MnemonicError(Exception):
    pass


def _round_bits(n: int, radix_bits: int) -> int:
    """Get the number of `radix_bits`-sized digits required to store a `n`-bit value."""
    return (n + radix_bits - 1) // radix_bits


def bits_to_bytes(n: int) -> int:
    """Round up bit count to whole bytes."""
    return _round_bits(n, 8)


def bits_to_words(n: int) -> int:
    """Round up bit count to a multiple of word size."""
    # XXX
    # In order to properly functionally decompose the original 1-file implementation,
    # function bits_to_words can only exist if it knows the value of RADIX_BITS (which
    # informs us of the word size). However, constants.py make use of the function,
    # because some constants count word-size of things.
    #
    # I considered the "least evil" solution to define bits_to_words in utils where it
    # logically belongs, and import constants only inside the function. This will work
    # as long as calls to bits_to_words only happens *after* RADIX_BITS are declared.
    #
    # An alternative is to have a private implementation of bits_to_words in constants
    from . import constants

    assert hasattr(constants, "RADIX_BITS"), "Declare RADIX_BITS *before* calling this"

    return _round_bits(n, constants.RADIX_BITS)


def int_to_indices(value: int, length: int, radix_bits: int) -> Iterable[int]:
    """Convert an integer value to indices in big endian order."""
    mask = (1 << radix_bits) - 1
    return ((value >> (i * radix_bits)) & mask for i in reversed(range(length)))
