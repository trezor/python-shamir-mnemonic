from .utils import bits_to_words

RADIX_BITS = 10
"""The length of the radix in bits."""

RADIX = 2**RADIX_BITS
"""The number of words in the wordlist."""

ID_LENGTH_BITS = 15
"""The length of the random identifier in bits."""

EXTENDABLE_FLAG_LENGTH_BITS = 1
"""The length of the extendable backup flag in bits."""

ITERATION_EXP_LENGTH_BITS = 4
"""The length of the iteration exponent in bits."""

ID_EXP_LENGTH_WORDS = bits_to_words(
    ID_LENGTH_BITS + EXTENDABLE_FLAG_LENGTH_BITS + ITERATION_EXP_LENGTH_BITS
)
"""The length of the random identifier, extendable backup flag and iteration exponent in words."""

MAX_SHARE_COUNT = 16
"""The maximum number of shares that can be created."""

CHECKSUM_LENGTH_WORDS = 3
"""The length of the RS1024 checksum in words."""

DIGEST_LENGTH_BYTES = 4
"""The length of the digest of the shared secret in bytes."""

CUSTOMIZATION_STRING_ORIG = b"shamir"
"""The customization string used in the RS1024 checksum and in the PBKDF2 salt for
shares _without_ the extendable backup flag."""

CUSTOMIZATION_STRING_EXTENDABLE = b"shamir_extendable"
"""The customization string used in the RS1024 checksum for
shares _with_ the extendable backup flag."""

GROUP_PREFIX_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 1
"""The length of the prefix of the mnemonic that is common to a share group."""

METADATA_LENGTH_WORDS = ID_EXP_LENGTH_WORDS + 2 + CHECKSUM_LENGTH_WORDS
"""The length of the mnemonic in words without the share value."""

MIN_STRENGTH_BITS = 128
"""The minimum allowed entropy of the master secret."""

MIN_MNEMONIC_LENGTH_WORDS = METADATA_LENGTH_WORDS + bits_to_words(MIN_STRENGTH_BITS)
"""The minimum allowed length of the mnemonic in words."""

BASE_ITERATION_COUNT = 10000
"""The minimum number of iterations to use in PBKDF2."""

ROUND_COUNT = 4
"""The number of rounds to use in the Feistel cipher."""

SECRET_INDEX = 255
"""The index of the share containing the shared secret."""

DIGEST_INDEX = 254
"""The index of the share containing the digest of the shared secret."""
