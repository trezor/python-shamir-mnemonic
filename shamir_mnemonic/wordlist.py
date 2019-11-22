import os.path
from typing import Dict, Iterable, List, Sequence, Tuple

from .constants import RADIX
from .utils import MnemonicError


def _load_wordlist() -> Tuple[List[str], Dict[str, int]]:
    with open(os.path.join(os.path.dirname(__file__), "wordlist.txt"), "r") as f:
        wordlist = [word.strip() for word in f]

    if len(wordlist) != RADIX:
        raise ImportError(
            f"The wordlist should contain {RADIX} words, but it contains {len(wordlist)} words."
        )

    word_index_map = {word: i for i, word in enumerate(wordlist)}

    return wordlist, word_index_map


WORDLIST, WORD_INDEX_MAP = _load_wordlist()


def words_from_indices(indices: Iterable[int]) -> Iterable[str]:
    return (WORDLIST[i] for i in indices)


def mnemonic_from_indices(indices: Iterable[int]) -> str:
    return " ".join(words_from_indices(indices))


def mnemonic_to_indices(mnemonic: str) -> Sequence[int]:
    try:
        return [WORD_INDEX_MAP[word.lower()] for word in mnemonic.split()]
    except KeyError as key_error:
        raise MnemonicError(f"Invalid mnemonic word {key_error}.") from None
