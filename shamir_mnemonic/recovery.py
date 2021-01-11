from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import attr

from .constants import GROUP_PREFIX_LENGTH_WORDS
from .shamir import combine_mnemonics
from .share import Share, ShareSetParameters
from .utils import MnemonicError

UNDETERMINED = -1


class RecoveryState:
    """Object for keeping track of running Shamir recovery."""

    def __init__(self) -> None:
        self.all_shares: List[Share] = []
        self.groups: Dict[int, Set[Share]] = defaultdict(set)
        self.parameters: Optional[ShareSetParameters] = None

    def group_prefix(self, group_index: int) -> str:
        """Return three starting words of a given group."""
        if not self.all_shares:
            raise RuntimeError("Add at least one share first")

        some_share = self.all_shares[0]
        fake_share = attr.evolve(some_share, group_index=group_index)
        return " ".join(fake_share.words()[:GROUP_PREFIX_LENGTH_WORDS])

    def group_status(self, group_index: int) -> Tuple[int, int]:
        """Return completion status of given group.

        Result consists of the number of shares already entered, and the threshold
        for recovering the group.
        """
        group = self.groups[group_index]
        if not group:
            return 0, UNDETERMINED

        share = next(iter(group))
        return len(group), share.threshold

    def group_is_complete(self, group_index: int) -> bool:
        """Check whether a given group is already complete."""
        shares, threshold = self.group_status(group_index)
        if threshold == UNDETERMINED:
            return False
        return shares >= threshold

    def groups_complete(self) -> int:
        """Return the number of groups that are already complete."""
        if self.parameters is None:
            return 0

        return sum(
            self.group_is_complete(i) for i in range(self.parameters.group_count)
        )

    def is_complete(self) -> bool:
        """Check whether the recovery set is complete.

        That is, at least M groups must be complete, where M is the global threshold.
        """
        if self.parameters is None:
            return False
        return self.groups_complete() >= self.parameters.group_threshold

    def matches(self, share: Share) -> bool:
        """Check whether the provided share matches the current set, i.e., has the same
        common parameters.
        """
        if self.parameters is None:
            return True
        return share.common_parameters() == self.parameters

    def add_share(self, share: Share) -> bool:
        """Add a share to the recovery set."""
        if not self.matches(share):
            raise MnemonicError(
                "This mnemonic is not part of the current set. Please try again."
            )
        self.groups[share.group_index].add(share)
        self.all_shares.append(share)
        if self.parameters is None:
            self.parameters = share.common_parameters()
        return True

    def __contains__(self, obj: Any) -> bool:
        if not isinstance(obj, Share):
            return False

        if not self.matches(obj):
            return False

        if not self.groups:
            return False

        return obj in self.groups[obj.group_index]

    def recover(self, passphrase: bytes) -> bytes:
        """Recover the master secret, given a passphrase."""
        all_mnemonics = [" ".join(share.words()) for share in self.all_shares]
        return combine_mnemonics(all_mnemonics, passphrase)
