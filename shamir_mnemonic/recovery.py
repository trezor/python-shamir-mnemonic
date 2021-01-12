from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import attr

from .constants import GROUP_PREFIX_LENGTH_WORDS
from .shamir import ShareGroup, recover_ems
from .share import Share, ShareSetParameters
from .utils import MnemonicError

UNDETERMINED = -1


class RecoveryState:
    """Object for keeping track of running Shamir recovery."""

    def __init__(self) -> None:
        self.last_share: Optional[Share] = None
        self.groups: Dict[int, ShareGroup] = defaultdict(ShareGroup)
        self.parameters: Optional[ShareSetParameters] = None

    def group_prefix(self, group_index: int) -> str:
        """Return three starting words of a given group."""
        if not self.last_share:
            raise RuntimeError("Add at least one share first")

        fake_share = attr.evolve(self.last_share, group_index=group_index)
        return " ".join(fake_share.words()[:GROUP_PREFIX_LENGTH_WORDS])

    def group_status(self, group_index: int) -> Tuple[int, int]:
        """Return completion status of given group.

        Result consists of the number of shares already entered, and the threshold
        for recovering the group.
        """
        group = self.groups[group_index]
        if not group:
            return 0, UNDETERMINED

        return len(group), group.member_threshold()

    def group_is_complete(self, group_index: int) -> bool:
        """Check whether a given group is already complete."""
        return self.groups[group_index].is_complete()

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
        if self.is_complete():
            raise MnemonicError("The recovery set is already complete.")
        if not self.matches(share):
            raise MnemonicError(
                "This mnemonic is not part of the current set. Please try again."
            )
        group = self.groups[share.group_index]
        if group.is_complete():
            prefix = " ".join(share.words()[:GROUP_PREFIX_LENGTH_WORDS])
            raise MnemonicError(
                f'The group of mnemonics starting with "{prefix} ..." is already complete.'
            )
        group.add(share)
        self.last_share = share
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
        # Use only groups that meet the member threshold.
        groups = {
            group_index: group
            for group_index, group in self.groups.items()
            if group.is_complete()
        }
        encrypted_master_secret = recover_ems(groups)
        return encrypted_master_secret.decrypt(passphrase)
