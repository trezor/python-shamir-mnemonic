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

import hmac
import itertools
import secrets
from dataclasses import dataclass
from typing import (
    Any,
    Collection,
    Dict,
    Generator,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from . import cipher
from .constants import (
    DIGEST_INDEX,
    DIGEST_LENGTH_BYTES,
    GROUP_PREFIX_LENGTH_WORDS,
    ID_EXP_LENGTH_WORDS,
    ID_LENGTH_BITS,
    MAX_SHARE_COUNT,
    MIN_STRENGTH_BITS,
    SECRET_INDEX,
)
from .share import Share, ShareCommonParameters, ShareGroupParameters
from .utils import MnemonicError, bits_to_bytes


class RawShare(NamedTuple):
    x: int
    data: bytes


class ShareGroup:
    def __init__(self) -> None:
        self.shares: Set[Share] = set()

    def __iter__(self) -> Iterator[Share]:
        return iter(self.shares)

    def __len__(self) -> int:
        return len(self.shares)

    def __bool__(self) -> bool:
        return bool(self.shares)

    def __contains__(self, obj: Any) -> bool:
        return obj in self.shares

    def add(self, share: Share) -> None:
        if self.shares and self.group_parameters() != share.group_parameters():
            fields = zip(
                ShareGroupParameters._fields,
                self.group_parameters(),
                share.group_parameters(),
            )
            mismatch = next(name for name, x, y in fields if x != y)
            raise MnemonicError(
                f"Invalid set of mnemonics. The {mismatch} parameters don't match."
            )

        self.shares.add(share)

    def to_raw_shares(self) -> List[RawShare]:
        return [RawShare(s.index, s.value) for s in self.shares]

    def get_minimal_group(self) -> "ShareGroup":
        return next(self.get_possible_groups())

    def get_possible_groups(self) -> Iterator["ShareGroup"]:
        """Return successive member_threshold length groups of indices into the available shares.
        If the shares are all valid, each group of mnemonics would be equivalent and sufficient to
        use in recovery.  But, if any mnemonic(s) are corrupted we need to avoid using them.

        """
        if not self.is_complete():
            raise MnemonicError(
                f"Incomplete group of mnemonics; {len(self.shares)} provided of {self.member_threshold()} required."
            )
        shares = list(self.shares)
        for combo in itertools.combinations(
            range(len(shares)), self.member_threshold()
        ):
            group = ShareGroup()
            group.shares = set(shares[i] for i in combo)
            yield group

    def common_parameters(self) -> ShareCommonParameters:
        return next(iter(self.shares)).common_parameters()

    def group_parameters(self) -> ShareGroupParameters:
        return next(iter(self.shares)).group_parameters()

    def member_threshold(self) -> int:
        return next(iter(self.shares)).member_threshold

    def is_complete(self) -> bool:
        if self.shares:
            return len(self.shares) >= self.member_threshold()
        else:
            return False


@dataclass(frozen=True)
class EncryptedMasterSecret:
    identifier: int
    extendable: bool
    iteration_exponent: int
    ciphertext: bytes

    @classmethod
    def from_master_secret(
        cls,
        master_secret: bytes,
        passphrase: bytes,
        identifier: int,
        extendable: bool,
        iteration_exponent: int,
    ) -> "EncryptedMasterSecret":
        ciphertext = cipher.encrypt(
            master_secret, passphrase, iteration_exponent, identifier, extendable
        )
        return EncryptedMasterSecret(
            identifier, extendable, iteration_exponent, ciphertext
        )

    def decrypt(self, passphrase: bytes) -> bytes:
        return cipher.decrypt(
            self.ciphertext,
            passphrase,
            self.iteration_exponent,
            self.identifier,
            self.extendable,
        )


RANDOM_BYTES = secrets.token_bytes
"""Source of random bytes. Can be overriden for deterministic testing."""


def _precompute_exp_log() -> Tuple[List[int], List[int]]:
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]

    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i

        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly

        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log


EXP_TABLE, LOG_TABLE = _precompute_exp_log()


def _interpolate(shares: Collection[RawShare], x: int) -> bytes:
    """
    Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
    :param shares: The Shamir shares.
    :type shares: A collection of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
        bytes representing the evaluations of the polynomials in x_i.
    :param int x: The x coordinate of the result.
    :return: Evaluations of the polynomials in x.
    :rtype: Array of bytes.
    """

    x_coordinates = set(share.x for share in shares)

    if len(x_coordinates) != len(shares):
        raise MnemonicError("Invalid set of shares. Share indices must be unique.")

    share_value_lengths = set(len(share.data) for share in shares)
    if len(share_value_lengths) != 1:
        raise MnemonicError(
            "Invalid set of shares. All share values must have the same length."
        )

    if x in x_coordinates:
        for share in shares:
            if share.x == x:
                return share.data

    # Logarithm of the product of (x_i - x) for i = 1, ... , k.
    log_prod = sum(LOG_TABLE[share.x ^ x] for share in shares)

    result = bytes(share_value_lengths.pop())
    for share in shares:
        # The logarithm of the Lagrange basis polynomial evaluated at x.
        log_basis_eval = (
            log_prod
            - LOG_TABLE[share.x ^ x]
            - sum(LOG_TABLE[share.x ^ other.x] for other in shares)
        ) % 255

        result = bytes(
            intermediate_sum
            ^ (
                EXP_TABLE[(LOG_TABLE[share_val] + log_basis_eval) % 255]
                if share_val != 0
                else 0
            )
            for share_val, intermediate_sum in zip(share.data, result)
        )

    return result


def _create_digest(random_data: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(random_data, shared_secret, "sha256").digest()[:DIGEST_LENGTH_BYTES]


def _split_secret(
    threshold: int, share_count: int, shared_secret: bytes
) -> List[RawShare]:
    if threshold < 1:
        raise ValueError("The requested threshold must be a positive integer.")

    if threshold > share_count:
        raise ValueError(
            "The requested threshold must not exceed the number of shares."
        )

    if share_count > MAX_SHARE_COUNT:
        raise ValueError(
            f"The requested number of shares must not exceed {MAX_SHARE_COUNT}."
        )

    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return [RawShare(i, shared_secret) for i in range(share_count)]

    random_share_count = threshold - 2

    shares = [
        RawShare(i, RANDOM_BYTES(len(shared_secret))) for i in range(random_share_count)
    ]

    random_part = RANDOM_BYTES(len(shared_secret) - DIGEST_LENGTH_BYTES)
    digest = _create_digest(random_part, shared_secret)

    base_shares = shares + [
        RawShare(DIGEST_INDEX, digest + random_part),
        RawShare(SECRET_INDEX, shared_secret),
    ]

    for i in range(random_share_count, share_count):
        shares.append(RawShare(i, _interpolate(base_shares, i)))

    return shares


def _recover_secret(threshold: int, shares: Collection[RawShare]) -> bytes:
    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return next(iter(shares)).data

    shared_secret = _interpolate(shares, SECRET_INDEX)
    digest_share = _interpolate(shares, DIGEST_INDEX)
    digest = digest_share[:DIGEST_LENGTH_BYTES]
    random_part = digest_share[DIGEST_LENGTH_BYTES:]

    if digest != _create_digest(random_part, shared_secret):
        raise MnemonicError("Invalid digest of the shared secret.")

    return shared_secret


def _recover_secret_rawshares(
    threshold: int, share_count: int, shares: Collection[RawShare]
) -> Sequence[RawShare]:
    """In addition to just the secret and its digest, we can recover all of a secret's original
    RawShares, that were used to produce its derived Shares.  This is the inverse of _split_secret.

    This allows us to regenerate missing Shares, or even expand a group's member Shares while
    retaining compatibility with the existing Shares.

    """
    shared_secret = _recover_secret(threshold, shares)  # verifies the digest
    digest_share = _interpolate(shares, DIGEST_INDEX)
    if threshold < 2 or len(shares) < threshold or share_count < threshold:
        raise MnemonicError(
            f"Cannot recover original group RawShares for group threshold {threshold} of {share_count} with {len(shares)} provided"
        )
    random_share_count = threshold - 2
    shares = [RawShare(i, _interpolate(shares, i)) for i in range(random_share_count)]
    base_shares = shares + [
        RawShare(SECRET_INDEX, shared_secret),
        RawShare(DIGEST_INDEX, digest_share),
    ]
    return shares + [
        RawShare(i, _interpolate(base_shares, i))
        for i in range(random_share_count, share_count)
    ]


def locate_ems_rawshares(
    distinct: ShareCommonParameters,
    possibles: Dict[int, Dict[RawShare, ShareGroup]],
    complete: bool = False,
) -> Generator[Tuple[EncryptedMasterSecret, Dict[RawShare, ShareGroup]], None, None]:
    """We have the available group indices w/ decoded RawShares secrets x(any w/ more than 1
    constitutent Share has been validated against its digest).  Produce the cartesian product of
    groups g0, g1, ..., gN, to see if we can recover any EncryptedMasterSecrets.  The possibles: {x:
    -> {RawGroup: ShareGroup}} gives us a sequence of RawGroup(s) for group index x.

    This would (inefficiently) find all combinations of available mnemonics that could be
    combined to recover any EncryptedMasterSecret -- but, the caller /should/ remove one/all
    used RawShares from possibles before re-invoking to find further EncryptedSharedSecrets
    to avoid re-trying with RawGroups that are already known to be used by another
    EncryptedMasterSecret.

    Mutates the supplied 'possibles' to remove one/all RawShares: ShareGroup to support desired
    level of 'complete'.  If the caller re-invokes (instead of just consuming all Combinations and
    Cartesian Products, which would yield all possible paths to obtaining each EMS), it can optimize
    the process of locating all available EMSs.

    """

    for subgroups in itertools.combinations(
        sorted(possibles), distinct.group_threshold
    ):
        for rawshares in itertools.product(*(possibles[gn].keys() for gn in subgroups)):
            try:
                ems = EncryptedMasterSecret(
                    distinct.identifier,
                    distinct.extendable,
                    distinct.iteration_exponent,
                    _recover_secret(distinct.group_threshold, rawshares),
                )
                using: Dict[RawShare, ShareGroup] = {}
                for rawshare in rawshares:
                    # always pops at least one
                    if complete and using:
                        using[rawshare] = possibles[rawshare.x][rawshare]
                    else:
                        using[rawshare] = possibles[rawshare.x].pop(rawshare)
                yield ems, using
            except MnemonicError:
                pass


def group_common_mnemonics(
    mnemonics: Iterable[Union[str, Share]],
    strict: bool = False,
) -> Dict[ShareCommonParameters, Dict[ShareGroupParameters, ShareGroup]]:
    """Eliminate any obviously flawed Mnemonics, group by distinct common, then group parameters."""
    common_params: Dict[
        ShareCommonParameters, Dict[ShareGroupParameters, ShareGroup]
    ] = {}
    for share in mnemonics:
        try:
            if isinstance(share, str):
                share = Share.from_mnemonic(share)
            distinct = share.common_parameters()
            grouping = share.group_parameters()
        except Exception:
            # If something is awry with any supplied Mnemonic, ignore it unless 'strict'
            if strict:
                raise
        else:
            # We will cluster mnemonic shares by distinct common_parameters, then grouping by
            # group_parameters.  This allows us to combine shares from original, extendable (or even
            # expanded additional mnemonics for a group_index generated later), and attempt to
            # recover seeds from mixed incompatible SLIP-39 groups.
            common_params.setdefault(
                # Incompatible SLIP-39 configuration groups, by:
                # - identifier
                # - extendable
                # - iteration_exponent
                # - group_threshold
                # - group_count
                distinct,
                {},
            ).setdefault(
                # Possible compatible mnemonics within a SLIP-39 configuration, by common_parameters plus:
                # - group_index
                # - member_threshold
                grouping,
                ShareGroup(),
            ).add(
                share
            )
    return common_params


def recover_group_rawshares(
    sharegroups: Dict[ShareGroupParameters, ShareGroup],
    complete: bool = False,
) -> Dict[int, Dict[RawShare, ShareGroup]]:
    """Recovers all available SLIP-39 group RawShares, optionally collecting the 'complete' set of
    provided Shares belonging to the ShareGroup used to recover the group's RawShare secret.
    Ignores invalid, incomplete or otherwise unusable Shares provided.  Produces a dict keyed by all
    deduced group RawShare x coordinates, to a dict keyed by all recovered RawShares for each group
    x coordinate, mapped to the ShareGroup of Shares used to recover it.  These RawShares may
    represent 1 or more SLIP-39 encoded EncryptedMasterSecrets.

    Go through each of the available groups, identifying all available recoverable group secrets,
    and all mnemonics provided that comprise each.  Once a subset of mnemonics is used, discard
    one/all of them and see if the same or any other secrets are recoverable; multiple different (or
    decoy) SLIP-39 groups w/ the same common parameters could have been provided, and/or redundant
    mnemonics.

    """
    possibles: Dict[int, Dict[RawShare, ShareGroup]] = {}
    for grouping, sharegroup in sharegroups.items():
        while sharegroup.is_complete():
            for shareminimal in sharegroup.get_possible_groups():
                try:
                    rawshare = RawShare(
                        grouping.group_index,
                        _recover_secret(
                            grouping.member_threshold, shareminimal.to_raw_shares()
                        ),
                    )
                except Exception:
                    pass
                else:
                    # We found (another?) minimal ShareGroup subset of sharegroup that leads to
                    # a RawShare.
                    group = possibles.setdefault(
                        # by SLIP-39 group indices
                        rawshare.x,
                        {},
                    ).setdefault(
                        # by recovered group RawShare
                        rawshare,
                        shareminimal,
                    )
                    # Each time, remove one of its consituent mnemonic Shares, and continue
                    # looking to ensure 'complete' coverage; this will (eventually) find *all*
                    # mnemonic Shares that combine to yield each RawShare.
                    group.shares |= shareminimal.shares
                    if complete:
                        sharegroup.shares.remove(next(iter(shareminimal.shares)))
                    else:
                        sharegroup.shares -= shareminimal.shares
                    break
            else:
                # No RawShare ever found in all possible combinations of this grouping!  Give up.
                break
    return possibles


def group_ems_rawshares(
    mnemonics: Iterable[Union[str, Share]],
    strict: bool = False,  # Fail if any Share is found to be invalid
    complete: bool = False,  # Find all related Shares, Groups instead of minimal
) -> Generator[
    Tuple[
        Tuple[EncryptedMasterSecret, ShareCommonParameters], Dict[RawShare, ShareGroup]
    ],
    None,
    None,
]:
    """Attempt to yield a sequence of uniquely decoded EncryptedMasterSecrets and their SLIP-39
    encoding parameters, and the dictionary of group indices -> set(<Share>) used to recover each
    SLIP-39 encoded encrypted seed.  Remember, the same EncryptedMasterSecret may have been encoded
    with muliple different SLIP-39 encodings.

    This is difficult to do externally, because it requires partially decoding the mnemonics to
    deduce the group parameters, and then select a subset of the mnemonics to satisfy them.

    Since extra mnemonics (some perhaps with errors) may be supplied, we may need to produce
    combinations of Shares until we've eliminated the erroneous one(s).  Then, if someone mistakenly
    collects groups of incompatible mnemonics (for example, with the same identifier and group
    numbers, but from a different original master secret, or from an attacker supplying decoy
    mnenonics), we'll supply all cartesion products of all possible combinations of the available
    compatible shares to aid recovery of the master secret(s).

    Even if groups of mnemonics from multiple SLIP-39 encodings are collected, aid the caller in
    recovery of any/all of them.

    Ignores invalid Mnemonics and absence of a recovered secret unless strict is specified.

    """

    # Once we have isolated the distinct share groups, it's time to see what we can recover.  How
    # many different Mnemonic sets are we possibly dealing with?  In addition to identifier, we have
    # group count, extendable, etc.  Allow multiple independent sets of mnemonics.  Our task is to
    # support the user in recovering their master seeds, however many they may have, or however the
    # mnemonics may have been mixed.  Try every minimum viable subset of groups of length
    # group_threshold, and for each group all minimum viable subsets of provided mnemonics.  We want
    # to support recovery, even if invalid Mnemonics have been provided for a group, and if
    # incompatible groups (same identifier and other common parameters but for a different master
    # seed, or mixed groups) were provided.
    common_mnemonics: Dict[
        ShareCommonParameters, Dict[ShareGroupParameters, ShareGroup]
    ] = group_common_mnemonics(mnemonics, strict)
    recovered: Dict[
        Tuple[EncryptedMasterSecret, ShareCommonParameters], Dict[RawShare, ShareGroup]
    ] = {}
    for distinct, sharegroups in common_mnemonics.items():
        possibles: Dict[int, Dict[RawShare, ShareGroup]] = recover_group_rawshares(
            sharegroups, complete
        )

        # We now have all resolved available group indices x and their decoded group secret from
        # RawGroup(x,data), and the minimal (or complete) set of Mnemonics that resulted in each.
        # We want to now recover all combinations of these groups that lead to different SLIP-39
        # encrypted master secrets.  Since we can't know which combinations of group secrets could
        # lead to a successful SLIP-39 decoding, we'll try every minimal combination of group
        # indices available.

        # Yield every encrypted master secret recovered, and the group indices and set of Share
        # mnemonics used to recover it.  This will be a minimal (or optionally 'complete') subset of
        # the groups and mnemonics supplied.  Note that we may end up with plenty of extra RawShares
        # that we cannot decode an EMS from, if an attacker is at work producing false shares; so
        # break when we're able to locate None.
        while len(possibles) >= distinct.group_threshold:
            for ems, using in locate_ems_rawshares(
                distinct, possibles, complete=complete
            ):
                if (ems, distinct) not in recovered:
                    # If caller doesn't care about collecting 'complete' set of source {RawShare:
                    # ShareGroup} used to recover the EMS, yield inline, otherwise at end of
                    if not complete:
                        yield (ems, distinct), using
                recovered.setdefault((ems, distinct), {}).update(using)
                # Always re-locate to optimize recovery for 'complete' w/ mutated 'possibles'.
                break
            else:
                # No EMS found; even though sufficient RawShares available to satisfy the
                # group_threshold; fake or incompatible
                break
        if complete:
            # If caller wanted 'complete' set of mnemonics, we'll yield at the end of scanning each
            # unique share encoding.
            for (ems, encoding), using in recovered.items():
                if encoding == distinct:
                    yield (ems, encoding), using
    if strict and not recovered:
        raise MnemonicError("Invalid set of mnemonics; No encoded secret found")


def expand_group(
    using: Dict[RawShare, ShareGroup],
    common_params: ShareCommonParameters,
    group: int,
    desired: Optional[int] = None,  # 0/None are equivalent
    strict: bool = False,
) -> None:
    """If sufficient group secrets are provided, we can recover the full spectrum of original group
    RawShares.  This recovers all base RawShare secrets (including additional entropy), and is
    sufficient to produce new (or replacement) 1/1 Shares for every group (even replace multi-Share
    groups with a new single-Share group, if not 'strict').

    For any group with sufficient mnemonics supplied to recover that group, we can also recover all
    of the originally generated group RawShare secrets (including additional entropy), allowing us
    to expand the group to include new mnemonics compatible with the existing mnemonics.

    It isn't possible to know how many shares in addition to the minimum member_threshold were
    originally produced; if desired is 0/None, we'll try to pick a sensible default; twice the
    member_threshold for multi-Share groups (or the greatest share index actually provided).

    """
    for rg, sg in using.items():
        if rg.x == group:
            # Found the target group in recoverable EMS RawGroups!
            grouping = next(iter(sg.shares)).group_parameters()
            if not desired:
                desired = max(
                    min(grouping.member_threshold * 2, MAX_SHARE_COUNT),
                    *(s.index + 1 for s in sg.shares),
                )
            if desired < grouping.member_threshold or grouping.member_threshold == 1:
                # They want fewer members than current threshold (impossible to do while
                # retaining compatibility with existing mnemonics), or threshold == 1.
                # We'll handle the special desired=1 case in loop exhaustion.
                continue
            if desired > MAX_SHARE_COUNT:
                raise ValueError(
                    f"The requested number of shares must not exceed {MAX_SHARE_COUNT}."
                )
            # Ready to expand!  Recover all the group's (original) RawShares from the
            # supplied shares, and then use them to produce any missing Shares.  This is
            # (group_threshold - 2) random RawShares at indices [0,group_threshold-2), plus
            # the group secret RawShare at index 255 and the digest RawShare at index 254.
            shares = {
                Share(
                    common_params.identifier,
                    common_params.extendable,
                    common_params.iteration_exponent,
                    group,
                    common_params.group_threshold,
                    common_params.group_count,
                    member_index,
                    grouping.member_threshold,
                    value,
                )
                for member_index, value in _recover_secret_rawshares(
                    grouping.member_threshold, desired, sg.to_raw_shares()
                )
            }
            if not sg.shares <= shares:
                # Expanding a group must never produce incompatible mnemonics!
                raise MnemonicError(
                    f"Expanding group {grouping.group_index} to {desired} Shares produced incompatible mnemonics"
                )
            sg.shares = shares
            break
    else:
        # Recovered groups exhausted; group not found in recoverable EMS RawShares.  We can satisfy
        # desired=1 for any group, even replacing a group if not 'strict'.
        if desired == 1 and group < common_params.group_count:
            # We're able to produce a single Share for *any* group; even one not provided in
            # the supplied mnemonic shares, or previously defined as having a threshold
            # greater than one!  This allows us to abandon a known-failed multi-mnemonic
            # group and replace it with a new single mnemonic (or recover a missing
            # threshold 1 group), if we have sufficient *other* groups to recover the
            # Encrypted Master Secret.  Here, we have to recover the full sequence of group
            # secrets underpinning the EMS's ciphertext.
            for group_index, value in _recover_secret_rawshares(
                common_params.group_threshold,
                common_params.group_count,
                using.keys(),
            ):
                if group == group_index:
                    shares = {
                        Share(
                            common_params.identifier,
                            common_params.extendable,
                            common_params.iteration_exponent,
                            group,
                            common_params.group_threshold,
                            common_params.group_count,
                            0,
                            1,
                            value,
                        )
                    }
                    rg = RawShare(group, value)
                    sg = using.setdefault(rg, ShareGroup())
                    if strict and not sg.shares <= shares:
                        # If 'strict', we won't allow you to replace a multi-mnemonic share group
                        # with a new single threshold group.
                        sg_threshold = (
                            next(iter(sg.shares)).group_parameters().member_threshold
                        )
                        raise MnemonicError(
                            f"Incompatible single-Share group {group} produced for existing {sg_threshold}-Share group"
                        )
                    sg.shares = shares
        elif strict:
            raise MnemonicError(f"Group {group} not recoverable in supplied mnemonics")


def group_ems_mnemonics(
    mnemonics: Iterable[Union[str, Share]],
    strict: bool = False,  # Fail if any Share is found to be invalid
    complete: bool = False,  # Find all related Shares, Groups instead of minimal
    expand: Optional[Iterable[Tuple[int, Optional[int]]]] = None,
) -> Generator[Tuple[EncryptedMasterSecret, Dict[int, Set[str]]], None, None]:
    """Here we just care about the recovered EMSs and their mnemonics.  Discard details about the specific
    encodings used.  We could yield the same EMS recovered with different sets of Mnemonics.

    May 'expand' a SLIP-39 group to the same or greater number of mnemonic shares originally
    specified for the group.  For this to be supported, the Encrypted Master Secret and the target
    group's RawShare must be recoverable in the supplied mnemonics, or it must be a group with a
    share threshold of 1.  Any existing group may be also be converted into a group with threshold 1
    in this fashion.  Unless 'script', any group not found to be expandable will be ignored.

    Yields the EMS and its recovered group(s), possibly expanded or (if not 'strict') even replaced
    with a new single-mnemonic group.

    """
    for (ems, common_params), using in group_ems_rawshares(mnemonics, strict, complete):
        for group, desired in expand or []:
            expand_group(using, common_params, group, desired, strict)
        yield ems, {rg.x: set(map(str, sg.shares)) for rg, sg in using.items()}


def decode_mnemonics(mnemonics: Iterable[str]) -> Dict[int, ShareGroup]:
    common_params: Set[ShareCommonParameters] = set()
    groups: Dict[int, ShareGroup] = {}
    for mnemonic in mnemonics:
        share = Share.from_mnemonic(mnemonic)
        common_params.add(share.common_parameters())
        group = groups.setdefault(share.group_index, ShareGroup())
        group.add(share)

    if len(common_params) != 1:
        raise MnemonicError(
            "Invalid set of mnemonics. "
            f"All mnemonics must begin with the same {ID_EXP_LENGTH_WORDS} words, "
            "must have the same group threshold and the same group count."
        )

    return groups


def split_ems(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    encrypted_master_secret: EncryptedMasterSecret,
) -> List[List[Share]]:
    """
    Split an Encrypted Master Secret into mnemonic shares.

    This function is a counterpart to `recover_ems`, and it is used as a subroutine in
    `generate_mnemonics`. The input is an *already encrypted* Master Secret (EMS), so it
    is possible to encrypt the Master Secret in advance and perform the splitting later.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param encrypted_master_secret: The encrypted master secret to split.
    :return: List of groups of mnemonics.
    """
    if len(encrypted_master_secret.ciphertext) * 8 < MIN_STRENGTH_BITS:
        raise ValueError(
            "The length of the master secret must be "
            f"at least {bits_to_bytes(MIN_STRENGTH_BITS)} bytes."
        )

    if group_threshold > len(groups):
        raise ValueError(
            "The requested group threshold must not exceed the number of groups."
        )

    if any(
        member_threshold == 1 and member_count > 1
        for member_threshold, member_count in groups
    ):
        raise ValueError(
            "Creating multiple member shares with member threshold 1 is not allowed. "
            "Use 1-of-1 member sharing instead."
        )

    group_shares = _split_secret(
        group_threshold, len(groups), encrypted_master_secret.ciphertext
    )

    return [
        [
            Share(
                encrypted_master_secret.identifier,
                encrypted_master_secret.extendable,
                encrypted_master_secret.iteration_exponent,
                group_index,
                group_threshold,
                len(groups),
                member_index,
                member_threshold,
                value,
            )
            for member_index, value in _split_secret(
                member_threshold, member_count, group_secret
            )
        ]
        for (member_threshold, member_count), (group_index, group_secret) in zip(
            groups, group_shares
        )
    ]


def _random_identifier() -> int:
    """Returns a random identifier with the given bit length."""
    identifier = int.from_bytes(RANDOM_BYTES(bits_to_bytes(ID_LENGTH_BITS)), "big")
    return identifier & ((1 << ID_LENGTH_BITS) - 1)


def generate_mnemonics(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    master_secret: bytes,
    passphrase: bytes = b"",
    extendable: bool = True,
    iteration_exponent: int = 1,
) -> List[List[str]]:
    """
    Split a master secret into mnemonic shares using Shamir's secret sharing scheme.

    The supplied Master Secret is encrypted by the passphrase (empty passphrase is used
    if none is provided) and split into a set of mnemonic shares.

    This is the user-friendly method to back up a pre-existing secret with the Shamir
    scheme, optionally protected by a passphrase.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param master_secret: The master secret to split.
    :param passphrase: The passphrase used to encrypt the master secret.
    :param extendable: Re-encoding of the same secret yields deterministic secrets when decrypted with other passwords
    :param int iteration_exponent: The encryption iteration exponent.
    :return: List of groups mnemonics.
    """
    if not all(32 <= c <= 126 for c in passphrase):
        raise ValueError(
            "The passphrase must contain only printable ASCII characters (code points 32-126)."
        )

    identifier = _random_identifier()
    encrypted_master_secret = EncryptedMasterSecret.from_master_secret(
        master_secret, passphrase, identifier, extendable, iteration_exponent
    )
    grouped_shares = split_ems(group_threshold, groups, encrypted_master_secret)
    return [[share.mnemonic() for share in group] for group in grouped_shares]


def recover_ems(groups: Dict[int, ShareGroup]) -> EncryptedMasterSecret:
    """
    Combine shares, recover metadata and the Encrypted Master Secret.

    This function is a counterpart to `split_ems`, and it is used as a subroutine in
    `combine_mnemonics`. It returns the EMS itself and data required for its decryption,
    except for the passphrase. It is thus possible to defer decryption of the Master
    Secret to a later time.

    Requires a minimal group_threshold subset of groups, and each group must be a minimal
    member_threshold of the group's mnemonics.

    :param groups: Set of shares classified into groups.
    :return: Encrypted Master Secret
    """

    if not groups:
        raise MnemonicError("The set of shares is empty.")

    params = next(iter(groups.values())).common_parameters()

    if len(groups) < params.group_threshold:
        raise MnemonicError(
            "Insufficient number of mnemonic groups. "
            f"The required number of groups is {params.group_threshold}."
        )

    if len(groups) != params.group_threshold:
        raise MnemonicError(
            "Wrong number of mnemonic groups. "
            f"Expected {params.group_threshold} groups, "
            f"but {len(groups)} were provided."
        )

    for group in groups.values():
        if len(group) != group.member_threshold():
            share_words = next(iter(group)).words()
            prefix = " ".join(share_words[:GROUP_PREFIX_LENGTH_WORDS])
            raise MnemonicError(
                "Wrong number of mnemonics. "
                f'Expected {group.member_threshold()} mnemonics starting with "{prefix} ...", '
                f"but {len(group)} were provided."
            )

    group_shares = [
        RawShare(
            group_index,
            _recover_secret(group.member_threshold(), group.to_raw_shares()),
        )
        for group_index, group in groups.items()
    ]

    ciphertext = _recover_secret(params.group_threshold, group_shares)
    return EncryptedMasterSecret(
        params.identifier, params.extendable, params.iteration_exponent, ciphertext
    )


def combine_mnemonics(mnemonics: Iterable[str], passphrase: bytes = b"") -> bytes:
    """
    Combine mnemonic shares to obtain the master secret which was previously split
    using Shamir's secret sharing scheme.

    This is the user-friendly method to recover a backed-up secret optionally protected
    by a passphrase.

    :param mnemonics: List of mnemonics.
    :param passphrase: The passphrase used to encrypt the master secret.
    :return: The master secret.
    """

    if not mnemonics:
        raise MnemonicError("The list of mnemonics is empty.")

    groups: Dict[int, ShareGroup] = decode_mnemonics(mnemonics)
    encrypted_master_secret = recover_ems(groups)
    return encrypted_master_secret.decrypt(passphrase)
