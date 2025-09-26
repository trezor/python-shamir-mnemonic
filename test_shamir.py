import json
import random
import secrets
from itertools import combinations
from random import shuffle
from typing import Union

import pytest
from bip32utils import BIP32Key
from deepset import deepset

import shamir_mnemonic as shamir
from shamir_mnemonic import MnemonicError, Share

MS = b"ABCDEFGHIJKLMNOP"


def test_basic_sharing_random():
    secret = secrets.token_bytes(16)
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], secret)[0]
    assert shamir.combine_mnemonics(mnemonics[:3]) == shamir.combine_mnemonics(
        mnemonics[2:]
    )


def test_basic_sharing_fixed():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[:3])
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[1:3])


def test_passphrase():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_non_extendable():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, extendable=False)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])


def test_iteration_exponent():
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=1
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=2
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_extendable_encryption_behavior():
    """Test that the extendable parameter affects encryption determinism.

    With extendable=False: same secret encrypted twice with different identifiers
    produces different encrypted results, even with same passphrase.

    With extendable=True: same secret always produces the same encrypted result
    when using the same passphrase, regardless of identifier.
    """
    fixed_secret = b"ABCDEFGHIJKLMNOP"
    passphrase1 = b"password1"
    passphrase2 = b"password2"

    # Test extendable=False behavior
    # Same secret, same passphrase, different identifiers -> different encrypted results
    ems_nonext_id1 = shamir.EncryptedMasterSecret.from_master_secret(
        fixed_secret, passphrase1, identifier=1, extendable=False, iteration_exponent=1
    )
    ems_nonext_id1a = shamir.EncryptedMasterSecret.from_master_secret(
        fixed_secret, passphrase1, identifier=1, extendable=False, iteration_exponent=1
    )
    ems_nonext_id2 = shamir.EncryptedMasterSecret.from_master_secret(
        fixed_secret, passphrase1, identifier=2, extendable=False, iteration_exponent=1
    )

    # With extendable=False, the same encryption parameters produces the same ciphertext, and
    # different identifier value produces *different* encrypted results
    assert ems_nonext_id1.ciphertext == ems_nonext_id1a.ciphertext
    assert ems_nonext_id1.ciphertext != ems_nonext_id2.ciphertext

    # But both decrypt to the original secret with the correct passphrase
    assert ems_nonext_id1.decrypt(passphrase1) == fixed_secret
    assert ems_nonext_id2.decrypt(passphrase1) == fixed_secret

    # With extendable=False and wrong passphrase, they decrypt to different (wrong) secrets.  This
    # may be surprising; re-encoding the same master secret yields different custom/decoy wallets
    # with each re-encoding.
    wrong_secret1 = ems_nonext_id1.decrypt(passphrase2)
    wrong_secret2 = ems_nonext_id2.decrypt(passphrase2)
    assert wrong_secret1 != fixed_secret
    assert wrong_secret2 != fixed_secret
    assert wrong_secret1 != wrong_secret2  # Different wrong secrets

    # Test extendable=True behavior
    # Same secret, same passphrase, different identifiers -> same encrypted results
    ems_ext_id1 = shamir.EncryptedMasterSecret.from_master_secret(
        fixed_secret, passphrase1, identifier=1, extendable=True, iteration_exponent=1
    )
    ems_ext_id1a = shamir.EncryptedMasterSecret.from_master_secret(
        fixed_secret, passphrase1, identifier=1, extendable=True, iteration_exponent=1
    )
    ems_ext_id2 = shamir.EncryptedMasterSecret.from_master_secret(
        fixed_secret, passphrase1, identifier=2, extendable=True, iteration_exponent=1
    )

    # With extendable=True, the same encryption parameters produces the same ciphertext, and
    # different identifier value now produces *the same* encrypted results
    assert ems_ext_id1.ciphertext == ems_ext_id1a.ciphertext
    assert ems_ext_id1.ciphertext == ems_ext_id2.ciphertext

    # Both decrypt to the original secret with the correct passphrase
    assert ems_ext_id1.decrypt(passphrase1) == fixed_secret
    assert ems_ext_id2.decrypt(passphrase1) == fixed_secret

    # With wrong passphrase, they decrypt to the same (wrong) secret
    wrong_secret_ext1 = ems_ext_id1.decrypt(passphrase2)
    wrong_secret_ext2 = ems_ext_id2.decrypt(passphrase2)
    assert wrong_secret_ext1 != fixed_secret
    assert wrong_secret_ext2 != fixed_secret
    assert wrong_secret_ext1 == wrong_secret_ext2  # Same wrong secret


def test_group_sharing():
    group_threshold = 2
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for groups in combinations(zip(mnemonics, member_thresholds), group_threshold):
        for group1_subset in combinations(groups[0][0], groups[0][1]):
            for group2_subset in combinations(groups[1][0], groups[1][1]):
                mnemonic_subset = list(group1_subset + group2_subset)
                shuffle(mnemonic_subset)
                assert MS == shamir.combine_mnemonics(mnemonic_subset)

    # Minimal sets of mnemonics.
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][0], mnemonics[2][2], mnemonics[3][0]]
    )
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][3], mnemonics[3][0], mnemonics[2][4]]
    )

    # One complete group and one incomplete group out of two groups required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][2:] + [mnemonics[1][0]])

    # One group of two required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][1:4])


def test_group_sharing_threshold_1():
    group_threshold = 1
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for group, member_threshold in zip(mnemonics, member_thresholds):
        for group_subset in combinations(group, member_threshold):
            mnemonic_subset = list(group_subset)
            shuffle(mnemonic_subset)
            assert MS == shamir.combine_mnemonics(mnemonic_subset)


def test_all_groups_exist():
    for group_threshold in (1, 2, 5):
        mnemonics = shamir.generate_mnemonics(
            group_threshold, [(3, 5), (1, 1), (2, 3), (2, 5), (3, 5)], MS
        )
        assert len(mnemonics) == 5
        assert len(sum(mnemonics, [])) == 19


def test_invalid_sharing():
    # Short master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS[:14])

    # Odd length master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS + b"X")

    # Group threshold exceeds number of groups.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(3, [(3, 5), (2, 5)], MS)

    # Invalid group threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(0, [(3, 5), (2, 5)], MS)

    # Member threshold exceeds number of members.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 2), (2, 5)], MS)

    # Invalid member threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(0, 2), (2, 5)], MS)

    # Group with multiple members and member threshold 1.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 5), (1, 3), (2, 5)], MS)


def test_vectors():
    with open("vectors.json", "r") as f:
        vectors = json.load(f)
    for description, mnemonics, secret_hex, xprv in vectors:
        if secret_hex:
            secret = bytes.fromhex(secret_hex)
            assert secret == shamir.combine_mnemonics(
                mnemonics, b"TREZOR"
            ), 'Incorrect secret for test vector "{}".'.format(description)
            assert (
                BIP32Key.fromEntropy(secret).ExtendedKey() == xprv
            ), 'Incorrect xprv for test vector "{}".'.format(description)
        else:
            with pytest.raises(MnemonicError):
                shamir.combine_mnemonics(mnemonics)
                pytest.fail(
                    'Failed to raise exception for test vector "{}".'.format(
                        description
                    )
                )


def test_split_ems():
    encrypted_master_secret = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"TREZOR", identifier=42, extendable=True, iteration_exponent=1
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], encrypted_master_secret)
    mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    recovered = shamir.combine_mnemonics(mnemonics[:3], b"TREZOR")
    assert recovered == MS


def test_recover_ems():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]

    groups = shamir.decode_mnemonics(mnemonics[:3])
    encrypted_master_secret = shamir.recover_ems(groups)
    recovered = encrypted_master_secret.decrypt(b"TREZOR")
    assert recovered == MS


def test_group_ems_mnemonics(monkeypatch):
    monkeypatch.setattr(shamir.shamir, "RANDOM_BYTES", lambda n: n * b"\0")

    ems_MS_nonext = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"TREZOR", identifier=0, extendable=False, iteration_exponent=1
    )
    mnemonics_nonext_a = shamir.split_ems(
        2,
        [(1, 1), (2, 3), (3, 5)],
        ems_MS_nonext,
    )
    # print( json.dumps( mnemonics_nonext_a, indent=4, default=str ))
    assert mnemonics_nonext_a == [
        [
            Share.from_mnemonic(
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            )
        ],
        [
            Share.from_mnemonic(
                "academic acid beard leaf desktop crowd erode vegan season warmth warn craft ceramic picture wrote depend radar result dream that"
            ),
            Share.from_mnemonic(
                "academic acid beard lily dwarf aide unknown fancy merit grant sharp leaves blimp exotic sharp fancy salon forecast worthy taught"
            ),
            Share.from_mnemonic(
                "academic acid beard lungs center injury academic pupal hand surface volume have smart hormone wealthy echo capture year browser material"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic acid ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic ugly saver sack"
            ),
            Share.from_mnemonic(
                "academic acid ceramic lips dress custody tension wildlife forbid surprise ticket already ugly emerald laundry pickup deny exhaust cards orange"
            ),
            Share.from_mnemonic(
                "academic acid ceramic luxury acquire gross likely very swimming rhythm member carbon regret daisy vintage gravity pile arena quiet material"
            ),
            Share.from_mnemonic(
                "academic acid ceramic march dream estimate genuine ambition listen gesture harvest broken fiction hawk making safari mountain problem hospital snake"
            ),
            Share.from_mnemonic(
                "academic acid ceramic method diet drift sweater alto epidemic beyond analysis hearing timber vegan alto tidy obtain ceramic cricket sack"
            ),
        ],
    ]

    mnemonics_nonext_b = shamir.split_ems(
        2,
        [(1, 1), (2, 5), (3, 7)],  # <-- increase group member count
        ems_MS_nonext,
    )
    # print( json.dumps( mnemonics_nonext_b, indent=4, default=str ))
    assert mnemonics_nonext_b == [
        [
            Share.from_mnemonic(
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            )
        ],
        [
            Share.from_mnemonic(
                "academic acid beard leaf desktop crowd erode vegan season warmth warn craft ceramic picture wrote depend radar result dream that"
            ),
            Share.from_mnemonic(
                "academic acid beard lily dwarf aide unknown fancy merit grant sharp leaves blimp exotic sharp fancy salon forecast worthy taught"
            ),
            Share.from_mnemonic(
                "academic acid beard lungs center injury academic pupal hand surface volume have smart hormone wealthy echo capture year browser material"
            ),
            Share.from_mnemonic(
                "academic acid beard marathon criminal force perfect being dwarf energy scroll satoshi welfare lunar slush charity guilt briefing steady medal"
            ),
            Share.from_mnemonic(
                "academic acid beard merit calcium music reaction says swimming rhythm member carbon regret daisy vintage gravity pile crisis estimate crush"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic acid ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic ugly saver sack"
            ),
            Share.from_mnemonic(
                "academic acid ceramic lips dress custody tension wildlife forbid surprise ticket already ugly emerald laundry pickup deny exhaust cards orange"
            ),
            Share.from_mnemonic(
                "academic acid ceramic luxury acquire gross likely very swimming rhythm member carbon regret daisy vintage gravity pile arena quiet material"
            ),
            Share.from_mnemonic(
                "academic acid ceramic march dream estimate genuine ambition listen gesture harvest broken fiction hawk making safari mountain problem hospital snake"
            ),
            Share.from_mnemonic(
                "academic acid ceramic method diet drift sweater alto epidemic beyond analysis hearing timber vegan alto tidy obtain ceramic cricket sack"
            ),
            Share.from_mnemonic(
                "academic acid ceramic mortgage ancient beard duration wolf beam smirk ultimate helpful amuse rapids item election plastic library voting orange"
            ),
            Share.from_mnemonic(
                "academic acid ceramic nervous devote force galaxy veteran much priority losing injury frost swimming vegan learn dress ruler formal material"
            ),
        ],
    ]
    # Confirm that the extended Mnemonics are a superset of the original Mnemonics
    assert mnemonics_nonext_b[0] == mnemonics_nonext_a[0]
    assert mnemonics_nonext_b[1] > mnemonics_nonext_a[1]
    assert mnemonics_nonext_b[2] > mnemonics_nonext_a[2]

    # Now, generate an identically encrypted EMS (since we have eliminated all entropy), only differing in 'extendable'.
    ems_MS_extend = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"TREZOR", identifier=0, extendable=True, iteration_exponent=1
    )
    mnemonics_extend_a = shamir.split_ems(
        2,
        [(1, 1), (2, 3), (3, 5)],
        ems_MS_extend,
    )
    # print( json.dumps( mnemonics_extend_a, indent=4, default=str ))
    assert mnemonics_extend_a == [
        [
            Share.from_mnemonic(
                "academic agency acrobat leader check clinic isolate slavery branch bulge hairy library emphasis slim fused both cargo predator network adult"
            )
        ],
        [
            Share.from_mnemonic(
                "academic agency beard leaf both husky alarm firefly obtain device response graduate bedroom flash luxury friendly grasp slice robin music"
            ),
            Share.from_mnemonic(
                "academic agency beard lily armed tadpole scroll dynamic security unwrap exercise require busy busy firefly drink item column costume nylon"
            ),
            Share.from_mnemonic(
                "academic agency beard lungs cinema device true move texture obesity freshman jury should sack froth custody froth race finance dwarf"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence"
            ),
            Share.from_mnemonic(
                "academic agency ceramic lips blind wireless process scramble military lecture diploma nylon birthday talent deal wealthy briefing edge geology scandal"
            ),
            Share.from_mnemonic(
                "academic agency ceramic luxury drove vampire criminal idea damage husband knife evening gross garlic check result extend work keyboard priority"
            ),
            Share.from_mnemonic(
                "academic agency ceramic march counter ancestor lizard railroad river usual estate software improve river behavior emperor envy elevator genre scholar"
            ),
            Share.from_mnemonic(
                "academic agency ceramic method change magazine exhaust forecast priority fused pink presence demand webcam violence visual crowd tendency declare coastal"
            ),
        ],
    ]
    mnemonics_extend_b = shamir.split_ems(
        2,
        [(1, 1), (2, 5), (3, 7)],  # <-- increase group member count
        ems_MS_extend,
    )
    # print( json.dumps( mnemonics_extend_b, indent=4, default=str ))
    assert mnemonics_extend_b == [
        [
            Share.from_mnemonic(
                "academic agency acrobat leader check clinic isolate slavery branch bulge hairy library emphasis slim fused both cargo predator network adult"
            )
        ],
        [
            Share.from_mnemonic(
                "academic agency beard leaf both husky alarm firefly obtain device response graduate bedroom flash luxury friendly grasp slice robin music"
            ),
            Share.from_mnemonic(
                "academic agency beard lily armed tadpole scroll dynamic security unwrap exercise require busy busy firefly drink item column costume nylon"
            ),
            Share.from_mnemonic(
                "academic agency beard lungs cinema device true move texture obesity freshman jury should sack froth custody froth race finance dwarf"
            ),
            Share.from_mnemonic(
                "academic agency beard marathon display oasis crowd wits rhyme eclipse problem pecan security main license exclude editor fumes salary deploy"
            ),
            Share.from_mnemonic(
                "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy"
            ),
        ],
        [
            Share.from_mnemonic(
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence"
            ),
            Share.from_mnemonic(
                "academic agency ceramic lips blind wireless process scramble military lecture diploma nylon birthday talent deal wealthy briefing edge geology scandal"
            ),
            Share.from_mnemonic(
                "academic agency ceramic luxury drove vampire criminal idea damage husband knife evening gross garlic check result extend work keyboard priority"
            ),
            Share.from_mnemonic(
                "academic agency ceramic march counter ancestor lizard railroad river usual estate software improve river behavior emperor envy elevator genre scholar"
            ),
            Share.from_mnemonic(
                "academic agency ceramic method change magazine exhaust forecast priority fused pink presence demand webcam violence visual crowd tendency declare coastal"
            ),
            Share.from_mnemonic(
                "academic agency ceramic mortgage desert imply tenant package dream syndrome paid diet clothes cluster scout average depend fused cubic express"
            ),
            Share.from_mnemonic(
                "academic agency ceramic nervous calcium item graduate critical license darkness spine total fiber numb starting eraser justice that deny clothes"
            ),
        ],
    ]
    assert mnemonics_extend_b[0] == mnemonics_extend_a[0]
    assert mnemonics_extend_b[1] > mnemonics_extend_a[1]
    assert mnemonics_extend_b[2] > mnemonics_extend_a[2]

    # Note that both SLIP-39 Mnemonics are "extendable", regardless of the value of the extendable
    # option when created.  So long as the caller only alters the number of shares in a group (and
    # not the group count or threshold, or the group member threshold required), you can create
    # additional group members usable to recover the original EncryptedMasterSecret.

    # We'll expect exactly one recovery for this set of mnemonic shares.  Note that we're recovering
    # a "non-extendable" EncryptedMasterSecret here, using output from two split_ems calls with
    # different group member counts, but identical thresholds.  Here we use the ..._nonext_a's group 0, but
    # only the new Mnemonics from ..._nonext_b:
    for ems, groups in shamir.group_ems_mnemonics(
        mnemonics_nonext_a[0]
        + list(set(mnemonics_nonext_b[1]) - set(mnemonics_nonext_a[1]))
    ):
        # print(f"Recovered {ems} using: {json.dumps( groups, indent=4, default=str )}")
        assert ems.decrypt(b"TREZOR") == MS

        assert groups == {
            0: {
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            },
            1: {
                "academic acid beard marathon criminal force perfect being dwarf energy scroll satoshi welfare lunar slush charity guilt briefing steady medal",
                "academic acid beard merit calcium music reaction says swimming rhythm member carbon regret daisy vintage gravity pile crisis estimate crush",
            },
        }

    # Here, we'll recover both unique EncryptedMasterSecret values with unique common_parameters
    # from the pool of all available mnemonics.  This is the super-power of group_ems_mnemonics; it
    # will process arbitrary pools of Mnemonics, identify the unique common_parameters, and then
    # iterate over all combinations and cartesion products of available share groups to try to
    # recover any SLIP-39 encoded EncryptedMasterSecret values available.  It will ignore any
    # invalid, redundant or incomplete mnemonics.

    recovered = {}
    for ems, groups in shamir.group_ems_mnemonics(
        sum(
            mnemonics_nonext_a
            + mnemonics_nonext_b
            + mnemonics_extend_a
            + mnemonics_extend_b,
            [],
        ),
        complete=True,
    ):
        assert ems not in recovered
        recovered[ems] = groups

    assert len(recovered) == 2
    assert all(ems.decrypt(b"TREZOR") == MS for ems, _ in recovered.items())
    # print(
    #     json.dumps(
    #         {str(ems): group for ems, group in recovered.items()}, indent=4, default=str
    #     )
    # )
    expected = {
        ems_MS_nonext: {
            0: {
                "academic acid acrobat leader civil gross counter dictate fancy findings lair freshman kind justice apart quiet lunch short vitamins painting"
            },
            1: {
                "academic acid beard merit calcium music reaction says swimming rhythm member carbon regret daisy vintage gravity pile crisis estimate crush",
                "academic acid beard marathon criminal force perfect being dwarf energy scroll satoshi welfare lunar slush charity guilt briefing steady medal",
                "academic acid beard lily dwarf aide unknown fancy merit grant sharp leaves blimp exotic sharp fancy salon forecast worthy taught",
                "academic acid beard leaf desktop crowd erode vegan season warmth warn craft ceramic picture wrote depend radar result dream that",
                "academic acid beard lungs center injury academic pupal hand surface volume have smart hormone wealthy echo capture year browser material",
            },
            2: {
                "academic acid ceramic mortgage ancient beard duration wolf beam smirk ultimate helpful amuse rapids item election plastic library voting orange",
                "academic acid ceramic luxury acquire gross likely very swimming rhythm member carbon regret daisy vintage gravity pile arena quiet material",
                "academic acid ceramic lips dress custody tension wildlife forbid surprise ticket already ugly emerald laundry pickup deny exhaust cards orange",
                "academic acid ceramic nervous devote force galaxy veteran much priority losing injury frost swimming vegan learn dress ruler formal material",
                "academic acid ceramic method diet drift sweater alto epidemic beyond analysis hearing timber vegan alto tidy obtain ceramic cricket sack",
                "academic acid ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic ugly saver sack",
                "academic acid ceramic march dream estimate genuine ambition listen gesture harvest broken fiction hawk making safari mountain problem hospital snake",
            },
        },
        ems_MS_extend: {
            0: {
                "academic agency acrobat leader check clinic isolate slavery branch bulge hairy library emphasis slim fused both cargo predator network adult"
            },
            1: {
                "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy",
                "academic agency beard lungs cinema device true move texture obesity freshman jury should sack froth custody froth race finance dwarf",
                "academic agency beard lily armed tadpole scroll dynamic security unwrap exercise require busy busy firefly drink item column costume nylon",
                "academic agency beard leaf both husky alarm firefly obtain device response graduate bedroom flash luxury friendly grasp slice robin music",
                "academic agency beard marathon display oasis crowd wits rhyme eclipse problem pecan security main license exclude editor fumes salary deploy",
            },
            2: {
                "academic agency ceramic method change magazine exhaust forecast priority fused pink presence demand webcam violence visual crowd tendency declare coastal",
                "academic agency ceramic march counter ancestor lizard railroad river usual estate software improve river behavior emperor envy elevator genre scholar",
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence",
                "academic agency ceramic luxury drove vampire criminal idea damage husband knife evening gross garlic check result extend work keyboard priority",
                "academic agency ceramic lips blind wireless process scramble military lecture diploma nylon birthday talent deal wealthy briefing edge geology scandal",
                "academic agency ceramic mortgage desert imply tenant package dream syndrome paid diet clothes cluster scout average depend fused cubic express",
                "academic agency ceramic nervous calcium item graduate critical license darkness spine total fiber numb starting eraser justice that deny clothes",
            },
        },
    }
    assert deepset(recovered) == expected

    # And again, with complete=False
    recovered = {}
    for ems, groups in shamir.group_ems_mnemonics(
        sum(
            mnemonics_nonext_a
            + mnemonics_nonext_b
            + mnemonics_extend_a
            + mnemonics_extend_b,
            [],
        ),
        complete=False,
    ):
        assert ems not in recovered
        recovered[ems] = groups
    assert len(recovered) == 2
    assert deepset(recovered) < expected

    # Let's test some groups of mnemonics from different seeds, but the same parameters.  Again, we
    # are suppressing entropy, so the only thing that will differ is the encryption of the seed; all
    # other EMS parameters will be identical, and (of course) the underlying seed is identical.
    ems_MS_extend_DIFFER = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"DIFFER", identifier=0, extendable=True, iteration_exponent=1
    )
    assert ems_MS_extend != ems_MS_extend_DIFFER
    assert (
        ems_MS_extend.decrypt(b"TREZOR")
        == ems_MS_extend_DIFFER.decrypt(b"DIFFER")
        == MS
    )

    # Produce SLIP-39 mnemonics for the alternatively encrypted (but identically parameterized) EMS
    mnemonics_extend_b_DIFFER = shamir.split_ems(
        2,
        [(1, 1), (2, 5), (3, 7)],  # <-- increase group member count
        ems_MS_extend_DIFFER,
    )

    class ShareCorrupt(Share):
        def corrupt(self, bits: int = 1) -> "Share":
            value_array = bytearray(self.value)
            pairs: set[tuple[int, int]] = set()
            while len(pairs) < bits:
                pairs.add(
                    (random.randint(0, len(value_array) - 1), random.randint(0, 7))
                )
            for byte, bit in pairs:
                value_array[byte] ^= 1 << bit
            return Share(
                self.identifier,
                self.extendable,
                self.iteration_exponent,
                self.group_index,
                self.group_threshold,
                self.group_count,
                self.index,
                self.member_threshold,
                bytes(value_array),
            )

    def corrupt(share: Union[Share, str], bits: int = 1) -> str:
        if isinstance(share, Share):
            share = share.mnemonic()
        return ShareCorrupt.from_mnemonic(share).corrupt(bits).mnemonic()

    # print(
    #     corrupt(
    #         "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy"
    #     )
    # )
    assert (
        corrupt(
            "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy",
            bits=0,
        )
        == "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy"
    )
    assert (
        corrupt(
            "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy"
        )
        != "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy"
    )

    # Now, attempt to recover.  Should regain both EMSs, even though all Shares have identical
    # parameters!!  Remember -- it is a /feature/ of SLIP-39 that an incorrect decryption key
    # results in a "valid" decrypted seed (just a seed that doesn't match the original).  So, see if
    # any decryption with the possible passwords correctly recovers the original seed...
    shares = sum(
        mnemonics_extend_b + mnemonics_extend_b_DIFFER,
        [],
    ) + list(
        map(
            corrupt,
            sum(
                mnemonics_extend_b,
                [],
            ),
        )
    )
    # print(
    #     "Mnemonics w/ TREZOR, DIFFER and corrupt sets:",
    #     json.dumps(shares, indent=4, default=str),
    # )
    recovered = {}
    for ems, groups in shamir.group_ems_mnemonics(
        shares,
        complete=True,
    ):
        assert ems not in recovered
        recovered[ems] = groups

    assert len(recovered) == 2
    # print(
    #     json.dumps(
    #         {str(ems): group for ems, group in recovered.items()}, indent=4, default=str
    #     )
    # )
    assert all(
        any(map(lambda p: ems.decrypt(p) == MS, (b"TREZOR", b"DIFFER")))
        for ems in recovered
    ), "Failed to recover original seed w/ any valid password"

    expected = {
        ems_MS_extend: {
            0: {
                "academic agency acrobat leader check clinic isolate slavery branch bulge hairy library emphasis slim fused both cargo predator network adult"
            },
            1: {
                "academic agency beard merit distance welfare survive sniff damage husband knife evening gross garlic check result extend estate agency destroy",
                "academic agency beard lungs cinema device true move texture obesity freshman jury should sack froth custody froth race finance dwarf",
                "academic agency beard lily armed tadpole scroll dynamic security unwrap exercise require busy busy firefly drink item column costume nylon",
                "academic agency beard leaf both husky alarm firefly obtain device response graduate bedroom flash luxury friendly grasp slice robin music",
                "academic agency beard marathon display oasis crowd wits rhyme eclipse problem pecan security main license exclude editor fumes salary deploy",
            },
            2: {
                "academic agency ceramic method change magazine exhaust forecast priority fused pink presence demand webcam violence visual crowd tendency declare coastal",
                "academic agency ceramic march counter ancestor lizard railroad river usual estate software improve river behavior emperor envy elevator genre scholar",
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence",
                "academic agency ceramic luxury drove vampire criminal idea damage husband knife evening gross garlic check result extend work keyboard priority",
                "academic agency ceramic lips blind wireless process scramble military lecture diploma nylon birthday talent deal wealthy briefing edge geology scandal",
                "academic agency ceramic mortgage desert imply tenant package dream syndrome paid diet clothes cluster scout average depend fused cubic express",
                "academic agency ceramic nervous calcium item graduate critical license darkness spine total fiber numb starting eraser justice that deny clothes",
            },
        },
        ems_MS_extend_DIFFER: {
            0: {
                "academic agency acrobat leader again gray increase worthy response music solution eraser squeeze cylinder acquire total music costume mountain snapshot"
            },
            1: {
                "academic agency beard merit cowboy view visual image skin adorn likely ladybug mouse merchant activity champion medal firm yelp lungs",
                "academic agency beard lungs bucket cleanup smell plan valid corner result leaf style rainbow academic elbow survive grasp angry agency",
                "academic agency beard lily actress ruler fake camera skunk dryer boundary daughter dwarf crazy acne window blanket simple best leaves",
                "academic agency beard leaf describe headset column cards steady secret plunge estate glad fused acquire glasses daughter fatigue acrobat famous",
                "academic agency beard marathon crush mayor relate plot timber source acrobat thunder lobe romp acid subject together wolf breathe sprinkle",
            },
            2: {
                "academic agency ceramic method document escape paces purple pitch famous wildlife language champion teaspoon activity perfect diagnose loud tension upstairs",
                "academic agency ceramic learn academic academic academic academic academic academic academic academic academic academic academic academic academic zero laundry presence",
                "academic agency ceramic lips dream home born metric hearing exceed grasp raisin adult necklace adapt amazing estate math vitamins become",
                "academic agency ceramic march adequate ticket auction general picture express tolerate silver multiple aluminum acne craft scandal divorce auction image",
                "academic agency ceramic luxury duke manager brother vampire skin adorn likely ladybug mouse merchant activity champion medal enlarge loyalty skin",
                "academic agency ceramic mortgage alarm client lunch chemical satisfy carpet paid similar chemical jerky acne primary kind view hazard exceed",
                "academic agency ceramic nervous again sack lobe elephant graduate extra jacket acquire race idea academic lily regular decent bulge merchant",
            },
        },
    }
    assert deepset(recovered) <= expected

    # And again, with complete=False
    recovered = {}
    for ems, groups in shamir.group_ems_mnemonics(
        shares,
        complete=False,
    ):
        assert ems not in recovered
        recovered[ems] = groups

    assert len(recovered) == 2
    assert deepset(recovered) < expected


ones = b"\xff" * 16
ones_mnemonics = {
    # First 1/1
    0: {
        "olympic guilt acrobat romp dining inform withdraw brave lips quarter bulge thorn best wildlife alive yelp home security lilac eclipse",
    },
    # Second 1/1
    1: {
        "olympic guilt beard romp apart preach various garden always mayor solution acid quantity domestic slush zero fatigue disaster fluff romp",
    },
    # Fam 2/4
    2: {
        "olympic guilt ceramic roster agency evidence beard emerald triumph crystal flip threaten yield slow dwarf mason together kidney center memory",
        "olympic guilt ceramic scared dream shrimp upgrade flip scroll cylinder evaluate acquire evening idle omit learn impulse custody estimate blanket",
        "olympic guilt ceramic shadow density false spark hesitate desert counter born omit smoking preach beyond dilemma aunt switch revenue peanut",
        "olympic guilt ceramic sister angel speak deliver idea brave crazy aide isolate grasp birthday pulse domestic object market squeeze dismiss",
    },
    # Frens 3/6
    3: {
        "olympic guilt decision round animal velvet bedroom species railroad energy findings general laden estate music ordinary tolerate duration photo laden",
        "olympic guilt decision scatter agency speak rapids quantity slice mustang fragment universe tackle screw wrist install moisture ticket founder display",
        "olympic guilt decision shaft auction various lyrics amazing peasant withdraw editor swing makeup review analysis physics capacity marathon beaver divorce",
        "olympic guilt decision skin acrobat spelling dance guest sugar crunch envy fancy cradle declare gasoline exceed hairy flash ugly language",
        "olympic guilt decision snake costume teaspoon aluminum deadline steady cricket subject bedroom acrobat elbow numb material scatter dramatic capture advance",
        "olympic guilt decision spider coastal round promise expect paper width spelling ounce party smart username grin provide tracks theater engage",
    },
}


def test_group_expand():
    """Confirm that we can recover an EMS from a groups of SLIP-39 mnemonics, and "expand" those
    groups to include more mnemonics compatible with the existing ones.

    We'll use a pre-generated 2 of 1/1, 1/1, 2/4 and 3/6 grouping.

    """

    # We can recover the original "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong" =~=
    # 0xffffffffffffffffffffffffffffffff seed and all of the supplied mnemonics are valid and
    # recovered (when 'complete')
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(*ones_mnemonics.values()), complete=True
    )
    assert ems.decrypt(b"") == ones
    assert recovered == ones_mnemonics

    # Now, lets only supply the Fam and Frens, and ensure we can get back the 1/1 shares.  Since
    # they contain no additional entropy, they will always match the original 1/1 shares.
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(ones_mnemonics[2], ones_mnemonics[3])
    )
    assert ems.decrypt(b"") == ones
    assert deepset(recovered) < ones_mnemonics
    assert 0 not in recovered  # First (group 0) but not recovered

    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(ones_mnemonics[2], ones_mnemonics[3]),
        expand=[(0, 1)],
    )
    assert ems.decrypt(b"") == ones
    assert deepset(recovered) < ones_mnemonics
    assert recovered[0] == {
        "olympic guilt acrobat romp dining inform withdraw brave lips quarter bulge thorn best wildlife alive yelp home security lilac eclipse",
    }
    assert 1 not in recovered

    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(ones_mnemonics[2], ones_mnemonics[3]),
        expand=[(0, 1), (1, 1)],
    )
    assert ems.decrypt(b"") == ones
    assert deepset(recovered) <= ones_mnemonics
    assert recovered[0] == {
        "olympic guilt acrobat romp dining inform withdraw brave lips quarter bulge thorn best wildlife alive yelp home security lilac eclipse",
    }
    assert recovered[1] == {
        "olympic guilt beard romp apart preach various garden always mayor solution acid quantity domestic slush zero fatigue disaster fluff romp",
    }

    # OK, we've recovered 2 1/1 groups.  Now, let's see if we can expand an existing threshold/count
    # group to increase the group's member count.  Let's increase Frens from a 3/6 to a larger 3/10
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(ones_mnemonics[0], ones_mnemonics[3]),
        expand=[(3, 10)],
    )
    assert ems.decrypt(b"") == ones
    assert not deepset(recovered) <= ones_mnemonics  # No longer a subset!
    assert (
        deepset(ones_mnemonics[3]) < recovered[3]
    )  # In fact, original group 3 is now a subset!
    # print(
    #     json.dumps(
    #         {str(ems): group for ems, group in recovered.items()}, indent=4, default=str
    #     )
    # )


def test_group_expand_failures():
    # Too many mnemonics are disallowed
    with pytest.raises(ValueError):
        ((ems, recovered),) = shamir.group_ems_mnemonics(
            set.union(ones_mnemonics[0], ones_mnemonics[3]),
            expand=[(3, 17)],
        )
    # Replacing a multi-Share group is disallowed if 'strict'
    with pytest.raises(MnemonicError):
        ((ems, recovered),) = shamir.group_ems_mnemonics(
            set.union(ones_mnemonics[0], ones_mnemonics[3]),
            expand=[(3, 1)],
            strict=True,
        )
    # ... but allowed if not 'strict'
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(ones_mnemonics[0], ones_mnemonics[3]),
        expand=[(3, 1)],
    )
    # And the resultant single-mnemonic group is usable to recover the Encrypted Master Secret
    # print(
    #     json.dumps(
    #         {str(ems): group for ems, group in recovered.items()}, indent=4, default=str
    #     )
    # )
    ((ems, recovered),) = shamir.group_ems_mnemonics(
        set.union(recovered[0], recovered[3]),
    )
    assert ems.decrypt(b"") == ones
