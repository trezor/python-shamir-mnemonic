import os
import sys
from collections import defaultdict, namedtuple

import click
from click import style

from . import (MnemonicError, combine_mnemonics, decode_mnemonic,
               generate_mnemonics, group_prefix, mnemonic_from_indices)


@click.group()
def cli():
    pass


@cli.command()
@click.argument("scheme")
@click.option(
    "-g",
    "--group",
    "groups",
    type=(int, int),
    metavar="T N",
    multiple=True,
    help="Add a T-of-N group to the custom scheme.",
)
@click.option(
    "-t",
    "--threshold",
    type=int,
    help="Number of groups required for recovery in the custom scheme.",
)
@click.option("-E", "--exponent", type=int, default=0, help="Iteration exponent.")
@click.option(
    "-s", "--strength", type=int, default=128, help="Secret strength in bits."
)
@click.option(
    "-S", "--master-secret", help="Hex-encoded custom master secret.", metavar="HEX"
)
@click.option("-p", "--passphrase", help="Supply passphrase for recovery.")
def create(scheme, groups, threshold, exponent, master_secret, passphrase, strength):
    """Create a Shamir mnemonic set
    
    SCHEME can be one of:
    
    \b
    single: Create a single recovery seed.
    2of3: Create 3 shares. Require 2 of them to recover the seed.
          (You can use any number up to 16. Try 3of5, 4of4, 1of7...)
    master: Create 1 master share that can recover the seed by itself,
            plus a 3-of-5 group: 5 shares, with 3 required for recovery.
            Keep the master for yourself, give the 5 shares to trusted friends.
    custom: Specify configuration with -t and -g options.
    """
    if passphrase and not master_secret:
        raise click.ClickException(
            "Only use passphrase in conjunction with an explicit master secret"
        )

    if (groups or threshold != None) and scheme != "custom":
        raise click.BadArgumentUsage(f"To use -g/-t, you must select 'custom' scheme.")

    if scheme == "single":
        threshold = 1
        groups = [(1, 1)]
    elif scheme == "master":
        threshold = 1
        groups = [(1, 1), (3, 5)]
    elif "of" in scheme:
        try:
            m, n = map(int, scheme.split("of", maxsplit=1))
            threshold = 1
            groups = [(m, n)]
        except Exception as e:
            raise click.BadArgumentUsage(f"Invalid scheme: {scheme}") from e
    elif scheme == "custom":
        if threshold is None:
            raise click.BadArgumentUsage(
                "Use '-t' to specify the number of groups required for recovery."
            )
        if not groups:
            raise click.BadArgumentUsage(
                "Use '-g T N' to add a T-of-N group to the collection."
            )
    else:
        raise click.ClickException(f"Unknown scheme: {scheme}")

    if any(m == 1 and n > 1 for m, n in groups):
        click.echo("1-of-X groups are not allowed.")
        click.echo("Instead, set up a 1-of-1 group and give everyone the same share.")
        sys.exit(1)

    if master_secret is not None:
        try:
            secret_bytes = bytes.fromhex(master_secret)
        except Exception as e:
            raise click.BadOptionUsage(
                "master_secret", f"Secret bytes must be hex encoded"
            ) from e
    else:
        secret_bytes = os.urandom(strength // 8)

    secret_hex = style(secret_bytes.hex(), bold=True)
    click.echo(f"Using master secret: {secret_hex}")

    if passphrase:
        try:
            passphrase_bytes = passphrase.encode("ascii")
        except UnicodeDecodeError:
            raise click.ClickException("Passphrase must be ASCII only")
    else:
        passphrase_bytes = b""

    mnemonics = generate_mnemonics(
        threshold, groups, secret_bytes, passphrase_bytes, exponent
    )

    for i, (group, (m, n)) in enumerate(zip(mnemonics, groups)):
        group_str = (
            style("Group ", fg="green")
            + style(str(i + 1), bold=True)
            + style(f" of {len(mnemonics)}", fg="green")
        )
        share_str = style(f"{m} of {n}", fg="blue", bold=True) + style(
            " shares required:", fg="blue"
        )
        click.echo(f"{group_str} - {share_str}")
        for g in group:
            click.echo(g)


MnemonicData = namedtuple(
    "MnemonicData",
    "str identifier exponent group_index group_threshold group_count index threshold value",
)


FINISHED = style("\u2713", fg="green", bold=True)
EMPTY = style("\u2717", fg="red", bold=True)
INPROGRESS = style("\u26ec", fg="yellow", bold=True)


def error(s):
    click.echo(style("ERROR: ", fg="red") + s)


@cli.command()
@click.option(
    "-p", "--passphrase-prompt", is_flag=True, help="Use passphrase after recovering"
)
def recover(passphrase_prompt):
    first_words = None
    group_threshold = None
    group_count = None
    groups = defaultdict(set)  # group idx : shares

    def make_group_prefix(idx):
        fake_group_prefix = group_prefix(0, 0, idx, group_threshold, group_count)
        group_word = mnemonic_from_indices(fake_group_prefix).split()[2]
        return " ".join(first_words + [group_word])

    def print_group_status(idx):
        group = groups[idx]
        group_prefix = style(make_group_prefix(idx), bold=True)
        bi = style(str(len(group)), bold=True)
        if not group:
            click.echo(f"{EMPTY} {bi} shares from group {group_prefix}")
        else:
            elem = next(iter(group))
            prefix = FINISHED if len(group) >= elem.threshold else INPROGRESS
            bt = style(str(elem.threshold), bold=True)
            click.echo(f"{prefix} {bi} of {bt} shares needed from group {group_prefix}")

    def group_is_complete(idx):
        group = groups[idx]
        if not group:
            return False
        return len(group) >= next(iter(group)).threshold

    def print_status():
        n_completed = len([idx for idx in groups if group_is_complete(idx)])
        bn = style(str(n_completed), bold=True)
        bt = style(str(group_threshold), bold=True)
        click.echo()
        if group_count > 1:
            click.echo(f"Completed {bn} of {bt} groups needed:")
        for i in range(group_count):
            print_group_status(i)

    def set_is_complete():
        n_completed = len([idx for idx in groups if group_is_complete(idx)])
        return n_completed >= group_threshold

    while group_threshold is None or not set_is_complete():
        try:
            mnemonic_str = click.prompt("Enter a recovery share")
            words = mnemonic_str.split()
            data = MnemonicData(mnemonic_str, *decode_mnemonic(mnemonic_str))

            if first_words and first_words != words[:2]:
                error("This mnemonic is not part of the current set. Please try again.")

            first_words = words[:2]
            group_threshold = data.group_threshold
            group_count = data.group_count

            groups[data.group_index].add(data)

            print_status()

        except click.Abort:
            return
        except Exception as e:
            error(str(e))

    try:
        all_data = set.union(*groups.values())
        all_mnemonics = [m.str for m in all_data]
        master_secret = combine_mnemonics(all_mnemonics)
    except MnemonicError as e:
        error(str(e))
        click.echo("Recovery failed")
        sys.exit(1)

    click.secho("SUCCESS!", fg="green", bold=True)
    if passphrase_prompt:
        while True:
            passphrase = click.prompt(
                "Enter passphrase", hide_input=True, confirmation_prompt=True
            )
            try:
                passphrase_bytes = passphrase.encode("ascii")
                break
            except UnicodeDecodeError:
                click.echo("Passphrase must be ASCII. Please try again.")
        master_secret = combine_mnemonics(all_mnemonics, passphrase_bytes)

    click.echo(f"Your master secret is: {master_secret.hex()}")


if __name__ == "__main__":
    cli()
