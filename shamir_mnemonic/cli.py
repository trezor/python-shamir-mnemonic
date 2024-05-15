import secrets
import sys
from typing import Sequence, Tuple

try:
    import click
    from click import style

except ImportError:
    print("Required dependencies are missing. Install them with:")
    print("  pip install shamir_mnemonic[cli]")
    sys.exit(1)

from .recovery import RecoveryState
from .shamir import generate_mnemonics
from .share import Share
from .utils import MnemonicError


@click.group()
def cli() -> None:
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
    "--group-threshold",
    type=int,
    help="Number of groups required for recovery in the custom scheme.",
)
@click.option(
    "-x/-X",
    "--extendable/--no-extendable",
    is_flag=True,
    default=True,
    help="Extendable backup flag.",
)
@click.option("-E", "--exponent", type=int, default=0, help="Iteration exponent.")
@click.option(
    "-s", "--strength", type=int, default=128, help="Secret strength in bits."
)
@click.option(
    "-S", "--master-secret", help="Hex-encoded custom master secret.", metavar="HEX"
)
@click.option("-p", "--passphrase", help="Supply passphrase for recovery.")
def create(
    scheme: str,
    groups: Sequence[Tuple[int, int]],
    group_threshold: int,
    extendable: bool,
    exponent: int,
    master_secret: str,
    passphrase: str,
    strength: int,
) -> None:
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

    if (groups or group_threshold is not None) and scheme != "custom":
        raise click.BadArgumentUsage("To use -g/-t, you must select 'custom' scheme.")

    if scheme == "single":
        group_threshold = 1
        groups = [(1, 1)]
    elif scheme == "master":
        group_threshold = 1
        groups = [(1, 1), (3, 5)]
    elif "of" in scheme:
        try:
            m, n = map(int, scheme.split("of", maxsplit=1))
            group_threshold = 1
            groups = [(m, n)]
        except Exception as e:
            raise click.BadArgumentUsage(f"Invalid scheme: {scheme}") from e
    elif scheme == "custom":
        if group_threshold is None:
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
                "master_secret", "Secret bytes must be hex encoded"
            ) from e
    else:
        secret_bytes = secrets.token_bytes(strength // 8)

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
        group_threshold, groups, secret_bytes, passphrase_bytes, extendable, exponent
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


FINISHED = style("\u2713", fg="green", bold=True)
EMPTY = style("\u2717", fg="red", bold=True)
INPROGRESS = style("\u25cf", fg="yellow", bold=True)


def error(s: str) -> None:
    click.echo(style("ERROR: ", fg="red") + s)


@cli.command()
@click.option(
    "-p", "--passphrase-prompt", is_flag=True, help="Use passphrase after recovering"
)
def recover(passphrase_prompt: bool) -> None:
    recovery_state = RecoveryState()

    def print_group_status(idx: int) -> None:
        group_size, group_threshold = recovery_state.group_status(idx)
        group_prefix = style(recovery_state.group_prefix(idx), bold=True)
        bi = style(str(group_size), bold=True)
        if not group_size:
            click.echo(f"{EMPTY} {bi} shares from group {group_prefix}")
        else:
            prefix = FINISHED if group_size >= group_threshold else INPROGRESS
            bt = style(str(group_threshold), bold=True)
            click.echo(f"{prefix} {bi} of {bt} shares needed from group {group_prefix}")

    def print_status() -> None:
        bn = style(str(recovery_state.groups_complete()), bold=True)
        assert recovery_state.parameters is not None
        bt = style(str(recovery_state.parameters.group_threshold), bold=True)
        click.echo()
        if recovery_state.parameters.group_count > 1:
            click.echo(f"Completed {bn} of {bt} groups needed:")
        for i in range(recovery_state.parameters.group_count):
            print_group_status(i)

    while not recovery_state.is_complete():
        try:
            mnemonic_str = click.prompt("Enter a recovery share")
            share = Share.from_mnemonic(mnemonic_str)
            if not recovery_state.matches(share):
                error("This mnemonic is not part of the current set. Please try again.")
                continue
            if share in recovery_state:
                error("Share already entered.")
                continue

            recovery_state.add_share(share)
            print_status()

        except click.Abort:
            return
        except Exception as e:
            error(str(e))

    passphrase_bytes = b""
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

    try:
        master_secret = recovery_state.recover(passphrase_bytes)
    except MnemonicError as e:
        error(str(e))
        click.echo("Recovery failed")
        sys.exit(1)
    click.secho("SUCCESS!", fg="green", bold=True)
    click.echo(f"Your master secret is: {master_secret.hex()}")


if __name__ == "__main__":
    cli()
