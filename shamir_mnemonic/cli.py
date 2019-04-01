import os

import click
from click import style

from .shamir_mnemonic import ShamirMnemonic

shamir = ShamirMnemonic()


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
    metavar="M N",
    multiple=True,
    help="Add a M-of-N group to the collection",
)
@click.option(
    "-t",
    "--threshold",
    type=int,
    default=1,
    help="Number of groups required for recovery",
)
@click.option("-E", "--exponent", type=int, default=0, help="Iteration exponent")
@click.option("-s", "--strength", type=int, default=128, help="Secret strength in bits")
@click.option(
    "-S", "--master-secret", help="Hex-encoded custom master secret", metavar="HEX"
)
@click.option(
    "-p", "password_prompt", help="Prompt for passphrase for recovery", is_flag=True
)
@click.option("--password", help="Supply passphrase for recovery")
def create(
    scheme,
    groups,
    threshold,
    exponent,
    master_secret,
    password,
    password_prompt,
    strength,
):
    """Create a Shamir mnemonic set
    
    SCHEME can be one of:
    
    \b
    single: Create a single recovery seed.
    2of3: Create 3 shares. Require 2 of them to recover the seed.
          (You can use any number up to 32. Try 3of5, 4of4, 1of7...)
    master: Create 1 master share that can recover the seed by itself,
            plus a 3-of-5 group: 5 shares, with 3 required for recovery.
            Keep the master for yourself, give the 5 shares to trusted friends.
    custom: Specify configuration with -g arguments.
    """
    if password_prompt and password:
        raise click.ClickException("Use only one of: -p, --password")

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
        pass
    else:
        raise click.ClickException(f"Unknown scheme: {scheme}")

    if master_secret is not None:
        try:
            secret_bytes = bytes.fromhex(master_secret)
        except Exception as e:
            raise click.BadOptionUsage(
                "master_secret", f"Secret bytes must be hex encoded"
            ) from e
    else:
        secret_bytes = os.urandom(strength // 8)

    if password_prompt:
        password = click.prompt(
            "Enter passphrase", hide_input=True, confirmation_prompt=True
        )
    if password:
        try:
            passphrase_bytes = password.encode("ascii")
        except UnicodeDecodeError:
            raise click.ClickException("Passphrase must be ASCII only")
    else:
        passphrase_bytes = b""

    mnemonics = shamir.generate_mnemonics(
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


if __name__ == "__main__":
    cli()
