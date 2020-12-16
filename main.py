#!/usr/bin/env python3
""" From https://stackoverflow.com/a/16985066 to resolve `ImportError: attempted relative import with no known parent package` """
from shamir_mnemonic.cli import cli

def main():
    cli()

if __name__ == '__main__':
    main()
