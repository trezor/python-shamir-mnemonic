from pathlib import Path

from setuptools import setup

# fmt: off
REQUIREMENTS = [
    "attrs",
    "click>=7,<8",
    "colorama",
]
# fmt: on

CWD = Path(__file__).resolve().parent


setup(
    name="shamir-mnemonic",
    version="0.2.0",
    description="SLIP-39 Shamir Mnemonics",
    long_description="\n".join(
        (
            (CWD / "README.rst").read_text(),
            (CWD / "CHANGELOG.rst").read_text(),
        )
    ),
    url="https://github.com/trezor/python-shamir-mnemonic",
    author="Satoshi Labs",
    packages=["shamir_mnemonic"],
    python_requires=">=3.6",
    install_requires=REQUIREMENTS,
    package_data={"shamir_mnemonic": ["wordlist.txt"]},
    entry_points={"console_scripts": ["shamir=shamir_mnemonic.cli:cli"]},
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3 :: Only",
    ],
)
