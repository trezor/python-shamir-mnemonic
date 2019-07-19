import os.path

from setuptools import setup

# fmt: off
REQUIREMENTS = [
    "click>=7,<8",
    "colorama",
]
# fmt: on

HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "README.rst"), encoding="utf-8") as f:
    long_description = f.read()


setup(
    name="shamir-mnemonic",
    version="0.1.0",
    description="SLIP-39 Shamir Mnemonics",
    long_description=long_description,
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
