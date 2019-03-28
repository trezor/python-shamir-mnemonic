.PHONY: tests

tests:
	pytest

style_check:
	isort --check-only --recursive shamir_mnemonic/ *.py
	black shamir_mnemonic/ *.py --check

style:
	black shamir_mnemonic/ *.py
	isort -y --recursive shamir_mnemonic/ *.py
