# Makefile for secret_scanner
#
# Provides convenience targets for common tasks. Makefiles use tabs
# for indentation (not spaces) — this is a Makefile syntax requirement.
#
# Usage:
#   make test    — run the full test suite with pytest
#   make scan    — run the scanner against test_configs/
#   make scan-json — run the scanner and output JSON results

.PHONY: test scan scan-json

test:
	python -m pytest tests/ -v

scan:
	python -m secret_scanner

scan-json:
	python -m secret_scanner --output json
