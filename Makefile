# Makefile for secret_scanner
#
# Provides convenience targets for common tasks. Makefiles use tabs
# for indentation (not spaces) — this is a Makefile syntax requirement.
#
# Usage:
#   make test          — run the full test suite with pytest
#   make scan          — run the scanner against test_configs/
#   make scan-json     — run the scanner and output JSON results
#   make install-hooks — install the standalone pre-commit hook

.PHONY: test scan scan-json install-hooks

test:
	python -m pytest tests/ -v

scan:
	python -m secret_scanner

scan-json:
	python -m secret_scanner --output json

install-hooks:
	cp hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed. Staged files will be scanned on commit."
