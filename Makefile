TOOL_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

.PHONY: install update uninstall dev test lint

# Install nexa globally (available as 'nexa' anywhere in terminal)
install:
	pipx install $(TOOL_DIR) --force

# Update after code changes (run this after git pull or edits)
update:
	pipx install $(TOOL_DIR) --force

# Remove global install
uninstall:
	pipx uninstall nexa

# Dev install (editable, in local .venv — use .venv/bin/nexa)
dev:
	python3 -m venv $(TOOL_DIR)/.venv
	$(TOOL_DIR)/.venv/bin/pip install -e "$(TOOL_DIR)[dev]" -q

# Run tests
test:
	$(TOOL_DIR)/.venv/bin/pytest $(TOOL_DIR)/tests/ -v

# Quick smoke test
smoke:
	nexa version
	echo "cfbenchmarks.com" | nexa scan --no-subdomain --depth 1 --max-pages 3 --format jsonl
