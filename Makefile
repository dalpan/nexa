TOOL_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
REPO_URL := https://github.com/dalpan/nexa

.PHONY: install update upgrade uninstall dev test smoke

# Install nexa globally (available as 'nexa' anywhere in terminal)
install:
	pipx install $(TOOL_DIR) --force

# Update from local folder (for development / after manual edits)
update:
	pipx install $(TOOL_DIR) --force
	@echo ""
	@nexa version

# Pull latest from GitHub then reinstall
upgrade:
	@echo "Pulling latest from $(REPO_URL)..."
	git -C $(TOOL_DIR) pull origin main
	@echo "Reinstalling..."
	pipx install $(TOOL_DIR) --force
	@echo ""
	@nexa version

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
