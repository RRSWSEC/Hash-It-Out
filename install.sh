#!/usr/bin/env bash
# one-command install - after this, hashitout works from anywhere
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
pip install -e . --quiet
echo "Hash It Out installed - run: hashitout --help"
