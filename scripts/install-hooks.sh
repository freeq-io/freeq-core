#!/usr/bin/env bash
set -euo pipefail

if [ ! -d ".git" ]; then
    echo "Error: Must be run from root of Git repo." >&2
    exit 1
fi

cp scripts/git-pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo "Git pre-commit guard successfully activated."
