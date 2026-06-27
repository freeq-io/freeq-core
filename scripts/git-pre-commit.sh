#!/usr/bin/env bash
set -euo pipefail

echo "[FreeQ Pre-Commit Guard] Evaluating project health..."

echo "Running cargo fmt check..."
cargo fmt -- --check

echo "Running cargo clippy audit analysis..."
cargo clippy --all-targets --all-features -- -D warnings

echo "Executing high-severity security test suites..."
cargo test --test security_audits -- --nocapture
