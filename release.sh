#!/usr/bin/env bash

set -euo pipefail

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
TAG="v${VERSION}"

if [[ -z "$VERSION" ]]; then
    echo "ERROR: Could not determine version from Cargo.toml."
    exit 1
fi

echo "========================================"
echo " Unified DNS Release Preflight"
echo " Version: ${VERSION}"
echo " Tag:     ${TAG}"
echo "========================================"
echo

echo "[1/10] Checking required files..."

for file in Cargo.toml Cargo.lock README.md LICENSE .github/workflows/release.yml; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing required file: $file"
        exit 1
    fi
done

echo "OK"
echo

echo "[2/10] Checking Git working tree..."

if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: Git working tree is not clean."
    echo
    git status --short
    echo
    echo "Commit or stash your changes before releasing."
    exit 1
fi

echo "OK"
echo

echo "[3/10] Checking Cargo.lock..."

if ! cargo metadata --locked --no-deps >/dev/null 2>&1; then
    echo "ERROR: Cargo.lock is missing or out of date."
    echo "Run: cargo check"
    exit 1
fi

echo "OK"
echo

echo "[4/10] Checking release version..."

PACKAGE_VERSION="$(cargo metadata --format-version 1 --no-deps \
    | sed -n 's/.*"name":"unified-dns","version":"\([^"]*\)".*/\1/p')"

if [[ "$PACKAGE_VERSION" != "$VERSION" ]]; then
    echo "ERROR: Cargo metadata version does not match Cargo.toml."
    echo "Cargo.toml: ${VERSION}"
    echo "Metadata:   ${PACKAGE_VERSION}"
    exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "ERROR: Git tag ${TAG} already exists."
    echo "If you are intentionally recreating the tag, remove it manually first."
    exit 1
fi

echo "Version ${VERSION} OK"
echo

echo "[5/10] Running rustfmt..."

cargo fmt --all -- --check

echo "OK"
echo

echo "[6/10] Running cargo check..."

cargo check --release --locked

echo "OK"
echo

echo "[7/10] Running tests..."

cargo test --release --locked

echo "OK"
echo

echo "[8/10] Running clippy..."

cargo clippy --release --locked --all-targets -- -D warnings

echo "OK"
echo

echo "[9/10] Verifying release workflow packaging..."

WORKFLOW=".github/workflows/release.yml"

if ! grep -q 'cp LICENSE' "$WORKFLOW"; then
    echo "WARNING: release workflow does not explicitly package LICENSE."
fi

if ! grep -q 'sha256sum "dist/\${{ matrix.artifact }}.tar.gz"' "$WORKFLOW"; then
    echo "ERROR: release workflow checksum path does not match expected dist/ path."
    exit 1
fi

if ! grep -q 'tar -C dist -czf "dist/\${{ matrix.artifact }}.tar.gz"' "$WORKFLOW"; then
    echo "ERROR: release workflow archive path does not match expected dist/ path."
    exit 1
fi

echo "OK"
echo

echo "[10/10] Checking release metadata..."

LICENSE_TYPE="$(sed -n 's/^license = "\(.*\)"/\1/p' Cargo.toml | head -n1)"

if [[ "$LICENSE_TYPE" == "MIT" && ! -s LICENSE ]]; then
    echo "ERROR: Cargo.toml declares MIT license but LICENSE is empty."
    exit 1
fi

if [[ ! -s README.md ]]; then
    echo "ERROR: README.md is empty."
    exit 1
fi

echo "OK"
echo

echo "========================================"
echo " PRE-FLIGHT PASSED"
echo "========================================"
echo
echo "Ready to release ${TAG}."
echo
echo "The following commands will be run:"
echo
echo "  git add -A"
echo "  git commit -m \"Release ${TAG}\""
echo "  git push origin main"
echo "  git tag -a ${TAG} -m \"Unified DNS ${TAG}\""
echo "  git push origin ${TAG}"
echo

read -r -p "Create and push ${TAG}? [y/N] " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo
    echo "Release cancelled. Nothing was committed or tagged."
    exit 0
fi

echo
echo "[RELEASE] Committing..."

git add -A
git commit -m "Release ${TAG}"

echo
echo "[RELEASE] Pushing main..."

git push origin main

echo
echo "[RELEASE] Creating tag ${TAG}..."

git tag -a "$TAG" -m "Unified DNS ${TAG}"

echo
echo "[RELEASE] Pushing tag ${TAG}..."

git push origin "$TAG"

echo
echo "========================================"
echo " RELEASE ${TAG} PUSHED"
echo "========================================"
echo
echo "GitHub Actions should now build and publish the release."
