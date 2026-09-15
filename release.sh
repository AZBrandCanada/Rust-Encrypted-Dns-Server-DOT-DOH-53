#!/usr/bin/env bash

set -euo pipefail

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
TAG="v${VERSION}"

if [[ -z "$VERSION" ]]; then
    echo "ERROR: Could not determine version from Cargo.toml."
    exit 1
fi

echo "========================================"
echo " Unified DNS Release"
echo " Version: ${VERSION}"
echo " Tag:     ${TAG}"
echo "========================================"
echo

echo "[1/12] Checking required files..."

for file in Cargo.toml Cargo.lock README.md LICENSE .github/workflows/release.yml; do
    if [[ ! -f "$file" ]]; then
        echo "ERROR: Missing required file: $file"
        exit 1
    fi
done

echo "OK"
echo

echo "[2/12] Formatting source..."

cargo fmt --all

echo "OK"
echo

echo "[3/12] Updating Cargo.lock..."

cargo check --release

echo "Cargo.lock is synchronized."
echo

echo "[4/12] Checking release version..."

PACKAGE_VERSION="$(
    cargo metadata --format-version 1 --no-deps --locked |
    sed -n 's/.*"name":"unified-dns","version":"\([^"]*\)".*/\1/p'
)"

if [[ "$PACKAGE_VERSION" != "$VERSION" ]]; then
    echo "ERROR: Cargo metadata version does not match Cargo.toml."
    echo "Cargo.toml: ${VERSION}"
    echo "Metadata:   ${PACKAGE_VERSION}"
    exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
    echo "ERROR: Git tag ${TAG} already exists locally."
    echo "Refusing to overwrite an existing release tag."
    exit 1
fi

if git ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1; then
    echo "ERROR: Git tag ${TAG} already exists on origin."
    echo "Refusing to overwrite an existing release tag."
    exit 1
fi

echo "Version ${VERSION} OK"
echo "Tag ${TAG} does not already exist."
echo

echo "[5/12] Running format verification..."

cargo fmt --all -- --check

echo "OK"
echo

echo "[6/12] Running locked cargo check..."

cargo check --release --locked

echo "OK"
echo

echo "[7/12] Running tests..."

cargo test --release --locked

echo "OK"
echo

echo "[8/12] Running clippy..."

cargo clippy --release --locked --all-targets -- -D warnings

echo "OK"
echo

echo "[9/12] Verifying release workflow..."

WORKFLOW=".github/workflows/release.yml"

if ! grep -q 'cp LICENSE' "$WORKFLOW"; then
    echo "ERROR: Release workflow does not package LICENSE."
    exit 1
fi

if ! grep -q 'tar -C dist -czf "dist/\${{ matrix.artifact }}.tar.gz"' "$WORKFLOW"; then
    echo "ERROR: Release workflow archive path is incorrect."
    exit 1
fi

if ! grep -q 'sha256sum "dist/\${{ matrix.artifact }}.tar.gz"' "$WORKFLOW"; then
    echo "ERROR: Release workflow checksum path is incorrect."
    exit 1
fi

if ! grep -q 'unified-dns-linux-x86_64' "$WORKFLOW"; then
    echo "ERROR: x86_64 release target is missing."
    exit 1
fi

if ! grep -q 'unified-dns-linux-aarch64' "$WORKFLOW"; then
    echo "ERROR: ARM64 release target is missing."
    exit 1
fi

echo "OK"
echo

echo "[10/12] Checking release metadata..."

LICENSE_TYPE="$(
    sed -n 's/^license = "\(.*\)"/\1/p' Cargo.toml |
    head -n1
)"

if [[ "$LICENSE_TYPE" == "MIT" && ! -s LICENSE ]]; then
    echo "ERROR: Cargo.toml declares MIT license but LICENSE is missing or empty."
    exit 1
fi

if [[ ! -s README.md ]]; then
    echo "ERROR: README.md is empty."
    exit 1
fi

if [[ ! -s Cargo.lock ]]; then
    echo "ERROR: Cargo.lock is missing or empty."
    exit 1
fi

echo "OK"
echo

echo "[11/12] Preparing Git..."

git add -A

if git diff --cached --quiet; then
    echo "No uncommitted changes."
    echo "Using the existing HEAD commit for ${TAG}."
else
    echo "Changes detected:"
    git diff --cached --stat
    echo
    echo "Creating release commit..."
    git commit -m "Release ${TAG}"
fi

echo

if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: Working tree is still dirty after preparation."
    git status --short
    exit 1
fi

CURRENT_BRANCH="$(git branch --show-current)"

if [[ "$CURRENT_BRANCH" != "main" ]]; then
    echo "ERROR: Release must be run from the main branch."
    echo "Current branch: ${CURRENT_BRANCH}"
    exit 1
fi

echo "Git working tree is clean."
echo "Current commit:"
git log -1 --oneline
echo

echo "[12/12] Final release confirmation..."

echo "========================================"
echo " PREFLIGHT CHECKS PASSED"
echo "========================================"
echo
echo "Version: ${VERSION}"
echo "Tag:     ${TAG}"
echo "Branch:  ${CURRENT_BRANCH}"
echo "Commit:  $(git rev-parse --short HEAD)"
echo

read -r -p "Push main, create ${TAG}, and push the tag? [y/N] " CONFIRM

if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo
    echo "Release cancelled."
    exit 0
fi

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
echo " RELEASE ${TAG} PUSHED SUCCESSFULLY"
echo "========================================"
echo
echo "GitHub Actions will now build and publish the release."
echo
echo "Release tag: ${TAG}"
echo "Commit:      $(git rev-parse --short HEAD)"