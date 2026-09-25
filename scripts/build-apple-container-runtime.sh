#!/usr/bin/env bash
set -euo pipefail

# Build the Apple Container runtime that coop's `apple-container` feature
# build requires, and install it into a directory you own.
#
# Stock Apple Container has no per-machine network or SSH-agent switch, so
# coop refuses to boot guests on it. The fork vendored at vendor/container
# (github.com/chr33s/container) adds `machine create --network` and
# `--no-ssh-agent` and reports both in `machine inspect`. This script builds
# that submodule in release mode, labelled `<base>+coop.<commit>` so coop's
# version check accepts it, and unpacks Apple's installer payload into PREFIX.
# It never uses sudo and never starts or stops the Apple Container service.
#
# Usage:
#   scripts/build-apple-container-runtime.sh [PREFIX]
#     PREFIX defaults to ~/.local/opt/coop-apple-container
#
# Then point coop at it (config.toml of the apple-container build):
#   [apple_container]
#   binary = "<PREFIX>/bin/container"
# and run that runtime's service instead of any other installation's; see
# docs/backends.md. Requires Xcode on an Apple Silicon Mac.

# The fork tracks upstream main after this release.
UPSTREAM_BASE_VERSION="1.4.1"

case "${1:-}" in
    -h | --help)
        sed -n '4,23p' "$0" | sed -E 's/^# ?//'
        exit 0
        ;;
esac
prefix="${1:-${HOME}/.local/opt/coop-apple-container}"

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "error: the Apple Container runtime needs an Apple Silicon Mac" >&2
    exit 1
fi
if [[ "${prefix}" != /* ]]; then
    echo "error: PREFIX must be an absolute path: ${prefix}" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
src="${repo_root}/vendor/container"
if [[ ! -f "${src}/Package.swift" ]]; then
    echo ">> initialising vendor/container submodule"
    git -C "${repo_root}" submodule update --init vendor/container
fi

commit="$(git -C "${src}" rev-parse --short=7 HEAD)"
version="${UPSTREAM_BASE_VERSION}+coop.${commit}"
if [[ -n "$(git -C "${src}" status --porcelain --untracked-files=no)" ]]; then
    version="${version}-dirty"
fi

echo ">> building Apple Container ${version}"
make -C "${src}" BUILD_CONFIGURATION=release RELEASE_VERSION="${version}" build
mkdir -p "${prefix}"
# `install` with an empty SUDO unpacks the package payload into DEST_DIR as
# the current user.
make -C "${src}" BUILD_CONFIGURATION=release RELEASE_VERSION="${version}" \
    DEST_DIR="${prefix}/" SUDO= install

echo ">> installed: $("${prefix}/bin/container" --version)"
cat <<EOF
>> add to the apple-container build's config.toml:
   [apple_container]
   binary = "${prefix}/bin/container"
>> stop any other Apple Container service, then start this one:
   ${prefix}/bin/container system start
EOF
