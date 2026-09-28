#!/usr/bin/env bash
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

dependencies=$(mktemp)
trap 'rm -f "$dependencies"' EXIT

check_dependencies() {
    echo "Checking for deprecated OpenPGP packages: $1"
    # Keep package-loading errors fatal; do not hide them in a grep pipeline.
    go list -mod=readonly -deps -test ./... > "$dependencies"
    if grep -E '^golang\.org/x/crypto/openpgp(/|$)' "$dependencies"; then
        echo "OpenPGP is affected by GO-2026-5932. Remove its imports and reassess osv-scanner.toml." >&2
        return 1
    fi
}

# Include the host's default CGO setting, as well as portable release builds.
check_dependencies "host"
for target_os in linux darwin windows; do
    for target_arch in amd64 arm64; do
        GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
            check_dependencies "$target_os/$target_arch"
    done
done
