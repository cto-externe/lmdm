#!/usr/bin/env bash
# SPDX-License-Identifier: EUPL-1.2
# SPDX-FileCopyrightText: 2026 CTO Externe
#
# install-tailwind.sh — installe le binaire Tailwind standalone dans bin/
# Usage : ./scripts/install-tailwind.sh [version]   (défaut v3.4.17)
set -euo pipefail

VERSION="${1:-v3.4.17}"
TARGET_DIR="${TAILWIND_DIR:-bin}"
mkdir -p "$TARGET_DIR"

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  ASSET="tailwindcss-linux-x64" ;;
    Linux-aarch64) ASSET="tailwindcss-linux-arm64" ;;
    Darwin-x86_64) ASSET="tailwindcss-macos-x64" ;;
    Darwin-arm64)  ASSET="tailwindcss-macos-arm64" ;;
    *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2 ; exit 2 ;;
esac

URL="https://github.com/tailwindlabs/tailwindcss/releases/download/${VERSION}/${ASSET}"
echo "Downloading $URL"
curl -fsSL -o "$TARGET_DIR/tailwindcss" "$URL"
chmod +x "$TARGET_DIR/tailwindcss"
echo "Installed $TARGET_DIR/tailwindcss ($VERSION)"
"$TARGET_DIR/tailwindcss" --help | head -1
