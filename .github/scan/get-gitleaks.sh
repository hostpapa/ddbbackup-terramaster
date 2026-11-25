#!/bin/bash
# Put the pinned gitleaks release in DIR (DIR/gitleaks), after checking the
# download against the SHA-256 below. Used by the build server's gate and by
# the store repository's workflows, so both run the same version.
#
#   get-gitleaks.sh <dir>
#
# To move to a newer version, take the SHA-256 of the linux_x64 tarball from
# the release's checksums file (or the "digest" of the asset in the GitHub
# API) and change both lines.
set -euo pipefail

VERSION=8.30.1
SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb

DIR="${1:?usage: get-gitleaks.sh <dir>}"
TGZ="$DIR/gitleaks_${VERSION}_linux_x64.tar.gz"
mkdir -p "$DIR"

# The tarball is kept, so the build server downloads it once; it is checked
# (and the binary unpacked again) on every run.
if ! { [ -f "$TGZ" ] && echo "$SHA256  $TGZ" | sha256sum -c --quiet - 2>/dev/null; }; then
  curl -fsSL --retry 3 -o "$TGZ.part" \
    "https://github.com/gitleaks/gitleaks/releases/download/v$VERSION/gitleaks_${VERSION}_linux_x64.tar.gz"
  echo "$SHA256  $TGZ.part" | sha256sum -c --quiet - || { rm -f "$TGZ.part"; echo "get-gitleaks: checksum mismatch" >&2; exit 1; }
  mv "$TGZ.part" "$TGZ"
fi
tar -xzf "$TGZ" -C "$DIR" gitleaks
chmod 755 "$DIR/gitleaks"
echo "gitleaks $VERSION in $DIR"
