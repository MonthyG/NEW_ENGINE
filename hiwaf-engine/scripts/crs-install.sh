#!/usr/bin/env bash
# Install an OWASP CRS release beside the engine's built-in rules, so the
# console (Settings > System > Rule set) can switch to it without a restart.
#
#   bash scripts/crs-install.sh 4.30.0
#
# The release is checked against the CRS project's signing key before it is
# unpacked; the key's fingerprint is pinned below (published at
# https://coreruleset.org/docs/1-getting-started/1-1-crs-installation/).
set -euo pipefail

VERSION="${1:-}"
DATA="${HIWAF_DATA:-/data/hiwaf}"
FPR="36006F0E0BA167832158821138EEACA1AB8A6E72"
KEY_URL="https://coreruleset.org/security.asc"
BASE="https://github.com/coreruleset/coreruleset/releases/download"

say() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ "$VERSION" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "usage: $0 <version>, for example $0 4.30.0"
command -v gpg >/dev/null || die "gpg is needed to check the release signature"
command -v curl >/dev/null || die "curl is needed to download the release"

DEST="$DATA/rulesets/$VERSION"
[ -e "$DEST" ] && die "$DEST already exists; remove it first to reinstall"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"

TAR="coreruleset-$VERSION-minimal.tar.gz"
say "Downloading CRS $VERSION"
curl -fsSL "$KEY_URL" -o "$WORK/key.asc"
curl -fsSL "$BASE/v$VERSION/$TAR" -o "$WORK/$TAR" || die "no release v$VERSION at $BASE"
curl -fsSL "$BASE/v$VERSION/$TAR.asc" -o "$WORK/$TAR.asc"

say "Checking the signature"
gpg --batch --quiet --import "$WORK/key.asc" 2>/dev/null
gpg --batch --with-colons --fingerprint | grep -q "^fpr:::::::::$FPR:" || die "the downloaded key is not the CRS key $FPR"
# --status-fd lets us require a good signature by that exact key: VALIDSIG's
# last field is the fingerprint of the signing key's primary key
gpg --batch --status-fd 1 --verify "$WORK/$TAR.asc" "$WORK/$TAR" 2>/dev/null | grep -qE "^\[GNUPG:\] VALIDSIG .* $FPR\$" \
  || die "the signature on $TAR does not check out; not installing"

say "Unpacking to $DEST"
mkdir -p "$WORK/x"
tar -xzf "$WORK/$TAR" -C "$WORK/x" --no-same-owner
SRC="$WORK/x/coreruleset-$VERSION"
[ -f "$SRC/crs-setup.conf.example" ] && [ -f "$SRC/rules/REQUEST-901-INITIALIZATION.conf" ] || die "unexpected release layout"
mkdir -p "$DEST"
cp -r "$SRC/crs-setup.conf.example" "$SRC/rules" "$SRC/LICENSE" "$DEST/"
chmod -R a+rX "$DEST"

say "Installed CRS $VERSION"
echo "Switch to it in the console: Settings > System > Rule set. If the engine"
echo "can't load it, the switch is refused and the current rules stay."
