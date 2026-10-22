#!/usr/bin/env bash
# make_ipa.sh — package ave2_exploit into a sideloadable ipa
#
# Layout produced:
#   Payload/ave2_exploit.app/
#     ave2_exploit          (arm64 binary, ldid-signed with entitlements)
#     Info.plist
#     _CodeSignature/       (ldid creates)
#
# Usage: ./make_ipa.sh <path-to-arm64-binary> [output.ipa]
set -euo pipefail

BIN="$1"
OUT="${2:-ave2_exploit.ipa}"
ENT="$(dirname "$0")/../resources/entitlements.plist"
INFO="$(dirname "$0")/../resources/Info.plist"

STAGE="$(mktemp -d)"
APP="$STAGE/Payload/ave2_exploit.app"
mkdir -p "$APP"

cp "$BIN" "$APP/ave2_exploit"
cp "$INFO" "$APP/Info.plist"

# ldid: pseudo-sign with entitlements (no developer cert needed)
ldid -S"$ENT" "$APP/ave2_exploit"

cd "$STAGE"
zip -qr "$OUT" Payload
echo "ipa written: $OUT"
rm -rf "$STAGE"
