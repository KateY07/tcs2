#!/bin/sh
# Run on Linux x86_64 with the .NET 10 SDK, clang and zlib1g-dev (NativeAOT cannot be cross-compiled from Windows).
# Usage: _linux/package-linux.sh <version> [output-dir]
set -eu
VERSION=${1:?version}; OUT=${2:-./_out}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
STAGE=$(mktemp -d)/tcs-$VERSION-linux-x64
mkdir -p "$STAGE" "$OUT"
dotnet publish "$ROOT/tcs.csproj" -c Release -r linux-x64 -o "$STAGE/build"
install -m 755 "$STAGE/build/tcs" "$STAGE/tcs"
install -m 755 "$STAGE/build/tcs" "$STAGE/tcsd"
install -m 644 "$ROOT/_linux/tcsd.service" "$ROOT/_linux/README-linux.txt" "$STAGE/"
rm -rf "$STAGE/build"
tar -C "$(dirname "$STAGE")" -czf "$OUT/tcs-$VERSION-linux-x64.tar.gz" "tcs-$VERSION-linux-x64"
(cd "$OUT" && sha256sum "tcs-$VERSION-linux-x64.tar.gz" > "tcs-$VERSION-linux-x64.tar.gz.sha256")
echo "$OUT/tcs-$VERSION-linux-x64.tar.gz"
