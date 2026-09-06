#!/usr/bin/env bash
# Builds openssl3_crypto.xcframework.zip from the five thin Apple dylibs in
# $1 (default: out). A convenience artifact for non-hooks consumers (ADR-0003);
# hook/build.dart never uses it.
set -euo pipefail
OUT="${1:-out}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME=libopenssl3_crypto

lipo -create "$OUT/$NAME.arm64.macos.dylib" "$OUT/$NAME.x64.macos.dylib" -output "$WORK/macos.dylib"
lipo -create "$OUT/$NAME.arm64.ios_sim.dylib" "$OUT/$NAME.x64.ios_sim.dylib" -output "$WORK/ios_sim.dylib"
cp "$OUT/$NAME.arm64.ios.dylib" "$WORK/ios.dylib"
for f in macos ios_sim ios; do
  install_name_tool -id "@rpath/openssl3_crypto.framework/openssl3_crypto" "$WORK/$f.dylib"
  codesign --force --sign - "$WORK/$f.dylib"
done
rm -rf "$OUT/openssl3_crypto.xcframework"
xcodebuild -create-xcframework \
  -library "$WORK/macos.dylib" \
  -library "$WORK/ios.dylib" \
  -library "$WORK/ios_sim.dylib" \
  -output "$OUT/openssl3_crypto.xcframework"
(cd "$OUT" && rm -f openssl3_crypto.xcframework.zip && zip -qry openssl3_crypto.xcframework.zip openssl3_crypto.xcframework && rm -rf openssl3_crypto.xcframework)
ls -la "$OUT/openssl3_crypto.xcframework.zip"
