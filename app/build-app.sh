#!/bin/bash
# Builds Keyreeve.app and keyreeve-vault for this Mac, with the Command Line Tools alone.
# SwiftPM makes no app bundles, so the bundle is written by hand.
set -euo pipefail
cd "$(dirname "$0")"

cargo build --release --locked --manifest-path ../Cargo.toml
swift build -c release
BIN=$(swift build -c release --show-bin-path)
APP="dist/Keyreeve.app"
rm -f "$APP/Contents/MacOS/Keyreeve" "$APP/Contents/MacOS/keyreeve-cli" "$APP/Contents/MacOS/keyreeve-vault"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
swift Tools/make-icon.swift .build/AppIcon.iconset
iconutil -c icns .build/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"
cp "$BIN/Keyreeve" "$APP/Contents/MacOS/Keyreeve"
# Not "keyreeve": most Mac disks ignore case, so it would replace the app itself.
cp ../target/release/keyreeve "$APP/Contents/MacOS/keyreeve-cli"
cp "$BIN/keyreeve-vault" dist/keyreeve-vault
# keyreeve-vault looks for the proxy beside itself, here as in the bundle.
cp ../target/release/keyreeve dist/keyreeve-cli
# A rotation saves each new key through this, since saving needs no fingerprint.
cp "$BIN/keyreeve-vault" "$APP/Contents/MacOS/keyreeve-vault"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Keyreeve</string>
    <key>CFBundleIdentifier</key><string>io.github.carlostapiacl.keyreeve</string>
    <key>CFBundleExecutable</key><string>Keyreeve</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
codesign --force --sign - dist/keyreeve-vault
codesign --force --sign - dist/keyreeve-cli
codesign --force --sign - "$APP/Contents/MacOS/keyreeve-cli"
codesign --force --sign - "$APP/Contents/MacOS/keyreeve-vault"
codesign --force --sign - "$APP"
echo "Built $APP and dist/keyreeve-vault"
