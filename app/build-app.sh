#!/bin/bash
# Builds Keyreeve.app and keyreeve-vault for this Mac, with the Command Line Tools alone.
# SwiftPM makes no app bundles, so the bundle is written by hand.
set -euo pipefail
cd "$(dirname "$0")"

swift build -c release
BIN=$(swift build -c release --show-bin-path)
APP="dist/Keyreeve.app"
mkdir -p "$APP/Contents/MacOS"
cp "$BIN/Keyreeve" "$APP/Contents/MacOS/Keyreeve"
cp "$BIN/keyreeve-vault" dist/keyreeve-vault
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Keyreeve</string>
    <key>CFBundleIdentifier</key><string>io.github.carlostapiacl.keyreeve</string>
    <key>CFBundleExecutable</key><string>Keyreeve</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST
codesign --force --sign - dist/keyreeve-vault
codesign --force --sign - "$APP"
echo "Built $APP and dist/keyreeve-vault"
