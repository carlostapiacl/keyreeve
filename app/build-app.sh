#!/bin/bash
# Builds Keyreeve.app and keyreeve-vault for this Mac, with the Command Line Tools alone.
# SwiftPM makes no app bundles, so the bundle is written by hand.
set -euo pipefail
cd "$(dirname "$0")"

# KEYREEVE_UNIVERSAL=1 builds for Apple silicon and Intel in one bundle, as a release does. It needs both Rust
# targets (rustup target add aarch64-apple-darwin x86_64-apple-darwin) and Xcode for Swift.
SWIFT_ARCHS=()
if [ -n "${KEYREEVE_UNIVERSAL:-}" ]; then
    for target in aarch64-apple-darwin x86_64-apple-darwin; do
        cargo build --release --locked --manifest-path ../Cargo.toml --target "$target"
    done
    mkdir -p ../target/release
    lipo -create ../target/aarch64-apple-darwin/release/keyreeve ../target/x86_64-apple-darwin/release/keyreeve \
        -output ../target/release/keyreeve
    SWIFT_ARCHS=(--arch arm64 --arch x86_64)
else
    cargo build --release --locked --manifest-path ../Cargo.toml
fi
# The app carries the version of the release it comes from, as Cargo.toml says it.
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' ../Cargo.toml | head -1)
swift build -c release ${SWIFT_ARCHS[@]+"${SWIFT_ARCHS[@]}"}
BIN=$(swift build -c release ${SWIFT_ARCHS[@]+"${SWIFT_ARCHS[@]}"} --show-bin-path)
APP="dist/Keyreeve.app"
# A Keyreeve left running would go on with the old code over files the new one writes, and one from before a
# format change can drop what it does not know. It is quit here and opened again at the end.
# A copy installed in /Applications is kept the same as this build, so whatever opens Keyreeve gets this version.
INSTALLED="/Applications/Keyreeve.app"
# KEYREEVE_BUILD_ONLY=1 builds the bundle and leaves the Mac alone: no Keyreeve is quit, none is replaced. For a
# release, and for building beside a Keyreeve in use.
[ -n "${KEYREEVE_BUILD_ONLY:-}" ] && INSTALLED="/nonexistent/Keyreeve.app"
RUNNING=""
if [ -z "${KEYREEVE_BUILD_ONLY:-}" ] && pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1; then
    RUNNING=yes
    osascript -e 'tell application id "io.github.carlostapiacl.keyreeve" to quit' >/dev/null 2>&1 || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1 || break; sleep 1; done
    # Asking to quit needs this terminal to be allowed to control Keyreeve, and is refused quietly when it is not.
    if pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1; then
        pkill -TERM -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1 || break; sleep 1; done
    fi
    if pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1; then
        echo "Keyreeve is still running and did not quit. Quit it from the menu bar and run this again." >&2
        exit 1
    fi
fi
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
    <key>CFBundleShortVersionString</key><string>${VERSION%%-*}</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
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
if [ -d "$INSTALLED" ]; then
    ditto "$APP" "$INSTALLED.new" && rm -rf "$INSTALLED.old" && mv "$INSTALLED" "$INSTALLED.old" && mv "$INSTALLED.new" "$INSTALLED" && rm -rf "$INSTALLED.old"
    echo "Updated $INSTALLED"
fi
if [ -d "$INSTALLED" ]; then
    # The build has the same bundle id as the installed copy, so Spotlight and Launchpad would show two Keyreeves
    # and opening one by its id could start the build. Only the installed copy stays known to the Mac.
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "$APP" >/dev/null 2>&1 || true
fi
if [ -n "$RUNNING" ]; then
    if [ -d "$INSTALLED" ]; then open "$INSTALLED"; else open "$APP"; fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1 && break; sleep 1; done
    if pgrep -f "Keyreeve.app/Contents/MacOS/Keyreeve\$" >/dev/null 2>&1; then
        echo "Keyreeve was open, so it was opened again with this build"
    else
        echo "Keyreeve was open and did not start again: open it from Applications." >&2
    fi
fi
