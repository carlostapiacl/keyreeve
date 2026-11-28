#!/bin/sh
# Draws the screenshots of the README and the site from the real views over made-up keys
# (Tests/AppTests/DocsScreenshots.swift), puts them in docs/img and docs/img/es, and makes a short tour GIF
# of each language when ffmpeg is there. Run it after a change to the window.
set -eu
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
KEYREEVE_DOCS_SHOTS="$out" swift test --filter DocsScreenshots >/dev/null
for lang in en es; do
  dest=../docs/img
  [ "$lang" = es ] && dest=../docs/img/es
  mkdir -p "$dest"
  for shot in home keys key-usage agents vault; do
    sips --resampleWidth 1600 "$out/$lang/$shot.png" --out "$dest/$shot.png" >/dev/null
  done
  if command -v ffmpeg >/dev/null; then
    list="$out/$lang.txt"
    : >"$list"
    for shot in home keys key-usage agents; do
      printf "file '%s'\nduration 2.5\n" "$out/$lang/$shot.png" >>"$list"
    done
    printf "file '%s'\n" "$out/$lang/agents.png" >>"$list"
    ffmpeg -loglevel error -y -f concat -safe 0 -i "$list" \
      -vf "scale=1000:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128[p];[b][p]paletteuse=dither=none" \
      -loop 0 "$dest/tour.gif"
  else
    echo "ffmpeg is not installed: the tour GIF was not made" >&2
  fi
done
echo "Screenshots in docs/img and docs/img/es"
