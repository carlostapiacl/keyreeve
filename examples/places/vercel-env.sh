#!/bin/sh
# Replaces a Vercel production variable with the new key, which arrives on stdin. Uses the vercel command.
# Run it in a folder linked to the project. Copy to ~/.keyreeve/providers and set the name and folder.
name="YOUR_VARIABLE"
folder="$HOME/path/to/project"
key=$(cat)
cd "$folder" || { echo '{"result":"no_result","message":"The project folder was not found"}'; exit 0; }
vercel env rm "$name" production --yes >/dev/null 2>&1
if printf '%s' "$key" | vercel env add "$name" production >/dev/null 2>&1; then
  echo '{"message":"Vercel variable updated"}'
else
  echo '{"result":"no_result","message":"vercel could not set the variable"}'
fi
