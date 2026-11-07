#!/bin/sh
# Sets a GitHub Actions secret to the new key, which arrives on stdin. Uses the gh command you are signed in to.
# Copy to ~/.keyreeve/providers, set these two values, and add it as a button (see my-deploys.yaml).
repo="your-name/your-repo"
name="YOUR_SECRET_NAME"
if gh secret set "$name" --repo "$repo" >/dev/null 2>&1; then
  echo '{"message":"GitHub secret updated"}'
else
  echo '{"result":"no_result","message":"gh could not set the secret"}'
fi
