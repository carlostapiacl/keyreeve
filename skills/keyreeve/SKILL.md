---
name: keyreeve
description: Use API keys, tokens and OAuth sign-ins through keyreeve without ever reading their values, and without asking the person for more fingerprints than needed. Use when a task needs a key, token or password; when a command fails because a key is missing; when setting up a script, bot or coding agent that needs keys; or when a key "has no provider".
---

# keyreeve

The person keeps their keys in keyreeve, a vault on their Mac. You never read a key from a file, an env file or the
clipboard, and never print one. You use a key through keyreeve: the command gets a **stand-in** of the same shape, and a
local proxy puts the real key only on requests to that key's provider.

## Use a key

1. `list_keys`: the keys offered to you, their level and their variable. A key that is not listed may still exist, not
   offered. Before saying it does not exist, call `list_keys all=true reason=...`: the person approves once and you see
   every key's name for an hour, never a value.
2. `use_key key=<id> command=[...] reason=...`: runs the command with the stand-in in the key's variable. Any command
   works, `curl` included. The key goes in a header, never in a URL.
3. If the key is closed, `request_access key=<id> duration=4h reason=...`. **Ask for as long as the task takes** (4h, 8h),
   not five minutes: each new request is another fingerprint.
4. Several keys for one task: ask once. `request_access keys=[a,b,c]`, or from a terminal
   `keyreeve-vault use a,b,c --as a=VAR_A,b=VAR_B -- <command>`: one window, one fingerprint.
5. A program that truly needs the real value: `run_with_key` (the program is pinned by its SHA-256). It asks for a
   fingerprint every time, so it is the last resort.

From a script: `keyreeve-vault use <id> --as VAR -- <command>`. Avoid `get` and `--real`.

## A coding agent or an MCP server

- Run the whole agent under `use`, so its config, database and logs only ever hold stand-ins:
  `keyreeve-vault use openai,github --as openai=OPENAI_API_KEY,github=GITHUB_TOKEN --for 8h -- opencode`.
  Its config points at the variables (`{env:OPENAI_API_KEY}`).
- A remote MCP server's header works the same way: `"Authorization": "Bearer {env:MCP_TOKEN}"`, with its host in a
  recipe the person approved.
- A remote MCP server that signs in with OAuth: `keyreeve-cli oauth-login <url> --provider <id> | keyreeve-vault add <id>`.
  The person signs in in the browser; keyreeve keeps the refresh token and renews the access token itself.

## A service that runs on its own

If nobody is at the Mac, the key needs the level **Always, no fingerprint**, and:

- The service starts with `KEYREEVE_AGENT=<name>`, and that name is in the key's agents. Without it, it falls back to
  asking for a fingerprint, silently. Ask for it with `request_access key=<id> duration=no-fingerprint for_agent=<name>`.
- The key has a provider. If `use` says "has no provider, so nothing says where it may go", write a recipe in
  `~/.keyreeve/providers/<id>.yaml` with **one** host, `auth` and a read-only `verify`, and ask the person to approve that
  host. You cannot approve a host yourself.
- The service uses the key through the proxy. "Always" never hands out the real value.

## What you do not do

- Read `~/.keyreeve/vault`, print `audit.jsonl` unfiltered, or run `keyreeve-vault get`.
- Approve a host, mark a key reviewed or give it a level on the person's behalf. Propose it, with `propose_tidy` or a
  recipe, and let them approve it.
- Pretend to be another agent (`KEYREEVE_AGENT=<someone else>`) to test a permission.
- Say something is pending (an approval, an "always") without checking it first: `list_keys`,
  `keyreeve-cli recipes --json` or `keyreeve-vault log --since 1d`.

## Check how it is going

`keyreeve-vault log --since 7d` lists what was asked, allowed and used, with ids and no values. A provider that answers 401
every time usually means a dead key: suggest rotating or archiving it.
