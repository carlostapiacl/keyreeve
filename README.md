# keyreeve

Rotate API keys on your own machine, with recipes the community writes for each provider.

Rotating a key by hand means creating a new one, pasting it everywhere it is used, checking
that nothing broke and revoking the old one. Each provider does this a little differently.
keyreeve puts those differences in a small file, so a recipe written once works for everyone.

**Status: early, and it cannot rotate a real key yet.** The recipe format, the rotation engine
and the simulator work. See [what is missing](#what-is-missing).

## A recipe

```yaml
schema: 1
provider: example
hosts: [api.example.com]
auth: { header: Authorization, prefix: "Bearer " }
create:
  method: POST
  path: /v1/keys
  body: { name: "{key_name}" }
  value_from: $.secret
  id_from: $.id
verify: { method: GET, path: /v1/me }
revoke: { method: DELETE, path: "/v1/keys/{id}" }
```

A recipe runs with a credential that can create keys, so a bad one could try to steal it.
That is why a recipe is data and has no way to run code. Requests go over HTTPS, only to the
hosts it lists, with redirects off. The credential goes in the header the recipe names and has
no placeholder, so a recipe cannot put it in a URL or a body. It can still pick the wrong
header, or list a host that stores what it receives, so read `hosts` before you use one.

[CONTRIBUTING.md](CONTRIBUTING.md) explains how to write one.

## The order of a rotation

1. Create the new key and save it.
2. Check that the new key works. If it fails, revoke it and stop.
3. Update each place that uses the key. If one fails, restore all of them and revoke the new key.
4. Make the new key current, and wait out the overlap if you set one.
5. Revoke the old key.

Each step is written to a journal first, so `resume` can finish or undo a rotation after a
crash. The journal holds key ids and step names, never values.

## Try it

You need [Rust](https://rustup.rs). There are no prebuilt binaries yet. This runs offline and uses no real keys.

```bash
cargo install --git https://github.com/carlostapiacl/keyreeve
git clone https://github.com/carlostapiacl/keyreeve
cd keyreeve
keyreeve check examples/recipe.yaml
keyreeve simulate examples/recipe.yaml
```

Tested on macOS and, in CI, on Linux. Windows has not been tried.

`simulate` builds a fake provider from the recipe, injects failures and stops the process at
every operation, then again at every operation of the recovery. After each stop it checks that:

- the stored key and every service hold a key that works
- when the rotation closes, they all hold the same key and no temporary copy remains
- any leftover key at the provider was reported for manual cleanup
- no key value reached the journal, an error or an outcome

A pass means the recipe and the engine hold up against the simulator. It does not prove that the
real provider behaves as the recipe describes.

## See what you have

If your keys live in a folder of text files, start here. Neither command changes a file.

```bash
keyreeve inventory ~/my-keys --out ~/.keyreeve/inventory.json
keyreeve catalog ~/.keyreeve/inventory.json --rules ~/.keyreeve/rules.yaml --history ~/.keyreeve/history.jsonl --edits ~/.keyreeve/edits.json --out ~/.keyreeve/catalog.csv
```

`inventory` describes each file: name, date, permissions, format, labels and the kind of key, recognized
by its prefix. It reads `.env` files, JSON and loose notes with `=`, `:`, `=>`, `|` or tabs, in any mix.
Whatever follows a separator is ignored. From comments and notes it keeps only words on a closed list,
such as `token` or a provider's name, and a label with any other word is counted but not shown. To allow
your own words, such as project names, pass `--words` with a file of one word per line.

`catalog` gives each file tags and an access level from [your rules](examples/rules.yaml), and tells you
which files they do not cover. It reads only the inventory, so it never opens a key file.

Values stay out of both, so you can hand them to an agent that must not see your keys. File names and
labels do go in, so keep them private. They are written with mode 600. A password in capitals placed before a
separator would read as a variable name, and a file named after a secret would show that name.

## Check whether a key still works

```bash
keyreeve recipes
keyreeve verify hetzner --key-file ~/my-keys/hetzner.txt
keyreeve verify github --key-file ~/my-keys/app.env --field GITHUB_TOKEN
keyreeve verify --plan ~/.keyreeve/plan.yaml --keys ~/my-keys
```

Each check is one GET request, so it cannot change anything. It prints the result and never the key. A plan
lists many keys at once:

```yaml
keys:
  - { file: hetzner.txt, recipe: hetzner }
  - { file: app.env, recipe: github, field: GITHUB_TOKEN }
```

A rejected key may
still be alive for other uses: a restricted token can fail a check it has no permission for. Cloudflare's check
only covers user tokens, so an account token reads as rejected. A pass says the key works, and not what it may do.
The `hetzner`, `langsmith` and `aws` recipes have passed with a real key.

## The Mac app

A native window over your keys, with no web inside, in English and Spanish. It opens with your fingerprint or your
Mac's password. This lock covers the window. Keys are protected by the vault below.

```bash
app/build-app.sh
open app/dist/Keyreeve.app
```

Check all sends each key to its own provider, at most six at a time, with progress and a summary. In Settings you can
also check keys set to "Agents can use it" every week, which needs no fingerprint and notifies you if one stops working.

The first time, choose your keys folder. No Terminal is needed after building. The app scans the folder each time it
opens, and shows what to do first, with a button on each item. To revoke a key, open the provider's page, revoke it, and
press "I already revoked it": the app checks the key again, and the warning goes away only if the provider rejects it.
A key with no check available is marked by hand. "Ignore" lasts 30 days, then the warning comes back.

Beside the list you can name a key and describe it, rate it from 1 to 5 by how bad a leak would be, change who can use
it, and archive it. A name does not rename the file, so nothing that uses the file breaks. Archiving hides a key and does
not stop it, so an archived key that still works keeps a warning. Identify asks the provider whose key it is, and keeps
only the fields that provider's file declares, then offers a name.

A check sends a key to a company, so the app never guesses where: you choose, or the key's prefix proves it. A check is
one read-only request, keys set to "Ask me" need your fingerprint, and keys set to "Only me" are not offered. Your
fingerprint lasts 5 minutes by default, and locking the app ends it. Settings has that period, the language, appearance and
auto-lock. The build is not notarized, so macOS warns you the first time.

## Adding a provider

Everything about a provider lives in one file, and the app knows no provider by name. See [`recipes/github.yaml`](recipes/github.yaml):

```yaml
schema: 1
provider: github
name: GitHub
dashboard: https://github.com/settings/tokens
prefixes: [ghp_, github_pat_]
hosts: [api.github.com]
auth: { header: Authorization, prefix: "Bearer " }
verify: { method: GET, path: /user }
identify:
  request: { method: GET, path: /user }
  fields: { account: $.login, email: $.email }
suggested_name: "GitHub · {account}"
```

Put yours in `~/.keyreeve/providers/` and it works with no new build, once you approve the hosts it lists, in Settings or
with `keyreeve recipes approve <name>`. Changing its hosts undoes the approval, and a file cannot replace one that ships.
To share it with everyone, open a pull request.

A file can also declare:

| field | what it does |
|---|---|
| `auth: { header }` | sends the key in a header. The usual case |
| `auth: { type: url }` | puts `{key}` in the address, for providers with no other way, such as Telegram |
| `auth: { type: basic }` | HTTP Basic |
| `auth: { type: oauth_token }` | exchanges two or three fields for a short-lived token, such as Google or PayPal |
| `auth: { type: aws_sigv4 }` | signs each request, so the secret never travels. AWS and R2 |
| `auth: { type: ssh }` | greets a server with an SSH key through the system's `ssh`, such as a GitHub deploy key |
| `self_hosted: true` | each person gives their own server, approved one at a time, always over HTTPS |
| `prefixes` | finds the key inside a file of notes, and refuses if there are two |
| `alive_if` | a refusal that still proves the key is alive, such as a restricted key |
| `fields` in `identify` | `$.path`, `header:name`, `token:name` or `reply:`. Name them `scopes` or `expires` to say what a key can do and when it ends |
| `rotate_every_days` | a suggested age, shown as "older than suggested" |
| `criticality_hint` | a rating from 1 to 5, shown faded until you confirm yours |

### Your own checks and buttons

For what a file cannot describe, a file of yours can run a program of yours. See
[`examples/providers`](examples/providers). Everyone shares the generic files, and your own stay in your folder:

```yaml
auth:
  type: command
  run: { program: my-service-check.sh }
actions:
  - id: open-runbook
    label: Open the runbook
    open: https://example.com/runbook
  - id: restart-worker
    label: Restart the worker
    run: { program: my-service-check.sh, args: [--restart] }
    needs_key: true
```

The program gets the key on stdin and answers in JSON, such as `{"result":"works","fields":{"account":"me"}}`. It runs with a
clean environment and a time limit, and only after you approve it. Changing the file or the program by even a byte undoes
the approval. A file that ships with keyreeve can never run a program.

A secret with no provider, such as a signing key, is marked as internal, and no check is offered. Secrets for your own
products go the same way: a file of yours, in that folder, never in a repository.

These recipes have been shown to reject a fake key at the real address, and that is all most of them have seen: a pass
with a real key is what proves a recipe. `self_hosted` recipes need your server first.

## The vault (Mac)

In the app, open **Vault** and press **Create my vault**. It shows a recovery key once, and saves nothing until you type
back its last group. Keep that key away from this Mac, because if the Mac dies it is the only way back in.

Then choose keys and press **Seal**. Each file is sealed by a key inside your Mac's Secure Enclave, which it cannot leave.
Your original files stay where they are. **Compare with the files** opens every sealed copy and tells you whether it matches.
From then on, checks, identification and your own actions use the sealed copy, and ask for your finger once per batch.

If a file changes after you seal it, the app says so and uses the file, because the sealed copy may be an old key.

The same vault works from a terminal:

```bash
app/dist/keyreeve-vault init
app/dist/keyreeve-vault add hosting-token
app/dist/keyreeve-vault run hosting-token --as HOSTING_TOKEN -- ./deploy.sh
```

Adding a key needs no fingerprint, so an agent can store a key it cannot read back. Using one asks for your finger. `init`
refuses to run outside a terminal so the recovery key does not land in a log. There is no command that prints a key.

A copy sealed from the app holds the whole file, so `run` hands a program everything in it. For a file with several values,
add the one key by hand under its own name.

If a file changes, **Seal the changed files again** replaces the copy, and the old one stays sealed. After a comparison, you can
move the files that matched out of the keys folder to `~/.keyreeve/originals`. They stay readable there, the list keeps showing
them and you can put them back. keyreeve never deletes them, so that step is yours once you trust the vault.

The vault format is mine and has had no outside review, so keep your old copies until it has.

## Rotate a key

Open a sealed key in the app. If its provider can rotate, you say where else the key is used and how long the old key should last,
then press **Rotate this key**. One fingerprint, and keyreeve:

1. Creates the new key at the provider, under a name like `keyreeve-2026-11-06`, and seals it.
2. Tries it. If it fails, the new key is revoked and everything stays as it was.
3. Updates every place: files where the old value is replaced, and buttons of your own that receive the new key on stdin.
4. Revokes the old key, right away or later when you press the button in **Vault**.

A crash at any step resumes from a journal in `~/.keyreeve/rotations.jsonl`, which holds ids and no values.

Most providers give no way to learn the id of a key you already have, so the first rotation may ask you to revoke the old key by
hand. Later ones know the id. Resend and LangSmith can rotate today, and neither has yet been tried against the real service. To add
a provider, give its file `create` and `revoke`, and `keyreeve simulate` will test it against failures and crashes.

A key joined from two fields, such as AWS, cannot rotate yet. A provider that rotates by replacing the key in one call, such as GitLab,
does not fit these steps yet.

## What is missing

- A rotation tried against a real provider
- Storage for Linux and Windows
- More places to update, such as GitHub and Netlify. Today a button of yours can reach them
- Recipes for more providers that can rotate, and rotation written as a program of yours
- Approvals that expire
- Integration with [seisin](https://github.com/carlostapiacl/seisin), which gives each agent its own keys

## Security

[THREAT_MODEL.md](THREAT_MODEL.md) lists what this protects against and what it does not.
To report a vulnerability, use [private reporting](https://github.com/carlostapiacl/keyreeve/security/advisories/new).

## License

[MIT](LICENSE)
