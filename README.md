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

Each check is one GET request, so it cannot change anything. A provider that uses OAuth first exchanges the key for a token, with a POST that holds the credentials. It prints the result and never the key. A plan
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
Mac's password, or with neither if you turn that off in Settings, since the list holds no value. This lock covers the
window. Keys are protected by the vault below.

It is laid out by task. **Home** leads with what needs you, each item with its action. **My keys** is the list, with filters
for archived keys and projects. **To review** holds what needs a look, and **Security and backup** the vault. **Agents**,
**Rotation** and **Log** sit apart, under Tools. A key's page has four tabs: Summary, Use, Security and History, with the
technical parts behind "More details and options".

```bash
app/build-app.sh
open app/dist/Keyreeve.app
```

**Check all**, in My keys, asks first, then sends each key to its own provider, at most six at a time, with progress and a summary. In Settings you can
also check keys set to "Checked without asking" every week, which needs no fingerprint and notifies you if one stops working. It
reads files, so a key whose original left the folder is skipped, and you check it from the app.

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
| `fields` in `identify` | `$.path`, `header:name`, `token:name` or `reply:`. `$.*.slug` keeps every item of a list, such as each organization a token reaches. Name them `scopes` or `expires` to say what a key can do and when it ends |
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

These recipes have been shown to reject a fake key at the real address. A file's `tested` line says when it was last tried with a
real key, and a pass with a real key is what proves a recipe. `self_hosted` recipes need your server first.

## The vault (Mac)

In the app, open **Security and backup** and press **Create my vault**. It shows a recovery key once, and saves nothing until you type
back its last 6 characters. Keep that key away from this Mac, because if the Mac dies it is the only way back in.

Then choose keys and press **Seal**. Each file is sealed for a key inside your Mac's Secure Enclave, which it cannot leave, and
for the recovery key. Your original files stay where they are. **Compare with the files** opens every sealed copy and tells you
whether it matches. From then on, checks, identification and your own actions use the sealed copy, and ask for your finger once per batch.

If a file changes after you seal it, the app says so and uses the file, because the sealed copy may be an old key.
**Seal the changed files again** replaces the copy, and the old one stays sealed. After a comparison, you can move the files that
matched out of the keys folder to `~/.keyreeve/originals`. They stay readable there, the list keeps showing them and you can put them
back. keyreeve never deletes them, so that step is yours once you trust the vault. A sealed key whose file you remove by hand also
stays on the list, and if the whole keys folder is gone, the app says so and keeps what the vault holds.

**Copy the vault…** saves the sealed vault file in a folder you choose, with no fingerprint. On another Mac, put that file at
`~/.keyreeve/vault/vault.json` and run `keyreeve-vault recover` with your recovery key. `keyreeve-vault backup <folder>` does the same
from a terminal.

The same vault works from a terminal:

```bash
app/dist/keyreeve-vault init
app/dist/keyreeve-vault add hosting-token
app/dist/keyreeve-vault run hosting-token --as HOSTING_TOKEN -- ./deploy.sh
```

Adding a key needs no fingerprint, so an agent can store a key it cannot read back. Using one asks for your finger. `init`
refuses to run outside a terminal so the recovery key does not land in a log. No command prints a key, and the app copies one only
when you press its button.

A copy sealed from the app holds the whole file, so `run` hands a program everything in it. For a file with several values, use
`env` below and name the field.

### Your keys do not depend on this tool

Each sealed key is a standard [age](https://age-encryption.org) file, and the recovery key is an ordinary age key. With only the
vault and the `age` command, on any computer:

```bash
keyreeve-vault export hosting-token --recovery | age -d -i recovery-key.txt
```

The first line of what comes out names the key, and the rest is its value. The keys in the chip use age's `p256tag` recipient. The
file format is public and used by other tools, and it is tested here against the official one in both directions. The code that
writes it is mine, and it has had no outside review.

## Keys and agents

Each key can have an identifier, separate from its file: `netlify`, `mail-shop`. A file with several values can have several, and
renaming or moving a file breaks nothing that uses one. The app suggests them and keeps them in `~/.keyreeve/keys.toml`, which holds no value.
An identifier can also say whose key it is, its `account`, which tells apart several keys of one provider. It comes from the provider when its
file can ask, and from you when it cannot, and the fingerprint prompt shows it.

```bash
keyreeve-vault list
keyreeve-vault use netlify --reason "deploy" -- netlify deploy --prod
keyreeve-vault grants
keyreeve-vault revoke
keyreeve-vault audit --key netlify
keyreeve-vault audit --verify
```

`use` runs one command with one key, and the command never holds it. Its variable holds a stand-in of the same shape, and a local proxy puts
the real key on requests to that provider's hosts, which come from its file. `printenv` shows the stand-in, and sent anywhere else it is useless.
Your finger is asked once for that key with that program, and the permission lasts 5 minutes unless `--for` says otherwise. A small service keeps
it, and stops on its own when idle. Quitting the app ends every permission. The variable comes from the provider's file, or from `--as`.

The swap happens in headers and in Basic passwords, and in the address for a provider that takes its key there. A body keeps the stand-in, so a
tool that sends its key in a body fails and leaks nothing. A reply that echoes the key gets the stand-in back. Other hosts get a tunnel, with TLS
end to end. The stand-in is what lets a request use the key, so nothing else needs to be in the command's environment.

An SSH key works the same way, with `provider = "ssh"` in `keys.toml` or a provider file that uses `auth: { type: ssh }`:

```bash
keyreeve-vault use vps --reason "restart" -- ssh root@my-server uptime
keyreeve-vault use deploy-key -- git push
```

The command gets `SSH_AUTH_SOCK`, pointing at a door in front of the system's own `ssh-agent`, which holds the key for as long as the permission
lasts. The door passes listing and signing and nothing else, so the key cannot be read, replaced or used to sign a file or a commit. OpenSSH tells the
agent which server each connection is for, so the permission covers the first server and every other one asks for your finger. Each signature goes in
the log with the user and the server's fingerprint. A key with a passphrase asks for it in a dialog when the permission opens.

To allow only servers you name, list their fingerprints, as `ssh-keygen -lf` or the usage log shows them. With a list there is no free first server:

```toml
[[key]]
id = "vps"
source = "vps-key"
provider = "ssh"
servers = "SHA256:abc... SHA256:def..."
```

`ssh`, `scp` and `sftp` get options that win over your `~/.ssh/config` and offer this key first. `git` and `rsync` get the same through `GIT_SSH_COMMAND`
and `RSYNC_RSH`, unless you set those yourself. Any other program uses `SSH_AUTH_SOCK` and your config.

`keyreeve-vault grant vps --for 1h` opens a permission ahead of time, so an agent's work does not stop to ask. A key that is not SSH takes `--program`, since
its permission is for one program. The app does the same from a key's page, shows what is in force and the key's recent use, and can end it.

`--real` hands the command the real key, for what cannot use a stand-in, such as a provider that signs requests or a script of your own. It asks for
your finger every time and is logged apart. A command that sends a stand-in past the proxy, or ignores its variables, simply fails to authenticate.

Every decision goes in `~/.keyreeve/audit.jsonl`: which key, which permission, the process and its parents as the system reports them, and
apart from those what the caller says about itself. It holds no value and no arguments. Each line carries the hash of the one before, so `--verify`
finds an edit. Another program running as you could rewrite the whole chain, so this detects changes and does not prevent them. The
process chain is a hint about who asked, and not proof.

An env file can hold references in place of values, so it is safe in a repository:

```bash
# app.env
HOSTING_TOKEN=keyreeve://hosting
MAIL_KEY=keyreeve://mail-shop
LOG_LEVEL=info
```

```bash
keyreeve-vault env app.env -- ./deploy.sh
```

One fingerprint opens them all for that command.

An agent can use keys over [MCP](https://modelcontextprotocol.io) with `keyreeve-vault mcp`. The app's **Agents** section shows
whether Claude Code is connected, copies the command that connects it in every folder, and lists each sealed key with two choices:

- **Level.** *Only me*, the default, keeps agents out. *Ask* shows a window with the key, the command and the agent's reason in its
  own words, where you choose **Once**, 1, 4, 8 or 24 hours, or **Deny**, then confirm with your finger. *Free* asks for your finger
  once, then covers any command until you quit Keyreeve, for a day at most.
- **Agents.** Any agent, or only Claude or only Codex. The agent is named from the process that started the server, which is a strong
  hint and not proof, since everything runs as you.

The agent's `use_key` tool runs a command with a stand-in for the key, through the proxy described above, so any command works,
including `curl`, and the real key only reaches the key's provider. An SSH key signs in through keyreeve. A key with no provider can
only go to a program you allow, which gets the real key in a variable and is pinned by its SHA-256: if the file changes, it is refused
until you allow it again. Shells, interpreters, `curl`, `env` and others like them cannot be allowed that way. A run stops after
2 minutes, and its output never shows the key or the stand-in.

Quitting Keyreeve, `keyreeve-vault revoke`, **Close all** in the menu bar or **Make them ask again** end every permission given to
agents. Locking the window only hides your keys, so an agent's work does not stop when you look away. The choices live in
`~/.keyreeve/agents.toml` ([example](examples/agents.toml)), which the server reads on each request, so a change counts without
restarting the agent. A file with a mistake allows nothing. Every yes, no and refusal goes in the usage log with the agent's reason.
The window shows the whole command before you choose, and **Agent terminal** in the same section shows each command an agent ran with a
key, its exit code, how long it took and the first 2,000 characters of what came back, kept in `~/.keyreeve/agent-runs.jsonl`.

### When an agent asks for a key

`list_keys` shows the keys an agent may use, the ones closed to it, by name and provider, and the providers you have no key for yet.
With `request_access` the agent asks for one, says why and suggests for how long. You get one window: **Allow** for 1, 4, 8 or 24
hours or always, or **Deny**. After a yes the key is free to that agent alone, with one fingerprint and no more questions, until the
time is up. A no stops that agent asking again in its session. A key already open to another agent is not reopened on new terms:
you add the second agent under **Agents**.

When the agent asks for a provider whose key is not saved, the request waits in the app. Pick the file that holds it and press
**Save and allow**: it is sealed, named and opened to that agent in one step. With no file, **Paste a new one** takes a key you copy
from the provider. If the agent knows which account the key should belong to, it says so with `account`, and the file that matches
comes first.

### When an agent asks to rotate a key

With `rotate_key` an agent asks for a sealed key to be rotated, and says why: it leaked, it is old, or you asked it to. The request
waits under **Agents** with where the new key goes, which is what you set in the key's **Security** tab: the agent cannot choose it.
For a provider with no way to make keys from here, you make the new one at its page and paste it in the request. **Rotate this key**
asks for your fingerprint, and the agent learns how it went when it asks again. It never sees either key. A place can be a button of
yours that receives the new key on stdin, such as an env file on a server over ssh (`examples/places/ssh-env.sh`).

### Add a key

**Add a key** (the **+** in the window, or the menu bar) reads the clipboard, tells the provider from how the key starts, and seals it
with no file on disk. The key itself is never shown, only its known start and its length, and the clipboard is cleared. A link opens
the provider's page where keys are made. Name it in your own words; its identifier, for scripts and agents, is made from that name and
shown before saving. A key of no known provider is kept too, and can be copied: it is checked or used through the proxy once you
choose its provider. With no keys folder at all, **Start with no folder** on the first screen opens the app where a vault is made.

### The menu bar

Keyreeve stays in the menu bar with its window closed. The icon counts the requests waiting. Its menu shows them, what agents hold
now and until when, the latest uses, and **Lock everything**: it ends every permission, locks the window and pauses agents, so each
request is refused with no window until you press **Resume agents**.

### One log for everything

```bash
keyreeve-vault log --since 7d            # one JSON line per event, oldest first
keyreeve-vault log --key resend --csv    # for a spreadsheet
```

It joins the usage log, what agents ran, every check of a key and your own uses, with names in place of file paths. Each decision
you make in the app goes in it too: a level changed, a request answered, a pause. No value is in any of them.

### With seisin

[seisin](https://github.com/carlostapiacl/seisin) gives each agent its own folders and keys, and takes a key from any command that
prints it. `keyreeve-vault get` is that command: it prints the real key after your fingerprint, every time, and logs it.

```toml
# seisin.toml
[keys.providers.keyreeve]
command = ["/path/to/keyreeve-vault", "get", "{ref}"]

[network]
allow = ["api.resend.com"]

[roles.mailer]
keys = ["RESEND_API_KEY=keyreeve://resend"]
key_mode = "env"
```

The role gets the key in its environment and can reach only the domains you list. seisin masks it in the output, and no file holds
it on disk. Here the role holds the real key, so prefer `use` and the proxy wherever the agent runs outside seisin.

**Copy the key**, on a sealed key in the app, puts it on the clipboard after your fingerprint. It is marked so clipboard history tools
skip it, and it leaves after 60 seconds, or when you lock the app, unless you copied something else by then.

## Rotate a key

Open a sealed key in the app. If its provider can rotate, you say where else the key is used and how long the old key should last,
then press **Rotate this key**. One fingerprint, and keyreeve:

1. Creates the new key at the provider, under a name like `keyreeve-2026-11-06`, and seals it.
2. Tries it. If it fails, the new key is revoked and everything stays as it was.
3. Updates every place: files where the old value is replaced, and buttons of your own that receive the new key on stdin.
4. Revokes the old key, right away or later when you press the button in **Rotation**.

A crash at any step resumes from a journal in `~/.keyreeve/rotations.jsonl`, which holds ids and no values.

Most providers give no way to learn the id of a key you already have, so the first rotation may ask you to revoke the old key by
hand. Later ones know the id.

There are three ways to rotate, and a provider's file says which:

- **Two keys for a while.** Resend and LangSmith. A failure anywhere before the old key goes undoes everything.
- **`rotation: single`.** GitLab and Cal.com end the old key the moment the new one exists, so nothing can be undone. A place that
  fails is reported for you to fix, and the rotation goes on.
- **By hand.** A provider with no way to make keys through its API, such as Hetzner or Netlify. You make the key at its page and paste
  it in. keyreeve tests it, updates the places, and then checks that the old key really died once you revoke it. This works for
  providers that test a key with one plain request.

None of these has run against a real service yet, and the list in Settings shows what each file has been tried with. To add a provider,
give its file `create` and `revoke`, and `keyreeve simulate` tests it against failures and crashes. The simulator's guarantees do not
apply to `rotation: single`.

A place can be a file, or a button of yours that receives the new key on stdin. There are [examples](examples/places) for GitHub
Actions, Vercel and an env file on a server, which have not been run against those services.

A key joined from two fields, such as AWS, cannot rotate yet.

## What is missing

- A rotation tried against a real provider
- Reading a provider's early answer during an upload. A provider that refuses a large body before reading it gets a 502 back from the proxy
- Using the vault on Linux and Windows, and a chip-free key for them. The file format already works there
- Other vaults as storage, such as 1Password or the system keychain
- A scan that finds where each key is used, and which permissions each key has
- An Apple signature, so the app can be downloaded and not only built
- Recipes for more providers that can rotate, keys made of two fields, and rotation written as a program of yours
- A stand-in for roles inside [seisin](https://github.com/carlostapiacl/seisin), so they reach a provider through the proxy and never hold the key
- One fingerprint for several seisin runs, without letting any other program ride on it

## Security

[THREAT_MODEL.md](THREAT_MODEL.md) lists what this protects against and what it does not.
To report a vulnerability, use [private reporting](https://github.com/carlostapiacl/keyreeve/security/advisories/new).

## License

[MIT](LICENSE)
