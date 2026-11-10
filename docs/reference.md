# keyreeve reference

The details the [README](../README.md) leaves out. [Español](reference.es.md)

Contents: [Try it offline](#try-it-offline) · [The Mac app](#the-mac-app) · [The vault](#the-vault-mac) ·
[Keys and agents](#keys-and-agents) · [From a terminal](#from-a-terminal) · [Providers and recipes](#providers-and-recipes) ·
[Where a key lives](#where-a-key-lives) · [Rotate a key](#rotate-a-key) · [What is missing](#what-is-missing)

## Try it offline

You need [Rust](https://rustup.rs). This runs offline and uses no real keys.

```bash
cargo install --git https://github.com/carlostapiacl/keyreeve
git clone https://github.com/carlostapiacl/keyreeve
cd keyreeve
keyreeve check examples/recipe.yaml
keyreeve simulate examples/recipe.yaml
```

`simulate` builds a fake provider from the recipe, injects failures and stops the process at every operation, then
again at every operation of the recovery. After each stop it checks that:

- the stored key and every service hold a key that works
- when the rotation closes, they all hold the same key and no temporary copy remains
- any leftover key at the provider was reported for manual cleanup
- no key value reached the journal, an error or an outcome

A pass means the recipe and the engine hold up against the simulator. It does not prove that the real provider behaves
as the recipe describes.

CI checks the command on Linux and the app on macOS. Windows has not been tried.

## The Mac app

A native window over your keys, with no web inside, in English and Spanish. Build it with the Command Line Tools:

```bash
app/build-app.sh
ditto app/dist/Keyreeve.app /Applications/Keyreeve.app   # once, to keep it with your other apps
open /Applications/Keyreeve.app
```

Once a copy is in /Applications, each build updates it too, and a Keyreeve that was open is quit before and opened again
after, so no older copy keeps running beside the files the new one writes. The build is not notarized, so macOS warns you
the first time.

The first time, press **Bring in your keys** ([below](#bring-in)), choose your keys folder, or **Start with no folder, and paste a key** to begin with an empty vault. The app opens with your
fingerprint or your Mac's password, or with neither if you turn that off in Settings, since the list holds no value. This
lock covers the window. Keys are protected by [the vault](#the-vault-mac).

It is laid out by task. **Home** leads with what needs you, each item with its action. **My keys** is the list, with filters
for archived keys and projects. **To review** holds what needs a look, and **Security and backup** the vault. **Agents**,
**Providers**, **Rotation** and **Log** sit apart, under Tools. A key's page has four tabs: Summary, Usage, Security and
History, with the technical parts behind "More details and options".

**Check all**, on Home or in My keys, asks first, then sends each key to its own provider, at most six at a time, with
progress and a summary. A key with no sealed copy whose file is gone shows as **Not in the vault**, apart from keys whose
provider did not answer. In Settings you can also check keys set to "Checked without asking" every week, which needs no
fingerprint and notifies you if one stops working. The weekly check reads files, so a key whose original left the folder is
skipped there, and you check it from the app.

A check sends a key to a company, so the app never guesses where: you choose, or the key's prefix proves it. A check is one
read-only request, keys set to "Ask me" need your fingerprint, and keys set to "Only me" are not offered. Your fingerprint
lasts 5 minutes by default, and locking the app ends it. Settings has that period, the language, appearance and auto-lock.

Beside the list you can name a key and describe it, rate it from 1 to 5 by how bad a leak would be, change who can use it,
and archive it. A name does not rename the file, so nothing that uses the file breaks. Archiving hides a key and does not
stop it, so an archived key that still works keeps a warning. **Identify** asks the provider whose key it is, keeps only the
fields that provider's file declares, and offers a name.

To revoke a key, open the provider's page, revoke it, and press "I already revoked it": the app checks the key again, and the
warning goes away only if the provider rejects it. A key with no check available is marked by hand. "Ignore" lasts 30 days,
then the warning comes back.

An AI you already run in your terminal, such as Claude Code, Codex or OpenCode, can help on your own subscription. Chosen in
Settings, it drafts provider files under **Providers** and, in **Sort keys**, proposes a provider for keys keyreeve cannot check
yet. It is given file names, tags and field names, never a value, and the app says so each time. keyreeve never hands it a key,
but Codex, OpenCode or a command of your own can read files on your Mac while they work. Claude Code is limited to web search.

### Bring in

**Bring in your keys** (on the first screen, in **Security and backup**, or File > Bring in keys…) finds keys and seals the ones you
choose, in one screen:

- **Where to look.** *Usual places on this Mac*: `~/.aws`, the GitHub CLI, gcloud, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, Docker,
  the `export` lines of your shell's startup files and your SSH keys (only their first line is read), plus `.env` files under the
  project folders you turn on. *Everywhere in my home folder*: all of it, for `.env` files and files whose name or start says
  they hold a key (`.pem`, `.p12`, `.key`, notes called `api-key.txt`, a `.txt` or `.json` starting with a provider's prefix);
  other files are not opened. It skips Library, the Trash, photo and music libraries, iCloud Drive, apps and big files, stops after
  two minutes and names the folders it did not finish, with **Look in those** to go on. macOS may ask before it reads Desktop,
  Documents and Downloads. Or *Choose a folder*. It skips `node_modules`, `.git`, builds and caches, and needs no Full Disk
  Access.
- **What it does.** Splits each file into pieces, says what each is (a key, configuration, a login, a document or a public key),
  puts the parts of one key together (client id and secret, Google's three, an access key and its secret with the endpoint as the
  server), and joins the same key found in two places. A key is checked only by the one provider its prefix, its variable
  name or its client id names; a name that only mentions a provider is shown as a guess and sends nothing.
- **Review.** Values stay hidden. Keys that work are chosen, dead ones are not, configuration and public keys are never sealed,
  and you decide only the doubtful ones.
- **Seal.** One fingerprint. Each key gets an identifier and is not offered to agents. One click can offer the ones a project's
  `.env` already uses. The original files are never moved, changed or deleted; where each key came from is kept with its copy.

### Add a key

**Add a key** (the **+** in the window, or the menu bar) reads the clipboard, tells the provider from how the key starts, and
seals it with no file on disk. The key itself is never shown, only its known start and its length, and the clipboard is cleared.
A link opens the provider's page where keys are made. Name it in your own words; its identifier, for scripts and agents, is made
from that name and shown before saving. A key of no known provider is kept too, and can be copied: it is checked or used through
the proxy once you choose its provider.

### When a key expires

Many keys end on a day: a token made for 90 days, a user token that lasts 60. Write the day in **Expires**, under **More details
and options** on a key, or let an agent give it with `propose`. A provider that says it fills it when the key is identified, as
GitHub and Cloudflare do. Two weeks before, the key goes to **To review** with the days left; once the day has passed, it says so
until it is renewed. **Expire soon** shows the keys ending within thirty days, and agents see the day in `inventory`.

### The menu bar

Keyreeve stays in the menu bar with its window closed. The icon counts the requests waiting. Its menu shows them, what agents hold
now and until when, the latest uses, and **Lock everything**: it ends every permission, locks the window and pauses agents, so each
request is refused with no window until you press **Resume agents**.

**Copy the key**, on a sealed key, puts it on the clipboard after your fingerprint. It is marked so clipboard history tools skip it,
and it leaves after 60 seconds, or when you lock the app, unless you copied something else by then.

## The vault (Mac)

In the app, open **Security and backup** and press **Create my vault**. It shows a recovery key once, and saves nothing until you
type back its last 6 characters. Keep that key away from this Mac, because if the Mac dies it is the only way back in.

Then choose keys and press **Seal**. Each file is sealed for a key inside your Mac's Secure Enclave, which it cannot leave, and for
the recovery key. Your original files stay where they are. **Compare with the files** opens every sealed copy and tells you whether
it matches. From then on, checks, identification and your own actions use the sealed copy, and ask for your finger once per batch.
Binary files, such as a `.pfx` or `.jks`, can be sealed too.

If a file changes after you seal it, the app says so and uses the file, because the sealed copy may be an old key. **Seal the
changed files again** replaces the copy, and the old one stays sealed. After a comparison, you can move the files that matched out
of the keys folder to `~/.keyreeve/originals`. They stay readable there, the list keeps showing them and you can put them back.
keyreeve never deletes them, so that step is yours once you trust the vault. A sealed key whose file you remove by hand also stays
on the list, and if the whole keys folder is gone, the app says so and keeps what the vault holds.

**Copy the vault…** saves the sealed vault file in a folder you choose, with no fingerprint. On another Mac, put that file at
`~/.keyreeve/vault/vault.json` and run `keyreeve-vault recover` with your recovery key. `keyreeve-vault backup <folder>` does the
same from a terminal, and `keyreeve-vault check-recovery <backup>` proves a backup opens with your recovery key.

The same vault works from a terminal:

```bash
app/dist/keyreeve-vault init
app/dist/keyreeve-vault add hosting-token
app/dist/keyreeve-vault run hosting-token --as HOSTING_TOKEN -- ./deploy.sh
```

`put <name>` adds a key, or for a key already there leaves a new value waiting ([below](#how-keys-get-in)), and `reseal <name>`
seals a key's file again exactly as it is now, from the folder it was sealed from, for a file a script changed. Adding a key needs no
fingerprint, so an agent can store a key it cannot read back. Using one asks for your finger. `init` refuses to run outside a terminal so the recovery key does not land in a
log. No command prints a key, and the app copies one only when you press its button.

A copy sealed from the app holds the whole file, so `run` hands a program everything in it. For a file with several values, use
`env` (below) and name the field.

### How keys get in

Every way in leaves the same trace: the app's **+**, Bring in, **Seal**, a request answered with **Save and allow**, and from a
terminal `add`, `put` and `reseal`. Each key gets a record in `keys.toml`, made from its name (`added/openai-prod` is
`openai-prod`, with a number when that is taken), with `added_by` and `added_at`. It is not offered to agents, so `list_keys` and
`keyreeve-vault list` do not show it. The usage log names who added it as it names every other event: the program and its parents
as the system reports them, and the agent when the process tree or `KEYREEVE_AGENT` names one. The app and `keyreeve-vault` write
`keys.toml` under one lock, each reading it as it is and writing only its own change, so a key an agent adds while the window is
open is never lost to an edit in the app, and the window shows it within a few seconds.

```bash
pbpaste | keyreeve-vault add added/openai-prod --description "OpenAI, production" --tags work,ai
keyreeve-vault orphans    # vault names with no record in keys.toml
```

A key that anything other than you in the app added carries `reviewed = false`. **My keys** shows it under **New, not reviewed**,
and the menu bar and **Agents** say "claude added 21 keys". On the key's page you look at it, name it, and press **Mark reviewed**.
None of that offers it: that is still **Offered to agents**, under **Usage**.

`put` over a key that is already there seals the new value as `<name>#pending`, the same name a rotation uses for its new key, and
the key keeps the value it had. The app says "A new value for X is waiting, from claude". **Accept the new value** asks for your
fingerprint and keeps the old value sealed as history; **Discard it** throws the new one away. A newer `put` takes the place of a
value still waiting. While a rotation of that key is open, `put` from anything else is refused, and the engine, run as
`keyreeve-cli rotate`, still writes its own copies and puts the new key in place as before. A rotation does not start while a value
waits.

An entry in the vault with no record, such as one an older version sealed, shows as **Sealed without a record**, with **Give it an
identifier**, not offered. In a `keys.toml` written by `keyreeve migrate` (schema 2) that is any entry; before it, only keys with no
file in the keys folder, since a file there has its own line in the list.

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

Each key has an identifier, separate from its file: `netlify`, `mail-shop`. A file with several values can have several, and
renaming or moving a file breaks nothing that uses one. An identifier can also say whose key it is, its `account`, which tells apart
several keys of one provider. It comes from the provider when its file can ask, and from you when it cannot, and the fingerprint
prompt shows it.

### keys.toml

`~/.keyreeve/keys.toml` says what each key is: its identifier, the file it came from, provider, field, account, description,
level, server, the day it ends and whether it is archived. It holds no value. A file with `schema = 2` holds every key, and the
list in the app reads it.

```bash
keyreeve migrate ~/.keyreeve --dry-run   # what it would write
keyreeve migrate ~/.keyreeve
```

`migrate` writes that file from what keyreeve knew before: the rules, the app's edits, what providers said and the identifiers you
had. Identifiers keep their name and only gain what they lacked. Every other file gets an identifier of its own, not offered to
agents. A copy of each file it reads goes to a new folder under `~/.keyreeve/backups` first, and running it twice changes nothing.

### Offered to agents

A key is offered to agents or not. Agents, `list_keys`, `request_access`, `use_key`, `run_with_key` and `keyreeve-vault use` only
see keys that are offered. A key not offered answers as a name that is not there. In `keys.toml` it carries `offered = false`.

A key you add with **+**, or an identifier you add by hand on a key's page, is offered. Identifiers given in bulk, with **Give them
identifiers** in **Agents** or by `keyreeve migrate`, are not. To offer one, open its page, go to **Usage** and check **Offered to
agents**. Giving a key a level, a program or a permission also offers it. Unchecking it closes the key: its level, the agents it was
open to and the programs allowed with it go.

```bash
keyreeve-vault list
keyreeve-vault use netlify --reason "deploy" -- netlify deploy --prod
keyreeve-vault grants
keyreeve-vault revoke
keyreeve-vault audit --key netlify
keyreeve-vault audit --verify
```

`use` runs one command with one key, and the command never holds it. Its variable holds a stand-in of the same shape, and a local
proxy puts the real key on requests to that provider's hosts, which come from its file. `printenv` shows the stand-in, and sent
anywhere else it is useless. Your finger is asked once for that key with that program, and the permission lasts 5 minutes unless
`--for` says otherwise. A small service keeps it, and stops on its own when idle. Quitting the app ends every permission. The variable
comes from the provider's file, or from `--as`.

The swap happens in headers and in Basic passwords, and in the address for a provider that takes its key there. A stand-in in the
address of a provider that takes it in a header is stopped at the proxy, with an answer that says where it goes. A body keeps the
stand-in, so a tool that sends its key in a body fails and leaks nothing. A reply that echoes the key gets the stand-in back. Other
hosts get a tunnel, with TLS end to end. The stand-in is what lets a request use the key, so nothing else needs to be in the command's
environment.

An SSH key works the same way, with `provider = "ssh"` in `keys.toml` or a provider file that uses `auth: { type: ssh }`:

```bash
keyreeve-vault use vps --reason "restart" -- ssh root@my-server uptime
keyreeve-vault use deploy-key -- git push
```

The command gets `SSH_AUTH_SOCK`, pointing at a door in front of the system's own `ssh-agent`, which holds the key for as long as the
permission lasts. The door passes listing and signing and nothing else, so the key cannot be read, replaced or used to sign a file or a
commit. OpenSSH tells the agent which server each connection is for, so the permission covers the first server and every other one asks
for your finger. Each signature goes in the log with the user and the server's fingerprint. A key with a passphrase asks for it in a
dialog when the permission opens.

To allow only servers you name, list their fingerprints, as `ssh-keygen -lf` or the usage log shows them. With a list there is no free
first server:

```toml
[[key]]
id = "vps"
source = "vps-key"
provider = "ssh"
servers = "SHA256:abc... SHA256:def..."
```

`ssh`, `scp` and `sftp` get options that win over your `~/.ssh/config` and offer this key first. `git` and `rsync` get the same through
`GIT_SSH_COMMAND` and `RSYNC_RSH`, unless you set those yourself. Any other program uses `SSH_AUTH_SOCK` and your config.

`keyreeve-vault grant vps --for 1h` opens a permission ahead of time, so an agent's work does not stop to ask. A key that is not SSH
takes `--program`, since its permission is for one program. The app does the same from a key's page, shows what is in force and the
key's recent use, and can end it.

An OAuth credential, such as Google's `authorized_user` file with a client id, a client secret and a refresh token, works the same
way. Its variable holds the path of a private copy of the file with stand-ins for the secret and the refresh token, and the real
client id, which is not a secret (`GOOGLE_APPLICATION_CREDENTIALS` for Google). When the command's library asks the token host
for an access token, the proxy answers it itself, with a stand-in, and never forwards that request. It gets the real access token
from the provider on its own, keeps it until shortly before it ends, and puts it on requests to the recipe's hosts that carry the
stand-in. A token request with anything else is refused. If the provider answers `invalid_grant`, nothing is tried again, and the
app shows the key as needing to be authorized again, like a key that expired, until you replace it. Libraries that speak HTTP/1.1
through `HTTPS_PROXY` work this way, such as Python's google-auth and Google's API client. gRPC clients do not.

```bash
keyreeve-vault use search-console --as GOOGLE_APPLICATION_CREDENTIALS -- python3 weekly_report.py
```

`--real` hands the command the real key, for what cannot use a stand-in, such as a provider that signs requests or a script of your
own. It asks for your finger every time and is logged apart. A command that sends a stand-in past the proxy, or ignores its variables,
simply fails to authenticate.

Every decision goes in `~/.keyreeve/audit.jsonl`: which key, which permission, the process and its parents as the system reports them,
and apart from those what the caller says about itself. It holds no value and no arguments. Each line carries the hash of the one
before, so `--verify` finds an edit. Another program running as you could rewrite the whole chain, so this detects changes and does
not prevent them. The process chain is a hint about who asked, and not proof.

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

### Several keys at once

```bash
keyreeve-vault use meta-ads,calcom,sentry -- python3 report.py
keyreeve-vault use --set weekly-report --as calcom=CAL_KEY -- python3 report.py
```

Each key goes in its own variable. One window lists them with the program, the folder and the reason: untick what you do not want,
choose 5 minutes, until it finishes, a day, or always for this program in this folder, and give one fingerprint. Single uses from
one script that arrive within two seconds share that window too.

*Always* is bound to the program's path and SHA-256, the script it runs when its first argument is a file, and the folder. A copy of
each key is sealed to the chip's key that asks nothing, as for *Always, no fingerprint*, so a script that runs on Monday at 9:00 needs
no one. A changed program or script, another folder or a key added later asks again. Remove it under **Agents**, in **Key sets**.

A set is a name for a list of keys, made in the app under **Agents**: by hand, or with **Make a set from what this project used**,
which suggests the keys one folder and program used in the last hour. Sets live in `~/.keyreeve/sets.toml`. A set grants nothing on
its own, and lists only keys offered to agents. No agent tool makes one.

### Agents over MCP

An agent can use keys over [MCP](https://modelcontextprotocol.io) with `keyreeve-vault mcp`. The app's **Agents** section shows
whether Claude Code is connected, copies the command that connects it in every folder, and lists each sealed key offered to agents
with two choices:

- **Level.** *Only me*, the default, keeps agents out. *Ask* shows a window with the key, the command and the agent's reason in its
  own words, where you choose **Once**, 1, 4, 8 or 24 hours, or **Deny**, then confirm with your finger. *Free* asks for your finger
  once, then covers any command until you quit Keyreeve, for a day at most. *Always, no fingerprint* asks for your finger once, to seal
  a copy of the key to a second key in the chip that opens with none, and from then on agents use it through the proxy with no question,
  across restarts. An agent can ask for it with `request_access`, but only you set it, in the app; the real key, `run_with_key` and `get` still ask. Keep it for keys that only read.
- **Agents.** Any agent, or only Claude or only Codex. The agent is named from the process that started the server, which is a strong
  hint and not proof, since everything runs as you. A session can name itself by starting with `KEYREEVE_AGENT` set, such as
  `KEYREEVE_AGENT=sales claude`, and is then `claude/sales`: a key open to `claude` serves it as before, and one open to
  `claude/sales` serves that session alone.

The tools an agent gets:

| tool | what it does |
|---|---|
| `list_keys` | the keys it may use, the ones closed to it, and the providers you have no key for yet |
| `use_key` | runs a command with a stand-in, through the proxy, so the real key only reaches its provider |
| `run_with_key` | runs a program you allowed, pinned by its SHA-256, with the real key in one variable |
| `request_access` | asks you to open a closed key, or to save one for a provider |
| `rotate_key` | asks you to rotate a sealed key |
| `inventory`, `propose` | read the folder without values and propose changes for many files, when you turn it on |
| `list_places`, `propose_places` | where offered keys live, and new places for you to approve ([below](#where-a-key-lives)) |
| `find_keys` | finds keys everywhere in your home folder, in the usual places or in folders, with no value and no provider check |
| `propose_bring` | proposes which keys found to seal, for you to review in Bring in and seal with one fingerprint |

`use_key` works with any command, including `curl`. An SSH key signs in through keyreeve. A key with no provider can only go to a
program you allow with `run_with_key`: if the file changes, it is refused until you allow it again. Shells, interpreters, `curl`, `env`
and others like them cannot be allowed that way. A run stops after 2 minutes, and its output never shows the key or the stand-in.

An agent's server that finds a newer Keyreeve in place becomes it at its next message, in the same process and connection, so a
session goes on with the new version without starting again.

Quitting Keyreeve, `keyreeve-vault revoke`, **Close all** in the menu bar or **Make them ask again** end every permission given to
agents. Locking the window only hides your keys, so an agent's work does not stop when you look away. The choices live in
`~/.keyreeve/agents.toml` ([example](../examples/agents.toml)), which the server reads on each request, so a change counts without
restarting the agent. A file with a mistake allows nothing. Every yes, no and refusal goes in the usage log with the agent's reason.
The window shows the whole command before you choose, and **Agent terminal** in the same section shows each command an agent ran with a
key, its exit code, how long it took and the first 2,000 characters of what came back, kept in `~/.keyreeve/agent-runs.jsonl`.

### When an agent asks for a key

With `request_access` the agent asks for a key, says why and suggests for how long. You get one window: **Allow** for 1, 4, 8 or 24
hours or always, or **Deny**. After a yes the key is free to that agent alone, with one fingerprint and no more questions, until the
time is up. A no stops that agent asking again in its session. A key already open to another agent is not reopened on new terms:
you add the second agent under **Agents**.

An agent that needs several keys sends `keys` in place of `key`. You see them in one window, untick what you do not want, and one
fingerprint opens the rest, so its next `use_key` asks nothing.

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

### When an agent sorts the whole folder

Turn on **Agents can sort my keys** under **Agents**, and an agent can read, with `inventory`, each file's name, field names,
provider and state, and the providers keyreeve knows. Never a value, and nothing at all while the switch is off. With `propose` it
sends changes for many files at once: which provider and field, nothing to check, an internal secret, not secret at all, what it is,
whether to seal, check or archive it, the server of a provider you run yourself, the day it expires, and whether to split a file
holding several keys of one provider. They wait under **Agents** as one list, every change chosen to start. **Apply** keeps the chosen
ones, checks the ones it should, which may ask for your fingerprint, and seals the rest. The agent reads how it went in its next
`inventory`. A folder of loose files ends as named keys, checked and sealed, that your agents use with `use_key`.

A server an agent suggests is saved but not approved. The key's page says so, and **Approve … and check** approves it after you
confirm and checks the key there.

### When an agent brings keys in

Ask an agent to "find all my keys and seal the ones that should be". With `find_keys` it runs what [Bring in](#bring-in) runs, as a
dry run. `where` is `everywhere` (the whole home folder), `places` (the usual places, and `.env` files under the `projects` it
names) or `folders` (only those, as everywhere). When everywhere runs out of time, `unfinished` names the folders left, and the agent
goes on with `where: "folders"`. It gets each key and login by
number, with its file and line, the names in it, its provider (only from strong evidence) or a guess, whether it was found twice and
whether it looks sealed already, judged by place and never by value. Configuration, documents and public keys are only counted. No
value, and no request to any provider.

With `propose_bring` it names the numbers to seal, with an identifier, a description and tags if it wants, and the ones to skip with
a reason. A number from no search, or a provider keyreeve does not know, refuses the whole proposal. It waits under **Agents**.
**Review** looks again where the agent looked, checks each key with its own provider as Bring in does, and opens the review with the
agent's choices marked. Change any of them, or turn off its names, and **Seal** with one fingerprint. A provider the agent names is
only shown: a key is saved with the provider its own evidence names. Sealed keys get identifiers and are not offered to agents, so
the agent does not see them in `list_keys`, and only you can offer them. The agent learns how many were sealed, never which.

### One log for everything

```bash
keyreeve-vault log --since 7d            # one JSON line per event, oldest first
keyreeve-vault log --key resend --csv    # for a spreadsheet
```

It joins the usage log, what agents ran, every check of a key and your own uses, with names in place of file paths. Each decision
you make in the app goes in it too: a level changed, a request answered, a pause. No value is in any of them. In the app's **Log**, a
request or use that repeats, such as a bot polling every thirty seconds, is one row with a count; the file keeps every line.

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

## From a terminal

The `keyreeve` command works on any system with Rust, and needs neither the app nor the vault.

### See what you have

`keyreeve bring` is what the app's Bring in runs. It prints each key it finds, what it is, its provider and whether it works,
and never a value or a change to a file. A key is only sent to the one provider its prefix, variable or client id names:

```bash
keyreeve bring --places --projects ~/code --dry-run   # look, check nothing
keyreeve bring --folder ~/my-keys                     # look and check each key with one read-only request
keyreeve bring --everywhere --dry-run                 # the whole home folder, within two minutes
keyreeve bring --everywhere --under ~/code --dry-run  # go on in a folder it did not finish
```

Add `--json` for the report the app reads: paths, names, lines and where each value stands in its file.

If your keys live in a folder of text files, you can also start here. Neither command changes a file.

```bash
keyreeve inventory ~/my-keys --out ~/.keyreeve/inventory.json
keyreeve catalog ~/.keyreeve/inventory.json --rules ~/.keyreeve/rules.yaml --history ~/.keyreeve/history.jsonl --edits ~/.keyreeve/edits.json --out ~/.keyreeve/catalog.csv
```

`inventory` describes each file: name, date, permissions, format, labels and the kind of key, recognized by its prefix. It reads
`.env` files, JSON and loose notes with `=`, `:`, `=>`, `|` or tabs, in any mix. Whatever follows a separator is ignored. From
comments and notes it keeps only words on a closed list, such as `token` or a provider's name, and a label with any other word is
counted but not shown. To allow your own words, such as project names, pass `--words` with a file of one word per line.

`catalog` gives each file tags and an access level from [your rules](../examples/rules.yaml), and tells you which files they do not
cover. It reads only the inventory, so it never opens a key file.

Values stay out of both, so you can hand them to an agent that must not see your keys. File names and labels do go in, so keep them
private. They are written with mode 600. A password in capitals placed before a separator would read as a variable name, and a file
named after a secret would show that name.

### Check whether a key still works

```bash
keyreeve recipes
keyreeve verify hetzner --key-file ~/my-keys/hetzner.txt
keyreeve verify github --key-file ~/my-keys/app.env --field GITHUB_TOKEN
keyreeve verify --plan ~/.keyreeve/plan.yaml --keys ~/my-keys
```

Each check is one GET request, so it cannot change anything. A provider that uses OAuth first exchanges the key for a token, with a
POST that holds the credentials. It prints the result and never the key. A plan lists many keys at once:

```yaml
keys:
  - { file: hetzner.txt, recipe: hetzner }
  - { file: app.env, recipe: github, field: GITHUB_TOKEN }
```

A rejected key may still be alive for other uses: a restricted token can fail a check it has no permission for. A pass says the key
works, and not what it may do.

## Providers and recipes

Everything about a provider lives in one file, and the app knows no provider by name. A recipe that only checks keys looks like
[`recipes/github.yaml`](../recipes/github.yaml):

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

To rotate, it also says how to create and revoke a key:

```yaml
create:
  method: POST
  path: /v1/keys
  body: { name: "{key_name}" }
  value_from: $.secret
  id_from: $.id
revoke: { method: DELETE, path: "/v1/keys/{id}" }
```

A recipe runs with a credential that can create keys, so a bad one could try to steal it. That is why a recipe is data and has no
way to run code. Requests go over HTTPS, only to the hosts it lists, with redirects off. The credential goes in the header the recipe
names, and it never goes in a body. Only a recipe with `auth: { type: url }` puts it in the address, with `{key}`, for providers
that take it nowhere else. A recipe can still pick the wrong header, or list a host that stores what it receives, so read `hosts`
before you use one.

keyreeve ships recipes for 33 providers in [`recipes/`](../recipes). A file's `tested` line says when it last passed a check with a real
key: 22 of them have. Put your own in `~/.keyreeve/providers/` and it works with no new build, once you approve the hosts it lists, in
Settings or with `keyreeve recipes approve <name>`. Changing its hosts undoes the approval, and a file cannot replace one that ships.
To share it with everyone, open a pull request. [CONTRIBUTING.md](../CONTRIBUTING.md) explains how to write one.

A file can also declare:

| field | what it does |
|---|---|
| `auth: { header }` | sends the key in a header. The usual case |
| `auth: { type: url }` | puts `{key}` in the address, for providers with no other way, such as Telegram |
| `auth: { type: basic }` | HTTP Basic |
| `auth: { type: oauth_token }` | exchanges two or three fields for a short-lived token, such as Google or PayPal. `token_host` is in `hosts`, and the other hosts are the APIs a command may reach with it. `client_id_ends` recognizes a pasted credentials file |
| `auth: { type: aws_sigv4 }` | signs each request, so the secret never travels. AWS and R2 |
| `auth: { type: ssh }` | greets a server with an SSH key through the system's `ssh`, such as a GitHub deploy key |
| `self_hosted: true` | each person gives their own server, approved one at a time, always over HTTPS |
| `prefixes` | finds the key inside a file of notes, and refuses if there are two |
| `alive_if` | a refusal that still proves the key is alive, such as a restricted key |
| `fields` in `identify` | `$.path`, `header:name`, `token:name` or `reply:`. `$.*.slug` keeps every item of a list, such as each organization a token reaches. Name them `scopes` or `expires` to say what a key can do and when it ends |
| `also` in `identify` | up to three more GET requests that only add missing fields, such as Cloudflare's expiry |
| `rotate_every_days` | a suggested age, shown as "older than suggested" |
| `criticality_hint` | a rating from 1 to 5, shown faded until you confirm yours |

A `self_hosted` recipe needs your server first. Typing it in the app approves it.

### Your own checks and buttons

For what a file cannot describe, a file of yours can run a program of yours. See [`examples/providers`](../examples/providers).
Everyone shares the generic files, and your own stay in your folder:

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

The program gets the key on stdin and answers in JSON, such as `{"result":"works","fields":{"account":"me"}}`. It runs with a clean
environment and a time limit, and only after you approve it. Changing the file or the program by even a byte undoes the approval. A
file that ships with keyreeve can never run a program.

A secret with no provider, such as a signing key, is marked as internal, and no check is offered. Secrets for your own products go
the same way: a file of yours, in that folder, never in a repository.

## Where a key lives

**Where it lives**, under a key's **Usage** tab, lists its places, what used it in the last 30 days (program, folder and agent, from
the usage log) and where Bring in found it. **No place known**, above My keys, shows the secrets with none.

A place is a key's identifier, a procedure, its parameters and a label, kept in `~/.keyreeve/key-places.json` with no value. A
procedure is a program that updates one kind of place:

- `<procedure> apply --name=value...` gets the new value on stdin and puts it in place. Exit 0 means it is there.
- `<procedure> check --name=value...` prints one line: the SHA-256 of the value in place, `absent`, or `present` for a place that
  never shows a value again, such as a GitHub secret. Anything else is an error, and keyreeve never shows it.
- Each parameter also arrives as `PLACE_<NAME>`. The environment is otherwise clean, plus `KEYREEVE_VAULT`, the `keyreeve-vault`
  program, for a procedure that calls an API with a token of yours through `keyreeve-vault use`. What a procedure prints when
  applying, and its stderr, are dropped.
- The header names it: `# keyreeve-procedure: what it updates` and one `# param name: what it is` per parameter, `(optional)` first
  for one that can be left out.

| procedure | parameters | how |
|---|---|---|
| `ssh-env` | host, file, variable, service?, compose_dir? | edits a dotenv on a server over ssh with one rename, keeping every other line, then restarts the service or `docker compose up -d` |
| `github-secret` | repo, name, environment? | `gh secret set`, value on stdin. A check says only present or absent |
| `vercel-env` | folder, variable, environment? | the `vercel` command in a linked folder. A check says only present or absent |
| `netlify-env` | token_key, account, site, variable, context? | Netlify's API, with a Netlify token of yours through `keyreeve-vault use` |
| `coolify-env` | token_key, server, app, variable, restart? | Coolify's API, the same way |
| `supabase-secret` | token_key, project, name | Supabase's API, which lists each secret's SHA-256 |

None of these has run against those services yet. `ssh-env` computes the hash on the server, so the value never comes back. The API
ones need `jq`, and their token key must be offered to agents for `use` to reach it. Your own go in `~/.keyreeve/procedures`, which can
be a git repository, as `<name>.sh`. A name that ships cannot be taken. `keyreeve procedures` lists them all with their SHA-256.

```bash
keyreeve procedures
keyreeve place check ssh-env --sha256 <hash> --param host=vps2 --param file=/opt/app/.env --param variable=API_KEY
```

A place is pinned to the SHA-256 of its procedure when you approve it, with your fingerprint, because it receives the real key. The
engine runs a private copy of the exact bytes it hashed. A procedure that changed shows **Changed, needs approval**, and neither
**Update** nor a rotation runs it until you approve it again.

**Check places** runs `check` for each place, with no fingerprint, and compares the hash with the SHA-256 of the key in the vault:
**Same**, **Old value** (an earlier value of this key, such as the one before a rotation), **Different**, **Absent**, or **There,
cannot compare**. The vault keeps a keyed digest of each value, HMAC-SHA256 of its SHA-256 with a key made from the chip key that
needs no fingerprint, in `~/.keyreeve/value-digests.json`. It is written whenever a value is sealed, added, replaced or rotated, and
for a key sealed before, the next time it is opened for any reason, or with **Compare with the vault**. The digest key is made in the
chip with no prompt and never leaves memory, so without this Mac's chip the file says nothing, and a check says **Not compared yet**.
Using places makes that chip key once if the vault has none. Each check goes in the usage log with its result, never the hash.

**Update** opens the key with your fingerprint, runs `apply` with it on stdin, and checks the place again. A rotation shows the same
list before it starts, updates every approved place before the old key is revoked, and leaves out places that wait for approval.

An agent with `list_places` sees the label, procedure, parameters, approval and last check of each place of the keys offered to it,
and only a count for the rest. It can find places by itself, such as by reading which variables a server's env file names, and propose
them with `propose_places`, each with a key, procedure, parameters, label and why. It may also write a new procedure in your
procedures folder. The proposal waits under **Agents**, where you see each place and the full text of any procedure of your folder,
untick what you do not want, and approve the rest with one fingerprint. Declining keeps nothing.

## Rotate a key

Open a sealed key in the app. If its provider can rotate, you say where else the key is used and how long the old key should last,
then press **Rotate this key**. One fingerprint, and keyreeve:

1. Creates the new key at the provider, under a name like `keyreeve-2026-11-06`, and seals it.
2. Tries it. If it fails, the new key is revoked and everything stays as it was.
3. Updates every place: files where the old value is replaced, and buttons of your own that receive the new key on stdin. If one
   fails, every place is restored and the new key is revoked.
4. Makes the new key current, and waits out the overlap if you set one.
5. Revokes the old key, right away or later when you press the button in **Rotation**.

Each step is written to a journal first, `~/.keyreeve/rotations.jsonl`, so a crash at any step resumes or undoes the rotation. The
journal holds key ids and step names, never values.

Most providers give no way to learn the id of a key you already have, so the first rotation may ask you to revoke the old key by
hand. Later ones know the id.

There are three ways to rotate, and a provider's file says which:

- **Two keys for a while.** Resend and LangSmith. A failure anywhere before the old key goes undoes everything.
- **`rotation: single`.** GitLab and Cal.com end the old key the moment the new one exists, so nothing can be undone. A place that
  fails is reported for you to fix, and the rotation goes on.
- **By hand.** A provider with no way to make keys through its API, such as Hetzner or Netlify. You make the key at its page and paste
  it in. keyreeve tests it, updates the places, and then checks that the old key really died once you revoke it. This works for
  providers that test a key with one plain request.

None of these has run against a real service yet, and the list in Settings shows what each file has been tried with. To add a
provider, give its file `create` and `revoke`, and `keyreeve simulate` tests it against failures and crashes. The simulator's
guarantees do not apply to `rotation: single`.

A place can be a file, a button of yours that receives the new key on stdin, or a place a procedure updates
([above](#where-a-key-lives)). There are [examples](../examples/places) of buttons for GitHub Actions, Vercel and an env file on a
server, which have not been run against those services. A key joined from two fields, such as
AWS, cannot rotate yet.

## What is missing

- A rotation tried against a real provider
- Prebuilt downloads, which need an Apple signature for the app
- Reading a provider's early answer during an upload. A provider that refuses a large body before reading it gets a 502 back from the proxy
- Using the vault on Linux and Windows, and a chip-free key for them. The file format already works there
- Other vaults as storage, such as 1Password or the system keychain
- A scan by keyreeve itself that finds where each key is used, beyond what agents propose, and which permissions each key has
- Recipes for more providers that can rotate, keys made of two fields, and rotation written as a program of yours
- A stand-in for roles inside [seisin](https://github.com/carlostapiacl/seisin), so they reach a provider through the proxy and never hold the key
- One fingerprint for several seisin runs, without letting any other program ride on it
