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
keyreeve catalog ~/.keyreeve/inventory.json --rules ~/.keyreeve/rules.yaml --history ~/.keyreeve/history.jsonl --out ~/.keyreeve/catalog.csv
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

A recipe with only `verify` is enough to check a key, and it is the easiest way to contribute. A rejected key may
still be alive for other uses: a restricted token can fail a check it has no permission for. Cloudflare's check
only covers user tokens, so an account token reads as rejected. A pass says the key works, and not what it may do.
The `hetzner` and `langsmith` recipes have passed with a real key. The others have only been shown to reject a
fake one, except `meta`, `instagram` and `cloudflare`, which have also rejected old real keys.

## The Mac app

A native window over your catalog, with no web inside. It opens with your fingerprint or your Mac's password.
This lock covers the window. Keys are protected by the vault below.

```bash
app/build-app.sh
open app/dist/Keyreeve.app
```

It reads `~/.keyreeve/catalog.csv`. The overview shows what to do first, such as an old copy that still works or a key
that was rejected, along with how many keys were checked, how old the files are and what happened lately. It scans
the folder each time it opens, and Refresh scans it again. Each use through the vault is recorded with the key's name and the program's name, and no value. The Check button sends one read-only request for each key, and keys set
to `ask` need your fingerprint first. Keys set to `never` are not offered. The build is not notarized, so macOS warns
you the first time.

A check sends a key to a provider, so a tag is not enough for it. A key is offered only if your rules name its recipe,
or if its prefix proves the provider:

```yaml
files:
  app.env: { recipes: [github], field: GITHUB_TOKEN }
```

## The vault (Mac)

```bash
app/dist/keyreeve-vault init
app/dist/keyreeve-vault add hosting-token
app/dist/keyreeve-vault run hosting-token --as HOSTING_TOKEN -- ./deploy.sh
```

Each key is sealed in a file by a key inside your Mac's Secure Enclave, which it cannot leave. Adding a key needs no
fingerprint, so an agent can store a key it cannot read back. Using one asks for your finger. `init` shows a
recovery key once, and refuses to run outside a terminal so the key does not land in a log. Keep it away from this
Mac, because if the Mac dies it is the only way back in. There is no command that prints a key.

The vault format is mine and has had no outside review, so keep your old copies until it has. It does not yet
connect to `verify` or to the app.

## What is missing

- `keyreeve rotate` and `resume` as commands, and a test against a real provider
- Connecting the vault to `verify` and to rotation, and storage for Linux and Windows
- Places to update: `.env`, GitHub, Netlify
- Recipes that can rotate a real provider
- Editing tags and levels in the app
- Approvals that expire
- Integration with [seisin](https://github.com/carlostapiacl/seisin), which gives each agent its own keys

## Security

[THREAT_MODEL.md](THREAT_MODEL.md) lists what this protects against and what it does not.
To report a vulnerability, use [private reporting](https://github.com/carlostapiacl/keyreeve/security/advisories/new).

## License

[MIT](LICENSE)
