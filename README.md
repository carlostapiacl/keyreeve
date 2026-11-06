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

You need [Rust](https://rustup.rs). This runs offline and uses no real keys.

```bash
git clone https://github.com/carlostapiacl/keyreeve
cd keyreeve
cargo run -- check examples/recipe.yaml
cargo run -- simulate examples/recipe.yaml
```

`simulate` builds a fake provider from the recipe, injects failures and stops the process at
every operation, then again at every operation of the recovery. After each stop it checks that:

- the stored key and every service hold a key that works
- when the rotation closes, they all hold the same key and no temporary copy remains
- any leftover key at the provider was reported for manual cleanup
- no key value reached the journal, an error or an outcome

A pass means the recipe and the engine hold up against the simulator. It does not prove that the
real provider behaves as the recipe describes.

## See what you have

```bash
cargo run -- inventory ~/my-keys --out ~/.keyreeve/inventory.json
```

This describes a folder of keys: file names, dates, permissions, formats, labels and the kind of key,
recognized by its prefix. It reads `.env` files, JSON and loose notes with `=`, `:`, `=>`, `|` or tabs, in
any mix. Whatever follows a separator is ignored. From comments and notes it keeps only words on a closed
list, such as `token` or a provider's name. A label with any other word is counted but not shown.

Values stay out, so you can hand the report to an agent that must not see them. File names and labels do
go in, so keep the report private. A password in capitals placed before a separator would read as a
variable name, and a file named after a secret would show that name. It is written with mode 600.

## What is missing

- `keyreeve rotate` and `resume` as commands, and a test against a real provider
- Keychain storage (macOS and Linux first)
- Places to update: `.env`, GitHub, Netlify
- Recipes for real providers
- A local panel to see each key, its age and its history
- Approvals that expire
- Integration with [seisin](https://github.com/carlostapiacl/seisin), which gives each agent its own keys

## Security

[THREAT_MODEL.md](THREAT_MODEL.md) lists what this protects against and what it does not.
To report a vulnerability, use [private reporting](https://github.com/carlostapiacl/keyreeve/security/advisories/new).

## License

[MIT](LICENSE)
