# Contributing

The most useful contribution is a recipe for a provider you use. New key prefixes and label words for
`keyreeve inventory` are also welcome, in `KINDS` and `KNOWN_WORDS` in `src/inventory.rs`, with a link to
where the provider documents the prefix. A label word must be common enough that it cannot be a password.

## Writing a recipe

A recipe that only checks a key needs `verify` and no `create` or `revoke`. See `recipes/hetzner.yaml`. Add it to
`BUILTIN` in `src/verify.rs` so it ships with the tool. The check must be a GET. Run it with a made-up key first: if
the provider answers something other than 401, list that status in `reject`.

To rotate too, copy `examples/recipe.yaml` to `recipes/<provider>.yaml`.

| field | what it is |
|---|---|
| `schema` | always `1` |
| `provider` | lowercase letters, digits and hyphens |
| `hosts` | every domain the recipe talks to |
| `auth.header` | the header that carries the credential |
| `auth.prefix` | text before the credential, such as `"Bearer "` |
| `headers` | optional fixed headers, such as an API version |
| `create` | optional, creates a key. Needs `value_from` and `id_from`, the paths to each in the answer |
| `verify` | a request that only succeeds with a working key. `reject` lists 4xx statuses that mean a bad key, besides 401 |
| `revoke` | optional, goes with `create`. Revokes a key by `{id}`. A 404 counts as already revoked |

Each step takes `method`, `path` and, when needed, `host`, `body` and `expect` (a 2xx status).

`{key_name}` is available in `create`, and `{id}` in `verify` and `revoke`. Paths look like `$.a.b`
or `$.data.0.id`.

## Before you open a pull request

```bash
keyreeve check recipes/<provider>.yaml
keyreeve simulate recipes/<provider>.yaml
```

Your pull request should say:

- a link to the provider's documentation for each step
- the permission the credential needs, as narrow as the provider allows
- how long a new key takes to start working, if you know
- whether you ran it against a real account, and when

Never paste a real key, a real id or a real response. If you used someone else's guide, write the recipe
from the provider's documentation. A recipe must be under MIT, and some guides have other licenses.

## Changing the app or the vault

Run `swift test` in `app/`, which needs only the Command Line Tools. Set `KEYREEVE_RENDER_DIR` to a folder to keep
images of each view, in light and dark. CI does not build the app, so say in your pull request that you ran these.

## Changing the engine

`cargo test` must pass, and so must `cargo clippy --all-targets -- -D warnings`. If you change the order of
a rotation, add the failure you are guarding against to `src/simulate.rs`.
