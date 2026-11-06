# Contributing

The most useful contribution is a recipe for a provider you use. New key prefixes and label words for
`keyreeve inventory` are also welcome, in `KINDS` and `KNOWN_WORDS` in `src/inventory.rs`, with a link to
where the provider documents the prefix. A label word must be common enough that it cannot be a password.

## Writing a recipe

Copy `examples/recipe.yaml` to `recipes/<provider>.yaml`. The `recipes/` folder does not exist yet, so
yours may be the first.

| field | what it is |
|---|---|
| `schema` | always `1` |
| `provider` | lowercase letters, digits and hyphens |
| `hosts` | every domain the recipe talks to |
| `auth.header` | the header that carries the credential |
| `auth.prefix` | text before the credential, such as `"Bearer "` |
| `headers` | optional fixed headers, such as an API version |
| `create` | creates a key. Needs `value_from` and `id_from`, the paths to each in the answer |
| `verify` | a request that only succeeds with a working key. It runs with the new key |
| `revoke` | revokes a key by `{id}`. A 404 counts as already revoked |

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

## Changing the engine

`cargo test` must pass, and so must `cargo clippy --all-targets -- -D warnings`. If you change the order of
a rotation, add the failure you are guarding against to `src/simulate.rs`.
