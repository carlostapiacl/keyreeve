## What changes

<!-- What this changes for the person using keyreeve. -->

## For a recipe

- [ ] A link to the provider's documentation for each step
- [ ] The permission the credential needs, as narrow as the provider allows
- [ ] How long a new key takes to start working, if you know
- [ ] Whether it ran against a real account, and when
- [ ] `keyreeve check` and `keyreeve simulate` pass

## Checks

- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] `swift test` in `app/` passes, if the app or the vault changed
- [ ] No real key, key id or provider response anywhere in this pull request
