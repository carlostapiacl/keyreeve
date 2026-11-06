# Threat model

keyreeve holds credentials that can create and revoke keys, so a mistake here costs more than
in most tools. This file covers the code that exists today. It grows with each feature.

## What it protects against

**A malicious or careless recipe.** Recipes are YAML with a closed list of fields and no way to
run code.

- Hosts must be bare domains. Schemes, ports, IP addresses and wildcards are refused.
- The client uses HTTPS only and does not follow redirects, so a 302 cannot carry the credential
  to another host.
- A secret has no placeholder. Only `{key_name}` and `{id}` exist, and only where they apply.
- Values placed in a path are percent-encoded, so an id returned by a provider cannot change the
  path.
- Headers that could replace the credential or reshape the request are refused.

**A crash or a failure halfway.** The new key is saved before anything uses it, and the old key is
revoked last. A new key is not revoked while a service may still hold it. The simulator tests this
at every operation.

**A value reaching a log.** The `Secret` type prints as `[redacted]`, has no serializer and is
wiped from memory on drop. Provider responses are kept out of errors, and client errors are dropped
because they can quote the request. The simulator checks the journal, errors and outcomes for its
test values.

## What it does not protect against

- **A recipe that lists a malicious host.** It can send the credential to any host it declares.
  Listing the hosts is what makes this visible, so you have to read them. Changing the hosts on
  a recipe update should require new approval, and that check does not exist yet.
- **A recipe that names the wrong header.** Validation cannot know which header a provider reads.
- **A host that stores what it receives,** such as one that logs headers.
- **Anything running as your user.** It can read the same memory and files.
- **A compromised provider, or a dependency of this tool.**
- **Memory copies.** Wiping covers the `Secret` type. The HTTP client and the JSON parser make their
  own copies, and those are not wiped.
- **A key lost in the gap between the provider's answer and the journal write.** A crash there leaves
  a key at the provider that nobody holds. The journal then asks you to check the provider, because
  keyreeve cannot know.

## Known limits of the simulator

It tests the engine against a fake built from the recipe, so it cannot catch a recipe that is wrong
about the real provider. It also assumes a new key works as soon as it is created. A provider that
takes time to activate a key would fail `verify` and roll back, and there are no retries yet.
