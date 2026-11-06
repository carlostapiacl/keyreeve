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

**A check that changes something.** `keyreeve verify` only sends a GET, and refuses a recipe whose check is another
method. Provider answers are ignored apart from their status. A provider can still count or log the request, and
a bad GET endpoint on its side could have effects.

**A provider answer that holds too much.** `identify` keeps only the fields the provider's file declares, drops any that
look like a credential or contain the key, and writes them to a private file. The command reports how many fields it found,
and not their values.

**A provider file you added.** It receives no key until you approve the hosts it lists. Editing its hosts undoes the approval,
and it cannot take the name of a provider that ships. A plan, your rules and your edits can only name a provider. A path to a
recipe is accepted only when typed at the `verify` command for one run, and such a recipe cannot run a program.

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

## The vault and the Mac app

The vault is a file sealed for two keys: one inside the Secure Enclave, which asks for a fingerprint, and a recovery
key held by you. Each value is bound to its name, so a value cannot be swapped under another name.

- **Any program running as you can ask for your finger,** with text of its own in the prompt. Only touch the sensor
  when you asked for something. The fingerprint is a check on you, and it does not identify the program asking.
- **Any program running as you can replace `vault.json`** with one it can open. Later additions would then be sealed
  for its keys, and a deleted file loses your keys. Keep backups, and watch for prompts you did not expect.
- **A key in use is in memory,** in the variable `run` sets and in the command that receives it.
- **The recovery key opens everything.** Whoever holds it does not need the Mac.
- **The app's lock covers the window.** The catalog it shows is a plain file with names and results, and it never holds
  a value.
- **A program of yours is yours.** A provider file you approved can run a program with your permissions, and it sees the
  key it checks. keyreeve pins the file and the program by hash, gives it a clean environment and filters what it says, and
  that does not make a bad program safe. Read what you approve. The hash lives in a file you own, so another program running
  as you could change it too.
- **The weekly check runs with no fingerprint.** It covers only keys you set to "Agents can use it", and it reads them from
  your files. Turn it off in Settings.
- **A fingerprint lasts a while.** During the period you choose, 5 minutes by default, the app checks "Ask me" keys without
  asking. It applies to buttons in the app alone. Locking ends it, and the vault asks every time.
- **One fingerprint opens a whole batch.** The prompt states how many keys, and not which. While a batch runs, its opened
  values are in the app's memory and the command's, and they reach the command on stdin, so they never appear in arguments
  or variables. Swift strings are not wiped.
- **An SSH key from the vault touches the disk.** `ssh` reads keys from files, so the sealed copy spends the call in a file
  only you can read, overwritten and removed afterwards. A crash in between leaves it there.
- **A rotation writes where you pointed it.** `places.json` names files and buttons that receive the new key, and a program
  running as you could add one. A file must already hold the key, and a button must come from a file you approved, but a
  program that can edit your files could meet both.
- **A moved original is still a key.** It stays in plain text in `~/.keyreeve/originals` until you delete it, and a rotation does
  not update it.
- **Replacing keeps the old value.** Old copies stay sealed in the vault, including keys already revoked.
- **A copy's folder is written in plain text.** Each copy notes the folder it came from, so the same path in another folder is
  not mistaken for it. A program running as you could edit that note.
- **Sealing is not moving.** Until you remove an original, the file is as readable as before, and anything that reads it
  gets the key with no fingerprint. The weekly check still reads files.
- **The screen shows the recovery key.** Anything recording your screen can see it, and the app cannot tell.
- **A key in the address.** Some providers accept a key only in the URL. It travels inside HTTPS, but such a provider may
  log its own addresses, which is why this is a declared `auth: { type: url }` and never a default.
- **The app's settings decide where a key is sent.** `edits.json` and your rules name the recipe for each key. A program
  running as you could change them, and the next check would send the key to another listed provider.
- **Pressing "I already revoked it" is proof only with a check.** A key with no recipe is marked on your word alone.
- **The format has had no outside review.** It uses standard CryptoKit parts (P-256, HKDF, AES-GCM), put together here.

## Known limits of the simulator

It tests the engine against a fake built from the recipe, so it cannot catch a recipe that is wrong
about the real provider. It also assumes a new key works as soon as it is created. A provider that
takes time to activate a key would fail `verify` and roll back, and there are no retries yet.
No rotation has run against a real provider yet.
