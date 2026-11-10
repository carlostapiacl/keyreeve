# Threat model

keyreeve holds credentials that can create and revoke keys, so a mistake here costs more than
in most tools. This file covers the code that exists today. It grows with each feature.

## What it protects against

**A malicious or careless recipe.** Recipes are YAML with a closed list of fields and no way to
run code.

- Hosts must be bare domains. Schemes, ports, IP addresses and wildcards are refused.
- The client uses HTTPS only and does not follow redirects, so a 302 cannot carry the credential
  to another host.
- A secret goes in the header the recipe names. The only placeholder for it is `{key}`, allowed in the address of a recipe with
  `auth: { type: url }`, for providers such as Telegram that take it nowhere else. `{key_name}` and `{id}` exist where they apply.
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

**A check that changes something.** `keyreeve verify` only sends a GET. A recipe whose check is another method passes
`keyreeve check`, but its check is never run. A provider using OAuth first gets a token, with a POST holding the credentials. Provider answers are ignored apart from their status. A provider can still count or log the request, and
a bad GET endpoint on its side could have effects.

**A provider answer that holds too much.** `identify` keeps only the fields the provider's file declares, drops any that
look like a credential or contain the key, and writes them to a private file. The command reports how many fields it found,
and not their values.

**A new key that is not a key.** A provider's answer ends up in your files, some of which a shell reads, so a new key with
characters like `$` or a space is refused before it lands. The rotation then undoes itself.

**A provider file you added.** It receives no key until you approve the hosts it lists. Editing its hosts undoes the approval,
and it cannot take the name of a provider that ships. A plan, your rules and your edits can only name a provider. A path to a
recipe is accepted only when typed at the `verify` command for one run, and such a recipe cannot run a program.

## What it does not protect against

- **A recipe that lists a malicious host.** It can send the credential to any host it declares.
  Listing the hosts is what makes this visible, so you have to read them. A provider file of yours that you approved is trusted
  for the hosts it listed then: changing them undoes the approval until you approve it again.
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

The vault holds one age file per key, sealed for two keys: one inside the Secure Enclave, which asks for a fingerprint, and a
recovery key held by you. Each value carries its name inside, so a value cannot be swapped under another name.

- **Any program running as you can ask for your finger,** with text of its own in the prompt. Only touch the sensor
  when you asked for something. The fingerprint is a check on you, and it does not identify the program asking.
- **Any program running as you can replace `vault.json`** with one it can open. Later additions would then be sealed
  for its keys, and a deleted file loses your keys. Keep backups, and watch for prompts you did not expect.
- **A key in use is in memory,** in the variable `run` sets and in the command that receives it.
- **The recovery key opens everything.** Whoever holds it does not need the Mac.
- **A copy of the vault is every key, sealed.** It opens only with the recovery key, so keep the two apart. A copy also keeps keys
  you later replaced or revoked, as they were on that day.
- **The app's lock covers the window.** The catalog it shows is a plain file with names and results, and it never holds
  a value.
- **A program of yours is yours.** A provider file you approved can run a program with your permissions, and it sees the
  key it checks. keyreeve pins the file and the program by hash, gives it a clean environment and filters what it says, and
  that does not make a bad program safe. Read what you approve. The hash lives in a file you own, so another program running
  as you could change it too.
- **The weekly check runs with no fingerprint.** It covers only keys you set to "Checked without asking", and it reads them from
  your files, so a key whose file left the folder is skipped and not reported. Turn it off in Settings.
- **A fingerprint lasts a while.** During the period you choose, 5 minutes by default, the app checks "Ask me" keys without
  asking. It applies to buttons in the app alone. Locking ends it, and the vault asks every time.
- **One fingerprint opens a whole batch.** The prompt states how many keys, and not which. While a batch runs, its opened
  values are in the app's memory and the command's, and they reach the command on stdin, so they never appear in arguments
  or variables. Swift strings are not wiped.
- **An SSH key checked from the vault touches the disk.** A check through `ssh` reads keys from files, so the sealed copy spends the call in a file
  only you can read, overwritten and removed afterwards. A crash in between leaves it there.
- **A program running as you can change the app.** It can replace `keyreeve-cli` or `keyreeve-vault` inside the bundle, and the
  next fingerprint then hands opened keys to its copy. An agent you run as yourself can do this too, so if you need to keep keys
  from an agent, run the agent as another macOS user or in a sandbox that cannot write here. Without an Apple signature
  the app cannot check its own parts.
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
- **This code has had no outside review.** The file format is age's, and tests compare it with the official tool in both
  directions, including `p256tag` for the chip. Writing it here is what lets one fingerprint cover a batch and leaves no plugin to
  trust. Decrypting with the chip was never compared with age's plugin for it.
- **An agent's program holds the key.** Over MCP an agent runs programs a person allowed, with a fingerprint each time. The output
  hides the plain key and its base64, and a program can hide it another way, so the allowed list is the protection. The agent runs as
  you, so it can also edit `agents.toml` and then ask for your finger. Read the prompt: it starts with keyreeve's own words, the agent, the key and its account, the program and for how long, and
  ends with the agent's reason, cut to one short line and set apart in quotes. Anything in quotes is the agent talking. The reason
  in the request window is the agent's own text, set apart in quotes, and it can say anything.
- **A yes for hours keeps the key open.** For a program you allowed, the agent server holds the opened key in memory until the time
  runs out, the agent session ends, or you quit Keyreeve or press Lock everything. Through the proxy, the key service holds it. Either way, during that time the
  agent uses it without asking, with whatever command it picks, and a free key works that way until you quit Keyreeve. Locking the window does not end it.
- **`get` hands out the real key.** It is for tools such as seisin that take a key from a command's output. It asks for your finger
  every time and never remembers a yes, because any program running as you could run it again. What it prints is in the hands of
  whoever ran it: seisin keeps it inside one role, masks it in the output and limits where the role can connect.
- **An agent that sorts sees names.** With "Agents can sort my keys" on, `inventory` gives an agent every file's path, field
  names, tags, provider and state. Never a value, but names can say a lot. `propose` changes nothing on its own: it waits for you,
  and Apply may check keys, sending each one only to its provider's hosts, or to a server of yours you approved. `rotate_key` and
  `request_access` also only leave a request. The reason an agent gives is its own text.
- **A key not offered is hidden from the agent tools, not from the disk.** `list_keys`, `request_access`, `use_key` and
  `run_with_key` leave out a key that is not offered, and its name answers as one that is not there. `keys.toml` holds no value
  but every name, and any program running as you can read it, or edit it to offer a key. Using that key still takes its level,
  and a fingerprint for every level but the one you set to need none.
- **Your terminal AI may read your files.** keyreeve hands it names and asks it for words, never a key, in an empty folder with a
  small environment. Claude Code is limited to web search; Codex, OpenCode and a command of your own can read what you can.
- **Naming the agent is a hint.** keyreeve reads which program started its server, so "only Claude" keeps an honest Codex out. A program
  running as you can start the server under any name.
- **The agent terminal keeps what came back.** The first 2,000 characters of each command's output stay in a private file, with the key
  and its stand-in taken out. A provider's answer can hold other private data, and a program that hides the key another way is not caught.
- **A permission belongs to the key and program, not to a process.** While one is open, any program running as you that asks
  the service for the same key and program uses it with no fingerprint. Who asked is recorded from the process tree, which a
  program running as you can shape. Keeping agents apart from each other takes separate users or sandboxes.
- **An SSH permission runs a real ssh-agent.** It holds the key, behind a door that only lets logins through, in a folder only
  you can open. A program running as you can find that agent's own socket and ask it to sign anything while the permission
  lasts. The key itself still never leaves it.
- **A command run for an agent gets the agent server's environment,** plus the stand-in and the proxy. Anything else in that
  environment, such as the agent's own login, the command can read.
- **The proxy's tunnels reach the internet only.** A request to a host that is not the key's goes through untouched, and
  never to this machine, a private network or the cloud metadata address. A key's own hosts come from its recipe, even a
  private one for a provider you host yourself.
- **What a command leaves running ends with it,** by its process group. A program that starts a new session on purpose leaves
  the group, and keeps running with what it was given.
- **A pinned program is pinned by its file.** A script that calls other programs is checked, and those programs are not.
- **A copied key is on the clipboard for up to 60 seconds.** Any program running as you can read it in that time. The marks that ask
  history tools to skip it are a convention, and a tool can ignore them.
- **The list of programs that cannot be allowed is not complete.** It stops the obvious ways to read a key. A program you allow
  and the arguments an agent gives it can still reach it.
- **A stand-in does not confine a program.** The real key stays in the proxy's memory and the command holds a stand-in, so
  `printenv` and a leaked variable give nothing. A program running as you can still use the key through the proxy while a permission lasts,
  doing whatever that key allows at its provider, and it can read your original files or replace these binaries. keyreeve is not a
  sandbox. If that matters, run the agent in one, and keep the keys folder and `~/.keyreeve` out of its reach.
- **The stand-in is a credential for the proxy.** Any program that gets it can use the key through the proxy while the permission
  lasts, and any local program can open a plain tunnel through the proxy, which gives it nothing it could not do alone.
  It keeps the key's shape, so its randomness depends on it: each character is drawn evenly, and a key whose shape leaves under
  64 bits is used with `--real` rather than given a stand-in that could be guessed. Guessing means sending requests to this
  machine's proxy while the permission lasts, a day at most.
- **The proxy reads that traffic.** It ends TLS for a key's hosts, with a CA made for each run whose key stays in memory. Only commands
  started by `use` are pointed at that CA. The system's own trust store is never touched.
- **A provider can hand the real key back.** One that stores what it receives and returns it later could, though the stand-in in a body stays a
  stand-in, and a reply is scrubbed, including across chunks. A provider that compresses a reply it was asked not to compress is not scrubbed.
- **`--real` is the real key.** A fingerprint is asked each time, and from there it is in the command's hands. So is the MCP server's
  `run_with_key` and `env`, which give the real value to the program they run. `run_with_key` gives the field keys.toml names for the key and no
  other, so a program allowed for one key of a file never receives another key of the same file.
- **An SSH permission lets anything running as you log in.** The key stays in `ssh-agent`, out of reach through the door, and no signature is made for
  anything but a login. While a permission lasts, any program of yours that finds the socket can use it to log in. The server check holds for a real
  `ssh`, which names its server truthfully. A program that speaks the protocol itself can name a server key of its own, and the agent accepts that as long as the
  signature matches, so it can take the free first server under an invented name, or trigger a prompt with the wrong fingerprint, while logging in somewhere else.
  The log then shows that invented fingerprint. Listing `servers` in `keys.toml` removes the free one, so only a prompt with a fingerprint you do not recognize is left.
- **A passphrase passes through a dialog.** It goes from a system dialog to `ssh-add` over a pipe, and any program running as you could show a dialog that looks the same.
- **An SSH key sits in a system process.** `ssh-agent` holds it opened until the permission ends, at the limit given to `ssh-add`. If the service is killed the agent stays with
  the key until that limit or until the service starts again. A login already open keeps working after the permission ends.
- **The usage log shows who, not proof of who.** A process and its parents come from the system. An agent can start a command through
  something else, and everything under your user looks alike. It can also rewrite the log and its hashes.
- **A key marked "always, no fingerprint" asks nobody.** Its copy is sealed to a second key in the chip that needs no presence, so while
  this Mac is unlocked any program running as you that reaches the key service can use it through the proxy, never see it. The service
  reads the mark from your own files on each use, the pause stops it, and taking the mark off removes the copy. The chip key never leaves
  this Mac, and a vault moved to a new one drops every copy.
- **A lost answer is not a no.** A request that went out with a key and got no whole reply is written down with how far it got, since the
  provider may have acted on it. When the key service does not answer, keyreeve says it does not know what happened, and closing a key in the
  app shows an error until the service confirms the permissions ended. Quitting Keyreeve ends them all.
- **An env file's references name your keys.** `keyreeve://` holds no value, but it says which keys exist.
- **A key you paste by hand** passes through the app's memory on its way to the vault, and Swift strings are not wiped.
- **A single rotation cannot be undone.** A provider that ends the old key at once leaves you with whatever comes back. If the
  answer is lost, or the new key fails, you make another at its page.

## Known limits of the simulator

It tests the engine against a fake built from the recipe, so it cannot catch a recipe that is wrong
about the real provider. It also assumes a new key works as soon as it is created. A provider that
takes time to activate a key would fail `verify` and roll back, and there are no retries yet.
No rotation has run against a real provider yet.
