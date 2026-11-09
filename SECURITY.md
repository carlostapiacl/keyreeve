# Security policy

keyreeve holds API keys, so a flaw in it can expose them. Thank you for taking the time to report one.

## Supported versions

There are no releases yet. Fixes go to the `main` branch, and only `main` is supported. Build from it to get them.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting instead:
[Security → Report a vulnerability](https://github.com/carlostapiacl/keyreeve/security/advisories/new).
Only the maintainer sees the report.

A useful report says:

- what an attacker can do, and what they need first (a recipe you install, a program running as you, a provider that answers
  in a certain way)
- the steps to reproduce it, with the commit you tried
- what you expected instead

Never include a real key, a real key id or a real provider response. Made-up values are enough.

## What to expect

keyreeve is maintained by one person in their spare time. You will get an answer in the report, and the fix is worked on there,
in a private fork when it helps. Once a fix is on `main`, the advisory is published with credit to you, unless you prefer not to
be named. If a report turns out to be a limit already listed in the threat model, the answer says so and points to it.

## Scope

[THREAT_MODEL.md](THREAT_MODEL.md) lists what keyreeve protects against and what it does not. In short, these are known limits
and not vulnerabilities:

- **Anything running as your user.** It can read the same files and memory. keyreeve is not a sandbox.
- **A recipe or provider file that lists a malicious host, or names the wrong header.** Read `hosts` before you approve one.
- **A provider, or a dependency, that is compromised.**
- **Memory copies** made by the HTTP client and the JSON parser, which are not wiped.

A way around one of the protections the threat model does claim is in scope, such as a recipe that runs code, a key that reaches
a host its recipe does not list, a value written to a log or journal, an agent that uses a key without the permission its level
requires, or a sealed key opened without the Secure Enclave or the recovery key.
