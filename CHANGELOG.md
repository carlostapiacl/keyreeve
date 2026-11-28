# Changelog

Each release lists what changed for the person using keyreeve. Versions follow [semver](https://semver.org); while
keyreeve is in alpha, a release may change a file format, and says so here.

## 0.1.0-alpha.1 (2026-11-28)

The first release with downloads: Keyreeve.app for Apple silicon, the `keyreeve` command for Linux, and a Homebrew tap.

- **Vault.** Keys sealed for the Secure Enclave and a recovery key, as standard age files. Bring in keys from where tools
  keep them, add one by pasting it, back the vault up.
- **Checks.** One read-only request per key, with 33 recipes for providers.
- **Agents.** An MCP server (`keyreeve-vault mcp`) whose tools never return a value. A command runs with a stand-in and a
  local proxy puts the real key only on requests to that key's provider. Levels: Only me, Ask, Free, Always.
- **Coding agents and MCP servers.** A whole coding agent can run under `use`, and a remote MCP server that signs in with
  OAuth can be signed in by keyreeve, which renews its access token itself.
- **Window.** Three places: Home, My keys and Tools.
- **Rotation is experimental.** It passes the simulator and has not run against a real provider yet.

Not signed with an Apple Developer ID: macOS asks you to allow Keyreeve the first time you open it (see the README).
