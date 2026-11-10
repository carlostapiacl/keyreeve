//! One file per family of commands. Each reads its arguments and prints, and the work lives in the library.

mod bring;
mod catalog;
mod checks;
mod proxy;
mod recipes;
mod rotation;

use keyreeve::verify;
use std::collections::HashMap;
use std::process::ExitCode;

pub use bring::run_bring;
pub use catalog::{run_catalog, run_inventory, run_migrate};
pub use checks::{run_check_free, run_custom_action, run_identify, run_verify};
pub use proxy::run_proxy;
pub use recipes::{run_recipe_files, run_recipes};
pub use rotation::{run_rotate, run_rotations};

pub const HELP: &str = "\
keyreeve rotates API keys on your own machine.

Usage:
  keyreeve check <recipe.yaml>...
      Validate recipes.
  keyreeve simulate <recipe.yaml>...
      Run recipes through failures and crashes, offline.
  keyreeve inventory <folder> --out <file.json> [--words <file>]
      Describe a folder of keys, without their values.
  keyreeve catalog <inventory.json> --out <file.csv> [--rules <rules.yaml>] [--history <file>] [--edits <file>] [--moved <file>] [--keys <keys.toml>]
      Give each file tags and an access level, from your rules, and from keys.toml once it holds every key.
  keyreeve migrate <folder> [--dry-run]
      Write in <folder>/keys.toml one entry per key, from the rules, the app's edits and what providers said.
      Identifiers keep their names; files with none get one, not offered to agents. A copy of each file
      read goes to <folder>/backups first. Run twice, it changes nothing.
  keyreeve bring --places [--projects <folder>]... [--dry-run] [--check] [--json]
  keyreeve bring --folder <folder> [--dry-run] [--check] [--json]
  keyreeve bring --everywhere [--under <folder>]... [--dry-run] [--check] [--json]
      Find keys in the places tools keep them on this Mac (and in .env files under the project
      folders you name), or in a folder, or with --everywhere in the whole home folder or the folders
      under --under (.env files and files that hold keys, within a time budget; folders not finished
      are named), and say what each is: a key, a setting, a login, a document
      or a public key, its provider, and whether it works. Parts of one key go together, and the same
      key in two places is one key. Values are never shown, and no file is moved or changed. A key is
      checked with one read-only request, only by the one provider its prefix, its variable or its
      client id names; a name alone is only a guess. Nothing is checked with --dry-run (unless --check).
  keyreeve verify <provider|recipe.yaml> --key-file <file> [--field <name>]
  keyreeve verify <provider> --key-stdin [--field <name>]
      Check whether a key still works, with one read-only request.
  keyreeve verify --plan <plan.yaml> --keys <folder> [--history <file>] [--progress] [--sealed-stdin]
      Check several keys at once, and keep the results. --sealed-stdin takes a JSON map of paths to
      file text, and uses it in place of those files. The Mac app sends this.
  keyreeve action <provider> <action> [--key-file <file>] [--field <name>] [--key-stdin]
      Run a button of your own, from a provider file of yours. --key-stdin reads the key's file from stdin.
  keyreeve check-free [--notify] [--spanish]
      Check the keys agents can use, which need no fingerprint. For a weekly schedule.
  keyreeve identify --plan <plan.yaml> --keys <folder> --details <file> [--sealed-stdin]
      Ask each provider whose key this is, and keep only the fields its file declares.
  keyreeve rotate --plan <plan.json> --vault-tool <program> --journal <file> [--resume] [--revoke-now]
      Rotate one key held in the vault, with the opened copies as JSON on stdin. The Mac app sends this.
  keyreeve rotations --journal <file> [--forget-id <key>]
      Show where each rotation stands, as JSON. It holds ids and step names, never values.
      --forget-id notes that a key was replaced by hand, so its old id is not used again.
  keyreeve proxy --run-dir <folder>
      Let commands use keys they never hold. The vault's service starts this and talks to it over stdin.
  keyreeve recipes [--json]
      List the providers keyreeve knows, from what ships and from ~/.keyreeve/providers.
  keyreeve recipes show <provider>
      Print a recipe that ships with keyreeve, to start a provider of your own from it.
  keyreeve recipes approve <provider>
      Allow a provider file of yours to receive keys at the hosts it lists.
  keyreeve recipes approve-host <provider> <server>
      Allow your own server, for a provider each person runs themselves.
  keyreeve --version
";

/// Reads `--name value` options after the positional argument.
pub(super) fn options<'a>(
    args: &'a [String],
    names: &[&str],
) -> Option<(&'a str, HashMap<String, &'a str>)> {
    let (first, rest) = args.split_first()?;
    let mut found = HashMap::new();
    for pair in rest.chunks(2) {
        let [name, value] = pair else { return None };
        if !names.contains(&name.as_str()) || first.starts_with("--") {
            return None;
        }
        found.insert(name.clone(), value.as_str());
    }
    Some((first, found))
}

/// Takes the keys a caller opened, when it asked to send them. Nothing is read otherwise, so a run
/// from a terminal does not wait on the keyboard.
pub(super) fn sealed_from_stdin(wanted: bool) -> Result<verify::Sealed, String> {
    if wanted {
        verify::Sealed::read(std::io::stdin())
    } else {
        Ok(verify::Sealed::default())
    }
}

pub fn usage() -> ExitCode {
    eprint!("{HELP}");
    ExitCode::from(2)
}
