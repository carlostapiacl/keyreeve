import CryptoKit
import Foundation
import KeyreeveVault

let help = """
    keyreeve-vault keeps keys in a file sealed by this Mac's Secure Enclave.

    Usage:
      keyreeve-vault init
          Create the vault and show its recovery key, once. Needs a terminal.
      keyreeve-vault add <name> [--file PATH] [--description TEXT] [--tags a,b]
          Add a key, read from stdin. Needs no fingerprint, and cannot read anything back. It gets an identifier
          in keys.toml, not offered to agents, and Keyreeve shows it as new until you review it.
          --file seals a whole file byte for byte, from anywhere, such as a .jks keystore or a .pfx
          certificate; the name can then be left out and the file's name is used. The file is only read.
      keyreeve-vault put <name>
          Add a key, read from stdin, as add does. For a key already there, the new value waits as
          <name>#pending and the current one stays in force until you accept it in Keyreeve, with your finger.
      keyreeve-vault reseal <name> [<name>...]
          Seal a key's file again, exactly as it is now, from the folder it was sealed from. The old copy
          stays sealed. Needs no fingerprint. For a file changed outside the app, such as by a script.
      keyreeve-vault orphans
          Show the vault's keys that have no identifier in keys.toml, by name. Keyreeve offers to give them one.
      keyreeve-vault drop <name#pending|name#previous>
          Remove a temporary copy of a rotation. Real keys cannot be removed.
      keyreeve-vault names
          Show what the vault holds by its internal names. Needs no fingerprint.
      keyreeve-vault run <name> --as <VARIABLE> -- <command> [args...]
          Run a command with the key in one variable. Asks for a fingerprint.
          The command's own output is not filtered, so choose a command that does not print it.
      keyreeve-vault run <name> --as-file <VARIABLE> -- <command> [args...]
          For a key that is a file, such as a .jks keystore or a .pfx certificate: the variable holds the path
          of a copy only you can read, byte for byte, removed when the command ends. Asks for a fingerprint.
      keyreeve-vault use <id> [--as VAR] [--for 5m] [--agent NAME] [--reason TEXT] [--real] -- <command> [args...]
          Run a command with a key, by its identifier. The command holds a stand-in, and a local proxy
          puts the real key on requests to that provider's hosts. Asks for your finger once for this key
          and program, then not again until the permission ends. Each use goes in the usage log.
          With an SSH key (provider = "ssh"), `ssh`, `scp`, `sftp`, `git` and `rsync` sign through an agent and
          never hold it. A permission covers the first server, or those in `servers` in keys.toml. Others ask.
          --real hands the command the real key, for what cannot use a stand-in. It asks every time.
      keyreeve-vault use <id>,<id>,... [--as id=VAR,...] [--for 5m] [--reason TEXT] -- <command> [args...]
      keyreeve-vault use --set <name> [--as id=VAR,...] [--for 5m] [--reason TEXT] -- <command> [args...]
          Several keys for one command, each in its own variable. One window lists them all: untick what you
          do not want, choose 5 min, until it finishes, a day, or always for this program in this folder, and
          give one fingerprint. Sets are made in the app, under Agents, and kept in sets.toml.
      keyreeve-vault get <id> [--reason TEXT]
          Print the real key on stdout, for a tool that takes a key from a command, such as seisin's
          key providers. It asks for your finger every time and is never remembered, so nothing can
          ride on an earlier yes. Prefer `use`, where the command holds a stand-in.
      keyreeve-vault list
          Show the identifiers and what each one is. Needs no fingerprint.
      keyreeve-vault grant <id> [--for 1h] [--program NAME]
      keyreeve-vault grants
          Show the permissions in force.
      keyreeve-vault revoke [id]
          End a key's permissions, or all of them.
      keyreeve-vault audit [--key <id>] [--verify]
          Show who used which key, or check that the log was not edited.
      keyreeve-vault log [--since 7d] [--key <id>] [--csv]
          Everything keyreeve logged, in time order and with no value: uses, agents, requests, checks.
      keyreeve-vault env <file.env> [--allow NAME] -- <command> [args...]
          Run a command with an env file whose values can be keyreeve://name or keyreeve://name#FIELD.
          Asks for one fingerprint. The file holds references, so it is safe in a repository. A variable that
          changes what runs (PATH, DYLD_*, NODE_OPTIONS, BASH_ENV and others) is refused unless you --allow it.
      keyreeve-vault mcp
          Serve agents over MCP. They run allowed programs with a key and never get its value.
          ~/.keyreeve/agents.toml says which, and it starts empty. Edit it in the app, on each key.
      keyreeve-vault export <name> --recovery
          Print an age file for this key, which any age tool opens with the recovery key.
      keyreeve-vault check-recovery [<backup.json>]
          Check a recovery key, read from stdin, by opening every key with it: of this vault, or of a backup.
      keyreeve-vault recover
          Move this vault to this Mac's chip, using a recovery key read from stdin.
      keyreeve-vault backup <folder>
          Copy the sealed vault into a folder. It needs no fingerprint and opens with the recovery key.

    Any other command, such as recipes, check, verify or rotate, goes to keyreeve-cli beside this program.

    KEYREEVE_VAULT sets the folder. The default is the vault folder in KEYREEVE_HOME, or ~/.keyreeve/vault.

    """

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("keyreeve-vault: \(message)\n".utf8))
    exit(code)
}

/// Reads stdin without showing it, and without a trailing line break.
func readSecret(prompt: String) -> Data {
    guard isatty(STDIN_FILENO) == 1 else {
        var data = FileHandle.standardInput.readDataToEndOfFile()
        while let last = data.last, last == 10 || last == 13 { data.removeLast() }
        return data
    }
    FileHandle.standardError.write(Data("\(prompt): ".utf8))
    var original = termios()
    tcgetattr(STDIN_FILENO, &original)
    var silent = original
    silent.c_lflag &= ~tcflag_t(ECHO)
    tcsetattr(STDIN_FILENO, TCSANOW, &silent)
    defer {
        tcsetattr(STDIN_FILENO, TCSANOW, &original)
        FileHandle.standardError.write(Data("\n".utf8))
    }
    return Data((readLine(strippingNewline: true) ?? "").utf8)
}

let store = VaultStore(
    directory: ProcessInfo.processInfo.environment["KEYREEVE_VAULT"].map(URL.init(fileURLWithPath:))
        ?? VaultStore.defaultDirectory)
let arguments = Array(CommandLine.arguments.dropFirst())
let home = store.directory.deletingLastPathComponent()
let keysFile = home.appendingPathComponent(KeyIndex.fileName)
let auditLog = AuditLog(url: home.appendingPathComponent("audit.jsonl"))
let socketPath = home.appendingPathComponent("run/keys.sock").path

/// This program's real place. It is often reached through a link, and its helper lives beside the real file.
func ownPath() -> URL {
    URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath()
}

/// Runs keyreeve-cli, from the same bundle, with these arguments. Without it, the help.
func handToCLI() -> Never {
    let cli = ownPath().deletingLastPathComponent().appendingPathComponent("keyreeve-cli").path
    guard FileManager.default.isExecutableFile(atPath: cli) else { fail(help, code: 2) }
    var pointers: [UnsafeMutablePointer<CChar>?] = ([cli] + arguments).map { strdup($0) } + [nil]
    execv(cli, &pointers)
    fail("could not run \(cli)")
}

/// Reaches the service, starting it the first time. It stops on its own once idle.
func askService(_ request: KeyService.Request) throws -> KeyService.Response {
    if let answer = try? KeySocket.send(request, path: socketPath) { return answer }
    // It is there and gave no answer. Saying "done" here could be false, and starting another would ask twice.
    if KeySocket.isListening(path: socketPath) { throw VaultError(KeySocket.silence(for: request.op)) }
    guard ["use", "use-many"].contains(request.op) else { return KeyService.Response(ok: true, grants: []) }
    let process = Process()
    process.executableURL = ownPath()
    process.arguments = ["serve"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    for _ in 0..<50 {
        usleep(100_000)
        if FileManager.default.fileExists(atPath: socketPath), let answer = try? KeySocket.send(request, path: socketPath) {
            return answer
        }
    }
    throw VaultError("the key service did not start")
}

