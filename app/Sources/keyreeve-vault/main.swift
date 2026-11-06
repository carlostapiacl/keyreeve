import CryptoKit
import Foundation
import KeyreeveVault

let help = """
    keyreeve-vault keeps keys in a file sealed by this Mac's Secure Enclave.

    Usage:
      keyreeve-vault init
          Create the vault and show its recovery key, once. Needs a terminal.
      keyreeve-vault add <name>
          Add a key, read from stdin. Needs no fingerprint.
      keyreeve-vault put <name>
          Add a key or replace it, read from stdin. The old value stays sealed. Needs no fingerprint.
      keyreeve-vault drop <name#pending|name#previous>
          Remove a temporary copy of a rotation. Real keys cannot be removed.
      keyreeve-vault list
          Show the names. Needs no fingerprint.
      keyreeve-vault run <name> --as <VARIABLE> -- <command> [args...]
          Run a command with the key in one variable. Asks for a fingerprint.
          The command's own output is not filtered, so choose a command that does not print it.
      keyreeve-vault env <file.env> -- <command> [args...]
          Run a command with an env file whose values can be keyreeve://name or keyreeve://name#FIELD.
          Asks for one fingerprint. The file holds references, so it is safe in a repository.
      keyreeve-vault mcp
          Serve agents over MCP. They run allowed programs with a key and never get its value.
          ~/.keyreeve/agent-commands.json says which, and it starts empty.
      keyreeve-vault export <name> --recovery
          Print an age file for this key, which any age tool opens with the recovery key.
      keyreeve-vault check-recovery
          Check a recovery key, read from stdin, against this vault.
      keyreeve-vault recover
          Move this vault to this Mac's chip, using a recovery key read from stdin.

    KEYREEVE_VAULT sets the folder. The default is ~/.keyreeve/vault.

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

do {
    switch arguments.first {
    case "init":
        // The recovery key must reach a person's eyes, and not an agent's transcript or a log.
        guard isatty(STDOUT_FILENO) == 1, isatty(STDIN_FILENO) == 1 else {
            fail("init shows the recovery key, so run it yourself in a terminal window")
        }
        guard !store.exists else { fail("there is already a vault in \(store.directory.path)") }
        let (enclave, blob) = try EnclaveRecipient.create()
        let recovery = Age.X25519Identity()
        try store.create(VaultFile(enclave: enclave.publicKey, recovery: recovery.recipient), blob: blob)
        print("""
            Vault created in \(store.directory.path)

            Recovery key. It is shown only now, and it opens every key in this vault:

                \(recovery.string)

            Write it on paper or in your password manager, away from this Mac. If this Mac dies,
            it is the only way back in. It is an ordinary age key, so any age tool can use it too.
            """)
    case "add":
        guard arguments.count == 2 else { fail(help, code: 2) }
        guard !VaultFile.isTemporary(arguments[1]) else { fail("that name is kept for a rotation") }
        guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
        let value = readSecret(prompt: "Value for \(arguments[1])")
        guard !value.isEmpty else { fail("the value is empty") }
        try store.update { try $0.add(name: arguments[1], value: value) }
        print("\(arguments[1]) added")
    case "put":
        guard arguments.count == 2 else { fail(help, code: 2) }
        guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
        let value = readSecret(prompt: "Value for \(arguments[1])")
        guard !value.isEmpty else { fail("the value is empty") }
        try store.update { vault in
            // A rotation's temporary copies have no history worth keeping.
            if VaultFile.isTemporary(arguments[1]) { vault.entries[arguments[1]] = nil }
            try vault.replace(name: arguments[1], value: value)
        }
    case "drop":
        guard arguments.count == 2, VaultFile.isTemporary(arguments[1]) else {
            fail("only a rotation's temporary copies can be removed")
        }
        try store.update { $0.entries[arguments[1]] = nil }
    case "list":
        for name in try store.load().entries.keys.sorted() { print(name) }
    case "run":
        guard arguments.count >= 6, arguments[2] == "--as", arguments[4] == "--" else {
            fail(help, code: 2)
        }
        let vault = try store.load()
        let recipient = try EnclaveRecipient.load(
            blob: try store.loadBlob(), reason: "use the key \(arguments[1])")
        let value = try vault.open(name: arguments[1], with: recipient)
        guard let text = String(data: value, encoding: .utf8) else { fail("the value is not text") }
        // A file sealed from the app keeps its last line break, which no program wants in a key.
        setenv(arguments[3], text.trimmingCharacters(in: .newlines), 1)
        let command = Array(arguments[5...])
        store.recordUse(of: arguments[1], by: command[0])
        var pointers: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        execvp(command[0], &pointers)
        fail("could not run \(command[0])")
    case "env":
        guard arguments.count >= 4, arguments[2] == "--" else { fail(help, code: 2) }
        let lines = EnvReferences.parse(try String(contentsOfFile: arguments[1], encoding: .utf8))
        let command = Array(arguments[3...])
        let references = lines.contains { if case .reference = $0 { true } else { false } }
        var recipient: EnclaveRecipient?
        if references {
            let program = URL(fileURLWithPath: command[0]).lastPathComponent
            let context = try EnclaveRecipient.confirm(reason: "run \(program) with its keys")
            recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), context: context)
        }
        let vault = references ? try store.load() : nil
        for line in lines {
            switch line {
            case .value(let name, let value):
                setenv(name, value, 1)
            case .reference(let name, let key, let field):
                guard let vault, let recipient else { fail("the vault could not be opened") }
                let value = try EnvReferences.value(in: try vault.open(name: key, with: recipient), field: field)
                setenv(name, value, 1)
                store.recordUse(of: key, by: command[0])
            }
        }
        var pointers: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        execvp(command[0], &pointers)
        fail("could not run \(command[0])")
    case "mcp":
        let policy = AgentPolicy.load(
            from: store.directory.deletingLastPathComponent().appendingPathComponent("agent-commands.json"))
        let bridge = AgentBridge(
            policy: policy,
            names: { Array(try store.load().entries.keys) },
            open: { key, prompt in
                let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), reason: prompt)
                return try store.load().open(name: key, with: recipient)
            },
            run: { try AgentRunner.run($0, variable: $1, value: $2) },
            record: { store.recordUse(of: $0, by: "agent:\($1)", reason: $2) })
        while let line = readLine() {
            if let answer = bridge.handle(line) {
                FileHandle.standardOutput.write(Data((answer + "\n").utf8))
            }
        }
    case "export":
        guard arguments.count == 3, arguments[2] == "--recovery" else { fail(help, code: 2) }
        guard let entry = try store.load().entries[arguments[1]] else { fail("\(arguments[1]) is not in the vault") }
        // This is ciphertext, so printing it reveals nothing without the recovery key.
        FileHandle.standardOutput.write(entry.sealed)
    case "check-recovery":
        let vault = try store.load()
        let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
        let recovery = try Age.X25519Identity(string: text)
        guard recovery.recipient.string == vault.recovery else {
            fail("this is not the recovery key of this vault")
        }
        for name in vault.entries.keys { _ = try vault.open(name: name, with: recovery) }
        print("The recovery key is right, and it opens all \(vault.entries.count) keys")
    case "recover":
        let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
        let recovery = try Age.X25519Identity(string: text)
        let (enclave, blob) = try EnclaveRecipient.create()
        try store.update { vault in
            try vault.moveToNewEnclave(enclave.publicKey, recovery: recovery)
            // After the move worked, so a bad key changes nothing. The vault's own save then
            // switches to this blob, and a crash before that leaves the old pair working.
            try store.saveBlob(blob, for: vault.enclave)
        }
        print("This vault now opens with this Mac's fingerprint")
    case "--help", "-h", "help":
        print(help)
    default:
        fail(help, code: 2)
    }
} catch let error as VaultError {
    fail(error.description)
} catch {
    // Errors from the system can mention the request, and they are no use to a person anyway.
    fail("the fingerprint was not accepted, or the Secure Enclave refused")
}
