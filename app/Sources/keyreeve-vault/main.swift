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
      keyreeve-vault list
          Show the names. Needs no fingerprint.
      keyreeve-vault run <name> --as <VARIABLE> -- <command> [args...]
          Run a command with the key in one variable. Asks for a fingerprint.
          The command's own output is not filtered, so choose a command that does not print it.
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
        let recovery = P256.KeyAgreement.PrivateKey()
        try store.saveBlob(blob)
        try store.save(VaultFile(enclave: enclave.publicKey, recovery: recovery.publicKey))
        print("""
            Vault created in \(store.directory.path)

            Recovery key. It is shown only now, and it opens every key in this vault:

                \(RecoveryKey.encode(recovery))

            Write it on paper or in your password manager, away from this Mac. If this Mac dies,
            it is the only way back in.
            """)
    case "add":
        guard arguments.count == 2 else { fail(help, code: 2) }
        var vault = try store.load()
        let value = readSecret(prompt: "Value for \(arguments[1])")
        guard !value.isEmpty else { fail("the value is empty") }
        try vault.add(name: arguments[1], value: value)
        try store.save(vault)
        print("\(arguments[1]) added")
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
    case "check-recovery":
        let vault = try store.load()
        let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
        let recovery = SoftwareRecipient(key: try RecoveryKey.decode(text))
        guard recovery.publicKey.rawRepresentation == vault.recoveryPublicKey else {
            fail("this is not the recovery key of this vault")
        }
        for name in vault.entries.keys { _ = try vault.open(name: name, with: recovery) }
        print("The recovery key is right, and it opens all \(vault.entries.count) keys")
    case "recover":
        var vault = try store.load()
        let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
        let recovery = SoftwareRecipient(key: try RecoveryKey.decode(text))
        let (enclave, blob) = try EnclaveRecipient.create()
        try vault.moveToNewEnclave(enclave.publicKey, recovery: recovery)
        try store.saveBlob(blob)
        try store.save(vault)
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
