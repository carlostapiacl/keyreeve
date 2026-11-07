import Foundation
import KeyreeveVault

// Handing a program the real value, which `use` avoids when it can.

func runWithKey() throws {
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
}

func runWithEnv() throws {
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
            // An identifier first. A vault's own name still works, for files written before them.
            let found = try KeyIndex.load(from: keysFile).key(key)
            let sealed = try vault.open(name: found?.source ?? key, with: recipient)
            setenv(name, try EnvReferences.value(in: sealed, field: field ?? found?.field), 1)
            store.recordUse(of: found?.id ?? key, by: command[0])
        }
    }
    var pointers: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
    execvp(command[0], &pointers)
    fail("could not run \(command[0])")
}

func serveAgents() throws {
    let policyFile = home.appendingPathComponent(AgentPolicy.fileName)
    func indexed(_ id: String) throws -> KeyIndex.Key {
        guard let key = try KeyIndex.load(from: keysFile).key(id) else { throw VaultError("no key is called \(id)") }
        return key
    }
    let bridge = AgentBridge(
        policy: { AgentPolicy.load(from: policyFile) },
        names: {
            let sealed = try store.load().entries.keys
            return try KeyIndex.load(from: keysFile).keys.filter { sealed.contains($0.source) }.map(\.id)
        },
        open: { id, prompt in
            let key = try indexed(id)
            let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), reason: prompt)
            return try store.load().open(name: key.source, with: recipient)
        },
        run: { try AgentRunner.run($0, variable: $1, value: $2) },
        record: {
            // Marked here, since a path's folders are dropped from the log.
            let program = URL(fileURLWithPath: $1).lastPathComponent
            store.recordUse(of: $0, by: "agent:\(program)", reason: $2)
        })
    while let line = readLine() {
        if let answer = bridge.handle(line) {
            FileHandle.standardOutput.write(Data((answer + "\n").utf8))
        }
    }
}
