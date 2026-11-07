import AppKit
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
        },
        approve: askApproval,
        endedAt: { AgentBridge.endedAt(home: home) })
    while let line = readLine() {
        if let answer = bridge.handle(line) {
            FileHandle.standardOutput.write(Data((answer + "\n").utf8))
        }
    }
}

/// A window that shows what the agent asks for and lets the person choose how long a yes lasts.
/// The fingerprint comes after, with keyreeve's own words.
func askApproval(_ request: AgentRequest) -> AgentApproval? {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let labels: [String: String] = spanish
        ? ["Once": "Solo esta vez", "1 hour": "1 hora", "4 hours": "4 horas", "8 hours": "8 horas", "24 hours": "24 horas"]
        : [:]
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = spanish
        ? "Un agente quiere usar la clave \(request.key)"
        : "An agent wants to use the key \(request.key)"
    let said = request.reason.isEmpty ? "-" : "\u{201C}\(request.reason)\u{201D}"
    alert.informativeText = spanish
        ? "Programa: \(request.program)\n\nLo que dice el agente, en sus palabras:\n\(said)\n\nDespués te pide la huella. Lo que permitas por un tiempo vale solo para este programa en esta sesión del agente, y termina al bloquear la app."
        : "Program: \(request.program)\n\nWhat the agent says, in its own words:\n\(said)\n\nYour fingerprint comes next. A yes for a while covers only this program in this agent session, and ends when you lock the app."
    for choice in AgentApproval.choices {
        alert.addButton(withTitle: labels[choice.label] ?? choice.label)
    }
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    let answer = alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
    guard answer >= 0, answer < AgentApproval.choices.count else { return nil }
    return AgentApproval.choices[answer].approval
}
