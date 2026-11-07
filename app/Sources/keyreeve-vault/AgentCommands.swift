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
    // This server's parent is the agent that started it. The tree is the system's word, not the agent's.
    let observed = CallerIdentity.observe(pid: getpid())
    let agent = AgentBridge.agentName(chain: observed.chain)
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
        endedAt: { AgentBridge.endedAt(home: home) },
        agent: agent,
        service: askService,
        log: { event, key, detail, reason in
            try? auditLog.append(
                event: event, key: key, observed: observed,
                declared: AuditLog.Declared(agent: agent, reason: reason), detail: detail)
        },
        describe: {
            let keys = (try? KeyIndex.load(from: keysFile).keys) ?? []
            return Dictionary(keys.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        },
        transcript: { AgentTranscript(url: home.appendingPathComponent(AgentTranscript.fileName)).append($0) },
        decideAccess: askAccess,
        savePolicy: { policy in
            let previous = umask(0o077)
            defer { umask(previous) }
            try Data(policy.toml.utf8).write(to: policyFile, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: policyFile.path)
        },
        offered: { AccessRequests.readOffered(from: home.appendingPathComponent(AccessRequests.offeredFileName)) },
        requests: { AccessRequests.read(from: home.appendingPathComponent(AccessRequests.fileName)) },
        addRequest: { try AccessRequests.append($0, to: home.appendingPathComponent(AccessRequests.fileName)) },
        announce: announceRequest)
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
    let command = request.command.isEmpty ? request.program : request.command
    alert.informativeText = spanish
        ? "Comando:\n\(command)\n\nLo que dice el agente, en sus palabras:\n\(said)\n\nDespués te pide la huella. Si eliges horas, vale para \(request.program) con esta clave hasta que pase el tiempo o bloquees la app."
        : "Command:\n\(command)\n\nWhat the agent says, in its own words:\n\(said)\n\nYour fingerprint comes next. Hours cover \(request.program) with this key until the time is up or you lock the app."
    for choice in AgentApproval.choices {
        alert.addButton(withTitle: labels[choice.label] ?? choice.label)
    }
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    let answer = answered(alert)
    guard answer >= 0, answer < AgentApproval.choices.count else { return nil }
    return AgentApproval.choices[answer].approval
}

/// Shows the alert and takes it down. This process goes back to reading stdin and never runs an event
/// loop, so the window would stay on screen after the click: it is ordered out and the window server
/// hears it before going on. The answer counts from the first button.
func answered(_ alert: NSAlert) -> Int {
    let app = NSApplication.shared
    let answer = alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
    alert.window.orderOut(nil)
    let until = Date().addingTimeInterval(0.1)
    while let event = app.nextEvent(matching: .any, until: until, inMode: .default, dequeue: true) {
        app.sendEvent(event)
    }
    return answer
}

/// A window for an agent asking to open a closed key: allow it for some time, or not. The agent's
/// suggestion is selected, and the person can change it.
func askAccess(_ request: AccessRequest) -> AccessDecision? {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .warning
    let provider = request.provider.map { " (\($0))" } ?? ""
    alert.messageText = spanish
        ? "\(request.agent) pide la clave \(request.key)\(provider)"
        : "\(request.agent) asks for the key \(request.key)\(provider)"
    alert.informativeText = spanish
        ? "Lo que dice el agente, en sus palabras:\n\u{201C}\(request.reason)\u{201D}\n\nSi permites, te pide la huella una vez y no vuelve a preguntar hasta que pase el tiempo o bloquees la app. Lo cambias cuando quieras en Agentes."
        : "What the agent says, in its own words:\n\u{201C}\(request.reason)\u{201D}\n\nIf you allow it, your fingerprint is asked once, and nothing more until the time is up or you lock the app. Change it any time under Agents."
    let durations = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 220, height: 26), pullsDown: false)
    let choices: [Int?] = AccessDecision.hourChoices.map { $0 } + [nil]
    for hours in choices {
        if let hours {
            durations.addItem(withTitle: spanish ? "Por \(hours) h" : "For \(hours) h")
        } else {
            durations.addItem(withTitle: spanish ? "Siempre" : "Always")
        }
    }
    durations.selectItem(at: choices.firstIndex(of: request.hours) ?? 0)
    alert.accessoryView = durations
    alert.addButton(withTitle: spanish ? "Permitir" : "Allow")
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    guard answered(alert) == 0 else { return nil }
    return AccessDecision(hours: choices[durations.indexOfSelectedItem])
}

/// Tells the person an agent asked for a key that is not saved yet. Saving happens in the app, which
/// knows the keys folder, so this only offers to open it.
func announceRequest(_ request: AccessRequests.Entry) -> AgentBridge.Announcement {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .informational
    alert.messageText = spanish
        ? "\(request.agent) pide una clave de \(request.provider)"
        : "\(request.agent) asks for a \(request.provider) key"
    let said = request.reason.map { "\u{201C}\($0)\u{201D}" } ?? "-"
    alert.informativeText = spanish
        ? "Lo que dice el agente, en sus palabras:\n\(said)\n\nTodavía no tienes una clave de \(request.provider) guardada. En Keyreeve eliges cuál, se guarda y queda permitida en un paso."
        : "What the agent says, in its own words:\n\(said)\n\nNo \(request.provider) key is saved yet. In Keyreeve you choose which, and it is saved and allowed in one step."
    alert.addButton(withTitle: spanish ? "Abrir Keyreeve" : "Open Keyreeve")
    alert.addButton(withTitle: spanish ? "Ahora no" : "Not now")
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    switch answered(alert) {
    case 0:
        // open(1) hands it to Launch Services at once; this process never runs the loop an async open needs.
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = ["-b", "io.github.carlostapiacl.keyreeve"]
        open.standardError = FileHandle.nullDevice
        try? open.run()
        return .open
    case 1: return .later
    default: return .deny
    }
}
