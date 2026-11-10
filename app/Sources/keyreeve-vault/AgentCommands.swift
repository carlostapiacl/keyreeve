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
    guard arguments.count >= 4, let dash = arguments.firstIndex(of: "--"), dash >= 2, dash + 1 < arguments.count else {
        fail(help, code: 2)
    }
    var allowed: Set<String> = []
    var index = 2
    while index < dash {
        guard arguments[index] == "--allow", index + 1 < dash else { fail(help, code: 2) }
        allowed.insert(arguments[index + 1].uppercased())
        index += 2
    }
    let lines = EnvReferences.parse(try String(contentsOfFile: arguments[1], encoding: .utf8))
    // A file can name a variable that decides what runs. That takes the person's word, not the file's.
    let risky = lines.compactMap { line -> String? in
        switch line {
        case .value(let name, _), .reference(let name, _, _): return name
        }
    }.filter { EnvReferences.changesWhatRuns($0) && !allowed.contains($0.uppercased()) }
    guard risky.isEmpty else {
        fail("\(arguments[1]) sets \(risky.joined(separator: ", ")), which changes what runs. If you meant it, add --allow NAME for each")
    }
    let command = Array(arguments[(dash + 1)...])
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
    // An agent's session keeps this server for hours. Once a newer Keyreeve is in place, this one may not read the
    // permissions as the new one writes them, so it no longer writes them: it says to start the session again.
    let startedAs = changeStamp(ownPath())
    // This server's parent is the agent that started it. The tree is the system's word, not the agent's.
    let observed = CallerIdentity.observe(pid: getpid())
    let agent = AgentBridge.agentName(chain: observed.chain, declared: ProcessInfo.processInfo.environment["KEYREEVE_AGENT"])
    func indexed(_ id: String) throws -> KeyIndex.Key {
        guard let key = try KeyIndex.load(from: keysFile).key(id) else { throw VaultError("no key is called \(id)") }
        return key
    }
    var bridge = AgentBridge(
        policy: { AgentPolicy.load(from: policyFile) },
        names: {
            let sealed = Set(try store.load().entries.keys)
            return try KeyIndex.load(from: keysFile).agentNames(sealed: sealed)
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
        describe: { (try? KeyIndex.load(from: keysFile).agentDescriptions) ?? [:] },
        transcript: { AgentTranscript(url: home.appendingPathComponent(AgentTranscript.fileName)).append($0) },
        decideAccess: askAccess,
        updatePolicy: { change in
            guard changeStamp(ownPath()) == startedAs else {
                throw VaultError(AgentBridge.outdated)
            }
            try AgentPolicy.update(at: policyFile, change)
        },
        offered: { AccessRequests.readOffered(from: home.appendingPathComponent(AccessRequests.offeredFileName)) },
        requests: { AccessRequests.read(from: home.appendingPathComponent(AccessRequests.fileName)) },
        addRequest: { try AccessRequests.append($0, to: home.appendingPathComponent(AccessRequests.fileName)) },
        announce: announceRequest,
        paused: { AgentBridge.isPaused(home: home) },
        inventory: { try? Data(contentsOf: AgentSorting.inventoryFile(home: home)) },
        saveProposal: { id, data in try AgentSorting.save(data, id: id, home: home) },
        revision: { id in
            guard let source = try? indexed(id).source else { return nil }
            return (try? store.load())?.entries[source]?.revision
        },
        checkWarnings: {
            let last = CheckHistory.latest(in: home.appendingPathComponent(CheckHistory.fileName()))
            let keys = (try? KeyIndex.load(from: keysFile).keys) ?? []
            return Dictionary(keys.compactMap { key in CheckHistory.warning(last[key.source]).map { (key.id, $0) } }, uniquingKeysWith: { a, _ in a })
        },
        decideNoFingerprint: askNoFingerprint,
        markUnattended: { id, prompt in
            let key = try indexed(id)
            _ = try store.ensureUnattended()
            let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), reason: prompt)
            let value = try store.load().open(name: key.source, with: recipient)
            try store.update { try $0.sealUnattended(name: key.source, value: value) }
        })
    bridge.places = { PlaceBook.load(from: PlaceBook.file(home: home)) }
    bridge.proceduresFolder = PlaceBook.proceduresFolder(home: home)
    // One message per line, at most a megabyte: a client that sends more is told so and the line is
    // dropped, read in pieces and never held whole.
    let limit = 1 << 20
    var line = Data()
    var tooLong = false
    let input = FileHandle.standardInput
    func take(_ chunk: Data) {
        for byte in chunk {
            if byte == 10 {
                if tooLong {
                    FileHandle.standardOutput.write(Data(#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"that message is over a megabyte"}}"#.utf8 + [10]))
                } else if let text = String(data: line, encoding: .utf8), let answer = bridge.handle(text) {
                    FileHandle.standardOutput.write(Data((answer + "\n").utf8))
                }
                line.removeAll(keepingCapacity: true)
                tooLong = false
            } else if !tooLong {
                if line.count < limit {
                    line.append(byte)
                } else {
                    tooLong = true
                    line.removeAll()
                }
            }
        }
    }
    // What arrived just before the previous version handed over to this one.
    if let pending = ProcessInfo.processInfo.environment[AgentHandOver.variable] {
        unsetenv(AgentHandOver.variable)
        if let chunk = Data(base64Encoded: pending) { take(chunk) }
    }
    while true {
        let chunk = input.availableData
        if chunk.isEmpty { break }
        // A newer Keyreeve is in place: this process becomes it, keeping the agent's connection and the message that
        // just came, so the session goes on with the new code and nobody has to start it again.
        if line.isEmpty, !tooLong, changeStamp(ownPath()) != startedAs, chunk.count <= AgentHandOver.maxPending {
            AgentHandOver.become(ownPath().path, pending: chunk)
        }
        take(chunk)
    }
}

/// How an agent's server hands over to a newer version of itself, in the same process.
enum AgentHandOver {
    static let variable = "KEYREEVE_MCP_PENDING"
    /// What fits in the environment beside everything else, with room to spare.
    static let maxPending = 192 * 1024

    /// Runs the program at this path in this process. Only if that fails does it come back, and the old one goes on.
    static func become(_ path: String, pending: Data) {
        guard FileManager.default.isExecutableFile(atPath: path) else { return }
        setenv(variable, pending.base64EncodedString(), 1)
        var pointers: [UnsafeMutablePointer<CChar>?] = [strdup(path), strdup("mcp"), nil]
        execv(path, &pointers)
        unsetenv(variable)
    }
}
