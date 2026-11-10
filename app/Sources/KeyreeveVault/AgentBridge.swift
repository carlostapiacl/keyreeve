import Foundation

/// A small MCP server over stdin and stdout. An agent can learn which keys it may use and run an
/// allowed program with one, and no tool returns a value.
public struct AgentBridge {
    /// Opened keys a person approved for a while, held by this server alone, which ends with the agent's session.
    final class Held: @unchecked Sendable {
        var entries: [String: (from: Date, until: Date, opened: Data, revision: String?)] = [:]
        /// Keys the person refused to open in this session, so the agent cannot keep asking.
        var refused: Set<String> = []
    }

    /// Ends everything agents were approved for a while: the app's lock and `revoke` touch this file, and
    /// each agent server compares its approvals with it.
    public static func endedFile(home: URL) -> URL { home.appendingPathComponent("run/agents-ended") }

    public static func endAll(home: URL) {
        let file = endedFile(home: home)
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? Data().write(to: file)
        try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: file.path)
    }

    /// While this file exists every agent is refused, with no window and no request: the person's
    /// emergency stop, which only they lift.
    public static func pausedFile(home: URL) -> URL { home.appendingPathComponent("run/agents-paused") }

    public static func setPaused(_ paused: Bool, home: URL) {
        let file = pausedFile(home: home)
        if paused {
            try? FileManager.default.createDirectory(
                at: file.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try? Data().write(to: file)
        } else {
            try? FileManager.default.removeItem(at: file)
        }
    }

    public static func isPaused(home: URL) -> Bool { FileManager.default.fileExists(atPath: pausedFile(home: home).path) }

    public static func endedAt(home: URL) -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: endedFile(home: home).path))?[.modificationDate] as? Date
    }

    public struct Output: Equatable {
        public let status: Int32
        public let text: String
        public init(status: Int32, text: String) {
            self.status = status
            self.text = text
        }
    }

    /// Read again for each request, so a permission you change in the app counts without restarting the agent.
    let currentPolicy: () -> AgentPolicy
    var policy: AgentPolicy { currentPolicy() }
    /// Names in the vault.
    let names: () throws -> [String]
    /// Opens a key, which asks for a fingerprint. The text is what the person sees in the prompt.
    let open: (_ key: String, _ prompt: String) throws -> Data
    let run: (_ command: [String], _ variable: String, _ value: String) throws -> Output
    let record: (_ key: String, _ program: String, _ reason: String) -> Void
    /// Asks the person, before the fingerprint. Nil is a no.
    let approve: (AgentRequest) -> AgentApproval?
    /// When the person last ended every approval, if ever.
    let endedAt: () -> Date?
    let now: () -> Date
    /// Who started this server, as the process tree says: `claude`, `codex`, or the program's name.
    let agent: String
    /// The key service, which opens keys with a fingerprint and holds them behind the proxy.
    let service: ((KeyService.Request) throws -> KeyService.Response)?
    let runPrepared: (_ environment: UseEnvironment) throws -> Output
    /// Writes a line in the usage log for what this server decides on its own.
    let log: (_ event: String, _ key: String, _ detail: String, _ reason: String?) -> Void
    /// Whether a program's file still is the one a person allowed.
    let pinned: (_ program: String, _ hash: String?) -> Bool
    /// Every key's provider and usual variable, from the identifiers file, read once per listing.
    let describe: () -> [String: KeyIndex.Key]
    /// Keeps what ran and what came back, for the person to read.
    let transcript: (AgentTranscript.Entry) -> Void
    /// Asks the person whether to open a closed key. Nil is a no.
    let decideAccess: (AccessRequest) -> AccessDecision?
    /// Changes the permissions after the person opened a key, under the file's lock.
    let updatePolicy: ((inout AgentPolicy) -> Void) throws -> Void
    /// Providers the person can save a key for in the app, by name only.
    let offered: () -> [String]
    /// Requests for keys not saved yet, read and added to.
    let requests: () -> [AccessRequests.Entry]
    let addRequest: (AccessRequests.Entry) throws -> Void
    /// Tells the person an agent asked for a key that is not saved yet.
    let announce: (AccessRequests.Entry) -> Announcement
    /// The person's emergency stop, read at each request.
    let paused: () -> Bool
    /// The list of key files the app publishes while the person lets agents sort keys. None when they do not.
    let inventory: () -> Data?
    /// Keeps a proposal's changes for the app, by the request's id.
    let saveProposal: (String, Data) throws -> Void
    /// Which sealing a key holds now, so a value held for a while is dropped once the key is replaced.
    let revision: (_ key: String) -> String?
    /// A word for each key whose last check failed, read once a listing.
    let checkWarnings: () -> [String: String]
    /// Asks the person whether a key may be used with no fingerprint. The window starts on no.
    let decideNoFingerprint: (AccessRequest) -> Bool
    /// Opens the key with the person's fingerprint and seals its copy to the chip's key that asks nothing.
    let markUnattended: (_ key: String, _ prompt: String) throws -> Void
    let held = Held()
    /// Where keys live, read again for each request. Set by the server; empty elsewhere.
    public var places: () -> PlaceBook = { PlaceBook() }
    /// The person's procedures folder, to tell an agent that a procedure it proposes is not there yet.
    public var proceduresFolder: URL?

    /// What the person answers when told of a request for a key that is not saved yet.
    public enum Announcement: Equatable, Sendable {
        /// Opens the app, where the request waits.
        case open
        case later
        case deny
    }

    public init(
        policy: AgentPolicy, names: @escaping () throws -> [String],
        open: @escaping (_ key: String, _ prompt: String) throws -> Data,
        run: @escaping (_ command: [String], _ variable: String, _ value: String) throws -> Output,
        record: @escaping (_ key: String, _ program: String, _ reason: String) -> Void,
        pinned: @escaping (_ program: String, _ hash: String?) -> Bool = AgentBridge.matchesPin
    ) {
        self.init(policy: { policy }, names: names, open: open, run: run, record: record, pinned: pinned)
    }

    public init(
        policy: @escaping () -> AgentPolicy, names: @escaping () throws -> [String],
        open: @escaping (_ key: String, _ prompt: String) throws -> Data,
        run: @escaping (_ command: [String], _ variable: String, _ value: String) throws -> Output,
        record: @escaping (_ key: String, _ program: String, _ reason: String) -> Void,
        approve: @escaping (AgentRequest) -> AgentApproval? = { _ in .once },
        endedAt: @escaping () -> Date? = { nil },
        now: @escaping () -> Date = Date.init,
        agent: String = "agent",
        service: ((KeyService.Request) throws -> KeyService.Response)? = nil,
        runPrepared: @escaping (_ environment: UseEnvironment) throws -> Output = { try AgentRunner.run($0) },
        log: @escaping (_ event: String, _ key: String, _ detail: String, _ reason: String?) -> Void = { _, _, _, _ in },
        pinned: @escaping (_ program: String, _ hash: String?) -> Bool = AgentBridge.matchesPin,
        describe: @escaping () -> [String: KeyIndex.Key] = { [:] },
        transcript: @escaping (AgentTranscript.Entry) -> Void = { _ in },
        decideAccess: @escaping (AccessRequest) -> AccessDecision? = { _ in nil },
        updatePolicy: @escaping ((inout AgentPolicy) -> Void) throws -> Void = { _ in throw VaultError("permissions cannot be saved here") },
        offered: @escaping () -> [String] = { [] },
        requests: @escaping () -> [AccessRequests.Entry] = { [] },
        addRequest: @escaping (AccessRequests.Entry) throws -> Void = { _ in throw VaultError("requests cannot be kept here") },
        announce: @escaping (AccessRequests.Entry) -> Announcement = { _ in .later },
        paused: @escaping () -> Bool = { false },
        inventory: @escaping () -> Data? = { nil },
        saveProposal: @escaping (String, Data) throws -> Void = { _, _ in throw VaultError("proposals cannot be kept here") },
        revision: @escaping (_ key: String) -> String? = { _ in nil },
        checkWarnings: @escaping () -> [String: String] = { [:] },
        decideNoFingerprint: @escaping (AccessRequest) -> Bool = { _ in false },
        markUnattended: @escaping (_ key: String, _ prompt: String) throws -> Void = { _, _ in
            throw VaultError("keys cannot be marked here")
        }
    ) {
        self.decideNoFingerprint = decideNoFingerprint
        self.markUnattended = markUnattended
        self.revision = revision
        self.checkWarnings = checkWarnings
        currentPolicy = policy
        self.names = names
        self.open = open
        self.run = run
        self.record = record
        self.approve = approve
        self.endedAt = endedAt
        self.now = now
        self.agent = agent
        self.service = service
        self.runPrepared = runPrepared
        self.log = log
        self.pinned = pinned
        self.describe = describe
        self.transcript = transcript
        self.decideAccess = decideAccess
        self.updatePolicy = updatePolicy
        self.offered = offered
        self.requests = requests
        self.addRequest = addRequest
        self.announce = announce
        self.paused = paused
        self.inventory = inventory
        self.saveProposal = saveProposal
    }

    /// Runs and writes down what ran, with the key and its stand-in taken out of what is kept.
    private func ran(
        key: String, command: [String], reason: String, hiding secrets: [String], _ body: () throws -> Output
    ) throws -> String {
        let started = Date()
        let output = try body()
        var text = output.text
        // The command as kept is cleaned too: an agent can write a value into its own arguments.
        var shown = AgentRequest.shown(command)
        for secret in secrets {
            text = Self.redact(text, value: secret)
            shown = Self.redact(shown, value: secret)
        }
        let kept = String(decoding: Data(text.utf8).prefix(AgentRunner.maxOutput), as: UTF8.self)
        transcript(AgentTranscript.Entry(
            at: started, agent: agent, key: key, command: shown, reason: reason, exit: output.status,
            output: kept, milliseconds: Int(Date().timeIntervalSince(started) * 1000)))
        return "exit \(output.status)\n\(kept)"
    }

    public static func matchesPin(_ program: String, _ hash: String?) -> Bool {
        guard let hash, !hash.isEmpty else { return false }
        return AgentPolicy.fingerprint(of: program) == hash
    }

    /// The agent behind a process chain, which starts with this server.
    public static func agentName(chain: [String], declared: String? = nil) -> String {
        let base: String = {
            for name in chain.dropFirst() {
                let lower = name.lowercased()
                if lower.contains("claude") { return "claude" }
                if lower.contains("codex") { return "codex" }
            }
            return chain.dropFirst().first ?? "agent"
        }()
        // A session can name itself, from its own setup: Claude's sales session is "claude/sales". The program
        // comes from the system and stays first, so the name only narrows it, and a key open to "claude" still is.
        guard let declared, let clean = AgentPolicy.cleanAgentName(declared), clean != base else { return base }
        return base + "/" + clean
    }

    /// The opened key, if the person approved this pair for a while and nothing ended it since.
    private func stillHeld(_ slot: String, key: String) -> Data? {
        guard let entry = held.entries[slot] else { return nil }
        let ended = endedAt().map { $0 >= entry.from } ?? false
        // A key replaced in the vault since is not the one the person said yes to.
        let replaced = entry.revision != nil && revision(key) != entry.revision
        guard !ended, !replaced, now() < entry.until else {
            held.entries[slot] = nil
            return nil
        }
        return entry.opened
    }

    /// Answers one line of JSON-RPC, or nothing for a notification.
    public func handle(_ line: String) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else {
            return reply(id: NSNull(), error: (-32700, "that is not JSON"))
        }
        guard let method = object["method"] as? String else {
            return reply(id: object["id"] ?? NSNull(), error: (-32600, "there is no method"))
        }
        guard let id = object["id"] else { return nil }
        let params = object["params"] as? [String: Any] ?? [:]
        switch method {
        case "initialize":
            return reply(id: id, result: [
                "protocolVersion": Self.version(for: params["protocolVersion"] as? String),
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": "keyreeve", "version": "0.1.0"],
            ])
        case "ping":
            return reply(id: id, result: [String: Any]())
        case "tools/list":
            return reply(id: id, result: ["tools": Self.tools])
        case "tools/call":
            let arguments = params["arguments"] as? [String: Any] ?? [:]
            let text: (String, Bool)
            do {
                text = (try call(params["name"] as? String ?? "", arguments), false)
            } catch let error as VaultError {
                text = (error.description, true)
            } catch {
                // Errors from the system say nothing useful, and could quote what they were given.
                text = ("the fingerprint was not accepted, or the key could not be opened", true)
            }
            return reply(id: id, result: ["content": [["type": "text", "text": text.0]], "isError": text.1])
        default:
            return reply(id: id, error: (-32601, "no such method"))
        }
    }

    private func call(_ tool: String, _ arguments: [String: Any]) throws -> String {
        // Before anything else, so a stopped agent cannot open a window or reach the service.
        if paused() {
            if tool != "list_keys" { log("refused", arguments["key"] as? String ?? "-", "paused", arguments["reason"] as? String) }
            throw VaultError("Keyreeve is paused: the person stopped every agent. Ask them in the conversation")
        }
        switch tool {
        case "list_keys":
            let policy = self.policy
            let known = Set(try names())
            let described = describe()
            let warnings = checkWarnings()
            let date = now()
            let isOpen = { (key: String) in policy.level(of: key, at: date) != nil && policy.admits(agent: agent, for: key) }
            // Checking a pin reads the whole program, and many keys allow the same one: each is read once a listing.
            var checked: [String: Bool] = [:]
            func pinnedOnce(_ program: String, _ hash: String?) -> Bool {
                let pair = program + "\u{0}" + (hash ?? "")
                if let known = checked[pair] { return known }
                let result = pinned(program, hash)
                checked[pair] = result
                return result
            }
            var lines = policy.keys.filter { known.contains($0) && isOpen($0) }.compactMap { key -> String? in
                guard let level = policy.level(of: key, at: date) else { return nil }
                var parts = [
                    level == .always
                        ? "always, with no fingerprint"
                        : level == .free ? "free: one fingerprint after Keyreeve starts, then no questions for up to 24 h" : "asks the person"
                ]
                if let closes = policy.until[key] { parts.append("open until \(ISO8601DateFormatter().string(from: closes))") }
                let info = described[key]
                if policy.levels[key] != nil {
                    if info?.provider == KeyService.sshProvider {
                        parts.append("use_key for ssh, scp, sftp, git or rsync")
                    } else {
                        parts.append("use_key with any command" + (info?.variable.map { ", as \($0)" } ?? ""))
                    }
                }
                // Only programs run_with_key would accept, so an agent is not sent to one that is refused.
                let programs = (policy.commands[key] ?? []).filter {
                    policy.allows($0, with: key) && policy.hash(of: $0, for: key) != nil && pinnedOnce($0, policy.hash(of: $0, for: key))
                }
                if !programs.isEmpty { parts.append("run_with_key with " + programs.joined(separator: ", ")) }
                if let warning = warnings[key] { parts.append(warning) }
                return "\(key)\(Self.about(info)): " + parts.joined(separator: "; ")
            }
            // Names and providers only, so the agent can ask for one with request_access.
            let closed = known.filter { !isOpen($0) }.sorted().map { key in
                let about = [described[key]?.provider, described[key]?.account, warnings[key]].compactMap { $0 }.joined(separator: ", ")
                return about.isEmpty ? key : "\(key) (\(about))"
            }
            if lines.isEmpty { lines.append("No key is allowed for agents yet.") }
            if !closed.isEmpty { lines.append("Closed, ask with request_access: " + closed.joined(separator: ", ")) }
            // A provider with a key in the vault is asked for by that key's name, shown above.
            let saved = Set(known.compactMap { described[$0]?.provider })
            let unsaved = offered().filter { !known.contains($0) && !saved.contains($0) }.sorted()
            if !unsaved.isEmpty {
                lines.append("Not saved yet, ask with request_access by provider: " + unsaved.joined(separator: ", "))
            }
            return lines.joined(separator: "\n")
        case "use_key":
            return try useKey(arguments)
        case "run_with_key":
            return try runWithKey(arguments)
        case "request_access":
            return try requestAccess(arguments)
        case "rotate_key":
            return try rotateKey(arguments)
        case "inventory":
            guard let list = inventory() else { throw VaultError(Self.sortingOff) }
            let page = AgentSorting.page(
                list, pending: (arguments["only"] as? String ?? "pending") != "all", matching: arguments["matching"] as? String,
                offset: arguments["offset"] as? Int ?? 0, limit: arguments["limit"] as? Int ?? 60)
            return String(decoding: page ?? list, as: UTF8.self)
        case "propose":
            return try propose(arguments)
        case "list_places":
            return try listPlaces(arguments)
        case "propose_places":
            return try proposePlaces(arguments)
        default:
            throw VaultError("no such tool")
        }
    }

    private func runWithKey(_ arguments: [String: Any]) throws -> String {
        guard let key = arguments["key"] as? String,
            let variable = arguments["variable"] as? String,
            let command = arguments["command"] as? [String], let program = command.first,
            let reason = arguments["reason"] as? String, !reason.isEmpty
        else { throw VaultError("this needs key, variable, command and reason") }
        guard Self.isVariableName(variable) else { throw VaultError("that is not a variable name") }
        let name = URL(fileURLWithPath: program).lastPathComponent
        // Checked first, so a refused request never reaches the person's finger.
        try admitProgram(program, key: key, policy: policy, reason: reason)
        // The key is what the person allowed, and its field is part of it: an agent naming another field of the
        // same file would hand the program a different key. The field comes from keys.toml, never the agent.
        let field = describe()[key]?.field
        if let asked = arguments["field"] as? String, asked != field {
            log("refused", key, "asked for field \(asked)", reason)
            throw VaultError(field.map { "\(key) is the field \($0) of its file, and no other" }
                ?? "\(key) has no field set, so none can be chosen here. The person sets it in Keyreeve")
        }
        let slot = key + "\u{0}" + program
        let sealed: Data
        if let opened = stillHeld(slot, key: key) {
            sealed = opened
        } else {
            // The person sees the request with the agent's reason, set apart, and chooses how long a yes lasts.
            guard let approval = approve(AgentRequest(key: key, program: program, reason: reason, command: command)) else {
                log("denied", key, "the person said no to \(name)", reason)
                throw VaultError("the person said no to \(key) for \(name)")
            }
            // Who and what, with the agent's words short and in quotes, set apart from keyreeve's own.
            var lasts = FingerPrompt.Lasts.once
            if case .lasting(let seconds) = approval { lasts = .hours(max(1, Int(seconds) / 3600)) }
            let prompt = FingerPrompt.use(
                who: agent, key: key, account: describe()[key]?.account, program: name, lasts: lasts, reason: reason)
            // Read before the value, so one replaced in between is never kept under the older sealing.
            let sealing = revision(key)
            do {
                sealed = try open(key, prompt)
            } catch {
                log("denied", key, "fingerprint for \(name)", reason)
                throw error
            }
            // Checked again as things are now: the key may have closed, the agents may have been stopped or the
            // program replaced while the window and the finger waited, and the yes was for things as they were.
            guard !paused() else {
                log("refused", key, "paused while the person was asked", reason)
                throw VaultError("Keyreeve is paused: the person stopped every agent. Ask them in the conversation")
            }
            try admitProgram(program, key: key, policy: policy, reason: reason)
            if case .lasting(let seconds) = approval {
                let start = now()
                held.entries[slot] = (start, start.addingTimeInterval(seconds), sealed, sealing)
                log("granted", key, "\(Int(seconds)) seconds, \(name)", reason)
            } else {
                log("granted", key, "once, \(name)", reason)
            }
        }
        let value = try EnvReferences.value(in: sealed, field: field)
        record(key, program, reason)
        // Hidden first and cut after, so the cut cannot leave half a key showing.
        return try ran(key: key, command: command, reason: reason, hiding: [value]) { try run(command, variable, value) }
    }

    /// Refuses, and writes down, a program that may not run with this key now: the key closed to this agent,
    /// the program not allowed or not pinned, or changed on disk since it was allowed.
    private func admitProgram(_ program: String, key: String, policy: AgentPolicy, reason: String) throws {
        let name = URL(fileURLWithPath: program).lastPathComponent
        try admit(key, policy: policy, reason: reason)
        guard policy.allows(program, with: key) else {
            log("refused", key, "\(name) is not allowed", reason)
            throw VaultError("\(name) may not run with \(key). A person allows programs in the app, under Agents")
        }
        guard policy.hash(of: program, for: key) != nil else {
            log("refused", key, "\(name) was allowed before programs were pinned", reason)
            throw VaultError("\(name) was allowed before keyreeve pinned programs, so a person has to allow it again in the app")
        }
        guard pinned(program, policy.hash(of: program, for: key)) else {
            log("refused", key, "\(name) changed since it was allowed", reason)
            throw VaultError("\(name) changed since a person allowed it, so it is refused until they allow it again")
        }
    }

    /// Refuses, and writes down, a key that is not open to agents or not to this one.
    private func admit(_ key: String, policy: AgentPolicy, reason: String) throws {
        // A key not offered to agents answers as one that is not open, even with a level left from before:
        // an agent cannot tell it from a name that is not there.
        guard policy.level(of: key, at: now()) != nil, (try? names().contains(key)) == true else {
            log("refused", key, policy.until[key] == nil ? "not open to agents" : "closed again", reason)
            throw VaultError("\(key) is not open to agents. Ask the person with request_access")
        }
        guard policy.admits(agent: agent, for: key) else {
            log("refused", key, "not open to \(agent)", reason)
            throw VaultError("\(key) is not open to \(agent). A person chooses which agents in the app, under Agents")
        }
    }

    /// Runs a command with a stand-in for the key. The proxy swaps in the real key only on the way to the
    /// key's provider, so the command and the agent never hold it.
    private func useKey(_ arguments: [String: Any]) throws -> String {
        guard let key = arguments["key"] as? String,
            let command = arguments["command"] as? [String], let program = command.first, !program.isEmpty,
            let reason = arguments["reason"] as? String, !reason.isEmpty
        else { throw VaultError("this needs key, command and reason") }
        let variable = arguments["variable"] as? String
        if let variable, !Self.isVariableName(variable) { throw VaultError("that is not a variable name") }
        let policy = self.policy
        try admit(key, policy: policy, reason: reason)
        guard let level = policy.levels[key] else {
            log("refused", key, "only through allowed programs", reason)
            throw VaultError("\(key) is open to agents only through run_with_key with an allowed program")
        }
        guard let service else { throw VaultError("the key service is not available") }
        let name = URL(fileURLWithPath: program).lastPathComponent
        var request = KeyService.Request(
            op: "use", key: key, program: program, arguments: command.count - 1, agent: agent, reason: reason,
            notAfter: policy.until[key])
        var once = false
        switch level {
        case .free, .always:
            // One fingerprint covers every command until the app locks, at most a day. A key marked "always" needs
            // none, if the service finds the mark; if it does not, it asks like a free one.
            request.unattended = level == .always ? true : nil
            request.anyProgram = true
            request.seconds = bounded(KeyService.maxSeconds, key: key, policy: policy)
            request.prompt = FingerPrompt.use(
                who: agent, key: key, account: describe()[key]?.account, lasts: .untilQuit, reason: reason)
        case .ask:
            let open = (try? service(KeyService.Request(op: "grants")))?.grants ?? []
            let covered = open.contains { $0.key == key && ($0.program == name || $0.program == KeyService.anyProgram) }
            if !covered {
                guard let approval = approve(AgentRequest(key: key, program: program, reason: reason, command: command)) else {
                    log("denied", key, "the person said no to \(name)", reason)
                    throw VaultError("the person said no to \(key) for \(name)")
                }
                switch approval {
                case .once:
                    once = true
                    request.seconds = Int(AgentRunner.limit) + 30
                case .lasting(let seconds):
                    request.seconds = bounded(Int(seconds), key: key, policy: policy)
                }
                request.prompt = FingerPrompt.use(
                    who: agent, key: key, account: describe()[key]?.account, program: name,
                    lasts: once ? .once : .hours(max(1, (request.seconds ?? 0) / 3600)), reason: reason)
            }
        }
        let answer = try service(request)
        guard answer.ok else { throw VaultError(answer.error ?? "the key could not be used") }
        defer {
            if once, let grant = answer.grant { _ = try? service(KeyService.Request(op: "revoke", key: key, grant: grant)) }
        }
        let prepared = try UseEnvironment(answer: answer, command: command, variable: variable ?? answer.variable)
        return try ran(key: key, command: command, reason: reason, hiding: [answer.standIn].compactMap { $0 }) {
            try runPrepared(prepared)
        }
    }

    /// Which account a key belongs to and what the person wrote about it, so an agent picks the right one of
    /// several keys of a provider without trying each. Names and words only, never a value.
    static func about(_ key: KeyIndex.Key?) -> String {
        guard let key else { return "" }
        let account = key.account.map { $0.trimmingCharacters(in: .whitespaces) }.flatMap { $0.isEmpty ? nil : $0 }
        let words = key.description.map { $0.count > 140 ? String($0.prefix(139)) + "…" : $0 }
        let parts = [account.map { "account \($0)" }, words.map { "\u{201C}\($0)\u{201D}" }].compactMap { $0 }
        return parts.isEmpty ? "" : " (" + parts.joined(separator: ", ") + ")"
    }

    /// What a server older than the Keyreeve in place says instead of changing permissions.
    public static let outdated =
        "Keyreeve was updated after this agent session started, so this session does not change permissions. Ask the person to start the session again"

    /// The client's version if this speaks it, or else the newest this does speak, as MCP asks.
    static func version(for requested: String?) -> String {
        let supported = ["2025-06-18", "2025-03-26", "2024-11-05"]
        return requested.flatMap { supported.contains($0) ? $0 : nil } ?? supported[0]
    }

    static func isVariableName(_ name: String) -> Bool {
        guard let first = name.utf8.first, first == 95 || (65...90).contains(first) || (97...122).contains(first) else {
            return false
        }
        return name.utf8.allSatisfy { $0 == 95 || (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }
    }

    /// Catches a program that prints the key plainly. It cannot catch one that hides it on purpose,
    /// which is why the list of allowed programs is the real protection.
    static func redact(_ text: String, value: String) -> String {
        guard !value.isEmpty else { return text }
        let encoded = Data(value.utf8).base64EncodedString()
        return text.replacingOccurrences(of: value, with: "[redacted]")
            .replacingOccurrences(of: encoded, with: "[redacted]")
    }

    private func reply(id: Any, result: [String: Any]) -> String? {
        encode(["jsonrpc": "2.0", "id": id, "result": result])
    }

    private func reply(id: Any, error: (Int, String)) -> String? {
        encode(["jsonrpc": "2.0", "id": id, "error": ["code": error.0, "message": error.1]])
    }

    private func encode(_ object: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    private static let tools: [[String: Any]] = [
        [
            "name": "list_keys",
            "description": "List the keys this agent may use, how, and whether the person is asked. No values.",
            "inputSchema": ["type": "object", "properties": [String: Any]()],
        ],
        [
            "name": "use_key",
            "description":
                "Run a command with a key. The command gets a stand-in in the key's variable, and a local proxy swaps in the real key only for requests to the key's provider, so any command works, including curl. For an SSH key, ssh, scp, sftp, git and rsync sign in through keyreeve. The person may be asked first. The key is never returned.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "key": ["type": "string"],
                    "command": ["type": "array", "items": ["type": "string"]],
                    "variable": ["type": "string", "description": "The variable for the stand-in, if not the key's usual one"],
                    "reason": ["type": "string", "description": "Why, shown to the person and kept in the usage log"],
                ],
                "required": ["key", "command", "reason"],
            ],
        ],
        [
            "name": "inventory",
            "description":
                "List the person's key files, to help them sort all of them: path, provider, field names, tags, level, last check, whether sealed or archived, and what it is. Never a value. Also the providers keyreeve knows, by id. Only while the person lets agents sort keys, in Keyreeve under Agents.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "only": ["type": "string", "enum": ["pending", "all"], "description": "pending (the default): keys that still need something"],
                    "matching": ["type": "string", "description": "Only paths holding this text"],
                    "offset": ["type": "integer"],
                    "limit": ["type": "integer", "description": "At most 200, 60 if left out. next_offset says where the next page starts"],
                ],
            ],
        ],
        [
            "name": "propose",
            "description":
                "Propose changes to many key files at once, from what inventory shows. They wait in Keyreeve, where the person reviews them in one list and applies them, all or some. Each change: {\"path\": as inventory gives it, \"kind\": \"provider\" (with \"provider\": an id from inventory, and \"field\": a field name when the file has several) | \"untestable\" (a login, password, database URL, document, public key, signature, webhook or DSN) | \"internal\" (a secret of the person's own software) | \"public\" (not a secret at all) | \"described\" (only what it is), \"what\": at most eight words on what it holds, \"seal\": true to keep it in the vault, \"check\": true to check it with its provider, \"archive\": true for a key that is dead or a copy, \"host\": the server, such as panel.example.com, for a provider that runs on the person's own server (the person approves it once), \"split\": true for a file that holds several keys of one provider, \"expires\": \"yyyy-mm-dd\", the day the key stops working, when the person or the provider said so}. Keys set to Only me are never checked from here. Prefer leaving a file out to guessing. Call inventory later to see what changed.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "reason": ["type": "string", "description": "What these changes do, in a sentence, shown to the person"],
                    "changes": ["type": "array", "items": ["type": "object"]],
                ],
                "required": ["reason", "changes"],
            ],
        ],
        [
            "name": "list_places",
            "description":
                "List where the keys offered to agents live: for each place its label, procedure and parameters, whether the person approved it, and the last check's result and time (holds the value in the vault, an earlier value, another value, none). Never a value or a hash. Places of keys not offered to agents are only counted.",
            "inputSchema": [
                "type": "object",
                "properties": ["key": ["type": "string", "description": "Only this key's places"]],
            ],
        ],
        [
            "name": "propose_places",
            "description":
                "Propose where keys live, so the person can check them and rotation can update them. Each place: {\"key\": a key offered to agents, \"procedure\": a procedure that updates that kind of place (ssh-env {host, file, variable, service?, compose_dir?}, github-secret {repo, name, environment?}, vercel-env {folder, variable, environment?}, netlify-env {token_key, account, site, variable, context?}, coolify-env {token_key, server, app, variable, restart?}, supabase-secret {token_key, project, name}, or one you wrote in the person's procedures folder), \"params\": an object of those parameters, \"label\": what the person reads, such as \"VPS2 · /opt/lh/.env · OPENAI_API_KEY\", \"why\": how you found it}. Find places yourself, such as by reading which variables a server's env file names, never their values. A procedure is a script that never holds a key: apply gets the new value on stdin, check prints only the SHA-256 of the value in place or absent. They wait in Keyreeve, where the person reviews them, sees each procedure's text, and approves the ones they want with one fingerprint.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "reason": ["type": "string", "description": "What these places are, in a sentence, shown to the person"],
                    "places": ["type": "array", "items": ["type": "object"]],
                ],
                "required": ["reason", "places"],
            ],
        ],
        [
            "name": "rotate_key",
            "description":
                "Ask the person to rotate a key in the vault: a new key replaces it where it is used, and the old one is revoked. Use it when a key has leaked, is old, or the person asks. They decide in Keyreeve with their fingerprint, and you never see either key. Call it again later to learn how it went.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "key": ["type": "string", "description": "The key's name, as list_keys shows it"],
                    "reason": ["type": "string", "description": "Why it should be rotated, shown to the person and kept in the usage log"],
                ],
                "required": ["key", "reason"],
            ],
        ],
        [
            "name": "request_access",
            "description":
                "Ask the person to open a closed key, one that list_keys shows as closed, or to save one for a provider that list_keys shows as not saved yet (give the provider as key). Say why, and suggest for how long. If they allow it, use_key works with that key until the time is up or they quit Keyreeve, with one fingerprint and no more questions. Nothing is opened until they decide.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "key": ["type": "string"],
                    "reason": ["type": "string", "description": "Why, shown to the person and kept in the usage log"],
                    "account": [
                        "type": "string",
                        "description": "The account, organization or project the key should belong to, for a provider not saved yet or a key of a saved provider in another account, if you know it, such as the organization's slug. The person may have several keys of one provider, and this picks the right one",
                    ],
                    "duration": [
                        "type": "string", "enum": ["1h", "4h", "8h", "24h", "always", "no-fingerprint"],
                        "description": "What you suggest, 1h if left out. always only for a key used every day. no-fingerprint asks the person to mark a saved key so agents use it with no fingerprint at all, through the proxy, even after Keyreeve restarts: only for a key used all the time that can do little harm, and they decide with their own click and finger",
                    ],
                ],
                "required": ["key", "reason"],
            ],
        ],
        [
            "name": "run_with_key",
            "description":
                "Run an allowed program with a key in one environment variable. The person confirms with a fingerprint. The key is never returned, and appears as [redacted] in the output.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "key": ["type": "string"],
                    "variable": ["type": "string", "description": "The environment variable to set"],
                    "command": ["type": "array", "items": ["type": "string"]],
                    "field": ["type": "string", "description": "Optional. The key's own field, as list_keys says; no other is accepted"],
                    "reason": ["type": "string", "description": "Why, kept in the usage log"],
                ],
                "required": ["key", "variable", "command", "reason"],
            ],
        ],
    ]
}
