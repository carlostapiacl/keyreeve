import Foundation

/// Whatever holds the real values and puts them on the wire. Tests use a stand-in for it.
public protocol KeyProxy: AnyObject, Sendable {
    /// `text` is the sealed file as it is. The proxy reads the key from it, as a check would.
    func add(grant: String, key: String, provider: String, text: String, field: String?, expires: Date) throws -> String
    func remove(grant: String)
    var endpoint: KeyService.ProxyEndpoint { get throws }
}

/// Starts a door for an SSH key. Tests can stand in for it.
public protocol SSHKeyAgents: AnyObject, Sendable {
    func open(
        grant: String, name: String, key: String, seconds: Int, check: @escaping SSHDoor.ServerCheck,
        signed: @escaping SSHDoor.SignatureLog, refused: @escaping SSHDoor.RefusalLog
    ) throws -> SSHDoorHandle
}

public protocol SSHDoorHandle: AnyObject {
    var socket: String { get }
    var identity: String? { get }
    func close()
}

extension SSHDoor: SSHDoorHandle {}

/// The real agents, one for each permission, with their sockets in the service's private folder.
public final class SystemSSHAgents: SSHKeyAgents, @unchecked Sendable {
    let folder: URL
    let askpass: String?

    /// An agent outlives a service that was killed, and its key stays until its limit. Starting clears those.
    public init(folder: URL, askpass: String? = nil) {
        self.folder = folder
        self.askpass = askpass
        let sweep = Process()
        sweep.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        sweep.arguments = ["-f", "^/usr/bin/ssh-agent -D -a \(NSRegularExpression.escapedPattern(for: folder.path))/a-"]
        sweep.standardOutput = FileHandle.nullDevice
        sweep.standardError = FileHandle.nullDevice
        sweep.standardInput = FileHandle.nullDevice
        try? sweep.run()
        sweep.waitUntilExit()
        let files = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        for name in files where (name.hasSuffix(".sock") || name.hasSuffix(".pub")) && (name.hasPrefix("a-") || name.hasPrefix("s-")) {
            unlink(folder.appendingPathComponent(name).path)
        }
    }

    public func open(
        grant: String, name: String, key: String, seconds: Int, check: @escaping SSHDoor.ServerCheck,
        signed: @escaping SSHDoor.SignatureLog, refused: @escaping SSHDoor.RefusalLog
    ) throws -> SSHDoorHandle {
        try SSHDoor.open(
            grant: grant, name: name, key: key, seconds: seconds, folder: folder, askpass: askpass,
            check: check, signed: signed, refused: refused)
    }
}

/// Decides who gets a key, keeps permissions for a short while, and writes down every decision. It
/// lives in its own process, so a permission outlasts one command and the agent never holds it.
public final class KeyService: @unchecked Sendable {
    public struct Request: Codable, Equatable, Sendable {
        public var op: String
        public var key: String?
        public var seconds: Int?
        public var program: String?
        public var arguments: Int?
        public var prompt: String?
        public var agent: String?
        public var reason: String?
        public var cwd: String?
        /// Asks for the value itself, for what cannot use a stand-in. It is never remembered.
        public var real: Bool?
        /// A permission that covers any program, for a key a person left free to agents.
        public var anyProgram: Bool?
        /// For a key the person marked "always, no fingerprint": opened with the chip's key that asks nothing, if
        /// the service itself finds the mark. What the caller says is never enough.
        public var unattended: Bool?
        /// One permission to end, by its id, and no other.
        public var grant: String?
        /// When the key closes for agents. No permission for it lasts past this, a new one or one in force.
        public var notAfter: Date?
        /// Several keys for one command, asked for in one window with one fingerprint (`use-many`).
        public var keys: [String]?
        /// The set the keys came from, shown in the window. A label only: the keys are what is asked.
        public var set: String?
        /// The program's full path and the script it runs, for a permission bound to them and to `cwd`.
        public var programPath: String?
        public var script: String?
        /// The person already chose these keys in the caller's own window, so only the fingerprint is left.
        public var decided: Bool?

        public init(
            op: String, key: String? = nil, seconds: Int? = nil, program: String? = nil, arguments: Int? = nil,
            prompt: String? = nil, agent: String? = nil, reason: String? = nil, cwd: String? = nil, real: Bool? = nil,
            anyProgram: Bool? = nil, grant: String? = nil, notAfter: Date? = nil, keys: [String]? = nil, set: String? = nil,
            programPath: String? = nil, script: String? = nil
        ) {
            self.keys = keys
            self.set = set
            self.programPath = programPath
            self.script = script
            self.notAfter = notAfter
            self.anyProgram = anyProgram
            self.grant = grant
            self.op = op
            self.key = key
            self.seconds = seconds
            self.program = program
            self.arguments = arguments
            self.prompt = prompt
            self.agent = agent
            self.reason = reason
            self.cwd = cwd
            self.real = real
        }
    }

    public struct ProxyEndpoint: Codable, Equatable, Sendable {
        public var port: Int
        public var ca: String
        public var bundle: String
        public init(port: Int, ca: String, bundle: String) {
            self.port = port
            self.ca = ca
            self.bundle = bundle
        }
    }

    public struct Response: Codable, Equatable, Sendable {
        public var ok: Bool
        public var error: String?
        /// The real key, only for a request that asked for it with its own fingerprint.
        public var value: String?
        public var standIn: String?
        public var proxy: ProxyEndpoint?
        /// For an SSH key: the socket that signs with it. The key stays on the other side.
        public var sshSocket: String?
        /// The public half of that key, so `ssh` offers this one and no other.
        public var sshIdentity: String?
        public var variable: String?
        public var grants: [GrantInfo]?
        /// The permission this answer used.
        public var grant: String?
        /// Which key this answer is for, in a `use-many` answer.
        public var key: String?
        /// One answer for each key of a `use-many`, in the order asked.
        public var many: [Response]?

        public init(
            ok: Bool, error: String? = nil, value: String? = nil, standIn: String? = nil,
            proxy: ProxyEndpoint? = nil, sshSocket: String? = nil, sshIdentity: String? = nil, variable: String? = nil, grants: [GrantInfo]? = nil,
            grant: String? = nil, key: String? = nil, many: [Response]? = nil
        ) {
            self.key = key
            self.many = many
            self.grant = grant
            self.ok = ok
            self.error = error
            self.value = value
            self.standIn = standIn
            self.proxy = proxy
            self.sshSocket = sshSocket
            self.sshIdentity = sshIdentity
            self.variable = variable
            self.grants = grants
        }
    }

    public struct GrantInfo: Codable, Equatable, Sendable {
        public var id: String
        public var key: String
        public var program: String
        public var expires: Date

        public init(id: String, key: String, program: String, expires: Date) {
            self.id = id
            self.key = key
            self.program = program
            self.expires = expires
        }
    }

    struct Grant {
        let id: String
        let key: String
        let program: String
        var expires: Date
        let standIn: String
        /// An SSH key signs for whichever program asks, so its permission is for the key alone.
        let door: SSHDoorHandle?
        /// The sealing the value came from. A key replaced in the vault ends the permission for the old one.
        var revision: String? = nil
        /// For a permission that lasts until the command ends: the process that asked, which the command runs as.
        var pid: Int32? = nil
    }

    /// What `provider` says for an SSH key that belongs to no provider's file, such as a server's.
    public static let sshProvider = "ssh"
    /// "90s", "5m" or "2h". Nil for what it cannot read, including a number too large to hold.
    public static func seconds(from text: String) -> Int? {
        guard let unit = text.last, let number = Int(text.dropLast()), number > 0 else { return Int(text) }
        let scale: Int
        switch unit {
        case "s": scale = 1
        case "m": scale = 60
        case "h": scale = 3600
        default: return nil
        }
        let (result, overflow) = number.multipliedReportingOverflow(by: scale)
        return overflow ? nil : result
    }

    public static let defaultSeconds = 5 * 60
    public static let maxSeconds = 24 * 60 * 60

    let index: () throws -> KeyIndex
    let open: (_ source: String, _ prompt: String) throws -> Data
    /// Which sealing a source holds now, read with no fingerprint.
    let revision: (_ source: String) -> String?
    /// The value of a key the person marked to need no fingerprint, for this agent, or nil. It reads the mark
    /// from the person's own files, so a caller that claims it gets nothing more.
    let openUnattended: (_ key: String, _ agent: String?, _ source: String) -> Data?
    let proxy: KeyProxy?
    private let agents: SSHKeyAgents?
    private let confirm: @Sendable (_ prompt: String) -> Bool
    let log: AuditLog
    let now: () -> Date
    /// The person's emergency stop. Checked before and after the fingerprint, so a use that was already
    /// waiting cannot finish once it is on.
    let paused: () -> Bool
    var grants: [Grant] = []
    /// Guards the list, and is never held while a person is being asked, so `revoke` always gets through.
    let lock = NSLock()
    /// One prompt at a time: a second one would cancel the first.
    private let asking = NSLock()
    /// The prompt on screen now, so a use waiting behind it can say what it waits for.
    private var onScreen: (key: String, who: String, since: Date)?
    /// How long a use waits behind another prompt before it says so. Under the client's two minutes, so
    /// the agent hears why instead of "did not answer".
    private let promptWait: TimeInterval
    /// Opens several sources on one fingerprint. Without it, each source asks on its own.
    let openMany: ((_ sources: [String], _ prompt: String) throws -> [String: Data])?
    /// The window that lists several keys. Without one, the fingerprint prompt is the only question.
    let choose: ((KeyBatch) -> KeyBatch.Answer?)?
    /// The person's sets and standing permissions, read at each use.
    let sets: () -> KeySets
    /// Seals the copies that ask nothing and writes a standing permission down. Called after the fingerprint.
    let keepStanding: (_ standing: KeySets.Standing, _ values: [String: Data]) throws -> Void
    /// A source's copy that asks nothing, for a use a standing permission covers.
    let openStanding: (_ source: String) -> Data?
    /// A file's SHA-256, for the program and script a standing permission pins.
    let fingerprint: (_ path: String) -> String?
    let isRunning: (_ pid: Int32) -> Bool
    /// How long a use that needs the person waits for others from the same caller, so they share one window.
    let gather: TimeInterval
    /// Uses waiting to be asked together, by who asks.
    var gatherings: [String: Gathering] = [:]
    var revocations = 0

    public init(
        index: @escaping () throws -> KeyIndex,
        open: @escaping (_ source: String, _ prompt: String) throws -> Data,
        proxy: KeyProxy?, agents: SSHKeyAgents? = nil, confirm: @escaping @Sendable (String) -> Bool = { _ in false },
        log: AuditLog, now: @escaping () -> Date = Date.init, paused: @escaping () -> Bool = { false },
        promptWait: TimeInterval = 90, revision: @escaping (_ source: String) -> String? = { _ in nil },
        openUnattended: @escaping (_ key: String, _ agent: String?, _ source: String) -> Data? = { _, _, _ in nil },
        openMany: ((_ sources: [String], _ prompt: String) throws -> [String: Data])? = nil,
        choose: ((KeyBatch) -> KeyBatch.Answer?)? = nil,
        sets: @escaping () -> KeySets = { KeySets() },
        keepStanding: @escaping (_ standing: KeySets.Standing, _ values: [String: Data]) throws -> Void = { _, _ in
            throw VaultError("standing permissions cannot be kept here")
        },
        openStanding: @escaping (_ source: String) -> Data? = { _ in nil },
        fingerprint: @escaping (_ path: String) -> String? = AgentPolicy.fingerprint(of:),
        isRunning: @escaping (_ pid: Int32) -> Bool = { kill($0, 0) == 0 || errno == EPERM },
        gather: TimeInterval = 0
    ) {
        self.openMany = openMany
        self.choose = choose
        self.sets = sets
        self.keepStanding = keepStanding
        self.openStanding = openStanding
        self.fingerprint = fingerprint
        self.isRunning = isRunning
        self.gather = gather
        self.openUnattended = openUnattended
        self.promptWait = promptWait
        self.revision = revision
        self.paused = paused
        self.proxy = proxy
        self.agents = agents
        self.confirm = confirm
        self.index = index
        self.open = open
        self.log = log
        self.now = now
    }

    public var isIdle: Bool {
        lock.lock()
        defer { lock.unlock() }
        dropExpired()
        return grants.isEmpty
    }

    func dropExpired() {
        let current = now()
        // A permission until the command ends goes once its process is gone.
        let over = { (grant: Grant) in grant.expires <= current || grant.pid.map { !self.isRunning($0) } == true }
        for grant in grants where over(grant) { end(grant) }
        grants.removeAll(where: over)
    }

    func end(_ grant: Grant) {
        if let door = grant.door {
            door.close()
        } else {
            proxy?.remove(grant: grant.id)
        }
    }

    /// One request that went out with a key, as the proxy reports it.
    public func record(grant: String, key: String, detail: String) {
        try? log.append(event: "request", key: key, grant: grant, detail: detail)
    }

    public func handle(_ request: Request, caller: AuditLog.Observed?) -> Response {
        do {
            switch request.op {
            case "use": return try use(request, caller: caller)
            case "use-many": return try useMany(request, caller: caller)
            case "grants":
                lock.lock()
                defer { lock.unlock() }
                dropExpired()
                return Response(
                    ok: true,
                    grants: grants.map { GrantInfo(id: $0.id, key: $0.key, program: $0.program, expires: $0.expires) })
            case "revoke":
                lock.lock()
                dropExpired()
                // Ending one permission that is done with does not cancel what others are opening.
                if request.grant == nil { revocations += 1 }
                let ends = { (grant: Grant) in
                    (request.key == nil || grant.key == request.key) && (request.grant == nil || grant.id == request.grant)
                }
                let closing = grants.filter(ends)
                for grant in closing { end(grant) }
                grants.removeAll(where: ends)
                lock.unlock()
                for grant in closing {
                    try? log.append(event: "closed", key: grant.key, grant: grant.id, observed: caller)
                }
                return Response(ok: true)
            default:
                return Response(ok: false, error: "unknown request")
            }
        } catch let error as VaultError {
            return Response(ok: false, error: error.description)
        } catch {
            // Errors from the system say nothing useful, and could quote what they were given.
            return Response(ok: false, error: "the fingerprint was not accepted, or the key could not be opened")
        }
    }

    /// An SSH key's permission covers every program. Any other covers one key with one program, so one
    /// for `netlify` does not also cover something else without showing you that it asked.
    /// The program name of a permission a person gave for any program.
    public static let anyProgram = "*"

    /// A permission in force for this key and program. One that would outlast the key's closing is cut
    /// to it here, and ended by the service's own clock when that comes.
    func grantInForce(key: String, program: String, notAfter: Date? = nil) -> Grant? {
        lock.lock()
        defer { lock.unlock() }
        dropExpired()
        guard let at = grants.firstIndex(where: {
            $0.key == key && ($0.door != nil || $0.program == program || $0.program == Self.anyProgram)
        }) else { return nil }
        let id = grants[at].id
        if let notAfter, grants[at].expires > notAfter {
            grants[at].expires = notAfter
            // Already past it: the permission ends now and a new one is needed.
            dropExpired()
        }
        return grants.first { $0.id == id }
    }

    /// A permission in force for this key, unless the key was replaced in the vault since: then it ends here,
    /// and the use asks again for the value as it is now.
    func current(_ key: KeyIndex.Key, program: String, notAfter: Date?, caller: AuditLog.Observed?) throws -> Grant? {
        guard let grant = grantInForce(key: key.id, program: program, notAfter: notAfter) else { return nil }
        guard let then = grant.revision, let now = revision(key.source), now != then else { return grant }
        lock.lock()
        end(grant)
        grants.removeAll { $0.id == grant.id }
        lock.unlock()
        try log.append(event: "closed", key: key.id, grant: grant.id, observed: caller, detail: "replaced in the vault")
        return nil
    }

    func answer(for grant: Grant, variable: String?) throws -> Response {
        if let door = grant.door { return Response(ok: true, sshSocket: door.socket, sshIdentity: door.identity, grant: grant.id) }
        guard let proxy else { throw VaultError("the proxy is not available") }
        return Response(ok: true, standIn: grant.standIn, proxy: try proxy.endpoint, variable: variable, grant: grant.id)
    }

    /// Takes the one turn at the fingerprint. Behind another prompt for longer than `promptWait`, it says which
    /// prompt that is and gives up, so the person hears of the one on screen and the agent can ask again.
    func takeTurn(key: String, who: String, caller: AuditLog.Observed?, declared: AuditLog.Declared) throws {
        guard asking.lock(before: Date().addingTimeInterval(promptWait)) else {
            lock.lock()
            let ahead = onScreen
            lock.unlock()
            try log.append(event: "refused", key: key, observed: caller, declared: declared, detail: "another fingerprint is pending")
            let what = ahead.map { " for \($0.key), asked by \($0.who) \(Int(Date().timeIntervalSince($0.since)))s ago" } ?? ""
            throw VaultError(
                "Keyreeve is waiting for the person's fingerprint\(what). Ask them to answer that prompt on the Mac, then try again")
        }
        lock.lock()
        onScreen = (key, who, Date())
        lock.unlock()
    }

    func endTurn() {
        lock.lock()
        onScreen = nil
        lock.unlock()
        asking.unlock()
    }

    private func use(_ request: Request, caller: AuditLog.Observed?) throws -> Response {
        guard let id = request.key, let program = request.program, !program.isEmpty else {
            throw VaultError("this needs a key and a command")
        }
        let declared = AuditLog.Declared(
            agent: request.agent, reason: request.reason,
            command: "\(URL(fileURLWithPath: program).lastPathComponent) (\(request.arguments ?? 0) arguments)",
            cwd: request.cwd)
        guard let key = try index().key(id) else {
            try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "no such key")
            throw VaultError("no key is called \(id). `list` shows them")
        }
        let name = URL(fileURLWithPath: program).lastPathComponent
        // The emergency stop holds for the real key too, and before any finger is asked.
        guard !paused() else {
            try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "paused")
            throw VaultError("Keyreeve is paused")
        }
        if request.real == true {
            // Asked every time and never remembered: past this point nothing protects the value.
            try takeTurn(key: id, who: request.agent ?? name, caller: caller, declared: declared)
            defer { endTurn() }
            lock.lock()
            let revocationsBefore = revocations
            lock.unlock()
            let sealed: Data
            do {
                sealed = try open(key.source, FingerPrompt.real(who: name, key: id, account: key.account, reason: request.reason))
            } catch {
                try log.append(event: "denied", key: id, observed: caller, declared: declared, detail: "real key")
                throw error
            }
            // The emergency stop or a revoke while the finger was on the sensor wins over the yes.
            lock.lock()
            let stopped = revocations != revocationsBefore || paused()
            lock.unlock()
            guard !stopped else {
                try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "stopped during the fingerprint")
                throw VaultError("this was stopped while it was being opened")
            }
            guard (try? index().key(id)) == key else {
                try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "changed during the fingerprint")
                throw VaultError("\(id) changed in keys.toml while it was being opened, so nothing was opened. Ask again")
            }
            let value = try EnvReferences.value(in: sealed, field: key.field)
            try log.append(event: "handed", key: id, observed: caller, declared: declared, detail: "real key")
            return Response(ok: true, value: value, variable: key.variable)
        }
        // No finger is spent on a key that could not be used anyway.
        guard let provider = key.provider else {
            throw VaultError(
                "\(id) has no provider, so nothing says where it may go. Set one (`ssh` for an SSH key), or use --real")
        }
        guard provider == Self.sshProvider || proxy != nil else {
            try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "no proxy")
            throw VaultError("the proxy is not available")
        }
        if let existing = try current(key, program: name, notAfter: request.notAfter, caller: caller) {
            try log.append(event: "used", key: id, grant: existing.id, observed: caller, declared: declared)
            return try answer(for: existing, variable: key.variable)
        }
        let ask = Ask(request: request, key: key, provider: provider, name: name, declared: declared, caller: caller)
        // A key marked to need no fingerprint, or one a standing permission covers, opens here with no prompt, and so
        // waits for no turn.
        let quiet = (request.unattended == true ? openUnattended(id, request.agent, key.source) : nil) ?? standingValue(for: ask)
        // A caller that brings its own words already asked its own question, such as an agent's window: it is not
        // asked again in a shared one.
        if quiet == nil, gather > 0, request.prompt == nil { return try coalesce(ask) }
        return try personal(ask, quiet: quiet)
    }

    /// One key, asked of the person alone, as it always was: the fingerprint prompt is the question.
    func personal(_ ask: Ask, quiet: Data?) throws -> Response {
        let (request, key, name, caller, declared) = (ask.request, ask.key, ask.name, ask.caller, ask.declared)
        let id = key.id
        if quiet == nil { try takeTurn(key: id, who: request.agent ?? name, caller: caller, declared: declared) }
        defer { if quiet == nil { endTurn() } }
        // While this waited, the prompt ahead of it may have given what this needs.
        if let existing = try current(key, program: name, notAfter: request.notAfter, caller: caller) {
            try log.append(event: "used", key: id, grant: existing.id, observed: caller, declared: declared)
            return try answer(for: existing, variable: key.variable)
        }
        lock.lock()
        let revocationsBefore = revocations
        lock.unlock()
        // Read before the value, so a value replaced in between is never kept under the older sealing.
        let sealing = revision(key.source)
        let sealed: Data
        do {
            // The asker's own prompt names the account already; one made here does too.
            sealed = try quiet ?? open(key.source, request.prompt ?? FingerPrompt.use(
                who: request.agent ?? name, key: id, account: key.account, program: name,
                lasts: request.seconds.map { .minutes(max(1, $0 / 60)) }, reason: request.reason))
        } catch {
            try log.append(event: "denied", key: id, observed: caller, declared: declared)
            throw error
        }
        return try install(
            ask, sealed: sealed, sealing: sealing, seconds: request.seconds ?? Self.defaultSeconds, quiet: quiet != nil,
            revocationsBefore: revocationsBefore)
    }

    /// Opens a permission with a value the person just gave, or one that needs no finger.
    func install(
        _ ask: Ask, sealed: Data, sealing: String?, seconds asked: Int, quiet: Bool, revocationsBefore: Int, pid: Int32? = nil,
        note: String? = nil
    ) throws -> Response {
        let (request, key, provider, name, caller, declared) = (ask.request, ask.key, ask.provider, ask.name, ask.caller, ask.declared)
        let id = key.id
        let account = key.account.map { " (\($0))" } ?? ""
        // The yes was for the key as keys.toml described it when asked. Changed meanwhile, its hosts, field or
        // servers could be other than the ones the person saw, so nothing is opened.
        guard (try? index().key(id)) == key else {
            try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "changed during the fingerprint")
            throw VaultError("\(id) changed in keys.toml while it was being opened, so nothing was opened. Ask again")
        }
        // Counted from the fingerprint, and never past the key's closing. A key that closed while the
        // finger was on the sensor gets nothing, not a second.
        var seconds = min(max(asked, 1), Self.maxSeconds)
        if let notAfter = request.notAfter {
            let left = Int(notAfter.timeIntervalSince(now()))
            guard left > 0 else {
                try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "closed during the fingerprint")
                throw VaultError("\(id) closed while it was being opened")
            }
            seconds = min(seconds, left)
        }
        let expires = now().addingTimeInterval(TimeInterval(seconds))
        let grantID = "g-" + UUID().uuidString.prefix(8).lowercased()
        let text = String(decoding: sealed, as: UTF8.self)
        let granted: Grant
        var detail: String
        if text.contains("PRIVATE KEY-----") {
            let door = try openDoor(grant: grantID, key: id, account: account, pinned: key.servers ?? [], text: text, seconds: seconds)
            granted = Grant(id: grantID, key: id, program: name, expires: expires, standIn: "", door: door, pid: pid)
            detail = "\(seconds) seconds, ssh"
        } else {
            guard provider != Self.sshProvider else {
                throw VaultError("\(id) says it is an SSH key, and what is sealed is not a private key")
            }
            guard let proxy else { throw VaultError("the proxy is not available") }
            // From here the value lives in the proxy, and this process keeps only the stand-in.
            let standIn = try proxy.add(
                grant: grantID, key: id, provider: provider, text: text, field: key.field, expires: expires)
            granted = Grant(
                id: grantID, key: id, program: request.anyProgram == true ? Self.anyProgram : name, expires: expires,
                standIn: standIn, door: nil, pid: pid)
            detail = "\(seconds) seconds" + (quiet ? ", no fingerprint" : "")
        }
        if pid != nil { detail += ", until the command ends" }
        if let note { detail += ", " + note }
        lock.lock()
        // Locking the app, or the emergency stop, while your finger was on its way ends this too.
        guard revocations == revocationsBefore, !paused() else {
            end(granted)
            lock.unlock()
            throw VaultError("this was revoked while it was being opened")
        }
        var kept = granted
        kept.revision = sealing
        grants.append(kept)
        lock.unlock()
        // A use that cannot be written down does not happen.
        do {
            try log.append(event: "granted", key: id, grant: grantID, observed: caller, declared: declared, detail: detail)
            try log.append(event: "used", key: id, grant: grantID, observed: caller, declared: declared)
            return try answer(for: granted, variable: key.variable)
        } catch {
            lock.lock()
            grants.removeAll { $0.id == grantID }
            end(granted)
            lock.unlock()
            throw error
        }
    }

    /// The first server is the one you just approved with your finger, unless the key names its servers.
    /// Each other asks again.
    private func openDoor(
        grant: String, key: String, account: String, pinned: [String], text: String, seconds: Int
    ) throws -> SSHDoorHandle {
        guard let agents else { throw VaultError("SSH keys are not available here") }
        let servers = ServerList(pinned: pinned)
        let log = self.log
        let confirm = self.confirm
        let asking = self.asking
        return try agents.open(
            grant: grant, name: key, key: text, seconds: seconds,
            check: { fingerprint in
                if servers.note(fingerprint, firstIsFree: false) == .known { return true }
                asking.lock()
                defer { asking.unlock() }
                switch servers.note(fingerprint) {
                case .known: return true
                case .first:
                    try? log.append(event: "server", key: key, grant: grant, detail: "\(fingerprint), with the permission")
                    return true
                case .new:
                    let allowed = confirm("sign in to a new server \(fingerprint) with the key \(key)\(account)")
                    if allowed { servers.allow(fingerprint) }
                    try? log.append(
                        event: allowed ? "server" : "denied", key: key, grant: grant, detail: "\(fingerprint), asked")
                    return allowed
                }
            },
            signed: { signature, caller in
                try? log.append(
                    event: "signed", key: key, grant: grant, observed: caller,
                    detail: "\(signature.user) at \(signature.server)")
            },
            refused: { why, caller in
                try? log.append(event: "refused", key: key, grant: grant, observed: caller, detail: why)
            })
    }
}

/// The servers one SSH permission has been approved for.
final class ServerList: @unchecked Sendable {
    enum Note { case first, known, new }
    private let lock = NSLock()
    private var servers: Set<String>
    private var firstIsFree: Bool

    init(pinned: [String] = []) {
        servers = Set(pinned)
        firstIsFree = pinned.isEmpty
    }

    func note(_ fingerprint: String, firstIsFree useFirst: Bool = true) -> Note {
        lock.lock()
        defer { lock.unlock() }
        if servers.contains(fingerprint) { return .known }
        if useFirst && firstIsFree {
            firstIsFree = false
            servers.insert(fingerprint)
            return .first
        }
        return .new
    }

    func allow(_ fingerprint: String) {
        lock.lock()
        defer { lock.unlock() }
        servers.insert(fingerprint)
    }
}
