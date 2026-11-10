import Foundation

/// Several keys at once: a `use-many` for one command, or single uses from one caller that arrive close together.
/// Either way the person sees one window with every key, unticks what they do not want, and gives one fingerprint.
extension KeyService {
    /// One key asked for, with everything needed to open it once the person says yes.
    struct Ask {
        let request: Request
        let key: KeyIndex.Key
        let provider: String
        /// The program's name, without its folders.
        let name: String
        let declared: AuditLog.Declared
        let caller: AuditLog.Observed?
    }

    /// Single uses that wait together for one window.
    final class Gathering: @unchecked Sendable {
        var asks: [Ask]
        var results: [Result<Response, Error>] = []
        let done = DispatchSemaphore(value: 0)
        init(_ first: Ask) { asks = [first] }
    }

    /// The value of a key a standing permission covers for this program, script and folder, with no fingerprint.
    func standingValue(for ask: Ask) -> Data? {
        let request = ask.request
        guard request.real != true, request.programPath != nil, request.cwd != nil else { return nil }
        let covered = sets().standing.contains {
            $0.covers(key: ask.key.id, program: request.programPath, script: request.script, folder: request.cwd, fingerprint: fingerprint)
        }
        return covered ? openStanding(ask.key.source) : nil
    }

    func useMany(_ request: Request, caller: AuditLog.Observed?) throws -> Response {
        var ids: [String] = []
        for id in request.keys ?? [] where !ids.contains(id) { ids.append(id) }
        guard !ids.isEmpty, ids.count <= KeySets.maxKeys, let program = request.program, !program.isEmpty else {
            throw VaultError("this needs from 1 to \(KeySets.maxKeys) keys and a command")
        }
        guard request.real != true else { throw VaultError("the real key goes one key at a time, with its own fingerprint") }
        let name = URL(fileURLWithPath: program).lastPathComponent
        let declared = AuditLog.Declared(
            agent: request.agent, reason: request.reason, command: "\(name) (\(request.arguments ?? 0) arguments)", cwd: request.cwd)
        guard !paused() else {
            for id in ids { try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "paused") }
            throw VaultError("Keyreeve is paused")
        }
        var results: [String: Response] = [:]
        var asks: [Ask] = []
        let index = try self.index()
        for id in ids {
            // Only keys offered to agents are in the index's list: one that is not answers as a name that is not there.
            guard let key = index.key(id) else {
                try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "no such key")
                results[id] = Response(ok: false, error: "no key is called \(id). `list` shows them", key: id)
                continue
            }
            guard let provider = key.provider, provider != Self.sshProvider else {
                results[id] = Response(
                    ok: false, error: key.provider == nil ? "\(id) has no provider, so nothing says where it may go"
                        : "\(id) is an SSH key, which goes on its own: `use \(id) -- ssh ...`", key: id)
                continue
            }
            guard proxy != nil else {
                try log.append(event: "refused", key: id, observed: caller, declared: declared, detail: "no proxy")
                results[id] = Response(ok: false, error: "the proxy is not available", key: id)
                continue
            }
            var single = request
            single.key = id
            single.keys = nil
            let ask = Ask(request: single, key: key, provider: provider, name: name, declared: declared, caller: caller)
            if let existing = try current(key, program: name, notAfter: request.notAfter, caller: caller) {
                try log.append(event: "used", key: id, grant: existing.id, observed: caller, declared: declared)
                results[id] = try keyed(answer(for: existing, variable: key.variable), id)
            } else if let quiet = standingValue(for: ask) {
                results[id] = Self.settle(id) {
                    try install(ask, sealed: quiet, sealing: revision(key.source), seconds: request.seconds ?? Self.defaultSeconds,
                        quiet: true, revocationsBefore: revocationsNow(), note: "always for \(name) in this folder")
                }
            } else {
                asks.append(ask)
            }
        }
        if !asks.isEmpty {
            for (ask, result) in zip(asks, try decide(asks, set: request.set, decided: request.decided == true)) {
                results[ask.key.id] = Self.settle(ask.key.id) { try result.get() }
            }
        }
        let many = ids.compactMap { results[$0] }
        let ok = many.contains { $0.ok }
        return Response(ok: ok, error: ok ? nil : many.first { $0.error != nil }?.error, many: many)
    }

    private func keyed(_ response: Response, _ id: String) -> Response {
        var out = response
        out.key = id
        return out
    }

    static func settle(_ id: String, _ body: () throws -> Response) -> Response {
        do {
            var out = try body()
            out.key = id
            return out
        } catch let error as VaultError {
            return Response(ok: false, error: error.description, key: id)
        } catch {
            return Response(ok: false, error: "the fingerprint was not accepted, or the key could not be opened", key: id)
        }
    }

    func revocationsNow() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return revocations
    }

    /// Waits a moment for other uses from the same caller, so a script that asks for ten keys one by one sees one
    /// window and not ten. The first to arrive asks for all of them; the others wait for its answer.
    func coalesce(_ ask: Ask) throws -> Response {
        let group = ask.request.agent.map { "agent:" + $0 }
            ?? "chain:" + (ask.caller?.chain.dropFirst().joined(separator: "<") ?? "")
        lock.lock()
        if let waiting = gatherings[group] {
            let place = waiting.asks.count
            waiting.asks.append(ask)
            lock.unlock()
            waiting.done.wait()
            waiting.done.signal()
            return try waiting.results[place].get()
        }
        let gathering = Gathering(ask)
        gatherings[group] = gathering
        lock.unlock()
        Thread.sleep(forTimeInterval: gather)
        lock.lock()
        gatherings[group] = nil
        let asks = gathering.asks
        lock.unlock()
        if asks.count == 1 {
            gathering.results = [Result { try personal(ask, quiet: nil) }]
        } else {
            do {
                gathering.results = try decide(asks, set: nil, decided: false)
            } catch {
                gathering.results = asks.map { _ in .failure(error) }
            }
        }
        gathering.done.signal()
        return try gathering.results[0].get()
    }

    /// Asks the person about several keys in one window and one fingerprint. One result for each ask, in order.
    func decide(_ asks: [Ask], set: String?, decided: Bool) throws -> [Result<Response, Error>] {
        let first = asks[0]
        let who = first.request.agent ?? first.name
        try takeTurn(key: asks.count == 1 ? first.key.id : "\(asks.count) keys", who: who, caller: first.caller, declared: first.declared)
        defer { endTurn() }
        var results = [Result<Response, Error>?](repeating: nil, count: asks.count)
        var pending: [Int] = []
        // While this waited, the prompt ahead of it may have given what these need.
        for (at, ask) in asks.enumerated() {
            if let existing = try current(ask.key, program: ask.name, notAfter: ask.request.notAfter, caller: ask.caller) {
                try log.append(event: "used", key: ask.key.id, grant: existing.id, observed: ask.caller, declared: ask.declared)
                results[at] = .success(try answer(for: existing, variable: ask.key.variable))
            } else {
                pending.append(at)
            }
        }
        guard !pending.isEmpty else { return results.map { $0! } }
        // "Always" is bound to one program, script and folder, so it is offered only when all of them share those.
        let places = Swift.Set(pending.map { at -> [String] in
            let request = asks[at].request
            return [request.programPath ?? "", request.script ?? "", request.cwd ?? ""]
        })
        let canStand = !decided && places.count == 1 && pending.allSatisfy {
            asks[$0].request.programPath != nil && asks[$0].request.cwd != nil && asks[$0].request.anyProgram != true
        }
        let (choices, suggested) = KeyBatch.choices(asked: first.request.seconds, canStand: canStand)
        let batch = KeyBatch(
            items: pending.map {
                let ask = asks[$0]
                return KeyBatch.Item(
                    key: ask.key.id, account: ask.key.account, provider: ask.provider, program: ask.name, agent: ask.request.agent,
                    reason: ask.request.reason)
            },
            set: set, folder: first.request.cwd, choices: choices, suggested: suggested)
        let chosen: KeyBatch.Answer?
        if decided || choose == nil {
            chosen = KeyBatch.Answer(chosen: Array(pending.indices), lasts: batch.suggested)
        } else {
            chosen = choose?(batch)
        }
        // A no, or a window closed, grants nothing.
        guard let chosen, choices.contains(chosen.lasts) else {
            for at in pending {
                try log.append(event: "denied", key: asks[at].key.id, observed: asks[at].caller, declared: asks[at].declared, detail: "the window was closed or said no")
                results[at] = .failure(VaultError("the person said no to \(asks[at].key.id)"))
            }
            return results.map { $0! }
        }
        let ticked = Swift.Set(chosen.chosen.filter { pending.indices.contains($0) })
        var opening: [Int] = []
        for (place, at) in pending.enumerated() {
            if ticked.contains(place) {
                opening.append(at)
            } else {
                try log.append(event: "denied", key: asks[at].key.id, observed: asks[at].caller, declared: asks[at].declared, detail: "unticked in the window")
                results[at] = .failure(VaultError("the person left \(asks[at].key.id) unticked"))
            }
        }
        guard !opening.isEmpty else { return results.map { $0! } }
        guard !paused() else { throw VaultError("Keyreeve is paused") }
        let revocationsBefore = revocationsNow()
        let names = opening.map { asks[$0].key.id }
        let programs = Swift.Set(opening.map { asks[$0].name })
        let folderName = first.request.cwd.map { URL(fileURLWithPath: $0).lastPathComponent }
        var lasts: FingerPrompt.Lasts?
        if case .seconds(let seconds) = chosen.lasts { lasts = seconds >= 3600 ? .hours(seconds / 3600) : .minutes(max(1, seconds / 60)) }
        let prompt = FingerPrompt.useMany(
            who: who, keys: names, program: programs.count == 1 ? programs.first : nil, lasts: lasts,
            always: chosen.lasts == .always ? folderName : nil, reason: first.request.reason)
        // Read before the values, so one replaced in between is never kept under the older sealing.
        let sealings = Dictionary(opening.map { (asks[$0].key.source, revision(asks[$0].key.source)) }, uniquingKeysWith: { a, _ in a })
        var sources: [String] = []
        for at in opening where !sources.contains(asks[at].key.source) { sources.append(asks[at].key.source) }
        let values: [String: Data]
        do {
            if let openMany {
                values = try openMany(sources, prompt)
            } else {
                values = try Dictionary(sources.map { ($0, try open($0, prompt)) }, uniquingKeysWith: { a, _ in a })
            }
        } catch {
            for at in opening {
                try log.append(event: "denied", key: asks[at].key.id, observed: asks[at].caller, declared: asks[at].declared)
                results[at] = .failure(VaultError("the fingerprint was not given, so nothing was opened"))
            }
            return results.map { $0! }
        }
        for at in opening {
            let ask = asks[at]
            guard let sealed = values[ask.key.source] else {
                results[at] = .failure(VaultError("\(ask.key.id) could not be opened"))
                continue
            }
            var seconds = ask.request.seconds ?? Self.defaultSeconds
            var pid: Int32?
            switch chosen.lasts {
            case .seconds(let chosenSeconds): seconds = chosenSeconds
            case .untilDone:
                // The command runs as the process that asked, so its end is the permission's end. A day at most.
                seconds = Self.maxSeconds
                pid = ask.caller?.pid
            case .always: break
            }
            if chosen.lasts == .untilDone, pid == nil {
                results[at] = .failure(VaultError("the command that asked could not be told apart, so choose a time"))
                continue
            }
            results[at] = Result {
                try install(
                    ask, sealed: sealed, sealing: sealings[ask.key.source] ?? nil, seconds: seconds, quiet: false,
                    revocationsBefore: revocationsBefore, pid: pid,
                    note: chosen.lasts == .always ? "always for \(ask.name) in this folder" : nil)
            }
        }
        if chosen.lasts == .always, let at = opening.first, let program = asks[at].request.programPath, let folder = asks[at].request.cwd,
            let hash = fingerprint(program)
        {
            let script = asks[at].request.script
            let granted = opening.filter { (try? results[$0]?.get())?.ok == true }.map { asks[$0].key.id }
            let standing = KeySets.Standing(
                keys: granted, program: program, hash: hash, script: script, scriptHash: script.flatMap(fingerprint), folder: folder,
                since: now(), set: set)
            do {
                if !granted.isEmpty, script == nil || standing.scriptHash != nil {
                    try keepStanding(standing, values)
                    try log.append(event: "standing", key: granted.joined(separator: " "), observed: first.caller, declared: first.declared,
                        detail: "always for \(asks[at].name) in \(folder)")
                }
            } catch {
                try? log.append(event: "refused", key: granted.joined(separator: " "), observed: first.caller, declared: first.declared,
                    detail: "always could not be kept, so this run only")
            }
        }
        return results.map { $0! }
    }
}
