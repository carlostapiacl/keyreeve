import Foundation
import KeyreeveVault

// Using keys by identifier, through the service that holds permissions.

func listKeys() throws {
    let sealed = Set((try? store.load().entries.keys.map { String($0) }) ?? [])
    for key in try KeyIndex.load(from: keysFile).keys where sealed.contains(key.source) {
        let parts = [key.provider, key.account, key.project, key.description].compactMap { $0 }
        print(([key.id] + parts).joined(separator: "  "))
    }
}

func useKey() throws {
    guard let dash = arguments.firstIndex(of: "--"), dash + 1 < arguments.count, dash >= 2 else { fail(help, code: 2) }
    // `use a,b,c` or `use --set name`: several keys for one command, in one window with one fingerprint.
    var setName: String?
    var index = 2
    if arguments[1] == "--set" {
        guard dash >= 3 else { fail(help, code: 2) }
        setName = arguments[2]
        index = 3
    }
    let ids = setName == nil ? arguments[1].split(separator: ",").map(String.init).filter { !$0.isEmpty } : []
    var options: [String: String] = [:]
    var named: [String] = []
    var wantsReal = false
    while index < dash {
        if arguments[index] == "--real" {
            wantsReal = true
            index += 1
            continue
        }
        guard ["--as", "--for", "--agent", "--reason"].contains(arguments[index]), index + 1 < dash else { fail(help, code: 2) }
        if arguments[index] == "--as" { named.append(arguments[index + 1]) }
        options[arguments[index]] = arguments[index + 1]
        index += 2
    }
    let command = Array(arguments[(dash + 1)...])
    var seconds: Int?
    if let text = options["--for"] {
        guard let parsed = KeyService.seconds(from: text) else { fail("--for takes a time like 90s, 5m or 2h") }
        seconds = parsed
    }
    let place = programPlace(command)
    if setName != nil || ids.count > 1 {
        guard !wantsReal else { fail("--real goes one key at a time, with its own fingerprint", code: 2) }
        useKeys(ids, set: setName, named: named, seconds: seconds, options: options, command: command, place: place)
    }
    guard let id = ids.first else { fail(help, code: 2) }
    var request = KeyService.Request(
        op: "use", key: id, seconds: seconds, program: command[0], arguments: command.count - 1,
        prompt: nil,
        agent: options["--agent"] ?? ProcessInfo.processInfo.environment["KEYREEVE_AGENT"],
        reason: options["--reason"], cwd: FileManager.default.currentDirectoryPath, real: wantsReal,
        programPath: place.program, script: place.script)
    // A key the person marked "always, no fingerprint" opens with none for a program run in the background, such
    // as a bot started at login. The service grants it only if it finds the mark itself; the real key always asks.
    if !wantsReal { request.unattended = true }
    let answer = try askService(request)
    guard answer.ok else { fail(answer.error ?? "the key could not be used", code: 77) }
    let prepared: UseEnvironment
    do {
        prepared = try UseEnvironment(answer: answer, command: command, variable: options["--as"] ?? answer.variable, real: wantsReal)
    } catch let error as VaultError {
        fail(answer.sshSocket == nil && (options["--as"] ?? answer.variable) == nil
            ? "\(id) has no variable set, so say which with --as" : error.description, code: 2)
    }
    run(prepared)
}

/// Where the program is on disk, and the script it runs when its first argument is a file: what a permission given
/// "always, for this program in this folder" is bound to, with their SHA-256.
func programPlace(_ command: [String]) -> (program: String?, script: String?) {
    let folder = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    func found(_ path: String) -> String? {
        var directory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &directory), !directory.boolValue else { return nil }
        return URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }
    var program: String?
    if command[0].contains("/") {
        program = found(URL(fileURLWithPath: command[0], relativeTo: folder).path)
    } else {
        for directory in (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":") {
            let candidate = URL(fileURLWithPath: String(directory)).appendingPathComponent(command[0]).path
            if FileManager.default.isExecutableFile(atPath: candidate) {
                program = found(candidate)
                break
            }
        }
    }
    let script = command.count > 1 && !command[1].hasPrefix("-")
        ? found(URL(fileURLWithPath: command[1], relativeTo: folder).path) : nil
    return (program, script)
}

/// Several keys for one command. Each goes in its own variable, from keys.toml, or `--as id=VAR`.
func useKeys(
    _ ids: [String], set: String?, named: [String], seconds: Int?, options: [String: String], command: [String],
    place: (program: String?, script: String?)
) -> Never {
    var keys = ids
    if let set {
        let sets: KeySets
        do { sets = try KeySets.loadStrict(from: home.appendingPathComponent(KeySets.fileName)) } catch { fail("\(error)") }
        guard let found = sets.set(set) else { fail("no set is called \(set). Keyreeve shows them under Agents, in Key sets") }
        keys = found.keys
    }
    var variables: [String: String] = [:]
    for pair in named.flatMap({ $0.split(separator: ",").map(String.init) }) {
        let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
        guard parts.count == 2, keys.contains(parts[0]) else {
            fail("with several keys, --as takes id=VARIABLE for a key in the list, such as --as \(keys[0])=MY_TOKEN", code: 2)
        }
        variables[parts[0]] = parts[1]
    }
    let index = (try? KeyIndex.load(from: keysFile)) ?? KeyIndex()
    // Said before anything is asked, so no finger is spent on a command that cannot start.
    let unnamed = keys.filter { index.key($0) != nil && variables[$0] == nil && index.key($0)?.variable == nil }
    guard unnamed.isEmpty else {
        fail("\(unnamed.joined(separator: ", ")) has no variable set, so say which with --as \(unnamed[0])=VARIABLE", code: 2)
    }
    let request = KeyService.Request(
        op: "use-many", seconds: seconds, program: command[0], arguments: command.count - 1,
        agent: options["--agent"] ?? ProcessInfo.processInfo.environment["KEYREEVE_AGENT"],
        reason: options["--reason"], cwd: FileManager.default.currentDirectoryPath, keys: keys, set: set,
        programPath: place.program, script: place.script)
    let answer: KeyService.Response
    do { answer = try askService(request) } catch { fail("\(error)") }
    guard answer.ok, let many = answer.many else { fail(answer.error ?? "the keys could not be used", code: 77) }
    var prepared = UseEnvironment.plain(command: command)
    for one in many {
        guard one.ok, let id = one.key else {
            FileHandle.standardError.write(Data("keyreeve-vault: \(one.key ?? "-"): \(one.error ?? "not opened"), so it is not set\n".utf8))
            continue
        }
        guard let each = try? UseEnvironment(answer: one, command: command, variable: variables[id] ?? one.variable) else {
            FileHandle.standardError.write(Data("keyreeve-vault: \(id) could not be set\n".utf8))
            continue
        }
        prepared.set.merge(each.set) { _, new in new }
        prepared.setIfMissing.merge(each.setIfMissing) { _, new in new }
        prepared.unset = Array(Set(prepared.unset + each.unset))
    }
    run(prepared)
}

/// Runs the command in this process, so a permission "until it finishes" ends when it does.
func run(_ prepared: UseEnvironment) -> Never {
    for name in prepared.unset { unsetenv(name) }
    for (name, value) in prepared.setIfMissing { setenv(name, value, 0) }
    for (name, value) in prepared.set { setenv(name, value, 1) }
    var pointers: [UnsafeMutablePointer<CChar>?] = prepared.command.map { strdup($0) } + [nil]
    execvp(prepared.command[0], &pointers)
    fail("could not run \(prepared.command[0])")
}

/// Opens a permission ahead of time, so what runs later does not stop to ask.
func grantKey() throws {
    guard arguments.count >= 2 else { fail(help, code: 2) }
    let id = arguments[1]
    var options: [String: String] = [:]
    var index = 2
    while index < arguments.count {
        guard ["--for", "--program"].contains(arguments[index]), index + 1 < arguments.count else { fail(help, code: 2) }
        options[arguments[index]] = arguments[index + 1]
        index += 2
    }
    var seconds: Int?
    if let text = options["--for"] {
        guard let parsed = KeyService.seconds(from: text) else { fail("--for takes a time like 90s, 5m or 2h") }
        seconds = parsed
    }
    let isSSH = try KeyIndex.load(from: keysFile).key(id)?.provider == KeyService.sshProvider
    guard let program = options["--program"] ?? (isSSH ? "ssh" : nil) else {
        fail("a permission is for one program, so say which with --program", code: 2)
    }
    let answer = try askService(
        KeyService.Request(
            op: "use", key: id, seconds: seconds, program: program,
            prompt: FingerPrompt.use(
                who: program, key: id, account: try? KeyIndex.load(from: keysFile).key(id)?.account,
                lasts: seconds.map { $0 >= 3600 ? .hours($0 / 3600) : .minutes(max(1, $0 / 60)) }),
            agent: ProcessInfo.processInfo.environment["KEYREEVE_AGENT"], reason: "permission given ahead of time",
            cwd: FileManager.default.currentDirectoryPath))
    guard answer.ok else { fail(answer.error ?? "the key could not be used", code: 77) }
    print("Done. `keyreeve-vault grants` shows how long it lasts, and `revoke \(id)` ends it.")
}

/// `ssh-add` calls this program for a key with a passphrase. It speaks only through a dialog, and only
/// the answer goes to stdout, which `ssh-add` reads.
func askPassphrase(for name: String) -> Never {
    let retry = CommandLine.arguments.dropFirst().first?.lowercased().contains("bad") == true
    let text = (retry ? "Wrong passphrase. " : "") + "Passphrase for the SSH key \(name)"
    let dialog = Process()
    dialog.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    dialog.arguments = [
        "-e", "on run argv",
        "-e", "return text returned of (display dialog (item 1 of argv) default answer \"\" with hidden answer)",
        "-e", "end run", text,
    ]
    dialog.standardError = FileHandle.nullDevice
    dialog.standardInput = FileHandle.nullDevice
    do { try dialog.run() } catch { exit(1) }
    dialog.waitUntilExit()
    exit(dialog.terminationStatus)
}

func serveKeys() throws {
    let descriptor = try KeySocket.listen(path: socketPath)
    // Beside this program, in the app's bundle.
    let command = ownPath().deletingLastPathComponent().appendingPathComponent("keyreeve-cli")
    let proxy: ProxyProcess?
    do {
        proxy = try ProxyProcess(binary: command, runFolder: home.appendingPathComponent("run"))
    } catch {
        // SSH keys still work without it, so the service runs, but say why use_key will fail.
        FileHandle.standardError.write(Data("keyreeve-vault: no proxy, \(command.path) did not start: \(error)\n".utf8))
        proxy = nil
    }
    let service = KeyService(
        index: { try KeyIndex.load(from: keysFile) },
        open: { source, prompt in
            let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), reason: prompt)
            return try store.load().open(name: source, with: recipient)
        },
        proxy: proxy, agents: SystemSSHAgents(folder: home.appendingPathComponent("run"), askpass: ownPath().path),
        confirm: { prompt in (try? EnclaveRecipient.confirm(reason: prompt)) != nil },
        log: auditLog,
        paused: { AgentBridge.isPaused(home: home) },
        revision: { source in (try? store.load())?.entries[source]?.revision },
        openUnattended: { id, agent, source in
            // The person's own mark, read here and now: the key at "always", open to this agent, not paused.
            guard let policy = try? AgentPolicy.loadStrict(from: home.appendingPathComponent(AgentPolicy.fileName)), policy.level(of: id, at: Date()) == .always,
                policy.admits(agent: agent ?? "", for: id), !AgentBridge.isPaused(home: home),
                let vault = try? store.load(), let blob = try? store.loadUnattendedBlob(for: vault),
                let recipient = try? EnclaveRecipient.loadUnattended(blob: blob)
            else { return nil }
            return try? vault.openUnattended(name: source, with: recipient)
        },
        openMany: { sources, prompt in
            // One fingerprint, then every source opens with it.
            let context = try EnclaveRecipient.confirm(reason: prompt)
            let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), context: context)
            let vault = try store.load()
            return try Dictionary(sources.map { ($0, try vault.open(name: $0, with: recipient)) }, uniquingKeysWith: { a, _ in a })
        },
        choose: askChoice,
        sets: { KeySets.load(from: home.appendingPathComponent(KeySets.fileName)) },
        keepStanding: { standing, values in
            // The copies that ask nothing first, then the permission that uses them.
            _ = try store.ensureUnattended()
            try store.update { vault in
                for (source, value) in values { try vault.sealUnattended(name: source, value: value) }
            }
            try KeySets.update(at: home.appendingPathComponent(KeySets.fileName)) { sets in
                var kept = standing
                // Keys given before for the same program as it is now stay; a program that changed starts over.
                if let old = sets.standing.first(where: { $0.id == standing.id }), old.hash == standing.hash,
                    old.scriptHash == standing.scriptHash
                {
                    kept.keys = Array(Set(old.keys + standing.keys)).sorted()
                }
                sets.standing.removeAll { $0.id == standing.id }
                sets.standing.append(kept)
            }
        },
        openStanding: { source in
            // Paused, nothing opens with no fingerprint. Otherwise the copy that asks nothing, through the proxy only.
            guard !AgentBridge.isPaused(home: home), let vault = try? store.load(), let blob = try? store.loadUnattendedBlob(for: vault),
                let recipient = try? EnclaveRecipient.loadUnattended(blob: blob)
            else { return nil }
            return try? vault.openUnattended(name: source, with: recipient)
        },
        gather: 2)
    proxy?.onEvent = { grant, key, detail in service.record(grant: grant, key: key, detail: detail) }
    // Stops after a while with nothing in force, so no process stays around for nothing. It also stops when
    // this program or the proxy is replaced on disk: an agent that uses a key all day would otherwise keep an
    // old version running, with fixes built since never in force. The next use starts the new one.
    var idleSince = Date()
    let started = [ownPath(), command].map(changeStamp)
    KeySocket.serve(descriptor: descriptor, service: service) {
        if !service.isIdle { idleSince = Date() }
        return Date().timeIntervalSince(idleSince) > 600 || [ownPath(), command].map(changeStamp) != started
    }
    unlink(socketPath)
    // The proxy reads until its stdin ends, so it stops with this process.
}

/// When a file last changed, and which file it is, so a replaced program is noticed.
func changeStamp(_ url: URL) -> String {
    let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
    let date = (attributes?[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
    return "\(date)-\(attributes?[.systemFileNumber] as? Int ?? 0)"
}

func showGrants() throws {
    let answer = try askService(KeyService.Request(op: "grants"))
    if (answer.grants ?? []).isEmpty { print("No permission is in force.") }
    for grant in answer.grants ?? [] {
        let left = Int(grant.expires.timeIntervalSinceNow)
        print("\(grant.key)  \(grant.program)  \(left / 60)m \(left % 60)s left  \(grant.id)")
    }
}

func revokeGrants() throws {
    if arguments.count == 1 { AgentBridge.endAll(home: home) }
    _ = try askService(KeyService.Request(op: "revoke", key: arguments.count > 1 ? arguments[1] : nil))
    print("Done")
}

func showAudit() throws {
    if arguments.contains("--help") || arguments.contains("-h") {
        print("keyreeve-vault audit [--key <id>] [--verify]\n    Show the usage log, or check that its chain holds together.")
        return
    }
    if arguments.contains("--verify") {
        if let broken = auditLog.firstBreak() {
            fail(broken.line == 0 ? "\(broken.file) could not be read" : "the usage log was changed: \(broken.file), line \(broken.line)")
        }
        let parts = auditLog.segments().count
        print("The usage log holds together: \(try auditLog.entries().count) lines" + (parts > 1 ? " in \(parts) files" : ""))
        return
    }
    var filter: String?
    if let at = arguments.firstIndex(of: "--key"), at + 1 < arguments.count { filter = arguments[at + 1] }
    let format = ISO8601DateFormatter()
    for entry in try auditLog.entries() where filter == nil || entry.key == filter {
        let who = entry.observed?.chain.joined(separator: " < ") ?? "-"
        let what = [entry.declared?.command, entry.declared?.agent.map { "agent \($0)" }, entry.declared?.reason, entry.detail]
            .compactMap { $0 }.joined(separator: " · ")
        print("\(format.string(from: entry.at))  \(entry.event)  \(entry.key)  \(who)  \(what)")
    }
}

/// Every log as one list in time order, to read or to analyse elsewhere. No value is in any of them.
func showTimeline() throws {
    func option(_ name: String) -> String? {
        guard let at = arguments.firstIndex(of: name), at + 1 < arguments.count else { return nil }
        return arguments[at + 1]
    }
    var since: Date?
    if let text = option("--since") {
        guard let start = Timeline.start(from: text) else { fail("--since takes a time like 30m, 24h or 7d", code: 2) }
        since = start
    }
    let index = (try? KeyIndex.load(from: keysFile)) ?? KeyIndex()
    var rows = Timeline.read(home: home, index: index, since: since)
    if let key = option("--key") { rows = rows.filter { $0.key == key } }
    print(arguments.contains("--csv") ? Timeline.csv(rows) : Timeline.jsonl(rows), terminator: "")
}

/// The real key on stdout, and nothing else: what seisin and other tools expect from a key provider.
/// A finger every time, named after the program that asked, so a yes is never reused.
func getKey() throws {
    guard arguments.count >= 2, !arguments[1].hasPrefix("-") else { fail(help, code: 2) }
    let id = arguments[1]
    var reason: String?
    if let at = arguments.firstIndex(of: "--reason"), at + 1 < arguments.count { reason = arguments[at + 1] }
    // Who ran this, as the system says, so the prompt reads "to seisin" and not "to keyreeve-vault".
    let parent = CallerIdentity.observe(pid: getppid()).program
    let asker = URL(fileURLWithPath: parent.isEmpty ? "a program" : parent).lastPathComponent
    let answer = try askService(
        KeyService.Request(
            op: "use", key: id, program: asker,
            agent: ProcessInfo.processInfo.environment["KEYREEVE_AGENT"], reason: reason,
            cwd: FileManager.default.currentDirectoryPath, real: true))
    guard answer.ok, let value = answer.value, !value.isEmpty else { fail(answer.error ?? "the key could not be read", code: 77) }
    FileHandle.standardOutput.write(Data(value.utf8))
}
