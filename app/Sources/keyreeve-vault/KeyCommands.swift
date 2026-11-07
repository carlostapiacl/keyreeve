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
    let id = arguments[1]
    var options: [String: String] = [:]
    var index = 2
    var wantsReal = false
    while index < dash {
        if arguments[index] == "--real" {
            wantsReal = true
            index += 1
            continue
        }
        guard ["--as", "--for", "--agent", "--reason"].contains(arguments[index]), index + 1 < dash else { fail(help, code: 2) }
        options[arguments[index]] = arguments[index + 1]
        index += 2
    }
    let command = Array(arguments[(dash + 1)...])
    var seconds: Int?
    if let text = options["--for"] {
        guard let parsed = KeyService.seconds(from: text) else { fail("--for takes a time like 90s, 5m or 2h") }
        seconds = parsed
    }
    let shown = command.joined(separator: " ")
    let answer = try askService(
        KeyService.Request(
            op: "use", key: id, seconds: seconds, program: command[0], arguments: command.count - 1,
            prompt: "run \(shown.prefix(120)) with the key \(id)",
            agent: options["--agent"] ?? ProcessInfo.processInfo.environment["KEYREEVE_AGENT"],
            reason: options["--reason"], cwd: FileManager.default.currentDirectoryPath, real: wantsReal))
    guard answer.ok else { fail(answer.error ?? "the key could not be used", code: 77) }
    let prepared: UseEnvironment
    do {
        prepared = try UseEnvironment(answer: answer, command: command, variable: options["--as"] ?? answer.variable, real: wantsReal)
    } catch let error as VaultError {
        fail(answer.sshSocket == nil && (options["--as"] ?? answer.variable) == nil
            ? "\(id) has no variable set, so say which with --as" : error.description, code: 2)
    }
    for name in prepared.unset { unsetenv(name) }
    for (name, value) in prepared.setIfMissing { setenv(name, value, 0) }
    for (name, value) in prepared.set { setenv(name, value, 1) }
    var pointers: [UnsafeMutablePointer<CChar>?] = prepared.command.map { strdup($0) } + [nil]
    execvp(prepared.command[0], &pointers)
    fail("could not run \(command[0])")
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
            prompt: isSSH ? "use the SSH key \(id)" : "let \(program) use the key \(id)",
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
        log: auditLog)
    proxy?.onEvent = { grant, key, detail in service.record(grant: grant, key: key, detail: detail) }
    // Stops after a while with nothing in force, so no process stays around for nothing.
    var idleSince = Date()
    KeySocket.serve(descriptor: descriptor, service: service) {
        if !service.isIdle { idleSince = Date() }
        return Date().timeIntervalSince(idleSince) > 600
    }
    unlink(socketPath)
    // The proxy reads until its stdin ends, so it stops with this process.
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
        if let line = auditLog.firstBrokenLine() { fail("the usage log was changed at line \(line)") }
        print("The usage log holds together: \(try auditLog.entries().count) lines")
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
