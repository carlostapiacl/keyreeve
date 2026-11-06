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
      keyreeve-vault put <name>
          Add a key or replace it, read from stdin. The old value stays sealed. Needs no fingerprint.
      keyreeve-vault drop <name#pending|name#previous>
          Remove a temporary copy of a rotation. Real keys cannot be removed.
      keyreeve-vault names
          Show what the vault holds by its internal names. Needs no fingerprint.
      keyreeve-vault run <name> --as <VARIABLE> -- <command> [args...]
          Run a command with the key in one variable. Asks for a fingerprint.
          The command's own output is not filtered, so choose a command that does not print it.
      keyreeve-vault use <id> [--as VAR] [--for 5m] [--agent NAME] [--reason TEXT] [--real] -- <command> [args...]
          Run a command with a key, by its identifier. The command holds a stand-in, and a local proxy
          puts the real key on requests to that provider's hosts. Asks for your finger once for this key
          and program, then not again until the permission ends. Each use goes in the usage log.
          --real hands the command the real key, for what cannot use a stand-in. It asks every time.
      keyreeve-vault list
          Show the identifiers and what each one is. Needs no fingerprint.
      keyreeve-vault grants
          Show the permissions in force.
      keyreeve-vault revoke [id]
          End a key's permissions, or all of them.
      keyreeve-vault audit [--key <id>] [--verify]
          Show who used which key, or check that the log was not edited.
      keyreeve-vault env <file.env> -- <command> [args...]
          Run a command with an env file whose values can be keyreeve://name or keyreeve://name#FIELD.
          Asks for one fingerprint. The file holds references, so it is safe in a repository.
      keyreeve-vault mcp
          Serve agents over MCP. They run allowed programs with a key and never get its value.
          ~/.keyreeve/agents.toml says which, and it starts empty. Edit it in the app, on each key.
      keyreeve-vault export <name> --recovery
          Print an age file for this key, which any age tool opens with the recovery key.
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
let home = store.directory.deletingLastPathComponent()
let keysFile = home.appendingPathComponent(KeyIndex.fileName)
let auditLog = AuditLog(url: home.appendingPathComponent("audit.jsonl"))
let socketPath = home.appendingPathComponent("run/keys.sock").path

/// Reaches the service, starting it the first time. It stops on its own once idle.
/// This program's real place. It is often reached through a link, and its helper lives beside the real file.
func ownPath() -> URL {
    URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath()
}

func askService(_ request: KeyService.Request) throws -> KeyService.Response {
    if let answer = try? KeySocket.send(request, path: socketPath) { return answer }
    guard request.op == "use" else { return KeyService.Response(ok: true, grants: []) }
    let process = Process()
    process.executableURL = ownPath()
    process.arguments = ["serve"]
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    for _ in 0..<50 {
        usleep(100_000)
        if FileManager.default.fileExists(atPath: socketPath), let answer = try? KeySocket.send(request, path: socketPath) {
            return answer
        }
    }
    throw VaultError("the key service did not start")
}

func parseDuration(_ text: String) -> Int? {
    guard let unit = text.last, let number = Int(text.dropLast()), number > 0 else { return Int(text) }
    switch unit {
    case "s": return number
    case "m": return number * 60
    case "h": return number * 3600
    default: return nil
    }
}

do {
    switch arguments.first {
    case "init":
        // The recovery key must reach a person's eyes, and not an agent's transcript or a log.
        guard isatty(STDOUT_FILENO) == 1, isatty(STDIN_FILENO) == 1 else {
            fail("init shows the recovery key, so run it yourself in a terminal window")
        }
        guard !store.exists else { fail("there is already a vault in \(store.directory.path)") }
        let (enclave, blob) = try EnclaveRecipient.create()
        let recovery = Age.X25519Identity()
        try store.create(VaultFile(enclave: enclave.publicKey, recovery: recovery.recipient), blob: blob)
        print("""
            Vault created in \(store.directory.path)

            Recovery key. It is shown only now, and it opens every key in this vault:

                \(recovery.string)

            Write it on paper or in your password manager, away from this Mac. If this Mac dies,
            it is the only way back in. It is an ordinary age key, so any age tool can use it too.
            """)
    case "add":
        guard arguments.count == 2 else { fail(help, code: 2) }
        guard !VaultFile.isTemporary(arguments[1]) else { fail("that name is kept for a rotation") }
        guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
        let value = readSecret(prompt: "Value for \(arguments[1])")
        guard !value.isEmpty else { fail("the value is empty") }
        try store.update { try $0.add(name: arguments[1], value: value) }
        print("\(arguments[1]) added")
    case "put":
        guard arguments.count == 2 else { fail(help, code: 2) }
        guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
        let value = readSecret(prompt: "Value for \(arguments[1])")
        guard !value.isEmpty else { fail("the value is empty") }
        try store.update { vault in
            // A rotation's temporary copies have no history worth keeping.
            if VaultFile.isTemporary(arguments[1]) { vault.entries[arguments[1]] = nil }
            try vault.replace(name: arguments[1], value: value)
        }
    case "drop":
        guard arguments.count == 2, VaultFile.isTemporary(arguments[1]) else {
            fail("only a rotation's temporary copies can be removed")
        }
        try store.update { $0.entries[arguments[1]] = nil }
    case "names":
        for name in try store.load().entries.keys.sorted() { print(name) }
    case "list":
        let sealed = Set((try? store.load().entries.keys.map { String($0) }) ?? [])
        for key in try KeyIndex.load(from: keysFile).keys where sealed.contains(key.source) {
            let parts = [key.provider, key.account, key.project, key.description].compactMap { $0 }
            print(([key.id] + parts).joined(separator: "  "))
        }
    case "use":
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
            guard let parsed = parseDuration(text) else { fail("--for takes a time like 90s, 5m or 2h") }
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
        guard let variable = options["--as"] ?? answer.variable else {
            fail("\(id) has no variable set, so say which with --as", code: 2)
        }
        if wantsReal {
            guard let value = answer.value else { fail("the key could not be used", code: 77) }
            setenv(variable, value, 1)
        } else {
            guard let standIn = answer.standIn, let token = answer.token, let proxy = answer.proxy else {
                fail("the key could not be used", code: 77)
            }
            setenv(variable, standIn, 1)
            let address = "http://keyreeve:\(token)@127.0.0.1:\(proxy.port)"
            for name in ["HTTPS_PROXY", "https_proxy"] { setenv(name, address, 1) }
            // Node does not read those variables unless it is told to.
            setenv("NODE_USE_ENV_PROXY", "1", 1)
            setenv("NODE_EXTRA_CA_CERTS", proxy.ca, 1)
            // A name on this list would skip the proxy and go straight out with a useless stand-in.
            unsetenv("NO_PROXY")
            unsetenv("no_proxy")
            for name in ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "AWS_CA_BUNDLE", "CARGO_HTTP_CAINFO", "DENO_CERT"] {
                setenv(name, proxy.bundle, 1)
            }
        }
        var pointers: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        execvp(command[0], &pointers)
        fail("could not run \(command[0])")
    case "serve":
        let descriptor = try KeySocket.listen(path: socketPath)
        // Beside this program, in the app's bundle.
        let command = ownPath().deletingLastPathComponent().appendingPathComponent("keyreeve-cli")
        let proxy = try? ProxyProcess(binary: command, runFolder: home.appendingPathComponent("run"))
        let service = KeyService(
            index: { try KeyIndex.load(from: keysFile) },
            open: { source, prompt in
                let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), reason: prompt)
                return try store.load().open(name: source, with: recipient)
            },
            proxy: proxy, log: auditLog)
        proxy?.onEvent = { grant, key, detail in service.record(grant: grant, key: key, detail: detail) }
        // Stops after a while with nothing in force, so no process stays around for nothing.
        var idleSince = Date()
        KeySocket.serve(descriptor: descriptor, service: service) {
            if !service.isIdle { idleSince = Date() }
            return Date().timeIntervalSince(idleSince) > 600
        }
        unlink(socketPath)
        // The proxy reads until its stdin ends, so it stops with this process.
    case "grants":
        let answer = try askService(KeyService.Request(op: "grants"))
        if (answer.grants ?? []).isEmpty { print("No permission is in force.") }
        for grant in answer.grants ?? [] {
            let left = Int(grant.expires.timeIntervalSinceNow)
            print("\(grant.key)  \(grant.program)  \(left / 60)m \(left % 60)s left  \(grant.id)")
        }
    case "revoke":
        _ = try askService(KeyService.Request(op: "revoke", key: arguments.count > 1 ? arguments[1] : nil))
        print("Done")
    case "audit":
        if arguments.contains("--verify") {
            if let line = auditLog.firstBrokenLine() { fail("the usage log was changed at line \(line)") }
            print("The usage log holds together: \(try auditLog.entries().count) lines")
            break
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
    case "env":
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
    case "mcp":
        let policy = AgentPolicy.load(from: home.appendingPathComponent(AgentPolicy.fileName))
        func indexed(_ id: String) throws -> KeyIndex.Key {
            guard let key = try KeyIndex.load(from: keysFile).key(id) else { throw VaultError("no key is called \(id)") }
            return key
        }
        let bridge = AgentBridge(
            policy: policy,
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
    case "export":
        guard arguments.count == 3, arguments[2] == "--recovery" else { fail(help, code: 2) }
        guard let entry = try store.load().entries[arguments[1]] else { fail("\(arguments[1]) is not in the vault") }
        // This is ciphertext, so printing it reveals nothing without the recovery key.
        FileHandle.standardOutput.write(entry.sealed)
    case "check-recovery":
        let vault = try store.load()
        let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
        let recovery = try Age.X25519Identity(string: text)
        guard recovery.recipient.string == vault.recovery else {
            fail("this is not the recovery key of this vault")
        }
        for name in vault.entries.keys { _ = try vault.open(name: name, with: recovery) }
        print("The recovery key is right, and it opens all \(vault.entries.count) keys")
    case "recover":
        let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
        let recovery = try Age.X25519Identity(string: text)
        let (enclave, blob) = try EnclaveRecipient.create()
        try store.update { vault in
            try vault.moveToNewEnclave(enclave.publicKey, recovery: recovery)
            // After the move worked, so a bad key changes nothing. The vault's own save then
            // switches to this blob, and a crash before that leaves the old pair working.
            try store.saveBlob(blob, for: vault.enclave)
        }
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
