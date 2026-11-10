import CryptoKit
import Foundation
import KeyreeveVault

// What keeps the vault itself: making it, filling it, and getting back in.

func createVault() throws {
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
}

/// Who is sealing, as the system says and as the caller says of itself, for the key's record and the usage log.
func arrivalCaller() -> (observed: AuditLog.Observed, addedBy: String, declared: AuditLog.Declared) {
    let observed = CallerIdentity.observe(pid: getpid())
    let named = ProcessInfo.processInfo.environment["KEYREEVE_AGENT"]
    return (
        observed, KeyArrival.addedBy(observed: observed, declared: named),
        AuditLog.Declared(agent: KeyArrival.agent(observed: observed, declared: named), cwd: FileManager.default.currentDirectoryPath)
    )
}

/// `add <name> [--file PATH] [--description TEXT] [--tags a,b]`. The key goes in with a record no agent sees,
/// marked as new for the person to review. `--file` seals a whole file as it is, such as a keystore.
func addKey() throws {
    var name: String?
    var description: String?
    var tags: [String]?
    var file: URL?
    var rest = arguments.dropFirst()
    while let word = rest.popFirst() {
        switch word {
        case "--description":
            guard let text = rest.popFirst() else { fail(help, code: 2) }
            description = text
        case "--tags":
            guard let text = rest.popFirst() else { fail(help, code: 2) }
            tags = text.split(separator: ",").map(String.init)
        case "--file":
            guard file == nil, let path = rest.popFirst() else { fail(help, code: 2) }
            file = URL(fileURLWithPath: path)
        default:
            guard name == nil, !word.hasPrefix("--") else { fail(help, code: 2) }
            name = word
        }
    }
    // With a file, the name can be left out: the file's own name is used.
    guard let name = name ?? file?.lastPathComponent else { fail(help, code: 2) }
    guard !VaultFile.isTemporary(name) else { fail("that name is kept for a rotation") }
    guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
    let value: Data
    if let file {
        // Byte for byte, so a keystore or a certificate goes in whole. The file itself is only read.
        switch VaultKeeper.readFile(at: file) {
        case .success(let data): value = data
        case .failure(.tooLarge): fail("\(file.path) is larger than 1 MB")
        case .failure(.empty): fail("\(file.path) is empty")
        case .failure: fail("\(file.path) could not be read as a file")
        }
    } else {
        value = readSecret(prompt: "Value for \(name)")
    }
    guard !value.isEmpty else { fail("the value is empty") }
    let caller = arrivalCaller()
    let key = try KeyArrival.add(
        value, as: name, addedBy: caller.addedBy, description: description, tags: tags, store: store, index: keysFile)
    try? auditLog.append(
        event: "sealed", key: key.id, observed: caller.observed, declared: caller.declared,
        detail: "added \(name) by \(caller.addedBy), not offered to agents")
    print("\(name) added as \(key.id). Agents do not see it, and Keyreeve shows it as new until you review it.")
}

/// `put <name>`. A new name goes in as `add` does. A key that is there keeps its value: the new one waits as
/// `<name>#pending` until the person accepts it in Keyreeve. Only the key's own rotation replaces it here.
func putKey() throws {
    guard arguments.count == 2 else { fail(help, code: 2) }
    guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
    let name = arguments[1]
    let value = readSecret(prompt: "Value for \(name)")
    guard !value.isEmpty else { fail("the value is empty") }
    let caller = arrivalCaller()
    // The engine runs this as `keyreeve-cli rotate`, from the app, after the person's fingerprint.
    let parent = URL(fileURLWithPath: CallerIdentity.observe(pid: getppid()).program).lastPathComponent
    let outcome = try KeyArrival.put(
        value, as: name, addedBy: caller.addedBy, byEngine: ["keyreeve-cli", "keyreeve"].contains(parent),
        journal: home.appendingPathComponent("rotations.jsonl"), store: store, index: keysFile)
    let id = (try? KeyIndex.load(from: keysFile))?.allKeys(forSource: name).first?.id ?? name
    switch outcome {
    case .temporary:
        break
    case .added(let key):
        try? auditLog.append(
            event: "sealed", key: key.id, observed: caller.observed, declared: caller.declared,
            detail: "added \(name) by \(caller.addedBy), not offered to agents")
        print("\(name) added as \(key.id). Agents do not see it, and Keyreeve shows it as new until you review it.")
    case .replacedByRotation:
        try? auditLog.append(
            event: "sealed", key: id, observed: caller.observed, declared: caller.declared, detail: "replaced by its rotation")
        endPermissions(forSources: [name])
    case .waiting:
        try? auditLog.append(
            event: "sealed", key: id, observed: caller.observed, declared: caller.declared,
            detail: "a new value from \(caller.addedBy) waits for the person; the current one stays in force")
        print("A new value for \(name) is waiting. The current one stays in force until you accept it in Keyreeve.")
    }
}

/// `orphans`: vault entries with no record in keys.toml. Names only.
func listOrphans() throws {
    for name in KeyArrival.orphans(in: try store.load(), index: try KeyIndex.load(from: keysFile)) { print(name) }
}

/// Permissions opened with a value that was just replaced end now, not when they run out. The service also
/// notices on the next use; this covers what the proxy already holds. With no service, none is in force.
func endPermissions(forSources sources: [String]) {
    guard FileManager.default.fileExists(atPath: socketPath),
        let index = try? KeyIndex.load(from: keysFile)
    else { return }
    for key in index.keys where sources.contains(key.source) {
        let answer = try? KeySocket.send(KeyService.Request(op: "revoke", key: key.id), path: socketPath, timeout: 5)
        if answer?.ok != true {
            FileHandle.standardError.write(Data(
                "keyreeve-vault: could not confirm that permissions for \(key.id) ended; `keyreeve-vault revoke \(key.id)` ends them\n".utf8))
        }
    }
}

/// The app's "Seal the changed files again", for scripts and agents: the file's exact bytes, from the
/// folder each key was sealed from, never a value on stdin or in an argument.
func resealKeys() throws {
    let names = Array(arguments.dropFirst())
    guard !names.isEmpty else { fail(help, code: 2) }
    let vault = try store.load()
    var byFolder: [String: [String]] = [:]
    for name in names {
        guard let source = vault.entries[name]?.source else { fail("\(name) was not sealed from a file") }
        byFolder[source, default: []].append(name)
    }
    let caller = arrivalCaller()
    for (folder, paths) in byFolder.sorted(by: { $0.key < $1.key }) {
        let report = try VaultKeeper.sealAgain(paths: paths, folder: URL(fileURLWithPath: folder), store: store)
        // A key sealed with no record gets one here, as any key that goes in does.
        _ = try? KeyArrival.giveRecords(to: report.sealed, addedBy: caller.addedBy, reviewed: false, index: keysFile)
        let index = try? KeyIndex.load(from: keysFile)
        for path in report.sealed {
            try? auditLog.append(
                event: "sealed", key: index?.allKeys(forSource: path).first?.id ?? path, observed: caller.observed,
                declared: caller.declared,
                detail: "sealed again from its file by \(caller.addedBy)")
            print("\(path) sealed again")
        }
        for (path, why) in report.skipped.sorted(by: { $0.key < $1.key }) { print("\(path) not sealed: \(why)") }
        endPermissions(forSources: report.sealed)
    }
}

func dropTemporary() throws {
    guard arguments.count == 2, VaultFile.isTemporary(arguments[1]) else {
        fail("only a rotation's temporary copies can be removed")
    }
    try store.update { $0.entries[arguments[1]] = nil }
}

func listNames() throws {
    for name in try store.load().entries.keys.sorted() { print(name) }
}

func exportKey() throws {
    guard arguments.count == 3, arguments[2] == "--recovery" else { fail(help, code: 2) }
    guard let entry = try store.load().entries[arguments[1]] else { fail("\(arguments[1]) is not in the vault") }
    // This is ciphertext, so printing it reveals nothing without the recovery key.
    FileHandle.standardOutput.write(entry.sealed)
}

func backupVault() throws {
    guard arguments.count == 2 else { fail(help, code: 2) }
    let target = try store.backup(to: URL(fileURLWithPath: arguments[1]))
    print("Saved \(target.path). It opens with your recovery key, through keyreeve-vault recover.")
}

/// With no argument, this vault; with a file, a backup made with `backup`, which proves it would bring the keys back.
func checkRecovery() throws {
    let backup = arguments.count > 1 ? URL(fileURLWithPath: arguments[1]) : nil
    let vault = try backup.map(VaultStore.read) ?? store.load()
    let text = String(decoding: readSecret(prompt: "Recovery key"), as: UTF8.self)
    let recovery = try Age.X25519Identity(string: text)
    let opened = try vault.openAll(with: recovery)
    print(backup == nil
        ? "The recovery key is right, and it opens all \(opened) keys"
        : "The backup opens with the recovery key: all \(opened) keys, and every older copy")
}

func recoverVault() throws {
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
}
