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

func addKey() throws {
    guard arguments.count == 2 else { fail(help, code: 2) }
    guard !VaultFile.isTemporary(arguments[1]) else { fail("that name is kept for a rotation") }
    guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
    let value = readSecret(prompt: "Value for \(arguments[1])")
    guard !value.isEmpty else { fail("the value is empty") }
    try store.update { try $0.add(name: arguments[1], value: value) }
    try? auditLog.append(event: "sealed", key: arguments[1])
    print("\(arguments[1]) added")
}

func putKey() throws {
    guard arguments.count == 2 else { fail(help, code: 2) }
    guard store.exists else { fail("there is no vault yet: run keyreeve-vault init") }
    let value = readSecret(prompt: "Value for \(arguments[1])")
    guard !value.isEmpty else { fail("the value is empty") }
    try store.update { vault in
        // A rotation's temporary copies have no history worth keeping.
        if VaultFile.isTemporary(arguments[1]) { vault.entries[arguments[1]] = nil }
        try vault.replace(name: arguments[1], value: value)
    }
    if !VaultFile.isTemporary(arguments[1]) {
        try? auditLog.append(event: "sealed", key: arguments[1], detail: "replaced")
        endPermissions(forSources: [arguments[1]])
    }
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
    for (folder, paths) in byFolder.sorted(by: { $0.key < $1.key }) {
        let report = try VaultKeeper.sealAgain(paths: paths, folder: URL(fileURLWithPath: folder), store: store)
        for path in report.sealed {
            try? auditLog.append(event: "sealed", key: path, detail: "sealed again from its file")
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
