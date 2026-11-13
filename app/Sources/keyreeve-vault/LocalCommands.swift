import Foundation
import KeyreeveVault

let localServicesFile = home.appendingPathComponent(LocalServices.fileName)

/// `local`: the keys that go to a service of yours on this Mac, and whether each is approved.
/// `local <id>=<address> ...`: approves each, with one fingerprint, and names it in keys.toml.
/// `local <id> --off`: takes it away with no fingerprint, and ends the key's permissions.
func localServices() throws {
    let rest = Array(arguments.dropFirst())
    if rest.isEmpty {
        let index = try KeyIndex.load(from: keysFile)
        let approvals = LocalServices.load(from: localServicesFile)
        let listed = (index.keys + index.unoffered).sorted { $0.id < $1.id }.filter {
            $0.local != nil || approvals.approved[$0.id] != nil
        }
        if listed.isEmpty { print("No key goes to a local service. `keyreeve local <id>=127.0.0.1:<port>` approves one.") }
        for key in listed {
            let state = (try? approvals.destination(of: key)) != nil ? "approved" : "not approved"
            print("\(key.id)\t\(key.local ?? approvals.approved[key.id] ?? "-")\t\(state)")
        }
        return
    }
    if rest.count == 2, rest[1] == "--off" {
        let id = rest[0]
        try LocalServices.remove(id, keys: keysFile, approvals: localServicesFile)
        // A permission in force would keep the key on its way there until it ends.
        _ = try? askService(KeyService.Request(op: "revoke", key: id))
        try auditLog.append(event: "policy", key: id, detail: "local service removed")
        print("\(id) no longer goes to a local service.")
        return
    }
    var wanted: [(key: String, address: String)] = []
    for pair in rest {
        guard let equals = pair.firstIndex(of: "="), equals != pair.startIndex else { fail(help, code: 2) }
        let id = String(pair[..<equals])
        let text = String(pair[pair.index(after: equals)...])
        guard let address = LocalServices.address(text) else {
            fail("\(text) is not a local service: write 127.0.0.1, [::1] or localhost, a colon and the port, such as 127.0.0.1:8790")
        }
        guard !wanted.contains(where: { $0.key == id }) else { fail("\(id) is named twice") }
        wanted.append((id, address))
    }
    // Checked before the finger, so a typo costs no prompt.
    let index = try KeyIndex.load(from: keysFile)
    for (id, _) in wanted where !index.isTaken(id) { fail("no key is called \(id). `keyreeve list` shows them") }
    _ = try EnclaveRecipient.confirm(reason: FingerPrompt.local(wanted))
    try LocalServices.apply(
        Dictionary(wanted.map { ($0.key, $0.address) }, uniquingKeysWith: { a, _ in a }), keys: keysFile,
        approvals: localServicesFile)
    for (id, address) in wanted {
        try auditLog.append(event: "policy", key: id, detail: "local service \(address) approved")
        print("\(id) goes to \(address), over plain HTTP through the proxy, with a stand-in.")
    }
}

/// `verifier <id>`: the SHA-256 a server of yours keeps in place of the token, so it needs no secret to start.
/// One fingerprint, and only the hash leaves: never for a value short or plain enough to be found from it.
func printVerifier() throws {
    guard arguments.count == 2, !arguments[1].hasPrefix("-") else { fail(help, code: 2) }
    let id = arguments[1]
    let index = try KeyIndex.load(from: keysFile)
    guard let key = index.key(id) ?? index.unoffered.first(where: { $0.id == id }) else {
        fail("no key is called \(id). `keyreeve list` shows them")
    }
    let recipient = try EnclaveRecipient.load(blob: try store.loadBlob(), reason: FingerPrompt.verifier(key: id))
    let sealed = try store.load().open(name: key.source, with: recipient)
    let verifier = try ServerVerifier.verifier(of: try EnvReferences.value(in: sealed, field: key.field))
    try auditLog.append(event: "handed", key: id, detail: "SHA-256 for a server")
    print(verifier)
}
