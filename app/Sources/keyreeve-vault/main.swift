import Foundation
import KeyreeveVault

if let name = ProcessInfo.processInfo.environment[SSHCommand.askpassVariable] { askPassphrase(for: name) }
// Each value this command seals or opens leaves its keyed digest, so places compare with no fingerprint.
VaultEvents.observe(VaultEvents.recorder(store: store, file: home.appendingPathComponent(ValueDigests.fileName)))

do {
    switch arguments.first {
    case "init": try createVault()
    case "add": try addKey()
    case "put": try putKey()
    case "reseal": try resealKeys()
    case "drop": try dropTemporary()
    case "names": try listNames()
    case "orphans": try listOrphans()
    case "list": try listKeys()
    case "use": try useKey()
    case "get": try getKey()
    case "serve": try serveKeys()
    case "grant": try grantKey()
    case "grants": try showGrants()
    case "revoke": try revokeGrants()
    case "audit": try showAudit()
    case "log": try showTimeline()
    case "run": try runWithKey()
    case "env": try runWithEnv()
    case "mcp": try serveAgents()
    case "choose": try chooseFromService()
    case "export": try exportKey()
    case "check-recovery": try checkRecovery()
    case "recover": try recoverVault()
    case "backup": try backupVault()
    case "--help", "-h", "help": print(help)
    case nil: fail(help, code: 2)
    // `keyreeve` on the PATH is this program, and messages name commands of the CLI beside it, such as
    // `keyreeve recipes approve`. Those go to it rather than ending in this help.
    default: handToCLI()
    }
} catch let error as VaultError {
    fail(error.description)
} catch {
    // Errors from the system can mention the request, and they are no use to a person anyway.
    fail("the fingerprint was not accepted, or the Secure Enclave refused")
}
