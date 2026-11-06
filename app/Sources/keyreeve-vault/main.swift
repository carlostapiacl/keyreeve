import Foundation
import KeyreeveVault

if let name = ProcessInfo.processInfo.environment[SSHCommand.askpassVariable] { askPassphrase(for: name) }

do {
    switch arguments.first {
    case "init": try createVault()
    case "add": try addKey()
    case "put": try putKey()
    case "drop": try dropTemporary()
    case "names": try listNames()
    case "list": try listKeys()
    case "use": try useKey()
    case "serve": try serveKeys()
    case "grant": try grantKey()
    case "grants": try showGrants()
    case "revoke": try revokeGrants()
    case "audit": try showAudit()
    case "run": try runWithKey()
    case "env": try runWithEnv()
    case "mcp": try serveAgents()
    case "export": try exportKey()
    case "check-recovery": try checkRecovery()
    case "recover": try recoverVault()
    case "--help", "-h", "help": print(help)
    default: fail(help, code: 2)
    }
} catch let error as VaultError {
    fail(error.description)
} catch {
    // Errors from the system can mention the request, and they are no use to a person anyway.
    fail("the fingerprint was not accepted, or the Secure Enclave refused")
}
