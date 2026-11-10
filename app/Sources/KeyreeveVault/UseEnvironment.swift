import Foundation

/// What a command started with a key gets: a stand-in and the proxy for an API key, or the signing socket
/// for an SSH key. The terminal's `use` and the agent server build it the same way.
public struct UseEnvironment: Equatable, Sendable {
    public var command: [String]
    public var set: [String: String] = [:]
    /// Set only when the person has not set them already.
    public var setIfMissing: [String: String] = [:]
    public var unset: [String] = []

    /// Tools that read a CA bundle from one of these.
    public static let bundleVariables = [
        "SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "AWS_CA_BUNDLE",
        "CARGO_HTTP_CAINFO", "DENO_CERT", "HTTPLIB2_CA_CERTS",
    ]

    /// A command with nothing added yet.
    public static func plain(command: [String]) -> UseEnvironment { UseEnvironment(command: command) }

    private init(command: [String]) { self.command = command }

    public init(answer: KeyService.Response, command: [String], variable: String?, real: Bool = false) throws {
        self.command = command
        if let socket = answer.sshSocket {
            set["SSH_AUTH_SOCK"] = socket
            if let identity = answer.sshIdentity {
                self.command = SSHCommand.arguments(for: command, socket: socket, identity: identity)
                for (name, value) in SSHCommand.variables(socket: socket, identity: identity) { setIfMissing[name] = value }
            }
            return
        }
        guard let variable else { throw VaultError("this key has no variable set, so say which") }
        if real {
            guard let value = answer.value else { throw VaultError("the key could not be used") }
            set[variable] = value
            return
        }
        guard let standIn = answer.standIn, let proxy = answer.proxy else { throw VaultError("the key could not be used") }
        set[variable] = standIn
        let address = "http://127.0.0.1:\(proxy.port)"
        set["HTTPS_PROXY"] = address
        set["https_proxy"] = address
        // Node does not read those variables unless it is told to.
        set["NODE_USE_ENV_PROXY"] = "1"
        set["NODE_EXTRA_CA_CERTS"] = proxy.ca
        // A name on this list would skip the proxy and go straight out with a useless stand-in.
        unset = ["NO_PROXY", "no_proxy"]
        for name in Self.bundleVariables { set[name] = proxy.bundle }
    }

    /// The environment a child gets, starting from `base`.
    public func applied(to base: [String: String]) -> [String: String] {
        var result = base
        for name in unset { result[name] = nil }
        for (name, value) in setIfMissing where result[name] == nil { result[name] = value }
        for (name, value) in set { result[name] = value }
        return result
    }
}
