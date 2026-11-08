import Foundation

/// Runs a program for an agent, with a time limit and a cap on what comes back.
public enum AgentRunner {
    public static let limit: TimeInterval = 120
    public static let maxOutput = 64 * 1024

    public static func run(
        _ command: [String], variable: String, value: String, limit: TimeInterval = limit
    ) throws -> AgentBridge.Output {
        var environment = UseEnvironment.plain(command: command)
        environment.set[variable] = value
        return try run(environment, keep: value.utf8.count, limit: limit)
    }

    /// Runs a command prepared by the key service: a stand-in and the proxy, or an SSH socket.
    ///
    /// The command starts in a process group of its own, and the whole group ends with the run: on the
    /// deadline, and once the command is done, so nothing it started in the background stays alive
    /// holding the key or its stand-in.
    public static func run(_ environment: UseEnvironment, keep extra: Int = 0, limit: TimeInterval = limit) throws -> AgentBridge.Output {
        let command = environment.command
        var pipe: [Int32] = [0, 0]
        guard Darwin.pipe(&pipe) == 0 else { throw VaultError("the command could not be started") }
        let (readEnd, writeEnd) = (pipe[0], pipe[1])

        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_adddup2(&actions, writeEnd, 1)
        posix_spawn_file_actions_adddup2(&actions, writeEnd, 2)
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        // A group of its own, and no descriptor of this process but the three given.
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT))
        posix_spawnattr_setpgroup(&attributes, 0)

        let arguments = ["/usr/bin/env"] + command
        let variables = environment.applied(to: ProcessInfo.processInfo.environment).map { "\($0.key)=\($0.value)" }
        var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) } + [nil]
        var envp: [UnsafeMutablePointer<CChar>?] = variables.map { strdup($0) } + [nil]
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }
        var pid: pid_t = 0
        let started = posix_spawn(&pid, "/usr/bin/env", &actions, &attributes, &argv, &envp)
        close(writeEnd)
        guard started == 0 else {
            close(readEnd)
            throw VaultError("the command could not be started")
        }

        // Room past the cap, so a key that starts before the cap arrives whole and can be hidden.
        let keep = maxOutput + extra * 2 + 16
        let collected = Collected()
        let reader = DispatchGroup()
        reader.enter()
        // On a thread of its own, which may stay blocked until a stubborn child lets go of the pipe.
        Thread.detachNewThread {
            var buffer = [UInt8](repeating: 0, count: 16 * 1024)
            while true {
                let count = read(readEnd, &buffer, buffer.count)
                if count <= 0 { break }
                collected.add(Data(buffer[0..<count]), keeping: keep)
            }
            close(readEnd)
            reader.leave()
        }
        let exited = DispatchSemaphore(value: 0)
        final class Status: @unchecked Sendable { var value: Int32 = 0 }
        let status = Status()
        Thread.detachNewThread {
            var raw: Int32 = 0
            while waitpid(pid, &raw, 0) == -1 && errno == EINTR {}
            status.value = raw
            exited.signal()
        }
        // One deadline for both: a program can close its output and stay alive, and the end of the output
        // says nothing about the end of the program.
        let deadline = DispatchTime.now() + limit
        let finished = exited.wait(timeout: deadline) == .success
        if !finished {
            kill(-pid, SIGTERM)
            if exited.wait(timeout: .now() + 1) == .timedOut {
                kill(-pid, SIGKILL)
                _ = exited.wait(timeout: .now() + 1)
            }
        }
        // Whatever the command left running ends with it, and so the output can end too.
        kill(-pid, SIGKILL)
        _ = reader.wait(timeout: .now() + 2)
        let raw = status.value
        let code: Int32 = finished && (raw & 0x7f) == 0 ? (raw >> 8) & 0xff : -1
        return AgentBridge.Output(status: code, text: String(decoding: collected.data, as: UTF8.self))
    }

    private final class Collected: @unchecked Sendable {
        private let lock = NSLock()
        private var bytes = Data()

        func add(_ chunk: Data, keeping limit: Int) {
            lock.lock()
            defer { lock.unlock() }
            if bytes.count < limit { bytes += chunk.prefix(limit - bytes.count) }
        }

        var data: Data {
            lock.lock()
            defer { lock.unlock() }
            return bytes
        }
    }
}
