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
    public static func run(_ environment: UseEnvironment, keep extra: Int = 0, limit: TimeInterval = limit) throws -> AgentBridge.Output {
        let command = environment.command
        let process = Process()
        let pipe = Pipe()
        // A program started later must not inherit this, or the output would never end.
        _ = fcntl(pipe.fileHandleForReading.fileDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(pipe.fileHandleForWriting.fileDescriptor, F_SETFD, FD_CLOEXEC)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = command
        process.environment = environment.applied(to: ProcessInfo.processInfo.environment)
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = pipe
        // Told when it ends. waitUntilExit polls a run loop and added tens of milliseconds to each command.
        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }
        try process.run()

        // Room past the cap, so a key that starts before the cap arrives whole and can be hidden.
        let keep = maxOutput + extra * 2 + 16
        let collected = Collected()
        let reader = DispatchGroup()
        reader.enter()
        let handle = pipe.fileHandleForReading
        // On a thread of its own, which may stay blocked until a stubborn child lets go of the pipe.
        Thread.detachNewThread {
            while true {
                let chunk = handle.availableData
                if chunk.isEmpty { break }
                collected.add(chunk, keeping: keep)
            }
            reader.leave()
        }
        // A program can ignore being asked to stop, or leave a child holding the output open. Neither
        // may hold the server, which has one request at a time.
        // One deadline for both: a program can close its output and stay alive, and the end of the output
        // says nothing about the end of the program.
        let deadline = DispatchTime.now() + limit
        let finished = reader.wait(timeout: deadline) == .success && exited.wait(timeout: deadline) == .success
        if !finished, process.isRunning {
            process.terminate()
            if exited.wait(timeout: .now() + 1) == .timedOut, process.isRunning { kill(process.processIdentifier, SIGKILL) }
        }
        let status: Int32 = finished ? process.terminationStatus : -1
        return AgentBridge.Output(status: status, text: String(decoding: collected.data, as: UTF8.self))
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
