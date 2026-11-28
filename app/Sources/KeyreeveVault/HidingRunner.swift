import Foundation

/// Runs a command that holds a real value, with that value taken out of what it prints.
///
/// An agent reads what a command prints, and its transcript keeps it. So when stdout or stderr is not a terminal,
/// keyreeve stays as the command's parent and passes its output on through an `OutputRedactor`. A terminal gets the
/// output as it is, so programs that draw on it (an editor, a database shell) still work for the person at it.
public enum HidingRunner {
    /// The command, for `SIGTERM` to reach it. A signal handler cannot capture anything, so it lives here.
    nonisolated(unsafe) static var child: pid_t = 0

    /// Of stdout and stderr, the ones that are not a terminal, each written where it is now.
    public static func piped() -> [(stream: Int32, to: Int32)] {
        [STDOUT_FILENO, STDERR_FILENO].filter { isatty($0) == 0 }.map { ($0, $0) }
    }

    /// Starts the command as a child. Each of its `streams` goes through the redactor and on to `to`; the rest it
    /// shares with this process. Returns how it ended, as a shell says it: its exit status, or 128 plus the signal
    /// that stopped it, or 127 if it could not start.
    public static func spawn(
        _ command: [String], environment: [String: String]? = nil, redactor: OutputRedactor,
        streams: [(stream: Int32, to: Int32)], passSignals: Bool = true
    ) -> Int32 {
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        var readers: [(read: Int32, to: Int32)] = []
        // Kept open here until the child has them.
        var writeEnds: [Int32] = []
        for each in streams {
            var ends: [Int32] = [0, 0]
            guard pipe(&ends) == 0 else { return 127 }
            // Neither end goes to the command as it is: only the copy dup2 makes, which does not close on exec.
            _ = fcntl(ends[0], F_SETFD, FD_CLOEXEC)
            _ = fcntl(ends[1], F_SETFD, FD_CLOEXEC)
            posix_spawn_file_actions_adddup2(&actions, ends[1], each.stream)
            readers.append((ends[0], each.to))
            writeEnds.append(ends[1])
        }

        let argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        let envp: [UnsafeMutablePointer<CChar>?]? = environment.map { $0.map { strdup("\($0.key)=\($0.value)") } + [nil] }
        defer { envp?.forEach { free($0) } }

        if passSignals {
            // The terminal's Ctrl-C reaches the command on its own, being in the same group. A SIGTERM sent to
            // keyreeve is passed on, so stopping keyreeve stops the command.
            signal(SIGINT, SIG_IGN)
            signal(SIGHUP, SIG_IGN)
            signal(SIGTERM) { _ in if HidingRunner.child > 0 { kill(HidingRunner.child, SIGTERM) } }
        }

        var pid: pid_t = 0
        let started = argv.withUnsafeBufferPointer { args -> Int32 in
            let arguments = UnsafePointer(args.baseAddress!)
            if let envp {
                return envp.withUnsafeBufferPointer {
                    posix_spawnp(&pid, command[0], &actions, nil, UnsafeMutablePointer(mutating: arguments),
                                 UnsafeMutablePointer(mutating: $0.baseAddress!))
                }
            }
            return posix_spawnp(&pid, command[0], &actions, nil, UnsafeMutablePointer(mutating: arguments), environ)
        }
        writeEnds.forEach { close($0) }
        guard started == 0 else {
            readers.forEach { close($0.read) }
            FileHandle.standardError.write(Data("keyreeve: could not run \(command[0]): \(String(cString: strerror(started)))\n".utf8))
            return 127
        }
        child = pid

        let done = DispatchGroup()
        for reader in readers {
            done.enter()
            Thread {
                var each = redactor
                let out = FileHandle(fileDescriptor: reader.to, closeOnDealloc: false)
                var buffer = [UInt8](repeating: 0, count: 64 * 1024)
                while true {
                    let count = read(reader.read, &buffer, buffer.count)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { break }
                    let safe = each.feed(Data(buffer[0..<count]))
                    if !safe.isEmpty { try? out.write(contentsOf: safe) }
                }
                let rest = each.finish()
                if !rest.isEmpty { try? out.write(contentsOf: rest) }
                close(reader.read)
                done.leave()
            }.start()
        }

        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        child = 0
        // A program the command left running may keep the output open; what it prints later is not waited for.
        _ = done.wait(timeout: .now() + 2)
        let signalled = status & 0x7f
        return signalled == 0 ? (status >> 8) & 0xff : 128 + signalled
    }
}
