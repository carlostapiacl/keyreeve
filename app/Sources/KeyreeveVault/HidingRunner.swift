import Foundation

/// Runs a command that holds a real value, with that value taken out of what it prints.
///
/// An agent reads what a command prints, and its transcript keeps it. So when stdout or stderr is not a terminal,
/// keyreeve stays as the command's parent and passes its output on through an `OutputRedactor`. A terminal gets the
/// output as it is, so programs that draw on it (an editor, a database shell) still work for the person at it.
///
/// The command starts with every signal as the system leaves it, whatever keyreeve ignores, so Ctrl-C, a closed
/// terminal and a closed pipe stop it as they would without keyreeve in between.
public enum HidingRunner {
    /// The command, for `SIGTERM` to reach it. A signal handler cannot capture anything, so it lives here.
    nonisolated(unsafe) static var child: pid_t = 0

    /// After the command ends, how long its output may still come from a program it left running. Then what is held
    /// back is passed on and the pipes close; such a program gets a broken pipe if it prints again.
    public static let grace: TimeInterval = 2

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

        // An ignored signal stays ignored across exec, and a blocked one blocked: the child gets them all back.
        var attributes: posix_spawnattr_t?
        posix_spawnattr_init(&attributes)
        defer { posix_spawnattr_destroy(&attributes) }
        var defaults = sigset_t()
        sigemptyset(&defaults)
        for each in [SIGINT, SIGHUP, SIGTERM, SIGPIPE, SIGQUIT] { sigaddset(&defaults, each) }
        posix_spawnattr_setsigdefault(&attributes, &defaults)
        var none = sigset_t()
        sigemptyset(&none)
        posix_spawnattr_setsigmask(&attributes, &none)
        posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK))

        let argv: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        let envp: [UnsafeMutablePointer<CChar>?]? = environment.map { $0.map { strdup("\($0.key)=\($0.value)") } + [nil] }
        defer { envp?.forEach { free($0) } }

        // A reader gone (`| head`) is a failed write here, not the end of keyreeve: the file of a key is still to go.
        signal(SIGPIPE, SIG_IGN)
        var term = sigset_t()
        sigemptyset(&term)
        sigaddset(&term, SIGTERM)
        if passSignals {
            // The terminal's Ctrl-C reaches the command on its own, being in the same group. A SIGTERM sent to
            // keyreeve is passed on, so stopping keyreeve stops the command. It waits, blocked, until the command
            // is known, so one that comes while it starts is not lost.
            signal(SIGINT, SIG_IGN)
            signal(SIGHUP, SIG_IGN)
            signal(SIGTERM) { _ in if HidingRunner.child > 0 { kill(HidingRunner.child, SIGTERM) } }
            pthread_sigmask(SIG_BLOCK, &term, nil)
        }

        var pid: pid_t = 0
        let started = argv.withUnsafeBufferPointer { args -> Int32 in
            let arguments = UnsafePointer(args.baseAddress!)
            if let envp {
                return envp.withUnsafeBufferPointer {
                    posix_spawnp(&pid, command[0], &actions, &attributes, UnsafeMutablePointer(mutating: arguments),
                                 UnsafeMutablePointer(mutating: $0.baseAddress!))
                }
            }
            return posix_spawnp(&pid, command[0], &actions, &attributes, UnsafeMutablePointer(mutating: arguments), environ)
        }
        writeEnds.forEach { close($0) }
        if started == 0 { child = pid }
        if passSignals { pthread_sigmask(SIG_UNBLOCK, &term, nil) }
        guard started == 0 else {
            readers.forEach { close($0.read) }
            FileHandle.standardError.write(Data("keyreeve: could not run \(command[0]): \(String(cString: strerror(started)))\n".utf8))
            return 127
        }

        let ended = Ended()
        let done = DispatchGroup()
        for reader in readers {
            done.enter()
            Thread {
                pass(reader.read, to: reader.to, through: redactor, until: ended)
                done.leave()
            }.start()
        }

        var status: Int32 = 0
        while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        child = 0
        ended.set(Date().addingTimeInterval(grace))
        _ = done.wait(timeout: .now() + grace + 1)
        let signalled = status & 0x7f
        return signalled == 0 ? (status >> 8) & 0xff : 128 + signalled
    }

    /// When the command ended, plus the grace, once it has.
    final class Ended: @unchecked Sendable {
        private let lock = NSLock()
        private var deadline: Date?
        func set(_ date: Date) { lock.withLock { deadline = date } }
        var passed: Bool { lock.withLock { deadline.map { Date() >= $0 } ?? false } }
    }

    /// Reads one stream to its end, or until the grace after the command is over, taking the value out as it goes.
    /// What the redactor held back is passed on in both cases. If nobody reads what it passes on, it stops and closes
    /// the pipe, so the command gets the broken pipe it would get without keyreeve.
    static func pass(_ fd: Int32, to out: Int32, through redactor: OutputRedactor, until ended: Ended) {
        var each = redactor
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        var listening = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        var open = true
        while true {
            let ready = poll(&listening, 1, 200)
            if ready < 0 {
                if errno == EINTR { continue }
                break
            }
            if ready == 0 {
                if ended.passed { break }
                continue
            }
            let count = read(fd, &buffer, buffer.count)
            if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            guard count > 0 else { break }
            open = write(each.feed(Data(buffer[0..<count])), to: out)
            if !open { break }
        }
        if open { _ = write(each.finish(), to: out) }
        close(fd)
    }

    /// Writes it all, or says it could not.
    static func write(_ data: Data, to fd: Int32) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return true }
            var offset = 0
            while offset < raw.count {
                let written = Darwin.write(fd, base + offset, raw.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                offset += written
            }
            return true
        }
    }
}
