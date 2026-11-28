import Foundation
import KeyreeveVault
import Testing

struct OutputRedactorTests {
    /// A pipe whose ends no command inherits, so a program one test leaves running cannot hold another test's open.
    static func pipe() -> Pipe {
        let pipe = Pipe()
        for handle in [pipe.fileHandleForReading, pipe.fileHandleForWriting] {
            _ = fcntl(handle.fileDescriptor, F_SETFD, FD_CLOEXEC)
        }
        return pipe
    }

    static let secret = "sk-CANARY/value+0123456789=="

    @Test func takesOutTheValueAsItIsAndAsProgramsEncodeIt() {
        let base64 = Data(Self.secret.utf8).base64EncodedString()
        let url = Self.secret.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let json = Self.secret.replacingOccurrences(of: "/", with: "\\/")
        let text = "a \(Self.secret) b \(base64) c \(url) d \(json) e"
        let out = OutputRedactor.redact(text, secrets: [Self.secret])
        #expect(out == "a [redacted] b [redacted] c [redacted] d [redacted] e")
    }

    @Test func aValueSplitAcrossReadsIsStillTakenOut() {
        var redactor = OutputRedactor(secrets: [Self.secret])
        var out = Data()
        for byte in Data("before \(Self.secret) after\n".utf8) { out += redactor.feed(Data([byte])) }
        out += redactor.finish()
        #expect(String(decoding: out, as: UTF8.self) == "before [redacted] after\n")
    }

    @Test func aValueSealedWithItsLineBreakIsFoundWithout() {
        let out = OutputRedactor.redact("token=\(Self.secret)\n", secrets: [Self.secret + "\n"])
        #expect(out == "token=[redacted]\n")
    }

    @Test func nothingToHideLeavesTheOutputAlone() {
        #expect(OutputRedactor(secrets: [String]()).isEmpty)
        // Too short to tell from an ordinary word.
        #expect(OutputRedactor.redact("abc abc", secrets: ["abc"]) == "abc abc")
    }

    @Test func aCommandThatPrintsTheKeyShowsItRedacted() throws {
        let out = Self.pipe(), err = Self.pipe()
        var environment = ProcessInfo.processInfo.environment
        environment["THE_KEY"] = Self.secret
        let status = HidingRunner.spawn(
            ["/bin/sh", "-c", "echo \"out $THE_KEY\"; printf %s \"$THE_KEY\" | base64; echo \"err $THE_KEY\" >&2; exit 3"],
            environment: environment, redactor: OutputRedactor(secrets: [Self.secret]),
            streams: [(STDOUT_FILENO, out.fileHandleForWriting.fileDescriptor),
                      (STDERR_FILENO, err.fileHandleForWriting.fileDescriptor)],
            passSignals: false)
        try out.fileHandleForWriting.close()
        try err.fileHandleForWriting.close()
        let printed = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let warned = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(status == 3)
        #expect(printed == "out [redacted]\n[redacted]\n")
        #expect(warned == "err [redacted]\n")
        #expect(!printed.contains("CANARY") && !warned.contains("CANARY"))
    }

    @Test func aCommandThatCannotStartSaysSo() {
        let status = HidingRunner.spawn(
            ["/nonexistent/program"], redactor: OutputRedactor(secrets: [Self.secret]), streams: [], passSignals: false)
        #expect(status == 127)
    }

    @Test func aKeyOnSeveralLinesIsTakenOutAsJSONPrintsItAndLineByLine() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----\n"
        let json = #"{"key": "\#(pem.replacingOccurrences(of: "\n", with: "\\n"))"}"#
        // The key is found without its last line break; the escaped break left after it gives nothing away.
        #expect(OutputRedactor.redact(json, secrets: [pem]) == #"{"key": "[redacted]\n"}"#)
        let line = OutputRedactor.redact("got MIIEvQIBADANBgkqhkiG9w0BAQEFAASC from it", secrets: [pem])
        #expect(line == "got [redacted] from it")
        // The header says what it is, not what it holds.
        #expect(OutputRedactor.redact("-----BEGIN PRIVATE KEY-----", secrets: [pem]) == "-----BEGIN PRIVATE KEY-----")
    }

    @Test func oneFieldOfAFileAndOneValueOfAnEnvAreTakenOut() {
        let file = #"{"type": "service_account", "private_key": "pk-0123456789abcdefXYZ", "token_uri": "https://oauth2.example.com/token"}"#
        let out = OutputRedactor.redact("pk-0123456789abcdefXYZ and https://oauth2.example.com/token", secrets: [file])
        #expect(out == "[redacted] and https://oauth2.example.com/token")
        let env = "API_TOKEN=\"tok_live_0123456789abcdef\"\nDEBUG=1\n"
        #expect(OutputRedactor.redact("tok_live_0123456789abcdef", secrets: [env]) == "[redacted]")
    }

    @Test func theCommandGetsBackTheSignalsKeyreeveIgnores() {
        // As keyreeve leaves them while the command runs. A shell started with SIGINT ignored could not undo it.
        signal(SIGINT, SIG_IGN)
        defer { signal(SIGINT, SIG_DFL) }
        let status = HidingRunner.spawn(
            ["/bin/sh", "-c", "kill -INT $$; exit 0"], redactor: OutputRedactor(secrets: [Self.secret]), streams: [],
            passSignals: false)
        #expect(status == 128 + SIGINT)
    }

    @Test func aReaderThatGoesAwayStopsTheCommandAndNotKeyreeve() throws {
        let out = Self.pipe()
        try out.fileHandleForReading.close()
        let status = HidingRunner.spawn(
            ["/usr/bin/yes"], redactor: OutputRedactor(secrets: [Self.secret]),
            streams: [(STDOUT_FILENO, out.fileHandleForWriting.fileDescriptor)], passSignals: false)
        #expect(status == 128 + SIGPIPE)
    }

    @Test func whatIsHeldBackComesOutEvenIfTheCommandLeftAProgramRunning() throws {
        let out = Self.pipe()
        let start = Date()
        let status = HidingRunner.spawn(
            ["/bin/sh", "-c", "sleep 6 & printf done"], redactor: OutputRedactor(secrets: [Self.secret]),
            streams: [(STDOUT_FILENO, out.fileHandleForWriting.fileDescriptor)], passSignals: false)
        try out.fileHandleForWriting.close()
        #expect(status == 0)
        #expect(Date().timeIntervalSince(start) < 5)
        #expect(String(decoding: out.fileHandleForReading.availableData, as: UTF8.self) == "done")
    }
}
