import Foundation
import KeyreeveVault
import Testing

struct OutputRedactorTests {
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
        let out = Pipe(), err = Pipe()
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
}
