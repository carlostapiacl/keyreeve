import Foundation
import KeyreeveCatalog
import Testing

/// The bridge to an AI the person runs in their terminal, tried with a script that stands in for it. One at a time:
/// one test stops every running assistant, and would end another's beside it.
@Suite(.serialized)
struct AssistantTests {
    func script(_ body: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("fake-ai-\(UUID().uuidString).sh")
        try ("#!/bin/sh\n" + body).write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }

    @Test func thePromptGoesInAndTheAnswerComesBack() throws {
        let fake = try script("echo \"got: $1\"")
        defer { try? FileManager.default.removeItem(at: fake) }
        let answer = try Assistants.ask(Assistant(id: "t", name: "T", command: [fake.path, "{prompt}"], readsFiles: true), "hello world")
        #expect(answer.trimmingCharacters(in: .newlines) == "got: hello world")
    }

    @Test func anAnswerInAFileIsRead() throws {
        let fake = try script("echo from-file > \"$2\"")
        defer { try? FileManager.default.removeItem(at: fake) }
        let answer = try Assistants.ask(Assistant(id: "t", name: "T", command: [fake.path, "{prompt}", "{out}"], readsFiles: true), "x")
        #expect(answer.trimmingCharacters(in: .newlines) == "from-file")
    }

    @Test func itRunsInAnEmptyFolderWithASmallEnvironment() throws {
        let fake = try script("ls -A | wc -l | tr -d ' '; env | cut -d= -f1 | sort | tr '\\n' ' '")
        defer { try? FileManager.default.removeItem(at: fake) }
        setenv("KEYREEVE_TEST_SECRET", "nope", 1)
        let answer = try Assistants.ask(Assistant(id: "t", name: "T", command: [fake.path, "{prompt}"], readsFiles: true), "x")
        let lines = answer.split(separator: "\n")
        #expect(lines.first == "0")
        #expect(!answer.contains("KEYREEVE_TEST_SECRET"))
        #expect(answer.contains("HOME") && answer.contains("PATH"))
    }

    @Test func aFailureOrSilenceIsAnError() throws {
        let failing = try script("echo 'not logged in' >&2; exit 1")
        let silent = try script("exit 0")
        defer {
            try? FileManager.default.removeItem(at: failing)
            try? FileManager.default.removeItem(at: silent)
        }
        #expect(throws: CheckError.self) { try Assistants.ask(Assistant(id: "t", name: "T", command: [failing.path, "{prompt}"], readsFiles: true), "x") }
        #expect(throws: CheckError.self) { try Assistants.ask(Assistant(id: "t", name: "T", command: [silent.path, "{prompt}"], readsFiles: true), "x") }
    }

    @Test func aCommandOfYourOwnNeedsAPlaceForTheWords() {
        #expect(Assistants.custom("mycli ask {prompt}")?.command == ["mycli", "ask", "{prompt}"])
        #expect(Assistants.custom("mycli ask") == nil)
        #expect(Assistants.custom("mycli {prompt}")?.readsFiles == true)
    }

    @Test func aFencedAnswerGivesItsYAML() {
        #expect(RecipeSpec.extractYAML("Here:\n```yaml\nschema: 1\nprovider: x\n```\nThanks") == "schema: 1\nprovider: x")
        #expect(RecipeSpec.extractYAML("schema: 1\n") == "schema: 1")
    }

    @Test func aProvidersIdIsReadOnlyWhenItIsSafe() {
        #expect(CheckRunner.providerID(in: "schema: 1\nprovider: my-panel\n") == "my-panel")
        #expect(CheckRunner.providerID(in: "provider: \"sentry\"") == "sentry")
        #expect(CheckRunner.providerID(in: "provider: ../etc") == nil)
        #expect(CheckRunner.providerID(in: "provider: Mayúscula") == nil)
    }

    @Test func stoppingEndsAnAssistantStillWorking() throws {
        let slow = try script("sleep 30; echo late")
        defer { try? FileManager.default.removeItem(at: slow) }
        let started = Date()
        let fast = try script("sleep 1; echo fine")
        defer { try? FileManager.default.removeItem(at: fast) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) { Assistants.stopAll(task: "stopped") }
        // Another window's assistant, working at the same time, is not stopped with it.
        final class Other: @unchecked Sendable { var answer: String? }
        let other = Other()
        let done = DispatchGroup()
        done.enter()
        DispatchQueue.global().async {
            other.answer = try? Assistants.ask(Assistant(id: "t", name: "T", command: [fast.path, "{prompt}"], readsFiles: true), "x", task: "kept")
            done.leave()
        }
        #expect(throws: CheckError.self) {
            try Assistants.ask(Assistant(id: "t", name: "T", command: [slow.path, "{prompt}"], readsFiles: true), "x", task: "stopped")
        }
        #expect(Date().timeIntervalSince(started) < 10)
        #expect(done.wait(timeout: .now() + 30) == .success, "the other assistant never answered")
        #expect(other.answer?.contains("fine") == true)
    }
}
