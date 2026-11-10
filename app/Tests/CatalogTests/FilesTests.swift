import Foundation
import KeyreeveCatalog
import Testing

/// keyreeve's own JSON files: what a person wrote is never lost to a file that did not read.
struct FilesTests {
    func files() throws -> KeyreeveFiles {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("files-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return KeyreeveFiles(directory: folder)
    }

    @Test func aDamagedFileIsLeftWholeAndTheChangeRefused() throws {
        let files = try files()
        defer { try? FileManager.default.removeItem(at: files.directory) }
        let damaged = Data("{\"a.txt\": {\"name\": \"Mine\"".utf8)
        for url in [files.edits, files.places, files.ignored] { try damaged.write(to: url) }
        #expect(throws: CheckError.self) { try files.saveEdit(KeyEdit(name: "New"), for: "b.txt") }
        #expect(throws: CheckError.self) { try files.savePlaces(KeyPlaces(), for: "b.txt") }
        #expect(throws: CheckError.self) { try files.ignore("b.txt", until: Date()) }
        for url in [files.edits, files.places, files.ignored] { #expect(try Data(contentsOf: url) == damaged) }
    }

    @Test func aFileThatIsNotThereStartsEmpty() throws {
        let files = try files()
        defer { try? FileManager.default.removeItem(at: files.directory) }
        try files.saveEdit(KeyEdit(name: "Mine"), for: "a.txt")
        try files.saveEdit(KeyEdit(description: "Kept"), for: "a.txt")
        let read = try JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: files.edits))
        #expect(read["a.txt"]?.name == "Mine" && read["a.txt"]?.description == "Kept")
    }

    @Test func writersAtTheSameTimeKeepEveryChange() throws {
        let files = try files()
        defer { try? FileManager.default.removeItem(at: files.directory) }
        DispatchQueue.concurrentPerform(iterations: 50) { index in
            try? files.saveEdit(KeyEdit(name: "n\(index)"), for: "k\(index).txt")
        }
        let read = try JSONDecoder().decode([String: KeyEdit].self, from: Data(contentsOf: files.edits))
        #expect(read.count == 50)
    }
}

struct DeadlineTests {
    @Test func aCommandPastItsTimeIsEnded() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["30"]
        try process.run()
        let started = Date()
        CheckRunner.watch(process, seconds: 1)
        process.waitUntilExit()
        // Ended by the watch, well before sleep would have finished on its own. A busy CI machine can be
        // slow to deliver the signal, so this asks only that it was ended, not how fast.
        #expect(process.terminationReason == .uncaughtSignal)
        #expect(Date().timeIntervalSince(started) < 29)
    }
}
