import Foundation
import KeyreeveCatalog
import Testing

struct HistoryTests {
    @Test func theLastCheckOfEachKeyIsRead() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("history-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let files = KeyreeveFiles(directory: root)
        try """
            {"at":1794100000,"file":"added/bot","recipe":"telegram","result":"rejected"}
            not json
            {"at":1794120000,"file":"added/bot","recipe":"telegram","result":"works"}
            {"at":1794120000,"file":"other.txt","recipe":"github","result":"works"}
            """.write(to: files.history, atomically: true, encoding: .utf8)
        let found = files.lastResults(for: ["added/bot"])
        #expect(found.count == 1 && found["added/bot"]?.result == "works" && found["added/bot"]?.day == "2026-11-08")
    }
}
