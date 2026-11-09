import Foundation
import KeyreeveCatalog
import Testing

/// KEYREEVE_HOME moves keyreeve's files, in the app as in the command line, so a second Keyreeve can run apart.
struct HomeTests {
    @Test func keyreeveHomeSetsTheFolder() {
        let url = KeyreeveFiles.defaultDirectory(environment: ["KEYREEVE_HOME": "/tmp/demo-home/.keyreeve"])
        #expect(url.path == "/tmp/demo-home/.keyreeve")
    }

    @Test func withoutItTheFolderIsInTheHomeFolder() {
        let home = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keyreeve")
        #expect(KeyreeveFiles.defaultDirectory(environment: [:]).path == home.path)
        #expect(KeyreeveFiles.defaultDirectory(environment: ["KEYREEVE_HOME": ""]).path == home.path)
    }
}
