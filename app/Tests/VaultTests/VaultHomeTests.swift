import Foundation
import Testing

@testable import KeyreeveVault

/// The vault follows KEYREEVE_HOME, so the app and keyreeve-vault open the same one.
struct VaultHomeTests {
    @Test func theVaultIsInsideKeyreeveHome() {
        let url = VaultStore.defaultDirectory(environment: ["KEYREEVE_HOME": "/tmp/demo-home/.keyreeve"])
        #expect(url.path == "/tmp/demo-home/.keyreeve/vault")
    }

    @Test func withoutItTheVaultIsInTheHomeFolder() {
        let home = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".keyreeve/vault")
        #expect(VaultStore.defaultDirectory(environment: [:]).path == home.path)
    }
}
