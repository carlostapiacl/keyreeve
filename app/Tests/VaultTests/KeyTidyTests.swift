import Foundation
@testable import KeyreeveVault
import Testing

struct KeyTidyTests {
    static func index() -> KeyIndex {
        var index = KeyIndex()
        index.keys = [
            KeyIndex.Key(id: "resend-acme", source: "resend-acme.txt", provider: "resend", project: "acme-labs"),
            KeyIndex.Key(id: "mykey", source: "mykey.txt", provider: "resend"),
            KeyIndex.Key(id: "shop-jwt", source: "jwt.txt", project: "shop", description: "JWT del backend"),
        ]
        index.unoffered = [KeyIndex.Key(id: "hidden-one", source: "hidden.txt")]
        return index
    }

    static let visible: Set<String> = ["resend-acme", "mykey", "shop-jwt"]

    func check(_ changes: [[String: Any]], usage: [String: KeyTidy.Use] = [:]) -> (accepted: [KeyTidy.Change], refused: [String]) {
        KeyTidy.check(changes, index: Self.index(), providers: ["resend", "meta"], visible: Self.visible, usage: usage)
    }

    @Test func aRenameThatFollowsTheConventionIsAccepted() {
        let result = check([["key": "mykey", "id": "resend-globex", "project": "globex", "why": "read globex/.env: RESEND_API_KEY"]])
        #expect(result.refused.isEmpty)
        #expect(result.accepted.first?.id == "resend-globex")
    }

    @Test func whatBreaksTheConventionComesBackWithTheReason() {
        let result = check([
            ["key": "mykey", "id": "my-resend", "why": "looks nicer this way"],
            ["key": "resend-acme", "id": "shop-jwt", "why": "taken on purpose here"],
            ["key": "shop-jwt", "description": "token=abcdef1234567890 for the api", "why": "copied from the file"],
            ["key": "hidden-one", "description": "x", "why": "not visible to this agent"],
        ])
        #expect(result.accepted.isEmpty)
        #expect(result.refused.count == 4)
        #expect(result.refused[0].contains("my-resend: start it with resend-"))
        #expect(result.refused[1].contains("already taken"))
        #expect(result.refused[2].contains("never the value"))
        #expect(result.refused[3].contains("no key you can see"))
    }

    @Test func aShortStartThePersonAlreadyUsesForAProjectCounts() {
        var index = Self.index()
        for name in ["acme-a", "acme-b", "acme-c"] {
            index.keys.append(KeyIndex.Key(id: name, source: "\(name).txt", project: "acme-labs"))
        }
        let result = KeyTidy.check(
            [["key": "resend-acme", "id": "acme-mail", "provider": "resend", "why": "the Acme mail key, read acme/.env"]],
            index: index, providers: ["resend"], visible: Self.visible, usage: [:])
        #expect(result.refused.isEmpty)
        #expect(KeyTidy.projectPrefixes(index)["acme-labs"] == ["acme"])
    }

    @Test func aKeyUsedLatelyIsNotArchived() {
        var use = KeyTidy.Use()
        use.last = Date().addingTimeInterval(-3 * 86400)
        use.agents = ["claude"]
        let result = check([["key": "mykey", "archive": true, "why": "looks unused to me"]], usage: ["mykey": use])
        #expect(result.accepted.isEmpty)
        #expect(result.refused.first?.contains("not dead") == true)
    }

    @Test func aWhyIsNeededAndAnUnknownProviderIsRefused() {
        let result = check([
            ["key": "mykey", "description": "Resend de HZ"],
            ["key": "shop-jwt", "provider": "madeup", "why": "guessed from the name"],
        ])
        #expect(result.accepted.isEmpty)
        #expect(result.refused.count == 2)
    }

    @Test func aRenamedKeyKeepsItsOldNameWorking() throws {
        var index = Self.index()
        let change = KeyTidy.Change(key: "mykey", id: "resend-globex", why: "read globex/.env")
        let result = KeyTidy.apply([change], to: &index)
        #expect(result.renamed.first! == ("mykey", "resend-globex"))
        #expect(index.key("mykey")?.id == "resend-globex")
        #expect(index.current("mykey") == "resend-globex")
        #expect(index.isTaken("mykey"))
        // Written and read back, the old name is still there.
        let again = try KeyIndex.parse(index.toml)
        #expect(again.key("mykey")?.id == "resend-globex")
        #expect(again.key("resend-globex")?.more.formerly == ["mykey"])
    }

    @Test func applyingInFilesMovesPermissionsAndPlacesAndKeepsACopy() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("tidy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try PrivateFile.write(Data(Self.index().toml.utf8), to: home.appendingPathComponent(KeyIndex.fileName))
        _ = try AgentPolicy.update(at: home.appendingPathComponent(AgentPolicy.fileName)) {
            $0.levels["mykey"] = .always
            $0.agents["mykey"] = ["mesa"]
        }
        try PlaceBook.update(at: PlaceBook.file(home: home)) {
            $0.places.append(PlaceBook.Place(id: "p-1", key: "mykey", procedure: "ssh-env", params: [:], label: "VPS1"))
        }
        try KeySets.update(at: home.appendingPathComponent(KeySets.fileName)) {
            $0.sets.append(KeySets.Set(name: "hz", keys: ["mykey", "resend-acme"]))
            $0.standing.append(KeySets.Standing(keys: ["mykey"], program: "/usr/bin/env", hash: "h", folder: "/tmp", since: Date()))
        }
        try LocalServices.approve(key: "mykey", address: "127.0.0.1:8790", at: home.appendingPathComponent(LocalServices.fileName))
        let result = try KeyTidy.apply(
            [KeyTidy.Change(key: "mykey", id: "resend-globex", description: "Resend de HZ", why: "read globex/.env")],
            home: home, stamp: "t1")
        #expect(result.done.count == 1 && result.skipped.isEmpty)
        let policy = AgentPolicy.load(from: home.appendingPathComponent(AgentPolicy.fileName))
        #expect(policy.levels["resend-globex"] == .always && policy.levels["mykey"] == nil)
        #expect(policy.agents["resend-globex"] == ["mesa"])
        #expect(PlaceBook.load(from: PlaceBook.file(home: home)).places.first?.key == "resend-globex")
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent("keys.toml.antes-tidy-t1").path))
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent("agents.toml.antes-tidy-t1").path))
        let index = try KeyIndex.load(from: home.appendingPathComponent(KeyIndex.fileName))
        #expect(index.key("mykey")?.description == "Resend de HZ")
        // A standing permission, a set and a local service follow the key, so nothing asks again for a finger.
        let sets = KeySets.load(from: home.appendingPathComponent(KeySets.fileName))
        #expect(sets.set("hz")?.keys == ["resend-globex", "resend-acme"])
        #expect(sets.standing.first?.keys == ["resend-globex"])
        #expect(LocalServices.load(from: home.appendingPathComponent(LocalServices.fileName)).approved == ["resend-globex": "127.0.0.1:8790"])
    }

    @Test func aSecondApplyInTheSameSecondKeepsTheFirstCopy() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("tidy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let keys = home.appendingPathComponent(KeyIndex.fileName)
        try PrivateFile.write(Data(Self.index().toml.utf8), to: keys)
        let first = try Data(contentsOf: keys)
        try KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-globex", why: "read globex/.env")], home: home, stamp: "t1")
        try KeyTidy.apply([KeyTidy.Change(key: "resend-globex", description: "HZ", why: "read globex/.env")], home: home, stamp: "t1")
        #expect(try Data(contentsOf: home.appendingPathComponent("keys.toml.antes-tidy-t1")) == first)
    }

    @Test func aKeyIsNotArchivedWhenTheLogIsTooShortToTell() {
        let now = Date()
        let short = KeyTidy.check(
            [["key": "mykey", "archive": true, "why": "nothing in the log uses it"]], index: Self.index(),
            providers: ["resend"], visible: Self.visible, usage: [:], logSince: now.addingTimeInterval(-3 * 86400), now: now)
        #expect(short.accepted.isEmpty)
        #expect(short.refused.first?.contains("under 30 days") == true)
        let long = KeyTidy.check(
            [["key": "mykey", "archive": true, "why": "nothing in the log uses it"]], index: Self.index(),
            providers: ["resend"], visible: Self.visible, usage: [:], logSince: now.addingTimeInterval(-40 * 86400), now: now)
        #expect(long.accepted.count == 1)
    }

    @Test func aKeyMayTakeBackAnOldNameOfItsOwn() {
        var index = Self.index()
        KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-globex", why: "read globex/.env")], to: &index)
        let back = KeyTidy.apply([KeyTidy.Change(key: "resend-globex", id: "mykey", why: "the old name was right")], to: &index)
        #expect(back.skipped.isEmpty)
        #expect(index.has("mykey") && index.key("mykey")?.more.formerly == ["resend-globex"])
    }

    @Test func anOldNameIsTakenButIsNoKey() {
        var index = Self.index()
        KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-globex", why: "read globex/.env")], to: &index)
        #expect(index.isTaken("mykey"))
        #expect(!index.has("mykey") && index.has("resend-globex"))
    }

    @Test func aReviewWithoutAllNamesNoProjectOfAKeyNotOffered() throws {
        var index = Self.index()
        for name in ["zz-a", "zz-b", "zz-c"] {
            index.unoffered.append(KeyIndex.Key(id: name, source: "\(name).txt", project: "secret-project"))
        }
        var bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { [] }, open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            describe: { index.agentDescriptions }, inventory: { Data("[]".utf8) })
        bridge.tidyContext = { KeyTidy.Context(index: index, entries: [], digests: ValueDigests()) }
        let review = try AgentTests().call(bridge, "review_keys", ["only": "all"])
        #expect(!review.text.contains("secret-project") && !review.text.contains("zz-"))
    }

    @Test func whatChangedSinceTheProposalIsLeftOutAndSaidSo() {
        var index = Self.index()
        // Since the proposal, another key took the new id, and the key to archive was used.
        index.keys.append(KeyIndex.Key(id: "resend-globex", source: "other.txt", provider: "resend"))
        var use = KeyTidy.Use()
        use.last = Date().addingTimeInterval(-600)
        let result = KeyTidy.apply([
            KeyTidy.Change(key: "mykey", id: "resend-globex", description: "Resend de HZ", why: "read globex/.env"),
            KeyTidy.Change(key: "shop-jwt", archive: true, why: "looked dead at proposal time"),
            KeyTidy.Change(key: "gone-key", description: "x", why: "was there at proposal time"),
        ], to: &index, usage: ["shop-jwt": use])
        #expect(result.done.isEmpty)
        #expect(result.skipped.count == 3)
        #expect(result.skipped[0].contains("was taken since"))
        #expect(result.skipped[1].contains("not archived"))
        #expect(result.skipped[2].contains("gone"))
        // Nothing half applied: the description that came with the refused rename is not written either.
        #expect(index.key("mykey")?.description == nil)
        #expect(index.key("shop-jwt")?.more.archived == false)
    }

    @Test func theDifferencesAreWhatTheCardAndTheLogSay() {
        let before = KeyIndex.Key(id: "mykey", source: "m.txt", provider: "resend")
        let change = KeyTidy.Change(key: "mykey", id: "resend-globex", provider: "resend", tags: ["hz"], archive: true, why: "read globex/.env")
        #expect(change.differences(from: before).map(\.field) == ["id", "tags"])
        #expect(change.summary(from: before) == "id: mykey → resend-globex; tags + hz; archive")
    }

    @Test func tidyingWaitsForTheSwitchThatLetsAgentsSort() throws {
        let index = Self.index()
        var bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { [] }, open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            describe: { index.agentDescriptions })
        bridge.tidyContext = { KeyTidy.Context(index: index, entries: [], digests: ValueDigests()) }
        let review = try AgentTests().call(bridge, "review_keys", [:])
        #expect(review.error)
        #expect(review.text.contains("Agents can sort my keys"))
    }

    @Test func theServiceTakesAnOldNameAsTheNewOne() throws {
        var index = Self.index()
        KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-globex", why: "read globex/.env")], to: &index)
        #expect(index.current("mykey") == "resend-globex")
        #expect(index.current("resend-globex") == "resend-globex")
        #expect(index.current("unknown") == "unknown")
    }

    @Test func anAgentReviewsAndProposesThroughTheTools() throws {
        final class Kept: @unchecked Sendable {
            var saved: Data?
            var requests: [AccessRequests.Entry] = []
        }
        let kept = Kept()
        let index = Self.index()
        var bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { [] }, open: { _, _ in Data() },
            run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude",
            describe: { index.agentDescriptions },
            offered: { ["resend"] },
            requests: { kept.requests },
            addRequest: { kept.requests.append($0) },
            inventory: { Data("[]".utf8) })
        bridge.tidyContext = { KeyTidy.Context(index: index, entries: [], digests: ValueDigests()) }
        bridge.saveTidy = { _, data in kept.saved = data }
        let review = try AgentTests().call(bridge, "review_keys", [:])
        #expect(!review.error)
        #expect(review.text.contains("How keys are named"))
        #expect(review.text.contains("mykey"))
        #expect(!review.text.contains("hidden-one"))
        let proposed = try AgentTests().call(bridge, "propose_tidy", [
            "reason": "name keys by provider",
            "changes": [
                ["key": "mykey", "id": "resend-globex", "why": "read globex/.env: RESEND_API_KEY"],
                ["key": "resend-acme", "id": "acme-mail", "why": "shorter to type"],
            ],
        ])
        #expect(!proposed.error)
        #expect(proposed.text.contains("1 changes wait"))
        #expect(proposed.text.contains("resend-acme → acme-mail"))
        #expect(kept.requests.first?.kind == KeyTidy.requestKind)
        let saved = try JSONDecoder().decode([KeyTidy.Change].self, from: try #require(kept.saved))
        #expect(saved.map(\.key) == ["mykey"])
    }

    @Test func aWhyMayCiteAPathOrAVariableButNotAValue() {
        #expect(!KeyTidy.looksLikeValue("read sales/desk/cmd/desk/card.go: --as PID_HMAC_CLAVE"))
        #expect(!KeyTidy.looksLikeValue("keyreeve use google --as GOOGLE_APPLICATION_CREDENTIALS"))
        #expect(!KeyTidy.looksLikeValue("read 03-automatizacion-claude/herramientas/gsc"))
        #expect(KeyTidy.looksLikeValue("token sk-proj-Ab3dEf9hIjKlMn0pQrStUvWxYz12"))
        #expect(KeyTidy.looksLikeValue("a3f9c2e8b1d04f6a9e7c5b3d1f0a2c4e6b8d0f1a"))
        #expect(KeyTidy.looksLikeValue("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"))
    }
}
