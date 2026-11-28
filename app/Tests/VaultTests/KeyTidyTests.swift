import Foundation
import KeyreeveVault
import Testing

struct KeyTidyTests {
    static func index() -> KeyIndex {
        var index = KeyIndex()
        index.keys = [
            KeyIndex.Key(id: "resend-lh", source: "resend-lh.txt", provider: "resend", project: "liquidity-hunters"),
            KeyIndex.Key(id: "mykey", source: "mykey.txt", provider: "resend"),
            KeyIndex.Key(id: "restoiq-jwt", source: "jwt.txt", project: "restoiq", description: "JWT del backend"),
        ]
        index.unoffered = [KeyIndex.Key(id: "hidden-one", source: "hidden.txt")]
        return index
    }

    static let visible: Set<String> = ["resend-lh", "mykey", "restoiq-jwt"]

    func check(_ changes: [[String: Any]], usage: [String: KeyTidy.Use] = [:]) -> (accepted: [KeyTidy.Change], refused: [String]) {
        KeyTidy.check(changes, index: Self.index(), providers: ["resend", "meta"], visible: Self.visible, usage: usage)
    }

    @Test func aRenameThatFollowsTheConventionIsAccepted() {
        let result = check([["key": "mykey", "id": "resend-hz", "project": "hernan-zurita", "why": "read hz/.env: RESEND_API_KEY"]])
        #expect(result.refused.isEmpty)
        #expect(result.accepted.first?.id == "resend-hz")
    }

    @Test func whatBreaksTheConventionComesBackWithTheReason() {
        let result = check([
            ["key": "mykey", "id": "my-resend", "why": "looks nicer this way"],
            ["key": "resend-lh", "id": "restoiq-jwt", "why": "taken on purpose here"],
            ["key": "restoiq-jwt", "description": "token=abcdef1234567890 for the api", "why": "copied from the file"],
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
        for name in ["lh-a", "lh-b", "lh-c"] {
            index.keys.append(KeyIndex.Key(id: name, source: "\(name).txt", project: "liquidity-hunters"))
        }
        let result = KeyTidy.check(
            [["key": "resend-lh", "id": "lh-mail", "provider": "resend", "why": "the LH mail key, read lh/.env"]],
            index: index, providers: ["resend"], visible: Self.visible, usage: [:])
        #expect(result.refused.isEmpty)
        #expect(KeyTidy.projectPrefixes(index)["liquidity-hunters"] == ["lh"])
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
            ["key": "restoiq-jwt", "provider": "madeup", "why": "guessed from the name"],
        ])
        #expect(result.accepted.isEmpty)
        #expect(result.refused.count == 2)
    }

    @Test func aRenamedKeyKeepsItsOldNameWorking() throws {
        var index = Self.index()
        let change = KeyTidy.Change(key: "mykey", id: "resend-hz", why: "read hz/.env")
        let result = KeyTidy.apply([change], to: &index)
        #expect(result.renamed.first! == ("mykey", "resend-hz"))
        #expect(index.key("mykey")?.id == "resend-hz")
        #expect(index.current("mykey") == "resend-hz")
        #expect(index.isTaken("mykey"))
        // Written and read back, the old name is still there.
        let again = try KeyIndex.parse(index.toml)
        #expect(again.key("mykey")?.id == "resend-hz")
        #expect(again.key("resend-hz")?.more.formerly == ["mykey"])
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
            $0.sets.append(KeySets.Set(name: "hz", keys: ["mykey", "resend-lh"]))
            $0.standing.append(KeySets.Standing(keys: ["mykey"], program: "/usr/bin/env", hash: "h", folder: "/tmp", since: Date()))
        }
        try LocalServices.approve(key: "mykey", address: "127.0.0.1:8790", at: home.appendingPathComponent(LocalServices.fileName))
        let result = try KeyTidy.apply(
            [KeyTidy.Change(key: "mykey", id: "resend-hz", description: "Resend de HZ", why: "read hz/.env")],
            home: home, stamp: "t1")
        #expect(result.done.count == 1 && result.skipped.isEmpty)
        let policy = AgentPolicy.load(from: home.appendingPathComponent(AgentPolicy.fileName))
        #expect(policy.levels["resend-hz"] == .always && policy.levels["mykey"] == nil)
        #expect(policy.agents["resend-hz"] == ["mesa"])
        #expect(PlaceBook.load(from: PlaceBook.file(home: home)).places.first?.key == "resend-hz")
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent("keys.toml.antes-tidy-t1").path))
        #expect(FileManager.default.fileExists(atPath: home.appendingPathComponent("agents.toml.antes-tidy-t1").path))
        let index = try KeyIndex.load(from: home.appendingPathComponent(KeyIndex.fileName))
        #expect(index.key("mykey")?.description == "Resend de HZ")
        // A standing permission, a set and a local service follow the key, so nothing asks again for a finger.
        let sets = KeySets.load(from: home.appendingPathComponent(KeySets.fileName))
        #expect(sets.set("hz")?.keys == ["resend-hz", "resend-lh"])
        #expect(sets.standing.first?.keys == ["resend-hz"])
        #expect(LocalServices.load(from: home.appendingPathComponent(LocalServices.fileName)).approved == ["resend-hz": "127.0.0.1:8790"])
    }

    @Test func aSecondApplyInTheSameSecondKeepsTheFirstCopy() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("tidy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let keys = home.appendingPathComponent(KeyIndex.fileName)
        try PrivateFile.write(Data(Self.index().toml.utf8), to: keys)
        let first = try Data(contentsOf: keys)
        try KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-hz", why: "read hz/.env")], home: home, stamp: "t1")
        try KeyTidy.apply([KeyTidy.Change(key: "resend-hz", description: "HZ", why: "read hz/.env")], home: home, stamp: "t1")
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
        KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-hz", why: "read hz/.env")], to: &index)
        let back = KeyTidy.apply([KeyTidy.Change(key: "resend-hz", id: "mykey", why: "the old name was right")], to: &index)
        #expect(back.skipped.isEmpty)
        #expect(index.has("mykey") && index.key("mykey")?.more.formerly == ["resend-hz"])
    }

    @Test func anOldNameIsTakenButIsNoKey() {
        var index = Self.index()
        KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-hz", why: "read hz/.env")], to: &index)
        #expect(index.isTaken("mykey"))
        #expect(!index.has("mykey") && index.has("resend-hz"))
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
        index.keys.append(KeyIndex.Key(id: "resend-hz", source: "other.txt", provider: "resend"))
        var use = KeyTidy.Use()
        use.last = Date().addingTimeInterval(-600)
        let result = KeyTidy.apply([
            KeyTidy.Change(key: "mykey", id: "resend-hz", description: "Resend de HZ", why: "read hz/.env"),
            KeyTidy.Change(key: "restoiq-jwt", archive: true, why: "looked dead at proposal time"),
            KeyTidy.Change(key: "gone-key", description: "x", why: "was there at proposal time"),
        ], to: &index, usage: ["restoiq-jwt": use])
        #expect(result.done.isEmpty)
        #expect(result.skipped.count == 3)
        #expect(result.skipped[0].contains("was taken since"))
        #expect(result.skipped[1].contains("not archived"))
        #expect(result.skipped[2].contains("gone"))
        // Nothing half applied: the description that came with the refused rename is not written either.
        #expect(index.key("mykey")?.description == nil)
        #expect(index.key("restoiq-jwt")?.more.archived == false)
    }

    @Test func theDifferencesAreWhatTheCardAndTheLogSay() {
        let before = KeyIndex.Key(id: "mykey", source: "m.txt", provider: "resend")
        let change = KeyTidy.Change(key: "mykey", id: "resend-hz", provider: "resend", tags: ["hz"], archive: true, why: "read hz/.env")
        #expect(change.differences(from: before).map(\.field) == ["id", "tags"])
        #expect(change.summary(from: before) == "id: mykey → resend-hz; tags + hz; archive")
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
        KeyTidy.apply([KeyTidy.Change(key: "mykey", id: "resend-hz", why: "read hz/.env")], to: &index)
        #expect(index.current("mykey") == "resend-hz")
        #expect(index.current("resend-hz") == "resend-hz")
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
                ["key": "mykey", "id": "resend-hz", "why": "read hz/.env: RESEND_API_KEY"],
                ["key": "resend-lh", "id": "lh-mail", "why": "shorter to type"],
            ],
        ])
        #expect(!proposed.error)
        #expect(proposed.text.contains("1 changes wait"))
        #expect(proposed.text.contains("resend-lh → lh-mail"))
        #expect(kept.requests.first?.kind == KeyTidy.requestKind)
        let saved = try JSONDecoder().decode([KeyTidy.Change].self, from: try #require(kept.saved))
        #expect(saved.map(\.key) == ["mykey"])
    }
}
