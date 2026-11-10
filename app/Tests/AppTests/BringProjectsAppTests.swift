import CryptoKit
import Foundation
@testable import KeyreeveCatalog
import KeyreeveVault
import Testing

@testable import KeyreeveUI

/// Bring in in the app: learning what the vault holds asks once and a no learns nothing; a key the vault holds starts
/// skipped and becomes a place to add; and projects are kept only when the person says so.
@MainActor
struct BringProjectsAppTests {
    final class Sensor: @unchecked Sendable {
        var waiting: [@Sendable (Bool) -> Void] = []
        func gate() -> FingerGate {
            var gate = FingerGate()
            gate.canAsk = { _, _, _ in true }
            gate.ask = { _, _, _, done in self.waiting.append(done) }
            return gate
        }
    }

    func model(_ sensor: Sensor) throws -> AppModel {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("bring-projects-app-\(UUID())")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: home), binary: nil)
        model.fingerGate = sensor.gate()
        try model.vaultStore.save(VaultFile(enclave: SoftwareRecipient().publicKey, recovery: Age.X25519Identity().recipient))
        return model
    }

    func settle() async { for _ in 0..<5 { await Task.yield() } }

    @Test func learningAsksOnceAndANoLearnsNothing() async throws {
        let sensor = Sensor()
        let model = try model(sensor)
        defer { try? FileManager.default.removeItem(at: model.files.directory) }
        var answers: [Bool] = []
        model.learnWhatTheVaultHolds { answers.append($0) }
        #expect(sensor.waiting.count == 1, "one fingerprint for the whole vault")
        sensor.waiting[0](false)
        await settle()
        #expect(answers == [false])
        #expect(!FileManager.default.fileExists(atPath: model.digestsFile.path), "a no learns nothing")
        #expect(sensor.waiting.count == 1, "and asks nothing more")
    }

    func found(_ id: Int, path: String, name: String, project: String) -> BringCandidate {
        let origin = BringCandidate.Origin(
            path: path, area: "project", bytes: 1, modified: 1,
            parts: [.init(name: name, section: nil, line: 2, span: [0, 1], json: nil, whole: false)], project: project)
        return BringCandidate(
            id: id, group: .works, kind: "key", why: "", provider: "openai", evidence: "prefix", guessed: [], check: nil,
            unchecked: nil, server: nil, origins: [origin], duplicate: false, from_project: true, suggested: "seal")
    }

    @Test func aKeyTheVaultHoldsIsSkippedAndBecomesAPlaceAndAProject() throws {
        let sensor = Sensor()
        let model = try model(sensor)
        defer { try? FileManager.default.removeItem(at: model.files.directory) }
        let report = BringReport(
            schema: 1, scope: "everywhere", roots: [], suggested_projects: [], files: 2, checked: true,
            skipped: .init(), summary: .init(),
            candidates: [
                found(1, path: "/code/shop/.env", name: "OPENAI_API_KEY", project: "/code/shop"),
                found(2, path: "/code/shop/notes/keys.txt", name: "OPENAI_API_KEY", project: "/code/shop"),
                found(3, path: "/code/bot/.env", name: "BOT_TOKEN", project: "/code/bot"),
            ],
            projects: [BringProject(path: "/code/shop", name: "shop", marker: ".git"), BringProject(path: "/code/bot", name: "bot", marker: ".env")])
        let sealed: [Int: AgentBringing.Sealed] = [1: .now(["openai-shop"]), 2: .now(["openai-shop"]), 3: .new]
        let decisions = AppModel.firstDecisions(report, sealed: sealed)
        #expect(decisions[1] == false && decisions[2] == false, "a key already in the vault is not sealed again")
        #expect(decisions[3] == true)

        var state = BringState()
        state.report = report
        state.sealedNow = sealed
        model.bringing = state
        // Only the dotenv file becomes a place, with its variable, and only for a key in the vault.
        let places = model.foundPlaces()
        #expect(places.count == 1)
        #expect(places[0].key == "openai-shop" && places[0].procedure == "dotenv-local")
        #expect(places[0].params == ["file": "/code/shop/.env", "variable": "OPENAI_API_KEY"])
        #expect(PlaceBook.load(from: model.placesFile).places.isEmpty, "nothing is added until the person says so")
        // A project is offered for the keys the vault holds, and kept only when asked.
        let projects = model.projectsFound()
        #expect(projects.map(\.folder) == ["/code/shop"])
        #expect(projects[0].name == "shop" && projects[0].keys == ["openai-shop"])
        #expect(projects[0].places == ["/code/shop/.env", "/code/shop/notes/keys.txt"])
        #expect(!FileManager.default.fileExists(atPath: model.projectsFile.path))
        model.rememberProjects()
        let kept = try Projects.loadStrict(from: model.projectsFile)
        #expect(kept.projects.map(\.folder) == ["/code/shop"])
        let text = try String(contentsOf: model.projectsFile, encoding: .utf8)
        #expect(!text.contains("CANARY"))
        #expect(model.newKeys(in: Projects.Project(name: "bot", folder: "/code/bot")) == 0, "nothing found yet in this model")
    }
}
