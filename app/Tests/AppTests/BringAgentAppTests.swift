import Foundation
@testable import KeyreeveCatalog
import KeyreeveVault
import LocalAuthentication
import Testing

@testable import KeyreeveUI

/// An agent's proposal to bring keys in: the app opens it in Bring in with the agent's choices marked, and
/// nothing is sealed until the person gives their finger.
@MainActor
struct BringAgentAppTests {
    final class World: @unchecked Sendable {
        var report = Data()
        var entries: [AccessRequests.Entry] = []
    }

    /// A temporary Keyreeve folder with a vault, a project `.env` with planted values, and what the engine
    /// says of it.
    func setUp() throws -> (root: URL, env: URL, report: BringReport) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("bring-agent-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        try store.save(VaultFile(enclave: SoftwareRecipient().publicKey, recovery: Age.X25519Identity().recipient))
        let env = root.appendingPathComponent("app.env")
        try "OPENAI_API_KEY=CANARYopenai\nBOT_TOKEN=CANARYbot\nDATABASE_HOST=db\n".write(to: env, atomically: true, encoding: .utf8)
        let helper = BringAppTests()
        var openai = try helper.candidate(1, env, value: "CANARYopenai", name: "OPENAI_API_KEY", provider: "openai", area: "project",
                                          group: .doubtful)
        openai.suggested = "decide"
        let bot = try helper.candidate(2, env, value: "CANARYbot", name: "BOT_TOKEN", provider: nil, group: .doubtful)
        var host = try helper.candidate(3, env, value: "db", name: "DATABASE_HOST", provider: nil, group: .other)
        host.kind = "configuration"
        host.suggested = "skip"
        let report = BringReport(
            schema: 1, scope: "folder", roots: [root.path], suggested_projects: [], files: 1, checked: false,
            skipped: .init(), summary: .init(), candidates: [openai, bot, host])
        return (root, env, report)
    }

    /// The agent's side: a server that searches with the report given and keeps its proposal in `root`.
    func propose(_ report: BringReport, root: URL, world: World, seal: [[String: Any]], skip: [[String: Any]] = []) throws
        -> AccessRequests.Entry
    {
        world.report = try JSONEncoder().encode(report)
        let requests = root.appendingPathComponent(AccessRequests.fileName)
        let bridge = AgentBridge(
            policy: { AgentPolicy() }, names: { [] },
            open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") }, record: { _, _, _ in },
            agent: "claude", offered: { ["openai", "telegram"] },
            requests: { AccessRequests.read(from: requests) }, addRequest: { try AccessRequests.append($0, to: requests) },
            saveProposal: { try AgentSorting.save($1, id: $0, home: root) },
            scanKeys: { _ in world.report })
        let found = try call(bridge, "find_keys", ["folder": root.path])
        #expect(!found.error && !found.text.contains("CANARY"), "\(found.text)")
        let answer = try call(bridge, "propose_bring", ["reason": "bring in the app's keys", "seal": seal, "skip": skip])
        #expect(!answer.error, "\(answer.text)")
        return try #require(AccessRequests.pending(AccessRequests.read(from: requests)).first)
    }

    func call(_ bridge: AgentBridge, _ name: String, _ arguments: [String: Any]) throws -> (text: String, error: Bool) {
        let request: [String: Any] = [
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["name": name, "arguments": arguments],
        ]
        let answer = try #require(bridge.handle(String(decoding: try JSONSerialization.data(withJSONObject: request), as: UTF8.self)))
        let object = try #require(try JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any])
        let result = try #require(object["result"] as? [String: Any])
        let content = try #require(result["content"] as? [[String: Any]])
        return (try #require(content[0]["text"] as? String), result["isError"] as? Bool ?? false)
    }

    func model(_ root: URL, sensor: FingerTests.Sensor) -> AppModel {
        let model = AppModel(files: KeyreeveFiles(directory: root), binary: nil)
        model.fingerGate = sensor.gate()
        model.unlocked = true
        return model
    }

    func settle() async { for _ in 0..<10 { await Task.yield() } }

    @Test func theAgentsChoicesFollowFilesNotNumbers() throws {
        let (root, _, report) = try setUp()
        defer { try? FileManager.default.removeItem(at: root) }
        let world = World()
        let request = try propose(report, root: root, world: world, seal: [["candidates": [1], "id": "openai-app"]],
                                  skip: [["candidates": [2], "reason": "an old bot"]])
        let proposal = try #require(AgentSorting.load(id: request.id, home: root).flatMap(AgentBringing.decode))
        // A new search numbers them otherwise, and finds a configuration where the agent's key was.
        var again = report
        again.candidates[0].id = 7
        again.candidates[1].id = 5
        again.candidates[2].origins = again.candidates[1].origins
        again.candidates[2].id = 9
        let found = AppModel.agentChoices(again, proposal: proposal)
        #expect(found.choices[7]?.id == "openai-app" && found.choices[7]?.seal == true)
        #expect(found.choices[5]?.seal == false)
        #expect(found.choices[9] == nil, "configuration is never sealed")
        #expect(found.missed.isEmpty)
        // A file that changed its names is told apart, not guessed.
        again.candidates.removeFirst()
        #expect(AppModel.agentChoices(again, proposal: proposal).missed.map(\.candidate) == [1])
    }

    @Test func aProposalOpensInTheReviewWithTheAgentsChoices() throws {
        let (root, _, report) = try setUp()
        defer { try? FileManager.default.removeItem(at: root) }
        let request = try propose(report, root: root, world: World(), seal: [["candidates": [1]]],
                                  skip: [["candidates": [2], "reason": "an old bot"]])
        let model = model(root, sensor: FingerTests.Sensor())
        model.reviewBringProposal(request)
        #expect(model.bringing?.request == request)
        #expect(model.bringing?.folder?.path == root.path && model.bringing?.usualPlaces == false)
        // The app looks again with checks, as for the person; here the search answers at once.
        model.showBrought(.success(report))
        let state = try #require(model.bringing)
        #expect(state.step == .review)
        #expect(state.decisions[1] == true && state.decisions[2] == false, "the agent's choices, which the person can change")
        #expect(state.agentChoices.keys.sorted() == [1, 2])
        #expect(state.chosen.map(\.id) == [1])
        model.decide(2, seal: true)
        #expect(model.bringing?.chosen.map(\.id) == [1, 2])
    }

    @Test func anAgentsProposalStillNeedsThePersonsFinger() async throws {
        let (root, env, report) = try setUp()
        defer { try? FileManager.default.removeItem(at: root) }
        let before = try Data(contentsOf: env)
        let request = try propose(
            report, root: root, world: World(),
            seal: [["candidates": [1], "id": "openai-app", "description": "The app's key", "tags": ["app"]]])
        let sensor = FingerTests.Sensor()
        let model = model(root, sensor: sensor)
        let store = VaultStore(directory: root.appendingPathComponent("vault"))
        model.reviewBringProposal(request)
        model.showBrought(.success(report))
        model.decide(2, seal: false)
        model.sealBrought()
        #expect(sensor.waiting.count == 1, "one fingerprint for the whole proposal")
        #expect(try store.load().entries.isEmpty, "nothing is sealed before the finger")
        sensor.waiting[0](false)
        await settle()
        #expect(try store.load().entries.isEmpty)
        #expect(AccessRequests.pending(AccessRequests.read(from: root.appendingPathComponent(AccessRequests.fileName))).count == 1)
        model.sealBrought()
        #expect(sensor.waiting.count == 2)
        sensor.waiting[1](true)
        await settle()
        #expect(try store.load().entries.keys.sorted() == ["added/openai-app"])
        let index = try KeyIndex.load(from: model.files.keyIndex)
        #expect(index.keys.isEmpty, "a key brought in is not offered to agents")
        let saved = try #require(index.unoffered.first)
        #expect(saved.id == "openai-app" && saved.description == "The app's key" && saved.more.tags == ["app"])
        #expect(saved.provider == "openai")
        let entries = AccessRequests.read(from: root.appendingPathComponent(AccessRequests.fileName))
        let answer = try #require(entries.last)
        #expect(answer.id == request.id && answer.event == .allowed)
        #expect(answer.result == "the person sealed 1 keys")
        #expect(answer.key == nil && !(answer.result ?? "").contains("openai-app"), "the agent learns how many, not which")
        #expect(try Data(contentsOf: env) == before, "the file is not changed")
    }

    @Test func theAgentsNamesAreLeftOutWhenThePersonSaysSo() async throws {
        let (root, _, report) = try setUp()
        defer { try? FileManager.default.removeItem(at: root) }
        let request = try propose(report, root: root, world: World(), seal: [["candidates": [1], "id": "openai-app", "description": "x"]])
        let sensor = FingerTests.Sensor()
        let model = model(root, sensor: sensor)
        model.reviewBringProposal(request)
        model.showBrought(.success(report))
        model.decide(2, seal: false)
        model.bringing?.useAgentNames = false
        model.sealBrought()
        sensor.waiting[0](true)
        await settle()
        let saved = try #require(try KeyIndex.load(from: model.files.keyIndex).unoffered.first)
        #expect(saved.id == "openai" && saved.description == nil)
    }
}
