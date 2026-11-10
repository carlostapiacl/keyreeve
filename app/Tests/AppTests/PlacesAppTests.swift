import Foundation
import Testing

import KeyreeveCatalog
import KeyreeveVault
@testable import KeyreeveUI

/// Places in the app: an agent's proposal adds nothing until the finger, declining keeps nothing, and a place
/// whose procedure changed is not run.
@MainActor
struct PlacesAppTests {
    final class Sensor: @unchecked Sendable {
        var waiting: [@Sendable (Bool) -> Void] = []
        func gate() -> FingerGate {
            var gate = FingerGate()
            gate.canAsk = { _, _, _ in true }
            gate.ask = { _, _, _, done in self.waiting.append(done) }
            return gate
        }
    }

    static func procedures(sha: String) throws -> [ProcedureInfo] {
        let json = #"[{"name":"ssh-env","origin":"builtin","sha256":"\#(sha)","description":"d","params":[],"text":"echo absent"}]"#
        return try JSONDecoder().decode([ProcedureInfo].self, from: Data(json.utf8))
    }

    func model(_ sensor: Sensor) throws -> AppModel {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("places-app-\(UUID())")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        let model = AppModel(files: KeyreeveFiles(directory: home), binary: nil)
        model.fingerGate = sensor.gate()
        model.placesState.procedures = try Self.procedures(sha: "aa")
        return model
    }

    func settle() async { for _ in 0..<5 { await Task.yield() } }

    func proposal(_ model: AppModel) throws -> AccessRequests.Entry {
        let entry = AccessRequests.Entry(
            id: AccessRequests.newID(), at: Date(), event: .asked, agent: "claude", provider: "keyreeve", reason: "found", kind: "places")
        let checked = try AgentBridge.checkPlaces(
            [[
                "key": "openai-lh", "procedure": "ssh-env", "params": ["host": "vps2", "variable": "OPENAI_API_KEY"],
                "label": "VPS2 · OPENAI_API_KEY",
            ]], offered: ["openai-lh"], by: "claude")
        try AgentSorting.save(checked.data, id: entry.id, home: model.files.directory)
        try AccessRequests.append(entry, to: model.requestsFile)
        return entry
    }

    @Test func aProposalAddsNothingWithoutTheFinger() async throws {
        let sensor = Sensor()
        let model = try model(sensor)
        let request = try proposal(model)
        let proposed = model.proposedPlaces(for: request)
        #expect(proposed.count == 1)
        model.approveProposal(request, chosen: proposed)
        #expect(sensor.waiting.count == 1)
        // Before the finger, and after a refused one, nothing is there.
        #expect(PlaceBook.load(from: model.placesFile).places.isEmpty)
        sensor.waiting[0](false)
        await settle()
        #expect(PlaceBook.load(from: model.placesFile).places.isEmpty)
        // With the finger, the chosen place is added, pinned to the procedure as it was shown.
        model.approveProposal(request, chosen: proposed)
        sensor.waiting[1](true)
        await settle()
        let book = PlaceBook.load(from: model.placesFile)
        #expect(book.places.count == 1 && book.places[0].sha256 == "aa" && book.places[0].by == "claude")
        #expect(AgentSorting.load(id: request.id, home: model.files.directory) == nil)
    }

    @Test func decliningKeepsNothing() async throws {
        let sensor = Sensor()
        let model = try model(sensor)
        let request = try proposal(model)
        model.declinePlaces(request)
        await settle()
        #expect(sensor.waiting.isEmpty)
        #expect(PlaceBook.load(from: model.placesFile).places.isEmpty)
        #expect(AgentSorting.load(id: request.id, home: model.files.directory) == nil)
        #expect(AccessRequests.read(from: model.requestsFile).last?.event == .declined)
    }

    @Test func aPlaceWhoseProcedureChangedIsNotUpdatedOrRotated() async throws {
        let sensor = Sensor()
        let model = try model(sensor)
        let place = PlaceBook.Place(key: "openai-lh", procedure: "ssh-env", params: [:], label: "VPS2", sha256: "aa")
        try PlaceBook.update(at: model.placesFile) { $0.places = [place] }
        model.reloadPlaces()
        #expect(model.status(of: place) == .approved)
        model.placesState.procedures = try Self.procedures(sha: "bb")
        #expect(model.status(of: place) == .changed)
        model.updatePlace(place)
        await settle()
        // Refused before the finger is asked.
        #expect(sensor.waiting.isEmpty)
        model.keyIndex = KeyIndex(keys: [KeyIndex.Key(id: "openai-lh", source: "lh.env")])
        #expect(model.plannedProcedures(for: CatalogItem(path: "lh.env")).isEmpty)
        model.placesState.procedures = try Self.procedures(sha: "aa")
        #expect(model.plannedProcedures(for: CatalogItem(path: "lh.env")).map(\.sha256) == ["aa"])
    }
}
