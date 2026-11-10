import Foundation
import KeyreeveCatalog
import Testing

/// What the app takes from the engine about a place: a hash or a word, never anything that could be a value.
struct PlaceRunnerTests {
    @Test func onlyAHashOrAWordIsTaken() {
        let hash = String(repeating: "ab", count: 32)
        #expect(PlaceRunner.found(in: Data(#"{"state":"hash","sha256":"\#(hash.uppercased())"}"#.utf8)) == .hash(hash))
        #expect(PlaceRunner.found(in: Data(#"{"state":"absent"}"#.utf8)) == .absent)
        #expect(PlaceRunner.found(in: Data(#"{"state":"present"}"#.utf8)) == .present)
        for bad in [
            #"{"state":"hash","sha256":"CANARY-sk-live-0123456789"}"#, #"{"state":"value","value":"CANARY"}"#, "CANARY", "",
            #"{"state":"hash","sha256":"\#(hash)0"}"#,
        ] {
            guard case .failed(let why) = PlaceRunner.found(in: Data(bad.utf8)) else {
                Issue.record("took \(bad)")
                continue
            }
            #expect(!why.contains("CANARY"))
        }
    }

    @Test func aRotationPlanCarriesPinnedProceduresAndStillItsFilesAndButtons() throws {
        var places = KeyPlaces()
        places.files = ["/a/.env"]
        places.actions = ["mine/update"]
        var plan = RotationPlan(item: CatalogItem(path: "k.env"), places: places, admin: nil, original: nil)
        plan.place_procedures = [
            PlannedProcedure(label: "VPS2", procedure: "ssh-env", sha256: "aa", params: ["host": "vps2"])
        ]
        plan.procedures_folder = "/h/.keyreeve/procedures"
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(plan)) as? [String: Any])
        #expect(object["place_files"] as? [String] == ["/a/.env"])
        #expect(object["place_actions"] as? [String] == ["mine/update"])
        let procedures = try #require(object["place_procedures"] as? [[String: Any]])
        #expect(procedures.first?["sha256"] as? String == "aa" && procedures.first?["procedure"] as? String == "ssh-env")
        #expect(object["procedures_folder"] as? String == "/h/.keyreeve/procedures")
    }

    /// A places.json written before procedures reads as it did.
    @Test func placesWrittenBeforeProceduresStillRead() throws {
        let old = #"{"k.env":{"files":["/srv/app.env"],"actions":["mine/deploy"],"nothingElse":false,"overlapMinutes":60}}"#
        let read = try JSONDecoder().decode([String: KeyPlaces].self, from: Data(old.utf8))
        let places = try #require(read["k.env"])
        #expect(places.files == ["/srv/app.env"] && places.actions == ["mine/deploy"] && places.isDecided)
    }

    /// With no engine there are no procedures, so no place can be approved.
    @Test func noEngineListsNoProcedures() {
        let found = PlaceRunner.procedures(binary: URL(fileURLWithPath: "/nonexistent"), folder: URL(fileURLWithPath: "/tmp"))
        #expect(found.isEmpty)
    }
}
