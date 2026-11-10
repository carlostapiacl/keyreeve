import Foundation
import KeyreeveVault
import Testing

/// The service with several keys: a counter for the fingerprint, a window the test answers, and files the test
/// changes, as the person or another program would.
final class SetFixture: @unchecked Sendable {
    let folder = FileManager.default.temporaryDirectory.appendingPathComponent("sets-\(UUID().uuidString)")
    let proxy = FakeProxy()
    var now = Date(timeIntervalSince1970: 1_800_000_000)
    /// Each fingerprint asked, with its words.
    var fingerprints: [String] = []
    var fingerRefused = false
    /// What the window saw, and what the person answers.
    var windows: [KeyBatch] = []
    var answer: (KeyBatch) -> KeyBatch.Answer? = { KeyBatch.Answer(chosen: Array($0.items.indices), lasts: $0.suggested) }
    var sets = KeySets()
    var kept: [(KeySets.Standing, [String: Data])] = []
    /// The program and script on disk, by path, as their SHA-256 would read.
    var files: [String: String] = ["/usr/bin/python3": "py-1", "/w/report.py": "script-1"]
    var running: Set<Int32> = [42]
    var unattended: Set<String> = []
    var gather: TimeInterval = 0
    let lock = NSLock()
    lazy var log = AuditLog(url: folder.appendingPathComponent("audit.jsonl"))
    static let index = """
        [[key]]
        id = "meta-ads"
        source = "meta-ads.txt"
        provider = "meta"
        account = "ads"
        variable = "META_TOKEN"

        [[key]]
        id = "calcom"
        source = "calcom.txt"
        provider = "calcom"
        variable = "CALCOM_KEY"

        [[key]]
        id = "sentry"
        source = "sentry.env"
        field = "TOKEN"
        provider = "sentry"
        variable = "SENTRY_TOKEN"

        [[key]]
        id = "hidden"
        source = "hidden.txt"
        provider = "stripe"
        offered = false

        [[key]]
        id = "vps"
        source = "vps-key"
        provider = "ssh"
        """
    lazy var service: KeyService = {
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let value = { (source: String) in Data((source == "sentry.env" ? "OTHER=1\nTOKEN=CANARY-\(source)\n" : "CANARY-\(source)\n").utf8) }
        return KeyService(
            index: { try KeyIndex.parse(Self.index) },
            open: { source, prompt in
                self.lock.lock()
                defer { self.lock.unlock() }
                if self.fingerRefused { throw VaultError("the fingerprint was not accepted") }
                self.fingerprints.append(prompt)
                return value(source)
            },
            proxy: proxy, log: log, now: { self.now },
            openMany: { sources, prompt in
                self.lock.lock()
                defer { self.lock.unlock() }
                if self.fingerRefused { throw VaultError("the fingerprint was not accepted") }
                self.fingerprints.append(prompt)
                return Dictionary(uniqueKeysWithValues: sources.map { ($0, value($0)) })
            },
            choose: { batch in
                self.lock.lock()
                self.windows.append(batch)
                self.lock.unlock()
                return self.answer(batch)
            },
            sets: { self.sets },
            keepStanding: { standing, values in
                self.kept.append((standing, values))
                self.unattended.formUnion(values.keys)
                self.sets.standing.append(standing)
            },
            openStanding: { source in self.unattended.contains(source) ? value(source) : nil },
            fingerprint: { self.files[$0] },
            isRunning: { self.running.contains($0) },
            gather: gather)
    }()
    let caller = AuditLog.Observed(pid: 42, program: "/usr/local/bin/keyreeve-vault", chain: ["keyreeve-vault", "zsh"])

    func many(
        _ keys: [String], cwd: String = "/w", program: String = "/usr/bin/python3", script: String? = "/w/report.py", seconds: Int? = nil
    ) -> KeyService.Response {
        service.handle(
            KeyService.Request(
                op: "use-many", seconds: seconds, program: "python3", arguments: 1, reason: "weekly report", cwd: cwd, keys: keys,
                set: "weekly-report", programPath: program, script: script),
            caller: caller)
    }

    var granted: [String] { (try? log.entries().filter { $0.event == "granted" }.map(\.key)) ?? [] }

    deinit { try? FileManager.default.removeItem(at: folder) }
}

struct KeySetTests {
    @Test func oneFingerprintOpensEveryKeyAndEachGetsItsOwnVariable() throws {
        let f = SetFixture()
        let answer = f.many(["meta-ads", "calcom", "sentry"])
        #expect(answer.ok)
        #expect(f.windows.count == 1 && f.windows[0].items.map(\.key) == ["meta-ads", "calcom", "sentry"])
        #expect(f.fingerprints.count == 1)
        #expect(f.fingerprints[0].contains("3") && f.fingerprints[0].contains("meta-ads") && f.fingerprints[0].contains("sentry"))
        #expect(answer.many?.map(\.key) == ["meta-ads", "calcom", "sentry"])
        #expect(answer.many?.map(\.variable) == ["META_TOKEN", "CALCOM_KEY", "SENTRY_TOKEN"])
        #expect(answer.many?.allSatisfy { $0.ok && $0.standIn == "STAND-IN" && $0.value == nil } == true)
        #expect(f.proxy.added.map(\.field) == [nil, nil, "TOKEN"])
        // In force now: the same command asks nothing again.
        #expect(f.many(["meta-ads", "calcom", "sentry"]).ok)
        #expect(f.fingerprints.count == 1 && f.windows.count == 1)
        // The window offers the four choices, and starts on 5 minutes.
        #expect(f.windows[0].choices == [.seconds(300), .untilDone, .seconds(86400), .always])
        #expect(f.windows[0].suggested == .seconds(300))
    }

    @Test func aKeyNotOfferedIsNeverShownOrOpened() throws {
        let f = SetFixture()
        let answer = f.many(["meta-ads", "hidden", "calcom"])
        #expect(f.windows.first?.items.map(\.key) == ["meta-ads", "calcom"])
        let hidden = answer.many?.first { $0.key == "hidden" }
        #expect(hidden?.ok == false && hidden?.error == "no key is called hidden. `list` shows them")
        #expect(!f.fingerprints.joined().contains("hidden"))
        #expect(!f.granted.contains("hidden"))
        // A set that names it, written by hand, changes nothing.
        f.sets.sets = [KeySets.Set(name: "x", keys: ["hidden"])]
        let alone = f.many(["hidden"])
        #expect(!alone.ok && f.windows.count == 1)
        // The suggestions from the log never name it either.
        let log = try f.log.entries()
        let suggested = KeySets.suggestions(from: log, offered: ["meta-ads", "calcom", "sentry"], now: Date())
        #expect(!suggested.flatMap(\.keys).contains("hidden"))
    }

    @Test func aNoOrAClosedWindowGrantsNothing() throws {
        let f = SetFixture()
        f.answer = { _ in nil }
        let answer = f.many(["meta-ads", "calcom"])
        #expect(!answer.ok)
        #expect(f.fingerprints.isEmpty)
        #expect(f.proxy.added.isEmpty && f.granted.isEmpty)
        #expect(try f.log.entries().filter { $0.event == "denied" }.count == 2)
        // A yes in the window and no finger at the sensor is a no too.
        f.answer = { KeyBatch.Answer(chosen: Array($0.items.indices), lasts: $0.suggested) }
        f.fingerRefused = true
        #expect(!f.many(["meta-ads", "calcom"]).ok)
        #expect(f.proxy.added.isEmpty && f.granted.isEmpty)
        // A choice the window never offered is a no.
        f.fingerRefused = false
        f.answer = { _ in KeyBatch.Answer(chosen: [0, 1], lasts: .seconds(999_999)) }
        #expect(!f.many(["meta-ads", "calcom"]).ok && f.proxy.added.isEmpty)
    }

    @Test func untickingAKeyGrantsOnlyTheRest() throws {
        let f = SetFixture()
        f.answer = { _ in KeyBatch.Answer(chosen: [0, 2, 9], lasts: .seconds(300)) }
        let answer = f.many(["meta-ads", "calcom", "sentry"])
        #expect(answer.ok)
        #expect(answer.many?.filter(\.ok).map(\.key) == ["meta-ads", "sentry"])
        #expect(answer.many?.first { $0.key == "calcom" }?.error == "the person left calcom unticked")
        #expect(f.granted == ["meta-ads", "sentry"])
        #expect(f.fingerprints.count == 1 && !f.fingerprints[0].contains("calcom"))
    }

    @Test func noValueReachesAnAnswerTheWindowOrTheLog() throws {
        let f = SetFixture()
        f.answer = { _ in KeyBatch.Answer(chosen: [0, 1, 2], lasts: .always) }
        let answer = f.many(["meta-ads", "calcom", "sentry"])
        let later = f.many(["meta-ads", "calcom", "sentry"])
        let texts = [
            String(decoding: try JSONEncoder().encode(answer), as: UTF8.self),
            String(decoding: try JSONEncoder().encode(later), as: UTF8.self),
            String(decoding: try JSONEncoder().encode(f.windows), as: UTF8.self),
            try String(contentsOf: f.log.url, encoding: .utf8), f.sets.toml, f.fingerprints.joined(),
        ]
        for text in texts { #expect(!text.contains("CANARY")) }
    }

    @Test func alwaysIsBoundToTheProgramTheScriptAndTheFolder() throws {
        let f = SetFixture()
        f.answer = { _ in KeyBatch.Answer(chosen: [0, 1], lasts: .always) }
        #expect(f.many(["meta-ads", "calcom"]).ok)
        #expect(f.fingerprints.count == 1 && f.fingerprints[0].contains("w"))
        let standing = try #require(f.sets.standing.first)
        #expect(standing.keys == ["meta-ads", "calcom"] && standing.program == "/usr/bin/python3" && standing.hash == "py-1")
        #expect(standing.script == "/w/report.py" && standing.scriptHash == "script-1" && standing.folder == "/w")
        // Monday at 9:00, after a restart: nothing in force, and the same command needs no window and no finger.
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        #expect(f.many(["meta-ads", "calcom"]).ok)
        #expect(f.fingerprints.count == 1 && f.windows.count == 1)
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        // Another folder, another program or a changed script asks again.
        f.answer = { _ in nil }
        #expect(!f.many(["meta-ads"], cwd: "/elsewhere").ok)
        #expect(!f.many(["meta-ads"], program: "/usr/bin/ruby").ok)
        f.files["/w/report.py"] = "script-2"
        #expect(!f.many(["meta-ads"]).ok)
        f.files["/w/report.py"] = "script-1"
        f.files["/usr/bin/python3"] = "py-2"
        #expect(!f.many(["meta-ads"]).ok)
        f.files["/usr/bin/python3"] = "py-1"
        // A key added to the set later is not covered: the permission keeps its own list.
        f.sets.sets = [KeySets.Set(name: "weekly-report", keys: ["meta-ads", "calcom", "sentry"])]
        let wider = f.many(["meta-ads", "calcom", "sentry"])
        #expect(wider.many?.first { $0.key == "sentry" }?.ok == false)
        #expect(wider.many?.first { $0.key == "meta-ads" }?.ok == true)
        // The real key never rides on it.
        let real = f.service.handle(
            KeyService.Request(op: "use-many", program: "python3", cwd: "/w", real: true, keys: ["meta-ads"], programPath: "/usr/bin/python3"),
            caller: f.caller)
        #expect(!real.ok)
    }

    @Test func untilItFinishesEndsWithTheCommand() throws {
        let f = SetFixture()
        f.answer = { _ in KeyBatch.Answer(chosen: [0], lasts: .untilDone) }
        #expect(f.many(["meta-ads"]).ok)
        #expect(f.service.handle(.init(op: "grants"), caller: f.caller).grants?.count == 1)
        f.running = []
        #expect(f.service.handle(.init(op: "grants"), caller: f.caller).grants?.isEmpty == true)
        #expect(f.proxy.removed.count == 1)
    }

    /// A script that asks for ten keys one by one sees one window, and one fingerprint opens them all.
    @Test func singleUsesCloseTogetherShareOneWindow() async throws {
        let f = SetFixture()
        f.gather = 0.5
        let service = f.service
        let caller = f.caller
        let answers = await withTaskGroup(of: KeyService.Response.self) { group in
            for key in ["meta-ads", "calcom", "sentry"] {
                group.addTask {
                    service.handle(
                        KeyService.Request(op: "use", key: key, program: "python3", arguments: 1, reason: "report", cwd: "/w"),
                        caller: caller)
                }
            }
            var out: [KeyService.Response] = []
            for await answer in group { out.append(answer) }
            return out
        }
        #expect(answers.allSatisfy { $0.ok })
        #expect(f.windows.count == 1 && Set(f.windows[0].items.map(\.key)) == ["meta-ads", "calcom", "sentry"])
        #expect(f.fingerprints.count == 1)
        // One by one still works: a single use alone is asked as before, with no window.
        _ = f.service.handle(.init(op: "revoke"), caller: f.caller)
        let alone = f.service.handle(
            KeyService.Request(op: "use", key: "calcom", program: "python3", arguments: 1, cwd: "/w"), caller: f.caller)
        #expect(alone.ok && f.windows.count == 1 && f.fingerprints.count == 2)
    }

    @Test func theFileRoundTripsAndADamagedOneIsAnError() throws {
        var sets = KeySets()
        try sets.save(.init(name: "weekly-report", keys: ["meta-ads", "calcom", "meta-ads"], folder: "/Users/me/report"))
        sets.standing = [.init(
            keys: ["calcom"], program: "/usr/bin/python3", hash: "abc", script: "/w/r.py", scriptHash: "def", folder: "/w",
            since: Date(timeIntervalSince1970: 1_800_000_000), set: "weekly-report")]
        #expect(sets.sets[0].keys == ["meta-ads", "calcom"])
        #expect(try KeySets.parse(sets.toml) == sets)
        #expect(throws: VaultError.self) { try sets.save(.init(name: "Bad Name", keys: ["a"])) }
        #expect(throws: VaultError.self) { try sets.save(.init(name: "empty", keys: [])) }
        for text in ["[[set]]\nname = \"a\"", "[[set]]\nname = \"a\"\nkeys = [\"x\"]\nother = \"y\"", "keys = [\"x\"]",
                     "[[always]]\nkeys = [\"x\"]\nprogram = \"/p\"\nfolder = \"/w\"\nsince = \"2027-01-01T00:00:00Z\""] {
            #expect(throws: VaultError.self) { try KeySets.parse(text) }
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("sets-\(UUID().uuidString).toml")
        defer { try? FileManager.default.removeItem(at: url) }
        try "[[set]]\nbroken".write(to: url, atomically: true, encoding: .utf8)
        #expect(KeySets.load(from: url) == KeySets())
        #expect(throws: VaultError.self) { try KeySets.update(at: url) { _ in } }
    }

    @Test func aSuggestionComesFromOneFolderAndProgramInTheLastHour() throws {
        let f = SetFixture()
        _ = f.service
        let log = f.log
        let at = Date()
        for key in ["meta-ads", "calcom", "hidden"] {
            try log.append(
                event: "used", key: key, declared: .init(command: "python3 (1 arguments)", cwd: "/w/report"), now: at)
        }
        try log.append(event: "used", key: "sentry", declared: .init(command: "python3 (1 arguments)", cwd: "/w/report"), now: at.addingTimeInterval(-7200))
        try log.append(event: "used", key: "sentry", declared: .init(command: "node (0 arguments)", cwd: "/w/report"), now: at)
        let found = KeySets.suggestions(from: try log.entries(), offered: ["meta-ads", "calcom", "sentry"], now: at)
        #expect(found == [KeySets.Suggestion(folder: "/w/report", program: "python3", keys: ["calcom", "meta-ads"])])
        #expect(KeySets(sets: [.init(name: "report", keys: ["x"])]).suggestedName(for: "/w/report") == "report-2")
    }

    /// A bot that polls every thirty seconds reads as a few rows, and the file keeps every line.
    @Test func repeatedRequestsAreOneRowAndTheFileKeepsEveryLine() throws {
        let f = SetFixture()
        _ = f.service
        let log = f.log
        var at = Date(timeIntervalSince1970: 1_800_000_000)
        for offset in 0..<392 {
            at.addTimeInterval(30)
            try log.append(event: "used", key: "telegram", grant: "g-1", now: at)
            try log.append(event: "request", key: "telegram", grant: "g-1", detail: "GET api.telegram.org/getUpdates?offset=\(offset) 200", now: at)
        }
        try log.append(event: "granted", key: "calcom", detail: "300 seconds", now: at.addingTimeInterval(1))
        let entries = Array(try log.entries().reversed())
        let groups = LogGroups.collapse(entries)
        #expect(groups.count == 3)
        #expect(groups[0].entry.event == "granted" && groups[0].count == 1)
        #expect(groups.map(\.count).reduce(0, +) == entries.count)
        #expect(groups.first { $0.entry.event == "request" }?.count == 392)
        #expect(try log.entries().count == 785)
        #expect(log.firstBrokenLine() == nil)
        // A decision is never folded into another.
        let refusals = LogGroups.collapse(Array(repeating: groups[0].entry, count: 3))
        #expect(refusals.count == 3)
    }
}
