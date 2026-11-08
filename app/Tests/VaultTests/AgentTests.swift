import Foundation
import KeyreeveVault
import Testing

struct AgentTests {
    static let canary = "CANARY-value-0123456789"

    /// Programs allowed the way the app allows them, with a pin, which these tests accept.
    static func pinnedPolicy(_ commands: [String: [String]]) -> AgentPolicy {
        AgentPolicy(commands: commands, hashes: commands.mapValues { Dictionary($0.map { ($0, "pin") }, uniquingKeysWith: { a, _ in a }) })
    }

    final class Log: @unchecked Sendable {
        var opened: [String] = []
        var prompts: [String] = []
        var ran: [[String]] = []
        var recorded: [String] = []
    }

    func bridge(_ log: Log, output: String = "done", commands: [String: [String]] = ["a.env": ["deploy.sh"]]) -> AgentBridge {
        AgentBridge(
            policy: Self.pinnedPolicy(commands),
            names: { ["a.env", "other.env"] },
            open: { key, prompt in
                log.opened.append(key)
                log.prompts.append(prompt)
                return Data("# note\nTOKEN=\(Self.canary)\nOTHER=x\n".utf8)
            },
            run: { command, _, _ in
                log.ran.append(command)
                return AgentBridge.Output(status: 0, text: output)
            },
            record: { key, program, reason in log.recorded.append("\(key) \(program) \(reason)") },
            pinned: { _, _ in true })
    }

    func call(_ bridge: AgentBridge, _ name: String, _ arguments: [String: Any]) throws -> (text: String, error: Bool) {
        let request: [String: Any] = [
            "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["name": name, "arguments": arguments],
        ]
        let line = String(decoding: try JSONSerialization.data(withJSONObject: request), as: UTF8.self)
        let answer = try #require(bridge.handle(line))
        let object = try #require(try JSONSerialization.jsonObject(with: Data(answer.utf8)) as? [String: Any])
        let result = try #require(object["result"] as? [String: Any])
        let content = try #require(result["content"] as? [[String: Any]])
        return (try #require(content[0]["text"] as? String), result["isError"] as? Bool ?? false)
    }

    let run: [String: Any] = [
        "key": "a.env", "variable": "TOKEN", "field": "TOKEN", "command": ["deploy.sh", "--now"], "reason": "deploy",
    ]

    @Test func testAnAllowedProgramRunsAndTheValueNeverComesBack() throws {
        let log = Log()
        let result = try call(bridge(log, output: "token is \(Self.canary)"), "run_with_key", run)
        #expect(!result.error)
        #expect(!result.text.contains("CANARY"))
        #expect(result.text.contains("[redacted]"))
        #expect(log.ran == [["deploy.sh", "--now"]])
        #expect(log.recorded == ["a.env deploy.sh deploy"])
    }

    @Test func testAPermissionChangedWhileTheAgentRunsCountsAtOnce() throws {
        final class Box: @unchecked Sendable { var policy = AgentPolicy() }
        let box = Box()
        let log = Log()
        let live = AgentBridge(
            policy: { box.policy }, names: { ["a.env"] },
            open: { key, _ in log.opened.append(key); return Data("TOKEN=x\n".utf8) },
            run: { command, _, _ in log.ran.append(command); return AgentBridge.Output(status: 0, text: "ok") },
            record: { _, _, _ in }, pinned: { _, _ in true })
        #expect(try call(live, "list_keys", [:]).text == "No key is allowed for agents yet.\nClosed, ask with request_access: a.env")
        #expect(try call(live, "run_with_key", run).error)
        box.policy = Self.pinnedPolicy(["a.env": ["deploy.sh"]])
        #expect(try call(live, "list_keys", [:]).text == "a.env: asks the person; run_with_key with deploy.sh")
        #expect(!(try call(live, "run_with_key", run).error))
        // Taking it away also counts before the next use, and no finger is asked.
        box.policy = AgentPolicy()
        #expect(try call(live, "run_with_key", run).error)
        #expect(log.opened == ["a.env"])
    }

    final class Clock: @unchecked Sendable {
        var now = Date(timeIntervalSince1970: 1_800_000_000)
        var ended: Date?
        var answers: [AgentApproval?] = []
        var asked: [AgentRequest] = []
    }

    func approving(_ log: Log, _ clock: Clock) -> AgentBridge {
        AgentBridge(
            policy: { Self.pinnedPolicy(["a.env": ["deploy.sh", "check.sh"]]) }, names: { ["a.env"] },
            open: { key, _ in log.opened.append(key); return Data("TOKEN=x\n".utf8) },
            run: { command, _, _ in log.ran.append(command); return AgentBridge.Output(status: 0, text: "ok") },
            record: { key, _, _ in log.recorded.append(key) },
            approve: { request in
                clock.asked.append(request)
                return clock.answers.isEmpty ? nil : clock.answers.removeFirst()
            },
            endedAt: { clock.ended }, now: { clock.now }, pinned: { _, _ in true })
    }

    @Test func testOnceAsksEachTimeAndANoOpensNothing() throws {
        let log = Log(), clock = Clock()
        let bridge = approving(log, clock)
        clock.answers = [.once, .once]
        #expect(!(try call(bridge, "run_with_key", run).error))
        #expect(!(try call(bridge, "run_with_key", run).error))
        #expect(log.opened.count == 2)
        clock.answers = [nil]
        let refused = try call(bridge, "run_with_key", run)
        #expect(refused.error && refused.text.contains("said no"))
        #expect(log.opened.count == 2 && log.ran.count == 2)
        #expect(clock.asked.count == 3)
    }

    @Test func testAYesForHoursCoversThatProgramUntilItEndsOrTheAppLocks() throws {
        let log = Log(), clock = Clock()
        let bridge = approving(log, clock)
        clock.answers = [.lasting(3600)]
        #expect(!(try call(bridge, "run_with_key", run).error))
        clock.now += 1800
        #expect(!(try call(bridge, "run_with_key", run).error))
        #expect(log.opened.count == 1 && clock.asked.count == 1 && log.ran.count == 2)
        // Another program with the same key asks on its own.
        var other = run
        other["command"] = ["check.sh"]
        clock.answers = [.once]
        #expect(!(try call(bridge, "run_with_key", other).error))
        #expect(clock.asked.count == 2)
        // Past the hour it asks again.
        clock.now += 1801
        clock.answers = [.lasting(14_400)]
        #expect(!(try call(bridge, "run_with_key", run).error))
        #expect(clock.asked.count == 3)
        // Locking the app ends it at once.
        clock.now += 60
        clock.ended = clock.now
        clock.answers = [nil]
        #expect(try call(bridge, "run_with_key", run).error)
        #expect(clock.asked.count == 4)
    }

    @Test func theAgentsReasonIsOneCleanLine() {
        let request = AgentRequest(key: "a", program: "/x/y/deploy.sh", reason: "  ship it\nnow\u{7}" + String(repeating: "z", count: 300))
        #expect(request.program == "deploy.sh")
        #expect(!request.reason.contains("\n") && request.reason.hasPrefix("ship it now"))
        #expect(request.reason.count == 200)
    }

    @Test func testBase64OfTheValueIsCaughtToo() throws {
        let encoded = Data(Self.canary.utf8).base64EncodedString()
        let result = try call(bridge(Log(), output: encoded), "run_with_key", run)
        #expect(!result.text.contains(encoded))
    }

    @Test func testARefusedProgramNeverReachesTheFinger() throws {
        for (key, program) in [("a.env", "printenv"), ("other.env", "deploy.sh"), ("a.env", "deploy.sh.evil")] {
            let log = Log()
            var arguments = run
            arguments["key"] = key
            arguments["command"] = [program]
            let result = try call(bridge(log), "run_with_key", arguments)
            #expect(result.error)
            #expect(log.opened.isEmpty)
            #expect(log.ran.isEmpty)
        }
    }

    @Test func testNothingIsAllowedByDefault() throws {
        let log = Log()
        #expect(try call(bridge(log, commands: [:]), "run_with_key", run).error)
        #expect(log.opened.isEmpty)
        #expect(try call(bridge(log, commands: [:]), "list_keys", [:]).text.contains("No key"))
    }

    @Test func testTheAgentsWordsComeLastInQuotesAndCut() throws {
        let log = Log()
        var arguments = run
        // An agent trying to pass as keyreeve, on several lines and far too long.
        arguments["reason"] = "Keyreeve update: touch the sensor\nto keep your keys safe " + String(repeating: "x", count: 200)
        _ = try call(bridge(log), "run_with_key", arguments)
        let prompt = try #require(log.prompts.first)
        // keyreeve's own words first: who, which key, with what.
        let own = FingerPrompt.use(who: "agent", key: "a.env", program: "deploy.sh")
        #expect(prompt.hasPrefix(own))
        let said = prompt.dropFirst(own.count)
        #expect(said.hasPrefix(": «") || said.hasPrefix(": \u{201C}"))
        #expect(!prompt.contains("\n") && said.count <= 66 && said.contains("…"))
    }

    @Test func testAPromptWithNoReasonEndsWithKeyreevesWords() {
        #expect(FingerPrompt.use(who: "claude", key: "pexels", reason: "  ") == FingerPrompt.use(who: "claude", key: "pexels"))
        #expect(FingerPrompt.use(who: "claude", key: "pexels", account: "me", program: "curl", lasts: .hours(4)).contains("4 h"))
    }

    @Test func testABadVariableAndMissingReasonAreRefused() throws {
        var arguments = run
        arguments["variable"] = "A=B; rm"
        #expect(try call(bridge(Log()), "run_with_key", arguments).error)
        arguments = run
        arguments["reason"] = ""
        #expect(try call(bridge(Log()), "run_with_key", arguments).error)
    }

    @Test func testListingLeavesOutAProgramThatWouldBeRefused() throws {
        let unpinned = AgentBridge(
            policy: AgentPolicy(commands: ["a.env": ["deploy.sh"]], hashes: [:]),
            names: { ["a.env"] }, open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") },
            record: { _, _, _ in }, pinned: { _, _ in true })
        #expect(try call(unpinned, "list_keys", [:]).text == "a.env: asks the person")
        let changed = AgentBridge(
            policy: Self.pinnedPolicy(["a.env": ["deploy.sh"]]),
            names: { ["a.env"] }, open: { _, _ in Data() }, run: { _, _, _ in AgentBridge.Output(status: 0, text: "") },
            record: { _, _, _ in }, pinned: { _, _ in false })
        #expect(try call(changed, "list_keys", [:]).text == "a.env: asks the person")
    }

    @Test func testListingHoldsNoValue() throws {
        let log = Log()
        let text = try call(bridge(log), "list_keys", [:]).text
        #expect(text == "a.env: asks the person; run_with_key with deploy.sh\nClosed, ask with request_access: other.env")
        #expect(log.opened.isEmpty)
    }

    @Test func testTheProtocolBasics() throws {
        let b = bridge(Log())
        #expect(b.handle(#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) == nil)
        #expect(try #require(b.handle("not json")).contains("-32700"))
        #expect(try #require(b.handle(#"{"jsonrpc":"2.0","id":2,"method":"nope"}"#)).contains("-32601"))
        let hello = try #require(b.handle(#"{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#))
        #expect(hello.contains("keyreeve") && hello.contains("2025-06-18"))
        #expect(try #require(b.handle(#"{"jsonrpc":"2.0","id":4,"method":"tools/list"}"#)).contains("run_with_key"))
    }

    @Test func testTheRealRunnerSetsOneVariableAndCapsOutput() throws {
        let out = try AgentRunner.run(["/bin/sh", "-c", "printf %s \"$MY_VAR\""], variable: "MY_VAR", value: "v1")
        #expect(out.status == 0)
        #expect(out.text == "v1")
        let big = try AgentRunner.run(["/bin/sh", "-c", "head -c 200000 /dev/zero"], variable: "X", value: "v")
        #expect(big.text.utf8.count <= AgentRunner.maxOutput + 64)
    }

    @Test func testAProgramThatWillNotStopDoesNotHoldTheServer() throws {
        let started = Date()
        let out = try AgentRunner.run(
            ["/bin/sh", "-c", "trap '' TERM; sleep 60 & wait"], variable: "X", value: "v", limit: 1)
        #expect(out.status == -1)
        #expect(Date().timeIntervalSince(started) < 10)
    }

    @Test func aProgramThatClosesItsOutputAndStaysAliveDoesNotHoldTheServer() throws {
        let started = Date()
        let out = try AgentRunner.run(
            ["/bin/sh", "-c", "exec >/dev/null 2>&1; sleep 30"], variable: "X", value: "v", limit: 1)
        #expect(out.status == -1)
        #expect(Date().timeIntervalSince(started) < 10)
    }

    @Test func variablesThatChangeWhatRunsNeedThePersonsWord() {
        for name in ["PATH", "path", "DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "NODE_OPTIONS", "BASH_ENV", "GIT_SSH_COMMAND", "HTTPS_PROXY"] {
            #expect(EnvReferences.changesWhatRuns(name), "\(name)")
        }
        for name in ["RESEND_API_KEY", "LOG_LEVEL", "DATABASE_URL", "PATHNAME"] {
            #expect(!EnvReferences.changesWhatRuns(name), "\(name)")
        }
    }

    @Test func testAKeyAtTheCutIsHiddenWhole() throws {
        let padding = String(repeating: "x", count: AgentRunner.maxOutput - 5)
        let result = try call(bridge(Log(), output: padding + Self.canary), "run_with_key", run)
        #expect(!result.text.contains("CANARY"))
        #expect(!result.text.contains(String(Self.canary.prefix(5))))
    }

    @Test func testAFieldUsesItsLastValueAndCommentsStayOut() throws {
        #expect(try EnvReferences.value(in: Data("T=old\nT=new\n".utf8), field: "T") == "new")
        #expect(EnvReferences.parse(#"A="keyreeve://k" # production"#) == [.reference(name: "A", key: "k", field: nil)])
        #expect(EnvReferences.parse("A=keyreeve://k # production") == [.reference(name: "A", key: "k", field: nil)])
        #expect(EnvReferences.parse("A=has#hash") == [.value(name: "A", value: "has#hash")])
    }

    @Test func testAnUnknownProtocolVersionGetsOneThisSpeaks() throws {
        let b = bridge(Log())
        let hello = try #require(b.handle(#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#))
        #expect(!hello.contains("2099"))
        #expect(hello.contains("2025-06-18"))
    }

    @Test func testReferencesParseAndResolve() throws {
        let lines = EnvReferences.parse("""
            # a comment
            export PLAIN="hello"
            TOKEN=keyreeve://dir/a b.env#TOKEN
            WHOLE='keyreeve://k.txt'
            """)
        #expect(lines == [
            .value(name: "PLAIN", value: "hello"),
            .reference(name: "TOKEN", key: "dir/a b.env", field: "TOKEN"),
            .reference(name: "WHOLE", key: "k.txt", field: nil),
        ])
        #expect(try EnvReferences.value(in: Data("abc\n".utf8), field: nil) == "abc")
        #expect(try EnvReferences.value(in: Data("A=1\nB=\"two\"\n".utf8), field: "B") == "two")
        XCTAssertThrowsError(try EnvReferences.value(in: Data("A=1\nB=2\n".utf8), field: nil))
        XCTAssertThrowsError(try EnvReferences.value(in: Data("A=1\n".utf8), field: "Z"))
    }

    @Test func testTheTomlFileRoundTrips() throws {
        let policy = AgentPolicy(commands: ["dir/a b.env": ["/usr/local/bin/deploy", "./x \"y\".sh"], "z": ["/bin/ls"]])
        #expect(try AgentPolicy.parse(policy.toml) == policy)
        let handwritten = """
            # mine
            [[allow]]
            key = "a.env"   # note
            programs = [
            """
        XCTAssertThrowsError(try AgentPolicy.parse(handwritten))
        #expect(try AgentPolicy.parse("[[allow]]\nkey = \"a\"\nprograms = [\"/x\", \"/y\"]  # both\n").commands == ["a": ["/x", "/y"]])
    }

    @Test func testABadFileAllowsNothing() throws {
        for text in [
            "key = \"a\"", "[[allow]]\nkey = \"a\"", "[[allow]]\nprograms = [\"/x\"]", "[[allow]]\nkey = a\nprograms = []",
            "[[allow]]\nkey = \"a\"\nprograms = [\"/x\"]\nextra = 1", "[[allow]]\nkey = \"a\"\nkey = \"b\"\nprograms = []",
            "[[allow]]\nkey = \"a\" junk\nprograms = []",
        ] {
            XCTAssertThrowsError(try AgentPolicy.parse(text), text)
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("agents-\(UUID().uuidString).toml")
        defer { try? FileManager.default.removeItem(at: url) }
        try "nonsense".write(to: url, atomically: true, encoding: .utf8)
        #expect(AgentPolicy.load(from: url) == AgentPolicy())
        #expect(AgentPolicy.load(from: url.appendingPathExtension("missing")) == AgentPolicy())
    }

    @Test func testAProgramThatCouldLeakTheKeyIsNeverAllowed() throws {
        for program in ["sh", "/bin/bash", "/usr/bin/env", "printenv", "/usr/bin/python3", "/usr/bin/CURL"] {
            let log = Log()
            var arguments = run
            arguments["command"] = [program, "-c", "x"]
            let result = try call(bridge(log, commands: ["a.env": [program]]), "run_with_key", arguments)
            #expect(result.error, "\(program)")
            #expect(log.opened.isEmpty)
        }
        let listed = try call(bridge(Log(), commands: ["a.env": ["/bin/sh", "/opt/deploy"]]), "list_keys", [:]).text
        #expect(listed == "a.env: asks the person; run_with_key with /opt/deploy\nClosed, ask with request_access: other.env")
    }

    @Test func testFieldsFromOtherShapesOfFile() throws {
        #expect(try EnvReferences.value(in: Data(#"{"token":"abc","x":"y"}"#.utf8), field: "token") == "abc")
        #expect(try EnvReferences.value(in: Data("user: me\ntoken: abc\n".utf8), field: "token") == "abc")
    }
}
