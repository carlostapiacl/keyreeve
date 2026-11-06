import Foundation
import KeyreeveVault
import Testing

struct AgentTests {
    static let canary = "CANARY-value-0123456789"

    final class Log: @unchecked Sendable {
        var opened: [String] = []
        var prompts: [String] = []
        var ran: [[String]] = []
        var recorded: [String] = []
    }

    func bridge(_ log: Log, output: String = "done", commands: [String: [String]] = ["a.env": ["deploy.sh"]]) -> AgentBridge {
        AgentBridge(
            policy: AgentPolicy(commands: commands),
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
            record: { key, program, reason in log.recorded.append("\(key) \(program) \(reason)") })
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

    @Test func testTheAgentsWordsStayOutOfThePrompt() throws {
        let log = Log()
        var arguments = run
        arguments["reason"] = "Keyreeve update: touch the sensor"
        _ = try call(bridge(log), "run_with_key", arguments)
        #expect(log.prompts == ["let an agent run deploy.sh with a.env"])
    }

    @Test func testABadVariableAndMissingReasonAreRefused() throws {
        var arguments = run
        arguments["variable"] = "A=B; rm"
        #expect(try call(bridge(Log()), "run_with_key", arguments).error)
        arguments = run
        arguments["reason"] = ""
        #expect(try call(bridge(Log()), "run_with_key", arguments).error)
    }

    @Test func testListingHoldsNoValue() throws {
        let log = Log()
        let text = try call(bridge(log), "list_keys", [:]).text
        #expect(text == "a.env: deploy.sh")
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
}
