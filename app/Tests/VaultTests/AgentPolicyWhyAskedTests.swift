import Foundation
import KeyreeveVault
import Testing

/// Why a key marked "always, no fingerprint" asked for one: the words the log keeps.
struct AgentPolicyWhyAskedTests {
    let policy = try! AgentPolicy.parse("""
        [[key]]
        key = "bot"
        level = "always"
        agents = ["claude"]

        [[key]]
        key = "open"
        level = "always"

        [[key]]
        key = "plain"
        level = "free"

        [[key]]
        key = "ended"
        level = "always"
        until = "2026-01-01T00:00:00Z"
        """)

    @Test func aKeyNotMarkedAlwaysHasNothingToSay() {
        #expect(policy.whyAsked(key: "plain", agent: "claude", hasCopy: false, paused: false) == nil)
        #expect(policy.whyAsked(key: "unknown", agent: "claude", hasCopy: false, paused: false) == nil)
    }

    @Test func eachReasonIsNamed() {
        #expect(policy.whyAsked(key: "bot", agent: "wapentakebot", hasCopy: true, paused: false)
            == "always is only for claude, and this was wapentakebot")
        #expect(policy.whyAsked(key: "bot", agent: nil, hasCopy: true, paused: false)
            == "always is only for claude, and this was an agent with no name")
        #expect(policy.whyAsked(key: "open", agent: "x", hasCopy: true, paused: true) == "always, but agents are paused")
        #expect(policy.whyAsked(key: "open", agent: "x", hasCopy: false, paused: false)
            == "always, but its copy for no fingerprint is missing: mark it again")
        #expect(policy.whyAsked(key: "ended", agent: "x", hasCopy: true, paused: false) == "always ended when its time was up")
        #expect(policy.whyAsked(key: "open", agent: "x", hasCopy: true, paused: false) == nil)
    }
}
