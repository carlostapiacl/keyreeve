import Foundation
import LocalAuthentication
import Testing

import KeyreeveCatalog
@testable import KeyreeveUI

@MainActor
struct FingerTests {
    /// A sensor that waits to be touched, and counts how many prompts were opened.
    final class Sensor: @unchecked Sendable {
        var waiting: [@Sendable (Bool) -> Void] = []
        func gate(canAsk: Bool = true) -> FingerGate {
            var gate = FingerGate()
            gate.canAsk = { _, _, _ in canAsk }
            gate.ask = { _, _, _, done in self.waiting.append(done) }
            return gate
        }
    }

    func model(_ sensor: Sensor, canAsk: Bool = true) -> AppModel {
        let model = AppModel(
            files: KeyreeveFiles(directory: FileManager.default.temporaryDirectory.appendingPathComponent("finger-\(UUID())")), binary: nil)
        model.fingerGate = sensor.gate(canAsk: canAsk)
        return model
    }

    func settle() async { for _ in 0..<5 { await Task.yield() } }

    @Test func testUnlockingTwiceOpensOnePrompt() async {
        let sensor = Sensor()
        let model = model(sensor)
        model.unlock()
        model.unlock()
        #expect(sensor.waiting.count == 1, "a second prompt would cancel the first")
        sensor.waiting[0](true)
        await settle()
        #expect(model.unlocked)
    }

    @Test func withTheSettingOffTheListOpensWithNoPrompt() async {
        let sensor = Sensor()
        let model = model(sensor)
        model.asksToOpenSetting = { false }
        model.unlock()
        await settle()
        #expect(model.unlocked)
        #expect(sensor.waiting.isEmpty)
    }

    @Test func aSecondRequestWhileOneIsOpenIsAnsweredAtOnce() async {
        let sensor = Sensor()
        let model = model(sensor)
        model.unlock()
        var second: Bool?
        _ = model.askFinger(LAContext(), .deviceOwnerAuthentication, "x") { second = $0 }
        await settle()
        #expect(second == false)
        #expect(model.lockMessage == nil)
        sensor.waiting[0](true)
        await settle()
        #expect(model.unlocked)
    }

    @Test func testAVaultRequestWaitsForTheOpenPrompt() async {
        let sensor = Sensor()
        let model = model(sensor)
        var answers = 0
        model.unlock()
        model.openVault(reason: "x") { _ in answers += 1 }
        #expect(sensor.waiting.count == 1)
        #expect(answers == 0)
    }

    @Test func testAfterAnAnswerTheNextRequestAsks() async {
        let sensor = Sensor()
        let model = model(sensor)
        model.unlock()
        sensor.waiting[0](false)
        await settle()
        #expect(!model.unlocked)
        model.unlock()
        #expect(sensor.waiting.count == 2, "a failed touch must not block the next try")
    }

    @Test func testAMacThatCannotAskSaysSo() async {
        let sensor = Sensor()
        let model = model(sensor, canAsk: false)
        model.unlock()
        #expect(sensor.waiting.isEmpty)
        #expect(model.lockMessage != nil)
        model.openVault(reason: "x") { _ in }
        #expect(model.message != nil)
    }
}
