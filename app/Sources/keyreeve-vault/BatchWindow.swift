import AppKit
import Foundation
import KeyreeveVault

// One window for several keys: every key with a tick, how long, Allow and Deny. The fingerprint comes after, once,
// with keyreeve's own words. A closed window or Deny is a no.

/// Shows the window and returns the rows left ticked and the duration chosen, or nil for a no.
func chooseKeys(title: String, intro: String, rows: [String], durations: [String], selected: Int) -> (ticked: [Int], duration: Int)? {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title
    alert.informativeText = intro
    let width: CGFloat = 460
    let rowHeight: CGFloat = 22
    let list = NSView(frame: NSRect(x: 0, y: 0, width: width, height: CGFloat(rows.count) * rowHeight))
    var boxes: [NSButton] = []
    for (at, row) in rows.enumerated() {
        let box = NSButton(checkboxWithTitle: row, target: nil, action: nil)
        box.state = .on
        box.lineBreakMode = .byTruncatingMiddle
        box.frame = NSRect(x: 0, y: CGFloat(rows.count - 1 - at) * rowHeight, width: width, height: rowHeight)
        list.addSubview(box)
        boxes.append(box)
    }
    let shown = min(CGFloat(rows.count) * rowHeight, 300)
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 36, width: width, height: shown))
    scroll.documentView = list
    scroll.hasVerticalScroller = CGFloat(rows.count) * rowHeight > shown
    scroll.drawsBackground = false
    list.scroll(NSPoint(x: 0, y: list.frame.height))
    let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 300, height: 26), pullsDown: false)
    popup.addItems(withTitles: durations)
    popup.selectItem(at: max(0, min(selected, durations.count - 1)))
    let holder = NSView(frame: NSRect(x: 0, y: 0, width: width, height: shown + 40))
    holder.addSubview(scroll)
    holder.addSubview(popup)
    alert.accessoryView = holder
    alert.addButton(withTitle: spanish ? "Permitir las marcadas" : "Allow the ticked ones")
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    guard answered(alert) == 0 else { return nil }
    return (boxes.indices.filter { boxes[$0].state == .on }, popup.indexOfSelectedItem)
}

/// `keyreeve-vault choose`: the key service runs this to show its window, since the service itself has no screen of
/// its own. It reads the keys on stdin and prints what the person chose, or nothing for a no.
func chooseFromService() throws {
    let input = FileHandle.standardInput.readDataToEndOfFile()
    guard let batch = try? JSONDecoder().decode(KeyBatch.self, from: input), !batch.items.isEmpty else { exit(2) }
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let programs = Set(batch.items.map(\.program))
    let agents = Set(batch.items.map { $0.agent ?? "" })
    let reasons = Set(batch.items.map { $0.reason ?? "" })
    let who = agents.count == 1 && !(agents.first ?? "").isEmpty ? agents.first! : (programs.count == 1 ? programs.first! : (spanish ? "Varios programas" : "Several programs"))
    let title = spanish ? "\(who) quiere usar \(batch.items.count) claves" : "\(who) wants to use \(batch.items.count) keys"
    var lines: [String] = []
    if programs.count == 1 { lines.append((spanish ? "Programa: " : "Program: ") + programs.first!) }
    if let folder = batch.folder { lines.append((spanish ? "Carpeta: " : "Folder: ") + (folder as NSString).abbreviatingWithTildeInPath) }
    if let set = batch.set { lines.append((spanish ? "Conjunto: " : "Set: ") + set) }
    if reasons.count == 1, let reason = reasons.first, !reason.isEmpty {
        lines.append("")
        lines.append((spanish ? "Lo que dice, en sus palabras:\n" : "What it says, in its own words:\n") + "\u{201C}\(reason)\u{201D}")
    }
    lines.append("")
    lines.append(spanish
        ? "Desmarca las que no quieras. Una huella abre el resto, con stand-ins y solo hacia su proveedor."
        : "Untick what you do not want. One fingerprint opens the rest, with stand-ins and only towards their provider.")
    let rows = batch.items.map { item -> String in
        var row = item.key + (item.account.map { " (\($0))" } ?? "")
        if programs.count > 1 { row += " · " + item.program }
        if agents.count > 1, let agent = item.agent { row += " · " + agent }
        if reasons.count > 1, let reason = item.reason, !reason.isEmpty { row += " · \u{201C}\(reason)\u{201D}" }
        return row
    }
    let program = programs.count == 1 ? programs.first : nil
    let labels = batch.choices.map { KeyBatch.label($0, program: program, folder: batch.folder, spanish: spanish) }
    guard let chosen = chooseKeys(
        title: title, intro: lines.joined(separator: "\n"), rows: rows, durations: labels,
        selected: batch.choices.firstIndex(of: batch.suggested) ?? 0)
    else { exit(1) }
    let answer = KeyBatch.Answer(chosen: chosen.ticked, lasts: batch.choices[chosen.duration])
    FileHandle.standardOutput.write(try JSONEncoder().encode(answer))
}

/// The service's side: shows the window through `choose`, and waits at most until just before the caller gives up.
func askChoice(_ batch: KeyBatch) -> KeyBatch.Answer? {
    guard let input = try? JSONEncoder().encode(batch) else { return nil }
    let process = Process()
    process.executableURL = ownPath()
    process.arguments = ["choose"]
    let stdin = Pipe()
    let stdout = Pipe()
    process.standardInput = stdin
    process.standardOutput = stdout
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return nil }
    stdin.fileHandleForWriting.write(input)
    try? stdin.fileHandleForWriting.close()
    let finished = DispatchSemaphore(value: 0)
    final class Box: @unchecked Sendable { var data = Data() }
    let box = Box()
    DispatchQueue.global().async {
        box.data = stdout.fileHandleForReading.readDataToEndOfFile()
        finished.signal()
    }
    // The client waits two minutes for the whole answer, and the fingerprint comes after this.
    guard finished.wait(timeout: .now() + 90) == .success else {
        process.terminate()
        return nil
    }
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { return nil }
    return try? JSONDecoder().decode(KeyBatch.Answer.self, from: box.data)
}

/// An agent asking for several closed keys with request_access: one window, every key ticked, and for how long.
func askAccessMany(_ batch: AccessBatch) -> AccessBatch.Answer? {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let title = spanish ? "\(batch.agent) pide \(batch.items.count) claves" : "\(batch.agent) asks for \(batch.items.count) keys"
    let intro = spanish
        ? "Lo que dice el agente, en sus palabras:\n\u{201C}\(batch.reason)\u{201D}\n\nSugiere: \(batch.hours.map { "\($0) h" } ?? "siempre").\n\nDesmarca las que no quieras. Una huella abre el resto y no vuelve a preguntar hasta que pase el tiempo o salgas de Keyreeve."
        : "What the agent says, in its own words:\n\u{201C}\(batch.reason)\u{201D}\n\nIt suggests: \(batch.hours.map { "\($0) h" } ?? "always").\n\nUntick what you do not want. One fingerprint opens the rest, and nothing more is asked until the time is up or you quit Keyreeve."
    let choices: [Int?] = AccessDecision.hourChoices.map { $0 } + [nil]
    let labels = choices.map { hours in
        hours.map { spanish ? "Por \($0) h" : "For \($0) h" } ?? (spanish ? "Siempre" : "Always")
    }
    let rows = batch.items.map { item in
        item.key + ([item.provider, item.account].compactMap { $0 }.isEmpty ? "" : " (" + [item.provider, item.account].compactMap { $0 }.joined(separator: ", ") + ")")
    }
    guard let chosen = chooseKeys(
        title: title, intro: intro, rows: rows, durations: labels,
        selected: choices.firstIndex(of: AccessDecision.startingHours(for: batch.hours)) ?? 0)
    else { return nil }
    return AccessBatch.Answer(keys: chosen.ticked.map { batch.items[$0].key }, hours: choices[chosen.duration])
}
