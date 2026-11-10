import AppKit
import Foundation
import KeyreeveVault

// The windows an agent server shows the person. Each asks one thing, and the fingerprint comes after,
// with keyreeve's own words.

/// A window that shows what the agent asks for and lets the person choose how long a yes lasts.
/// The fingerprint comes after, with keyreeve's own words.
func askApproval(_ request: AgentRequest) -> AgentApproval? {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let labels: [String: String] = spanish
        ? ["Once": "Solo esta vez", "1 hour": "1 hora", "4 hours": "4 horas", "8 hours": "8 horas", "24 hours": "24 horas"]
        : [:]
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = spanish
        ? "Un agente quiere usar la clave \(request.key)"
        : "An agent wants to use the key \(request.key)"
    let said = request.reason.isEmpty ? "-" : "\u{201C}\(request.reason)\u{201D}"
    let command = request.command.isEmpty ? request.program : request.command
    alert.informativeText = spanish
        ? "Comando:\n\(command)\n\nLo que dice el agente, en sus palabras:\n\(said)\n\nDespués te pide la huella. Si eliges horas, vale para \(request.program) con esta clave hasta que pase el tiempo o salgas de Keyreeve."
        : "Command:\n\(command)\n\nWhat the agent says, in its own words:\n\(said)\n\nYour fingerprint comes next. Hours cover \(request.program) with this key until the time is up or you quit Keyreeve."
    for choice in AgentApproval.choices {
        alert.addButton(withTitle: labels[choice.label] ?? choice.label)
    }
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    let answer = answered(alert)
    guard answer >= 0, answer < AgentApproval.choices.count else { return nil }
    return AgentApproval.choices[answer].approval
}

/// Shows the alert and takes it down. This process goes back to reading stdin and never runs an event
/// loop, so the window would stay on screen after the click: it is ordered out and the window server
/// hears it before going on. The answer counts from the first button.
func answered(_ alert: NSAlert) -> Int {
    let app = NSApplication.shared
    let answer = alert.runModal().rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
    alert.window.orderOut(nil)
    let until = Date().addingTimeInterval(0.1)
    while let event = app.nextEvent(matching: .any, until: until, inMode: .default, dequeue: true) {
        app.sendEvent(event)
    }
    return answer
}

/// A window for an agent asking to open a closed key: allow it for some time, or not. The agent's
/// suggestion is selected, and the person can change it.
func askAccess(_ request: AccessRequest) -> AccessDecision? {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .warning
    let provider = request.provider.map { " (\($0))" } ?? ""
    alert.messageText = spanish
        ? "\(request.agent) pide la clave \(request.key)\(provider)"
        : "\(request.agent) asks for the key \(request.key)\(provider)"
    alert.informativeText = spanish
        ? "Lo que dice el agente, en sus palabras:\n\u{201C}\(request.reason)\u{201D}\n\nSugiere: \(request.hours.map { "\($0) h" } ?? "siempre").\n\nSi permites, te pide la huella una vez y no vuelve a preguntar hasta que pase el tiempo o salgas de Keyreeve. Lo cambias cuando quieras en Agentes."
        : "What the agent says, in its own words:\n\u{201C}\(request.reason)\u{201D}\n\nIt suggests: \(request.hours.map { "\($0) h" } ?? "always").\n\nIf you allow it, your fingerprint is asked once, and nothing more until the time is up or you quit Keyreeve. Change it any time under Agents."
    let durations = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 220, height: 26), pullsDown: false)
    let choices: [Int?] = AccessDecision.hourChoices.map { $0 } + [nil]
    for hours in choices {
        if let hours {
            durations.addItem(withTitle: spanish ? "Por \(hours) h" : "For \(hours) h")
        } else {
            durations.addItem(withTitle: spanish ? "Siempre" : "Always")
        }
    }
    durations.selectItem(at: choices.firstIndex(of: AccessDecision.startingHours(for: request.hours)) ?? 0)
    alert.accessoryView = durations
    alert.addButton(withTitle: spanish ? "Permitir" : "Allow")
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    guard answered(alert) == 0 else { return nil }
    return AccessDecision(hours: choices[durations.indexOfSelectedItem])
}

/// Asks whether agents may use a key with no fingerprint at all. It starts on keeping the key as it is: Return and
/// Escape both keep it, and only a click on the other button changes it.
func askNoFingerprint(_ request: AccessRequest) -> Bool {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .critical
    let provider = request.provider.map { " (\($0))" } ?? ""
    alert.messageText = spanish
        ? "\(request.agent) pide usar \(request.key)\(provider) sin huella, siempre"
        : "\(request.agent) asks to use \(request.key)\(provider) with no fingerprint, always"
    alert.informativeText = spanish
        ? "Lo que dice el agente, en sus palabras:\n\u{201C}\(request.reason)\u{201D}\n\nSi aceptas, pones la huella una vez y desde ahí los agentes usan esta clave a través del proxy sin preguntarte, también después de reiniciar. Cualquier programa que corra con tu usuario podría usarla así mientras la Mac esté desbloqueada. Úsalo solo para claves que hacen poco daño. Lo quitas cuando quieras en Agentes."
        : "What the agent says, in its own words:\n\u{201C}\(request.reason)\u{201D}\n\nIf you accept, you give your finger once, and from then on agents use this key through the proxy with no question, after a restart too. Any program running as you could use it that way while this Mac is unlocked. Keep it for keys that can do little harm. Take it off any time under Agents."
    let keep = alert.addButton(withTitle: spanish ? "Dejar como está" : "Keep it as it is")
    keep.keyEquivalent = "\r"
    let allow = alert.addButton(withTitle: spanish ? "Siempre, sin huella" : "Always, no fingerprint")
    allow.keyEquivalent = ""
    alert.window.level = .floating
    return answered(alert) == 1
}

/// Tells the person an agent asked for a key that is not saved yet. Saving happens in the app, which
/// knows the keys folder, so this only offers to open it.
func announceRequest(_ request: AccessRequests.Entry) -> AgentBridge.Announcement {
    let spanish = Locale.preferredLanguages.first?.hasPrefix("es") ?? false
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    app.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.alertStyle = .informational
    let said = request.reason.map { "\u{201C}\($0)\u{201D}" } ?? "-"
    if request.kind == "sort" {
        alert.messageText = spanish ? "\(request.agent) propone ordenar tus claves" : "\(request.agent) proposes sorting your keys"
        alert.informativeText = spanish
            ? "Lo que dice el agente, en sus palabras:\n\(said)\n\nEn Keyreeve ves cada cambio y aplicas los que quieras. Nada cambia antes."
            : "What the agent says, in its own words:\n\(said)\n\nIn Keyreeve you see each change and apply the ones you want. Nothing changes before."
    } else if request.kind == AgentBringing.kind {
        alert.messageText = spanish ? "\(request.agent) propone traer claves a tu bóveda" : "\(request.agent) proposes bringing keys into your vault"
        alert.informativeText = spanish
            ? "Lo que dice el agente, en sus palabras:\n\(said)\n\nEn Keyreeve ves sus sugerencias, cambias lo que quieras y sellas con tu huella. Nada se sella antes."
            : "What the agent says, in its own words:\n\(said)\n\nIn Keyreeve you see its suggestions, change what you want and seal with your fingerprint. Nothing is sealed before."
    } else if request.isRotation {
        let key = request.key ?? request.provider
        alert.messageText = spanish ? "\(request.agent) pide rotar \(key)" : "\(request.agent) asks to rotate \(key)"
        alert.informativeText = spanish
            ? "Lo que dice el agente, en sus palabras:\n\(said)\n\nEn Keyreeve ves dónde se reemplaza y lo apruebas con tu huella. El agente no ve ninguna de las dos claves."
            : "What the agent says, in its own words:\n\(said)\n\nIn Keyreeve you see where it is replaced and approve it with your fingerprint. The agent sees neither key."
    } else {
        alert.messageText = spanish
            ? "\(request.agent) pide una clave de \(request.provider)"
            : "\(request.agent) asks for a \(request.provider) key"
        alert.informativeText = spanish
            ? "Lo que dice el agente, en sus palabras:\n\(said)\n\nTodavía no tienes una clave de \(request.provider) guardada. En Keyreeve eliges cuál, se guarda y queda permitida en un paso."
            : "What the agent says, in its own words:\n\(said)\n\nNo \(request.provider) key is saved yet. In Keyreeve you choose which, and it is saved and allowed in one step."
    }
    alert.addButton(withTitle: spanish ? "Abrir Keyreeve" : "Open Keyreeve")
    alert.addButton(withTitle: spanish ? "Ahora no" : "Not now")
    let deny = alert.addButton(withTitle: spanish ? "No permitir" : "Deny")
    deny.keyEquivalent = "\u{1b}"
    alert.window.level = .floating
    switch answered(alert) {
    case 0:
        // open(1) hands it to Launch Services at once; this process never runs the loop an async open needs.
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = ["-b", "io.github.carlostapiacl.keyreeve"]
        open.standardError = FileHandle.nullDevice
        open.standardInput = FileHandle.nullDevice
        try? open.run()
        return .open
    case 1: return .later
    default: return .deny
    }
}
