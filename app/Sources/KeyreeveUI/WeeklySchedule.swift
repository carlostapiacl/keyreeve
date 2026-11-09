import Foundation
import KeyreeveCatalog

/// The weekly check, as a launch agent the system runs. It is off until you turn it on.
public enum WeeklySchedule {
    static let label = "io.github.carlostapiacl.keyreeve.weekly"

    static var file: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    }

    public static var isOn: Bool { FileManager.default.fileExists(atPath: file.path) }

    public static func plist(binary: URL, spanish: Bool) throws -> Data {
        var arguments = [binary.path, "check-free", "--notify"]
        if spanish { arguments.append("--spanish") }
        let description: [String: Any] = [
            "Label": label,
            "ProgramArguments": arguments,
            "StartCalendarInterval": ["Weekday": 1, "Hour": 10, "Minute": 0],
            "ProcessType": "Background",
        ]
        return try PropertyListSerialization.data(fromPropertyList: description, format: .xml, options: 0)
    }

    public static func set(_ on: Bool, binary: URL?) {
        let domain = "gui/\(getuid())"
        launchctl(["bootout", domain, file.path])
        guard on, let binary else {
            try? FileManager.default.removeItem(at: file)
            return
        }
        let spanish = Language.current.resolved == .spanish
        guard let data = try? plist(binary: binary, spanish: spanish) else { return }
        try? FileManager.default.createDirectory(
            at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: file, options: .atomic)
        launchctl(["bootstrap", domain, file.path])
    }

    private static func launchctl(_ arguments: [String]) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }
}
