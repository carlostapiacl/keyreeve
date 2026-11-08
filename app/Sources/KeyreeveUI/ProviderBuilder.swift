import Foundation
import KeyreeveCatalog

/// Making a provider file, in basic use (describe it and an assistant drafts it) or advanced use (the whole
/// file, field by field or as text). Either way it is checked by keyreeve's own check and simulate, read in
/// plain words, and saved only when the person says so. Saving leaves it waiting for approval like any other.
@MainActor
public final class ProviderBuilder: ObservableObject {
    public enum Phase: Equatable {
        case writing
        case asking
        case ready
        case failed(String)
        case saved(String)
    }

    @Published public var description = ""
    @Published public var yaml = ""
    @Published public var report: CheckRunner.RecipeReport?
    @Published public var phase: Phase = .writing
    @Published public var advanced = false
    /// A provider keyreeve already ships that the description names, offered before drafting a new one.
    @Published public var offered: ProviderInfo?
    /// Set when the file being edited is one of the person's own, so saving replaces it.
    @Published public var editing: String?

    typealias Draft = @Sendable (Assistant, String) throws -> (yaml: String, report: CheckRunner.RecipeReport)
    let draft: Draft
    let validate: @Sendable (String) throws -> CheckRunner.RecipeReport
    let save: (String) throws -> String
    /// A shipped recipe's text, to start one of your own from all of it.
    let shipped: (String) -> String?
    private var generation = 0

    init(
        draft: @escaping Draft, validate: @escaping @Sendable (String) throws -> CheckRunner.RecipeReport,
        save: @escaping (String) throws -> String, shipped: @escaping (String) -> String? = { _ in nil }
    ) {
        self.draft = draft
        self.validate = validate
        self.save = save
        self.shipped = shipped
    }

    /// Builds one against the app's command and folder.
    public convenience init(model: AppModel) {
        let binary = model.commandURL
        let files = model.files
        self.init(
            draft: { assistant, text in
                guard let binary else { throw CheckError(T("This app was built without its command")) }
                return try Assistants.draftRecipe(assistant, describing: text) { try CheckRunner.validateRecipe($0, binary: binary) }
            },
            validate: { text in
                guard let binary else { throw CheckError(T("This app was built without its command")) }
                return try CheckRunner.validateRecipe(text, binary: binary)
            },
            save: { text in
                guard let binary else { throw CheckError(T("This app was built without its command")) }
                return try CheckRunner.saveProvider(text, binary: binary, files: files)
            },
            shipped: { id in binary.flatMap { CheckRunner.builtinRecipe(id, binary: $0) } })
    }

    public var summary: RecipeSummary { RecipeSummary(yaml) }

    /// True when the description names a provider that ships, which is then offered instead.
    @discardableResult
    public func lookForExisting(in directory: ProviderDirectory) -> Bool {
        offered = directory.shipped(matching: description)
        return offered != nil
    }

    /// Asks the assistant in the background. A newer request or a cancel makes the answer of this one land nowhere.
    public func ask(_ assistant: Assistant) {
        let text = description.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        generation += 1
        let current = generation
        phase = .asking
        report = nil
        let draft = self.draft
        Task.detached {
            let result = Result { try draft(assistant, text) }
            await MainActor.run {
                guard current == self.generation else { return }
                switch result {
                case .success(let answer):
                    self.yaml = answer.yaml
                    self.report = answer.report
                    self.phase = answer.report.ok ? .ready : .failed(answer.report.lines.last ?? T("That provider file is not valid"))
                case .failure(let error):
                    self.phase = .failed((error as? CheckError)?.description ?? T("%@ did not answer", assistant.name))
                }
            }
        }
    }

    /// Stops waiting. The assistant's own process ends on its deadline; what it says then is dropped.
    public func cancel() {
        // Only this window's assistant: one sorting keys in another window keeps working.
        Assistants.stopAll(task: "provider")
        generation += 1
        phase = .writing
    }

    public func check() {
        do {
            let result = try validate(yaml)
            report = result
            phase = result.ok ? .ready : .failed(result.lines.last ?? T("That provider file is not valid"))
        } catch {
            phase = .failed((error as? CheckError)?.description ?? T("That provider file is not valid"))
        }
    }

    /// Saves it among the person's providers, where it waits for approval. Returns its id.
    @discardableResult
    public func saveNow() -> String? {
        do {
            let id = try save(yaml)
            phase = .saved(id)
            return id
        } catch {
            phase = .failed((error as? CheckError)?.description ?? T("That provider file is not valid"))
            return nil
        }
    }

    /// A start for one of your own, from what the app already knows of a provider: its name, hosts, page,
    /// prefixes and variable. The request that checks a key is left for you or the assistant to write.
    public func start(from info: ProviderInfo) {
        // The whole recipe when it ships, so nothing it knows is lost; else what the app knows of it.
        if let text = shipped(info.id) {
            yaml = CheckRunner.ownCopy(of: text, id: info.id)
            editing = nil
            advanced = true
            report = nil
            phase = .writing
            return
        }
        var lines = ["schema: 1", "provider: \(info.id)-mine", "name: \(info.name.isEmpty ? info.id : info.name) (mine)"]
        if let dashboard = info.dashboard { lines.append("dashboard: \(dashboard)") }
        if let prefixes = info.prefixes, !prefixes.isEmpty { lines.append("prefixes: [\(prefixes.joined(separator: ", "))]") }
        if let variable = info.env_var { lines.append("env_var: \(variable)") }
        lines.append("hosts: [\(info.hosts.joined(separator: ", "))]")
        lines.append("auth: { header: Authorization, prefix: \"Bearer \" }")
        lines.append("verify: { method: GET, path: /replace-me }")
        yaml = lines.joined(separator: "\n") + "\n"
        editing = nil
        advanced = true
        report = nil
        phase = .writing
    }

    /// Opens one of your own files to change it.
    public func edit(_ text: String, id: String) {
        yaml = text
        editing = id
        advanced = true
        report = nil
        phase = .writing
    }

    /// The file of one of your own providers, found by the id it declares.
    public static func ownFile(_ id: String, in folder: URL) -> String? {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: folder.path)) ?? []
        for name in names where name.hasSuffix(".yaml") || name.hasSuffix(".yml") {
            if let text = try? String(contentsOf: folder.appendingPathComponent(name), encoding: .utf8),
                CheckRunner.providerID(in: text) == id
            {
                return text
            }
        }
        return nil
    }
}
