import AppKit
import CryptoKit
import KeyreeveCatalog
import KeyreeveVault

@MainActor
extension AppModel {
    /// Makes the chip's key and the recovery key, and keeps both in memory for the next screen.
    public func startVault() {
        guard !vaultStore.exists else { return }
        do {
            let (enclave, blob) = try EnclaveRecipient.create()
            vaultDraft = VaultDraft(enclave: enclave, blob: blob, recovery: P256.KeyAgreement.PrivateKey())
        } catch {
            message = T("This Mac could not create a key in its chip")
        }
    }

    public func finishVault() {
        guard let draft = vaultDraft else { return }
        do {
            try draft.save(to: vaultStore)
            message = T("Your vault is ready")
        } catch {
            message = T("The vault could not be saved")
        }
        hasVault = vaultStore.exists
        vaultDraft = nil
        load()
    }

    public func cancelVault() { vaultDraft = nil }

    /// Seals the changed files again. Their old copies stay sealed, so nothing is lost.
    public func sealAgain(_ chosen: [CatalogItem]) {
        guard !busy, !chosen.isEmpty, let folder = keysFolder else { return }
        let store = vaultStore
        let paths = chosen.map(\.path)
        // A rotation in progress has its own idea of the current key, and revoking by it would
        // leave this copy dead.
        let open = Set(rotations.filter(\.isOpen).map(\.key))
        guard paths.allSatisfy({ !open.contains($0) }) else {
            message = T("Close this key's open rotation before sealing it again.")
            return
        }
        do {
            if let binary {
                for path in paths { try CheckRunner.forgetRotationID(of: path, binary: binary, files: files) }
            }
            let report = try VaultKeeper.sealAgain(paths: paths, folder: folder, store: store)
            message = report.sealed.count == 1 ? T("1 key sealed") : T("%d keys sealed", report.sealed.count)
        } catch {
            message = T("The vault could not be saved")
        }
        load()
    }

    var movedOriginals: MovedOriginals {
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.dateFormat = "yyyy-MM-dd"
        return MovedOriginals(
            ledger: files.moved, destination: files.originals.appendingPathComponent(format.string(from: Date())))
    }

    /// Moves the files that the last comparison proved match their sealed copies, and only those.
    public func moveOriginals() {
        guard !busy, let folder = keysFolder, let report = vaultComparison, !report.same.isEmpty else { return }
        do {
            let matching = VaultKeeper.stillMatching(report, folder: folder)
            let moved = try movedOriginals.move(matching, from: folder, inventory: files.inventory)
            vaultComparison = nil
            message =
                moved.count == report.same.count
                ? T("%d originals moved to %@", moved.count, files.originals.path)
                : T("%d moved. The rest changed since the comparison, so compare again.", moved.count)
            refresh()
        } catch {
            message = T("The files could not be moved")
        }
    }

    public func putOriginalsBack(_ chosen: [CatalogItem]) {
        guard !busy, let folder = keysFolder else { return }
        do {
            let restored = try movedOriginals.putBack(chosen.map(\.path), to: folder)
            message = T("%d originals put back", restored.count)
            refresh()
        } catch {
            message = T("The files could not be moved")
        }
    }

    public func showOriginals() { NSWorkspace.shared.open(files.originals) }
}
