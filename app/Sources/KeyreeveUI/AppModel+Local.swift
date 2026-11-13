import KeyreeveCatalog
import KeyreeveVault

/// A key a service of yours on this Mac checks, such as a server on 127.0.0.1:8790: approved for that one address with
/// your fingerprint, it goes there through the proxy, over plain HTTP, in place of a provider.
@MainActor
extension AppModel {
    /// The address approved for this key, or nil.
    public func approvedLocalService(of id: String) -> String? {
        LocalServices.load(from: files.localServices).approved[id]
    }

    public func approveLocalService(_ text: String, for id: String) {
        guard let address = LocalServices.address(text) else {
            message = T("Write 127.0.0.1, [::1] or localhost, a colon and the port, such as 127.0.0.1:8790")
            return
        }
        confirm(reason: FingerPrompt.local([(id, address)])) { confirmed in
            guard confirmed else {
                self.message = T("Not approved: it was not confirmed")
                return
            }
            do {
                try LocalServices.apply([id: address], keys: self.files.keyIndex, approvals: self.files.localServices)
                self.keyIndex = try KeyIndex.load(from: self.files.keyIndex)
                self.audit([(key: id, detail: "local service \(address) approved")])
                self.message = T("%@ goes to %@ from now on", id, address)
            } catch {
                self.message = (error as? VaultError)?.description ?? T("That identifier could not be saved")
            }
        }
    }

    /// Needs no finger: it only closes, and ends the key's permissions.
    public func removeLocalService(for id: String) {
        do {
            try LocalServices.remove(id, keys: files.keyIndex, approvals: files.localServices)
            keyIndex = try KeyIndex.load(from: files.keyIndex)
            audit([(key: id, detail: "local service removed")])
            endPermissions(of: id)
        } catch {
            message = (error as? VaultError)?.description ?? T("That identifier could not be saved")
        }
    }
}
