import Foundation

/// Files only this user can read, written whole or not at all, with no change to the process's umask:
/// that is shared by every thread, and changing it for one write can leave another write open to others.
public enum PrivateFile {
    /// Makes the folder at 0700 when it is missing. One that is there keeps its mode: it may be shared
    /// on purpose, and changing it is not this file's business.
    public static func folder(_ url: URL) throws {
        guard !FileManager.default.fileExists(atPath: url.path) else { return }
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        guard chmod(url.path, 0o700) == 0 else { throw VaultError("\(url.lastPathComponent) could not be made private") }
    }

    /// Writes beside the target at 0600 from the first byte, reaches the disk, then takes its place.
    public static func write(_ data: Data, to url: URL) throws {
        let folder = url.deletingLastPathComponent()
        try Self.folder(folder)
        let temp = folder.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString)")
        let descriptor = open(temp.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw VaultError("\(url.lastPathComponent) could not be saved") }
        var saved = false
        defer {
            close(descriptor)
            if !saved { unlink(temp.path) }
        }
        // The mode asked for is masked by the umask; this makes it exactly 0600 whatever that is.
        guard fchmod(descriptor, 0o600) == 0 else { throw VaultError("\(url.lastPathComponent) could not be saved") }
        try data.withUnsafeBytes { (bytes: UnsafeRawBufferPointer) in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(descriptor, bytes.baseAddress! + offset, bytes.count - offset)
                guard written > 0 else { throw VaultError("\(url.lastPathComponent) could not be saved") }
                offset += written
            }
        }
        guard fsync(descriptor) == 0, rename(temp.path, url.path) == 0 else {
            throw VaultError("\(url.lastPathComponent) could not be saved")
        }
        saved = true
    }
}
