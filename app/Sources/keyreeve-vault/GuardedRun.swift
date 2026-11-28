import Foundation
import KeyreeveVault

/// Runs the command with the environment this process has now, hiding these values in what it prints (see
/// HidingRunner), and exits as it does. With nothing to hide, or only a terminal to print on, the command takes this
/// process's place, as before.
func runHiding(_ secrets: [Data], command: [String]) -> Never {
    let redactor = OutputRedactor(secrets: secrets)
    let streams = HidingRunner.piped()
    if redactor.isEmpty || streams.isEmpty {
        var pointers: [UnsafeMutablePointer<CChar>?] = command.map { strdup($0) } + [nil]
        execvp(command[0], &pointers)
        fail("could not run \(command[0])")
    }
    exit(HidingRunner.spawn(command, redactor: redactor, streams: streams))
}
