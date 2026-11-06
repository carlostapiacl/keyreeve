import AppKit
import KeyreeveCatalog
import SwiftUI

public struct LockedView: View {
    let message: String?
    let unlock: () -> Void

    public init(message: String?, unlock: @escaping () -> Void) {
        self.message = message
        self.unlock = unlock
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "touchid")
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(Theme.accent)
            Text(T("Keyreeve is locked")).font(.system(size: 17, weight: .semibold)).foregroundStyle(Theme.text)
            if let message {
                Text(message).foregroundStyle(Theme.muted).multilineTextAlignment(.center)
            }
            Button(T("Unlock"), action: unlock)
                .buttonStyle(KRButtonStyle(primary: true))
                .keyboardShortcut(.defaultAction)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
    }
}

/// The first screen anyone sees: one decision, and no Terminal.
public struct WelcomeView: View {
    let choose: () -> Void
    let busy: Bool

    public init(busy: Bool = false, choose: @escaping () -> Void) {
        self.busy = busy
        self.choose = choose
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "key.fill")
                .font(.system(size: 34))
                .foregroundStyle(Theme.accent)
                .frame(width: 72, height: 72)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 18))
                .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(Theme.border))
            Text(T("Your keys, without showing them")).font(Theme.title).foregroundStyle(Theme.text)
            Text(T("A short list of what to do, and a way to confirm it got done.")).foregroundStyle(Theme.muted)
            if busy {
                ProgressView().controlSize(.small).padding(.top, 6)
            } else {
                Button(T("Choose your keys folder"), action: choose)
                    .buttonStyle(KRButtonStyle(primary: true))
                    .keyboardShortcut(.defaultAction)
                    .padding(.top, 6)
            }
            Text(T("Scanning sends nothing out of this Mac. Keyreeve reads your files to describe them, and saves no value."))
                .font(Theme.caption)
                .foregroundStyle(Theme.muted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 420)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
    }
}
