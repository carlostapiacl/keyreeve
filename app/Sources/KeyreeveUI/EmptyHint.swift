import KeyreeveCatalog
import SwiftUI

/// An empty place that says why it is empty and offers the one next step.
struct EmptyHint: View {
    let title: String
    let text: String
    var action: String?
    var run: (() -> Void)?

    var body: some View {
        VStack(spacing: 10) {
            Text(title).font(Theme.section).foregroundStyle(Theme.text)
            Text(text).font(Theme.body).foregroundStyle(Theme.muted)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 380)
            if let action, let run {
                Button(action, action: run).buttonStyle(KRButtonStyle(primary: true)).padding(.top, 2)
            }
        }
        .padding(28)
        .frame(maxWidth: .infinity)
    }
}
