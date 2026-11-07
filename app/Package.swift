// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "keyreeve-app",
    platforms: [.macOS("14.0")],
    products: [
        .library(name: "KeyreeveVault", targets: ["KeyreeveVault"]),
        .executable(name: "keyreeve-vault", targets: ["keyreeve-vault"]),
        .executable(name: "Keyreeve", targets: ["Keyreeve"]),
    ],
    targets: [
        .target(name: "KeyreeveVault"),
        .target(name: "KeyreeveCatalog"),
        .target(name: "KeyreeveUI", dependencies: ["KeyreeveCatalog", "KeyreeveVault"]),
        .executableTarget(name: "keyreeve-vault", dependencies: ["KeyreeveVault"]),
        .executableTarget(name: "Keyreeve", dependencies: ["KeyreeveUI"]),
        .testTarget(
            name: "KeyreeveTests",
            dependencies: ["KeyreeveVault", "KeyreeveCatalog", "KeyreeveUI"]
        ),
    ]
)
