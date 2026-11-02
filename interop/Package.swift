// swift-tools-version: 6.0
import PackageDescription

// Swift Ivy, at the release this port follows, for interop/run.sh.
let package = Package(
    name: "interop",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/0xLattice/Ivy2.git", exact: "3.1.1"),
        .package(url: "https://github.com/0xLattice/Tally.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"6.0.0"),
    ],
    targets: [
        .executableTarget(name: "admission-trace", dependencies: [.product(name: "IvyCore", package: "Ivy2"), "Tally", .product(name: "Crypto", package: "swift-crypto")], swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "simulation-trace", dependencies: [.product(name: "IvyCore", package: "Ivy2"), .product(name: "IvySimulation", package: "Ivy2"), "Tally", .product(name: "Crypto", package: "swift-crypto")], swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name: "simulation-digest", dependencies: [.product(name: "IvyCore", package: "Ivy2"), .product(name: "IvySimulation", package: "Ivy2"), "Tally", .product(name: "Crypto", package: "swift-crypto")], swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(name:"relay-node",dependencies:[.product(name:"Ivy",package:"Ivy2"),"Tally",.product(name:"Crypto",package:"swift-crypto")],swiftSettings:[.swiftLanguageMode(.v5)]),
        .executableTarget(name: "core-trace", dependencies: [.product(name: "IvyCore", package: "Ivy2"), "Tally", .product(name: "Crypto", package: "swift-crypto")], swiftSettings: [.swiftLanguageMode(.v5)]),
        .executableTarget(
            name: "node",
            dependencies: [
                .product(name: "Ivy", package: "Ivy2"),
                "Tally",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            // Linux's `stdout` is a mutable global, which Swift 6 mode rejects.
            swiftSettings: [.swiftLanguageMode(.v5)]),
    ]
)
