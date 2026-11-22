# Garlic Router

Garlic Router is an iOS application for exploring a pure-Swift I2P router and its client-facing tools. The app includes router status and participation controls, SAM v3.3, an I2P eepsite reader with saved/offline pages, an IRC client, and protocol self-tests and alignment reports.

## Status and limitations

This is an experimental implementation, not a production-ready or independently audited I2P router. The protocol suites provide local, deterministic and loopback evidence; they do not establish full interoperability. The most recent checked-in interoperability report (2026-11-18) reports a recorded NTCP2 handshake and several mainnet exchanges, but live tunnel-build adoption and live SSU2 interoperability remain unverified. See [INTEROP_REPORT.md](INTEROP_REPORT.md) and [the compliance review](Untitled1/COMPLIANCE_REVIEW.md) for evidence and open protocol gaps.

The live mainnet probes are opt-in. Running one contacts public reseed services and a bounded set of floodfill peers; it should be done only with network access and an understanding that it sends real traffic. Do not treat a green local suite as proof of live-network security or interoperability.

The app targets iOS 26.0 or later and uses the shared `Untitled1` Xcode scheme. iOS may suspend the app when it is backgrounded; the app does not have a supported entitlement for continuous router operation, and no always-on or inbound-reachability guarantee is made. Test on physical devices and networks before any release decision.

## Build and test

Use Xcode 27.1 or a compatible newer Xcode with an installed iOS Simulator runtime:

```sh
xcodebuild -resolvePackageDependencies -project Untitled1.xcodeproj -scheme Untitled1
xcodebuild build -project Untitled1.xcodeproj -scheme Untitled1 \
  -destination 'platform=iOS Simulator,name=<available iPhone>' CODE_SIGNING_ALLOWED=NO
xcodebuild test -project Untitled1.xcodeproj -scheme Untitled1 \
  -destination 'platform=iOS Simulator,name=<available iPhone>' CODE_SIGNING_ALLOWED=NO
```

CI builds the app and runs the unit and UI test targets on an available simulator. The standalone I2P harness can also run the protocol suites on macOS without launching the UI:

```sh
mkdir -p .probe-build
swiftc -swift-version 5 -o .probe-build/selftestprobe \
  Untitled1/I2P/*.swift SelfTestProbe/main.swift
./.probe-build/selftestprobe --all
```

The harness supports focused selectors such as `--sam`, `--tunnel`, `--netdb`, `--netdb-entries`, `--alignment`, `--b33` and `--spec`; it exits nonzero when any selected check fails. Some bundle-dependent checks are only meaningful in the app/test bundle. In particular, the standalone macOS process used for this review could not access the app Keychain and its SAM persistent-key checks returned `persistent_key_store_unavailable`; run those checks in the iOS test bundle or on a configured device. Live-network verification requires reachable external services. See [CI and CD](docs/CI-CD.md) for CI and TestFlight setup.

## Security and privacy notes

- The app uses only HTTPS for its direct `URLSession` requests; I2P eepsite HTTP is carried through the app's I2P stream path, not through a global App Transport Security exception.
- `PERSISTENT=true` SAM destination keys and saved IRC server passwords are stored in the device-only Keychain. Legacy IRC passwords are migrated out of user defaults; if Keychain storage is unavailable during migration, the plaintext is scrubbed and that password is discarded. See [SAM_API.md](Untitled1/SAM_API.md) and the [release-readiness review](docs/RELEASE-READINESS.md).
- The key-import helper is not currently used by app features. Its bundled AES-GCM data is not suitable for protecting credentials because its decryption key is derived from the public bundle identifier. The bundled `ENCRYPTED_KEYS.plist` should remain empty.
- No release readiness claim is made here. Device/background behavior, real-peer interoperability, signing, privacy-label accuracy, export-compliance answers, and App Store review still require separate verification. See [release readiness](docs/RELEASE-READINESS.md).
