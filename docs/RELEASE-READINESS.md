# Release-readiness review

This is a bounded source/build review, not a security certification or App Store approval. Findings below reflect source inspection and the verification attempted for this pass.

## Addressed in this pass

- Removed the global `NSAllowsArbitraryLoads` App Transport Security exception. The inspected direct `URLSession` requests use HTTPS; the eepsite reader transports HTTP content through the I2P stream implementation.
- Added `Untitled1/PrivacyInfo.xcprivacy` for the observed required-reason API use: app-owned preferences (`UserDefaults`, reason `CA92.1`) and reading an app-container crash marker's modification timestamp (`FileManager` resource value, reason `C617.1`). No tracking or data-collection declaration was inferred from source alone.
- Moved SAM `PERSISTENT=true` destination private keys from plaintext Application Support files into the device-only Keychain (`AfterFirstUnlockThisDeviceOnly`). Existing files migrate only after Keychain storage succeeds; unavailable or malformed storage now fails closed. Nicknames are represented by SHA-256 account names.
- Moved saved IRC server passwords out of `UserDefaults` into the device-only Keychain (`AfterFirstUnlockThisDeviceOnly`). Existing entries are migrated and scrubbed; when secure storage is unavailable, the plaintext is still removed, that password is discarded and the server list warns the user. New password saves and server deletion fail closed if the Keychain operation fails.
- Removed API-key importer debug output that included bundled plist contents, key identifiers and secret lengths.

## Decisions recorded (2026-11-25)

- **Language policy: English only, by decision.** The project sets `LOCALIZATION_PREFERS_STRING_CATALOGS = YES` and `SWIFT_EMIT_LOC_STRINGS = YES`, but ships no `*.xcstrings` and no `Localizable.strings`; every shipped string is inline English. That is the current answer rather than an unfinished feature, so an App Store listing must not claim another language until a catalogue is added. Adding one later is a self-contained change: the build settings already point at the mechanism.
- **`ApiKeyManager` is kept, with its limit recorded rather than removed.** It is the mechanism by which a key entered at runtime reaches the Keychain, and nothing calls it yet. Its bundled `ENCRYPTED_KEYS.plist` is decrypted with a key derived from the public bundle identifier, and that file ships inside the app bundle, so its contents are extractable from any IPA: it obscures a value, it does not protect one. Nothing that must stay secret may be placed in it. Keychain entries written at runtime are the supported path.
- **Exports are pinned to their stated fields.** The alignment JSON, the peer traffic CSV and the router health CSV are each asserted by a unit test against exact column names and values, so a field cannot be added silently. The alignment and peer-traffic cases additionally assert that nothing about peers, sessions or destinations appears in the file.

## Finalization verification (2026-11-21)

- `xcodebuild clean build-for-testing -project Untitled1.xcodeproj -scheme Untitled1 -destination 'generic/platform=iOS Simulator' CODE_SIGNING_ALLOWED=NO` succeeded after the final code changes. This compiles the app, unit-test target and UI-test target; it does not execute XCTest cases.
- The standalone `--netdb-entries` regression suite previously passed **3/3**. The broad local harness run with `SAM_ONLY=LOAD` passed **263/263**, including the IRC server-book and password-migration self-tests. Those tests inject a fake password store, so they verify persistence/migration behavior but do not validate the platform Keychain API.
- The final unfiltered standalone harness reported **272 passed, 2 failed**. Both failures are SAM persistent-Keychain scenarios returning `persistent_key_store_unavailable` from this macOS command-line context. This does not establish whether those scenarios pass in the iOS app/test environment; rerun them there. The harness now exits nonzero when any check fails.
- XCTest and UI tests were not executed because no simulator device was available to this build service. No live-network probe or physical-device verification was performed in this pass.
- The macOS Swift compiler also reported Swift 6 migration warnings for `NSLock` use from async contexts and non-Sendable captures in existing modules. The Xcode project is still in Swift 5 language mode; address these before migrating to Swift 6.

## Open release checks

- **I2P interoperability:** the checked-in [interop report](../INTEROP_REPORT.md) is dated 2026-11-18. Its recorded evidence is historical; repeat controlled tests with authorized Java I2P/i2pd peers. Live tunnel-build adoption and live SSU2 remain unverified there.
- **iOS runtime:** verify suspend/resume, network changes, memory pressure, battery use and Keychain availability on physical devices. iOS does not provide this app with continuous background router execution.
- **Privacy and policy:** complete App Store privacy labels from actual product data flows, export-compliance answers for the cryptographic features, age rating and review notes. A source scan is not a substitute for Apple's current submission checks.
- **Signing and distribution:** register the production App ID, verify the distribution profile/certificate and App Store Connect record, and run the TestFlight workflow with authorized secrets. No signing configuration or credentials were changed here.
- **Credential importer:** `ApiKeyManager` currently has no app-feature callers, and its bundled AES-GCM key is derived from the public bundle identifier. Do not add secrets to `ENCRYPTED_KEYS.plist`; replace this mechanism with an appropriate runtime Keychain flow before a feature depends on it.
- **Test execution:** the app and both test targets compile for the generic iOS Simulator destination, but XCTest/UI tests need to run on a CI runner or a machine with an available simulator. The standalone macOS Keychain failures noted above still need an iOS test-environment result.
- **Swift 6 migration:** review and resolve the compiler's async-locking and Sendable warnings before changing the project from Swift 5 language mode.

## Configuration reviewed

- App deployment target: iOS 26.0; iPhone and iPad device families.
- No camera, microphone, contacts, photos or location usage descriptions are present or needed by the inspected app paths.
- `Untitled1/Info.plist` has no broad ATS exception after this pass.
- `Untitled1/ENCRYPTED_KEYS.plist` is an empty dictionary in this checkout. A repository scan found no credential/private-key material; a textual scan cannot prove that every secret format is absent.
- No external Swift package dependencies are currently declared (see the CI workflow and project settings).
