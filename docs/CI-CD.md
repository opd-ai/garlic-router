# CI and CD

Two GitHub Actions workflows live in `.github/workflows/`:

- **`ci.yml`** — every push and pull request against `main`. Selects a pinned
  Xcode, caches and resolves Swift packages, builds the app for the iOS
  Simulator and runs the `Untitled1Tests` (unit) and `Untitled1UITests` (UI)
  targets. Any build or test failure fails the run. It uses **no** signing
  material, so it passes on forks and on pull requests where none of the secrets
  below exist.
- **`cd-testflight.yml`** — on a `v*` tag push, or manually from the Actions tab.
  Imports a distribution certificate and provisioning profile into a throwaway
  keychain, archives with manual signing, exports a signed IPA and uploads it to
  TestFlight with an App Store Connect API key. The temporary keychain and every
  key file are deleted in a final step that runs even if an earlier step fails.

## Tooling choices

- **Signing** — plain `xcodebuild archive` + `xcodebuild -exportArchive` with an
  `ExportOptions.plist` (`method app-store-connect`, `signingStyle manual`).
  This is Xcode's own supported export path; it needs no extra dependency and
  the exported IPA is exactly what the archive step signed.
- **Upload** — `xcrun altool --upload-app` with an App Store Connect API key
  (`--apiKey` / `--apiIssuer`). altool ships inside Xcode, so there is nothing to
  install, and API-key authentication means no Apple ID password is ever stored
  in the repository. altool is marked deprecated by Apple; if a future Xcode
  drops it, replace that one step with `fastlane pilot` (already present on
  GitHub's macOS runner images) using the same three secrets.
- **No Apple ID / app-specific password** is used anywhere.

## Required secrets

Add these under **Settings → Secrets and variables → Actions → Secrets**.
Every one of them is referenced by name in `cd-testflight.yml`; none has a
default value baked into the workflow. `cd-testflight.yml` checks that all nine
exist before doing anything and fails with a `Missing secret:` annotation
naming the one that is absent.

| Secret | Format | How to create it |
| --- | --- | --- |
| `BUILD_CERTIFICATE_BASE64` | Base64 of an **Apple Distribution** `.p12` | On a Mac: open **Keychain Access → login → My Certificates**, find *Apple Distribution: <your name> (<TEAMID>)*, right-click → **Export…**, save as `.p12` with a password. Then `base64 -i Certificates.p12 \| pbcopy` and paste. |
| `P12_PASSWORD` | Plain text | The export password you chose above. |
| `KEYCHAIN_PASSWORD` | Any strong random string | Generate one (`openssl rand -base64 32`). It only protects the throwaway keychain created during the run. |
| `PROVISIONING_PROFILE_BASE64` | Base64 of a `.mobileprovision` file | Apple Developer portal → **Certificates, Identifiers & Profiles → Profiles** → create an **App Store** distribution profile for the app's bundle ID and an Apple Distribution certificate → download → `base64 -i profile.mobileprovision \| pbcopy`. |
| `PROVISIONING_PROFILE_SPECIFIER` | Plain text, the profile's **name** | The name you typed when creating the profile (not a UUID). It must match the name shown in the portal's Profiles list. |
| `APPLE_TEAM_ID` | 10-character Team ID | Apple Developer portal → **Membership** → Team ID, or the suffix shown in the Developer portal's top-right account menu. |
| `APPSTORE_API_KEY_ID` | 10-character Key ID | App Store Connect → **Users and Access → Integrations → App Store Connect API** → generate a key with the **App Manager** role; copy its **Key ID**. |
| `APPSTORE_API_ISSUER_ID` | UUID | Same page: the **Issuer ID** shown above the key list. |
| `APPSTORE_API_PRIVATE_KEY` | Full contents of the `AuthKey_XXXXXXXXXX.p8` file, including the `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` lines | Same page: **Download API Key**. It can only be downloaded once — store it safely. Paste the whole file text. |

## Repository variables

Set under **Settings → Secrets and variables → Actions → Variables** (visible,
non-secret). Both are optional.

| Variable | Default | Purpose |
| --- | --- | --- |
| `XCODE_VERSION` | `27.1` | The Xcode version both workflows select on the runner (e.g. `27.1`, `26.2`). Set this to a version present on the runner image if the default is not. Check with `ls /Applications \| grep Xcode` on a failed run's log, or the runner image README. |
| `APP_BUNDLE_ID` | `ai.opd.garlicrouter` | The app's bundle identifier. Used as the `provisioningProfiles` key in `ExportOptions.plist` and passed to the archive as `PRODUCT_BUNDLE_IDENTIFIER`, so the profile and the binary agree. Must match the App ID the provisioning profile was created for. |

## Manual setup that cannot be automated here

1. **Register the bundle identifier.** The app builds as `ai.opd.garlicrouter`
   (the test bundles are `ai.opd.garlicrouter.tests` and
   `ai.opd.garlicrouter.uitests`). Register `ai.opd.garlicrouter` as an App ID in
   the Apple Developer portal (**Certificates, Identifiers & Profiles →
   Identifiers**) under the team the workflow signs with, so a provisioning
   profile can be issued for it. If the app should ship under a different
   reverse-DNS namespace, change the bundle ID in Xcode (the app target's
   `PRODUCT_BUNDLE_IDENTIFIER`) and set the `APP_BUNDLE_ID` variable to the same
   value — the two must always agree.
2. **Create the App Store Connect app record.** App Store Connect → **Apps → +**
   → new app for that bundle ID. TestFlight uploads are rejected until the app
   record exists.
3. **Agree to the agreements.** App Store Connect → **Agreements, Tax, and
   Banking** must be signed for uploads to be accepted.
4. **Enable macOS runners.** The workflows use `macos-latest`. GitHub-hosted
   macOS runners are available to private repositories but consume paid minutes
   (macOS minutes are billed at a multiplier); check **Settings → Billing** that
   Actions minutes are available. For a private repository, if Actions is
   disabled, enable it under **Settings → Actions → General**.
5. **Distribution certificate must be exportable.** The `.p12` must include its
   private key — export it as a *certificate* from Keychain Access, not a copy of
   the raw `.cer`.
6. **First-run timing.** TestFlight processing takes a few minutes after the
   upload succeeds; the workflow returns as soon as Apple accepts the upload,
   which is why the upload step is not waited on.

## Notes

- The scheme used by both workflows is the **shared** scheme at
   `Untitled1.xcodeproj/xcshareddata/xcschemes/Untitled1.xcscheme`. Without a
   shared scheme, `xcodebuild` on a fresh clone has no scheme to build and CI
   fails before compiling anything.
- The CI build passes `CODE_SIGNING_ALLOWED=NO`; simulator builds do not need a
  signing identity, which is what lets CI stay green with no secrets.
- `Untitled1/Info.plist` takes its version, build number and bundle identifier
  from build settings (`$(MARKETING_VERSION)`, `$(CURRENT_PROJECT_VERSION)`,
  `$(PRODUCT_BUNDLE_IDENTIFIER)`), so a tag `v1.2.3` produces marketing version
  `1.2.3` and the build number is the workflow run number (or the manual
  dispatch input).
- Cached paths: `~/Library/Caches/org.swift.swiftpm` and the DerivedData
   `SourcePackages` directory, keyed on `Package.resolved`. The project currently
   has no Swift package dependencies, so the cache is a no-op until one is added.
- `Untitled1/ENCRYPTED_KEYS.plist` is an empty template in this checkout. Do not
  put credentials in it or commit populated copies. The current API-key importer
  derives its AES-GCM key from the public bundle identifier, so that ciphertext
  is not a security boundary against someone who can inspect the app. No app
  feature currently reads `ApiKeyManager`; add a proper runtime Keychain entry
  flow before shipping any feature that needs a credential.
- `Untitled1/PrivacyInfo.xcprivacy` declares the app's observed UserDefaults and
  app-container file-timestamp access. Revisit the manifest whenever a new
  required-reason API or third-party SDK is added.

## Running the same checks locally

```
xcodebuild -resolvePackageDependencies -project Untitled1.xcodeproj -scheme Untitled1
xcodebuild build  -project Untitled1.xcodeproj -scheme Untitled1 \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO
xcodebuild test   -project Untitled1.xcodeproj -scheme Untitled1 \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO
```

## Rotating or revoking credentials

- Revoke a leaked API key in App Store Connect → **Users and Access →
  Integrations**; it stops working immediately.
- Revoke a leaked distribution certificate in the Apple Developer portal; the
  provisioning profile that used it becomes invalid and must be reissued.
- Secrets pasted into GitHub can be overwritten at any time; CI never reads them,
  so rotating them cannot break pull requests.
