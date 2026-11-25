# Repository audit — garlic-router (pure-Swift I2P router for iOS)

**Audit date:** 2026-11-25
**Audited revision:** `main` at `693d898` ("Prepare project for GitHub CI and TestFlight CD"), working tree clean.
**Target:** Xcode project `Untitled1.xcodeproj`, targets `Untitled1` (app, `ai.opd.garlicrouter`), `Untitled1Tests`, `Untitled1UITests`. Deployment target iOS 26.0, Swift 5 language mode, Xcode 27.1.

This document is an audit and planning artefact. No application behaviour was changed to produce it. The only file moves were of one superseded audit pass (see §7).

---

## 1. Scope and methodology

### 1.1 Scope

The whole repository was inventoried — sources, tests, build configuration, workflows, markdown, and hidden files — excluding generated output (`.probe-build/`, `DerivedData/`) and dependency directories. Candidate sources were:

- Audit, compliance, interoperability and release documents at the root and under `Untitled1/`, `docs/`.
- `TODO`/`FIXME`/`XXX`/`HACK`/`WIP`/`TBD` markers.
- `XCTSkip`, `XCTExpectFailure`, disabled tests, and tests with no assertions.
- `fatalError`, `precondition`, `try!`, unused `try?` results, and parameters accepted but never serialized.
- Stubbed, orphaned or unreachable code and developer harnesses.
- Self-documented limitations inside the app's own spec truth table.
- CI/CD workflow coverage versus the test surface the repository actually has.

### 1.2 How each candidate was validated

Every candidate was checked against the current implementation before being reported. Where the tooling allowed, the claim was **executed**, not read:

| Evidence class | Meaning in this document |
| --- | --- |
| **VERIFIED** | A command was run in this audit and its output is quoted. |
| **STATIC** | Read at source against the specification or against the code it describes. |
| **DOCUMENTED** | Recorded by the project's own documents and consistent with the code, but not reproducible here. |
| **UNVERIFIED** | No evidence obtainable in this environment; listed in §4 instead of as a finding. |

All commands ran on the project's remote build Mac (Xcode 27.1, build 27A9275), which has no iOS Simulator runtime. The exact commands and their results are in §6.

### 1.3 Out of scope

- Running live mainnet probes. They contact public reseed services and real peers; the README marks them opt-in and this audit is non-disruptive.
- App Store submission, signing credentials, and physical-device behaviour (no device, no credentials, no account).
- Product decisions with no code signal (pricing, positioning).

---

## 2. Summary of findings

Every candidate lead was checked against the current implementation. **23 survive as active findings** below; the leads that proved resolved are kept in §5.2 with the evidence that closed them, and 6 that could not be verified are in §4.

### 2.1 By status and priority

| Priority | Count | IDs |
| --- | --- | --- |
| High (blocks a release claim) | 3 | AUD-01, AUD-02, AUD-05 |
| Medium | 10 | AUD-03, AUD-04, AUD-06, AUD-07, AUD-08, AUD-09, AUD-10, AUD-11, AUD-13, AUD-14 |
| Low | 10 | AUD-12, AUD-15, AUD-16, AUD-17, AUD-18, AUD-19, AUD-20, AUD-21, AUD-22, AUD-23 |

| Status | Count | IDs |
| --- | --- | --- |
| Open — confirmed, nothing applied | 13 | AUD-01, AUD-04, AUD-08, AUD-09, AUD-10, AUD-11, AUD-12, AUD-17, AUD-18, AUD-19, AUD-20, AUD-21, AUD-22 |
| Open — blocked on an environment not available here | 5 | AUD-02, AUD-03, AUD-05, AUD-06, AUD-07 |
| Open — intermittent, not reproduced lately | 1 | AUD-23 |
| Open — documentation or in-app content only | 4 | AUD-13, AUD-14, AUD-15, AUD-16 |

### 2.2 By category

| Category | IDs |
| --- | --- |
| Build & CI coverage | AUD-01, AUD-02, AUD-20 |
| Testing gaps | AUD-03, AUD-11, AUD-12, AUD-23 |
| Protocol / interoperability | AUD-04, AUD-05, AUD-06, AUD-07, AUD-08, AUD-09, AUD-10 |
| Documentation drift | AUD-13, AUD-15, AUD-16 |
| User-facing content | AUD-13, AUD-14 |
| Dead / orphan code | AUD-17, AUD-18, AUD-19 |
| Release readiness | AUD-21, AUD-22 |

---

## 3. Active findings

### AUD-01 — CI does not run the project's main protocol suites

- **Category:** build & CI coverage · **Priority:** High · **Confidence:** VERIFIED · **Status:** open
- **Description.** `xcodebuild test` is the only gate CI runs, and the unit-test adapter it executes calls `I2PSelfTest.runCoreTests()` rather than the composed `runAll()`. Large parts of the protocol surface — including the SAM conformance suite, the NTCP2 suite, the SSU2 suite and the transport wiring suite — therefore never run in CI, while the README and `INTEROP_REPORT.md` present the standalone harness as the project's evidence base.
- **Evidence.**
  - `Untitled1Tests/I2PProtocolTests.swift:26` — `I2PSelfTest.runCoreTests()`; the adapter's other cases cover cross-validation, thirteen client-logic suites, `I2PNetDBEntriesSelfTest`, `I2PTunnelSelfTest`, `I2PRouterStatusSelfTest`.
  - `Untitled1/I2P/I2PSelfTest.swift:85-226` — `runAll()` composes ~55 suites including `I2PNetDBSelfTest` (:96), `I2PNTCP2SelfTest` (:100), `I2PSSU2SelfTest`, `I2PRouterTransportWiringSelfTest`, `I2NPSelfTest` (:102 is tunnel; I2NP follows), `I2PGarlicSelfTest`, `I2PB33BlindingSelfTest`, `I2PSAMConformanceTest` (:222).
  - `.github/workflows/ci.yml:103-114` — the only test step is `xcodebuild test`.
  - Measured sizes (VERIFIED): harness `--all` → **279 checks**; the XCTest adapter's suites are a strict subset.
- **Validation performed.** Read the adapter and `runAll()` at source; ran the harness (`--all` → 279 checks) and `--sam`/`--alignment`/`--tunnel` selectors on the build Mac to confirm those suites exist and pass locally.
- **Impact.** A green CI badge says far less than it appears to. A regression in SAM stream handling, NTCP2 framing, SSU2 session establishment or the transport wiring would merge without failing anything.
- **Dependencies/blockers.** None technical; the harness already exits nonzero on any failure (`SelfTestProbe/main.swift:75-79`), so it can be wired into CI as written.
- **Recommended next action.** Add a second CI job that compiles and runs the standalone harness (`swiftc … Untitled1/I2P/*.swift SelfTestProbe/main.swift && ./.probe-build/selftestprobe --all`), and extend `I2PProtocolTests` with cases for `I2PSAMConformanceTest`, `I2PSSU2SelfTest` and `I2PRouterTransportWiringSelfTest`.

### AUD-02 — No CI run has ever completed for the default branch

- **Category:** build & CI coverage · **Priority:** High · **Confidence:** VERIFIED (absence) / inference (cause) · **Status:** open
- **Description.** The workflows were added in the audited commit, but GitHub reports no check run (success or failure) for `main` at `693d898`. The entire CI/CD pipeline is therefore unproven: the pinned Xcode 27.1, the simulator-selection script, the archive/export path and the TestFlight upload have never executed.
- **Evidence.** `github_checks` for `main` @ `693d898`: *"none have reported. Either the repository runs no CI for this commit, or it has not started yet."* The workflow files exist at `.github/workflows/ci.yml` and `.github/workflows/cd-testflight.yml`.
- **Validation performed.** Queried the repository's check runs through the GitHub integration. Did not (and will not) trigger a run: pushing is not part of an audit.
- **Impact.** The delivery pipeline's first real test will be the first tag push, i.e. at the moment the team intends to ship.
- **Dependencies/blockers.** Actions and macOS runners must be enabled for the private repository (billing), per `docs/CI-CD.md` §"Manual setup".
- **Recommended next action.** Push any commit (or run `workflow_dispatch` on `ci.yml`) and confirm the job completes; fix the first-run failures, then record the passing run in `docs/CI-CD.md`.

### AUD-03 — The standalone harness has two failing checks off-device

- **Category:** testing gaps · **Priority:** Medium · **Confidence:** VERIFIED · **Status:** open (environment-dependent)
- **Description.** The harness the documentation calls green fails two checks in a plain macOS `swiftc` process, both because the platform Keychain is unavailable outside an app/test bundle: *"SAM persistent key store migrates legacy files into Keychain"* and *"SAM session persistence (save/restore private keys)"*, each returning `persistent_key_store_unavailable`.
- **Evidence.** Ran `.probe-build/selftestprobe --all` → `277 passed, 2 failed`, exit 1. Offending detail string: `SESSION STATUS RESULT=I2P_ERROR MESSAGE=persistent_key_store_unavailable`. The same limitation is described in `docs/RELEASE-READINESS.md:16-17`.
- **Validation performed.** Both runs above were executed on the build Mac, from the sources as they stand.
- **Impact.** The headline "harness is green" claim is only true inside an iOS test bundle, and no record exists that it has ever been run there. Anyone reproducing the README command sees a red result and an exit code of 1.
- **Dependencies/blockers.** Requires a simulator or device to execute the iOS test bundle; the build Mac has no simulator runtime.
- **Recommended next action.** Record an iOS-bundle run of these two checks (GitHub's simulator runner is sufficient once AUD-02 is closed), and mark the checks as skipped-with-reason in the off-device harness rather than failed, so the exit code reflects real defects.

### AUD-04 — 17 of 61 spec truth-table rows are still `pendingWireVerification`

- **Category:** protocol / interoperability · **Priority:** Medium · **Confidence:** VERIFIED · **Status:** open
- **Description.** The app's own truth table classifies 44 rows as aligned and 17 as pending wire verification, with zero documented deviations and zero defects. Those 17 rows are the project's own inventory of requirements it cannot claim.
- **Evidence.** Counted from `Untitled1/I2P/I2PSpecTruthTable.swift` (`44 status: .aligned`, `17 status: .pendingWireVerification`). Row IDs pending: `CR-ED25519`, `CR-ED25519PH`, `CR-BLAKE2B`, `ST-LSET`, `ND-LOOKUP`, `ND-STORE`, `NP-DBSTORE`, `NP-DBLOOKUP`, `NP-TUNGW`, `NP-GARLIC`, `NT-M3`, `NT-BLOCKS`, `NT-KDF`, `NT-RIEX`, `SS-HPROTECT`, `SS-NOISE`, `GL-CLOVE`.
- **Validation performed.** Extracted with `awk` over the row definitions and cross-checked the totals against a full read of the I2NP row block (`I2PSpecTruthTable.swift:403-425`).
- **Impact.** Everything a live peer would have to confirm — NTCP2 message 3 and KDF labels, SSU2 header protection and Noise handshake, DatabaseStore/DatabaseLookup bodies, garlic clove framing — is unconfirmed. The Alignment screen states this correctly, so the gap is honest, but it is large.
- **Dependencies/blockers.** Needs a reference router (Java I2P or i2pd) on a non-production netId; see AUD-05 and §4.
- **Recommended next action.** Prioritise the rows that a single reference-router session would settle — `NT-M3`, `NT-KDF`, `NT-RIEX`, `NP-DBSTORE`, `ND-STORE` — and flip them as evidence lands rather than in one batch.

### AUD-05 — Live tunnel-build adoption has never been observed (0 of 21 starts)

- **Category:** protocol / interoperability · **Priority:** High · **Confidence:** DOCUMENTED · **Status:** open
- **Description.** The build message is spec-shaped locally (randomised record order, four-record minimum, inbound originator decoy) but no mainnet hop has ever been observed accepting a build from this router. The most recent recorded live run shows 21 build starts and 0 tunnels adopted. Because a tunnel is the prerequisite for every user-facing I2P path, this gates the product.
- **Evidence.** `INTEROP_REPORT.md:24-26` and `:99-103`; `docs/archive/audits/AUDIT-2026-11-18.md:210-212` (archived by this audit, §7); `BUGLOG.md:1117-1123`, which also records the suspected cause: an outbound build's reply is addressed via the build record's last-hop field, a field this router's data pipeline uses for the Tunnel Gateway handoff — *"changing the addressing needs a data-path refactor, not a one-line fix."*
- **Validation performed.** Read the three documents against `Untitled1/I2P/I2PTunnelBuild.swift` and the truth-table row `TN-RECORD-ECIES`; re-ran the tunnel suites (`--tunnel` → 6 passed, 0 failed; cross-validation `T4-TN-RECORD-ECIES-LAYOUT` passes). **No live observation was made in this audit** — it would require a reference peer.
- **Impact.** Without adoption the router cannot route real traffic: no outbound tunnel means no garlic delivery to a lease, no SAM stream, no eepsite fetch.
- **Dependencies/blockers.** A reference router with `--loglevel=debug` on a non-default netId, as `INTEROP_REPORT.md:99-103` prescribes. Blocked on infrastructure, not on code.
- **Recommended next action.** Stand up that reference router first; the peer's log names the exact check it applies to our records. Do not tune the build layout blind against mainnet.

### AUD-06 — Live SSU2 interoperability has never been observed

- **Category:** protocol / interoperability · **Priority:** Medium · **Confidence:** DOCUMENTED + STATIC · **Status:** open
- **Description.** SSU2 is implemented, wired into the app context and loopback-tested, and the published RouterInfo carries an SSU2 address with an introduction key — but no UDP session with a reference peer has ever been recorded.
- **Evidence.** `INTEROP_REPORT.md:48-55` ("NOT RUN — module wired, address published, loopback only") and `:104-105`. Code and tests exist: `Untitled1/I2P/I2PSSU2.swift` (2882 lines), `I2PSSU2Wiring.swift:76` (`I2PRouterTransportWiringSelfTest`).
- **Validation performed.** Ran the cross-validation and full suites; `T4-SS-UDP-LOOPBACK` passes (real UDP loopback handshake + I2NP delivery, both directions). That is loopback evidence only.
- **Impact.** A phone behind carrier NAT is unreachable without SSU2, so inbound participation (AUD-07) depends on it.
- **Dependencies/blockers.** Same reference-router requirement as AUD-05, with UDP reachability between the two hosts.
- **Recommended next action.** Fold SSU2 into the reference-router session planned for AUD-05; record the first established session in `INTEROP_REPORT.md` §2.

### AUD-07 — Inbound participation has never been observed organically

- **Category:** protocol / interoperability · **Priority:** Medium · **Confidence:** DOCUMENTED · **Status:** open (environment)
- **Description.** No other router has ever built a tunnel through this one. The recorded verdict is environmental (NAT) rather than a defect: our advertised address sits behind the CI environment's NAT, and mainnet refreshes hop selection on a minutes scale.
- **Evidence.** `BUGLOG.md:1112-1116`; `INTEROP_REPORT.md:54` ("LIVE PASS with the NAT verdict — no organic inbound connection; environment, not defect").
- **Validation performed.** Read at source and cross-checked with `Untitled1/I2P/I2PRouterAppContext.swift` (publish-once-reachable logic) and the netdb publication path. Not re-attempted live.
- **Impact.** Participation features that the UI promises (transit share ratio, quiet hours, per-peer blocklist applied to hop selection) cannot be shown to work against real traffic.
- **Dependencies/blockers.** AUD-06 (SSU2) plus a reachable address.
- **Recommended next action.** Same as AUD-06; do not treat the absence as a bug until a reachable path exists.

### AUD-08 — I2NP messages are not fragmented across NTCP2 blocks, and the row still says "aligned"

- **Category:** protocol / interoperability · **Priority:** Medium · **Confidence:** VERIFIED (source text) · **Status:** open
- **Description.** The truth table records that I2NP messages larger than one NTCP2 block are not fragmented, and that all current live traffic happens to fit a single block. The same row's status is `aligned`, so the Alignment screen and its export present an unimplemented path as conformant.
- **Evidence.** `Untitled1/I2P/I2PSpecTruthTable.swift:412` — *"messages larger than one NTCP2 block are not yet fragmented (all live-suite traffic fits a single block) — tracked as the remaining gap"*; the row `NP-HEADER` closes with `status: .aligned` on line 413. SSU2 does have both session-confirmed and I2NP fragmenters (`I2PSSU2.swift:596-700`); NTCP2 does not.
- **Validation performed.** Read the row and searched the whole `I2P/` tree for fragmentation logic — the only fragmenters found are in `I2PSSU2.swift`.
- **Impact.** Any larger message (a large LeaseSet2 bundle, a long garlic clove set, a big DatabaseStore) would be silently truncated or rejected by a peer once real traffic flows. The row's status would also mislead a reader of the exported compliance JSON.
- **Dependencies/blockers.** None; this is self-contained work in the NTCP2 data-phase writer.
- **Recommended next action.** Either implement NTCP2 block fragmentation and add a golden-vector test, or downgrade `NP-HEADER` to `pendingWireVerification` until it exists. Do not leave `aligned` on a row that documents its own gap.

### AUD-09 — Encrypted DatabaseLookup replies are parsed but never requested

- **Category:** protocol / interoperability · **Priority:** Medium · **Confidence:** VERIFIED · **Status:** open
- **Description.** `I2PDatabaseLookup` carries an `encryptedReplyRequested` flag, but `serialize()` never sets the corresponding flag bits, so no lookup this router sends ever asks for an ECIES-encrypted reply. The field is dead on the write path.
- **Evidence.** `Untitled1/I2P/I2PNetDBMessages.swift:135-136` (field), `:142` (init parameter), `:154` (assignment), `:158-173` (`serialize()` sets only the delivery and lookup-kind bits — `flags |= 0x01`, `(lookupType.rawValue & 0x03) << 2`). The only consumer is `Untitled1/I2P/I2PNetDB.swift:462`, which uses it to *refuse to answer* an encrypted request. `INTEROP_REPORT.md:111-113` records it as "still a product decision".
- **Validation performed.** Grepped every occurrence of the symbol across `Untitled1/` and read the serializer and parser in full.
- **Impact.** No immediate functional defect (direct replies interoperate), but a privacy property the protocol offers is unimplemented, and the parameter reads as if it were wired.
- **Dependencies/blockers.** Needs the reply-key/tag handling (`reply key/tags when encryption is requested`, per the same file's header comment) plus a decision that it is wanted.
- **Recommended next action.** Either implement the flag and the reply-key path with a loopback test, or remove the parameter and note the omission in the truth table so it cannot be mistaken for finished work.

### AUD-10 — SSU2 dial failures are discarded and never enter the handshake backoff

- **Category:** protocol / interoperability (reliability) · **Priority:** Medium · **Confidence:** VERIFIED (warning + source) · **Status:** open
- **Description.** The NTCP2 dial path records each attempt's ending against the peer's profile (`watchHandshake`), which is what schedules the 1/2/5/15/30-minute retry ladder. The SSU2 dial path calls `try? ssu2.connect(...)` and ignores the result; a peer reachable only over UDP therefore never gets a failure recorded and is never backed off.
- **Evidence.** `Untitled1/I2P/I2PRouterAppContext.swift:823-825` and `:894-896` (both `try? ssu2.connect(...)`, result discarded); the compiler flags both: *"warning: result of 'try?' is unused [#NoUsage]"* at 823 and 894. Contrast `:808-819`, where the NTCP2 session is passed to `watchHandshake(of:peer:)` at `:841-866`.
- **Validation performed.** Observed the two warnings in the `build-for-testing` log, then read the surrounding code and `I2PPeerHandshakeBackoff.swift` to confirm the asymmetry.
- **Impact.** A peer whose only reachable transport is SSU2 is retried on every maintenance tick instead of a schedule — wasted dials — and its failure never surfaces in the peer inspector's last-failure line.
- **Dependencies/blockers.** None.
- **Recommended next action.** Record the SSU2 attempt's ending in the same backoff store the NTCP2 path uses, and keep the two transports' profiles separate if they can fail independently.

### AUD-11 — The UI test target is Apple's template with zero assertions

- **Category:** testing gaps · **Priority:** Medium · **Confidence:** VERIFIED · **Status:** open
- **Description.** Both UI test files are unmodified Xcode templates. `testExample` launches the app and asserts nothing; `testLaunchPerformance` measures launch time; the launch test only attaches a screenshot. CI does execute them, so "unit and UI tests pass" is technically true and substantively empty.
- **Evidence.** `Untitled1UITests/Untitled1UITests.swift:25-40` and `Untitled1UITests/Untitled1UITestsLaunchTests.swift:20-32`; `grep -c 'func test'` → 2 and 1 respectively, with no `XCTAssert` anywhere in the target.
- **Validation performed.** Read both files in full and counted assertions (zero).
- **Impact.** No user journey is regression-tested — not first launch, not the Router dashboard, not the eepsite browser, not the IRC client. A UI regression is caught only by a human.
- **Dependencies/blockers.** The app has 40+ screens; a full UI suite is out of proportion. A smoke path is not.
- **Recommended next action.** Replace the template with one launch smoke test that asserts the tab bar exists and each tab opens without crashing, then grow it from the journeys the README advertises.

### AUD-12 — The unit-test target still contains an empty template file

- **Category:** testing gaps · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** `Untitled1Tests/Untitled1Tests.swift` is the generated placeholder: one `@Test func example()` with a comment and no assertion. It adds a green test that verifies nothing.
- **Evidence.** `Untitled1Tests/Untitled1Tests.swift:11-16`.
- **Validation performed.** Read in full.
- **Impact.** Cosmetic, but it inflates the apparent test count and models a pattern that produced AUD-11.
- **Recommended next action.** Delete the file, or convert it into a real test of a small pure type.

### AUD-13 — The app ships a stale 2026-11-17 audit report as a live screen

- **Category:** documentation drift / user-facing content · **Priority:** Medium · **Confidence:** VERIFIED · **Status:** open
- **Description.** The Alignment tab renders a bundled Markdown audit (`AUDIT-2026-11-17.md`) whose headline states that wire-format interoperability "remains unverified", and whose severity counts are hard-coded in Swift. Later live runs — recorded in `INTEROP_REPORT.md` and `BUGLOG.md` — contradict the headline for NTCP2, NetDB and garlic delivery. The screen also means the file is a **runtime asset**, not just a document.
- **Evidence.** `Untitled1/AuditReportView.swift:20-33` (`resourceName = "AUDIT-2026-11-17"`, `date = "2026-11-17"`, `highSeverity = 1`, `mediumSeverity = 6`, `lowSeverity = 3`, and the `headline` string); `Untitled1/AUDIT-2026-11-17.md`; opened from `Untitled1/AlignmentView.swift`. Verified that the built app bundle contains the file: `find …/Untitled1.app -maxdepth 1 -name '*.md'` listed `AUDIT-2026-11-17.md`, `AUDIT-2026-11-18.md`, `COMPLIANCE_REVIEW.md`, `SAM_API.md`, `README.md` at the time of measurement — every Markdown file under `Untitled1/` is copied into the bundle, which is why the archived pass had been shipping unread. After this audit's archive move the bundle carries four of those five.
- **Validation performed.** Read the reader and its metadata, listed the built bundle, and compared the report's opening claims with `INTEROP_REPORT.md:15-38`.
- **Impact.** The app presents out-of-date negative findings as current, and the hard-coded counts will drift further with every pass. It also blocks the normal remedy (archiving old audits) because moving the file would break the screen.
- **Dependencies/blockers.** The app cannot read a file outside the bundle, so the document must live under `Untitled1/` unless the reader is re-pointed at an embedded resource or a generated string.
- **Recommended next action.** Regenerate the report from `INTEROP_REPORT.md` + this file, derive the severity counts from the document instead of hard-coding them, and add a date/liveness banner so a reader can tell how old the report is.

### AUD-14 — The in-app strategy screen states facts the code has moved past

- **Category:** user-facing content · **Priority:** Medium · **Confidence:** VERIFIED · **Status:** open
- **Description.** `StrategyView` is reachable from the Alignment tab and presents a written plan. Several of its "what is missing" statements are no longer true, so the app tells users about gaps that have been closed.
- **Evidence.** `Untitled1/StrategyView.swift:633` — *"Wire SSU2 into the running transport set. The UDP transport exists but the app context is NTCP2-only"*, contradicted by `Untitled1/I2P/I2PSSU2Wiring.swift` and `INTEROP_REPORT.md:69` (*"Wired into `I2PRouterAppContext`"*); `:690` — *"The repo still says Untitled1: product name, bundle identifier, project name"*, contradicted by `Info.plist` (`CFBundleDisplayName = Garlic Router`) and `PRODUCT_BUNDLE_IDENTIFIER = ai.opd.garlicrouter` (`project.pbxproj:428`); `:691` — *"Remove NSAllowsArbitraryLoads … Add a privacy manifest"*, both done per `docs/RELEASE-READINESS.md:7-8` and `Untitled1/PrivacyInfo.xcprivacy`.
- **Validation performed.** Read the strategy content and checked each claim against the current project file, `Info.plist`, the SSU2 wiring module and the release-readiness notes.
- **Impact.** A user-facing screen whose credibility depends on being accurate is partly wrong; the "check the claims" promise at `:399` makes that worse.
- **Dependencies/blockers.** None.
- **Recommended next action.** Mark the item list as a dated snapshot with its own date stamp, and correct the three specific claims above.

### AUD-15 — `COMPLIANCE_REVIEW.md` describes closed divergences as open

- **Category:** documentation drift · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** The compliance review's four outstanding interop items — tunnel ChaChaPoly→AES-256-CBC layering, garlic envelope re-framing, the NTCP2 obfuscation KDF, and the message-1 options prefix — are exactly the work three later roadmap tickets completed, and the truth table no longer carries them as deviations. The document still says the tunnelling divergence "MUST be closed before routing real traffic".
- **Evidence.** `Untitled1/COMPLIANCE_REVIEW.md:25` (tunnel divergence) and `:45-47` (the checklist); contradicted by `Untitled1/I2P/I2PTunnelBuild.swift` (AES-256-CBC layer keys) and the passing case `T4-TN-DATA-RT` — *"spec layout (4+16+1008) byte-for-byte; AES-256-CBC layer with ECB-keyed IV chaining verified"* — plus `T4-GL-ENV-RT` and `NT-KDF`. The document is linked from `README.md:7`.
- **Validation performed.** Read the document, then ran the tunnel and alignment suites to confirm the described work is present and passing.
- **Impact.** A reader following the README is told three closed items are still open.
- **Recommended next action.** Annotate each item with its resolution and the ticket that closed it, or archive the review beside the audit it belongs to.

### AUD-16 — Documentation quotes test counts and dates that no longer match the tree

- **Category:** documentation drift · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** `INTEROP_REPORT.md` quotes both "212/212 self-test cases" (§1) and "214 passed" (§4, §8) for the same suite, and describes the cross-validation suite as "73/74" while today's run reports 74 passed / 1 failed out of 75. The real, measured figures today are 279 and 75.
- **Evidence.** `INTEROP_REPORT.md:30-34`, `:79-83`, `:167-168`; measured: `--all` → 277 passed, 2 failed (279); `--alignment` → 74 passed, 1 failed (75).
- **Validation performed.** Ran both selectors and compared.
- **Impact.** Small, but the report is the project's primary evidence document and it disagrees with itself.
- **Recommended next action.** Make §8's command block the single source of the numbers and re-run it when the document is next touched.

### AUD-17 — Five developer probes cannot compile as written

- **Category:** dead / orphan code · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** `DbProbe`, `KeyProbe`, `Msg1Probe`, `NetDBProbe` and `WireProbe` each declare `@main` inside a file named `main.swift`, which the Swift compiler rejects. They are diagnostic harnesses left over from earlier debugging passes.
- **Evidence.** `DbProbe/main.swift:19`, `KeyProbe/main.swift:8`, `Msg1Probe/main.swift:7`, `NetDBProbe/main.swift:6`, `WireProbe/main.swift:8`. Compiler experiment run in this audit:
  ```
  $ printf '@main\nstruct A { static func main() { print("hi") } }\n' > .probe-build/atmain/main.swift
  $ swiftc -o .probe-build/atmain/a .probe-build/atmain/main.swift
  main.swift:1:1: error: 'main' attribute cannot be used in a module that contains top-level code
  ```
  `DhtProbe`, `Diagnose`, `MainnetProbe`, `NetDiag` and `SelfTestProbe` use top-level code and are unaffected; `LiveProbe/run.swift` is legal because its file is not named `main.swift`.
- **Validation performed.** Enumerated the entry-point style of all eleven harnesses and reproduced the compiler error.
- **Impact.** No shipped effect. It is the residue of a harness-rot class the 2026-11-18 pass fixed for three other probes but not these five.
- **Recommended next action.** Convert them to top-level code as the others were, or delete them (see AUD-18).

### AUD-18 — Seven harnesses and one Python tool have no documented entry point

- **Category:** dead / orphan code · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** Only four harnesses are referenced by any documentation: `SelfTestProbe` (`README.md:25-32`), `LiveProbe` (`INTEROP_REPORT.md:178-180`), `NetDiag` and `MainnetProbe` (`Untitled1/AUDIT-2026-11-17.md`). `DbProbe`, `DhtProbe`, `Diagnose`, `KeyProbe`, `Msg1Probe`, `NetDBProbe`, `WireProbe` and `Tools/verify_msg1.py` are referenced nowhere.
- **Evidence.** Grepped all documentation for each directory name; only the four above appear. The orphan harnesses do still reference live APIs (`mainnetEncryptionKey`, `mainnetSignedRouterInfo`, `mainnetNTCP2`, `ensureReachableAddress`, `selectFloodfills` are all still defined in `Untitled1/I2P/`), so they were not broken by refactoring — they were simply never documented.
- **Validation performed.** Read each harness's header comment and entry point; grepped the documentation corpus.
- **Impact.** Repository hygiene: eleven top-level harness directories obscure the four that matter, and the README's single documented harness is lost among them.
- **Recommended next action.** Keep the four documented harnesses, move the rest into a `Tools/probes/` (or similar) folder with one README paragraph each stating what it diagnoses and how to run it — or delete the ones whose question is already answered in `BUGLOG.md`.

### AUD-19 — `ApiKeyManager` is unreachable dead code with a weak key-derivation design

- **Category:** dead / security · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** The credential importer has no app-feature caller, derives its AES-GCM key from the public bundle identifier, and re-imports on **every** launch because its initialiser removes the "initialised" flag before running. Both the README and the release-readiness review flag it; the code is still in the target.
- **Evidence.** `Untitled1/Utils/ApiKeyManager.swift:19-23` (`initializeKeysFromEncryptedFile()` preceded by `UserDefaults.standard.removeObject(forKey: initializationKey)`), `:36-44` (`projectName` derived from the bundle identifier). No caller: grepping `ApiKeyManager` across the project finds only its own file and three documents (`README.md:40`, `docs/RELEASE-READINESS.md:27`, `docs/CI-CD.md:107-112`).
- **Validation performed.** Grepped every reference and read the initialiser.
- **Impact.** None today, because nothing calls it. It becomes a credential-leak path the moment a feature uses it, and it is 170 lines of code that looks supported.
- **Recommended next action.** Delete it, or replace the file-derived AEAD key with a proper Keychain entry flow before any feature depends on it, as the release notes already prescribe. Do not ship it as-is.

### AUD-20 — Swift 6 migration warnings remain across the protocol layer

- **Category:** build · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** Compiling the sources emits a stream of `NSLock`-from-async warnings that Swift 6 turns into errors, plus unused-result warnings in the router context. The project is pinned to `SWIFT_VERSION = 5.0`, so this is a future break, not a current failure.
- **Evidence.** Harness compile log: `Untitled1/I2P/I2PTunnel.swift:813:14: warning: instance method 'unlock' is unavailable from asynchronous contexts; … this is an error in the Swift 6 language mode` (and the same for `lock()`); `project.pbxproj:435` and `:469` (`SWIFT_VERSION = 5.0`). `docs/RELEASE-READINESS.md:19` records the same class.
- **Validation performed.** Observed the warnings in this audit's own `swiftc` run and in the `build-for-testing` log.
- **Impact.** Moving to Swift 6 becomes a large mechanical change with concurrency-safety risk in the tunnel, transport and SAM paths — the exact areas that had four data races fixed in `BUG-055…060`.
- **Recommended next action.** Convert the `NSLock`-around-`await` sites to scoped/async-safe locking while still in Swift 5 mode, in small batches, with the harness and ThreadSanitizer run between batches.

### AUD-21 — No localization catalogues

- **Category:** release readiness · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** All user copy is inline English; there is no `*.xcstrings` and no `Localizable.strings`, although the project sets `LOCALIZATION_PREFERS_STRING_CATALOGS = YES` and `SWIFT_EMIT_LOC_STRINGS = YES`.
- **Evidence.** `find . -name '*.xcstrings' -o -name 'Localizable.strings'` → no results; `project.pbxproj:339`, `:434`, `:468`.
- **Validation performed.** Ran the find and read the build settings.
- **Impact.** The app is English-only by construction. Not a defect for a first release, but the build settings imply a capability the project has not built.
- **Recommended next action.** Either add a string catalogue and extract the shipped copy, or record "English only" as a deliberate decision in `docs/RELEASE-READINESS.md`.

### AUD-22 — `Info.plist` carries no export-compliance declaration

- **Category:** release readiness · **Priority:** Low · **Confidence:** VERIFIED · **Status:** open
- **Description.** The app implements cryptography and has no `ITSAppUsesNonExemptEncryption` key, so every upload to App Store Connect will stop at the export-compliance question until it is answered by hand.
- **Evidence.** `Untitled1/Info.plist` (34 lines, full contents read — the key is absent); no occurrence of `ITSAppUsesNonExemptEncryption` anywhere in the repository. `docs/RELEASE-READINESS.md:25` lists export compliance as an open release check.
- **Validation performed.** Read `Info.plist` in full and grepped the repository.
- **Impact.** Submission friction and a manual step in the first TestFlight flow (AUD-02), not a runtime defect.
- **Recommended next action.** Once the export determination is made, add the key and record the reasoning in `docs/RELEASE-READINESS.md`.

### AUD-23 — BUG-061: a rare SAM load stall is still open by the project's own record

- **Category:** testing gaps (intermittent) · **Priority:** Low · **Confidence:** DOCUMENTED · **Status:** open — not reproduced
- **Description.** A `SAM load: 3 concurrent streams` stall was seen about once in 25 full-suite runs, was never reproducible in isolation, and survived 130 consecutive traced runs afterwards. It is the one item the project deliberately kept open rather than closing on stress-test evidence.
- **Evidence.** `BUGLOG.md:1966-1991` (marked `Status: **open**`), including the next-step instructions (retain `.probe-build/sam-trace-N.log`, read the last per-stream marker).
- **Validation performed.** The single full-suite run performed in this audit (`--all`, 279 checks) passed every SAM case; two Keychain checks failed for the unrelated reason in AUD-03. One run is not evidence of absence.
- **Impact.** Low probability, high diagnosis cost: it presents as a 20 s timeout in a stream whose siblings succeed.
- **Dependencies/blockers.** Needs a reproduction, ideally on a CI runner with the harness wired in (AUD-01).
- **Recommended next action.** Wire the harness into CI, retain the trace logs as artefacts, and let a real reproduction supply the diagnosis.

---

## 4. Unresolved or unverified leads

These were examined and **could not be confirmed** in this environment. They are listed so nothing is silently dropped, and each states why it stopped.

| ID | Lead | Why it could not be confirmed | What would settle it |
| --- | --- | --- | --- |
| L-1 | Whether `xcodebuild test` actually passes on a GitHub runner (simulator selection, Xcode 27.1 availability via `setup-xcode`, test-bundle signing off) | No CI run exists (AUD-02) and the build Mac has no simulator runtime | One `workflow_dispatch` run of `ci.yml` |
| L-2 | Whether the two Keychain-dependent SAM checks pass inside the iOS test bundle | The build Mac cannot execute XCTest; the harness fails them by environment | A simulator or device run of `I2PProtocolTests` |
| L-3 | Whether the SSU2 fallback (`scheduleSSU2Fallback`, 4 s window) ever establishes a session in the running app | Loopback evidence only; no reference peer | A UDP-reachable reference router |
| L-4 | The cause of the two mainnet NTCP2 peers that close after SessionRequest | The peer's rejection reason is only in the peer's own log | i2pd at `--loglevel=debug` on a non-default netId |
| L-5 | Whether the BUG-061 stall still exists | Not reproduced in 1 run here; the project's own record says 130 clean runs | CI wiring plus trace artefacts (AUD-23) |
| L-6 | Provenance of `README.md` inside the built `.app` | Observed by listing the bundle; the repository's root README is not inside the target's synchronized folder, so the copy mechanism was not established | Inspect the build phase's copy products |

---

## 5. Source documents and markers reviewed

### 5.1 Reviewed and retained

| Source | Role | Disposition |
| --- | --- | --- |
| `BUGLOG.md` (2022 lines) | The project's bug history, referenced by `INTEROP_REPORT.md` and by the code comments | Retained. BUG-061 is carried forward as AUD-23; all other entries were checked and are marked fixed, with two "still open" blocks now superseded (see §5.2). |
| `INTEROP_REPORT.md` (191 lines) | Living interoperability evidence document | Retained. Drives AUD-05, AUD-06, AUD-07, AUD-09, AUD-16. |
| `Untitled1/COMPLIANCE_REVIEW.md` (50 lines) | Spec compliance review from an earlier phase | Retained in place (linked from `README.md`); its staleness is AUD-15. |
| `docs/RELEASE-READINESS.md` (37 lines) | Release readiness review | Retained; drives AUD-19, AUD-20, AUD-22. |
| `Untitled1/SAM_API.md` (173 lines) | SAM API reference | Retained; one "provisional pending live-network verification" caveat still applies and is covered by AUD-04. |
| `docs/CI-CD.md` (134 lines) | CI/CD documentation | Retained. Verified it matches both workflows: nine secrets named in §"Required secrets" are exactly the nine the workflow checks, and the `APP_BUNDLE_ID` variable is used as documented. |
| `README.md`, `Untitled1/Resources/reseed-certs/README.md` | Project and asset documentation | Retained. |
| `.milq/roadmap.json` (410 lines) | Roadmap metadata written by the app, not authored documentation | Excluded as out of scope; the app's own roadmap is not the repository's state. |

### 5.2 Markers and leads examined and excluded

| Item | Where | Why excluded |
| --- | --- | --- |
| F-01 TunnelGateway missing 2-byte length | `docs/archive/audits/AUDIT-2026-11-18.md` §2.1 | **Resolved.** `I2PTunnelGatewayPayload` encodes `tunnelID(4) \| length(2) \| message`; `T4-NP-TUNGW-RT` passes in this audit. |
| F-02 Data body missing 4-byte length | same | **Resolved.** `I2NPDataMessage` exists; `T4-NP-DATA-RT` passes. |
| F-03 truth table drifted from wire codes | same | **Resolved.** Row text reads type codes from `I2NPMessageType`; `truthTableNamesTheSpecTypeCodes` asserts 19/20/11 (`I2PProtocolTests.swift:77-88`). |
| F-04 CI ran an empty test target | same | **Resolved.** `I2PProtocolTests.swift` runs the cross-validation and core suites. (Its *coverage* is incomplete — that is AUD-01, not F-04.) |
| F-05 stale test assertions | same | **Resolved.** All triaged; the suites pass in this audit. |
| F-06 SSU2 not wired into the app context | `docs/archive/audits/AUDIT-2026-11-18.md` §5 | **Resolved.** `I2PSSU2Wiring.swift`; `T4-SS-UDP-LOOPBACK` and `I2PRouterTransportWiringSelfTest` pass. |
| F-07 short-header parsers indexed from absolute zero | same | **Resolved.** `parseShort` rebases through `Array(data)`; short-header cases pass. |
| F-08 `precondition` in `I2PWriter` | same | **Resolved as a proven invariant**; `T4-ST-MAPPING-BOUNDS` round-trips a maximal mapping byte-identically. Remaining `precondition`s are documented input contracts, not remote-reachable traps. |
| F-09 harness rot | same | **Partly resolved.** `NetDiag`, `LiveProbe`, `MainnetProbe` were fixed; five probes remain broken — carried forward as **AUD-17**. |
| F-10 Swift 6 mutable-`var` capture | same | **Resolved** for the named site; the class of warning remains — **AUD-20**. |
| COMPLIANCE_REVIEW divergences: NTCP2 obfuscation KDF, message-1 options prefix, tunnel layering, garlic envelope | `COMPLIANCE_REVIEW.md:20,25,34` | **Resolved in code** (AES-CBC ephemeral obfuscation, `TN-DATA` AES-256-CBC layering, ECIES three-section envelope + spec HKDF labels). The *document* is stale — **AUD-15**. |
| BUG-034/035/036/043/045/046/052/053/055–060/062/063/064 | `BUGLOG.md` | **Resolved**, each with a passing regression case in this audit's run. |
| BUG-061 | `BUGLOG.md:1966` | **Open** — carried forward as **AUD-23**. |
| "Still open: inbound tunnel participation" | `BUGLOG.md:1112` | Carried forward as **AUD-07**. |
| "Outbound tunnel creation … needs a data-path refactor" | `BUGLOG.md:1117` | Carried forward as part of **AUD-05**. |
| `TODO`/`FIXME`/`XXX`/`HACK`/`WIP`/`TBD` markers | whole tree | **No actionable marker found.** The 37 matches were: roadmap JSON prose, reseed certificate base64, and the word "swipe"/"WiP" inside SwiftUI `swipeActions` and comments. Two genuine `TBD`s appear only inside quoted spec prose: `BUGLOG.md:1184` and `Untitled1/I2P/I2PLeaseSet2.swift:450` — both describing a field the spec itself leaves open, both already handled in code. |
| `XCTSkip` / `XCTExpectFailure` / disabled tests | whole tree | **None.** No test is skipped or marked expected-to-fail. |
| `fatalError` sites | `I2P/I2PHardening.swift:306`, `I2P/Ed25519.swift:325` | **Not a finding.** `I2PInvariant.enforce` is the deliberate fail-closed policy and `Ed25519`'s is a fixed base-point decompression that cannot fail. Neither is reachable from network input on a path that is not already trapping on an invariant. |
| `I2PProductionAudit` / `I2PStabilityAudit` / `I2PSpecConformanceAudit` | `Untitled1/ContentView.swift:272,294,364,452` | **Not dead.** Each is reachable from a tab; they are app-facing audit rails, not orphans. |
| `I2PReadinessAudit` | `ContentView.swift:74,151,205` | **Not dead.** Wraps the production audit and surfaces interruption checkpoints. |
| Unused `try?` results | `I2PRouterAppContext.swift:823,894` | **Reported as AUD-10**, not as dead code. |
| `.gitignore` signing/secrets rules | `.gitignore:34-55` | **Verified adequate.** `*.p12`, `*.mobileprovision`, `*.p8`, `AuthKey_*.p8`, `*.pem`, `*.cer`, `secrets/`, `.env*` and `Untitled1/ENCRYPTED_KEYS.plist` are all excluded; no secret material is tracked. |
| `Untitled1/ENCRYPTED_KEYS.plist` | target | **Empty dictionary, as documented.** Tracked (not ignored by git in this checkout), so any future populated copy would need care; `.gitignore:55` covers it once changed. Recorded here so the state is not a surprise. |

### 5.3 Archived by this audit

| Original path | New path | Reason |
| --- | --- | --- |
| `Untitled1/AUDIT-2026-11-18.md` | `docs/archive/audits/AUDIT-2026-11-18.md` | Superseded audit pass. Its conclusions are carried forward into this document (§5.2) and its remaining open items became AUD-05, AUD-06, AUD-07, AUD-17, AUD-20 and AUD-23. It was referenced by no code, documentation or build setting, and it was being copied into the app bundle unread. |

**Not archived — deliberate.** `Untitled1/AUDIT-2026-11-17.md` is also a superseded audit, but it is a **runtime asset**: `Untitled1/AuditReportView.swift:37-56` loads it from the app bundle and renders it in the Alignment tab. Moving it would break a shipped screen, so it stays where it is and its staleness is recorded as AUD-13 instead.

**Nothing was deleted.** No source file, test or general-purpose document was removed.

---

## 6. Verification performed

All commands ran on the project's remote build Mac, Xcode 27.1 (27A9275), 2026-11-25.

```
# toolchain and scheme
xcodebuild -version                       → Xcode 27.1 / 27A9275
xcodebuild -list -json -project Untitled1.xcodeproj
                                          → scheme Untitled1; targets Untitled1, Untitled1Tests, Untitled1UITests

# the app, the unit-test target and the UI-test target all compile
xcodebuild build-for-testing -project Untitled1.xcodeproj -scheme Untitled1 \
  -configuration Debug -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath .probe-build/DD CODE_SIGNING_ALLOWED=NO
                                          → exit 0 (warnings only)

# the off-device protocol harness
swiftc -swift-version 5 -o .probe-build/selftestprobe \
  Untitled1/I2P/*.swift SelfTestProbe/main.swift
                                          → exit 0 (Swift 6 warnings quoted in AUD-20)
./.probe-build/selftestprobe --all        → 277 passed, 2 failed (exit 1)
                                             failures: both SAM persistent-Keychain cases (AUD-03)
./.probe-build/selftestprobe --alignment  →  74 passed, 1 failed (exit 1)
                                             failure: T4-ND-SU3-SIGNER, no app bundle in a swiftc binary
./.probe-build/selftestprobe --tunnel     →   6 passed, 0 failed (exit 0)
./.probe-build/selftestprobe --alignment --tunnel --netdb --ntcp2 --b33 --spec
                                          → 100 passed, 3 failed

# static counts used above
truth-table rows                          → 44 aligned, 17 pendingWireVerification, 0 deviation, 0 defect
XCTest funcs                              → unit: 22 @Test (plus 1 empty template); UI: 3, zero assertions
check runs for main @ 693d898             → none reported (AUD-02)

# the @main claim (AUD-17)
printf '@main\nstruct A { static func main() {}\n' > .probe-build/atmain/main.swift
swiftc -o .probe-build/atmain/a .probe-build/atmain/main.swift
  → error: 'main' attribute cannot be used in a module that contains top-level code

# what the built app bundle ships
find .probe-build/DD/Build/Products/Debug-iphonesimulator/Untitled1.app -maxdepth 1 -name '*.md'
  → AUDIT-2026-11-17.md, AUDIT-2026-11-18.md, COMPLIANCE_REVIEW.md, SAM_API.md, README.md
find … -name '*.crt' | wc -l              → 19
```

**Checks that could not be run, and why:** `xcodebuild test` (no iOS Simulator runtime on the build Mac; the reason CI matters), any live mainnet probe (needs public reseed endpoints and real peers, and is opt-in per `README.md:9`), and any device-only behaviour.

---

## 7. Roadmap

Ordered by impact and dependency. Every item names the audit IDs it closes and the criterion that says it is done. No estimates or owners are implied.

### Phase 0 — Make the pipeline prove itself

| # | Item | Closes | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 0.1 | Get `ci.yml` to run to completion on `main`, fixing whatever the first run exposes | AUD-02 | Actions + macOS minutes enabled | A green run is visible for a commit, and its URL is recorded in `docs/CI-CD.md` |
| 0.2 | Add a CI job that compiles and runs the standalone harness (`--all`) and uploads the log | AUD-01, AUD-03 (evidence), AUD-23 (evidence) | 0.1 | The job fails on any harness failure and its log is an artefact |
| 0.3 | Run the two Keychain-dependent SAM checks inside the iOS test bundle and record the result | AUD-03, L-2 | 0.1 | Both pass, or their failure is a named iOS-side defect |
| 0.4 | Extend `I2PProtocolTests` to cover the SAM conformance, SSU2 and transport-wiring suites | AUD-01 | 0.1 | Those suites fail the build when broken |

### Phase 1 — Close the self-documented protocol gaps

| # | Item | Closes | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 1.1 | Fragment I2NP messages across NTCP2 blocks, with a golden-vector test — or downgrade the `NP-HEADER` row | AUD-08 | none | A message larger than one block round-trips, and no row marked `aligned` documents an unimplemented path |
| 1.2 | Implement encrypted DatabaseLookup replies (flag bits + reply key/tag), or delete the unused parameter | AUD-09 | none | The flag is on the wire with a loopback test, or the parameter and its doc note are gone |
| 1.3 | Record SSU2 dial outcomes in the handshake-backoff store | AUD-10 | none | A failing SSU2-only peer gets a scheduled retry and appears in the peer inspector's last-failure line |
| 1.4 | Work the 17 `pendingWireVerification` rows against a reference router, in priority order (`NT-M3`, `NT-KDF`, `NP-DBSTORE`, `ND-STORE`, `SS-NOISE`) | AUD-04 | Phase 2's reference router | Each row flips on recorded evidence, or is re-worded to say why it cannot |

### Phase 2 — Prove interoperability on a controlled network

| # | Item | Closes | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 2.1 | Stand up a reference router (Java I2P or i2pd) at debug level on a non-default netId | AUD-05, L-4 | infrastructure | Its log can be read while our router dials it |
| 2.2 | Diagnose why builds are not adopted (0 of 21), starting from the documented reply-addressing question | AUD-05 | 2.1 | At least one reference hop adopts one of our builds, or the rejecting check is named |
| 2.3 | Establish a live SSU2 session with the same peer | AUD-06 | 2.1 | A session is recorded in `INTEROP_REPORT.md` §2 |
| 2.4 | Observe one organic inbound tunnel | AUD-07 | 2.3, a reachable address | A peer builds through us without synthetic coordination |

### Phase 3 — Make the shipped app tell the truth

| # | Item | Closes | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 3.1 | Regenerate the bundled audit report and derive its severity counts instead of hard-coding them; date-stamp it | AUD-13 | none (it can be regenerated from this document) | The Alignment tab's report matches `INTEROP_REPORT.md`, and its counts come from the document |
| 3.2 | Correct the three superseded claims in the strategy screen and date-stamp the snapshot | AUD-14 | none | No claim contradicts the current project file, `Info.plist`, the SSU2 wiring or `PrivacyInfo.xcprivacy` |
| 3.3 | Annotate or archive `COMPLIANCE_REVIEW.md`'s closed divergences | AUD-15 | none | A reader cannot mistake a closed item for an open one |
| 3.4 | Reconcile the test counts in `INTEROP_REPORT.md` with a single reproduced run | AUD-16 | 0.2 | The document quotes one set of numbers, from one command block |

### Phase 4 — Test and hygiene debt

| # | Item | Closes | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 4.1 | Replace the template UI tests with a launch smoke path | AUD-11 | 0.1 | The suite asserts the tab bar and each tab's first screen; a broken tab fails CI |
| 4.2 | Delete or fill the empty unit-test template | AUD-12 | none | No test exists that asserts nothing |
| 4.3 | Fix or delete the five non-compiling probes; document or retire the orphan harnesses | AUD-17, AUD-18 | none | Every harness in the repository compiles and is named in one place |
| 4.4 | Remove or rebuild `ApiKeyManager` | AUD-19 | none | No code path derives a key from the bundle identifier |
| 4.5 | Burn down the Swift 6 concurrency warnings in small batches under ThreadSanitizer | AUD-20 | none | A `swiftc -swift-version 6`-equivalent check is clean, or the remaining sites are enumerated |
| 4.6 | Chase BUG-061 with CI-retained trace artefacts | AUD-23 | 0.2 | Reproduced with a diagnosis, or closed after a documented reproduction window |

### Phase 5 — Release metadata

| # | Item | Closes | Depends on | Done when |
| --- | --- | --- | --- | --- |
| 5.1 | Decide export compliance and add `ITSAppUsesNonExemptEncryption` | AUD-22 | the determination itself | The key is in `Info.plist` and the reasoning is in `docs/RELEASE-READINESS.md` |
| 5.2 | Decide and record the language policy; add a string catalogue if the answer is "localised" | AUD-21 | none | The build settings and the shipped copy agree |

---

## 8. Changes made by this audit

| Change | Path |
| --- | --- |
| Created this document | `AUDIT.md` |
| Archived a superseded audit pass | `Untitled1/AUDIT-2026-11-18.md` → `docs/archive/audits/AUDIT-2026-11-18.md` |

No application code, test, workflow, build setting or general-purpose document was modified. Nothing was deleted.

### Remaining uncertainties

- The repository's CI has never run, so no statement in this document about CI is evidence about a runner (AUD-02).
- Every live-network statement is either quoted from the project's own recorded runs or marked UNVERIFIED; none was re-observed here.
- The `README.md` copy found inside the built app bundle could not be traced to a build phase (§4, L-6).
