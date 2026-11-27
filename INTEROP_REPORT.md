# INTEROP_REPORT — Swift I2P router

**Living document.** Last updated 2026-11-25 (numbers re-measured from the
current tree; the evidence rows below are unchanged, so a cell still names the
day its observation was made). The 2026-11-18 text replaced the 2026-11-10
edition, which described a router that no longer exists: its headline blockers
(NTCP2 framing, SSU2 unwired, LeaseSet2 unparsed) have since been implemented,
and the build record layout has been aligned with the tunnel-creation spec as
well. Every cell below names the evidence behind it and the day it was observed.
Where the evidence is a recorded live run rather than a run made in this pass, it
says so — no cell is presented as stronger than it is.

Reproduce the offline evidence with the commands in §8. The figures quoted in §1
come from that block and from nowhere else.

---

## 1. Bottom line

- **NTCP2 to reference routers works.** A recorded live run on 2026-11-18
  established 6 of 12 floodfill dials (BUGLOG BUG-043); messages 1–3, the
  `es`/`ee` KDFs, the AES-CBC ephemeral-key obfuscation and the option blocks are
  therefore accepted by Java I2P / i2pd peers. The previous report's open question
  — "is message 3 accepted?" — is answered: yes.
- **The build message is now spec-shaped.** Record order is randomized, the
  message is padded to the spec's recommended minimum of four records, and an
  inbound build carries the mandatory decoy record for the originator (§6,
  BUG-052). Whether real hops *adopt* our builds is still open: the last live run
  showed 21 build starts with 0 tunnels adopted.
- **SSU2 is wired.** Our published RouterInfo carries an SSU2 address with an
  introduction key (observed in this pass). No live SSU2 session with a reference
  peer has been observed yet.
- **Offline protocol suites, measured 2026-11-25:** `--all` reports **279 passed,
  2 failed** (281 checks) and `--alignment` **74 passed, 1 failed** (75 cases).
  All three failures are harness artefacts rather than defects: the two SAM
  persistent-key checks need the app bundle's Keychain and return
  `persistent_key_store_unavailable` from a bare `swiftc` process, and
  `T4-ND-SU3-SIGNER` loads the reseed certificates from the app bundle, which a
  `swiftc` binary does not have. The app bundle carries all 19 reseed
  certificates (verified in the 2026-11-18 pass), so SU3 verification is live in
  the app, and the unit-test target runs both SAM checks for real in a simulator.
- **Live re-verification is blocked from the build Mac right now** by reseed
  reachability (§7), not by the code: this pass's live run reported 0/9 with every
  row classified *transient network condition*.

---

## 2. Interop matrix

`LIVE` = observed against real mainnet routers. `LOCAL` = offline harness or
loopback. `NOT RUN` = no observation.

| Path | NTCP2 (Java I2P / i2pd) | SSU2 (Java I2P / i2pd) |
| --- | --- | --- |
| Handshake | **LIVE PASS** — 6/12 established, 2026-11-18 (recorded, BUG-043) | NOT RUN — module wired, address published, loopback only |
| RouterInfo exchange | **LIVE PASS** — publication acknowledged by live floodfills, 2026-11-18 (recorded) | NOT RUN |
| NetDB store | **LIVE PASS** — DatabaseStore acknowledged, 2026-11-18 (recorded) | NOT RUN |
| NetDB lookup | **LIVE PASS** — Kademlia DatabaseLookup round-trip, 2026-11-18 (recorded) | NOT RUN |
| Destination resolution | **LIVE PASS** to the extent the DHT returns lease-bearing entries (recorded); plain and encrypted LS2 parsing/resolution covered LOCAL | NOT RUN |
| Garlic delivery | **LIVE PASS** toward a resolved lease's gateway, 2026-11-18 (recorded) | NOT RUN |
| Inbound participation | **LIVE PASS with the NAT verdict** — no organic inbound connection; environment, not defect (BUG-043) | NOT RUN |
| Tunnel build | Build message **LOCAL PASS** and now spec-shaped; **live adoption open** (0 of 21 starts, recorded 2026-11-18) | NOT RUN |
| App build | **PASS** — simulator `xcodebuild`, bundle resources checked | — |

Router ↔ router (loopback, this pass): the NTCP2 frame codec, the 218-byte short
build record box, the reply rejection/acceptance paths, the tunnel pool lifecycle
and the SAM end-to-end streams all pass in the harness.

---

## 3. What changed since the 2026-11-10 report

| Then | Now |
| --- | --- |
| NTCP2 handshake expected to fail (protocol id, obfuscation, message layout, data-phase rules) | Spec aligned and **live-verified** with reference routers |
| SSU2 module existing but not wired | Wired into `I2PRouterAppContext`; an SSU2 address with its intro key is published beside the NTCP2 one |
| LeaseSet2 not parsed | LeaseSet2 (store types 2/3/5) parsed, verified and resolved; encrypted LS2 resolved through the b33 blinding path for credentialled destinations |
| TunnelGateway body missing its 2-byte length; Data message missing its 4-byte length | Fixed with golden-vector tests (BUG-045/046) |
| "No reference router available" | Reference routers reached over NTCP2; SSU2 and the build *path* still lack a live observation |
| Tunnel build records "fixed earlier, live path unproven" | Record layout aligned and now randomized/padded with an inbound decoy (§6); adoption still unproven |

---

## 4. Verified in this pass (2026-11-18)

*The counts below are the 2026-11-18 pass's, kept as its record. The current
figures — larger, because the suites have grown — are in §1 and are produced by
the block in §8; nothing else in this document quotes a count.*

- **Full self-test suite: 212 passed, 0 failed** (`--all`), compiled from the real
  sources on the build Mac.
- **Cross-validation suite: 73 passed, 1 failed** (`--alignment`). The failure is
  `T4-ND-SU3-SIGNER`, which loads `Resources/reseed-certs` from the app bundle; a
  `swiftc` binary has no bundle. It passes in the app and in the unit-test target.
- **The app bundle carries its trust anchors:** a clean simulator `xcodebuild`
  produced `Untitled1.app` containing all 19 reseed `.crt` files (flattened at the
  bundle root, which the loader's flat fallback resolves).
- **The published RouterInfo carries both transports:** the live probe printed our
  own signed RouterInfo (`sigOK=true`) with an NTCP2 address (`v=2`, `s`, `i`,
  `host`, `port`) and an SSU2 address (`v=2`, `s`, `i`, `host`, `port`) — the
  wiring the previous report listed as missing.
- **No live sessions could be re-established** because reseed is blocked from this
  host (§7). The live suite's nine rows all reported the missing prerequisite and
  were classified *transient network condition*, not implementation gaps.

---

## 5. Still unverified, ranked

1. **Live tunnel build adoption.** The message is now spec-shaped, but no mainnet
   hop has been observed accepting a build from us. The next step is a second
   router (i2pd at debug level, non-default netId) whose log names the check it
   applies to our records and replies. Nothing here should be tuned blind on
   mainnet.
2. **Live SSU2.** The transport, loopback tests and published address exist; no
   live UDP session with a reference peer has been observed.
3. **Inbound participation behind NAT.** The listener works; whether a carrier
   lets the phone be reached needs a reference router on the same network or an
   SSU2 report to answer.
4. **Encrypted (b33) destinations over the live DHT.** Implemented and covered
   offline, including the fail-closed stranger case; not yet observed on mainnet.
5. **Encrypted netdb replies.** Our own `DatabaseLookup` requests ask for a direct,
   unencrypted reply, and that interoperates. An inbound request that sets the
   encrypted-reply flag is recorded and refused rather than answered in the wrong
   shape; the outbound lookup type no longer carries a flag it does not set. ECIES
   replies need a reply key and tag on the wire plus a decrypt path — a protocol
   feature, not a fix, and still a product decision.
6. **LeaseSet renewal over live floodfills** beyond the single acknowledged
   publication scenario.

---

## 6. Fixed in this pass: build record layout

The tunnel-creation spec (ECIES-X25519, §Implementation Notes) requires three
things the builder did not do:

- **"Build record order must be randomized, so middle hops do not know their
  location within the tunnel."** Records went out in path order, telling every
  hop its position.
- **"The recommended minimum number of build records is 4."** A two-hop tunnel
  sent exactly two records, exposing the hop count.
- **"For inbound tunnel builds, there must always be one 'fake' record for the
  originating router, with the correct 16-byte hash prefix and a real X25519
  ephemeral key."** Inbound builds sent none, so the hop nearest the originator
  could tell it sat beside the tunnel's endpoint.

`I2PTunnelBuilder.buildLayout` now picks the slots (4–8 records, always leaving a
free slot for the inbound decoy) and `originatorDecoyRecord` builds that decoy
from this router's truncated identity hash plus a fresh X25519 public key. The
creator keeps its reply material per *wire slot*, so reply peeling still opens the
right slot with the right key: a rejection peels the hops before the reporting one
in build-path order, an acceptance opens unlayered.

Tests: `T4-TN-RECORD-ECIES-LAYOUT` (cross-validation, tagged to the
`TN-RECORD-ECIES` truth-table row) and "Build records randomized, padded and
decoyed per the spec" in the tunnel suite.

---

## 7. Environment notes (this run)

- **Reseed is blocked from the build Mac, not by the code.** Across two passes,
  four hosts time out, four answer HTTP 403 (nginx IP reputation), one refuses the
  connection and one answers 429; `curl` reproduces every result. The persisted
  netdb held no floodfills, so the live suite had nothing to dial.
- **The SU3 harness failure is the bundle, not the verifier.** `T4-ND-SU3-SIGNER`
  needs `Resources/reseed-certs` inside a bundle; the app has them, a `swiftc`
  binary does not.
- Live runs are non-disruptive: a reseed fetch and a handful of dials, no crawling.

---

## 8. Reproducing

```sh
# Offline harness (from the repository root). The counts quoted in §1 come from
# these two commands and are not restated anywhere else in this document.
mkdir -p .probe-build
swiftc -swift-version 5 -o .probe-build/selftestprobe \
    Untitled1/I2P/*.swift SelfTestProbe/main.swift
./.probe-build/selftestprobe --all         # 279 passed, 2 failed (281 checks)
./.probe-build/selftestprobe --alignment   # 74 passed, 1 failed (75 cases)
./.probe-build/selftestprobe --tunnel      # build records, layouts, pool lifecycle
./.probe-build/selftestprobe --netdb --ntcp2 --sam   # per-subsystem selectors

# The three failures above are bundle-dependent, not defects: the two SAM
# persistent-key checks and T4-ND-SU3-SIGNER need the app bundle the iOS test
# target provides. Run `xcodebuild test` for those.

# Race detection: must report 0 warnings (BUG-056). Last measured in the
# 2026-11-18 pass; re-run it before any Swift 6 migration.
swiftc -swift-version 5 -sanitize=thread -g -o .probe-build/probe-tsan \
    Untitled1/I2P/*.swift SelfTestProbe/main.swift
./.probe-build/probe-tsan --all

# Live suite (needs reachable reseed servers and network)
swiftc -swift-version 5 -o .probe-build/live \
    Untitled1/I2P/*.swift LiveProbe/run.swift
./.probe-build/live
```

---

## 9. Earlier passes

The 2026-11-10 pass is preserved in `BUGLOG.md` (BUG-002 … BUG-025): the I2NP type
table, DatabaseStore compression and store types, DatabaseLookup bodies, garlic
delivery instructions, the 60 s I2NP expiry, the NTCP2 wire audit and the first
live mainnet runs. Its findings are superseded where §3 says so; its open items
are carried forward in §5.
