# INTEROP_REPORT — Swift I2P router

Date: 2026-11-10. Scope of this pass: wire-level audit of NTCP2, I2NP, NetDB and
tunnel build against i2p.net/en/docs/specs, plus fixes that are provable with
local harnesses. No reference router was available in this environment (no Java
I2P, no i2pd, no packet capture, no simulator on the build Mac), so **no cell in
the matrix below is a live result**.

---

## 1. Interop matrix

Format: transport → handshake | RouterInfo exchange | netDb store | netDb lookup | tunnel build.

**NTCP2 with i2pd**
- handshake: NOT RUN — static audit shows non-spec protocol id/KDF (BUG-008),
  key obfuscation (BUG-009), message layout (BUG-010) and data-phase length/nonce
  rules (BUG-011). Expected to fail.
- RouterInfo exchange: NOT RUN (blocked by handshake).
- netDb store: NOT RUN (blocked by handshake). Payload encoding itself fixed
  (BUG-003/004).
- netDb lookup: NOT RUN. Body layout fixed (BUG-005).
- tunnel build: NOT RUN. Records fixed earlier (BUG-013); live path unproven.

**NTCP2 with Java I2P**: same as above — NOT RUN, same static blockers.

**SSU2 with i2pd**
- handshake: NOT RUN. The SSU2 module exists and has loopback tests, but it is not
  wired into `I2PRouterAppContext`; no live UDP session can be established.
- RouterInfo exchange / netDb / tunnel build: NOT RUN, N/A until wired.

**SSU2 with Java I2P**: NOT RUN, same reason.

**Router ↔ router (self, loopback)**
- NTCP2 frame codec: PASS (separate TX/RX codecs, sequential + incremental frames,
  tampered MAC rejected — Mac harness).
- Tunnel short-record box: PASS (154/218 bytes, Noise_N X25519 round trip, layer/
  reply keys equal, reply code round trip, RFC 8439 ChaCha20 vector — Mac
  harness).
- DatabaseStore with gzip RouterInfo: PASS (Java-compatible gzip header, GNU
  `gzip -dc` inflates, 3000-byte payload round trips through the store body —
  Mac harness).
- App build (simulator, Debug): PASS.

**Bottom line:** the router cannot yet claim interoperability with a reference
router. The protocol layers below NTCP2 are now closer to spec; NTCP2 itself is
the gate.

---

## 2. Remaining blockers, ranked by impact

1. **NTCP2 transport rewrite** (blocking everything).
   Protocol id + null prologue, AES-CBC ephemeral-key obfuscation using the
   router hash and the address `i` IV, SessionRequest/SessionCreated option
   layouts, SessionConfirm part-1 key/nonce, Noise Split + ASK/SipHash KDF,
   SipHash IV chain and little-endian nonces, block codec types and termination
   order.
2. **SSU2 integration** into the running router (reachability behind NAT, inbound
   tunnels, being selected as a hop). Module exists; wiring and a RouterInfo
   `SSU2` address with intro key are missing.
3. **Live tunnel-build validation** with the new short records: path ordering,
   reply peeling and hop acceptance against real routers.
4. **Local testnet harness + packet capture** as the gate for every future fix
   (i2pd + Java I2P, netId != 2). Nothing should be tuned on mainnet before this
   exists.
5. **Encrypted / tunnel-routed netdb replies** (DatabaseLookup flags bits 1/4):
   we request only direct, unencrypted replies and answer only direct,
   unencrypted lookups. Interop works but privacy/latency are weaker than
   reference routers.
6. **LeaseSet publication and renewal** against reference floodfills (no ack
   accounting for DeliveryStatus from reference routers was previously possible;
   now fixed for direct acks, but unverified live).

---

## 3. Spec discrepancies found (and how they were resolved)

- **I2NP type codes**: earlier code comments claimed 4/5/6/7/8 were the spec
  codes; the current I2NP spec (updated 2026-03) lists 10/11/18/19/20 for
  DeliveryStatus/Garlic/TunnelData/TunnelGateway/Data. Followed the spec.
- **DatabaseStore RouterInfo compression**: spec says type-0 data is a 2-byte
  size + gzip; Java masks the type byte with 0x0f and gunzips without fallback;
  i2pd treats any nonzero type as LeaseSet and always inflates type 0. Followed
  the spec and both parsers' expectations.
- **DatabaseStore type values**: 3/5/7 for LS2/Encrypted/Meta (not 2/3/5).
- **DatabaseLookup has no reply token**: the spec asks for direct replies to
  `from`, tunnel replies via flags bit 0, and encrypted replies via flags bits
  1/4. We removed the invented token from the wire.
- **NTCP2 spec internal inconsistencies**: the spec's message-3 hash chain text
  says "24 byte encrypted payload from message 2" while its own layout is 32
  bytes (16 ciphertext + 16 MAC), and the SipHash slice notation `[0:7]/[8:15]/
  [16:23]` is off by one for 8-byte keys plus an 8-byte IV. i2pd hashes 32 bytes
  and uses `[0:8)/[8:16)/[16:24)`. Follow i2pd when the rewrite happens.
- **Tunnel builds**: TunnelBuild 21/22 are deprecated; the modern path is
  ShortTunnelBuild 25 / OutboundTunnelBuildReply 26 with 218-byte records, which
  this router now uses.

---

## 4. Recommended next steps (human decisions)

1. **Approve the NTCP2 rewrite** as a dedicated work item. It should be built
   against the spec KDF text and validated against i2pd first, then Java I2P.
   Do not patch piecemeal: the handshake hash chain, obfuscation and options
   layout change together.
2. **Stand up the testnet**: i2pd and Java I2P on a non-production netId, the
   Swift router on the simulator, tcpdump on both endpoints, logs at debug level.
   Publish a success/failure matrix per handshake phase.
3. **Wire SSU2** after NTCP2 passes; add the SSU2 RouterInfo address with intro
   key and an `i` option for NTCP2, so reachability is real.
4. **Then re-validate** tunnel builds and netdb against the live local testnet
   before any mainnet run (per the hard rules).
5. Decide whether direct-only netdb replies are acceptable for v1 or whether
   encrypted replies (DatabaseLookup flags bit 4, ECIES reply key/tag) are
   required before launch.

---

## 5. What is verified in this pass

- The alignment suite no longer traps: the full cross-validation suite (68
  cases) executes to completion in a Mac harness. 53 pass; the 15 failures are
  functional, pre-existing issues (garlic ECIES/tags, SSU2 loopback handshakes
  and tokens, the 3-hop tunnel layer check, LeaseSet2 offline/meta). They are
  reported by the Alignment tab instead of killing the process.
- `I2PSelfTest.runAll()` also completes without a trap (84 cases, 45 pass); the
  failures are the same functional families plus the netdb/tunnel-pool cases.
- Chaos: the two crash causes found this session were non-zero `Data` index
  bases from CryptoKit seals and a shared-direction frame codec; both are fixed
  at the source.
- I2NP message numbers now match the current spec (BUG-002).
- RouterInfo DatabaseStore payloads use Java-compatible gzip with the 2-byte size,
  and LS2 family store types are 3/5/7 (BUG-003/004).
- DatabaseLookup / DatabaseStore bodies now follow the spec byte maps for direct,
  unencrypted exchanges; store acknowledgments use DeliveryStatus (BUG-005/006).
- Short tunnel build records and replies follow the ECIES tunnel-creation spec
  (BUG-013, from the previous pass).
- Garlic delivery instructions now use the I2NP flag byte (type in bits 6-5,
  hash before tunnel ID, 1/33/37-byte lengths); the NP-DI alignment row is
  `aligned` and its cross-validation case passes (BUG-016).
- I2NP envelopes now default to the spec's 60 s expiration window (BUG-015).
- Debug build for the simulator succeeds on the remote build Mac; standalone
  harnesses validate ChaCha20, the short-record box and the gzip/DSM wire path.


   ---

   ## 6. Second live mainnet pass (same day, later run)

   The suite was run again against the live network from the build Mac, with
   harnesses compiled from the real source files (`MainnetProbe`, `Diagnose`,
   `WireProbe`, `KeyProbe`; each lives outside the app target).

   **What the run proved**

   - NTCP2 reaches mainnet peers: `SessionRequest` is answered with a real
     `SessionCreated` by several floodfills, our `SessionConfirmed` is sent, and
     the transport reports the sessions as established. Messages 1–2, the
     `es`/`ee` KDFs, the AES-CBC ephemeral obfuscation and the option blocks are
     therefore accepted by reference routers.
   - Live sessions to real floodfills were established (`sessionSummaries` shows
     them with byte counters), so DNS, TCP, the listener and the dial path all
     work from this environment.

   **What fails, and why**

   1. **Reseed is blocked by the network, not by the code (BUG-025).** All nine
      reseed hosts refuse from this Mac: four time out, four answer *HTTP 403*
      (nginx, IP reputation) and diva answers *429*. `curl` reproduces every
      result. The reseed row and every row gated on it report as environment
      failures.
   2. **A persisted netdb was restored as an empty routing table (BUG-022).**
      The netdb held 284 signature-verified RouterInfos while `floodfillCount`
      and `knownPeerCount` read 0, so "nothing to dial" was reported with a full
      peer cache. Fixed: the restore indexes every RouterInfo, expiry prunes the
      index, and stores are keyed by the verified identity hash. The same
      persisted netdb now reports 92 floodfills / 214 peers.
   3. **Peers close after message 3 without a Termination block.** Our side has
      already sent `SessionConfirmed` and marks the session established; the peer
      then drops the socket and no byte is ever received on it. i2pd's
      post-message-3 silent closes are (a) the static key from part 1 differing
      from the published `s` and (b) the observed endpoint differing from a
      published host. (a) was a real defect in this build — the transport was
      given CryptoKit's raw public key while the RouterInfo published the
      canonicalized one — and is fixed at the source (BUG-023). (b) cannot be
      ruled out from our side; this Mac publishes `38.22.0.87` (from ipify) and
      dials from the same address, so they should match.
   4. **The DHT row needed a fresh reseed (BUG-024).** Fixed: the row now runs a
      live `probeLookup` (a random-key `DatabaseLookup` answered by either a
      DatabaseStore or a DatabaseSearchReply) when no deferred reseed hash
      exists, so a healthy persisted netdb can prove the query path.

   **Still unverified (needs a reference router with logs)**

   - Whether message 3 is accepted end-to-end. The next step is one i2pd at
     `eLogDebug` on a non-production netId, dialing the Swift router, so its own
     log names the check it rejects. Nothing else in the handshake is left to
     infer from our side: the byte layout, KDFs, nonces and obfuscation chain
     were re-checked against i2pd's `NTCP2.cpp`/`Crypto.cpp` line by line.
   - Live tunnel builds, inbound hop participation and garlic delivery all need
     a session that survives message 3, so they stay "not run" until then.
