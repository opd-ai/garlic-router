# Diagnostic probes

Standalone Swift drivers used to diagnose the router from outside the app. None of
them belongs to an Xcode target; each is compiled against the I2P sources with
`swiftc` from the repository root.

## The four harnesses the documents name

These stay at the repository root, because the README and the interop report
point at them by path:

| Path | What it is |
| --- | --- |
| `SelfTestProbe/` | The offline protocol harness (`README.md`, `INTEROP_REPORT.md` §8). Runs every suite, exits nonzero on any failure. |
| `LiveProbe/` | The opt-in live mainnet probe (`INTEROP_REPORT.md` §8). Contacts reseed servers and a bounded set of floodfills. |
| `NetDiag/` | Netdb and transport state report (`Untitled1/AUDIT-2026-11-17.md`). |
| `MainnetProbe/` | The reseed and floodfill dial probe (`Untitled1/AUDIT-2026-11-17.md`). |

## What is in this folder

**Every probe below except `NetDBProbe` contacts the real network.** The ones that
dial (`DbProbe`, `DhtProbe`, `Diagnose`, `Msg1Probe`, `WireProbe`) start the
router and reach reseed servers, floodfills and peers over HTTPS, NTCP2 and UDP.
`KeyProbe` reads the mainnet identity and RouterInfo the context builds and does
not start the router, so it dials nothing. They are opt-in live tools on the same
terms as `LiveProbe`: run them with network access and an understanding that they
send real traffic. None of them crawls, floods or probes hosts it did not learn
about from the netdb.

| Probe | Question it answers |
| --- | --- |
| `DbProbe/DbProbe.swift` | After a session is established, does anything come back at all? Counts inbound I2NP messages by type over a live NTCP2 session, so an empty pipe and a rejected message look different. |
| `DhtProbe/main.swift` | Which floodfills a lookup picks, whether they have live sessions, and what actually comes back from each — a DHT round trip with the selection shown, not just its result. |
| `Diagnose/main.swift` | What the netdb, transport and lookup paths actually hold over time, sampled, so a failing mainnet row can be pinned to a real cause instead of a cascade. |
| `KeyProbe/KeyProbe.swift` | The RouterInfo `s` option, the message-3 static key and the identity's encryption key must be the same bytes. Prints whether they are. |
| `Msg1Probe/Msg1Probe.swift` | Produces one real SessionRequest toward a reseeded floodfill and prints every ingredient needed to check it independently. Pairs with `verify_msg1.py`. |
| `NetDBProbe/NetDBProbe.swift` | Runs the in-process netdb suite (`I2PNetDBSelfTest`) against the real code and prints each result. Offline; the same checks `SelfTestProbe --netdb` runs. |
| `WireProbe/WireProbe.swift` | After the handshake "completes" on our side, does the peer keep the session when we send nothing? Separates a message-3 rejection from a data-phase frame rejection. |
| `verify_msg1.py` | Independently verifies an NTCP2 SessionRequest produced by the router: implements the Noise `XK` message-1 KDF from the specification with Python's `cryptography` and decrypts the options block. Usage: `verify_msg1.py <peerStaticKeyHex> <ephemeralPrivHex> <message1Hex>`. |

## Building one

Pass the whole I2P source tree and the probe's single file:

```sh
mkdir -p .probe-build
swiftc -swift-version 5 -o .probe-build/dbprobe \
    Untitled1/I2P/*.swift Tools/probes/DbProbe/DbProbe.swift
./.probe-build/dbprobe
```

Two conventions the probes depend on, worth knowing before editing one:

- A probe whose file is named `main.swift` uses top-level code (that file already
  provides the entry point). Any other name must use `@main` on a type instead —
  `@main` in `main.swift` does not compile.
- The probes that dial the network call `I2PRouterAppContext.shared.start()` first;
  without it the netdb is empty and every dial reports "no peer".
