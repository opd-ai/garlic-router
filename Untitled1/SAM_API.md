# SAMv3.3 API — Pure Swift I2P Router

The router exposes the SAMv3.3 client protocol on a TCP socket bound to
`127.0.0.1:7656` (configurable in the router context; the SAM tab can start
and stop the socket). The transport, session, stream, datagram, naming and
destination layers ride the router's real NTCP2, tunnel pool, garlic pipeline
and network database — the same components the dashboard reports on.

## Line protocol

Every command and every reply is a single UTF-8 line terminated by `\n`.

### Session lifecycle

```
HELLO VERSION MIN=3.0 MAX=3.3          →  HELLO REPLY RESULT=OK VERSION=3.3
                                        (incompatible → HELLO REPLY RESULT=NO_VERSION)
SESSION CREATE STYLE=STREAM ID=s1 DESTINATION=TRANSIENT
                                       →  SESSION STATUS RESULT=OK DESTINATION=<b64>
SESSION CREATE STYLE=DATAGRAM ID=d1 DESTINATION=<priv b64> PORT=7658 HOST=127.0.0.1
SESSION CREATE STYLE=RAW ID=r1 DESTINATION=TRANSIENT
SESSION QUIT                            →  (connection closes)
```

- `TRANSIENT` generates a fresh destination per session. `DESTINATION` may
  instead carry a private destination key (base64 of `Ed25519 seed(32) ‖
  X25519 private key(32)` = 64 bytes) to reuse an identity.
- Each TCP connection owns one session (creating a second replaces it;
  reusing an ID answers `DUPLICATED_ID`).
- Every session builds its own tunnel pool (3–5 outbound + 3–5 inbound) and
  publishes its LeaseSet to the floodfills under its own destination; the
  lease set is renewed on a maintenance cycle.
- `STYLE=DATAGRAM`/`RAW` with `PORT=`/`HOST=` receives inbound datagrams as
  SAM v3 UDP datagrams (repliable: `<b64 destination> <payload>`; raw:
  payload only). Without `PORT`, inbound datagrams are delivered on the TCP
  connection as `DATAGRAM RECEIVED DESTINATION=<b64> SIZE=n\n<payload>\n`
  (anonymous sends carry no DESTINATION).

### Streams (STYLE=STREAM)

```
STREAM CONNECT ID=s1 DESTINATION=<b64 destination> [SILENT=true]
STREAM ACCEPT  ID=s1 [SILENT=true]
```

- `CONNECT` resolves the remote LeaseSet (DHT), sends a garlic'd stream SYN
  through the session's outbound tunnel pool and replies once the peer
  accepts: `STREAM STATUS RESULT=OK ID=s1`. Errors answer
  `CANT_REACH_PEER` / `TIMEOUT` / `I2P_ERROR`.
- `ACCEPT` waits for an inbound SYN (up to the handshake timeout, then
  `TIMEOUT`), completes the garlic handshake in the reverse direction and
  replies OK.
- After OK, the TCP connection is the stream: client bytes are carried as
  garlic'd stream frames to the peer, peer frames are delivered as raw bytes.
  Stream frames sequence-chunk large writes and reassemble in order; closing
  the TCP connection sends a FIN through the garlic stream and closes the
  remote side (and vice versa).
- `SILENT=true` suppresses the STATUS reply.

### Datagrams (STYLE=DATAGRAM / RAW)

```
DATAGRAM SEND ID=d1 DESTINATION=<b64 destination> SIZE=n\n<n payload bytes>
```

- Payload fragmentation is handled by the bridge: large datagrams are split
  into garlic-sized chunks, sequenced, and reassembled at the receiving
  session (up to the SAM limit of 11,520 bytes).
- `DATAGRAM` carries the sender's destination (repliable); `RAW` is anonymous.
- No reply is produced per SAM v3; delivery to the receiving client follows
  the session's datagram mode above.

### Naming and destination utilities

```
NAMING LOOKUP NAME=ME                        → NAMING REPLY RESULT=OK NAME=… VALUE=<b64>
NAMING LOOKUP NAME=<52-char>.b32.i2p         → resolves via the network database
NAMING LOOKUP NAME=site.i2p                  → addressbook (KEY_NOT_FOUND if unknown)
NAMING ADD NAME=site.i2p DESTINATION=<b64>   → destination import (addressbook)
DEST GENERATE                                → DEST REPLY PUB=<b64 dest> PRIV=<b64 keys>
```

## Result codes

`OK`, `DUPLICATED_ID`, `KEY_NOT_FOUND`, `CANT_REACH_PEER`, `TIMEOUT`,
`NO_VERSION`, `I2P_ERROR MESSAGE=<reason>`.

## Error handling

- Malformed or unknown verbs answer `I2P_ERROR` and keep the connection.
- `SESSION CREATE` before a successful HELLO is rejected.
- Datagram sends consume the announced payload bytes even on validation
  failure so the command framing stays in sync.
- QUIT or socket close tears down the session (pool stopped, LeaseSet
  session removed) and releases stream state.

## Quick start

```
python3 - <<'PY'
import socket
s = socket.create_connection(("127.0.0.1", 7656))
def cmd(line):
    s.sendall((line + "\n").encode())
    return s.recv(4096).decode().strip()
print(cmd("HELLO VERSION MIN=3.0 MAX=3.3"))
print(cmd("SESSION CREATE STYLE=STREAM ID=demo DESTINATION=TRANSIENT"))
# For a real stream: STREAM CONNECT to a peer's destination b64, then
# read/write raw bytes on this socket.
s.sendall(b"SESSION QUIT\n")
PY
```

## Conformance

The in-app self-test suite drives the full command set over a real loopback
TCP socket against a live in-memory router network (tunnel hops, netdb,
garlic pipeline): HELLO negotiation and edge cases, session creation with
transient and imported keys, LeaseSet publication, NAMING lookups (ME, b32
DHT, addressbook) and DEST GENERATE, STREAM CONNECT/ACCEPT end-to-end through
tunnels with bidirectional data and FIN propagation, fragmented DATAGRAM
SEND with reassembly, and anonymous RAW datagrams.

## Deviations & integration notes

- SAM pools default to single-hop tunnels; multi-hop pooling lands together
  with the tunnel-layer alignment work (nested per-hop layer budget).
- LeaseSet publication requires live inbound tunnels; sessions report
  `no lease yet` until peers exist and builds succeed.
- The bridge installs the outbound/inbound gateway glue on routers it
  controls (the reference rig demonstrates the full path). On the live
  network remote hops run the standard I2P IBGW/OBEP behavior; tunnel build
  delivery over NTCP2 is part of the core router alignment work.
- The I2NP wire type codes for Garlic (21) and TunnelGateway remain marked
  provisional pending live-network verification (see COMPLIANCE_REVIEW.md).
- App integration: `I2PRouterAppContext.shared.samServer` owns the listener;
  the router's `start()` boots it. The SAM tab exposes status, sessions, the
  command reference and the activity log.
## Session persistence

`SESSION CREATE` accepts an optional `PERSISTENT=true` option. When set, the bridge saves the destination's private keys under the session nickname (in `Application Support/i2p-sam-keys`) and restores them on a later `SESSION CREATE` with the same nickname, giving the session a stable destination across reconnects and bridge restarts. Without the option, `TRANSIENT` always generates a fresh destination.

```
SESSION CREATE STYLE=STREAM ID=echo DESTINATION=TRANSIENT PERSISTENT=true
```

## Load characteristics

The conformance suite includes a load validation: three concurrent stream pairs (each on its own connection, per SAM v3's one-stream-per-connection model) run at the same time over the loopback router rig. Each stream performs six latency probes (32-byte round-trips, reported as average RTT in ms) and one 8 KB bidirectional bulk transfer (reported in KB/s). The results appear in the app's self-test card alongside the other SAM conformance results, giving a baseline throughput/latency reference for the bridge as tunnels and transports evolve.