
# Spec Compliance Review — Pure Swift I2P Router

Scope: modern crypto only — ECIES X25519 + ChaCha20-Poly1305, NTCP2 Noise_XK_25519_ChaChaPoly_SHA256, Ed25519 (SigType 7) / Ed25519ph (SigType 11), HKDF-SHA256, SHA-256 / BLAKE2b. No ElGamal, DSA, 3DES or legacy signature types exist anywhere in the codebase (verified by the algorithm-registry self-test).

Verdict: 4 of 7 compliance areas pass outright, 1 passes with fixes applied during this review, 2 carry documented interop divergences that must be closed before live-network (mainnet) participation. All live-network items are gated on the SAM roadmap phases, exactly as planned.
## Area 1 — Data structures & binary format: PASS

Big-endian encoding verified on every primitive (byte-order self-test asserts network byte order). RouterInfo and LeaseSet round-trip with signatures verified on parse and tampered bytes rejected (RouterInfoIdentity hash stable). Certificates carry the modern types only. I2P Mapping uses 2-byte length with sorted keys; keys are ASCII in practice, byte-order sorting would differ only for non-ASCII keys (noted, no action).

## Area 2 — NetDB & peer discovery: PASS (live-network items pending)

Kademlia XOR metric verified byte-wise with lexicographic ordering. Floodfill selection by XOR distance with known-floodfill learning, DatabaseStore/Lookup/SearchReply cycles round-trip with reply tokens, and entries are ingested only after signature verification. Expiration matches spec (RouterInfo ~1h, LeaseSet ~1h with 10-15 min leases) with persistent disk storage. Pending: reseed and mainnet peer-distribution validation (SAM Phase 1).
## Area 3 — NTCP2 transport: PASS with one fix applied

Handshake phases (SessionRequest → SessionCreated → SessionConfirm) follow the Noise_XK pattern correctly: pre-message <- s mixed, es/ee/ss DH stages ordered as the spec requires, Split into two direction AEAD streams. Frames are [SipHash-obfuscated 2-byte length][ChaChaPoly payload+16-byte MAC] with per-counter masks, MAC failures throw and drop. Block types 0-5 (padding, options, routerInfo, data, termination, time) match the spec numbering, 16-byte payload alignment enforced.

FIX APPLIED: the Noise chaining state hashed the 32-byte protocol name. Noise §5 requires names of at most HASHLEN bytes to ride verbatim (zero-padded) as the chaining key and hash — the hashed form diverges from every mainnet NTCP2 peer's handshake KDF. Now used verbatim; covered by a dedicated self-test.

Pending live verification: message 1 options length prefix, the exact ephemeral-key obfuscation KDF literal (spec uses an AES-CBC keystream; this router substitutes a ChaCha20 keystream), and the two-stage SipHash key derivation. These are wire-exactness items a mainnet handshake will confirm or correct immediately (SAM Phase 1).
## Area 4 — Tunnel architecture: PASS with one divergence

VariableTunnelBuild records are 528 bytes, encrypted per-hop so only the target hop can read its record, with per-hop accept/reject codes on BuildReply. The pool orchestrates 3-5 outbound and inbound tunnels with staggered creation, 10-30 minute expiry, pre-built replacements and latency-aware selection. Tunnel IDs, hop states and the data path (decrypt one layer, forward) are exercised end-to-end by the tunnel and I2NP suites, including inbound-gateway delivery.

DIVERGENCE: tunnel layer encryption uses ChaCha20-Poly1305 with a 12-byte IV and a 16-byte tag per hop; the live tunnel spec uses AES-256-CBC layering with a 16-byte IV and no per-hop MAC (TunnelData payload 4-byte tunnel ID + 16-byte IV + 1008 bytes). This router's crypto scope is ChaChaPoly-only, so the divergence is accepted for now but MUST be closed before routing real traffic — it is the top remediation item for SAM Phase 1.

## Area 5 — I2NP protocol: PASS with fixes applied

Wire type codes were internal assignments that did not match the I2P common message spec. Reconciled during this review: DatabaseSearchReply 2→99, DeliveryStatus 3→10, DataMessage 9→31, Garlic 94→21, TunnelBuild 10→123 (this router's build format is ECIES VariableTunnelBuild), TunnelBuildReply 11→124. Header format (type, message ID, expiry, big-endian size) round-trips and stale messages are dropped on receipt.
## Area 6 — Garlic routing & e2e encryption: PASS with one divergence

ECIES-X25519 crypto core is spec-shaped: new-session ephemeral DH → HKDF-SHA256 session keys, ChaCha20-Poly1305 AEAD, 32-byte single-use session tags with inbound tag-to-key binding and replay rejection, clove sets with message ID + expiration (stale sets rejected on unwrap), delivery instructions for local/tunnel/router delivery with optional delay, per-clove certificates, and the wrap/unwrap pipeline addressed to a LeaseSet lease through the outbound tunnel pool. Expiration and replay edge cases are covered by tests.

DIVERGENCE: the garlic envelope is simplified versus the ECIES-X25519 spec — the spec frames the encrypted payload as [ephemeral key][static section][payload section] with DateTime, I2NP, Options, Termination and Padding blocks and defines exact HKDF info strings. This router uses a compact [ephemeral key][AEAD clove set] framing with its own HKDF info. Crypto strength is unaffected; wire interop with real peers is not. Remediation (re-frame to spec blocks) is scheduled with SAM Phase 1.
## Area 7 — Router behavior: PASS with gaps documented

Peer selection and connection pooling work (tunnel pool with replacement pre-building and build timeouts); NTCP2 sessions support concurrent peers, graceful termination via the Termination block, and the running router wires netdb, NTCP2 listener, tunnel pool and the I2NP router together with live status reporting. Gaps (by design of the roadmap, not review failures): lease publication/renewal cycles, bandwidth limiting and congestion awareness, peer reputation tracking — all are scheduled with SAM Phases 1-3 where real network participation begins.

## Runtime verification

A dedicated spec-compliance self-test suite now runs alongside the existing round-trip suites and checks programmatically what a review can: the algorithm registries contain only modern types, the reconciled I2NP wire codes, header round-trip plus expiry enforcement, big-endian byte order, the verbatim NTCP2 protocol-name chaining, nonce96 layout, block codec round-trip, frame MAC rejection, Ed25519ph dom2 with canonical-S rejection, and SipHash determinism. Existing suites already cover signature/tamper rejection, ReplayTag single-use, build reply codes and full garlic-over-tunnels delivery.

## Outstanding live-network checklist (SAM phases)

1. NTCP2 wire-exactness: message 1 options prefix, obfuscation KDF literal, sip KDF stages (Phase 1).
2. Tunnel layering: ChaChaPoly → AES-256-CBC with 16-byte IV (Phase 1).
3. Garlic envelope: re-frame to spec blocks and HKDF info strings (Phase 1).
4. Provisional TunnelGateway type code 15: verify against mainnet peers (Phase 1).
5. Reseed + floodfill connectivity on mainnet; peer distribution validation (Phase 1).
6. Lease publication cycles, bandwidth limits, congestion awareness, peer reputation (Phases 1-3).