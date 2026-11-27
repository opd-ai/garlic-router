#!/usr/bin/env python3
"""Independently verifies an NTCP2 SessionRequest produced by the Swift router.

Usage: verify_msg1.py <peerStaticKeyHex> <ephemeralPrivHex> <message1Hex>
Implements the Noise_XK message-1 KDF from the NTCP2 spec with `cryptography`
and decrypts the options block. Not part of the app.
"""
import hashlib
import hmac
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL = b"Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"

peer_s = bytes.fromhex(sys.argv[1])
e_priv = bytes.fromhex(sys.argv[2])
msg = bytes.fromhex(sys.argv[3])

h = hashlib.sha256(PROTOCOL).digest()
ck = h
h = hashlib.sha256(h).digest()            # null prologue
h = hashlib.sha256(h + peer_s).digest()   # MixHash(rs)

key = X25519PrivateKey.from_private_bytes(e_priv)
try:
    e_pub = key.public_key().public_bytes_raw()
except AttributeError:  # older cryptography
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    e_pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
h = hashlib.sha256(h + e_pub).digest()    # MixHash(e)

es = key.exchange(X25519PublicKey.from_public_bytes(peer_s))
temp = hmac.new(ck, es, hashlib.sha256).digest()
ck2 = hmac.new(temp, b"\x01", hashlib.sha256).digest()
k = hmac.new(temp, ck2 + b"\x02", hashlib.sha256).digest()

plain = ChaCha20Poly1305(k).decrypt(b"\x00" * 12, msg[32:64], h)
print("ephemeralPublic", e_pub.hex())
print("options", plain.hex())
print("netId", plain[0], "ver", plain[1],
      "padLen", int.from_bytes(plain[2:4], "big"),
      "m3p2len", int.from_bytes(plain[4:6], "big"),
      "tsA", int.from_bytes(plain[8:12], "big"))
import time
print("clockSkew", int(time.time()) - int.from_bytes(plain[8:12], "big"))
