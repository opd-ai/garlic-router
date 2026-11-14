Reseed signing certificates
===========================

These are the public SU3 signer certificates the I2P reference routers ship
for reseed verification:

  Java I2P:  installer/resources/certificates/reseed/
  i2pd:      contrib/certificates/reseed/   (copied from here; BSD-3)

Copied unchanged from i2pd's set (https://github.com/PurpleI2P/i2pd,
contrib/certificates/reseed). They are public trust anchors — no private key
material is involved.

How they are used: an `i2pseeds.su3` container names its signer in a header
field; I2PSU3Verifier looks that name up here (trimmed, lowercased, '@' folded
to '_at_', which is why the file names read `igor_at_novg.net.crt` for the
signer `igor@novg.net`) and verifies the container signature against the
certificate's public key. Unknown signers are rejected, exactly as both
reference routers reject them.

Adding a signer: drop its `<signer>.crt` file (PEM or DER) in this folder. The
file name is the signer ID. Remove a certificate here if a reseed operator
retires a key.
