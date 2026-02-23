SecretShare n8n Node

This node provides simple AES-256-GCM encryption and decryption for sharing secrets (API keys, tokens, passwords) using a passphrase-derived key.

Usage
- Operation: `Encrypt` or `Decrypt`
- `Secret`: plaintext to encrypt (when Operation is `Encrypt`)
- `Encrypted`: base64 payload to decrypt (when Operation is `Decrypt`)
- `Passphrase`: required passphrase (used to derive the AES key)

Format
- Encrypted payload is Base64 of `iv(12) | authTag(16) | ciphertext`.

Security notes
- The node derives the key using SHA-256 of the passphrase. For highest security, use high-entropy passphrases or integrate an KMS.

Example
1) Encrypt `my-api-key` with passphrase `s3cr3t` → stores `encrypted` string on output.
2) Send `encrypted` to a collaborator and they can `Decrypt` it with the same passphrase.
