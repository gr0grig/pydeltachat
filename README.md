# pydeltachat

Native Python implementation of the Delta Chat protocol. **Zero external dependencies** — all crypto (OpenPGP, Ed25519, X25519, AES) is implemented in pure Python.

## Requirements

- Python 3.10+

No pip packages, no GPG, no Rust compilation.

## Quick Start

```bash
# 1. Register a chatmail account
python -m pydeltachat.tests.register

# 2. Start the echo bot (prints invite link)
python -m pydeltachat.tests.echobot

# 3. Scan the invite link in Delta Chat
```

The bot completes SecureJoin, sends a welcome message, and echoes back anything you send.

## Library Modules

### `pydeltachat.crypto`

PGP operations: key generation, encryption, signing, decryption, Autocrypt.

| Function | Description |
|---|---|
| `generate_key(addr, display_name)` | Generate Ed25519 + Cv25519 keypair |
| `sign_and_encrypt(inner_bytes, privkey, recipient_key_bytes)` | Sign + encrypt to recipient |
| `symmetric_encrypt(inner_bytes, shared_secret, privkey)` | Symmetric encrypt (S2K type 1) |
| `decrypt_asymmetric(pgp_data, privkey)` | Decrypt with private key |
| `decrypt_symmetric(pgp_data, password)` | Decrypt with passphrase |
| `build_pgp_mime(encrypted_armor, from_addr, to_addr, ...)` | Wrap in multipart/encrypted |
| `extract_pgp_payload(msg)` | Extract PGP data from email |
| `fold_autocrypt_header(addr, pubkey_b64)` | Build Autocrypt header |
| `extract_autocrypt_key(msg)` | Extract `(addr, key_bytes)` from Autocrypt |
| `get_text_body(msg)` | Extract plain text from MIME message |

### `pydeltachat.message`

| Function | Description |
|---|---|
| `build_encrypted_message(from_addr, to_addr, text, recipient_key_bytes, privkey, pubkey_b64, ...)` | Build signed+encrypted Delta Chat message |

### `pydeltachat.securejoin`

SecureJoin v3 protocol (inviter side):

```
Joiner  -> Inviter:  vc-request-pubkey    (symmetric)
Inviter -> Joiner:   vc-pubkey            (symmetric, signed)
Joiner  -> Inviter:  vc-request-with-auth (asymmetric, signed)
Inviter -> Joiner:   vc-contact-confirm   (asymmetric, signed)
```

| Function | Description |
|---|---|
| `build_vc_pubkey(...)` | Step 2: symmetric-encrypted response |
| `build_vc_contact_confirm(...)` | Step 4: public-key encrypted confirmation |

### `pydeltachat.invite`

Invite link generation and parsing (`https://i.delta.chat/#FP&v=3&i=...&s=...&a=...&n=...`).

| Function | Description |
|---|---|
| `generate_invite_link(fingerprint, addr, name, ...)` | Generate invite link + tokens |
| `parse_invite_link(url)` | Parse invite link into dict |

### `pydeltachat.transport`

IMAP/SMTP connection management with auto-reconnect.

**`IMAPConnection`**: `connect()`, `select_inbox()`, `fetch_new_messages()`, `poll_wait()`, `close()`

**`SMTPConnection`**: `connect()`, `send()`, `close()`

### `pydeltachat.onboarding`

Chatmail account creation (auto-created on first IMAP login).

| Function | Description |
|---|---|
| `generate_credentials(domain)` | Random `(email, password)` |
| `create_account(domain, display_name)` | Generate credentials + activate via IMAP |

## Native Crypto Modules

All crypto is pure Python, no external dependencies:

| Module | Description |
|---|---|
| `_openpgp.py` | OpenPGP packet construction, key generation, encrypt/decrypt/sign (RFC 4880) |
| `_ed25519.py` | Ed25519 digital signatures |
| `_x25519.py` | X25519 ECDH key exchange |
| `_aes.py` | AES-CFB and AES-OCB encryption |

Output format: PKESK v3 + SEIPD v1 (RFC 4880) — fully compatible with Delta Chat.

## Architecture Notes

### Key structure

Delta Chat verifies signatures only against the primary key. Keys must have:

- **Primary**: Ed25519 (sign + certify)
- **Subkey**: Cv25519 (encrypt only)
- **No signing subkey**

### S2K type for SecureJoin

Delta Chat's `check_symmetric_encryption` only accepts **S2K type 1 (Salted)**. Standard S2K type 3 (Iterated+Salted) is rejected. This library uses S2K type 1 for symmetric encryption.

### Decryption compatibility

Handles both RFC 4880 (PKESK v3, SEIPD v1) and RFC 9580 (PKESK v6, SEIPD v2 with OCB/AEAD) — can decrypt messages from any Delta Chat version.
