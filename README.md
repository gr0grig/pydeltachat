# pydeltachat

Native Python implementation of the Delta Chat protocol. **Zero external dependencies** — all crypto (OpenPGP, Ed25519, X25519, AES) is implemented in pure Python.

## Requirements

- Python 3.10+

No pip packages, no GPG, no Rust compilation.

## Quick Start

```bash
# 1. Register a chatmail account
python -m pydeltachat.tests.register

# 2a. Start the echo bot (inviter role — prints invite link, replies to messages)
python -m pydeltachat.tests.echobot

# 2b. ...or join an existing invite and send one message (joiner role)
python -m pydeltachat.tests.join_and_send --link "https://i.delta.chat/#..." --text "Hello!"
```

Both test scripts accept `--debug` to dump raw MIME of every outgoing and incoming message.

The echo bot completes SecureJoin (inviter side), sends a welcome message, and echoes back anything you send. `join_and_send` walks through the joiner side of the handshake and delivers a single encrypted message to the inviter.

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

SecureJoin v3 protocol — both joiner and inviter sides:

```
Joiner  -> Inviter:  vc-request            (cleartext, legacy bootstrap)
                 or  vc-request-pubkey     (v3, symmetric)
Inviter -> Joiner:   vc-auth-required      (from mainline DC, cleartext)
                 or  vc-pubkey             (v3, symmetric, signed)
Joiner  -> Inviter:  vc-request-with-auth  (asymmetric, signed)
Inviter -> Joiner:   vc-contact-confirm    (asymmetric, signed)
```

| Function | Role | Description |
|---|---|---|
| `build_vc_request(...)` | joiner | Step 1 (legacy cleartext bootstrap) |
| `build_vc_request_pubkey(...)` | joiner | Step 1 (v3 symmetric-encrypted bootstrap) |
| `build_vc_pubkey(...)` | inviter | Step 2 (v3 symmetric-encrypted, signed, carries Autocrypt key) |
| `build_vc_request_with_auth(...)` | joiner | Step 3 (public-key encrypted, signed, carries auth code) |
| `build_vc_contact_confirm(...)` | inviter | Step 4 (public-key encrypted, signed confirmation) |

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

Delta Chat verifies signatures only against the primary key (`pgp.rs:259`). Keys must have:

- **Primary**: Ed25519 (sign + certify)
- **Subkey**: Cv25519 (encrypt only)
- **No signing subkey** — if one exists, PGPy/GPG prefers it over the primary, and DC's signature check fails silently (no padlock).

### S2K type for SecureJoin

Delta Chat's `check_symmetric_encryption` only accepts **S2K type 1 (Salted)**. Standard S2K type 3 (Iterated+Salted) — the default in both `pgpy` and most OpenPGP libraries — is rejected with `"unsupported string2key algorithm"`. This library uses S2K type 1 for all symmetric encryption.

### Decryption compatibility

Handles both RFC 4880 (PKESK v3, SEIPD v1) and RFC 9580 (PKESK v6, SEIPD v2 with OCB/AEAD) — can decrypt messages from any Delta Chat version.

### Autocrypt + SecureJoin

Two layers of trust:

- **Autocrypt** — opportunistic TOFU: the first public key seen for an address is trusted. Implemented via `fold_autocrypt_header()` / `extract_autocrypt_key()`. Vulnerable to an active MITM on the very first contact.
- **SecureJoin v3** — out-of-band fingerprint verification via an invite link containing the inviter's fingerprint + shared secret. Closes the first-contact MITM hole. This is what produces the verified (green-checkmark) state in Delta Chat UI.
