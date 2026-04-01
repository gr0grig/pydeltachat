# pydeltachat

Native Python implementation of the Delta Chat protocol. Works **without** `deltachat-rpc-server` or Rust compilation — uses only Python libraries for PGP, IMAP, and SMTP.

## Requirements

- Python 3.10+
- GPG (via Git for Windows or GnuPG)
- Python packages:

```
pip install pgpy pysequoia
```

## Quick Start

```bash
# 1. Register a chatmail account
python -m pydeltachat.tests.register

# 2. Get the invite link
python -m pydeltachat.tests.get_link

# 3. Scan the link in Delta Chat, then start the echo bot
python -m pydeltachat.tests.echobot
```

The bot accepts SecureJoin connections and echoes back any message you send.

## Library Modules

### `pydeltachat.onboarding`

Chatmail instant account creation. Chatmail servers auto-create accounts on first IMAP login — no separate registration API needed.

| Function | Description |
|---|---|
| `generate_credentials(domain)` | Generate random `(email, password)` for a chatmail server |
| `create_account(domain, display_name)` | Generate credentials + IMAP login to activate account |

### `pydeltachat.crypto`

All PGP operations: key generation, encryption, signing, decryption, Autocrypt handling.

**Key generation** (via GPG subprocess):

| Function | Description |
|---|---|
| `generate_key(addr, display_name)` | Generate Ed25519 + Cv25519 keypair. Returns dict with `fingerprint`, `privkey_armor`, `pubkey_armor`, `pubkey_b64` |

Keys have NO separate signing subkey — only primary Ed25519 (sign/certify) + Cv25519 subkey (encrypt). Delta Chat verifies signatures only against the primary key.

**Encryption/signing** (via PGPy — produces RFC 4880 PKESK v3 + SEIPD v1, compatible with Delta Chat):

| Function | Description |
|---|---|
| `sign_and_encrypt(inner_bytes, privkey, recipient_key_bytes)` | Sign with private key + encrypt to recipient public key |
| `symmetric_encrypt(inner_bytes, shared_secret, privkey=None)` | Symmetric encrypt with passphrase, optionally signed |

**Decryption** (via pysequoia — handles both RFC 4880 and RFC 9580):

| Function | Description |
|---|---|
| `decrypt_asymmetric(pgp_data, cert)` | Decrypt with private key, returns parsed MIME message |
| `decrypt_symmetric(pgp_data, password)` | Decrypt with passphrase, returns parsed MIME message |

**PGP/MIME (RFC 3156)**:

| Function | Description |
|---|---|
| `build_pgp_mime(encrypted_armor, from_addr, to_addr, ...)` | Wrap PGP armor in `multipart/encrypted` email |
| `extract_pgp_payload(msg)` | Extract PGP data from `multipart/encrypted` email |

**Autocrypt**:

| Function | Description |
|---|---|
| `fold_autocrypt_header(addr, pubkey_b64)` | Build folded Autocrypt header for SMTP line limits |
| `extract_autocrypt_key(msg)` | Extract `(addr, raw_key_bytes)` from Autocrypt header |

**Utilities**:

| Function | Description |
|---|---|
| `get_text_body(msg)` | Extract plain text body from MIME message |

### `pydeltachat.message`

Delta Chat encrypted message construction.

| Function | Description |
|---|---|
| `build_encrypted_message(from_addr, to_addr, text, recipient_key_bytes, privkey, pubkey_b64, ...)` | Build a signed+encrypted Delta Chat message with `Chat-Version: 1.0` and protected headers |

### `pydeltachat.securejoin`

SecureJoin v3 protocol — inviter side of the handshake.

The SecureJoin handshake establishes verified contact between two Delta Chat instances:

```
Step 1: Joiner  -> Inviter:  vc-request-pubkey    (symmetric, unsigned)
Step 2: Inviter -> Joiner:   vc-pubkey             (symmetric, SIGNED)
Step 3: Joiner  -> Inviter:  vc-request-with-auth  (asymmetric, signed)
Step 4: Inviter -> Joiner:   vc-contact-confirm     (asymmetric, signed)
```

| Function | Description |
|---|---|
| `build_vc_pubkey(from_addr, to_addr, invite, pubkey_b64, fingerprint, privkey, ...)` | Build step 2: signed + symmetric-encrypted with shared secret |
| `build_vc_contact_confirm(from_addr, to_addr, recipient_key_bytes, privkey, pubkey_b64, ...)` | Build step 4: signed + public-key encrypted |

The shared secret is derived from the invite: `securejoin/{FINGERPRINT}/{auth_code}`.

### `pydeltachat.invite`

Invite link generation and parsing. Links follow the format:

```
https://i.delta.chat/#FINGERPRINT&v=3&i=INVITE_NUMBER&s=AUTH_CODE&a=ADDR&n=NAME
```

| Function | Description |
|---|---|
| `generate_invite_link(fingerprint, addr, name, ...)` | Generate invite link + tokens. Returns `(url, invite_dict)` |
| `parse_invite_link(url)` | Parse invite link into dict with `fingerprint`, `addr`, `name`, `invite_number`, `auth_code` |

### `pydeltachat.transport`

IMAP and SMTP connection management.

**`IMAPConnection`** — receive messages:

| Method | Description |
|---|---|
| `connect(user, password)` | Connect and authenticate (SSL, port 993) |
| `select_inbox()` | Select INBOX, return message count |
| `fetch_new_messages()` | Fetch messages since last check (by UID tracking) |
| `poll_wait(timeout, interval)` | Poll for new messages via NOOP + UID search |
| `close()` | Disconnect |

**`SMTPConnection`** — send messages:

| Method | Description |
|---|---|
| `connect(user, password)` | Connect and authenticate (SSL, port 465) |
| `send(from_addr, to_addr, raw_message)` | Send raw email bytes. Auto-reconnects on failure |
| `close()` | Disconnect |

## Test Scripts

All scripts are in `pydeltachat/tests/` and store data (`account.json`, `invite.json`) in the same directory.

### `register.py`

Register a new chatmail account with a Delta Chat-compatible PGP key.

```bash
python -m pydeltachat.tests.register
python -m pydeltachat.tests.register --name "My Bot" --domain nine.testrun.org
```

- Generates random chatmail credentials
- Creates Ed25519 + Cv25519 key via GPG (no signing subkey)
- Verifies that signing uses the primary key
- Saves everything to `account.json`
- Backs up the previous account to `account.json.bak`

### `get_link.py`

Generate and display a SecureJoin invite link for the registered account.

```bash
python -m pydeltachat.tests.get_link
```

- Reads `account.json`
- Generates a new invite (or loads existing `invite.json`)
- Auto-regenerates if the invite belongs to a different account
- Prints the link to scan in Delta Chat

### `echobot.py`

Echo bot that handles SecureJoin and replies to every message with "Echo: ...".

```bash
python -m pydeltachat.tests.echobot
python -m pydeltachat.tests.echobot --timeout 1800
```

- Connects to IMAP/SMTP using `account.json`
- Generates/loads invite link from `invite.json`
- Scans existing messages for contacts and pending handshakes
- Handles SecureJoin v3: `vc-request-pubkey` -> `vc-pubkey`, `vc-request-with-auth` -> `vc-contact-confirm`
- Echoes back encrypted messages from verified contacts
- Default timeout: 600 seconds

## Architecture Notes

### Why PGPy for encryption, pysequoia for decryption?

- **PGPy** produces PKESK v3 + SEIPD v1 (RFC 4880) — compatible with Delta Chat
- **pysequoia** produces PKESK v6 + SEIPD v2 (RFC 9580) — NOT compatible with Delta Chat for encryption
- **pysequoia** handles decryption of both formats fine

### Why GPG for key generation?

PGPy cannot generate Ed25519/Cv25519 keys. GPG is used in a temporary homedir to generate the keypair, then the armored keys are exported and used by PGPy for all subsequent operations.

### Key structure

Delta Chat's signature verification (`pgp.rs:259`) only checks the primary key. If a signing subkey exists, PGPy/GPG will prefer it for signing, causing signature verification failures (messages show without the encryption padlock). The key must have:

- **Primary key**: Ed25519 (sign + certify)
- **Subkey**: Cv25519 (encrypt only)
- **No signing subkey**
"# pydeltachat" 
