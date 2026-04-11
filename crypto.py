"""PGP operations for Delta Chat.

Pure Python — uses _openpgp (Ed25519, X25519, AES) for all PGP operations.
No external dependencies (no pgpy, pysequoia, or GPG).

IMPORTANT: Keys must have NO separate signing subkey — only primary Ed25519 (sign)
+ Cv25519 subkey (encrypt). Delta Chat verifies signatures only against the
primary key (pgp.rs:259).
"""

from __future__ import annotations

import base64
import email
import email.message
import email.utils
import logging
import textwrap
import uuid

from . import _openpgp as openpgp

log = logging.getLogger(__name__)


# ── Key generation ───────────────────────────────────────────────────────


def generate_key(addr: str, display_name: str = "") -> dict:
    """Generate Ed25519 + Cv25519 key (pure Python, no GPG).

    Returns dict with: fingerprint, privkey_armor, pubkey_armor, pubkey_b64
    """
    uid = f"{display_name} <{addr}>" if display_name else addr
    result = openpgp.generate_key(uid)
    log.info("Generated key %s for %s", result["fingerprint"], addr)
    return {
        "fingerprint": result["fingerprint"],
        "privkey_armor": result["privkey_armor"],
        "pubkey_armor": result["pubkey_armor"],
        "pubkey_b64": result["pubkey_b64"],
    }


# ── Autocrypt ────────────────────────────────────────────────────────────


def fold_autocrypt_header(addr: str, pubkey_b64: str) -> str:
    """Build folded Autocrypt header for SMTP line limits."""
    first = f"Autocrypt: addr={addr}; prefer-encrypt=mutual;"
    kd = f"keydata={pubkey_b64}"
    wrapped = textwrap.wrap(kd, width=72)
    lines = [first] + [f"\t{w}" for w in wrapped]
    return "\r\n".join(lines)


def extract_autocrypt_key(msg) -> tuple[str, bytes] | None:
    """Extract (addr, raw_key_bytes) from Autocrypt header."""
    ac = msg.get("Autocrypt", "")
    if not ac:
        return None
    addr = keydata = None
    for part in ac.split(";"):
        part = part.strip()
        if part.startswith("addr="):
            addr = part[5:].strip()
        elif part.startswith("keydata="):
            keydata = part[8:].strip()
    if not addr or not keydata:
        return None
    try:
        key_bytes = base64.b64decode(keydata)
        openpgp.parse_pubkey(key_bytes)  # validate
        return (addr, key_bytes)
    except Exception:
        return None


# ── PGP/MIME ─────────────────────────────────────────────────────────────


def build_pgp_mime(encrypted_armor: bytes | str, from_addr: str, to_addr: str,
                   pubkey_b64: str = "", subject: str = "[...]") -> bytes:
    """Build PGP/MIME email (RFC 3156) from encrypted armor.

    Matches DC `group_headers_by_confidentiality`:
    - Subject: "[...]"
    - From: address-only (no display name)
    - To: "hidden-recipients: ;"
    """
    if isinstance(encrypted_armor, bytes):
        encrypted_armor = encrypted_armor.decode("utf-8")
    boundary = f"b-{uuid.uuid4().hex[:16]}"
    msg_id = f"<{uuid.uuid4()}@pydeltachat>"
    date = email.utils.formatdate(localtime=True)

    headers = [
        f'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="{boundary}"',
        "MIME-Version: 1.0",
        "Chat-Version: 1.0",
        f"From: <{from_addr}>",
        'To: "hidden-recipients": ;',
        f"Date: {date}",
        f"Message-ID: {msg_id}",
        f"Subject: {subject}",
    ]

    ac_header = ""
    if pubkey_b64:
        ac_header = fold_autocrypt_header(from_addr, pubkey_b64) + "\r\n"

    body_lines = [
        "",
        f"--{boundary}",
        "Content-Type: application/pgp-encrypted",
        "",
        "Version: 1",
        "",
        f"--{boundary}",
        'Content-Type: application/octet-stream; name="encrypted.asc"',
        'Content-Disposition: inline; filename="encrypted.asc"',
        "",
    ] + encrypted_armor.replace("\r\n", "\n").rstrip("\n").split("\n") + [
        f"--{boundary}--",
        "",
    ]

    raw = "\r\n".join(headers) + "\r\n" + ac_header + "\r\n".join(body_lines)
    return raw.encode("utf-8")


def extract_pgp_payload(msg) -> bytes | None:
    """Extract PGP encrypted data from multipart/encrypted email."""
    if msg.get_content_type() != "multipart/encrypted":
        return None
    for part in msg.walk():
        if part.get_content_type() == "application/octet-stream":
            payload = part.get_payload(decode=True)
            if payload and b"-----BEGIN PGP MESSAGE-----" in payload:
                return payload
            p = part.get_payload(decode=False)
            if isinstance(p, str) and "-----BEGIN PGP MESSAGE-----" in p:
                return p.encode()
    return None


# ── Encrypt / Sign ───────────────────────────────────────────────────────


def sign_and_encrypt(inner_bytes: bytes, privkey: dict,
                     recipient_key_bytes: bytes) -> str:
    """Sign with privkey + encrypt to recipient. Returns PGP armor string.

    privkey: parsed private key dict (from openpgp.parse_privkey)
    recipient_key_bytes: raw public key bytes (binary OpenPGP)
    """
    recipient = openpgp.parse_pubkey(recipient_key_bytes)
    return openpgp.encrypt_and_sign(inner_bytes, privkey, recipient)


def symmetric_encrypt(inner_bytes: bytes, shared_secret: str,
                      privkey: dict | None = None) -> str:
    """Symmetric-encrypt (optionally signed). Returns PGP armor string.

    privkey: parsed private key dict or None
    """
    return openpgp.encrypt_symmetric(inner_bytes, shared_secret, signer=privkey)


# ── Decrypt ──────────────────────────────────────────────────────────────


def decrypt_symmetric(pgp_data: bytes, password: str) -> email.message.Message | None:
    """Decrypt with password (native). Returns parsed MIME or None."""
    try:
        plaintext = openpgp.decrypt_symmetric_msg(pgp_data, password)
        return email.message_from_bytes(plaintext)
    except Exception:
        return None


def decrypt_asymmetric(pgp_data: bytes, privkey: dict) -> email.message.Message | None:
    """Decrypt with private key (native). Returns parsed MIME or None.

    privkey: parsed private key dict (from openpgp.parse_privkey)
    """
    try:
        plaintext = openpgp.decrypt_public(pgp_data, privkey)
        return email.message_from_bytes(plaintext)
    except Exception:
        return None


# ── Text extraction ──────────────────────────────────────────────────────


def get_text_body(msg) -> str:
    """Extract plain text body from a MIME message."""
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type() == "text/plain":
                body = p.get_payload(decode=True)
                if body:
                    return body.decode("utf-8", errors="replace")
    else:
        body = msg.get_payload(decode=True)
        if body:
            return body.decode("utf-8", errors="replace")
        body = msg.get_payload()
        if isinstance(body, str):
            return body
    return ""
