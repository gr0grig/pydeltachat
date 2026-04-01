"""PGP operations for Delta Chat.

Key generation (GPG), encryption/signing (PGPy), decryption (pysequoia).

IMPORTANT: Keys must have NO separate signing subkey — only primary Ed25519 (sign)
+ Cv25519 subkey (encrypt). Delta Chat verifies signatures only against the
primary key (pgp.rs:259).

PGPy produces PKESK v3 + SEIPD v1 (RFC 4880) — compatible with Delta Chat.
pysequoia produces PKESK v6 + SEIPD v2 (RFC 9580) — NOT compatible for encryption.
pysequoia works fine for decryption.
"""

from __future__ import annotations

import base64
import email
import email.message
import email.utils
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
import warnings

import pgpy
from pysequoia import Cert, decrypt

warnings.filterwarnings("ignore", message=".*compression.*not in key preferences.*")

log = logging.getLogger(__name__)


# ── Key generation ───────────────────────────────────────────────────────


def _find_gpg() -> str:
    """Find GPG executable."""
    found = shutil.which("gpg")
    if found:
        return found
    for candidate in [
        r"C:\Program Files\Git\usr\bin\gpg.exe",
        r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
        r"C:\Program Files\GnuPG\bin\gpg.exe",
    ]:
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError("gpg not found. Install Git for Windows or GnuPG.")


def _gpg_path(raw_path: str, gpg_exe: str) -> str:
    """Convert path for GPG (Git's GPG needs Unix-style paths on Windows)."""
    if sys.platform == "win32" and "Git" in gpg_exe:
        if len(raw_path) > 2 and raw_path[1] == ':':
            return "/" + raw_path[0].lower() + raw_path[2:].replace("\\", "/")
        return raw_path.replace("\\", "/")
    return raw_path


def generate_key(addr: str, display_name: str = "") -> dict:
    """Generate Ed25519 + Cv25519 key via GPG (no signing subkey).

    Returns dict with: fingerprint, privkey_armor, pubkey_armor, pubkey_b64
    """
    gpg_exe = _find_gpg()
    raw_home = tempfile.mkdtemp(prefix="pydckey_")
    homedir = _gpg_path(raw_home, gpg_exe)
    gpg = [gpg_exe, "--homedir", homedir]

    try:
        uid = f"{display_name} <{addr}>" if display_name else addr

        # Primary Ed25519 (sign + certify)
        r = subprocess.run(
            gpg + ["--batch", "--passphrase", "", "--pinentry-mode", "loopback",
                   "--quick-generate-key", uid, "ed25519", "sign", "0"],
            capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"GPG keygen failed: {r.stderr.decode()}")

        # Get fingerprint
        r = subprocess.run(gpg + ["--batch", "--with-colons", "--list-keys"], capture_output=True)
        fpr = None
        for line in r.stdout.decode().split('\n'):
            parts = line.split(':')
            if parts[0] == 'fpr':
                fpr = parts[9].lower()
                break
        if not fpr:
            raise RuntimeError("Could not find fingerprint")

        # Cv25519 encryption subkey
        r = subprocess.run(
            gpg + ["--batch", "--passphrase", "", "--pinentry-mode", "loopback",
                   "--quick-add-key", fpr.upper(), "cv25519", "encr", "0"],
            capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(f"GPG add subkey failed: {r.stderr.decode()}")

        # Export private key
        r = subprocess.run(
            gpg + ["--batch", "--passphrase", "", "--pinentry-mode", "loopback",
                   "--armor", "--export-secret-keys", fpr.upper()],
            capture_output=True)
        privkey_armor = r.stdout.decode()

        # Export public key (armor)
        r = subprocess.run(gpg + ["--batch", "--armor", "--export", fpr.upper()], capture_output=True)
        pubkey_armor = r.stdout.decode()

        # Export public key (binary -> base64 for Autocrypt)
        r = subprocess.run(gpg + ["--batch", "--export", fpr.upper()], capture_output=True)
        pubkey_b64 = base64.b64encode(r.stdout).decode()

        log.info("Generated key %s for %s", fpr, addr)
        return {
            "fingerprint": fpr,
            "privkey_armor": privkey_armor,
            "pubkey_armor": pubkey_armor,
            "pubkey_b64": pubkey_b64,
        }
    finally:
        shutil.rmtree(raw_home, ignore_errors=True)


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
        pgpy.PGPKey.from_blob(key_bytes)  # validate
        return (addr, key_bytes)
    except Exception:
        return None


# ── PGP/MIME ─────────────────────────────────────────────────────────────


def build_pgp_mime(encrypted_armor: bytes | str, from_addr: str, to_addr: str,
                   pubkey_b64: str = "", subject: str = "...") -> bytes:
    """Build PGP/MIME email (RFC 3156) from encrypted armor."""
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
        f"To: <{to_addr}>",
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


def sign_and_encrypt(inner_bytes: bytes, privkey: pgpy.PGPKey,
                     recipient_key_bytes: bytes) -> str:
    """Sign with privkey + encrypt to recipient. Returns PGP armor string."""
    recipient_key, _ = pgpy.PGPKey.from_blob(recipient_key_bytes)
    pgp_msg = pgpy.PGPMessage.new(inner_bytes)
    sig = privkey.sign(pgp_msg)
    pgp_msg |= sig
    encrypted = recipient_key.encrypt(pgp_msg)
    return str(encrypted)


def symmetric_encrypt(inner_bytes: bytes, shared_secret: str,
                      privkey: pgpy.PGPKey | None = None) -> str:
    """Symmetric-encrypt (optionally signed). Returns PGP armor string."""
    pgp_msg = pgpy.PGPMessage.new(inner_bytes)
    if privkey:
        sig = privkey.sign(pgp_msg)
        pgp_msg |= sig
    encrypted = pgp_msg.encrypt(passphrase=shared_secret)
    return str(encrypted)


# ── Decrypt ──────────────────────────────────────────────────────────────


def decrypt_symmetric(pgp_data: bytes, password: str) -> email.message.Message | None:
    """Decrypt with password (pysequoia). Returns parsed MIME or None."""
    try:
        result = decrypt(pgp_data, passwords=[password])
        return email.message_from_bytes(result.bytes)
    except Exception:
        return None


def decrypt_asymmetric(pgp_data: bytes, cert: Cert) -> email.message.Message | None:
    """Decrypt with private key (pysequoia). Returns parsed MIME or None."""
    try:
        result = decrypt(pgp_data, decryptor=cert.secrets.decryptor())
        return email.message_from_bytes(result.bytes)
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
