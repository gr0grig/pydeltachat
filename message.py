"""Delta Chat encrypted message construction.

Builds signed+encrypted PGP/MIME messages with proper Delta Chat headers.
"""

import email.utils
import uuid

from .crypto import build_pgp_mime, sign_and_encrypt


def build_encrypted_message(from_addr: str, to_addr: str, text: str,
                            recipient_key_bytes: bytes, privkey: dict,
                            pubkey_b64: str, display_name: str = "") -> bytes:
    """Build a signed+encrypted Delta Chat message.

    privkey: parsed private key dict (from openpgp.parse_privkey)
    """
    msg_id = f"<{uuid.uuid4()}@pydeltachat>"
    date = email.utils.formatdate(localtime=True)
    from_hdr = email.utils.formataddr((display_name, from_addr)) if display_name else from_addr
    subject = text[:40] if len(text) <= 40 else text[:37] + "..."

    inner_lines = [
        f'Content-Type: text/plain; charset="utf-8"; protected-headers="v1"',
        f"From: {from_hdr}",
        f"To: <{to_addr}>",
        f"Subject: {subject}",
        f"Date: {date}",
        f"Message-ID: {msg_id}",
        "Chat-Version: 1.0",
        f"Autocrypt: addr={from_addr}; prefer-encrypt=mutual; keydata={pubkey_b64}",
        "MIME-Version: 1.0",
        "",
        text,
    ]
    inner_bytes = "\r\n".join(inner_lines).encode("utf-8")

    armor = sign_and_encrypt(inner_bytes, privkey, recipient_key_bytes)
    return build_pgp_mime(armor, from_addr, to_addr, pubkey_b64=pubkey_b64)
