"""SecureJoin v3 protocol for Delta Chat.

Implements the inviter side of the SecureJoin handshake:
  Step 1: Joiner sends vc-request-pubkey (symmetric)
  Step 2: Inviter sends vc-pubkey (symmetric, SIGNED, with Autocrypt key)
  Step 3: Joiner sends vc-request-with-auth (asymmetric)
  Step 4: Inviter sends vc-contact-confirm (asymmetric)
"""

import email.utils
import uuid
from email.mime.text import MIMEText

from .crypto import build_pgp_mime, sign_and_encrypt, symmetric_encrypt


def _build_inner_mime(from_addr: str, to_addr: str, display_name: str,
                      pubkey_b64: str, sj_header: str,
                      extra_headers: dict | None = None) -> bytes:
    """Build inner MIME for SecureJoin messages."""
    inner = MIMEText("Secure-Join", "plain", "utf-8")
    if display_name:
        inner["From"] = email.utils.formataddr((display_name, from_addr))
    else:
        inner["From"] = from_addr
    inner["To"] = to_addr
    inner["Date"] = email.utils.formatdate(localtime=True)
    inner["Message-ID"] = f"<{uuid.uuid4()}@pydeltachat>"
    inner["Chat-Version"] = "1.0"
    inner["Subject"] = "Secure-Join"
    inner["Secure-Join"] = sj_header
    if pubkey_b64:
        inner["Autocrypt"] = f"addr={from_addr}; prefer-encrypt=mutual; keydata={pubkey_b64}"
    if extra_headers:
        for k, v in extra_headers.items():
            inner[k] = v
    return inner.as_string().encode("utf-8")


def build_vc_pubkey(from_addr: str, to_addr: str, invite: dict,
                    pubkey_b64: str, fingerprint: str,
                    privkey: dict, display_name: str = "") -> bytes:
    """Build vc-pubkey (step 2): signed + symmetric-encrypted with shared secret.

    privkey: parsed private key dict (from openpgp.parse_privkey)
    """
    auth = invite["auth_code"]
    shared_secret = f"securejoin/{invite['fingerprint'].upper()}/{auth}"

    inner_bytes = _build_inner_mime(
        from_addr, to_addr, display_name, pubkey_b64,
        sj_header="vc-pubkey",
        extra_headers={
            "Secure-Join-Auth": auth,
            "Secure-Join-Fingerprint": fingerprint.upper(),
        },
    )

    armor = symmetric_encrypt(inner_bytes, shared_secret, privkey=privkey)
    return build_pgp_mime(armor, from_addr, to_addr, pubkey_b64=pubkey_b64)


def build_vc_contact_confirm(from_addr: str, to_addr: str,
                             recipient_key_bytes: bytes, privkey: dict,
                             pubkey_b64: str, display_name: str = "") -> bytes:
    """Build vc-contact-confirm (step 4): signed + public-key encrypted.

    privkey: parsed private key dict (from openpgp.parse_privkey)
    """
    inner_bytes = _build_inner_mime(
        from_addr, to_addr, display_name, pubkey_b64,
        sj_header="vc-contact-confirm",
    )

    armor = sign_and_encrypt(inner_bytes, privkey, recipient_key_bytes)
    return build_pgp_mime(armor, from_addr, to_addr, pubkey_b64=pubkey_b64)
