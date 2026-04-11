"""SecureJoin v3 protocol for Delta Chat.

Implements both sides of the SecureJoin handshake:
  Step 1: Joiner sends vc-request-pubkey (symmetric)
  Step 2: Inviter sends vc-pubkey (symmetric, SIGNED, with Autocrypt key)
  Step 3: Joiner sends vc-request-with-auth (asymmetric)
  Step 4: Inviter sends vc-contact-confirm (asymmetric)
"""

import email.utils
import uuid

from .crypto import build_pgp_mime, fold_autocrypt_header, sign_and_encrypt, symmetric_encrypt


def _build_inner_mime(from_addr: str, to_addr: str, display_name: str,
                      pubkey_b64: str, sj_header: str,
                      extra_headers: dict | None = None) -> bytes:
    """Build inner MIME for SecureJoin messages (protected headers v1).

    Matches DC's `add_headers_to_encrypted_part`: inner Content-Type carries
    `protected-headers="v1"` and the inner part includes Subject/From/To/etc.
    """
    msg_id = f"<{uuid.uuid4()}@pydeltachat>"
    date = email.utils.formatdate(localtime=True)
    # From: address-only form for SecureJoin (matches DC mimefactory.rs)
    from_hdr = f"<{from_addr}>"

    headers = [
        'Content-Type: text/plain; charset=utf-8; protected-headers="v1"',
        "Content-Transfer-Encoding: 7bit",
        "Subject: ...",
        f"From: {from_hdr}",
        f"To: <{to_addr}>",
        f"Date: {date}",
        f"Message-ID: {msg_id}",
        "Chat-Version: 1.0",
        f"Secure-Join: {sj_header}",
    ]
    if pubkey_b64:
        headers.append(fold_autocrypt_header(from_addr, pubkey_b64))
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append(f"{k}: {v}")

    body = "Secure-Join\r\n"
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode("utf-8")


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


def build_vc_request(from_addr: str, to_addr: str, invite: dict,
                     pubkey_b64: str = "", display_name: str = "") -> bytes:
    """Build vc-request (step 1, legacy cleartext): multipart/mixed.

    Joiner's initial message — sent as cleartext because the joiner does not
    yet have the inviter's key. Chatmail's filtermail has an explicit
    passthrough for vc-request/vg-request messages. Matches the canonical
    `securejoin-vc.eml` sample used by filtermail's blackbox tests.
    """
    boundary = f"b-{uuid.uuid4().hex[:16]}"
    msg_id = f"<{uuid.uuid4()}@pydeltachat>"
    date = email.utils.formatdate(localtime=True)
    from_hdr = (
        email.utils.formataddr((display_name, from_addr))
        if display_name else f"<{from_addr}>"
    )

    headers = [
        f"Subject: Message from {from_addr}",
        f"From: {from_hdr}",
        f"To: <{to_addr}>",
        f"Date: {date}",
        f"Message-ID: {msg_id}",
        "Chat-Version: 1.0",
        "Secure-Join: vc-request",
        f"Secure-Join-Invitenumber: {invite['invite_number']}",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
    ]
    if pubkey_b64:
        headers.append(fold_autocrypt_header(from_addr, pubkey_b64))

    body = [
        "",
        f"--{boundary}",
        "Content-Type: text/plain; charset=utf-8",
        "",
        "Secure-Join: vc-request",
        "",
        f"--{boundary}--",
        "",
    ]
    raw = "\r\n".join(headers) + "\r\n" + "\r\n".join(body)
    return raw.encode("utf-8")


def build_vc_request_pubkey(from_addr: str, to_addr: str, invite: dict,
                            display_name: str = "") -> bytes:
    """Build vc-request-pubkey (step 1, v3): symmetric-encrypted with shared secret.

    Alternative initial message for v3 invites. Minimal bootstrap — NO signing,
    NO attached pubkey (matches DC's `attach_self_pubkey = false` branch).
    Inner MIME carries `Secure-Join: vc-request-pubkey` + `Secure-Join-Auth`.
    """
    shared_secret = f"securejoin/{invite['fingerprint'].upper()}/{invite['auth_code']}"

    inner_bytes = _build_inner_mime(
        from_addr, to_addr, display_name, pubkey_b64="",
        sj_header="vc-request-pubkey",
        extra_headers={
            "Secure-Join-Auth": invite["auth_code"],
        },
    )

    armor = symmetric_encrypt(inner_bytes, shared_secret, privkey=None)
    return build_pgp_mime(armor, from_addr, to_addr, pubkey_b64="")


def build_vc_request_with_auth(from_addr: str, to_addr: str, invite: dict,
                               self_fingerprint: str,
                               recipient_key_bytes: bytes, privkey: dict,
                               pubkey_b64: str, display_name: str = "") -> bytes:
    """Build vc-request-with-auth (step 3): signed + public-key encrypted.

    Sent by joiner after receiving the inviter's key via vc-pubkey.
    `Secure-Join-Fingerprint` carries the JOINER's (Bob's) own fingerprint,
    not the inviter's — matches mainline DC (`self_fingerprint(context)`).
    """
    inner_bytes = _build_inner_mime(
        from_addr, to_addr, display_name, pubkey_b64,
        sj_header="vc-request-with-auth",
        extra_headers={
            "Secure-Join-Auth": invite["auth_code"],
            "Secure-Join-Fingerprint": self_fingerprint.upper(),
        },
    )

    armor = sign_and_encrypt(inner_bytes, privkey, recipient_key_bytes)
    return build_pgp_mime(armor, from_addr, to_addr, pubkey_b64=pubkey_b64)
