#!/usr/bin/env python3
"""Join a contact via SecureJoin (joiner role) and send an encrypted message.

Loads credentials from account.json, parses an invite link, walks through the
SecureJoin v3 handshake as the joiner and finally sends a plain text message
to the inviter.

Usage:
    python -m pydeltachat.tests.join_and_send --link "https://i.delta.chat/#..."
    python -m pydeltachat.tests.join_and_send --link "..." --text "Hello!" --timeout 300
"""

import argparse
import email.utils
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from pydeltachat import _openpgp as openpgp
from pydeltachat.transport import IMAPConnection, SMTPConnection
from pydeltachat.invite import parse_invite_link
from pydeltachat.crypto import (
    extract_autocrypt_key, extract_pgp_payload, decrypt_asymmetric,
)
from pydeltachat.securejoin import (
    build_vc_request, build_vc_request_with_auth,
)
from pydeltachat.message import build_encrypted_message


ACCOUNT_FILE = Path(__file__).parent / "account.json"





def main():
    parser = argparse.ArgumentParser(
        description="Join contact via SecureJoin and send a message",
    )
    parser.add_argument("--link", required=True, help="Invite link")
    parser.add_argument("--text", default="Hello from pydeltachat!",
                        help="Message text to send after handshake")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Seconds to wait for each handshake reply")
    parser.add_argument("--debug", action="store_true",
                        help="Print full raw MIME of every outgoing and incoming message")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    log = logging.getLogger("join_and_send")

    if not ACCOUNT_FILE.exists():
        log.error("account.json not found. Run: python -m pydeltachat.tests.register")
        sys.exit(1)

    # Load account
    data = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
    privkey = openpgp.parse_privkey(data["privkey_armor"])

    # Parse invite
    invite = parse_invite_link(args.link)
    if not invite.get("fingerprint") or not invite.get("addr"):
        log.error("Invalid invite link: %s", args.link)
        sys.exit(1)

    inviter_addr = invite["addr"].lower()

    log.info("=" * 60)
    log.info("JOIN AND SEND")
    log.info("Account:     %s", data["addr"])
    log.info("Inviter:     %s (%s)", invite.get("name", "?"), inviter_addr)
    log.info("Fingerprint: %s", invite["fingerprint"])
    log.info("Text:        %r", args.text)
    log.info("=" * 60)

    def dump_outgoing(label: str, raw: bytes) -> None:
        if not args.debug:
            return
        text = raw.decode("utf-8", errors="replace")
        sep = "-" * 60
        log.info("[DEBUG] %s raw MIME (%d bytes):\n%s\n%s\n%s",
                 label, len(raw), sep, text, sep)

    def dump_incoming(label: str, msg) -> None:
        if not args.debug:
            return
        text = msg.as_string()
        sep = "-" * 60
        log.info("[DEBUG] %s MIME (%d chars):\n%s\n%s\n%s",
                 label, len(text), sep, text, sep)

    # Connect
    imap = IMAPConnection(data["domain"], 993)
    imap.connect(data["addr"], data["password"])
    imap.select_inbox()  # records current max UID so we only see new mail

    smtp = SMTPConnection(data["domain"], 465)
    smtp.connect(data["addr"], data["password"])

    inviter_key_bytes: bytes | None = None

    try:
        # ── Step 1: vc-request (cleartext, legacy) ───────────────────
        log.info("Step 1: sending vc-request -> %s", inviter_addr)
        req = build_vc_request(
            from_addr=data["addr"],
            to_addr=inviter_addr,
            invite=invite,
            pubkey_b64=data["pubkey_b64"],
            display_name=data.get("display_name", ""),
        )
        dump_outgoing("vc-request", req)
        smtp.send(data["addr"], inviter_addr, req)
        log.info("  vc-request sent")

        # ── Step 2: wait for vc-auth-required ────────────────────────
        log.info("Step 2: waiting for vc-auth-required...")
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline and inviter_key_bytes is None:
            remaining = deadline - time.monotonic()
            if not imap.poll_wait(timeout=min(10.0, remaining), interval=3.0):
                continue

            for raw_msg in imap.fetch_new_messages():
                _, sender_addr = email.utils.parseaddr(raw_msg.get("From", ""))
                log.info("  <-- from %s, subject=%r, content-type=%s",
                         sender_addr or raw_msg.get("From", "?"),
                         raw_msg.get("Subject", ""),
                         raw_msg.get_content_type())
                dump_incoming("incoming (outer)", raw_msg)

                if not sender_addr or sender_addr.lower() != inviter_addr:
                    continue

                sj = raw_msg.get("Secure-Join", "")
                inner = None

                # Legacy: vc-auth-required is cleartext (outer headers)
                if sj == "vc-auth-required":
                    inner = raw_msg
                else:
                    # Try decrypting in case inviter is v3
                    pgp_data = extract_pgp_payload(raw_msg)
                    if pgp_data:
                        inner = decrypt_asymmetric(pgp_data, privkey)
                        if inner:
                            dump_incoming("incoming (decrypted inner)", inner)
                            sj = inner.get("Secure-Join", "")

                if sj != "vc-auth-required":
                    log.info("  ignored Secure-Join=%r", sj)
                    continue

                ac = extract_autocrypt_key(inner) or extract_autocrypt_key(raw_msg)
                if not ac:
                    log.error("  vc-auth-required has no Autocrypt key")
                    sys.exit(1)

                inviter_key_bytes = ac[1]
                log.info("  vc-auth-required received (inviter key: %d bytes)",
                         len(inviter_key_bytes))
                break

        if inviter_key_bytes is None:
            log.error("Timed out waiting for vc-auth-required")
            sys.exit(1)

        # ── Step 3: vc-request-with-auth ─────────────────────────────
        log.info("Step 3: sending vc-request-with-auth -> %s", inviter_addr)
        auth_msg = build_vc_request_with_auth(
            from_addr=data["addr"],
            to_addr=inviter_addr,
            invite=invite,
            self_fingerprint=data["fingerprint"],
            recipient_key_bytes=inviter_key_bytes,
            privkey=privkey,
            pubkey_b64=data["pubkey_b64"],
            display_name=data.get("display_name", ""),
        )
        dump_outgoing("vc-request-with-auth", auth_msg)
        smtp.send(data["addr"], inviter_addr, auth_msg)
        log.info("  vc-request-with-auth sent")

        # ── Step 4: send the actual message ──────────────────────────
        log.info("Step 4: sending encrypted message (%d chars)", len(args.text))
        msg = build_encrypted_message(
            from_addr=data["addr"],
            to_addr=inviter_addr,
            text=args.text,
            recipient_key_bytes=inviter_key_bytes,
            privkey=privkey,
            pubkey_b64=data["pubkey_b64"],
            display_name=data.get("display_name", ""),
        )
        dump_outgoing("chat-message", msg)
        smtp.send(data["addr"], inviter_addr, msg)
        log.info("  message sent")
        log.info("=" * 60)
        log.info("DONE")

    finally:
        smtp.close()
        imap.close()


if __name__ == "__main__":
    main()
