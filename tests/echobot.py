#!/usr/bin/env python3
"""Echo bot — listens for messages and replies with "Echo: <text>".

Handles SecureJoin v3 handshake (inviter role) and encrypted messaging.

Run register.py and get_link.py first, then scan the invite link in Delta Chat.

Usage:
    python -m pydeltachat.tests.echobot
    python -m pydeltachat.tests.echobot --timeout 1800
"""

import argparse
import email.utils
import json
import logging
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pgpy
from pysequoia import Cert

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from pydeltachat.transport import IMAPConnection, SMTPConnection
from pydeltachat.invite import generate_invite_link
from pydeltachat.crypto import (
    extract_autocrypt_key, extract_pgp_payload,
    decrypt_symmetric, decrypt_asymmetric, get_text_body,
)
from pydeltachat.securejoin import build_vc_pubkey, build_vc_contact_confirm
from pydeltachat.message import build_encrypted_message

ACCOUNT_FILE = Path(__file__).parent / "account.json"
INVITE_FILE = Path(__file__).parent / "invite.json"

# Known contacts: addr -> raw public key bytes
CONTACTS: dict[str, bytes] = {}


def store_key(msg):
    """Extract and store Autocrypt key from a message."""
    ac = extract_autocrypt_key(msg)
    if ac:
        CONTACTS[ac[0].lower()] = ac[1]


def main():
    parser = argparse.ArgumentParser(description="Delta Chat echo bot")
    parser.add_argument("--timeout", type=int, default=600, help="seconds to listen")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    log = logging.getLogger("echobot")

    if not ACCOUNT_FILE.exists():
        log.error("account.json not found. Run: python -m pydeltachat.tests.register")
        sys.exit(1)

    # Load account
    data = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))
    cert = Cert.from_bytes(data["privkey_armor"].encode())
    privkey, _ = pgpy.PGPKey.from_blob(data["privkey_armor"])

    # Load invite, regenerate if account changed
    if INVITE_FILE.exists():
        invite = json.loads(INVITE_FILE.read_text(encoding="utf-8"))
        if invite.get("addr") != data["addr"]:
            log.warning("invite.json is for %s, but account is %s — regenerating...",
                        invite.get("addr"), data["addr"])
            INVITE_FILE.unlink()

    if not INVITE_FILE.exists():
        _, invite = generate_invite_link(
            fingerprint=data["fingerprint"],
            addr=data["addr"],
            name=data.get("display_name", ""),
        )
        INVITE_FILE.write_text(json.dumps(invite, indent=2), encoding="utf-8")
        log.info("Generated new invite.")

    shared_secret = f"securejoin/{invite['fingerprint'].upper()}/{invite['auth_code']}"
    url = (
        f"https://i.delta.chat/#{invite['fingerprint']}"
        f"&v=3&i={invite['invite_number']}&s={invite['auth_code']}"
        f"&a={quote(invite['addr'], safe='')}&n={quote(invite.get('name', ''), safe='')}"
    )

    log.info("=" * 60)
    log.info("ECHO BOT")
    log.info("Account: %s", data["addr"])
    log.info("Invite:  %s", url)
    log.info("Timeout: %ds", args.timeout)
    log.info("=" * 60)

    # Connect
    imap = IMAPConnection(data["domain"], 993)
    imap.connect(data["addr"], data["password"])
    imap.select_inbox()

    smtp = SMTPConnection(data["domain"], 465)
    smtp.connect(data["addr"], data["password"])

    msg_count = 0
    deadline = time.monotonic() + args.timeout
    handshake_done = set()

    def send_vc_pubkey(to_addr):
        response = build_vc_pubkey(
            from_addr=data["addr"], to_addr=to_addr, invite=invite,
            pubkey_b64=data["pubkey_b64"], fingerprint=data["fingerprint"],
            privkey=privkey, display_name=data.get("display_name", ""),
        )
        smtp.send(data["addr"], to_addr, response)

    def send_vc_confirm(to_addr, key_bytes):
        confirm = build_vc_contact_confirm(
            from_addr=data["addr"], to_addr=to_addr,
            recipient_key_bytes=key_bytes, privkey=privkey,
            pubkey_b64=data["pubkey_b64"],
            display_name=data.get("display_name", ""),
        )
        smtp.send(data["addr"], to_addr, confirm)

    def send_echo(to_addr, text):
        reply = build_encrypted_message(
            from_addr=data["addr"], to_addr=to_addr,
            text=f"Echo: {text.strip()}",
            recipient_key_bytes=CONTACTS[to_addr.lower()],
            privkey=privkey, pubkey_b64=data["pubkey_b64"],
            display_name=data.get("display_name", ""),
        )
        smtp.send(data["addr"], to_addr, reply)

    try:
        # Scan existing messages for contacts and pending handshakes
        imap._last_uid = None
        existing = imap.fetch_new_messages()
        log.info("Scanning %d existing message(s)...", len(existing))

        pending_requests = {}
        for raw_msg in existing:
            _, sender_addr = email.utils.parseaddr(raw_msg.get("From", ""))
            store_key(raw_msg)

            pgp_data = extract_pgp_payload(raw_msg)
            if not pgp_data:
                continue

            inner = decrypt_asymmetric(pgp_data, cert)
            if inner:
                if sender_addr:
                    handshake_done.add(sender_addr.lower())
                store_key(inner)
                continue

            inner = decrypt_symmetric(pgp_data, shared_secret)
            if inner and inner.get("Secure-Join") == "vc-request-pubkey" and sender_addr:
                pending_requests[sender_addr.lower()] = raw_msg

        for addr_req in pending_requests:
            if addr_req in handshake_done:
                continue
            log.info("Pending handshake from %s, sending vc-pubkey...", addr_req)
            send_vc_pubkey(addr_req)

        log.info("Contacts: %s", list(CONTACTS.keys()) or "none")
        log.info("Listening...")

        # Poll loop
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            has_new = imap.poll_wait(timeout=min(5.0, remaining), interval=3.0)
            if not has_new:
                continue

            for raw_msg in imap.fetch_new_messages():
                msg_count += 1
                sender = raw_msg.get("From", "?")
                _, sender_addr = email.utils.parseaddr(sender)
                log.info("--- Message #%d from %s ---", msg_count, sender_addr or sender)

                pgp_data = extract_pgp_payload(raw_msg)
                if not pgp_data:
                    log.info("  (not encrypted)")
                    continue

                # SecureJoin: symmetric decrypt
                inner = decrypt_symmetric(pgp_data, shared_secret)
                if inner:
                    sj = inner.get("Secure-Join", "")
                    if sj == "vc-request-pubkey":
                        clean = sender_addr or sender
                        log.info("  SecureJoin: vc-request-pubkey from %s", clean)
                        send_vc_pubkey(clean)
                        log.info("  SecureJoin: vc-pubkey sent!")
                        continue
                    elif sj:
                        log.info("  SecureJoin: %s", sj)
                        continue

                # Private key decrypt
                inner = decrypt_asymmetric(pgp_data, cert)
                if not inner:
                    log.info("  Could not decrypt")
                    continue

                sj = inner.get("Secure-Join", "")
                if sj == "vc-request-with-auth":
                    clean = sender_addr or sender
                    log.info("  SecureJoin: vc-request-with-auth from %s", clean)
                    for src in (inner, raw_msg):
                        store_key(src)
                    handshake_done.add(clean.lower())
                    key_bytes = CONTACTS.get(clean.lower())
                    if key_bytes:
                        send_vc_confirm(clean, key_bytes)
                        log.info("  SecureJoin: vc-contact-confirm sent! Handshake complete.")
                    else:
                        log.warning("  SecureJoin: no key for %s, cannot confirm", clean)
                    continue

                # Regular message
                for src in (inner, raw_msg):
                    store_key(src)

                text = get_text_body(inner)
                log.info("  Text: %s", text.strip()[:200] if text else "(empty)")

                clean = sender_addr or sender
                key_bytes = CONTACTS.get(clean.lower())
                if key_bytes and text.strip():
                    log.info("  Replying...")
                    try:
                        send_echo(clean, text)
                        log.info("  Reply sent!")
                    except Exception as e:
                        log.error("  Reply failed: %s", e)
                elif not key_bytes:
                    log.info("  No key for %s, cannot reply", clean)

        log.info("Timeout. Messages: %d", msg_count)

    except KeyboardInterrupt:
        log.info("Stopped. Messages: %d", msg_count)
    finally:
        smtp.close()
        imap.close()


if __name__ == "__main__":
    main()
