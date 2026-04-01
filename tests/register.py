#!/usr/bin/env python3
"""Register a new chatmail account with a Delta Chat-compatible PGP key.

Generates:
  - Random chatmail credentials (auto-created on first IMAP login)
  - Ed25519 primary key (sign) + Cv25519 subkey (encrypt), NO signing subkey

Saves everything to account.json.

Usage:
    python -m pydeltachat.tests.register
    python -m pydeltachat.tests.register --name "My Bot"
"""

import argparse
import imaplib
import json
import ssl
import sys
from pathlib import Path

import pgpy

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from pydeltachat.onboarding import generate_credentials
from pydeltachat.crypto import generate_key

ACCOUNT_FILE = Path(__file__).parent / "account.json"


def main():
    parser = argparse.ArgumentParser(description="Register chatmail account")
    parser.add_argument("--name", default="PyDC Bot", help="Display name")
    parser.add_argument("--domain", default="nine.testrun.org", help="Chatmail domain")
    args = parser.parse_args()

    # 1. Generate credentials
    addr, password = generate_credentials(args.domain)
    print(f"Address:  {addr}")

    # 2. Create account (IMAP login auto-creates on chatmail)
    ctx = ssl.create_default_context()
    imap = imaplib.IMAP4_SSL(args.domain, 993, ssl_context=ctx)
    imap.login(addr, password)
    imap.logout()
    print("Account created.")

    # 3. Generate key
    print("Generating key (Ed25519 + Cv25519)...")
    key = generate_key(addr, args.name)
    print(f"Fingerprint: {key['fingerprint']}")

    # 4. Verify signing uses primary key
    privkey, _ = pgpy.PGPKey.from_blob(key["privkey_armor"])
    sig = privkey.sign(pgpy.PGPMessage.new(b"test"))
    primary_keyid = key["fingerprint"][-16:].upper()
    assert sig.signer.upper() == primary_keyid, \
        f"Signing with subkey {sig.signer} instead of primary {primary_keyid}!"
    print("Signing:  primary key (OK)")

    # 5. Save
    account = {
        "addr": addr,
        "password": password,
        "domain": args.domain,
        "display_name": args.name,
        "fingerprint": key["fingerprint"],
        "privkey_armor": key["privkey_armor"],
        "pubkey_armor": key["pubkey_armor"],
        "pubkey_b64": key["pubkey_b64"],
    }

    if ACCOUNT_FILE.exists():
        backup = ACCOUNT_FILE.with_suffix(".json.bak")
        backup.unlink(missing_ok=True)
        ACCOUNT_FILE.rename(backup)
        print(f"Backed up old account to {backup.name}")

    ACCOUNT_FILE.write_text(json.dumps(account, indent=2), encoding="utf-8")
    print(f"Saved to {ACCOUNT_FILE.name}")


if __name__ == "__main__":
    main()
