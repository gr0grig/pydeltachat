#!/usr/bin/env python3
"""Generate and display an invite link for the registered account.

Reads account.json, generates a SecureJoin invite link, saves to invite.json.
Run register.py first.

Usage:
    python -m pydeltachat.tests.get_link
"""

import json
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from pydeltachat.invite import generate_invite_link

ACCOUNT_FILE = Path(__file__).parent / "account.json"
INVITE_FILE = Path(__file__).parent / "invite.json"


def main():
    if not ACCOUNT_FILE.exists():
        print(f"ERROR: {ACCOUNT_FILE.name} not found. Run register.py first.")
        sys.exit(1)

    data = json.loads(ACCOUNT_FILE.read_text(encoding="utf-8"))

    # Generate or load invite (regenerate if account changed)
    if INVITE_FILE.exists():
        invite = json.loads(INVITE_FILE.read_text(encoding="utf-8"))
        if invite.get("addr") != data["addr"]:
            print(f"Invite is for {invite.get('addr')}, regenerating for {data['addr']}...")
            INVITE_FILE.unlink()
        else:
            print("Loaded existing invite.")

    if not INVITE_FILE.exists():
        _, invite = generate_invite_link(
            fingerprint=data["fingerprint"],
            addr=data["addr"],
            name=data.get("display_name", ""),
        )
        INVITE_FILE.write_text(json.dumps(invite, indent=2), encoding="utf-8")
        print("Generated new invite.")

    url = (
        f"https://i.delta.chat/#{invite['fingerprint']}"
        f"&v=3"
        f"&i={invite['invite_number']}"
        f"&s={invite['auth_code']}"
        f"&a={quote(invite['addr'], safe='')}"
        f"&n={quote(invite.get('name', ''), safe='')}"
    )

    print()
    print(f"Account: {data['addr']}")
    print(f"Name:    {data.get('display_name', '')}")
    print(f"FP:      {data['fingerprint']}")
    print()
    print("Invite link (scan in Delta Chat):")
    print()
    print(f"  {url}")
    print()
    print(f"Saved to {INVITE_FILE.name}")


if __name__ == "__main__":
    main()
