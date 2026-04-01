"""Delta Chat invite link parser and generator.

Parses/generates URLs like:
  https://i.delta.chat/#FINGERPRINT&v=3&i=INVITE&s=AUTH&a=ADDR&n=NAME
"""

import secrets
import string
from urllib.parse import quote, unquote


def parse_invite_link(url: str) -> dict:
    """Parse a Delta Chat invite link (OPENPGP4FPR format).

    Returns dict with: fingerprint, addr, name, invite_number, auth_code, version
    """
    # Strip the URL prefix to get the fragment
    if "#" in url:
        fragment = url.split("#", 1)[1]
    else:
        fragment = url

    # Split into fingerprint and params
    parts = fragment.split("&")
    fingerprint = parts[0] if parts else ""

    params = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = unquote(v)

    return {
        "fingerprint": fingerprint,
        "addr": params.get("a", ""),
        "name": params.get("n", ""),
        "invite_number": params.get("i", ""),
        "auth_code": params.get("s", ""),
        "version": params.get("v", ""),
    }


def _random_token(length: int = 24) -> str:
    """Generate a random alphanumeric token (like Delta Chat's create_id)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_invite_link(
    fingerprint: str,
    addr: str,
    name: str = "",
    invite_number: str | None = None,
    auth_code: str | None = None,
) -> tuple[str, dict]:
    """Generate a Delta Chat invite link.

    Returns (url, invite_dict) where invite_dict contains all fields
    including generated tokens.
    """
    if invite_number is None:
        invite_number = _random_token(24)
    if auth_code is None:
        auth_code = _random_token(24)

    fp = fingerprint.replace(" ", "")
    encoded_addr = quote(addr, safe="")
    encoded_name = quote(name, safe="")

    url = (
        f"https://i.delta.chat/#{fp}"
        f"&v=3"
        f"&i={invite_number}"
        f"&s={auth_code}"
        f"&a={encoded_addr}"
        f"&n={encoded_name}"
    )

    invite = {
        "fingerprint": fp,
        "addr": addr,
        "name": name,
        "invite_number": invite_number,
        "auth_code": auth_code,
        "version": "3",
    }

    return url, invite
