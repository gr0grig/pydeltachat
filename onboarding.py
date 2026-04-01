"""Chatmail instant onboarding — account creation on chatmail servers."""

import imaplib
import secrets
import ssl
import string

DEFAULT_DOMAIN = "nine.testrun.org"
_ALPHABET = string.ascii_letters + string.digits


def generate_credentials(domain: str = DEFAULT_DOMAIN) -> tuple[str, str]:
    """Generate random credentials for a chatmail server.

    Chatmail servers auto-create accounts on first IMAP login,
    so no separate registration is needed.

    Returns (email_address, password).
    """
    username = "".join(secrets.choice(_ALPHABET) for _ in range(9))
    password = "".join(secrets.choice(_ALPHABET) for _ in range(50))
    return f"{username}@{domain}", password


def create_account(
    domain: str = DEFAULT_DOMAIN,
    display_name: str | None = None,
) -> dict[str, str]:
    """Create an account on a chatmail server via instant onboarding.

    1. Generates random credentials
    2. Performs IMAP login (which auto-creates the account on chatmail)
    3. Returns account info dict

    Returns dict with keys: addr, password, domain, display_name
    """
    addr, password = generate_credentials(domain)

    # IMAP login auto-creates the account on chatmail servers
    ctx = ssl.create_default_context()
    imap = imaplib.IMAP4_SSL(domain, 993, ssl_context=ctx)
    try:
        imap.login(addr, password)
        imap.logout()
    except imaplib.IMAP4.error as e:
        raise RuntimeError(f"Failed to create account on {domain}: {e}") from e

    return {
        "addr": addr,
        "password": password,
        "domain": domain,
        "display_name": display_name or "",
    }
