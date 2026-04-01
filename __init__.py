"""pydeltachat — native Python Delta Chat library.

Uses Python standard library (imaplib, smtplib, email, ssl) + pgpy/pysequoia for PGP.
Works with chatmail servers for instant account onboarding.
"""

from .crypto import (
    generate_key, build_pgp_mime, extract_pgp_payload, extract_autocrypt_key,
    sign_and_encrypt, symmetric_encrypt, decrypt_symmetric, decrypt_asymmetric,
    get_text_body, fold_autocrypt_header,
)
from .invite import generate_invite_link, parse_invite_link
from .message import build_encrypted_message
from .onboarding import create_account, generate_credentials
from .securejoin import build_vc_pubkey, build_vc_contact_confirm
from .transport import IMAPConnection, SMTPConnection

__all__ = [
    "generate_key",
    "build_pgp_mime",
    "extract_pgp_payload",
    "extract_autocrypt_key",
    "fold_autocrypt_header",
    "sign_and_encrypt",
    "symmetric_encrypt",
    "decrypt_symmetric",
    "decrypt_asymmetric",
    "get_text_body",
    "generate_invite_link",
    "parse_invite_link",
    "build_encrypted_message",
    "create_account",
    "generate_credentials",
    "build_vc_pubkey",
    "build_vc_contact_confirm",
    "IMAPConnection",
    "SMTPConnection",
]
