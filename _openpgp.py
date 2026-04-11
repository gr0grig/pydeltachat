"""OpenPGP format implementation for Delta Chat.

Handles key generation/parsing, encryption, decryption, signing.
Pure Python — uses only _ed25519, _x25519, _aes and stdlib.
"""

import base64
import hashlib
import hmac
import os
import struct
import time
import zlib

from . import _ed25519 as ed25519
from . import _x25519 as x25519
from . import _aes as aes

# ── Constants ──

ALGO_EDDSA = 22
ALGO_ECDH = 18
HASH_SHA256 = 8
HASH_SHA1 = 2
SYM_AES256 = 9
SYM_AES128 = 7

# OIDs (length-prefixed)
ED25519_OID = b"\x09\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01"
CV25519_OID = b"\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01"

# KDF params for Cv25519: 03 01 SHA256 AES256
CV25519_KDF = b"\x03\x01\x08\x09"

# ── Packet I/O ──


def _build_packet(tag: int, body: bytes) -> bytes:
    """Build new-format OpenPGP packet."""
    hdr = bytes([0xC0 | tag])
    blen = len(body)
    if blen < 192:
        hdr += bytes([blen])
    elif blen < 8384:
        adj = blen - 192
        hdr += bytes([(adj >> 8) + 192, adj & 0xFF])
    else:
        hdr += b"\xFF" + blen.to_bytes(4, "big")
    return hdr + body


def _parse_packets(data: bytes):
    """Parse OpenPGP packet stream. Yields (tag, body)."""
    i = 0
    while i < len(data):
        if i >= len(data):
            break
        b0 = data[i]; i += 1
        if not (b0 & 0x80):
            break
        if b0 & 0x40:  # New format
            tag = b0 & 0x3F
            if i >= len(data):
                break
            fb = data[i]; i += 1
            if fb < 192:
                length = fb
            elif fb < 224:
                sb = data[i]; i += 1
                length = ((fb - 192) << 8) + sb + 192
            elif fb == 255:
                length = int.from_bytes(data[i:i+4], "big"); i += 4
            else:
                # Partial body
                parts = []
                cl = 1 << (fb & 0x1F)
                parts.append(data[i:i+cl]); i += cl
                while True:
                    fb2 = data[i]; i += 1
                    if fb2 < 192:
                        parts.append(data[i:i+fb2]); i += fb2; break
                    elif fb2 < 224:
                        sb2 = data[i]; i += 1
                        l2 = ((fb2 - 192) << 8) + sb2 + 192
                        parts.append(data[i:i+l2]); i += l2; break
                    elif fb2 == 255:
                        l2 = int.from_bytes(data[i:i+4], "big"); i += 4
                        parts.append(data[i:i+l2]); i += l2; break
                    else:
                        cl2 = 1 << (fb2 & 0x1F)
                        parts.append(data[i:i+cl2]); i += cl2
                body = b"".join(parts)
                yield (tag, body)
                continue
        else:  # Old format
            tag = (b0 & 0x3C) >> 2
            lt = b0 & 0x03
            if lt == 0:
                length = data[i]; i += 1
            elif lt == 1:
                length = int.from_bytes(data[i:i+2], "big"); i += 2
            elif lt == 2:
                length = int.from_bytes(data[i:i+4], "big"); i += 4
            else:
                length = len(data) - i
        body = data[i:i+length]; i += length
        yield (tag, body)


# ── MPI ──


def _mpi_encode(data: bytes) -> bytes:
    """Encode raw bytes as an OpenPGP MPI (big-endian, with bit count)."""
    # Strip leading zeros
    start = 0
    while start < len(data) - 1 and data[start] == 0:
        start += 1
    data = data[start:]
    bits = (len(data) - 1) * 8 + data[0].bit_length() if data[0] else 0
    return bits.to_bytes(2, "big") + data


def _mpi_read(buf: bytes, off: int):
    """Read MPI from buffer. Returns (value_bytes, new_offset)."""
    bits = int.from_bytes(buf[off:off+2], "big")
    nbytes = (bits + 7) // 8
    off += 2
    return buf[off:off+nbytes], off + nbytes


# ── Armor ──


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor_encode(data: bytes, block_type: str = "MESSAGE") -> str:
    """Encode binary data to ASCII armor."""
    b64 = base64.b64encode(data).decode()
    lines = [b64[i:i+76] for i in range(0, len(b64), 76)]
    crc = _crc24(data)
    crc_b64 = base64.b64encode(crc.to_bytes(3, "big")).decode()
    return (
        f"-----BEGIN PGP {block_type}-----\n\n"
        + "\n".join(lines) + "\n"
        + f"={crc_b64}\n"
        + f"-----END PGP {block_type}-----\n"
    )


def armor_decode(text: str) -> bytes:
    """Decode ASCII armor to binary."""
    lines = text.strip().splitlines()
    body_lines = []
    in_body = False
    for line in lines:
        if line.startswith("-----BEGIN"):
            in_body = True
            continue
        if line.startswith("-----END"):
            break
        if not in_body:
            continue
        if line.startswith("="):
            break
        if line.strip() == "":
            continue
        body_lines.append(line.strip())
    return base64.b64decode("".join(body_lines))


# ── Fingerprint / Key ID ──


def _fingerprint(pubkey_body: bytes) -> bytes:
    """Compute v4 key fingerprint (SHA-1)."""
    return hashlib.sha1(b"\x99" + len(pubkey_body).to_bytes(2, "big") + pubkey_body).digest()


# ── Key building ──


def _build_ed25519_pubkey_body(pub32: bytes, creation_time: int) -> bytes:
    """Build Ed25519 public key body (for tag 6 packet)."""
    return (
        b"\x04"
        + creation_time.to_bytes(4, "big")
        + bytes([ALGO_EDDSA])
        + ED25519_OID
        + _mpi_encode(b"\x40" + pub32)
    )


def _build_cv25519_pubkey_body(pub32: bytes, creation_time: int) -> bytes:
    """Build Cv25519 public subkey body (for tag 14 packet)."""
    return (
        b"\x04"
        + creation_time.to_bytes(4, "big")
        + bytes([ALGO_ECDH])
        + CV25519_OID
        + _mpi_encode(b"\x40" + pub32)
        + CV25519_KDF
    )


def _build_seckey_material(secret_bytes: bytes) -> bytes:
    """Build unprotected secret key material (S2K usage 0x00)."""
    mpi = _mpi_encode(secret_bytes)
    checksum = sum(mpi) & 0xFFFF  # checksum of entire MPI (including bit count)
    return b"\x00" + mpi + checksum.to_bytes(2, "big")


# ── Signature building ──


def _build_subpacket(sub_type: int, data: bytes) -> bytes:
    total = 1 + len(data)
    if total < 192:
        return bytes([total, sub_type]) + data
    elif total < 16320:
        adj = total - 192
        return bytes([(adj >> 8) + 192, adj & 0xFF, sub_type]) + data
    else:
        return b"\xFF" + total.to_bytes(4, "big") + bytes([sub_type]) + data


def _build_sig_v4(sig_type: int, ed_seed: bytes, ed_pub: bytes,
                  hash_data_prefix: bytes, creation_time: int,
                  key_id: bytes, fp: bytes, key_flags: bytes,
                  recipient_fp: bytes = None) -> bytes:
    """Build a v4 signature packet body.

    Matches rPGP (Delta Chat) layout:
    - Data sig (0x00): SignatureCreationTime(critical) + IntendedRecipientFingerprint + IssuerFingerprint
    - UID cert (0x10-0x13): + Key flags + Prefs + Features
    - Subkey binding (0x18): + Key flags
    """
    # Hashed subpackets
    hashed = b""
    # SignatureCreationTime (type 2) — rPGP marks this CRITICAL (high bit set on type byte)
    hashed += _build_subpacket(2 | 0x80, creation_time.to_bytes(4, "big"))
    # Data signature: include IntendedRecipientFingerprint (type 35, regular, v4 format)
    if sig_type == 0x00 and recipient_fp is not None:
        hashed += _build_subpacket(35, b"\x04" + recipient_fp)
    # Key flags (type 27) — only for cert/binding sigs, NOT for data sigs
    if sig_type != 0x00:
        hashed += _build_subpacket(27, key_flags)
    # Issuer fingerprint (type 33, regular)
    hashed += _build_subpacket(33, b"\x04" + fp)
    # For UID cert: add preferences
    if sig_type in (0x10, 0x11, 0x12, 0x13):
        hashed += _build_subpacket(11, bytes([SYM_AES256]))  # Preferred symmetric
        hashed += _build_subpacket(21, bytes([HASH_SHA256]))  # Preferred hash
        hashed += _build_subpacket(30, b"\x01")  # Features: MDC

    hashed_len = len(hashed)

    # Unhashed subpackets
    unhashed = _build_subpacket(16, key_id)  # Issuer key ID

    # Signature trailer
    trailer_body = bytes([4, sig_type, ALGO_EDDSA, HASH_SHA256])
    trailer_body += hashed_len.to_bytes(2, "big") + hashed
    trailer_final = trailer_body + b"\x04\xFF" + len(trailer_body).to_bytes(4, "big")

    # Hash
    h = hashlib.sha256(hash_data_prefix + trailer_final).digest()
    left16 = h[:2]

    # EdDSA sign the hash digest
    sig = ed25519.sign(ed_seed, h)
    R, S = sig[:32], sig[32:]

    # Build packet body
    body = trailer_body
    body += len(unhashed).to_bytes(2, "big") + unhashed
    body += left16
    body += _mpi_encode(R) + _mpi_encode(S)
    return body


# ── Key generation ──


def generate_key(uid: str, creation_time: int = None):
    """Generate Ed25519 + Cv25519 OpenPGP key.

    Returns dict with: fingerprint, subkey_fingerprint, privkey_armor, pubkey_armor,
    pubkey_bytes, pubkey_b64, ed_seed, ed_pub, cv_secret, cv_pub
    """
    if creation_time is None:
        creation_time = int(time.time())

    # Generate raw keys
    ed_seed = os.urandom(32)
    ed_pub = ed25519.publickey(ed_seed)
    cv_secret = os.urandom(32)
    cv_pub = x25519.x25519(cv_secret, x25519.BASE_POINT)

    # Build packet bodies
    pk_body = _build_ed25519_pubkey_body(ed_pub, creation_time)
    sk_body = _build_cv25519_pubkey_body(cv_pub, creation_time)

    fp = _fingerprint(pk_body)
    sk_fp = _fingerprint(sk_body)
    key_id = fp[12:]  # Last 8 bytes
    sk_key_id = sk_fp[12:]

    # UID packet
    uid_bytes = uid.encode("utf-8")
    uid_packet = _build_packet(13, uid_bytes)

    # UID certification signature (type 0x13)
    uid_hash_prefix = (
        b"\x99" + len(pk_body).to_bytes(2, "big") + pk_body
        + b"\xB4" + len(uid_bytes).to_bytes(4, "big") + uid_bytes
    )
    uid_sig_body = _build_sig_v4(
        0x13, ed_seed, ed_pub, uid_hash_prefix,
        creation_time, key_id, fp, b"\x03"  # certify + sign
    )
    uid_sig_packet = _build_packet(2, uid_sig_body)

    # Subkey binding signature (type 0x18)
    sk_hash_prefix = (
        b"\x99" + len(pk_body).to_bytes(2, "big") + pk_body
        + b"\x99" + len(sk_body).to_bytes(2, "big") + sk_body
    )
    sk_sig_body = _build_sig_v4(
        0x18, ed_seed, ed_pub, sk_hash_prefix,
        creation_time, key_id, fp, b"\x0C"  # encrypt communications + storage
    )
    sk_sig_packet = _build_packet(2, sk_sig_body)

    # Public key packets
    pub_packets = (
        _build_packet(6, pk_body)
        + uid_packet + uid_sig_packet
        + _build_packet(14, sk_body)
        + sk_sig_packet
    )

    # Secret key packets (Cv25519 secret stored reversed = big-endian)
    priv_packets = (
        _build_packet(5, pk_body + _build_seckey_material(ed_seed))
        + uid_packet + uid_sig_packet
        + _build_packet(7, sk_body + _build_seckey_material(cv_secret[::-1]))
        + sk_sig_packet
    )

    pubkey_b64 = base64.b64encode(pub_packets).decode()

    return {
        "fingerprint": fp.hex(),
        "subkey_fingerprint": sk_fp.hex(),
        "privkey_armor": armor_encode(priv_packets, "PRIVATE KEY BLOCK"),
        "pubkey_armor": armor_encode(pub_packets, "PUBLIC KEY BLOCK"),
        "pubkey_bytes": pub_packets,
        "pubkey_b64": pubkey_b64,
        "ed_seed": ed_seed,
        "ed_pub": ed_pub,
        "cv_secret": cv_secret,
        "cv_pub": cv_pub,
    }


# ── Key parsing ──


def parse_pubkey(data: bytes) -> dict:
    """Parse OpenPGP public key packets (binary).

    Returns dict with: ed_pub, cv_pub, fingerprint, subkey_fingerprint,
    key_id, subkey_id, uid
    """
    result = {}
    primary_body = None
    for tag, body in _parse_packets(data):
        if tag in (6, 5):  # Public/Secret key
            primary_body = body[:_pubkey_body_len(body)] if tag == 5 else body
            algo = body[5] if len(body) > 5 else 0
            if algo == ALGO_EDDSA:
                off = 6 + body[6] + 1 if len(body) > 6 else 0  # Skip OID
                kdata, _ = _mpi_read(body, off)
                if kdata and kdata[0] == 0x40:
                    result["ed_pub"] = kdata[1:]
            fp = _fingerprint(primary_body)
            result["fingerprint"] = fp
            result["key_id"] = fp[12:]
        elif tag in (14, 7):  # Public/Secret subkey
            sub_body = body[:_pubkey_body_len(body)] if tag == 7 else body
            algo = body[5] if len(body) > 5 else 0
            if algo == ALGO_ECDH:
                oid_len = body[6] if len(body) > 6 else 0
                oid_raw = body[6:7 + oid_len]  # length-prefixed OID
                off = 7 + oid_len
                kdata, off2 = _mpi_read(body, off)
                if kdata and kdata[0] == 0x40:
                    result["cv_pub"] = kdata[1:]
                # Read KDF params
                kdf_len = body[off2] if off2 < len(body) else 0
                kdf = body[off2:off2 + 1 + kdf_len]
                result["cv_kdf"] = kdf
                result["cv_oid"] = oid_raw
            sk_fp = _fingerprint(sub_body)
            result["subkey_fingerprint"] = sk_fp
            result["subkey_id"] = sk_fp[12:]
        elif tag == 13:  # UID
            result["uid"] = body.decode("utf-8", errors="replace")
    return result


def parse_privkey(data: bytes) -> dict:
    """Parse OpenPGP private key (binary or armored).

    Returns all of parse_pubkey plus: ed_seed, cv_secret
    """
    if isinstance(data, str):
        data = armor_decode(data)
    elif data[:5] == b"-----":
        data = armor_decode(data.decode())

    result = {}
    primary_body = None
    for tag, body in _parse_packets(data):
        if tag == 5:  # Secret key
            pub_len = _pubkey_body_len(body)
            primary_body = body[:pub_len]
            algo = body[5]
            if algo == ALGO_EDDSA:
                oid_len = body[6]
                off = 7 + oid_len
                kdata, off = _mpi_read(body, off)
                if kdata and kdata[0] == 0x40:
                    result["ed_pub"] = kdata[1:]
                # Secret material
                s2k = body[off]; off += 1
                if s2k == 0:  # Unprotected
                    seed_data, off = _mpi_read(body, off)
                    result["ed_seed"] = seed_data
            fp = _fingerprint(primary_body)
            result["fingerprint"] = fp
            result["key_id"] = fp[12:]
        elif tag == 7:  # Secret subkey
            pub_len = _pubkey_body_len(body)
            sub_body = body[:pub_len]
            algo = body[5]
            if algo == ALGO_ECDH:
                oid_len = body[6]
                oid_raw = body[6:7 + oid_len]
                off = 7 + oid_len
                kdata, off = _mpi_read(body, off)
                if kdata and kdata[0] == 0x40:
                    result["cv_pub"] = kdata[1:]
                # Read KDF params
                kdf_len = body[off] if off < len(body) else 0
                kdf = body[off:off + 1 + kdf_len]
                result["cv_kdf"] = kdf
                result["cv_oid"] = oid_raw
                off += 1 + kdf_len
                # Secret material
                s2k = body[off]; off += 1
                if s2k == 0:
                    sec_data, off = _mpi_read(body, off)
                    # Reverse from big-endian MPI to native little-endian
                    result["cv_secret"] = sec_data.rjust(32, b"\x00")[::-1]
            sk_fp = _fingerprint(sub_body)
            result["subkey_fingerprint"] = sk_fp
            result["subkey_id"] = sk_fp[12:]
        elif tag == 13:
            result["uid"] = body.decode("utf-8", errors="replace")
    return result


def _pubkey_body_len(body: bytes) -> int:
    """Compute the length of the public portion of a key packet body."""
    if len(body) < 6:
        return len(body)
    algo = body[5]
    off = 6
    if algo in (ALGO_EDDSA, ALGO_ECDH):
        oid_len = body[off]; off += 1 + oid_len
        _, off = _mpi_read(body, off)  # public key MPI
        if algo == ALGO_ECDH:
            kdf_len = body[off] if off < len(body) else 0
            off += 1 + kdf_len
    return off


# ── ECDH (Cv25519) ──


def _ecdh_kdf(shared: bytes, cv_oid_raw: bytes, kdf_params: bytes,
              subkey_fp: bytes) -> bytes:
    """ECDH KDF: derive KEK from shared secret (RFC 6637 Section 8)."""
    hash_algo = kdf_params[2] if len(kdf_params) > 2 else HASH_SHA256
    sym_algo = kdf_params[3] if len(kdf_params) > 3 else SYM_AES256
    key_len = _SYM_KEY_SIZE.get(sym_algo, 32)

    param = (
        cv_oid_raw  # includes length prefix
        + bytes([ALGO_ECDH])
        + kdf_params
        + b"Anonymous Sender    "  # 20 bytes
        + subkey_fp  # 20 bytes
    )
    if hash_algo == HASH_SHA256:
        digest = hashlib.sha256(b"\x00\x00\x00\x01" + shared + param).digest()
    elif hash_algo == HASH_SHA1:
        digest = hashlib.sha1(b"\x00\x00\x00\x01" + shared + param).digest()
    else:
        digest = hashlib.sha256(b"\x00\x00\x00\x01" + shared + param).digest()
    return digest[:key_len]


def _ecdh_encrypt_session(session_key_data: bytes, recipient: dict) -> tuple:
    """ECDH encrypt session key. Returns (ephemeral_pub, wrapped_data)."""
    cv_pub = recipient["cv_pub"]
    subkey_fp = recipient["subkey_fingerprint"]
    oid_raw = recipient.get("cv_oid", CV25519_OID)
    kdf = recipient.get("cv_kdf", CV25519_KDF)

    # Generate ephemeral keypair
    eph_secret = os.urandom(32)
    eph_pub = x25519.x25519(eph_secret, x25519.BASE_POINT)

    # Shared secret
    shared = x25519.x25519(eph_secret, cv_pub)

    # KDF
    kek = _ecdh_kdf(shared, oid_raw, kdf, subkey_fp)

    # PKCS5 pad session_key_data to multiple of 8
    pad_len = 8 - (len(session_key_data) % 8)
    padded = session_key_data + bytes([pad_len] * pad_len)

    # AES Key Wrap (use appropriate key size)
    wrapped = aes.key_wrap(kek, padded)
    return eph_pub, wrapped


def _ecdh_decrypt_session(eph_pub: bytes, wrapped: bytes,
                          privkey: dict) -> bytes:
    """ECDH decrypt session key. Returns session key data (algo + key + checksum)."""
    cv_secret = privkey["cv_secret"]
    subkey_fp = privkey["subkey_fingerprint"]
    oid_raw = privkey.get("cv_oid", CV25519_OID)
    kdf = privkey.get("cv_kdf", CV25519_KDF)

    shared = x25519.x25519(cv_secret, eph_pub)
    kek = _ecdh_kdf(shared, oid_raw, kdf, subkey_fp)
    padded = aes.key_unwrap(kek, wrapped)
    # Remove PKCS5 padding
    pad_len = padded[-1]
    return padded[:-pad_len]


# ── S2K ──


def _s2k_derive(passphrase: bytes, salt: bytes, coded_count: int,
                hash_algo: int, key_len: int) -> bytes:
    """S2K iterated+salted key derivation (type 3)."""
    count = (16 + (coded_count & 15)) << ((coded_count >> 4) + 6)
    data = salt + passphrase
    result = b""
    prefix = b""
    while len(result) < key_len:
        to_hash = prefix + data
        # Repeat to fill count
        if len(to_hash) < count:
            reps = count // len(to_hash) + 1
            to_hash = (to_hash * reps)[:count]
        else:
            to_hash = to_hash[:count]
        if hash_algo == HASH_SHA256:
            result += hashlib.sha256(to_hash).digest()
        elif hash_algo == HASH_SHA1:
            result += hashlib.sha1(to_hash).digest()
        else:
            raise ValueError(f"Unsupported S2K hash: {hash_algo}")
        prefix += b"\x00"
    return result[:key_len]


# Key size for symmetric algorithms
_SYM_KEY_SIZE = {SYM_AES256: 32, SYM_AES128: 16, 8: 24}  # 8 = AES192

# AEAD nonce sizes (RFC 9580 Section 5.13.2)
_AEAD_NONCE_SIZE = {1: 15, 2: 15, 3: 12}  # EAX=15, OCB=15, GCM=12
_AEAD_TAG_SIZE = 16  # All AEAD modes use 16-byte tags


# ── HKDF-SHA256 (RFC 5869) ──


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF using SHA-256. salt can be empty."""
    # Extract
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    # Expand
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


# ── S2K type 1 (Salted) ──


def _s2k_salted(passphrase: bytes, salt: bytes, hash_algo: int,
                key_len: int) -> bytes:
    """S2K salted key derivation (type 1): hash(salt || passphrase)."""
    data = salt + passphrase
    result = b""
    prefix = b""
    while len(result) < key_len:
        if hash_algo == HASH_SHA256:
            result += hashlib.sha256(prefix + data).digest()
        elif hash_algo == HASH_SHA1:
            result += hashlib.sha1(prefix + data).digest()
        else:
            raise ValueError(f"Unsupported S2K hash: {hash_algo}")
        prefix += b"\x00"
    return result[:key_len]


# ── SEIPD v2 (RFC 9580) ──


def _seipd_v2_decrypt(session_key: bytes, body: bytes) -> bytes:
    """Decrypt SEIPD v2 (AEAD). Returns content packets."""
    if body[0] != 2:
        raise ValueError("Not SEIPD v2")
    sym_algo = body[1]
    aead_algo = body[2]
    chunk_size_byte = body[3]
    salt = body[4:36]
    encrypted_data = body[36:]

    if aead_algo != 2:
        raise ValueError(f"Unsupported AEAD algo: {aead_algo} (only OCB=2 supported)")

    key_size = _SYM_KEY_SIZE.get(sym_algo, 32)
    nonce_size = _AEAD_NONCE_SIZE[aead_algo]
    chunk_size = 1 << (chunk_size_byte + 6)

    # HKDF: derive message_key + IV
    info = bytes([0xD2, 0x02, sym_algo, aead_algo, chunk_size_byte])
    derived_len = key_size + (nonce_size - 8)
    derived = _hkdf_sha256(session_key, salt, info, derived_len)
    message_key = derived[:key_size]
    iv = derived[key_size:]  # nonce_size - 8 bytes

    # Decrypt chunks
    plaintext = bytearray()
    chunk_idx = 0
    pos = 0
    ad = info  # Associated data for regular chunks

    while pos < len(encrypted_data):
        remaining = len(encrypted_data) - pos
        # Last 16 bytes are the final auth tag
        if remaining <= _AEAD_TAG_SIZE:
            break
        # Chunk = up to chunk_size bytes ciphertext + 16 bytes tag
        ct_len = min(chunk_size, remaining - _AEAD_TAG_SIZE)
        # But we also need room for the final tag after all chunks
        # Check if this is the last chunk + final tag
        if ct_len + _AEAD_TAG_SIZE >= remaining:
            # This chunk's ciphertext + tag = remaining - final_tag_size
            ct_and_tag = remaining - _AEAD_TAG_SIZE
            if ct_and_tag <= _AEAD_TAG_SIZE:
                break
            ct_len = ct_and_tag - _AEAD_TAG_SIZE

        chunk_ct = encrypted_data[pos:pos + ct_len]
        chunk_tag = encrypted_data[pos + ct_len:pos + ct_len + _AEAD_TAG_SIZE]
        pos += ct_len + _AEAD_TAG_SIZE

        nonce = iv + chunk_idx.to_bytes(8, "big")
        chunk_pt = aes.ocb_decrypt(message_key, nonce, chunk_ct, chunk_tag, ad)
        plaintext.extend(chunk_pt)
        chunk_idx += 1

    # Verify final authentication tag
    final_tag = encrypted_data[pos:pos + _AEAD_TAG_SIZE]
    final_nonce = iv + chunk_idx.to_bytes(8, "big")
    final_ad = ad + len(plaintext).to_bytes(8, "big")
    aes.ocb_decrypt(message_key, final_nonce, b"", final_tag, final_ad)

    return bytes(plaintext)


# ── SEIPD v1 ──


def _seipd_encrypt(session_key: bytes, content: bytes) -> bytes:
    """Build SEIPD v1 encrypted data."""
    BS = 16
    prefix = os.urandom(BS)
    plaintext = prefix + prefix[-2:] + content

    # MDC = SHA-1(prefix + prefix[-2:] + content + 0xD3 + 0x14)
    mdc_hash = hashlib.sha1(plaintext + b"\xD3\x14").digest()
    plaintext += b"\xD3\x14" + mdc_hash

    encrypted = aes.cfb_encrypt(session_key, plaintext)
    return b"\x01" + encrypted  # Version 1 + encrypted data


def _seipd_decrypt(session_key: bytes, data: bytes) -> bytes:
    """Decrypt SEIPD v1, verify MDC. Returns content packets."""
    if data[0] != 1:
        raise ValueError("Unsupported SEIPD version")
    decrypted = aes.cfb_decrypt(session_key, data[1:])

    # Verify prefix repeat
    BS = 16
    if decrypted[BS:BS+2] != decrypted[BS-2:BS]:
        raise ValueError("SEIPD prefix check failed")

    # Verify MDC
    content_end = len(decrypted) - 22  # 2 (tag+len) + 20 (sha1)
    if decrypted[content_end] != 0xD3 or decrypted[content_end+1] != 0x14:
        raise ValueError("MDC packet not found")
    expected_mdc = decrypted[content_end+2:]
    actual_mdc = hashlib.sha1(decrypted[:content_end] + b"\xD3\x14").digest()
    if expected_mdc != actual_mdc:
        raise ValueError("MDC verification failed")

    return decrypted[BS+2:content_end]


# ── Literal Data packet ──


def _build_literal_data(data: bytes) -> bytes:
    """Build Literal Data packet (tag 11). Binary format, no filename, date=0.
    Matches rPGP's MessageBuilder::from_bytes default (data_mode=Binary).
    """
    body = b"b\x00" + b"\x00\x00\x00\x00" + data
    return _build_packet(11, body)


def _extract_literal_data(body: bytes) -> bytes:
    """Extract raw data from Literal Data packet body."""
    fname_len = body[1]
    return body[2 + fname_len + 4:]


def _decompress(algo: int, data: bytes) -> bytes:
    """Decompress OpenPGP compressed data."""
    if algo == 0:
        return data
    elif algo == 1:  # ZIP (raw deflate)
        return zlib.decompress(data, -zlib.MAX_WBITS)
    elif algo == 2:  # ZLIB
        return zlib.decompress(data)
    else:
        raise ValueError(f"Unsupported compression: {algo}")


def _extract_plaintext(content: bytes) -> bytes:
    """Extract plaintext from decrypted content (handles compressed + literal data)."""
    for ptag, pbody in _parse_packets(content):
        if ptag == 8:  # Compressed Data
            algo = pbody[0]
            decompressed = _decompress(algo, pbody[1:])
            return _extract_plaintext(decompressed)
        if ptag == 11:  # Literal Data
            return _extract_literal_data(pbody)
    return content


# ── Inline signature ──


def _build_onepass_sig(key_id: bytes) -> bytes:
    """Build One-Pass Signature packet (tag 4), v3 (used for v4 keys).

    Last flag = 1 (this is the final OPS, no nested sigs follow).
    rPGP's OnePassSignature.is_nested() returns true iff last == 0, so
    a standalone non-nested OPS MUST set last = 1.
    """
    body = bytes([3, 0x00, HASH_SHA256, ALGO_EDDSA]) + key_id + b"\x01"
    return _build_packet(4, body)


def _build_inline_sig(data: bytes, ed_seed: bytes, ed_pub: bytes,
                      creation_time: int, key_id: bytes, fp: bytes,
                      recipient_fp: bytes = None) -> bytes:
    """Build signature packet for inline signed data."""
    body = _build_sig_v4(
        0x00, ed_seed, ed_pub, data,
        creation_time, key_id, fp, b"\x03",
        recipient_fp=recipient_fp,
    )
    return _build_packet(2, body)


# ── High-level: encrypt + sign ──


def encrypt_and_sign(plaintext: bytes, signer: dict, recipient: dict) -> str:
    """Create signed + public-key encrypted OpenPGP message. Returns armor."""
    now = int(time.time())
    session_key = os.urandom(32)

    # Build inner content: OnePassSig + LiteralData + Signature
    lit = _build_literal_data(plaintext)
    ops = _build_onepass_sig(signer["key_id"])
    # Pass recipient primary-key fingerprint for IntendedRecipientFingerprint subpacket
    sig = _build_inline_sig(
        plaintext, signer["ed_seed"], signer["ed_pub"],
        now, signer["key_id"], signer["fingerprint"],
        recipient_fp=recipient.get("fingerprint"),
    )
    content = ops + lit + sig

    # SEIPD v1
    seipd_data = _seipd_encrypt(session_key, content)
    seipd_packet = _build_packet(18, seipd_data)

    # PKESK v3
    sk_data = bytes([SYM_AES256]) + session_key
    checksum = sum(session_key) & 0xFFFF
    sk_data += checksum.to_bytes(2, "big")

    eph_pub, wrapped = _ecdh_encrypt_session(sk_data, recipient)
    pkesk_body = (
        b"\x03"  # version 3
        + recipient["subkey_id"]  # 8-byte key ID
        + bytes([ALGO_ECDH])
        + _mpi_encode(b"\x40" + eph_pub)
        + bytes([len(wrapped)]) + wrapped
    )
    pkesk_packet = _build_packet(1, pkesk_body)

    return armor_encode(pkesk_packet + seipd_packet)


def encrypt_symmetric(plaintext: bytes, passphrase: str, signer: dict = None) -> str:
    """Create symmetric-encrypted OpenPGP message. Returns armor."""
    now = int(time.time())
    session_key = os.urandom(32)
    salt = os.urandom(8)

    # Derive KEK from passphrase — S2K type 1 (Salted)
    # Delta Chat ONLY accepts S2K type 1 for SecureJoin symmetric messages
    pw_bytes = passphrase.encode("utf-8")
    kek = _s2k_salted(pw_bytes, salt, HASH_SHA256, 32)

    # Encrypt session key with KEK
    enc_sk = aes.cfb_encrypt(kek, bytes([SYM_AES256]) + session_key)

    # SKESK v4 packet with S2K type 1 (Salted)
    skesk_body = (
        b"\x04"  # version 4
        + bytes([SYM_AES256])
        + bytes([1, HASH_SHA256])  # S2K type 1 (Salted), SHA256
        + salt
        + enc_sk
    )
    skesk_packet = _build_packet(3, skesk_body)

    # Content
    if signer:
        lit = _build_literal_data(plaintext)
        ops = _build_onepass_sig(signer["key_id"])
        sig = _build_inline_sig(
            plaintext, signer["ed_seed"], signer["ed_pub"],
            now, signer["key_id"], signer["fingerprint"]
        )
        content = ops + lit + sig
    else:
        content = _build_literal_data(plaintext)

    seipd_data = _seipd_encrypt(session_key, content)
    seipd_packet = _build_packet(18, seipd_data)

    return armor_encode(skesk_packet + seipd_packet)


# ── High-level: decrypt ──


def decrypt_public(pgp_data: bytes, privkey: dict) -> bytes:
    """Decrypt public-key encrypted message. Returns plaintext bytes."""
    if isinstance(pgp_data, str):
        pgp_data = pgp_data.encode()
    if pgp_data[:5] == b"-----":
        pgp_data = armor_decode(pgp_data.decode())

    session_key = None
    seipd_body = None

    for tag, body in _parse_packets(pgp_data):
        if tag == 1:  # PKESK
            ver = body[0]
            if ver != 3:
                continue
            pkesk_algo = body[9]
            if pkesk_algo != ALGO_ECDH:
                continue
            # Read ephemeral public key MPI
            eph_data, off = _mpi_read(body, 10)
            if eph_data[0] == 0x40:
                eph_pub = eph_data[1:]
            else:
                eph_pub = eph_data
            # Read wrapped session key
            wrap_len = body[off]; off += 1
            wrapped = body[off:off+wrap_len]
            # Decrypt
            try:
                sk_data = _ecdh_decrypt_session(eph_pub, wrapped, privkey)
                sym_algo = sk_data[0]
                session_key = sk_data[1:-2]
            except Exception:
                continue
        elif tag == 18:  # SEIPD
            seipd_body = body

    if session_key is None or seipd_body is None:
        raise ValueError("Cannot decrypt: no matching PKESK or SEIPD")

    content = _seipd_decrypt(session_key, seipd_body)
    return _extract_plaintext(content)


def decrypt_symmetric_msg(pgp_data: bytes, passphrase: str) -> bytes:
    """Decrypt symmetric-encrypted message. Returns plaintext bytes.

    Supports both RFC 4880 (SKESK v4 + SEIPD v1) and
    RFC 9580 (SKESK v6 + SEIPD v2).
    """
    if isinstance(pgp_data, str):
        pgp_data = pgp_data.encode()
    if pgp_data[:5] == b"-----":
        pgp_data = armor_decode(pgp_data.decode())

    session_key = None
    seipd_body = None
    seipd_version = None
    pw_bytes = passphrase.encode("utf-8")

    for tag, body in _parse_packets(pgp_data):
        if tag == 3:  # SKESK
            ver = body[0]
            if ver == 6:
                # SKESK v6 (RFC 9580)
                try:
                    session_key = _parse_skesk_v6(body, pw_bytes)
                except Exception:
                    continue
            elif ver == 4:
                # SKESK v4 (RFC 4880)
                sym_algo = body[1]
                s2k_type = body[2]
                if s2k_type == 3:
                    hash_algo = body[3]
                    salt = body[4:12]
                    coded_count = body[12]
                    key_size = _SYM_KEY_SIZE.get(sym_algo, 32)
                    kek = _s2k_derive(pw_bytes, salt, coded_count, hash_algo, key_size)
                    remaining = body[13:]
                elif s2k_type == 1:
                    hash_algo = body[3]
                    salt = body[4:12]
                    key_size = _SYM_KEY_SIZE.get(sym_algo, 32)
                    kek = _s2k_salted(pw_bytes, salt, hash_algo, key_size)
                    remaining = body[12:]
                elif s2k_type == 0:
                    hash_algo = body[3]
                    key_size = _SYM_KEY_SIZE.get(sym_algo, 32)
                    kek = _s2k_salted(pw_bytes, b"", hash_algo, key_size)
                    remaining = body[4:]
                else:
                    continue
                if remaining:
                    dec = aes.cfb_decrypt(kek, remaining)
                    if dec[0] == sym_algo or dec[0] in _SYM_KEY_SIZE:
                        session_key = dec[1:]
                    else:
                        session_key = dec
                else:
                    session_key = kek
        elif tag == 18:
            seipd_body = body
            seipd_version = body[0] if body else None

    if session_key is None or seipd_body is None:
        raise ValueError("Cannot decrypt: no matching SKESK or SEIPD")

    if seipd_version == 2:
        content = _seipd_v2_decrypt(session_key, seipd_body)
    else:
        content = _seipd_decrypt(session_key, seipd_body)
    return _extract_plaintext(content)


def _parse_skesk_v6(body: bytes, pw_bytes: bytes) -> bytes:
    """Parse SKESK v6 packet and return decrypted session key."""
    # body[0] = 6 (version)
    count_byte = body[1]  # bytes from here to end of AEAD nonce
    sym_algo = body[2]
    aead_algo = body[3]
    s2k_len = body[4]
    s2k_data = body[5:5 + s2k_len]

    # Parse S2K specifier
    s2k_type = s2k_data[0]
    s2k_hash = s2k_data[1]
    if s2k_type == 1:  # Salted
        s2k_salt = s2k_data[2:10]
        raw_key = _s2k_salted(pw_bytes, s2k_salt, s2k_hash,
                              _SYM_KEY_SIZE.get(sym_algo, 32))
    elif s2k_type == 3:  # Iterated+Salted
        s2k_salt = s2k_data[2:10]
        coded_count = s2k_data[10]
        raw_key = _s2k_derive(pw_bytes, s2k_salt, coded_count, s2k_hash,
                              _SYM_KEY_SIZE.get(sym_algo, 32))
    elif s2k_type == 0:  # Simple
        raw_key = _s2k_salted(pw_bytes, b"", s2k_hash,
                              _SYM_KEY_SIZE.get(sym_algo, 32))
    else:
        raise ValueError(f"Unsupported S2K type in SKESK v6: {s2k_type}")

    # HKDF to derive KEK
    info = bytes([0xC3, 0x06, sym_algo, aead_algo])
    key_size = _SYM_KEY_SIZE.get(sym_algo, 32)
    kek = _hkdf_sha256(raw_key, b"", info, key_size)

    # After S2K: AEAD nonce, encrypted session key, auth tag
    nonce_size = _AEAD_NONCE_SIZE.get(aead_algo, 15)
    after_s2k = 5 + s2k_len
    nonce = body[after_s2k:after_s2k + nonce_size]
    enc_sk_start = after_s2k + nonce_size
    enc_sk = body[enc_sk_start:enc_sk_start + key_size]
    tag = body[enc_sk_start + key_size:enc_sk_start + key_size + _AEAD_TAG_SIZE]

    # AEAD decrypt session key
    ad = info  # Same as HKDF info
    if aead_algo == 2:  # OCB
        session_key = aes.ocb_decrypt(kek, nonce, enc_sk, tag, ad)
    else:
        raise ValueError(f"Unsupported AEAD algo: {aead_algo}")

    return session_key
