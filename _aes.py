"""AES-256 block cipher, CFB mode, and Key Wrap (RFC 3394).

Pure Python — no external dependencies.
"""

# fmt: off
_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)

_INV_SBOX = (
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
)

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
# fmt: on


# ── GF(2^8) multiplication lookup tables ──

def _xtime(a):
    return ((a << 1) ^ 0x1b if a & 0x80 else a << 1) & 0xFF


def _gf_mul(a, b):
    r = 0
    t = b
    while a > 0:
        if a & 1:
            r ^= t
        t = _xtime(t)
        a >>= 1
    return r


_GF = {}
for _c in (2, 3, 9, 11, 13, 14):
    _GF[_c] = tuple(_gf_mul(_c, i) for i in range(256))


# ── Key expansion ──

def _sub_word(w):
    return (_SBOX[w >> 24] << 24 | _SBOX[(w >> 16) & 0xFF] << 16 |
            _SBOX[(w >> 8) & 0xFF] << 8 | _SBOX[w & 0xFF])


def _rot_word(w):
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _key_expansion(key: bytes):
    """AES key expansion. Supports 128/192/256 bit keys."""
    key_len = len(key)
    if key_len == 32:
        Nk, Nr = 8, 14
    elif key_len == 24:
        Nk, Nr = 6, 12
    elif key_len == 16:
        Nk, Nr = 4, 10
    else:
        raise ValueError(f"Invalid AES key length: {key_len}")
    w = [0] * (4 * (Nr + 1))
    for i in range(Nk):
        w[i] = int.from_bytes(key[4 * i : 4 * i + 4], "big")
    for i in range(Nk, 4 * (Nr + 1)):
        t = w[i - 1]
        if i % Nk == 0:
            t = _sub_word(_rot_word(t)) ^ (_RCON[i // Nk - 1] << 24)
        elif Nk > 6 and i % Nk == 4:
            t = _sub_word(t)
        w[i] = w[i - Nk] ^ t
    return w, Nr


# ── Block encrypt / decrypt ──

def _add_round_key(s, w, rnd):
    for c in range(4):
        k = w[4 * rnd + c]
        s[4 * c] ^= (k >> 24) & 0xFF
        s[4 * c + 1] ^= (k >> 16) & 0xFF
        s[4 * c + 2] ^= (k >> 8) & 0xFF
        s[4 * c + 3] ^= k & 0xFF


def encrypt_block(key_sched_nr, block: bytes) -> bytes:
    """Encrypt a single 16-byte block. key_sched_nr = (words, Nr) or just words (Nr=14)."""
    if isinstance(key_sched_nr, tuple):
        ks, Nr = key_sched_nr
    else:
        ks, Nr = key_sched_nr, 14
    s = list(block)
    _add_round_key(s, ks, 0)
    for r in range(1, Nr + 1):
        # SubBytes
        for i in range(16):
            s[i] = _SBOX[s[i]]
        # ShiftRows
        s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
        # MixColumns (skip last round)
        if r < Nr:
            for c in range(4):
                a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
                s[4*c]   = _GF[2][a0] ^ _GF[3][a1] ^ a2 ^ a3
                s[4*c+1] = a0 ^ _GF[2][a1] ^ _GF[3][a2] ^ a3
                s[4*c+2] = a0 ^ a1 ^ _GF[2][a2] ^ _GF[3][a3]
                s[4*c+3] = _GF[3][a0] ^ a1 ^ a2 ^ _GF[2][a3]
        _add_round_key(s, ks, r)
    return bytes(s)


def decrypt_block(key_sched_nr, block: bytes) -> bytes:
    """Decrypt a single 16-byte block. key_sched_nr = (words, Nr) or just words (Nr=14)."""
    if isinstance(key_sched_nr, tuple):
        ks, Nr = key_sched_nr
    else:
        ks, Nr = key_sched_nr, 14
    s = list(block)
    _add_round_key(s, ks, Nr)
    for r in range(Nr - 1, -1, -1):
        # InvShiftRows
        s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
        s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
        s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
        # InvSubBytes
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]
        _add_round_key(s, ks, r)
        # InvMixColumns (skip round 0)
        if r > 0:
            for c in range(4):
                a0, a1, a2, a3 = s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
                s[4*c]   = _GF[14][a0] ^ _GF[11][a1] ^ _GF[13][a2] ^ _GF[9][a3]
                s[4*c+1] = _GF[9][a0]  ^ _GF[14][a1] ^ _GF[11][a2] ^ _GF[13][a3]
                s[4*c+2] = _GF[13][a0] ^ _GF[9][a1]  ^ _GF[14][a2] ^ _GF[11][a3]
                s[4*c+3] = _GF[11][a0] ^ _GF[13][a1] ^ _GF[9][a2]  ^ _GF[14][a3]
    return bytes(s)


# ── CFB-128 mode ──

def cfb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CFB encrypt with IV=0."""
    ks = _key_expansion(key)
    BS = 16
    fr = b"\x00" * BS
    out = bytearray()
    for i in range(0, len(plaintext), BS):
        chunk = plaintext[i : i + BS]
        fre = encrypt_block(ks, fr)
        enc = bytes(a ^ b for a, b in zip(chunk, fre))
        out.extend(enc)
        if len(enc) == BS:
            fr = enc
        else:
            fr = (fr + enc)[-BS:]
    return bytes(out)


def cfb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CFB decrypt with IV=0."""
    ks = _key_expansion(key)
    BS = 16
    fr = b"\x00" * BS
    out = bytearray()
    for i in range(0, len(ciphertext), BS):
        chunk = ciphertext[i : i + BS]
        fre = encrypt_block(ks, fr)
        dec = bytes(a ^ b for a, b in zip(chunk, fre))
        out.extend(dec)
        if len(chunk) == BS:
            fr = chunk
        else:
            fr = (fr + chunk)[-BS:]
    return bytes(out)


# ── AES Key Wrap (RFC 3394) ──

def key_wrap(kek: bytes, plaintext: bytes) -> bytes:
    """AES Key Wrap. plaintext must be multiple of 8 bytes."""
    assert len(plaintext) % 8 == 0
    ks = _key_expansion(kek)
    n = len(plaintext) // 8
    A = 0xA6A6A6A6A6A6A6A6
    R = [plaintext[i * 8 : i * 8 + 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            B = encrypt_block(ks, A.to_bytes(8, "big") + R[i])
            A = int.from_bytes(B[:8], "big") ^ (n * j + i + 1)
            R[i] = B[8:]
    return A.to_bytes(8, "big") + b"".join(R)


def key_unwrap(kek: bytes, ciphertext: bytes) -> bytes:
    """AES Key Unwrap. Returns unwrapped data or raises ValueError."""
    ks = _key_expansion(kek)
    n = (len(ciphertext) - 8) // 8
    A = int.from_bytes(ciphertext[:8], "big")
    R = [ciphertext[8 + i * 8 : 16 + i * 8] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            xored = (A ^ (n * j + i + 1)).to_bytes(8, "big")
            B = decrypt_block(ks, xored + R[i])
            A = int.from_bytes(B[:8], "big")
            R[i] = B[8:]
    if A != 0xA6A6A6A6A6A6A6A6:
        raise ValueError("AES key unwrap: integrity check failed")
    return b"".join(R)


# ── OCB mode (RFC 7253) ──

def _xor16(a: bytes, b: bytes) -> bytes:
    """XOR two 16-byte blocks."""
    return bytes(x ^ y for x, y in zip(a, b))


def _double_block(block: bytes) -> bytes:
    """GF(2^128) doubling (multiply by x). Reduction polynomial 0x87."""
    carry = block[0] >> 7
    result = bytearray(16)
    for i in range(15):
        result[i] = ((block[i] << 1) | (block[i + 1] >> 7)) & 0xFF
    result[15] = (block[15] << 1) & 0xFF
    if carry:
        result[15] ^= 0x87
    return bytes(result)


def _ntz(n: int) -> int:
    """Number of trailing zeros in binary representation."""
    if n == 0:
        return 0
    count = 0
    while (n & 1) == 0:
        count += 1
        n >>= 1
    return count


def _ocb_hash(ks, L_star, L_cache, adata: bytes) -> bytes:
    """OCB HASH function for associated data."""
    if not adata:
        return b"\x00" * 16
    sum_val = b"\x00" * 16
    offset = b"\x00" * 16
    num_full = len(adata) // 16
    for i in range(1, num_full + 1):
        A_i = adata[(i - 1) * 16 : i * 16]
        # Ensure L_cache has enough entries
        idx = _ntz(i)
        while len(L_cache) <= idx:
            L_cache.append(_double_block(L_cache[-1]))
        offset = _xor16(offset, L_cache[idx])
        sum_val = _xor16(sum_val, encrypt_block(ks, _xor16(A_i, offset)))
    partial = adata[num_full * 16 :]
    if partial:
        offset = _xor16(offset, L_star)
        padded = partial + b"\x80" + b"\x00" * (15 - len(partial))
        sum_val = _xor16(sum_val, encrypt_block(ks, _xor16(padded, offset)))
    return sum_val


def _ocb_nonce_to_offset(ks, nonce: bytes, taglen: int = 128) -> bytes:
    """Compute initial offset from nonce (RFC 7253 Section 4.2)."""
    # Build Nonce block: 0-padded to 16 bytes with taglen bits
    nonce_block = bytearray(16)
    nn = len(nonce)
    # Place nonce right-justified in bytes 1..15
    nonce_block[16 - nn :] = nonce
    # Set bit at position 128 - 8*nn (the "1" separator bit)
    nonce_block[0] = ((taglen % 128) << 1) & 0xFF
    nonce_block[16 - nn - 1] |= 0x01

    bottom = nonce_block[15] & 0x3F  # Last 6 bits
    nonce_block[15] &= 0xC0  # Zero out last 6 bits

    Ktop = encrypt_block(ks, bytes(nonce_block))
    # Stretch = Ktop || (Ktop[0:8] XOR Ktop[1:9])
    stretch = Ktop + bytes(Ktop[i] ^ Ktop[i + 1] for i in range(8))  # 24 bytes

    # Extract 128 bits starting at bit position 'bottom'
    # Convert stretch to a big integer, shift, extract
    stretch_int = int.from_bytes(stretch, "big")
    total_bits = len(stretch) * 8  # 192
    shifted = (stretch_int >> (total_bits - 128 - bottom)) & ((1 << 128) - 1)
    return shifted.to_bytes(16, "big")


def ocb_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                adata: bytes = b"") -> tuple[bytes, bytes]:
    """OCB encrypt. Returns (ciphertext, 16-byte tag)."""
    ks = _key_expansion(key)
    L_star = encrypt_block(ks, b"\x00" * 16)
    L_dollar = _double_block(L_star)
    L_cache = [_double_block(L_dollar)]  # L[0]

    offset = _ocb_nonce_to_offset(ks, nonce)
    checksum = b"\x00" * 16

    num_full = len(plaintext) // 16
    partial = plaintext[num_full * 16 :]
    ct = bytearray()

    for i in range(1, num_full + 1):
        P_i = plaintext[(i - 1) * 16 : i * 16]
        idx = _ntz(i)
        while len(L_cache) <= idx:
            L_cache.append(_double_block(L_cache[-1]))
        offset = _xor16(offset, L_cache[idx])
        C_i = _xor16(offset, encrypt_block(ks, _xor16(P_i, offset)))
        checksum = _xor16(checksum, P_i)
        ct.extend(C_i)

    if partial:
        offset = _xor16(offset, L_star)
        pad = encrypt_block(ks, offset)
        C_star = bytes(p ^ pad[j] for j, p in enumerate(partial))
        ct.extend(C_star)
        padded = partial + b"\x80" + b"\x00" * (15 - len(partial))
        checksum = _xor16(checksum, padded)

    tag = _xor16(
        encrypt_block(ks, _xor16(_xor16(checksum, offset), L_dollar)),
        _ocb_hash(ks, L_star, L_cache, adata),
    )
    return bytes(ct), tag


def ocb_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                tag: bytes, adata: bytes = b"") -> bytes:
    """OCB decrypt + verify. Returns plaintext or raises ValueError."""
    ks = _key_expansion(key)
    L_star = encrypt_block(ks, b"\x00" * 16)
    L_dollar = _double_block(L_star)
    L_cache = [_double_block(L_dollar)]  # L[0]

    offset = _ocb_nonce_to_offset(ks, nonce)
    checksum = b"\x00" * 16

    num_full = len(ciphertext) // 16
    partial = ciphertext[num_full * 16 :]
    pt = bytearray()

    for i in range(1, num_full + 1):
        C_i = ciphertext[(i - 1) * 16 : i * 16]
        idx = _ntz(i)
        while len(L_cache) <= idx:
            L_cache.append(_double_block(L_cache[-1]))
        offset = _xor16(offset, L_cache[idx])
        P_i = _xor16(offset, decrypt_block(ks, _xor16(C_i, offset)))
        checksum = _xor16(checksum, P_i)
        pt.extend(P_i)

    if partial:
        offset = _xor16(offset, L_star)
        pad = encrypt_block(ks, offset)
        P_star = bytes(c ^ pad[j] for j, c in enumerate(partial))
        pt.extend(P_star)
        padded = P_star + b"\x80" + b"\x00" * (15 - len(P_star))
        checksum = _xor16(checksum, padded)

    computed_tag = _xor16(
        encrypt_block(ks, _xor16(_xor16(checksum, offset), L_dollar)),
        _ocb_hash(ks, L_star, L_cache, adata),
    )
    if computed_tag != tag:
        raise ValueError("OCB: authentication tag mismatch")
    return bytes(pt)
