"""X25519 Diffie-Hellman key exchange (RFC 7748).

Pure Python — no external dependencies.
"""

_P = 2**255 - 19
_A24 = 121665

BASE_POINT = (9).to_bytes(32, "little")


def _clamp(k: bytes) -> int:
    s = bytearray(k)
    s[0] &= 248
    s[31] &= 127
    s[31] |= 64
    return int.from_bytes(s, "little")


def x25519(k: bytes, u: bytes) -> bytes:
    """X25519(scalar, point) -> 32-byte shared secret."""
    k_s = _clamp(k)
    u_i = int.from_bytes(u, "little") % _P
    x_2, x_3 = 1, u_i
    z_2, z_3 = 0, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k_s >> t) & 1
        swap ^= k_t
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        A = (x_2 + z_2) % _P
        AA = A * A % _P
        B = (x_2 - z_2) % _P
        BB = B * B % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = D * A % _P
        CB = C * B % _P
        x_3 = pow(DA + CB, 2, _P)
        z_3 = u_i * pow(DA - CB, 2, _P) % _P
        x_2 = AA * BB % _P
        z_2 = E * (AA + _A24 * E) % _P
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    return (x_2 * pow(z_2, _P - 2, _P) % _P).to_bytes(32, "little")
