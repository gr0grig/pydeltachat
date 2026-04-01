"""Ed25519 digital signature algorithm (RFC 8032).

Pure Python — no external dependencies. Uses only hashlib (stdlib).
"""

import hashlib

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int:
    y2 = y * y % _P
    x2 = (y2 - 1) * _inv(_D * y2 + 1) % _P
    if x2 == 0:
        if sign:
            raise ValueError("invalid point")
        return 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        raise ValueError("invalid point")
    if x & 1 != sign:
        x = _P - x
    return x


_By = 4 * _inv(5) % _P
_Bx = _recover_x(_By, 0)
_B = (_Bx, _By, 1, _Bx * _By % _P)


def _point_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _encode_point(P) -> bytes:
    zi = _inv(P[2])
    x = P[0] * zi % _P
    y = P[1] * zi % _P
    r = bytearray(y.to_bytes(32, "little"))
    if x & 1:
        r[31] |= 0x80
    return bytes(r)


def _decode_point(bs: bytes):
    y = int.from_bytes(bs, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


def _clamp(h32: bytes):
    a = int.from_bytes(h32, "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def publickey(seed: bytes) -> bytes:
    """Derive 32-byte public key from 32-byte seed."""
    a = _clamp(_sha512(seed)[:32])
    return _encode_point(_scalar_mult(a, _B))


def sign(seed: bytes, msg: bytes) -> bytes:
    """Sign message. Returns 64-byte signature (R || S)."""
    h = _sha512(seed)
    a = _clamp(h[:32])
    A = _encode_point(_scalar_mult(a, _B))
    r = int.from_bytes(_sha512(h[32:] + msg), "little") % _L
    R = _encode_point(_scalar_mult(r, _B))
    k = int.from_bytes(_sha512(R + A + msg), "little") % _L
    s = (r + k * a) % _L
    return R + s.to_bytes(32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify an Ed25519 signature."""
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R = _decode_point(sig[:32])
        A = _decode_point(pub)
    except (ValueError, IndexError):
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(sig[:32] + pub + msg), "little") % _L
    sB = _scalar_mult(s, _B)
    kA = _scalar_mult(k, A)
    RkA = _point_add(R, kA)
    return _encode_point(sB) == _encode_point(RkA)
