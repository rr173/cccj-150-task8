"""纯 Python 的 Ed25519（RFC 8032）签名实现。

回执中继需要按**接收机构**签发可离线核验的非对称回执包：核验方不依赖
中继在线、也不与中继共享密钥。为保证整个项目零外部依赖（仅标准库），
这里内置一份与 RFC 8032 测试向量一致的 Ed25519 实现；性能上用基点
预计算表、2^4 窗口标量乘与多标量联合乘法（Straus 算法）加速，
生产部署也可替换为 cryptography / libsodium。

私钥格式：32 字节种子（seed）；公钥：32 字节；签名：64 字节。
全部以 hex 字符串在 JSON 中传输。
"""
from __future__ import annotations

import hashlib
import os

__all__ = ["keypair", "public_key_from_seed", "sign", "verify",
           "PublicKeyError", "SignatureError"]

q = 2 ** 255 - 19
l_ = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _expmod(b, e, m):
    return pow(b, e, m)


d = -121665 * _expmod(121666, q - 2, q) % q
I = _expmod(2, (q - 1) // 4, q)


def _xrecover(y):
    # 曲线 -x² + y² = 1 + d·x²·y²  =>  x² = (y² - 1) / (1 + d·y²)
    xx = (y * y - 1) * _expmod(d * y * y + 1, q - 2, q) % q
    x = _expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _expmod(5, q - 2, q) % q
Bx = _xrecover(By)
B = (Bx, By)
O = (0, 1)


# ---------------------------------------------------------------------------
# 群律：扩展坐标 (X:Y:Z:T) 满足 x=X/Z, y=Y/Z, T=X·Y/Z
# 点加/倍点全程无模逆，最后取仿射坐标时才做一次批量逆元。
# ---------------------------------------------------------------------------

def _edwards_affine(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _expmod(1 + d * x1 * x2 * y1 * y2, q - 2, q) % q
    y3 = (y1 * y2 + x1 * x2) * _expmod(1 - d * x1 * x2 * y1 * y2, q - 2, q) % q
    return x3, y3


def _ext(P):
    """仿射 -> 扩展坐标。"""
    x, y = P
    return (x, y, 1, x * y % q)


def _add(P, Q):
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % q
    B = (Y1 + X1) * (Y2 + X2) % q
    C = T1 * 2 * d * T2 % q
    D = Z1 * 2 * Z2 % q
    E = (B - A) % q
    F = (D - C) % q
    G = (D + C) % q
    H = (B + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _dbl(P):
    X1, Y1, Z1, _ = P
    A = X1 * X1 % q
    B = Y1 * Y1 % q
    C = 2 * Z1 * Z1 % q
    H = (A + B) % q
    E = (H - (X1 + Y1) ** 2) % q
    G = (A - B) % q
    F = (C + G) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _neg(P):
    X, Y, Z, T = P
    return ((q - X) % q, Y, Z, (q - T) % q)


def _to_affine(P):
    X, Y, Z, _ = P
    zi = _expmod(Z, q - 2, q)
    return X * zi % q, Y * zi % q


# 基点 4 位窗口预计算表：_BASE_MULT[j] = j·B（扩展坐标），j=0..15。
# Horner 从最高窗口位到低位：每窗先做 4 次倍点（×16），再叠加当前窗数字。
def _build_base_multiples():
    row = [_ext(O)]
    for _ in range(15):
        row.append(_add(row[-1], _ext(B)))
    return tuple(row)


_BASE_MULT = _build_base_multiples()


def _scalarmult_base(n):
    """基点标量乘（4 位窗口；n 可为 512 位哈希整数，按实际位长扫描）。"""
    acc = _ext(O)
    top = (n.bit_length() + 3) // 4
    for i in range(top - 1, -1, -1):
        acc = _dbl(_dbl(_dbl(_dbl(acc))))
        digit = (n >> (4 * i)) & 15
        if digit:
            acc = _add(acc, _BASE_MULT[digit])
    return _to_affine(acc)


def _multiples_table(P):
    row = [_ext(O)]
    for _ in range(15):
        row.append(_add(row[-1], _ext(P)))
    return row


def _scalarmult(P, n):
    """任意点标量乘（4 位窗口）。"""
    if n == 0:
        return O
    multiples = _multiples_table(P)
    res = _ext(O)
    top = (n.bit_length() + 3) // 4
    for i in range(top - 1, -1, -1):
        res = _dbl(_dbl(_dbl(_dbl(res))))
        digit = (n >> (4 * i)) & 15
        if digit:
            res = _add(res, multiples[digit])
    return _to_affine(res)


def _msm_two(na, PA, nb, PB):
    """双标量乘法 na·PA + nb·PB（Straus 联合窗口，共享 4 倍点）。"""
    mA = _multiples_table(PA)
    mB = _multiples_table(PB)
    res = _ext(O)
    top = max(na.bit_length(), nb.bit_length(), 1)
    windows = (top + 3) // 4
    for i in range(windows - 1, -1, -1):
        res = _dbl(_dbl(_dbl(_dbl(res))))
        da = (na >> (4 * i)) & 15
        db = (nb >> (4 * i)) & 15
        if da:
            res = _add(res, mA[da])
        if db:
            res = _add(res, mB[db])
    return _to_affine(res)


def _encodepoint(P):
    x, y = P
    b = bytearray(y.to_bytes(32, "little"))
    b[31] |= (x & 1) << 7
    return bytes(b)


def _bit(s, i):
    return (s[i // 8] >> (i % 8)) & 1


def _Hint(m):
    return int.from_bytes(_H(m), "little")


def _decodeint(s):
    return int.from_bytes(s, "little")


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, 255):
        x = q - x
    P = (x, y)
    if not _isoncurve(P):
        raise PublicKeyError("点不在 Edwards 曲线上")
    return P


def _clamp(a: int) -> int:
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed 必须为 32 字节")
    h = _H(seed)
    a = _clamp(_decodeint(h[:32]))
    return _encodepoint(_scalarmult_base(a))


def keypair() -> tuple[bytes, bytes]:
    """返回 (seed, public_key)，均为 32 字节。"""
    seed = os.urandom(32)
    return seed, public_key_from_seed(seed)


def sign(message: bytes, seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("seed 必须为 32 字节")
    h = _H(seed)
    a = _clamp(_decodeint(h[:32]))
    A = _encodepoint(_scalarmult_base(a))
    r = _Hint(h[32:64] + message)
    Rb = _encodepoint(_scalarmult_base(r))
    k = _Hint(Rb + A + message)
    S = (r + k * a) % l_
    return Rb + S.to_bytes(32, "little")


class PublicKeyError(Exception):
    pass


class SignatureError(Exception):
    pass


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """验签：通过返回 True；签名/公钥非法抛出 :class:`SignatureError`。

    采用 S·B = R + h·A 的**多标量联合乘法**一次算出（Straus 窗口），
    而不是三次独立标量乘，纯 Python 下快数倍。
    """
    if len(signature) != 64:
        raise SignatureError("签名必须为 64 字节")
    if len(public_key) != 32:
        raise PublicKeyError("公钥必须为 32 字节")
    try:
        A = _decodepoint(public_key)
    except PublicKeyError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PublicKeyError(f"公钥点非法: {exc}") from exc
    try:
        R = _decodepoint(signature[:32])
    except Exception as exc:  # noqa: BLE001
        raise SignatureError(f"签名中的点非法: {exc}") from exc
    S = _decodeint(signature[32:64])
    if S >= l_:
        raise SignatureError("S 越界")
    h = _Hint(signature[:32] + public_key + message)
    # S·B = R + h·A  =>  S·B + (l-h)·A = R（用群阶补码表示 -h·A）
    if _msm_two(S, B, (l_ - h) % l_, A) != R:
        raise SignatureError("签名校验失败")
    return True
