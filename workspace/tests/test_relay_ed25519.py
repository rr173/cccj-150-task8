"""内置纯 Python Ed25519：RFC 8032 测试向量、群律、性能与接口。"""
from __future__ import annotations

import time

import pytest

from app.relay import ed25519 as ed


# RFC 8032 §7.1 测试向量 1-3（公钥/签名均为官方值）
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     b"",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     bytes([0x72]),
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     bytes.fromhex("af82"),
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


@pytest.mark.parametrize("seed_h,pub_h,msg,sig_h", RFC8032)
def test_rfc8032_vectors(seed_h, pub_h, msg, sig_h):
    seed, pub, sig = map(bytes.fromhex, (seed_h, pub_h, sig_h))
    assert ed.public_key_from_seed(seed) == pub
    assert ed.sign(msg, seed) == sig
    assert ed.verify(msg, sig, pub) is True


def test_group_law_identities():
    assert ed._scalarmult(ed.B, ed.l_) == (0, 1)            # 群阶·基点 = 单位元
    neg_b = (-ed.B[0] % ed.q, ed.B[1])
    assert ed._edwards_affine(ed.B, neg_b) == (0, 1)


def test_scalar_mult_implementations_agree():
    import random
    random.seed(11)
    for _ in range(20):
        n = random.randrange(0, ed.l_)
        assert ed._scalarmult(ed.B, n) == ed._scalarmult_base(n)


def test_keypair_roundtrip_and_tamper_detection():
    seed, pub = ed.keypair()
    msg = b"delivery-receipt-relay" * 20
    sig = ed.sign(msg, seed)
    assert ed.verify(msg, sig, pub) is True
    with pytest.raises(ed.SignatureError):
        ed.verify(msg + b"x", sig, pub)
    with pytest.raises(ed.SignatureError):
        ed.verify(msg, sig[:63] + bytes([sig[63] ^ 1]), pub)
    with pytest.raises((ed.SignatureError, ed.PublicKeyError)):
        # bytes(32) 是合法编码的低阶点；等式不成立 -> SignatureError
        ed.verify(msg, sig, bytes(32))


def test_bad_input_lengths():
    seed, pub = ed.keypair()
    with pytest.raises(ValueError):
        ed.public_key_from_seed(b"short")
    with pytest.raises(ed.SignatureError):
        ed.verify(b"m", b"0" * 32, pub)
