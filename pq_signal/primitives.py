import os
import hashlib
from typing import Tuple

P_25519 = 2**255 - 19
A24_25519 = 121665
U_BASE_POINT = (9).to_bytes(32, "little")

def _mod_inv_25519(x: int) -> int:
    return pow(x, P_25519 - 2, P_25519)

def _clamp_scalar(scalar_bytes: bytes) -> int:
    raw = bytearray(scalar_bytes[:32])
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    return int.from_bytes(raw, "little")

def curve25519_scalarmult(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    k = _clamp_scalar(scalar_bytes)
    u = int.from_bytes(u_bytes[:32], "little") % P_25519

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for bit_pos in reversed(range(255)):
        k_bit = (k >> bit_pos) & 1
        swap ^= k_bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_bit

        a_sum = (x2 + z2) % P_25519
        aa = (a_sum * a_sum) % P_25519
        b_diff = (x2 - z2) % P_25519
        bb = (b_diff * b_diff) % P_25519
        e = (aa - bb) % P_25519

        c_sum = (x3 + z3) % P_25519
        d_diff = (x3 - z3) % P_25519
        da = (d_diff * a_sum) % P_25519
        cb = (c_sum * b_diff) % P_25519

        x3 = pow(da + cb, 2, P_25519)
        z3 = (x1 * pow(da - cb, 2, P_25519)) % P_25519
        x2 = (aa * bb) % P_25519
        z2 = (e * (aa + A24_25519 * e)) % P_25519

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    result = (x2 * _mod_inv_25519(z2)) % P_25519
    return result.to_bytes(32, "little")

def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    priv = os.urandom(32)
    pub = curve25519_scalarmult(priv, U_BASE_POINT)
    return pub, priv

def x25519_diffie_hellman(private_bytes: bytes, public_bytes: bytes) -> bytes:
    return curve25519_scalarmult(private_bytes, public_bytes)

Q_ED = 2**255 - 19
L_ED = 2**252 + 27742317777372353535851937790883648493
D_ED = (-121665 * pow(121666, Q_ED - 2, Q_ED)) % Q_ED
I_ED = pow(2, (Q_ED - 1) // 4, Q_ED)

def _recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(D_ED * y * y + 1, Q_ED - 2, Q_ED)
    x = pow(xx, (Q_ED + 3) // 8, Q_ED)
    if (x * x - xx) % Q_ED != 0:
        x = (x * I_ED) % Q_ED
    if x % 2 != 0:
        x = Q_ED - x
    return x

BY_ED = (4 * pow(5, Q_ED - 2, Q_ED)) % Q_ED
BX_ED = _recover_x(BY_ED)
BASE_ED = (BX_ED % Q_ED, BY_ED % Q_ED)

def _ed_point_add(p1: Tuple[int, int], p2: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = p1
    x2, y2 = p2
    denom = (D_ED * x1 * x2 * y1 * y2) % Q_ED
    inv_denom_p = pow(1 + denom, Q_ED - 2, Q_ED)
    inv_denom_m = pow(1 - denom, Q_ED - 2, Q_ED)
    x3 = ((x1 * y2 + x2 * y1) * inv_denom_p) % Q_ED
    y3 = ((y1 * y2 + x1 * x2) * inv_denom_m) % Q_ED
    return (x3, y3)

def _ed_point_mul(pt: Tuple[int, int], scalar: int) -> Tuple[int, int]:
    acc = (0, 1)
    base = pt
    while scalar > 0:
        if scalar & 1:
            acc = _ed_point_add(acc, base)
        base = _ed_point_add(base, base)
        scalar >>= 1
    return acc

def _encode_ed_point(pt: Tuple[int, int]) -> bytes:
    x, y = pt
    val = (y & ((1 << 255) - 1)) | ((x & 1) << 255)
    return val.to_bytes(32, "little")

def _decode_ed_point(raw: bytes) -> Tuple[int, int]:
    val = int.from_bytes(raw[:32], "little")
    y = (val & ((1 << 255) - 1)) % Q_ED
    sign_bit = (val >> 255) & 1
    x = _recover_x(y)
    if (x & 1) != sign_bit:
        x = Q_ED - x
    return (x, y)

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    priv_seed = os.urandom(32)
    h = hashlib.sha512(priv_seed).digest()
    a_scalar = int.from_bytes(h[:32], "little")
    a_scalar &= (1 << 254) - 8
    a_scalar |= (1 << 254)
    pub_point = _ed_point_mul(BASE_ED, a_scalar)
    pub_bytes = _encode_ed_point(pub_point)
    return pub_bytes, priv_seed

def ed25519_sign(private_bytes: bytes, data: bytes) -> bytes:
    h = hashlib.sha512(private_bytes[:32]).digest()
    a_scalar = int.from_bytes(h[:32], "little")
    a_scalar &= (1 << 254) - 8
    a_scalar |= (1 << 254)
    pub_bytes = _encode_ed_point(_ed_point_mul(BASE_ED, a_scalar))

    prefix = h[32:]
    r_scalar = int.from_bytes(hashlib.sha512(prefix + data).digest(), "little") % L_ED
    r_point = _ed_point_mul(BASE_ED, r_scalar)
    r_bytes = _encode_ed_point(r_point)

    k_scalar = int.from_bytes(hashlib.sha512(r_bytes + pub_bytes + data).digest(), "little") % L_ED
    s_scalar = (r_scalar + k_scalar * a_scalar) % L_ED
    return r_bytes + s_scalar.to_bytes(32, "little")

def ed25519_verify(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    if len(signature) != 64 or len(public_bytes) != 32:
        return False
    try:
        r_bytes = signature[:32]
        s_scalar = int.from_bytes(signature[32:], "little")
        if s_scalar >= L_ED:
            return False
        r_point = _decode_ed_point(r_bytes)
        a_point = _decode_ed_point(public_bytes)
        k_scalar = int.from_bytes(hashlib.sha512(r_bytes + public_bytes + data).digest(), "little") % L_ED

        left = _ed_point_mul(BASE_ED, s_scalar)
        right = _ed_point_add(r_point, _ed_point_mul(a_point, k_scalar))
        return left == right
    except Exception:
        return False

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    block_size = 64
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    key = key.ljust(block_size, b"\x00")
    o_key_pad = bytes(b ^ 0x5c for b in key)
    i_key_pad = bytes(b ^ 0x36 for b in key)
    inner = hashlib.sha256(i_key_pad + msg).digest()
    return hashlib.sha256(o_key_pad + inner).digest()

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac_sha256(salt, ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])

def hkdf_extract_and_expand(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)

AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _sub_word(w: int) -> int:
    return (
        (AES_SBOX[(w >> 24) & 0xff] << 24) |
        (AES_SBOX[(w >> 16) & 0xff] << 16) |
        (AES_SBOX[(w >> 8) & 0xff] << 8) |
        (AES_SBOX[w & 0xff])
    )

def _rot_word(w: int) -> int:
    return ((w << 8) & 0xffffffff) | (w >> 24)

def _key_expansion_256(key_bytes: bytes) -> list:
    w = [int.from_bytes(key_bytes[i*4:(i+1)*4], "big") for i in range(8)]
    for i in range(8, 60):
        temp = w[i - 1]
        if i % 8 == 0:
            temp = _sub_word(_rot_word(temp)) ^ (RCON[i // 8] << 24)
        elif i % 8 == 4:
            temp = _sub_word(temp)
        w.append(w[i - 8] ^ temp)
    return w

def _xtime(a: int) -> int:
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

def _aes_encrypt_block(pt: bytes, round_keys: list) -> bytes:
    state = [[pt[r + 4*c] for c in range(4)] for r in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] ^= (round_keys[c] >> (24 - 8*r)) & 0xff

    for rnd in range(1, 14):
        for r in range(4):
            for c in range(4):
                state[r][c] = AES_SBOX[state[r][c]]
        state[1] = state[1][1:] + state[1][:1]
        state[2] = state[2][2:] + state[2][:2]
        state[3] = state[3][3:] + state[3][:3]
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
            state[0][c] = _xtime(s0) ^ (_xtime(s1) ^ s1) ^ s2 ^ s3
            state[1][c] = s0 ^ _xtime(s1) ^ (_xtime(s2) ^ s2) ^ s3
            state[2][c] = s0 ^ s1 ^ _xtime(s2) ^ (_xtime(s3) ^ s3)
            state[3][c] = (_xtime(s0) ^ s0) ^ s1 ^ s2 ^ _xtime(s3)
        rk_idx = rnd * 4
        for r in range(4):
            for c in range(4):
                state[r][c] ^= (round_keys[rk_idx + c] >> (24 - 8*r)) & 0xff

    for r in range(4):
        for c in range(4):
            state[r][c] = AES_SBOX[state[r][c]]
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    rk_idx = 14 * 4
    for r in range(4):
        for c in range(4):
            state[r][c] ^= (round_keys[rk_idx + c] >> (24 - 8*r)) & 0xff

    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4*c] = state[r][c]
    return bytes(out)

def _ghash_mult(x_bytes: bytes, y_bytes: bytes) -> bytes:
    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")
    z = 0
    v = x
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ (0xe1000000000000000000000000000000)
        else:
            v >>= 1
    return z.to_bytes(16, "big")

def _ghash(h_key: bytes, aad: bytes, ct: bytes) -> bytes:
    y = b"\x00" * 16

    def pad16(data: bytes) -> bytes:
        rem = len(data) % 16
        return data + (b"\x00" * (16 - rem) if rem else b"")

    aad_padded = pad16(aad)
    for i in range(0, len(aad_padded), 16):
        block = bytes(a ^ b for a, b in zip(y, aad_padded[i:i+16]))
        y = _ghash_mult(block, h_key)

    ct_padded = pad16(ct)
    for i in range(0, len(ct_padded), 16):
        block = bytes(a ^ b for a, b in zip(y, ct_padded[i:i+16]))
        y = _ghash_mult(block, h_key)

    lens = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    block = bytes(a ^ b for a, b in zip(y, lens))
    return _ghash_mult(block, h_key)

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    round_keys = _key_expansion_256(key)
    h_sub = _aes_encrypt_block(b"\x00" * 16, round_keys)
    nonce = os.urandom(12)
    j0 = nonce + b"\x00\x00\x00\x01"

    ct = bytearray(len(plaintext))
    cb = int.from_bytes(j0, "big")
    for idx in range(0, len(plaintext), 16):
        cb = (cb + 1) & 0xffffffffffffffffffffffffffffffff
        keystream_block = _aes_encrypt_block(cb.to_bytes(16, "big"), round_keys)
        chunk = plaintext[idx:idx+16]
        for j in range(len(chunk)):
            ct[idx + j] = chunk[j] ^ keystream_block[j]
    ciphertext = bytes(ct)

    s = _ghash(h_sub, associated_data, ciphertext)
    e_j0 = _aes_encrypt_block(j0, round_keys)
    tag = bytes(a ^ b for a, b in zip(s, e_j0))
    return nonce, ciphertext + tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = b"") -> bytes:
    if len(key) != 32:
        raise ValueError("AES-256 requires 32-byte key")
    if len(ciphertext_with_tag) < 16:
        raise ValueError("Ciphertext too short for tag")
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    round_keys = _key_expansion_256(key)
    h_sub = _aes_encrypt_block(b"\x00" * 16, round_keys)
    j0 = nonce + b"\x00\x00\x00\x01"

    s = _ghash(h_sub, associated_data, ciphertext)
    e_j0 = _aes_encrypt_block(j0, round_keys)
    expected_tag = bytes(a ^ b for a, b in zip(s, e_j0))
    if not _constant_time_compare(tag, expected_tag):
        raise ValueError("AES-GCM Authentication Failed: Invalid Tag!")

    pt = bytearray(len(ciphertext))
    cb = int.from_bytes(j0, "big")
    for idx in range(0, len(ciphertext), 16):
        cb = (cb + 1) & 0xffffffffffffffffffffffffffffffff
        keystream_block = _aes_encrypt_block(cb.to_bytes(16, "big"), round_keys)
        chunk = ciphertext[idx:idx+16]
        for j in range(len(chunk)):
            pt[idx + j] = chunk[j] ^ keystream_block[j]
    return bytes(pt)

def _constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0

import pqcrypto.kem.ml_kem_768 as _kem_backend

KEM_CIPHERTEXT_SIZE = _kem_backend.CIPHERTEXT_SIZE
KEM_PUBLIC_KEY_SIZE = _kem_backend.PUBLIC_KEY_SIZE
KEM_SECRET_KEY_SIZE = _kem_backend.SECRET_KEY_SIZE
KEM_SHARED_SECRET_SIZE = _kem_backend.SHARED_SECRET_SIZE

def generate_kem_keypair() -> Tuple[bytes, bytes]:
    pk, sk = _kem_backend.keygen()
    return bytes(pk), bytes(sk)

def kem_encapsulate(public_bytes: bytes) -> Tuple[bytes, bytes]:
    ct, ss = _kem_backend.encaps(public_bytes)
    return bytes(ct), bytes(ss)

def kem_decapsulate(secret_bytes: bytes, ciphertext: bytes) -> bytes:
    ss = _kem_backend.decaps(secret_bytes, ciphertext)
    return bytes(ss)
