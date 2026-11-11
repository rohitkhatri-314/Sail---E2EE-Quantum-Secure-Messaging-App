"""
Cryptographic Primitives for Quantum-Resistant Signal Protocol
Combines:
- Classical Asymmetric: X25519 (ECDH) & Ed25519 (Signatures)
- Post-Quantum KEM: ML-KEM-768 (FIPS 203 standardized Kyber-768)
- Symmetric Authenticated Cipher: AES-256-GCM
- KDF: HKDF-SHA256 (Extract & Expand)
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import pqcrypto.kem.ml_kem_768 as ml_kem_768

# Constants
KEM_CIPHERTEXT_SIZE = ml_kem_768.CIPHERTEXT_SIZE
KEM_PUBLIC_KEY_SIZE = ml_kem_768.PUBLIC_KEY_SIZE
KEM_SECRET_KEY_SIZE = ml_kem_768.SECRET_KEY_SIZE
KEM_SHARED_SECRET_SIZE = ml_kem_768.SHARED_SECRET_SIZE

# --- Classical X25519 DH Primitives ---

def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    """Generates an X25519 keypair. Returns (public_bytes, private_bytes)."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return pub.public_bytes_raw(), priv.private_bytes_raw()

def x25519_diffie_hellman(private_bytes: bytes, public_bytes: bytes) -> bytes:
    """Computes scalar multiplication DH(priv, pub). Returns 32-byte shared secret."""
    priv = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    pub = x25519.X25519PublicKey.from_public_bytes(public_bytes)
    return priv.exchange(pub)

# --- Classical Ed25519 Signing Primitives ---

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Generates an Ed25519 keypair for identity signing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return pub.public_bytes_raw(), priv.private_bytes_raw()

def ed25519_sign(private_bytes: bytes, data: bytes) -> bytes:
    """Signs data with an Ed25519 private key."""
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    return priv.sign(data)

def ed25519_verify(public_bytes: bytes, signature: bytes, data: bytes) -> bool:
    """Verifies an Ed25519 signature."""
    pub = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
    try:
        pub.verify(signature, data)
        return True
    except Exception:
        return False

# --- Post-Quantum ML-KEM-768 (Kyber) Primitives ---

def generate_kem_keypair() -> Tuple[bytes, bytes]:
    """Generates an ML-KEM-768 keypair. Returns (public_bytes, secret_bytes)."""
    pk, sk = ml_kem_768.keygen()
    return bytes(pk), bytes(sk)

def kem_encapsulate(public_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Encapsulates a shared secret using peer's ML-KEM-768 public key.
    Returns (ciphertext, shared_secret).
    """
    ct, ss = ml_kem_768.encaps(public_bytes)
    return bytes(ct), bytes(ss)

def kem_decapsulate(secret_bytes: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulates shared secret using own ML-KEM-768 secret key and received ciphertext.
    Returns shared_secret.
    """
    ss = ml_kem_768.decaps(secret_bytes, ciphertext)
    return bytes(ss)

# --- Symmetric Encryption & Key Derivation ---

def hkdf_extract_and_expand(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256: extracts pseudorandom key and expands to specified length."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else None,
        info=info,
    )
    return hkdf.derive(ikm)

def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-256-GCM.
    Returns (nonce (12 bytes), ciphertext_with_tag).
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext_with_tag

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypts and authenticates AES-256-GCM ciphertext.
    Raises exception if authentication tag fails.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 requires 32-byte key, got {len(key)}")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
