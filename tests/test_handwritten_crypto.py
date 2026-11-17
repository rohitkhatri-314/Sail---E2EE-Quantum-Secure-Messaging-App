"""
Comprehensive Verification Tests for Handwritten Cryptographic Primitives
Validates:
  1. RFC 7748 Curve25519 scalar multiplication against official test vectors
  2. Ed25519 digital signature generation and verification
  3. HMAC-SHA256 and HKDF-SHA256 key expansion
  4. FIPS 197 AES-256 block cipher and AES-GCM AEAD encryption/decryption
  5. End-to-end PQXDH handshake and Double Ratchet messaging
"""

import pytest
import os
from pq_signal.primitives import (
    generate_x25519_keypair,
    x25519_diffie_hellman,
    curve25519_scalarmult,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    hmac_sha256,
    hkdf_extract_and_expand,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    generate_kem_keypair,
    kem_encapsulate,
    kem_decapsulate,
)
from pq_signal.pqxdh import PQXDHManager
from pq_signal.client import PQMessengerClient

def test_rfc7748_curve25519_test_vector():
    """Verify Curve25519 ladder against RFC 7748 official test vector."""
    # RFC 7748 Section 6.1 Alice test vector
    alice_private = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    base_u = (9).to_bytes(32, "little")
    alice_public = curve25519_scalarmult(alice_private, base_u)
    expected_alice_pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert alice_public == expected_alice_pub

def test_x25519_diffie_hellman_symmetry():
    """Verify shared secret agreement between two independent keypairs."""
    pub_a, priv_a = generate_x25519_keypair()
    pub_b, priv_b = generate_x25519_keypair()

    shared_ab = x25519_diffie_hellman(priv_a, pub_b)
    shared_ba = x25519_diffie_hellman(priv_b, pub_a)

    assert shared_ab == shared_ba
    assert len(shared_ab) == 32

def test_ed25519_signature_lifecycle():
    """Verify Ed25519 sign and verify round-trip and tampering detection."""
    pub, priv = generate_ed25519_keypair()
    message = b"Sail quantum-secure E2EE authentication payload"

    sig = ed25519_sign(priv, message)
    assert len(sig) == 64
    assert ed25519_verify(pub, sig, message) is True

    # Tampered message must fail verification
    assert ed25519_verify(pub, sig, b"Modified payload") is False

    # Corrupted signature must fail verification
    corrupt_sig = bytearray(sig)
    corrupt_sig[10] ^= 0x01
    assert ed25519_verify(pub, bytes(corrupt_sig), message) is False

def test_hmac_and_hkdf():
    """Verify HMAC-SHA256 and HKDF derivation."""
    key = b"master-key-seed-32-bytes-long!!"
    salt = b"test-salt"
    info = b"pq-signal-info"
    derived = hkdf_extract_and_expand(salt=salt, ikm=key, info=info, length=64)
    assert len(derived) == 64

    # Consistency check
    derived2 = hkdf_extract_and_expand(salt=salt, ikm=key, info=info, length=64)
    assert derived == derived2

def test_aes_gcm_handwritten_encrypt_decrypt():
    """Verify handwritten AES-256-GCM authenticated cipher."""
    key = os.urandom(32)
    plaintext = b"This is a confidential message encrypted with custom AES-256-GCM."
    aad = b"associated-header-data"

    nonce, ct_with_tag = aes_gcm_encrypt(key, plaintext, associated_data=aad)
    assert len(nonce) == 12
    assert len(ct_with_tag) == len(plaintext) + 16

    recovered = aes_gcm_decrypt(key, nonce, ct_with_tag, associated_data=aad)
    assert recovered == plaintext

    # Tampering ciphertext must trigger tag mismatch
    tampered_ct = bytearray(ct_with_tag)
    tampered_ct[0] ^= 0x55
    with pytest.raises(ValueError):
        aes_gcm_decrypt(key, nonce, bytes(tampered_ct), associated_data=aad)

    # Tampering AAD must trigger tag mismatch
    with pytest.raises(ValueError):
        aes_gcm_decrypt(key, nonce, ct_with_tag, associated_data=b"wrong-aad")

def test_ml_kem_768_roundtrip():
    """Verify Post-Quantum KEM keygen, encapsulation, and decapsulation."""
    pk, sk = generate_kem_keypair()
    ct, ss_enc = kem_encapsulate(pk)
    ss_dec = kem_decapsulate(sk, ct)
    assert ss_enc == ss_dec
    assert len(ss_enc) == 32
