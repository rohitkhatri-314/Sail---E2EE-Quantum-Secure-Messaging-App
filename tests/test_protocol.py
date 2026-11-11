"""
Tests for Custom Post-Quantum Signal Protocol:
- PQXDH Handshake Agreement
- Double Ratchet Turn-Taking & Forward Secrecy
- Out-of-order Message Recovery (Skipped Keys)
- Tampering Detection & AEAD Tag Integrity
- MITM Safety Number Verification
"""

import pytest
from pq_signal.pqxdh import PQXDHManager
from pq_signal.client import PQMessengerClient
from pq_signal.types import EncryptedEnvelope

def test_pqxdh_shared_master_key_agreement():
    """Verify that Alice and Bob derive identical 32-byte shared master keys via PQXDH."""
    alice = PQXDHManager("alice")
    bob = PQXDHManager("bob")

    # Bob publishes prekey bundle
    bob_bundle = bob.create_prekey_bundle()

    # Alice initiates handshake
    alice_master_key, init_header = alice.initiate(bob_bundle)

    # Bob responds and derives master key
    bob_master_key = bob.respond(init_header)

    assert alice_master_key == bob_master_key
    assert len(alice_master_key) == 32

def test_end_to_end_messaging_and_ratcheting():
    """Verify bidirectional message exchange and asymmetric ratchet advancement."""
    alice = PQMessengerClient("alice")
    bob = PQMessengerClient("bob")

    bob_bundle = bob.get_public_prekey_bundle()

    # Alice sends first message (contains PQXDH init)
    env1 = alice.encrypt_message("bob", "Hello Bob! Quantum security activated.", bob_bundle_if_first=bob_bundle)
    assert env1.pqxdh_init is not None

    # Bob decrypts message 1
    msg1 = bob.receive_envelope(env1)
    assert msg1 == "Hello Bob! Quantum security activated."

    # Bob replies to Alice (triggers hybrid asymmetric ratchet turn)
    env2 = bob.encrypt_message("alice", "Hi Alice! Verified ML-KEM-768 ciphertext received.")
    msg2 = alice.receive_envelope(env2)
    assert msg2 == "Hi Alice! Verified ML-KEM-768 ciphertext received."

    # Multiple conversational turns
    env3 = alice.encrypt_message("bob", "How is the post-compromise security?")
    msg3 = bob.receive_envelope(env3)
    assert msg3 == "How is the post-compromise security?"

    env4 = bob.encrypt_message("alice", "Self-healing ratified on turn 2.")
    msg4 = alice.receive_envelope(env4)
    assert msg4 == "Self-healing ratified on turn 2."

def test_out_of_order_message_handling():
    """Verify that out-of-order messages in a chain decrypt correctly using skipped keys."""
    alice = PQMessengerClient("alice")
    bob = PQMessengerClient("bob")
    bob_bundle = bob.get_public_prekey_bundle()

    # Alice generates 3 messages in a burst
    e1 = alice.encrypt_message("bob", "Message 1", bob_bundle_if_first=bob_bundle)
    e2 = alice.encrypt_message("bob", "Message 2")
    e3 = alice.encrypt_message("bob", "Message 3")

    # Bob receives Message 1 first to initialize session
    assert bob.receive_envelope(e1) == "Message 1"

    # Bob receives Message 3 BEFORE Message 2 (out of order!)
    assert bob.receive_envelope(e3) == "Message 3"

    # Now Bob receives the delayed Message 2
    assert bob.receive_envelope(e2) == "Message 2"

def test_tamper_detection():
    """Verify that any modification to ciphertext or nonce raises an authentication failure."""
    alice = PQMessengerClient("alice")
    bob = PQMessengerClient("bob")
    bob_bundle = bob.get_public_prekey_bundle()

    env = alice.encrypt_message("bob", "Confidential text", bob_bundle_if_first=bob_bundle)

    # Malicious adversary flips a byte in the ciphertext
    tampered_bytes = bytearray(env.ciphertext)
    tampered_bytes[0] ^= 0x01
    env.ciphertext = bytes(tampered_bytes)

    with pytest.raises(Exception):
        bob.receive_envelope(env)

def test_safety_numbers_match():
    """Verify that Alice and Bob compute identical safety numbers for fingerprint verification."""
    alice = PQMessengerClient("alice")
    bob = PQMessengerClient("bob")

    sn_alice = alice.get_safety_number("bob", bob.pqxdh.identity_keys.sign_public, bob.pqxdh.identity_keys.dh_public)
    sn_bob = bob.get_safety_number("alice", alice.pqxdh.identity_keys.sign_public, alice.pqxdh.identity_keys.dh_public)

    assert sn_alice == sn_bob
    assert len(sn_alice.replace(" ", "")) == 60
