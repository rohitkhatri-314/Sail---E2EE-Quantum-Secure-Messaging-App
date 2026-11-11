"""
User Client Session Manager for PQ-Signal Messenger.
Integrates PQXDH and Double Ratchet state machines with local session storage,
Safety Number / Fingerprint computation, and message dispatch.
"""

import hashlib
from typing import Dict, Optional, Tuple, List
from .primitives import generate_x25519_keypair, generate_kem_keypair
from .pqxdh import PQXDHManager
from .ratchet import PQDoubleRatchetSession
from .types import PreKeyBundle, EncryptedEnvelope, b64_encode

class PQMessengerClient:
    """End-user client managing local identity and sessions with contacts."""

    def __init__(self, username: str):
        self.username = username
        self.pqxdh = PQXDHManager(username)
        # Active sessions with peers: peer_username -> PQDoubleRatchetSession
        self.sessions: Dict[str, PQDoubleRatchetSession] = {}
        # Decrypted chat message logs: peer_username -> list of message dicts
        self.message_history: Dict[str, List[dict]] = {}

    def get_public_prekey_bundle(self) -> PreKeyBundle:
        """Export prekey bundle to register with the server."""
        return self.pqxdh.create_prekey_bundle()

    def get_safety_number(self, peer_username: str, peer_identity_sign_key: bytes, peer_identity_dh_key: bytes) -> str:
        """
        Computes 60-digit Safety Number (MITM verification)
        combining both Alice and Bob's long-term identity keys.
        """
        # Lexicographically sort identities so both parties calculate the identical number
        user_data = self.username.encode('utf-8') + self.pqxdh.identity_keys.sign_public + self.pqxdh.identity_keys.dh_public
        peer_data = peer_username.encode('utf-8') + peer_identity_sign_key + peer_identity_dh_key

        if self.username < peer_username:
            combined = user_data + peer_data
        else:
            combined = peer_data + user_data

        h = hashlib.sha512(combined).digest()
        # Convert to 12 blocks of 5 digits (total 60 digits)
        digits = []
        for i in range(0, 24, 2):
            chunk = int.from_bytes(h[i:i+2], 'big') % 100000
            digits.append(f"{chunk:05d}")
        return " ".join(digits)

    def start_session_as_alice(self, bob_bundle: PreKeyBundle) -> PQDoubleRatchetSession:
        """Alice performs PQXDH handshake and initializes ratchet session."""
        shared_master_key, init_header = self.pqxdh.initiate(bob_bundle)
        session = PQDoubleRatchetSession(self.username, bob_bundle.username)
        session.initialize_as_alice(
            shared_master_key=shared_master_key,
            bob_ratchet_dh_pub=bob_bundle.signed_prekey_dh,
            bob_ratchet_kem_pub=bob_bundle.signed_prekey_kem
        )
        self.sessions[bob_bundle.username] = session
        # Store init header to be attached to the first message envelope
        session._initial_pqxdh_header = init_header
        return session

    def encrypt_message(self, recipient: str, plaintext: str, bob_bundle_if_first: Optional[PreKeyBundle] = None) -> EncryptedEnvelope:
        """Encrypts a text message for a recipient."""
        if recipient not in self.sessions:
            if not bob_bundle_if_first:
                raise ValueError(f"No existing session for {recipient}; PreKeyBundle required to initiate.")
            self.start_session_as_alice(bob_bundle_if_first)

        session = self.sessions[recipient]
        init_header = getattr(session, '_initial_pqxdh_header', None)
        # Clear once used
        if hasattr(session, '_initial_pqxdh_header'):
            delattr(session, '_initial_pqxdh_header')

        envelope = session.encrypt(plaintext.encode('utf-8'), pqxdh_init=init_header)

        # Record locally
        if recipient not in self.message_history:
            self.message_history[recipient] = []
        self.message_history[recipient].append({
            "sender": self.username,
            "text": plaintext,
            "turn": session.ratchet_turn_count,
            "n": envelope.ratchet_header.n,
            "status": "sent"
        })

        return envelope

    def receive_envelope(self, envelope: EncryptedEnvelope) -> str:
        """
        Processes and decrypts an incoming envelope from peer.
        If initial PQXDH header is present, initializes Bob's session.
        """
        sender = envelope.sender
        if sender not in self.sessions:
            if not envelope.pqxdh_init:
                raise ValueError(f"Session with {sender} does not exist and no PQXDH init header was attached!")

            # Bob derives shared master key using his private prekeys
            shared_master_key = self.pqxdh.respond(envelope.pqxdh_init)
            session = PQDoubleRatchetSession(self.username, sender)
            session.initialize_as_bob(
                shared_master_key=shared_master_key,
                bob_ratchet_dh_priv=self.pqxdh.spk_dh_priv,
                bob_ratchet_dh_pub=self.pqxdh.spk_dh_pub,
                bob_ratchet_kem_priv=self.pqxdh.spk_kem_priv,
                bob_ratchet_kem_pub=self.pqxdh.spk_kem_pub
            )
            self.sessions[sender] = session

        session = self.sessions[sender]
        plaintext_bytes = session.decrypt(envelope)
        plaintext = plaintext_bytes.decode('utf-8')

        if sender not in self.message_history:
            self.message_history[sender] = []
        self.message_history[sender].append({
            "sender": sender,
            "text": plaintext,
            "turn": session.ratchet_turn_count,
            "n": envelope.ratchet_header.n,
            "status": "received"
        })

        return plaintext
