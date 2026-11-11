"""
Custom Hybrid Post-Quantum Double Ratchet Algorithm
Written entirely from scratch.

Features:
- Symmetric KDF chain ratcheting per message (sending & receiving)
- Hybrid Asymmetric Turn-Taking Ratchet combining X25519 DH step + ML-KEM-768 KEM step
- Post-compromise security (self-healing) against quantum adversaries
- Skipped message key store for handling out-of-order message delivery
- AES-256-GCM encryption authenticated over message headers (AEAD)
"""

from typing import Optional, Tuple, Dict
from .primitives import (
    generate_x25519_keypair,
    x25519_diffie_hellman,
    generate_kem_keypair,
    kem_encapsulate,
    kem_decapsulate,
    hkdf_extract_and_expand,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
)
from .types import RatchetHeader, EncryptedEnvelope, PQXDHInitHeader

KDF_RK_INFO = b"PQ_DOUBLE_RATCHET_ROOT_CHAIN"
KDF_CK_INFO = b"PQ_DOUBLE_RATCHET_CHAIN_STEP"
KDF_MK_INFO = b"PQ_DOUBLE_RATCHET_MESSAGE_KEY"
MAX_SKIP = 1000

class PQDoubleRatchetSession:
    """Stateful hybrid Post-Quantum Double Ratchet session."""

    def __init__(self, username: str, peer_username: str):
        self.username = username
        self.peer_username = peer_username

        # Root Key and Chain Keys
        self.rk: Optional[bytes] = None        # 32-byte Root Key
        self.cks: Optional[bytes] = None       # Sending Chain Key
        self.ckr: Optional[bytes] = None       # Receiving Chain Key

        # Current Asymmetric Ratchet Keys (DH + KEM)
        self.dhs_pub: Optional[bytes] = None   # Own ratchet DH public (X25519)
        self.dhs_priv: Optional[bytes] = None  # Own ratchet DH private (X25519)
        self.kems_pub: Optional[bytes] = None  # Own ratchet KEM public (ML-KEM-768)
        self.kems_priv: Optional[bytes] = None # Own ratchet KEM secret (ML-KEM-768)

        # Peer's Current Ratchet Public Keys
        self.dhr_pub: Optional[bytes] = None   # Peer's ratchet DH public (X25519)
        self.kemr_pub: Optional[bytes] = None  # Peer's ratchet KEM public (ML-KEM-768)

        # Pending KEM ciphertext to send with the next outbound message
        self.pending_kem_ct: Optional[bytes] = None

        # Message Counters
        self.ns: int = 0                       # Messages sent in current chain
        self.nr: int = 0                       # Messages received in current chain
        self.pn: int = 0                       # Previous chain length

        # Out-of-order Skipped Keys Store: (ratchet_dh_pub, n) -> message_key (32 bytes)
        self.skipped_message_keys: Dict[Tuple[bytes, int], bytes] = {}

        # Log of cryptographic ratchet steps for live protocol inspector
        self.ratchet_turn_count: int = 0
        self.audit_events: list = []

    def _log_event(self, action: str, details: str):
        self.audit_events.append({
            "turn": self.ratchet_turn_count,
            "action": action,
            "details": details,
            "ns": self.ns,
            "nr": self.nr
        })

    def initialize_as_alice(self, shared_master_key: bytes, bob_ratchet_dh_pub: bytes, bob_ratchet_kem_pub: bytes):
        """
        Alice initializes the session after PQXDH handshake.
        Alice generates her first ratchet keypair, encapsulates to Bob's ratchet KEM,
        and derives the first sending chain.
        """
        self.dhs_pub, self.dhs_priv = generate_x25519_keypair()
        self.kems_pub, self.kems_priv = generate_kem_keypair()
        self.dhr_pub = bob_ratchet_dh_pub
        self.kemr_pub = bob_ratchet_kem_pub

        # Alice immediately executes the first asymmetric step
        # 1. Classical DH(DHs, DHr)
        dh_out = x25519_diffie_hellman(self.dhs_priv, self.dhr_pub)
        # 2. Quantum KEM encaps(KEMr)
        kem_ct, kem_ss = kem_encapsulate(self.kemr_pub)
        self.pending_kem_ct = kem_ct

        # Derive new Root Key and Alice's initial Sending Chain Key
        ikm = dh_out + kem_ss
        derived = hkdf_extract_and_expand(salt=shared_master_key, ikm=ikm, info=KDF_RK_INFO, length=64)
        self.rk = derived[:32]
        self.cks = derived[32:]
        self.ckr = None
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.ratchet_turn_count = 1
        self._log_event("Alice Init", "Derived initial Root Key and Sending Chain via Hybrid Asymmetric step.")

    def initialize_as_bob(self, shared_master_key: bytes, bob_ratchet_dh_priv: bytes, bob_ratchet_dh_pub: bytes,
                          bob_ratchet_kem_priv: bytes, bob_ratchet_kem_pub: bytes):
        """
        Bob initializes session with the pre-generated ratchet keypair advertised in his signed prekey.
        Bob's sending chain is None until Alice's first message arrives.
        """
        self.rk = shared_master_key
        self.dhs_priv = bob_ratchet_dh_priv
        self.dhs_pub = bob_ratchet_dh_pub
        self.kems_priv = bob_ratchet_kem_priv
        self.kems_pub = bob_ratchet_kem_pub
        self.dhr_pub = None
        self.kemr_pub = None
        self.cks = None
        self.ckr = None
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self._log_event("Bob Init", "Initialized with Root Key; waiting for Alice's first message.")

    # --- Symmetric KDF Ratchet Step ---

    def _symmetric_step(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Advances symmetric chain key by 1 step.
        Returns: (next_chain_key, message_key)
        """
        # message_key = HMAC(CK, 0x01)
        mk = hkdf_extract_and_expand(salt=chain_key, ikm=b"\x01", info=KDF_MK_INFO, length=32)
        # next_chain_key = HMAC(CK, 0x02)
        next_ck = hkdf_extract_and_expand(salt=chain_key, ikm=b"\x02", info=KDF_CK_INFO, length=32)
        return next_ck, mk

    # --- Hybrid Asymmetric Ratchet Step ---

    def _asymmetric_ratchet_step(self, header: RatchetHeader):
        """
        Performs hybrid DH + KEM asymmetric ratchet turn upon receiving a new ratchet key from peer.
        Provides Post-Compromise Security (self-healing).
        """
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr_pub = header.sender_ratchet_dh_pub
        self.kemr_pub = header.sender_ratchet_kem_pub

        # 1. Decapsulate peer's KEM ciphertext using our current KEM secret key
        if header.kem_ciphertext is None:
            raise ValueError("Protocol Error: Missing KEM ciphertext in asymmetric ratchet turn!")
        kem_ss_rec = kem_decapsulate(self.kems_priv, header.kem_ciphertext)

        # 2. Compute classical DH(DHs, DHr)
        dh_rec = x25519_diffie_hellman(self.dhs_priv, self.dhr_pub)

        # 3. Advance Root Key and derive Receiving Chain Key
        ikm_rec = dh_rec + kem_ss_rec
        derived_rec = hkdf_extract_and_expand(salt=self.rk, ikm=ikm_rec, info=KDF_RK_INFO, length=64)
        self.rk = derived_rec[:32]
        self.ckr = derived_rec[32:]

        # 4. Generate our FRESH keypair for DH and KEM to ratchet forward our sending chain
        self.dhs_pub, self.dhs_priv = generate_x25519_keypair()
        self.kems_pub, self.kems_priv = generate_kem_keypair()

        # 5. Compute DH with peer's new public DH key
        dh_send = x25519_diffie_hellman(self.dhs_priv, self.dhr_pub)
        # 6. Encapsulate to peer's new public KEM key
        kem_ct_send, kem_ss_send = kem_encapsulate(self.kemr_pub)
        self.pending_kem_ct = kem_ct_send

        # 7. Advance Root Key again and derive Sending Chain Key
        ikm_send = dh_send + kem_ss_send
        derived_send = hkdf_extract_and_expand(salt=self.rk, ikm=ikm_send, info=KDF_RK_INFO, length=64)
        self.rk = derived_send[:32]
        self.cks = derived_send[32:]

        self.ratchet_turn_count += 1
        self._log_event(
            "Hybrid Asymmetric Ratchet Turn",
            f"Turn {self.ratchet_turn_count}: Ratcheted forward with fresh X25519 and ML-KEM-768 keys."
        )

    # --- Skipped Keys Handling ---

    def _skip_message_keys(self, until: int):
        if self.nr + MAX_SKIP < until:
            raise ValueError("Too many skipped messages; exceeds MAX_SKIP threshold")
        if self.ckr is not None:
            while self.nr < until:
                self.ckr, mk = self._symmetric_step(self.ckr)
                self.skipped_message_keys[(self.dhr_pub, self.nr)] = mk
                self.nr += 1

    # --- Encrypt & Decrypt ---

    def encrypt(self, plaintext: bytes, pqxdh_init: Optional[PQXDHInitHeader] = None) -> EncryptedEnvelope:
        """
        Encrypts a message using the current sending chain key.
        Advances symmetric chain.
        """
        if self.cks is None:
            raise ValueError("Session Error: Sending chain key is not initialized!")

        self.cks, mk = self._symmetric_step(self.cks)
        header = RatchetHeader(
            sender_ratchet_dh_pub=self.dhs_pub,
            sender_ratchet_kem_pub=self.kems_pub,
            kem_ciphertext=self.pending_kem_ct,
            pn=self.pn,
            n=self.ns,
        )
        # Once transmitted, clear pending KEM ciphertext until next asymmetric turn
        self.pending_kem_ct = None
        self.ns += 1

        # Authenticate header as associated data
        assoc_data = header.sender_ratchet_dh_pub + header.sender_ratchet_kem_pub + header.n.to_bytes(4, 'big')
        nonce, ciphertext = aes_gcm_encrypt(mk, plaintext, associated_data=assoc_data)

        self._log_event("Message Encrypted", f"Message #{header.n} encrypted with AES-256-GCM.")

        return EncryptedEnvelope(
            sender=self.username,
            recipient=self.peer_username,
            pqxdh_init=pqxdh_init,
            ratchet_header=header,
            nonce=nonce,
            ciphertext=ciphertext
        )

    def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        """
        Decrypts an incoming message envelope.
        Handles out-of-order delivery and triggers asymmetric ratchet turn if peer's key changed.
        """
        header = envelope.ratchet_header

        # 1. Check if key is already in skipped keys pool (out-of-order delivery)
        key_tuple = (header.sender_ratchet_dh_pub, header.n)
        if key_tuple in self.skipped_message_keys:
            mk = self.skipped_message_keys.pop(key_tuple)
            assoc_data = header.sender_ratchet_dh_pub + header.sender_ratchet_kem_pub + header.n.to_bytes(4, 'big')
            plaintext = aes_gcm_decrypt(mk, envelope.nonce, envelope.ciphertext, associated_data=assoc_data)
            self._log_event("Decrypted (Skipped Key)", f"Decrypted out-of-order message #{header.n}")
            return plaintext

        # 2. Check if peer's ratchet DH key has changed (asymmetric ratchet turn needed)
        if header.sender_ratchet_dh_pub != self.dhr_pub:
            # Skip any unreceived messages from previous chain
            self._skip_message_keys(header.pn)
            # Execute Asymmetric DH + KEM Ratchet Step
            self._asymmetric_ratchet_step(header)

        # 3. Skip any missed messages in the current chain
        self._skip_message_keys(header.n)

        # 4. Advance receiving chain to current message index
        self.ckr, mk = self._symmetric_step(self.ckr)
        self.nr += 1

        # 5. Decrypt and verify AEAD tag
        assoc_data = header.sender_ratchet_dh_pub + header.sender_ratchet_kem_pub + header.n.to_bytes(4, 'big')
        plaintext = aes_gcm_decrypt(mk, envelope.nonce, envelope.ciphertext, associated_data=assoc_data)

        self._log_event("Message Decrypted", f"Message #{header.n} decrypted successfully.")
        return plaintext
