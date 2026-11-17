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

    def __init__(self, username: str, peer_username: str):
        self.username = username
        self.peer_username = peer_username

        self.rk: Optional[bytes] = None
        self.cks: Optional[bytes] = None
        self.ckr: Optional[bytes] = None

        self.dhs_pub: Optional[bytes] = None   
        self.dhs_priv: Optional[bytes] = None  
        self.kems_pub: Optional[bytes] = None  
        self.kems_priv: Optional[bytes] = None 

        self.dhr_pub: Optional[bytes] = None   
        self.kemr_pub: Optional[bytes] = None  

        self.pending_kem_ct: Optional[bytes] = None

        self.ns: int = 0
        self.nr: int = 0
        self.pn: int = 0

        self.skipped_message_keys: Dict[Tuple[bytes, int], bytes] = {}

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
        self.dhs_pub, self.dhs_priv = generate_x25519_keypair()
        self.kems_pub, self.kems_priv = generate_kem_keypair()
        self.dhr_pub = bob_ratchet_dh_pub
        self.kemr_pub = bob_ratchet_kem_pub

        dh_out = x25519_diffie_hellman(self.dhs_priv, self.dhr_pub)
        k_ct, k_ss = kem_encapsulate(self.kemr_pub)
        self.pending_kem_ct = k_ct

        combo = dh_out + k_ss
        out_keys = hkdf_extract_and_expand(salt=shared_master_key, ikm=combo, info=KDF_RK_INFO, length=64)
        self.rk = out_keys[:32]
        self.cks = out_keys[32:]
        self.ckr = None
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.ratchet_turn_count = 1
        self._log_event("Alice Init", "Derived initial Root Key and Sending Chain via Hybrid Asymmetric step.")

    def initialize_as_bob(self, shared_master_key: bytes, bob_ratchet_dh_priv: bytes, bob_ratchet_dh_pub: bytes,
                          bob_ratchet_kem_priv: bytes, bob_ratchet_kem_pub: bytes):
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

    def _symmetric_step(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        mk = hkdf_extract_and_expand(salt=chain_key, ikm=b"\x01", info=KDF_MK_INFO, length=32)
        next_ck = hkdf_extract_and_expand(salt=chain_key, ikm=b"\x02", info=KDF_CK_INFO, length=32)
        return next_ck, mk

    def _asymmetric_ratchet_step(self, header: RatchetHeader):
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr_pub = header.sender_ratchet_dh_pub
        self.kemr_pub = header.sender_ratchet_kem_pub

        if header.kem_ciphertext is None:
            raise ValueError("Protocol Error: Missing KEM ciphertext in asymmetric ratchet turn!")
        
        rec_kem_ss = kem_decapsulate(self.kems_priv, header.kem_ciphertext)

        rec_dh = x25519_diffie_hellman(self.dhs_priv, self.dhr_pub)

        combo_rec = rec_dh + rec_kem_ss
        d_rec = hkdf_extract_and_expand(salt=self.rk, ikm=combo_rec, info=KDF_RK_INFO, length=64)
        self.rk = d_rec[:32]
        self.ckr = d_rec[32:]

        self.dhs_pub, self.dhs_priv = generate_x25519_keypair()
        self.kems_pub, self.kems_priv = generate_kem_keypair()

        send_dh = x25519_diffie_hellman(self.dhs_priv, self.dhr_pub)
        s_ct, s_ss = kem_encapsulate(self.kemr_pub)
        self.pending_kem_ct = s_ct

        combo_send = send_dh + s_ss
        d_send = hkdf_extract_and_expand(salt=self.rk, ikm=combo_send, info=KDF_RK_INFO, length=64)
        self.rk = d_send[:32]
        self.cks = d_send[32:]

        self.ratchet_turn_count += 1
        self._log_event(
            "Hybrid Asymmetric Ratchet Turn",
            f"Turn {self.ratchet_turn_count}: Ratcheted forward with fresh X25519 and ML-KEM-768 keys."
        )

    def _skip_message_keys(self, until: int):
        if self.nr + MAX_SKIP < until:
            raise ValueError("Too many skipped messages; exceeds MAX_SKIP threshold")
        if self.ckr is not None:
            while self.nr < until:
                self.ckr, mk = self._symmetric_step(self.ckr)
                self.skipped_message_keys[(self.dhr_pub, self.nr)] = mk
                self.nr += 1

    def encrypt(self, plaintext: bytes, pqxdh_init: Optional[PQXDHInitHeader] = None) -> EncryptedEnvelope:
        if self.cks is None:
            raise ValueError("Session Error: Sending chain key is not initialized!")

        self.cks, msg_key = self._symmetric_step(self.cks)
        hdr = RatchetHeader(
            sender_ratchet_dh_pub=self.dhs_pub,
            sender_ratchet_kem_pub=self.kems_pub,
            kem_ciphertext=self.pending_kem_ct,
            pn=self.pn,
            n=self.ns,
        )
        self.pending_kem_ct = None
        self.ns += 1

        aad = hdr.sender_ratchet_dh_pub + hdr.sender_ratchet_kem_pub + hdr.n.to_bytes(4, 'big')
        iv, cipher_text = aes_gcm_encrypt(msg_key, plaintext, associated_data=aad)

        self._log_event("Message Encrypted", f"Message #{hdr.n} encrypted with AES-256-GCM.")

        return EncryptedEnvelope(
            sender=self.username,
            recipient=self.peer_username,
            pqxdh_init=pqxdh_init,
            ratchet_header=hdr,
            nonce=iv,
            ciphertext=cipher_text
        )

    def decrypt(self, envelope: EncryptedEnvelope) -> bytes:
        hdr = envelope.ratchet_header

        k_tuple = (hdr.sender_ratchet_dh_pub, hdr.n)
        if k_tuple in self.skipped_message_keys:
            msg_key = self.skipped_message_keys.pop(k_tuple)
            aad = hdr.sender_ratchet_dh_pub + hdr.sender_ratchet_kem_pub + hdr.n.to_bytes(4, 'big')
            pt = aes_gcm_decrypt(msg_key, envelope.nonce, envelope.ciphertext, associated_data=aad)
            self._log_event("Decrypted (Skipped Key)", f"Decrypted out-of-order message #{hdr.n}")
            return pt

        if hdr.sender_ratchet_dh_pub != self.dhr_pub:
            self._skip_message_keys(hdr.pn)
            self._asymmetric_ratchet_step(hdr)

        self._skip_message_keys(hdr.n)

        self.ckr, msg_key = self._symmetric_step(self.ckr)
        self.nr += 1

        aad = hdr.sender_ratchet_dh_pub + hdr.sender_ratchet_kem_pub + hdr.n.to_bytes(4, 'big')
        pt = aes_gcm_decrypt(msg_key, envelope.nonce, envelope.ciphertext, associated_data=aad)

        self._log_event("Message Decrypted", f"Message #{hdr.n} decrypted successfully.")
        return pt
