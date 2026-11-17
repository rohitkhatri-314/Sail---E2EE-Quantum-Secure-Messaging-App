import hashlib
from typing import Dict, Optional, Tuple, List
from .primitives import generate_x25519_keypair, generate_kem_keypair
from .pqxdh import PQXDHManager
from .ratchet import PQDoubleRatchetSession
from .types import PreKeyBundle, EncryptedEnvelope, b64_encode

class PQMessengerClient:

    def __init__(self, username: str):
        self.username = username
        self.pqxdh = PQXDHManager(username)
        self.sessions: Dict[str, PQDoubleRatchetSession] = {}
        self.message_history: Dict[str, List[dict]] = {}

    def get_public_prekey_bundle(self) -> PreKeyBundle:
        return self.pqxdh.create_prekey_bundle()

    def get_safety_number(self, peer_username: str, peer_identity_sign_key: bytes, peer_identity_dh_key: bytes) -> str:
        u_bytes = self.username.encode('utf-8') + self.pqxdh.identity_keys.sign_public + self.pqxdh.identity_keys.dh_public
        p_bytes = peer_username.encode('utf-8') + peer_identity_sign_key + peer_identity_dh_key

        if self.username < peer_username:
            combo = u_bytes + p_bytes
        else:
            combo = p_bytes + u_bytes

        dig = hashlib.sha512(combo).digest()
        chunks = []
        for idx in range(0, 24, 2):
            num = int.from_bytes(dig[idx:idx+2], 'big') % 100000
            chunks.append(f"{num:05d}")
        return " ".join(chunks)

    def start_session_as_alice(self, bob_bundle: PreKeyBundle) -> PQDoubleRatchetSession:
        sk, hdr = self.pqxdh.initiate(bob_bundle)
        sess = PQDoubleRatchetSession(self.username, bob_bundle.username)
        sess.initialize_as_alice(
            shared_master_key=sk,
            bob_ratchet_dh_pub=bob_bundle.signed_prekey_dh,
            bob_ratchet_kem_pub=bob_bundle.signed_prekey_kem
        )
        self.sessions[bob_bundle.username] = sess
        sess._initial_pqxdh_header = hdr
        return sess

    def encrypt_message(self, recipient: str, plaintext: str, bob_bundle_if_first: Optional[PreKeyBundle] = None) -> EncryptedEnvelope:
        if recipient not in self.sessions:
            if not bob_bundle_if_first:
                raise ValueError(f"No existing session for {recipient}; PreKeyBundle required to initiate.")
            self.start_session_as_alice(bob_bundle_if_first)

        sess = self.sessions[recipient]
        init_hdr = getattr(sess, '_initial_pqxdh_header', None)
        if hasattr(sess, '_initial_pqxdh_header'):
            delattr(sess, '_initial_pqxdh_header')

        env = sess.encrypt(plaintext.encode('utf-8'), pqxdh_init=init_hdr)

        if recipient not in self.message_history:
            self.message_history[recipient] = []
        self.message_history[recipient].append({
            "sender": self.username,
            "text": plaintext,
            "turn": sess.ratchet_turn_count,
            "n": env.ratchet_header.n,
            "status": "sent"
        })

        return env

    def receive_envelope(self, envelope: EncryptedEnvelope) -> str:
        snd = envelope.sender
        if snd not in self.sessions:
            if not envelope.pqxdh_init:
                raise ValueError(f"Session with {snd} does not exist and no PQXDH init header was attached!")

            shared_k = self.pqxdh.respond(envelope.pqxdh_init)
            sess = PQDoubleRatchetSession(self.username, snd)
            sess.initialize_as_bob(
                shared_master_key=shared_k,
                bob_ratchet_dh_priv=self.pqxdh.spk_dh_priv,
                bob_ratchet_dh_pub=self.pqxdh.spk_dh_pub,
                bob_ratchet_kem_priv=self.pqxdh.spk_kem_priv,
                bob_ratchet_kem_pub=self.pqxdh.spk_kem_pub
            )
            self.sessions[snd] = sess

        sess = self.sessions[snd]
        pt_raw = sess.decrypt(envelope)
        pt_str = pt_raw.decode('utf-8')

        if snd not in self.message_history:
            self.message_history[snd] = []
        self.message_history[snd].append({
            "sender": snd,
            "text": pt_str,
            "turn": sess.ratchet_turn_count,
            "n": envelope.ratchet_header.n,
            "status": "received"
        })

        return pt_str
