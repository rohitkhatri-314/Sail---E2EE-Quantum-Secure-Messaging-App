"""
Post-Quantum Extended Triple Diffie-Hellman (PQXDH) Protocol Engine
Written entirely from scratch.

Combines:
- Classical 4-way X25519 DH (IK_A x SPK_B, EK_A x IK_B, EK_A x SPK_B, EK_A x OPK_B)
- Post-Quantum Dual ML-KEM-768 Encapsulations (SS_kem1 to SPK_kem, SS_kem2 to OPK_kem)
- Hybrid HKDF Master Secret derivation.
"""

from typing import Tuple, Dict
from .primitives import (
    generate_x25519_keypair,
    x25519_diffie_hellman,
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    generate_kem_keypair,
    kem_encapsulate,
    kem_decapsulate,
    hkdf_extract_and_expand,
)
from .types import (
    IdentityKeyPair,
    PreKeyBundle,
    PQXDHInitHeader,
)

PQXDH_INFO = b"PQXDH_HYBRID_X25519_ML_KEM_768_V1"

class PQXDHManager:
    """Manages prekeys, identity generation, and PQXDH handshake execution."""

    def __init__(self, username: str):
        self.username = username
        # Generate Identity Key Pair (DH + Sign)
        ik_dh_pub, ik_dh_priv = generate_x25519_keypair()
        ik_sign_pub, ik_sign_priv = generate_ed25519_keypair()
        self.identity_keys = IdentityKeyPair(
            dh_public=ik_dh_pub,
            dh_private=ik_dh_priv,
            sign_public=ik_sign_pub,
            sign_private=ik_sign_priv,
        )

        # Signed Prekey (DH + KEM)
        self.spk_dh_pub, self.spk_dh_priv = generate_x25519_keypair()
        self.spk_kem_pub, self.spk_kem_priv = generate_kem_keypair()
        # Sign the combination (SPK_dh || SPK_kem) with Identity Signing Key
        data_to_sign = self.spk_dh_pub + self.spk_kem_pub
        self.spk_signature = ed25519_sign(self.identity_keys.sign_private, data_to_sign)

        # One-time Prekeys pool: id -> (dh_pub, dh_priv, kem_pub, kem_priv)
        self.one_time_prekeys: Dict[int, Tuple[bytes, bytes, bytes, bytes]] = {}
        self._next_opk_id = 1
        self.generate_one_time_prekeys(count=10)

    def generate_one_time_prekeys(self, count: int = 10):
        """Generates a batch of one-time hybrid prekeys."""
        for _ in range(count):
            opk_dh_pub, opk_dh_priv = generate_x25519_keypair()
            opk_kem_pub, opk_kem_priv = generate_kem_keypair()
            self.one_time_prekeys[self._next_opk_id] = (
                opk_dh_pub, opk_dh_priv, opk_kem_pub, opk_kem_priv
            )
            self._next_opk_id += 1

    def create_prekey_bundle(self) -> PreKeyBundle:
        """
        Produces a prekey bundle for publication to the directory server.
        Consumes one OPK from the pool.
        """
        if not self.one_time_prekeys:
            self.generate_one_time_prekeys(count=5)
        
        opk_id = next(iter(self.one_time_prekeys.keys()))
        opk_dh_pub, _, opk_kem_pub, _ = self.one_time_prekeys[opk_id]

        return PreKeyBundle(
            username=self.username,
            identity_dh_key=self.identity_keys.dh_public,
            identity_sign_key=self.identity_keys.sign_public,
            signed_prekey_dh=self.spk_dh_pub,
            signed_prekey_kem=self.spk_kem_pub,
            signed_prekey_sig=self.spk_signature,
            one_time_prekey_id=opk_id,
            one_time_prekey_dh=opk_dh_pub,
            one_time_prekey_kem=opk_kem_pub,
        )

    def initiate(self, bob_bundle: PreKeyBundle) -> Tuple[bytes, PQXDHInitHeader]:
        """
        Executed by Alice: initiates PQXDH with Bob's published prekey bundle.
        Returns:
            shared_master_key: 32-byte secret seed for the Double Ratchet.
            init_header: PQXDH header to send to Bob.
        """
        # 1. Verify Bob's signed prekey signature
        signed_data = bob_bundle.signed_prekey_dh + bob_bundle.signed_prekey_kem
        if not ed25519_verify(bob_bundle.identity_sign_key, bob_bundle.signed_prekey_sig, signed_data):
            raise ValueError("PQXDH Handshake Error: Bob's Signed Prekey signature is invalid!")

        # 2. Generate Alice's ephemeral keypair
        ek_a_pub, ek_a_priv = generate_x25519_keypair()

        # 3. Post-Quantum Encapsulations (ML-KEM-768)
        # Encapsulate to Bob's Signed Prekey KEM
        kem_ct1, kem_ss1 = kem_encapsulate(bob_bundle.signed_prekey_kem)
        # Encapsulate to Bob's One-Time Prekey KEM
        kem_ct2, kem_ss2 = kem_encapsulate(bob_bundle.one_time_prekey_kem)

        # 4. Classical Diffie-Hellman Computations (X25519)
        # DH1 = DH(IK_A, SPK_B)
        dh1 = x25519_diffie_hellman(self.identity_keys.dh_private, bob_bundle.signed_prekey_dh)
        # DH2 = DH(EK_A, IK_B)
        dh2 = x25519_diffie_hellman(ek_a_priv, bob_bundle.identity_dh_key)
        # DH3 = DH(EK_A, SPK_B)
        dh3 = x25519_diffie_hellman(ek_a_priv, bob_bundle.signed_prekey_dh)
        # DH4 = DH(EK_A, OPK_B)
        dh4 = x25519_diffie_hellman(ek_a_priv, bob_bundle.one_time_prekey_dh)

        # 5. Hybrid Master Key Derivation (HKDF)
        # Combines all 4 classical DH shared secrets and both Post-Quantum KEM shared secrets
        ikm = dh1 + dh2 + dh3 + dh4 + kem_ss1 + kem_ss2
        shared_master_key = hkdf_extract_and_expand(
            salt=b"\x00" * 32,
            ikm=ikm,
            info=PQXDH_INFO,
            length=32
        )

        init_header = PQXDHInitHeader(
            alice_identity_dh=self.identity_keys.dh_public,
            alice_identity_sign=self.identity_keys.sign_public,
            alice_ephemeral_dh=ek_a_pub,
            kem_ct_signed_prekey=kem_ct1,
            kem_ct_one_time_prekey=kem_ct2,
            one_time_prekey_id=bob_bundle.one_time_prekey_id,
        )

        return shared_master_key, init_header

    def respond(self, init_header: PQXDHInitHeader) -> bytes:
        """
        Executed by Bob: processes Alice's PQXDH init header and recovers identical master key.
        Returns:
            shared_master_key: 32-byte secret seed for the Double Ratchet.
        """
        # Retrieve Bob's OPK used by Alice
        opk_id = init_header.one_time_prekey_id
        if opk_id not in self.one_time_prekeys:
            raise ValueError(f"PQXDH Response Error: OPK with ID {opk_id} not found or already consumed!")

        opk_dh_pub, opk_dh_priv, opk_kem_pub, opk_kem_priv = self.one_time_prekeys.pop(opk_id)

        # 1. Post-Quantum Decapsulations (ML-KEM-768)
        kem_ss1 = kem_decapsulate(self.spk_kem_priv, init_header.kem_ct_signed_prekey)
        kem_ss2 = kem_decapsulate(opk_kem_priv, init_header.kem_ct_one_time_prekey)

        # 2. Classical Diffie-Hellman Computations (X25519)
        # DH1 = DH(SPK_B, IK_A)
        dh1 = x25519_diffie_hellman(self.spk_dh_priv, init_header.alice_identity_dh)
        # DH2 = DH(IK_B, EK_A)
        dh2 = x25519_diffie_hellman(self.identity_keys.dh_private, init_header.alice_ephemeral_dh)
        # DH3 = DH(SPK_B, EK_A)
        dh3 = x25519_diffie_hellman(self.spk_dh_priv, init_header.alice_ephemeral_dh)
        # DH4 = DH(OPK_B, EK_A)
        dh4 = x25519_diffie_hellman(opk_dh_priv, init_header.alice_ephemeral_dh)

        # 3. Hybrid Master Key Derivation (HKDF)
        ikm = dh1 + dh2 + dh3 + dh4 + kem_ss1 + kem_ss2
        shared_master_key = hkdf_extract_and_expand(
            salt=b"\x00" * 32,
            ikm=ikm,
            info=PQXDH_INFO,
            length=32
        )

        return shared_master_key
