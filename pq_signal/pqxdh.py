# pqxdh handshake logic
# combines x25519 dh with ml-kem-768 for post quantum security

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
    # manager class for prekey bundles and initial handshake

    def __init__(self, username: str):
        self.username = username
        
        # generate identity keys (dh and signing)
        ik_pub, ik_priv = generate_x25519_keypair()
        sig_pub, sig_priv = generate_ed25519_keypair()
        self.identity_keys = IdentityKeyPair(
            dh_public=ik_pub,
            dh_private=ik_priv,
            sign_public=sig_pub,
            sign_private=sig_priv,
        )

        # signed prekeys
        self.spk_dh_pub, self.spk_dh_priv = generate_x25519_keypair()
        self.spk_kem_pub, self.spk_kem_priv = generate_kem_keypair()
        
        # sign spk dh + spk kem using identity sign key
        combined_spk = self.spk_dh_pub + self.spk_kem_pub
        self.spk_signature = ed25519_sign(self.identity_keys.sign_private, combined_spk)

        # one-time prekeys pool
        self.one_time_prekeys: Dict[int, Tuple[bytes, bytes, bytes, bytes]] = {}
        self._next_opk_id = 1
        self.generate_one_time_prekeys(count=10)

    def generate_one_time_prekeys(self, count: int = 10):
        # generate a batch of one time prekeys
        for _ in range(count):
            o_dh_pub, o_dh_priv = generate_x25519_keypair()
            o_kem_pub, o_kem_priv = generate_kem_keypair()
            self.one_time_prekeys[self._next_opk_id] = (
                o_dh_pub, o_dh_priv, o_kem_pub, o_kem_priv
            )
            self._next_opk_id += 1

    def create_prekey_bundle(self) -> PreKeyBundle:
        # package up public bundle to send to server
        if not self.one_time_prekeys:
            self.generate_one_time_prekeys(count=5)
        
        k_id = next(iter(self.one_time_prekeys.keys()))
        o_dh_pub, _, o_kem_pub, _ = self.one_time_prekeys[k_id]

        return PreKeyBundle(
            username=self.username,
            identity_dh_key=self.identity_keys.dh_public,
            identity_sign_key=self.identity_keys.sign_public,
            signed_prekey_dh=self.spk_dh_pub,
            signed_prekey_kem=self.spk_kem_pub,
            signed_prekey_sig=self.spk_signature,
            one_time_prekey_id=k_id,
            one_time_prekey_dh=o_dh_pub,
            one_time_prekey_kem=o_kem_pub,
        )

    def initiate(self, bob_bundle: PreKeyBundle) -> Tuple[bytes, PQXDHInitHeader]:
        # alice initiates handshake with bob bundle
        
        # 1. check signature on bob's signed prekey
        to_verify = bob_bundle.signed_prekey_dh + bob_bundle.signed_prekey_kem
        ok = ed25519_verify(bob_bundle.identity_sign_key, bob_bundle.signed_prekey_sig, to_verify)
        if not ok:
            raise ValueError("PQXDH Handshake Error: Bob's Signed Prekey signature is invalid!")

        # 2. alice generates ephemeral keypair
        ek_pub, ek_priv = generate_x25519_keypair()

        # 3. kem encapsulations
        kem_c1, kem_s1 = kem_encapsulate(bob_bundle.signed_prekey_kem)
        kem_c2, kem_s2 = kem_encapsulate(bob_bundle.one_time_prekey_kem)

        # 4. four diffie hellman operations
        dh1 = x25519_diffie_hellman(self.identity_keys.dh_private, bob_bundle.signed_prekey_dh)
        dh2 = x25519_diffie_hellman(ek_priv, bob_bundle.identity_dh_key)
        dh3 = x25519_diffie_hellman(ek_priv, bob_bundle.signed_prekey_dh)
        dh4 = x25519_diffie_hellman(ek_priv, bob_bundle.one_time_prekey_dh)

        # 5. combine everything with hkdf
        all_secrets = dh1 + dh2 + dh3 + dh4 + kem_s1 + kem_s2
        master_secret = hkdf_extract_and_expand(
            salt=b"\x00" * 32,
            ikm=all_secrets,
            info=PQXDH_INFO,
            length=32
        )

        init_hdr = PQXDHInitHeader(
            alice_identity_dh=self.identity_keys.dh_public,
            alice_identity_sign=self.identity_keys.sign_public,
            alice_ephemeral_dh=ek_pub,
            kem_ct_signed_prekey=kem_c1,
            kem_ct_one_time_prekey=kem_c2,
            one_time_prekey_id=bob_bundle.one_time_prekey_id,
        )

        return master_secret, init_hdr

    def respond(self, init_header: PQXDHInitHeader) -> bytes:
        # bob computes the same master secret
        opk_idx = init_header.one_time_prekey_id
        if opk_idx not in self.one_time_prekeys:
            raise ValueError(f"PQXDH Response Error: OPK with ID {opk_idx} not found or already consumed!")

        opk_dh_pub, opk_dh_priv, opk_kem_pub, opk_kem_priv = self.one_time_prekeys.pop(opk_idx)

        # 1. kem decapsulations
        kem_s1 = kem_decapsulate(self.spk_kem_priv, init_header.kem_ct_signed_prekey)
        kem_s2 = kem_decapsulate(opk_kem_priv, init_header.kem_ct_one_time_prekey)

        # 2. matching dh operations
        dh1 = x25519_diffie_hellman(self.spk_dh_priv, init_header.alice_identity_dh)
        dh2 = x25519_diffie_hellman(self.identity_keys.dh_private, init_header.alice_ephemeral_dh)
        dh3 = x25519_diffie_hellman(self.spk_dh_priv, init_header.alice_ephemeral_dh)
        dh4 = x25519_diffie_hellman(opk_dh_priv, init_header.alice_ephemeral_dh)

        # 3. combine with hkdf
        all_secrets = dh1 + dh2 + dh3 + dh4 + kem_s1 + kem_s2
        master_secret = hkdf_extract_and_expand(
            salt=b"\x00" * 32,
            ikm=all_secrets,
            info=PQXDH_INFO,
            length=32
        )

        return master_secret
