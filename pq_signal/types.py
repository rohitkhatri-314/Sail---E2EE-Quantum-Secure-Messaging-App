"""
Data structures, serialization, and typing for PQ-Signal protocol.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, List
import base64

def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64_decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode('utf-8'))

@dataclass
class IdentityKeyPair:
    """Long-term identity keys."""
    dh_public: bytes       # X25519 public key (32 bytes)
    dh_private: bytes      # X25519 private key (32 bytes)
    sign_public: bytes     # Ed25519 public key (32 bytes)
    sign_private: bytes    # Ed25519 private key (32 bytes)

@dataclass
class PreKeyBundle:
    """
    Public prekey bundle uploaded to untrusted server.
    Hybrid post-quantum construction.
    """
    username: str
    identity_dh_key: bytes          # IK_dh (X25519)
    identity_sign_key: bytes        # IK_sign (Ed25519)
    signed_prekey_dh: bytes         # SPK_dh (X25519)
    signed_prekey_kem: bytes        # SPK_kem (ML-KEM-768 public key)
    signed_prekey_sig: bytes        # Ed25519 signature over (SPK_dh || SPK_kem)
    one_time_prekey_id: int         # Identifier for selected OPK
    one_time_prekey_dh: bytes       # OPK_dh (X25519)
    one_time_prekey_kem: bytes      # OPK_kem (ML-KEM-768 public key)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "identity_dh_key": b64_encode(self.identity_dh_key),
            "identity_sign_key": b64_encode(self.identity_sign_key),
            "signed_prekey_dh": b64_encode(self.signed_prekey_dh),
            "signed_prekey_kem": b64_encode(self.signed_prekey_kem),
            "signed_prekey_sig": b64_encode(self.signed_prekey_sig),
            "one_time_prekey_id": self.one_time_prekey_id,
            "one_time_prekey_dh": b64_encode(self.one_time_prekey_dh),
            "one_time_prekey_kem": b64_encode(self.one_time_prekey_kem),
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'PreKeyBundle':
        return cls(
            username=d["username"],
            identity_dh_key=b64_decode(d["identity_dh_key"]),
            identity_sign_key=b64_decode(d["identity_sign_key"]),
            signed_prekey_dh=b64_decode(d["signed_prekey_dh"]),
            signed_prekey_kem=b64_decode(d["signed_prekey_kem"]),
            signed_prekey_sig=b64_decode(d["signed_prekey_sig"]),
            one_time_prekey_id=d["one_time_prekey_id"],
            one_time_prekey_dh=b64_decode(d["one_time_prekey_dh"]),
            one_time_prekey_kem=b64_decode(d["one_time_prekey_kem"]),
        )

@dataclass
class PQXDHInitHeader:
    """Header embedded in the initial message to allow recipient to complete PQXDH."""
    alice_identity_dh: bytes         # IK_A_dh (X25519)
    alice_identity_sign: bytes       # IK_A_sign (Ed25519)
    alice_ephemeral_dh: bytes        # EK_A_dh (X25519)
    kem_ct_signed_prekey: bytes      # CT_kem1 (ML-KEM ciphertext for Bob's SPK_kem)
    kem_ct_one_time_prekey: bytes    # CT_kem2 (ML-KEM ciphertext for Bob's OPK_kem)
    one_time_prekey_id: int          # ID of OPK used

    def to_dict(self) -> dict:
        return {
            "alice_identity_dh": b64_encode(self.alice_identity_dh),
            "alice_identity_sign": b64_encode(self.alice_identity_sign),
            "alice_ephemeral_dh": b64_encode(self.alice_ephemeral_dh),
            "kem_ct_signed_prekey": b64_encode(self.kem_ct_signed_prekey),
            "kem_ct_one_time_prekey": b64_encode(self.kem_ct_one_time_prekey),
            "one_time_prekey_id": self.one_time_prekey_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'PQXDHInitHeader':
        return cls(
            alice_identity_dh=b64_decode(d["alice_identity_dh"]),
            alice_identity_sign=b64_decode(d["alice_identity_sign"]),
            alice_ephemeral_dh=b64_decode(d["alice_ephemeral_dh"]),
            kem_ct_signed_prekey=b64_decode(d["kem_ct_signed_prekey"]),
            kem_ct_one_time_prekey=b64_decode(d["kem_ct_one_time_prekey"]),
            one_time_prekey_id=d["one_time_prekey_id"],
        )

@dataclass
class RatchetHeader:
    """
    Header transmitted with every encrypted message.
    Contains current ratchet state keys (Hybrid DH + KEM).
    """
    sender_ratchet_dh_pub: bytes     # Current ratchet DH public key (X25519)
    sender_ratchet_kem_pub: bytes    # Current ratchet KEM public key (ML-KEM-768 pk)
    kem_ciphertext: Optional[bytes]  # KEM ciphertext if this message performed an asymmetric KEM step
    pn: int                          # Previous chain message count (PN)
    n: int                           # Current message index in chain (N)

    def to_dict(self) -> dict:
        return {
            "sender_ratchet_dh_pub": b64_encode(self.sender_ratchet_dh_pub),
            "sender_ratchet_kem_pub": b64_encode(self.sender_ratchet_kem_pub),
            "kem_ciphertext": b64_encode(self.kem_ciphertext) if self.kem_ciphertext else None,
            "pn": self.pn,
            "n": self.n,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'RatchetHeader':
        return cls(
            sender_ratchet_dh_pub=b64_decode(d["sender_ratchet_dh_pub"]),
            sender_ratchet_kem_pub=b64_decode(d["sender_ratchet_kem_pub"]),
            kem_ciphertext=b64_decode(d["kem_ciphertext"]) if d.get("kem_ciphertext") else None,
            pn=d["pn"],
            n=d["n"],
        )

@dataclass
class EncryptedEnvelope:
    """Wire envelope for a message transmitted across the network."""
    sender: str
    recipient: str
    pqxdh_init: Optional[PQXDHInitHeader]
    ratchet_header: RatchetHeader
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "pqxdh_init": self.pqxdh_init.to_dict() if self.pqxdh_init else None,
            "ratchet_header": self.ratchet_header.to_dict(),
            "nonce": b64_encode(self.nonce),
            "ciphertext": b64_encode(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'EncryptedEnvelope':
        return cls(
            sender=d["sender"],
            recipient=d["recipient"],
            pqxdh_init=PQXDHInitHeader.from_dict(d["pqxdh_init"]) if d.get("pqxdh_init") else None,
            ratchet_header=RatchetHeader.from_dict(d["ratchet_header"]),
            nonce=b64_decode(d["nonce"]),
            ciphertext=b64_decode(d["ciphertext"]),
        )
