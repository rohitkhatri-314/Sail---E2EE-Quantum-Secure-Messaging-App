# types and helper structures for assignment project
# wrote this for network security e2e messaging lab

from dataclasses import dataclass
from typing import Optional, Dict, List
import base64

# helper for b64 string
def b64_encode(data: bytes) -> str:
    # encode bytes to b64 string
    res = base64.b64encode(data).decode('utf-8')
    return res

def b64_decode(data_str: str) -> bytes:
    # decode b64 string back to bytes
    res_bytes = base64.b64decode(data_str.encode('utf-8'))
    return res_bytes


@dataclass
class IdentityKeyPair:
    # long term id keys for alice or bob
    dh_public: bytes       # x25519 pub key
    dh_private: bytes      # x25519 priv key
    sign_public: bytes     # ed25519 pub
    sign_private: bytes    # ed25519 priv


@dataclass
class PreKeyBundle:
    # prekey bundle that bob uploads to server
    username: str
    identity_dh_key: bytes          
    identity_sign_key: bytes        
    signed_prekey_dh: bytes         
    signed_prekey_kem: bytes        
    signed_prekey_sig: bytes        
    one_time_prekey_id: int         
    one_time_prekey_dh: bytes       
    one_time_prekey_kem: bytes      

    def to_dict(self) -> dict:
        # pack to dictionary so json can send it
        temp_dict = {
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
        return temp_dict

    @classmethod
    def from_dict(cls, d: dict) -> 'PreKeyBundle':
        # unpack from dict
        bundle_obj = cls(
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
        return bundle_obj


@dataclass
class PQXDHInitHeader:
    # init header alice sends to bob in 1st msg
    alice_identity_dh: bytes         
    alice_identity_sign: bytes       
    alice_ephemeral_dh: bytes        
    kem_ct_signed_prekey: bytes      
    kem_ct_one_time_prekey: bytes    
    one_time_prekey_id: int          

    def to_dict(self) -> dict:
        my_map = {
            "alice_identity_dh": b64_encode(self.alice_identity_dh),
            "alice_identity_sign": b64_encode(self.alice_identity_sign),
            "alice_ephemeral_dh": b64_encode(self.alice_ephemeral_dh),
            "kem_ct_signed_prekey": b64_encode(self.kem_ct_signed_prekey),
            "kem_ct_one_time_prekey": b64_encode(self.kem_ct_one_time_prekey),
            "one_time_prekey_id": self.one_time_prekey_id,
        }
        return my_map

    @classmethod
    def from_dict(cls, d: dict) -> 'PQXDHInitHeader':
        h = cls(
            alice_identity_dh=b64_decode(d["alice_identity_dh"]),
            alice_identity_sign=b64_decode(d["alice_identity_sign"]),
            alice_ephemeral_dh=b64_decode(d["alice_ephemeral_dh"]),
            kem_ct_signed_prekey=b64_decode(d["kem_ct_signed_prekey"]),
            kem_ct_one_time_prekey=b64_decode(d["kem_ct_one_time_prekey"]),
            one_time_prekey_id=d["one_time_prekey_id"],
        )
        return h


@dataclass
class RatchetHeader:
    # current ratchet keys for this packet
    sender_ratchet_dh_pub: bytes     
    sender_ratchet_kem_pub: bytes    
    kem_ciphertext: Optional[bytes]  
    pn: int                          # previous chain count
    n: int                           # msg count in current chain

    def to_dict(self) -> dict:
        rh_dict = {
            "sender_ratchet_dh_pub": b64_encode(self.sender_ratchet_dh_pub),
            "sender_ratchet_kem_pub": b64_encode(self.sender_ratchet_kem_pub),
            "kem_ciphertext": b64_encode(self.kem_ciphertext) if self.kem_ciphertext else None,
            "pn": self.pn,
            "n": self.n,
        }
        return rh_dict

    @classmethod
    def from_dict(cls, d: dict) -> 'RatchetHeader':
        r = cls(
            sender_ratchet_dh_pub=b64_decode(d["sender_ratchet_dh_pub"]),
            sender_ratchet_kem_pub=b64_decode(d["sender_ratchet_kem_pub"]),
            kem_ciphertext=b64_decode(d["kem_ciphertext"]) if d.get("kem_ciphertext") else None,
            pn=d["pn"],
            n=d["n"],
        )
        return r


@dataclass
class EncryptedEnvelope:
    # outer packet that goes over websocket
    sender: str
    recipient: str
    pqxdh_init: Optional[PQXDHInitHeader]
    ratchet_header: RatchetHeader
    nonce: bytes
    ciphertext: bytes

    def to_dict(self) -> dict:
        env = {
            "sender": self.sender,
            "recipient": self.recipient,
            "pqxdh_init": self.pqxdh_init.to_dict() if self.pqxdh_init else None,
            "ratchet_header": self.ratchet_header.to_dict(),
            "nonce": b64_encode(self.nonce),
            "ciphertext": b64_encode(self.ciphertext),
        }
        return env

    @classmethod
    def from_dict(cls, d: dict) -> 'EncryptedEnvelope':
        obj = cls(
            sender=d["sender"],
            recipient=d["recipient"],
            pqxdh_init=PQXDHInitHeader.from_dict(d["pqxdh_init"]) if d.get("pqxdh_init") else None,
            ratchet_header=RatchetHeader.from_dict(d["ratchet_header"]),
            nonce=b64_decode(d["nonce"]),
            ciphertext=b64_decode(d["ciphertext"]),
        )
        return obj
