from dataclasses import dataclass
from typing import Optional, Dict, List
import base64

def b64_encode(data: bytes) -> str:
    res = base64.b64encode(data).decode('utf-8')
    return res

def b64_decode(data_str: str) -> bytes:
    res_bytes = base64.b64decode(data_str.encode('utf-8'))
    return res_bytes

@dataclass
class IdentityKeyPair:
    dh_public: bytes
    dh_private: bytes
    sign_public: bytes
    sign_private: bytes

@dataclass
class PreKeyBundle:
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
    sender_ratchet_dh_pub: bytes     
    sender_ratchet_kem_pub: bytes    
    kem_ciphertext: Optional[bytes]  
    pn: int
    n: int

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
