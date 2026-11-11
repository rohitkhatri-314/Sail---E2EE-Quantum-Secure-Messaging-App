# Sail — Quantum-Secure End-to-End Encrypted Messaging App

A full-featured end-to-end encrypted messaging application implementing a **custom, from-scratch Post-Quantum Signal Protocol** (**PQXDH + PQ-Double Ratchet**) using hybrid **X25519 + ML-KEM-768 (FIPS 203)** cryptography.

---

## 1. Cryptographic Architecture (Written From Scratch)

Standard Signal Protocol relies on classical Curve25519 (X25519) Diffie-Hellman, which is vulnerable to Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC). **Sail** upgrades the protocol to a **Hybrid Post-Quantum construction** without using any high-level protocol libraries (`libsignal`, etc.):

```
+-----------------------------------------------------------------------------+
|                            Sail Protocol Engine                             |
+-----------------------------------------------------------------------------+
| 1. PQXDH (Hybrid Initial Key Agreement):                                    |
|    - 4 Classical Diffie-Hellman exchanges (X25519):                         |
|        DH1 = DH(IK_A, SPK_B)                                                |
|        DH2 = DH(EK_A, IK_B)                                                 |
|        DH3 = DH(EK_A, SPK_B)                                                |
|        DH4 = DH(EK_A, OPK_B)                                                |
|    - 2 Post-Quantum Key Encapsulations (ML-KEM-768 / Kyber-768, FIPS 203):  |
|        SS_kem1 = KEM.Encaps(SPK_kem,B)                                      |
|        SS_kem2 = KEM.Encaps(OPK_kem,B)                                      |
|    - Hybrid Master Key Derivation:                                          |
|        SK = HKDF(0, DH1 || DH2 || DH3 || DH4 || SS_kem1 || SS_kem2)        |
+-----------------------------------------------------------------------------+
| 2. PQ-Double Ratchet (Forward Secrecy + Post-Compromise Security):           |
|    - Symmetric KDF Ratchet: advances sending/receiving chains per-message.  |
|    - Hybrid Asymmetric Ratchet: triggered upon conversational turns.        |
|        Derives fresh root key from:                                         |
|        RK_{i+1}, CK = HKDF(RK_i, DH(EK_{curr}, EK_{peer}) || SS_{kem})     |
|    - Out-of-Order Delivery: maintains a Skipped Keys store for reordered    |
|      messages without breaking forward secrecy.                             |
|    - AEAD Encryption: AES-256-GCM with authenticated message headers.       |
+-----------------------------------------------------------------------------+
```

---

## 2. Features

- **Clean Messaging Interface**: Familiar chat layout with contact list, unread badges, delivery checkmarks, timestamps, and persistent local message history (`SQLite`).
- **Simple Account Login**: Isolated per-tab/per-browser sessions (`alice / alice`, `bob / bob`).
- **Security Verification**: 60-digit safety numbers computed from both participants' identity keys to verify against Man-In-The-Middle (MITM) attacks.
- **Blind Relay Architecture**: Server routes only encrypted envelopes (`AES-256-GCM` ciphertext, nonces, ephemeral ratchet keys, and `ML-KEM-768` ciphertexts) and cannot decrypt user messages.

---

## 3. Running Sail

### Prerequisites
Install Python 3.10+ dependencies:
```bash
pip install -r requirements.txt
```

### Start the Server
```bash
python run.py
```
Open **`http://127.0.0.1:8000`** in two separate browser windows or tabs:
- Window 1: sign in with `alice` / `alice`
- Window 2: sign in with `bob` / `bob`

---

## 4. Running the Protocol Test Suite

```bash
python -m pytest tests/ -v
```

Covered tests:
- `test_pqxdh_shared_master_key_agreement`: Verifies Alice and Bob derive identical 32-byte master secrets.
- `test_end_to_end_messaging_and_ratcheting`: Verifies bidirectional exchanges and hybrid asymmetric ratchet turns.
- `test_out_of_order_message_handling`: Verifies skipped-key buffer decrypts reordered packets.
- `test_tamper_detection`: Verifies AEAD tag verification fails on modified ciphertext.
- `test_safety_numbers_match`: Verifies matching 60-digit safety numbers.
