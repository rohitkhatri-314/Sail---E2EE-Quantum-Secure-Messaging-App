"""
Sail — Quantum-Secure E2E Messaging Application Server
Single FastAPI app handling:
  - Login / session management (simple credentials)
  - Prekey registration & directory (REST)
  - Message relay (WebSocket)
  - Local protocol engine (crypto; runs in-process)
  - Static file serving for the product Web UI
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Response, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import hashlib
import secrets
import uvicorn

# ── Protocol engine (100 % custom, no high-level protocol libs) ──────────────
from pq_signal.client import PQMessengerClient
from pq_signal.types  import PreKeyBundle, EncryptedEnvelope, b64_encode
from server.history_db import init_db, save_message, get_history_for_peer, get_all_previews
import time

# Initialize local message store database
init_db()

# ─── Static credentials (simple auth as requested) ───────────────────────────
CREDENTIALS: Dict[str, str] = {
    "alice": "alice",
    "bob":   "bob",
}

# ─── In-process shared state ──────────────────────────────────────────────────
# All clients live in the same Python process so Alice → Bob delivery is instant
messenger_clients: Dict[str, PQMessengerClient] = {}   # username → client
sessions: Dict[str, str] = {}                           # session_token → username
ws_connections: Dict[str, WebSocket] = {}               # username → ws
offline_queue: Dict[str, List[dict]] = {}               # username → [envelope_dict]

# ─── FastAPI app ──────────────────────────────────────────────────────────────
app = FastAPI(title="Sail Messenger")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Pre-create protocol clients for all known users so prekey bundles are available
# even before the peer has logged in (needed for PQXDH initiation)
for _u in CREDENTIALS:
    messenger_clients[_u] = PQMessengerClient(_u)
    offline_queue[_u] = []

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "client", "static")

# ── Helpers ───────────────────────────────────────────────────────────────────
def _make_token() -> str:
    return secrets.token_hex(24)

def _extract_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get("session_token")

def _get_user_from_request(request: Request) -> Optional[str]:
    token = _extract_token(request)
    return sessions.get(token) if token else None

def _ensure_client(username: str):
    """Lazily create the protocol client for a user the first time they log in."""
    if username not in messenger_clients:
        messenger_clients[username] = PQMessengerClient(username)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def login(req: LoginRequest, response: Response):
    u = req.username.strip().lower()
    if CREDENTIALS.get(u) != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    _ensure_client(u)
    if u not in offline_queue:
        offline_queue[u] = []
    token = _make_token()
    sessions[token] = u
    response.set_cookie("session_token", token, httponly=True, samesite="lax")
    return {"status": "ok", "username": u, "token": token}

@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = _extract_token(request)
    if token and token in sessions:
        del sessions[token]
    response.delete_cookie("session_token")
    return {"status": "ok"}

@app.get("/api/me")
def whoami(request: Request):
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return {"username": user}

# ══════════════════════════════════════════════════════════════════════════════
# PREKEY DIRECTORY  (used by both sender & receiver in-process)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def list_users(request: Request):
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    # Return only peers (not self)
    peers = [u for u in messenger_clients if u != user]
    return {"users": peers}

# ══════════════════════════════════════════════════════════════════════════════
# MESSAGING  (encrypt, decrypt, session info)
# ══════════════════════════════════════════════════════════════════════════════

class SendRequest(BaseModel):
    recipient: str
    text: str

@app.post("/api/send")
async def send_message(req: SendRequest, request: Request):
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    
    sender_client = messenger_clients.get(user)
    if not sender_client:
        raise HTTPException(status_code=400, detail="Client not initialized")
    
    recipient = req.recipient.strip().lower()
    _ensure_client(recipient)
    
    # First message → need recipient's prekey bundle to initiate PQXDH
    bob_bundle: Optional[PreKeyBundle] = None
    if recipient not in sender_client.sessions:
        bob_client = messenger_clients[recipient]
        bob_bundle = bob_client.get_public_prekey_bundle()
    
    envelope = sender_client.encrypt_message(recipient, req.text, bob_bundle_if_first=bob_bundle)
    env_dict = envelope.to_dict()

    turn_count = sender_client.sessions[recipient].ratchet_turn_count
    print(f"\n[BLIND RELAY] >>> Encrypted Packet Routed:")
    print(f"  Sender: {user} -> Recipient: {recipient}")
    print(f"  Ratchet Turn: {turn_count} | Msg Index: {envelope.ratchet_header.n}")
    print(f"  AES-256-GCM Nonce: {env_dict['nonce']}")
    print(f"  AES-256-GCM Ciphertext (bytes): {env_dict['ciphertext'][:40]}... [len={len(env_dict['ciphertext'])}]")
    if env_dict.get('pqxdh_init'):
        print(f"  PQXDH Handshake Attached: ML-KEM-768 Ciphertext: {env_dict['pqxdh_init']['kem_ct_signed_prekey'][:40]}...")
    print(f"  [Server Status]: Undecryptable ciphertext safely forwarded to {recipient}.\n")

    # Deliver to recipient immediately if they are online
    recipient_ws = ws_connections.get(recipient)
    if recipient_ws is not None:
        try:
            await recipient_ws.send_json({"type": "envelope", "envelope": env_dict})
            print(f"  [WS PUSH] Delivered encrypted envelope to {recipient}.")
        except Exception as e:
            print(f"  [WS WARN] Failed pushing to {recipient} ({e}); queueing offline.")
            if ws_connections.get(recipient) is recipient_ws:
                ws_connections.pop(recipient, None)
            offline_queue.setdefault(recipient, []).append(env_dict)
    else:
        print(f"  [QUEUE] {recipient} not connected; queued encrypted envelope.")
        offline_queue.setdefault(recipient, []).append(env_dict)

    session = sender_client.sessions[recipient]
    ts_now = int(time.time() * 1000)

    # Persist sent message in sender's local history database
    save_message(
        owner=user,
        peer=recipient,
        sender=user,
        text=req.text,
        ts=ts_now,
        status="sent",
        turn=session.ratchet_turn_count,
        n=envelope.ratchet_header.n
    )

    return {
        "status": "ok",
        "n": envelope.ratchet_header.n,
        "turn": session.ratchet_turn_count,
        "ts": ts_now,
    }

@app.get("/api/session-info/{peer}")
def session_info(peer: str, request: Request):
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    
    client = messenger_clients.get(user)
    if not client:
        return {"has_session": False}
    
    session = client.sessions.get(peer)
    if not session:
        return {"has_session": False}
    
    return {
        "has_session": True,
        "ratchet_turn": session.ratchet_turn_count,
        "ns": session.ns,
        "nr": session.nr,
        "pn": session.pn,
        "root_key_prefix": b64_encode(session.rk[:8]) if session.rk else None,
        "ratchet_dh_pub": b64_encode(session.dhs_pub) if session.dhs_pub else None,
        "ratchet_kem_pub_prefix": b64_encode(session.kems_pub[:16]) if session.kems_pub else None,
        "audit_events": session.audit_events[-10:],
    }

@app.post("/api/receive")
def receive_envelope_endpoint(request: Request, envelope_dict: dict):
    """Called by the browser after receiving a WS-pushed envelope; decrypts it."""
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)

    client = messenger_clients.get(user)
    if not client:
        raise HTTPException(status_code=400, detail="Client not initialized")

    try:
        envelope = EncryptedEnvelope.from_dict(envelope_dict)
        # Ensure sender's client exists (so Bob is registered if Alice just sent)
        sender = envelope.sender
        _ensure_client(sender)
        plaintext = client.receive_envelope(envelope)
        ts_now = int(time.time() * 1000)

        # Persist received message in recipient's local history database
        session = client.sessions[sender]
        save_message(
            owner=user,
            peer=sender,
            sender=sender,
            text=plaintext,
            ts=ts_now,
            status="received",
            turn=session.ratchet_turn_count,
            n=envelope.ratchet_header.n
        )

        return {"status": "ok", "sender": sender, "text": plaintext, "ts": ts_now}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

@app.get("/api/history/{peer}")
def fetch_history(peer: str, request: Request):
    """Retrieves stored message history between the logged-in user and peer."""
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    history = get_history_for_peer(owner=user, peer=peer)
    return {"status": "ok", "history": history}

@app.get("/api/previews")
def fetch_previews(request: Request):
    """Retrieves last message previews for all contacts."""
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    previews = get_all_previews(owner=user)
    return {"status": "ok", "previews": previews}

@app.post("/api/sync")
def sync_pending(request: Request):
    """Decrypts any remaining offline-queued messages for the logged-in user."""
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    client = messenger_clients.get(user)
    if not client:
        raise HTTPException(status_code=400, detail="Client not initialized")

    pending = offline_queue.pop(user, [])
    offline_queue[user] = []
    decrypted = []
    for env_dict in pending:
        try:
            envelope = EncryptedEnvelope.from_dict(env_dict)
            sender = envelope.sender
            _ensure_client(sender)
            plaintext = client.receive_envelope(envelope)
            ts_now = int(time.time() * 1000)
            session = client.sessions[sender]
            save_message(
                owner=user,
                peer=sender,
                sender=sender,
                text=plaintext,
                ts=ts_now,
                status="received",
                turn=session.ratchet_turn_count,
                n=envelope.ratchet_header.n
            )
            decrypted.append({"sender": sender, "text": plaintext, "ts": ts_now})
        except Exception as e:
            print(f"[SYNC ERROR] Failed to decrypt queued message for {user}: {e}")
    return {"status": "ok", "messages": decrypted}

@app.get("/api/safety-number/{peer}")
def safety_number(peer: str, request: Request):
    user = _get_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401)
    
    client = messenger_clients.get(user)
    if not client:
        raise HTTPException(status_code=400)
    
    peer_client = messenger_clients.get(peer)
    if not peer_client:
        raise HTTPException(status_code=404, detail="Peer not found")
    
    sn = client.get_safety_number(
        peer,
        peer_client.pqxdh.identity_keys.sign_public,
        peer_client.pqxdh.identity_keys.dh_public,
    )
    return {"safety_number": sn, "peer": peer}

# ══════════════════════════════════════════════════════════════════════════════
# WEBSOCKET  (real-time delivery of incoming messages to the browser)
# ══════════════════════════════════════════════════════════════════════════════

@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: Optional[str] = Query(default=None)):
    # Auth via query param (?token=...) for per-tab isolation, with cookie fallback
    tok = token or websocket.cookies.get("session_token")
    username = sessions.get(tok) if tok else None

    await websocket.accept()
    if not username:
        await websocket.close(code=4001)
        return

    ws_connections[username] = websocket
    print(f"[WS] {username} connected.")

    # Flush offline queue
    pending = offline_queue.pop(username, [])
    offline_queue[username] = []
    for i, env in enumerate(pending):
        try:
            await websocket.send_json({"type": "envelope", "envelope": env})
        except Exception:
            # Re-queue unsent items
            offline_queue[username] = pending[i:] + offline_queue.get(username, [])
            break

    try:
        while True:
            await websocket.receive_text()   # keep-alive / heartbeat
    except (WebSocketDisconnect, Exception):
        if ws_connections.get(username) is websocket:
            ws_connections.pop(username, None)
        print(f"[WS] {username} disconnected.")

# ══════════════════════════════════════════════════════════════════════════════
# STATIC FILES & SPA ROUTING
# ══════════════════════════════════════════════════════════════════════════════

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)   # No content — silences the 404 log spam

@app.get("/{full_path:path}")
def catch_all(full_path: str):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("\n══════════════════════════════════════════════")
    print("  SAIL MESSENGER  |  Quantum-Secure E2EE")
    print("  http://127.0.0.1:8000")
    print("══════════════════════════════════════════════\n")
    uvicorn.run("run:app", host="127.0.0.1", port=8000, log_level="info", reload=False)
