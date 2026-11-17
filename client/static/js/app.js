let currentUser  = null;
let currentPeer  = null;
let authToken    = sessionStorage.getItem("sail_token") || null;
let socket       = null;
let heartbeatId  = null;
let receiveQueue = Promise.resolve();
const unreadCounts = {};

function getStorageKey(user) {
  return `sail_messages_${user}`;
}

function loadStoredMessages(user) {
  try {
    const raw = localStorage.getItem(getStorageKey(user));
    return raw ? JSON.parse(raw) : {};
  } catch (e) {
    return {};
  }
}

function saveStoredMessages(user, msgs) {
  try {
    localStorage.setItem(getStorageKey(user), JSON.stringify(msgs));
  } catch (e) {
    console.error("Failed to save to localStorage", e);
  }
}

let localMessages = {};

async function apiFetch(url, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }
  const res = await fetch(url, Object.assign({}, options, { headers }));
  if (res.status === 401 && currentUser) {
    resetToLogin();
  }
  return res;
}

function resetToLogin() {
  if (heartbeatId) clearInterval(heartbeatId);
  heartbeatId = null;
  if (socket) {
    socket.onclose = null;
    socket.close();
  }
  socket = null;
  currentUser = null;
  currentPeer = null;
  authToken = null;
  sessionStorage.removeItem("sail_token");
  document.getElementById("chat-screen").classList.add("hidden");
  document.getElementById("login-screen").classList.remove("hidden");
}

window.addEventListener("DOMContentLoaded", async () => {
  if (authToken) {
    const res = await apiFetch("/api/me").catch(() => null);
    if (res && res.ok) {
      const data = await res.json();
      await enterChat(data.username);
    } else {
      sessionStorage.removeItem("sail_token");
      authToken = null;
    }
  }
  document.getElementById("login-pass").addEventListener("keydown", e => {
    if (e.key === "Enter") doLogin();
  });
});

async function doLogin() {
  const username = document.getElementById("login-user").value.trim().toLowerCase();
  const password = document.getElementById("login-pass").value;
  const errEl    = document.getElementById("login-error");
  errEl.classList.add("hidden");

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    errEl.textContent = "Incorrect username or password.";
    errEl.classList.remove("hidden");
    return;
  }
  const data = await res.json();
  authToken = data.token;
  sessionStorage.setItem("sail_token", authToken);
  await enterChat(data.username);
}

async function doLogout() {
  await apiFetch("/api/logout", { method: "POST" }).catch(() => {});
  resetToLogin();
}

async function enterChat(username) {
  currentUser = username;
  localMessages = loadStoredMessages(username);
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("chat-screen").classList.remove("hidden");
  document.getElementById("me-name").textContent = capitalize(username);
  document.getElementById("me-avatar").textContent = username[0].toUpperCase();

  await loadContacts();
  openWebSocket();
  await syncPendingMessages();
}

async function loadContacts() {
  const res = await apiFetch("/api/users");
  if (!res.ok) return;
  const { users } = await res.json();

  const prevRes = await apiFetch("/api/previews");
  const previews = prevRes.ok ? (await prevRes.json()).previews : {};

  const list = document.getElementById("contact-list");
  list.innerHTML = "";

  users.forEach(peer => {
    if (!localMessages[peer]) localMessages[peer] = [];
    const el = document.createElement("div");
    el.id = `contact-${peer}`;
    el.className = "flex items-center gap-3.5 px-4 py-3.5 cursor-pointer hover:bg-violet-100/50 transition duration-150";
    el.onclick = () => openConversation(peer);

    const prev = previews[peer];
    const prevText = prev ? prev.text : "🔒 Encrypted";
    const prevTs = prev ? formatTime(prev.ts) : "";
    const unread = unreadCounts[peer] || 0;

    el.innerHTML = `
      <div class="w-12 h-12 rounded-2xl bg-gradient-to-tr from-violet-600 via-purple-600 to-indigo-500 flex items-center justify-center text-white font-bold text-base uppercase shrink-0 shadow-md shadow-violet-500/20">
        ${peer[0]}
      </div>
      <div class="flex-1 min-w-0">
        <div class="flex justify-between items-center">
          <span class="font-bold text-sm text-slate-800 tracking-tight">${capitalize(peer)}</span>
          <span class="text-[10px] text-violet-500/80 font-medium contact-ts" id="ts-${peer}">${prevTs}</span>
        </div>
        <div class="flex justify-between items-center mt-1">
          <div class="text-xs text-violet-700/60 font-medium truncate contact-preview" id="preview-${peer}">${prevText.length > 32 ? escHtml(prevText.slice(0, 32)) + "…" : escHtml(prevText)}</div>
          <span id="badge-${peer}" class="${unread > 0 ? "" : "hidden"} ml-2 bg-gradient-to-r from-violet-600 to-purple-600 text-white text-[10px] font-bold px-2 py-0.5 rounded-full min-w-[20px] text-center shadow-sm shadow-violet-500/30">${unread}</span>
        </div>
      </div>
    `;
    list.appendChild(el);
  });
}

function updateContactPreview(peer, text, ts) {
  const previewEl = document.getElementById(`preview-${peer}`);
  const tsEl      = document.getElementById(`ts-${peer}`);
  if (previewEl) previewEl.textContent = text.length > 32 ? text.slice(0, 32) + "…" : text;
  if (tsEl) tsEl.textContent = formatTime(ts);
}

function updateUnreadBadge(peer) {
  const badgeEl = document.getElementById(`badge-${peer}`);
  if (!badgeEl) return;
  const count = unreadCounts[peer] || 0;
  if (count > 0) {
    badgeEl.textContent = count;
    badgeEl.classList.remove("hidden");
  } else {
    badgeEl.classList.add("hidden");
  }
}

async function openConversation(peer) {
  currentPeer = peer;
  unreadCounts[peer] = 0;
  updateUnreadBadge(peer);

  document.querySelectorAll("#contact-list > div").forEach(el => {
    el.classList.remove("bg-violet-100", "border-l-4", "border-violet-600");
  });
  const contactEl = document.getElementById(`contact-${peer}`);
  if (contactEl) contactEl.classList.add("bg-violet-100/70", "border-l-4", "border-violet-600");

  document.getElementById("empty-state").classList.add("hidden");
  document.getElementById("active-chat").classList.remove("hidden");
  document.getElementById("peer-name").textContent = capitalize(peer);
  document.getElementById("peer-avatar").textContent = peer[0].toUpperCase();

  try {
    const res = await apiFetch(`/api/history/${peer}`);
    if (res.ok) {
      const data = await res.json();
      localMessages[peer] = data.history || [];
      saveStoredMessages(currentUser, localMessages);
    }
  } catch (err) {
    console.warn("Could not fetch history from database, using cached:", err);
  }

  renderMessages(peer);
  document.getElementById("msg-input").focus();
}

function renderMessages(peer) {
  const container = document.getElementById("messages");
  container.innerHTML = "";

  (localMessages[peer] || []).forEach(msg => appendBubble(msg));
  container.scrollTop = container.scrollHeight;
}

function appendBubble(msg) {
  if (!currentPeer || msg.peer !== currentPeer) return;
  const container = document.getElementById("messages");
  const isMe = msg.sender === currentUser;

  const wrapper = document.createElement("div");
  wrapper.className = `flex ${isMe ? "justify-end" : "justify-start"} mb-1`;

  const bubble = document.createElement("div");
  bubble.className = `msg-bubble px-4 py-2.5 rounded-3xl text-sm leading-relaxed shadow-sm ${
    isMe
      ? "bg-gradient-to-r from-violet-600 via-purple-600 to-indigo-600 text-white rounded-tr-md shadow-violet-500/20"
      : "bg-white text-slate-800 rounded-tl-md border border-violet-100 shadow-violet-100/50"
  }`;

  bubble.innerHTML = `
    <div class="leading-relaxed font-normal">${escHtml(msg.text)}</div>
    <div class="flex items-center justify-end gap-1.5 mt-1">
      <span class="text-[10px] ${isMe ? "text-violet-200" : "text-violet-400"} font-medium">${formatTime(msg.ts)}</span>
      ${isMe ? statusIcon(msg.status) : ""}
    </div>
  `;

  wrapper.appendChild(bubble);
  container.appendChild(wrapper);
  container.scrollTop = container.scrollHeight;
}

function statusIcon(status) {
  if (status === "sending") {
    return `<svg class="w-3.5 h-3.5 text-violet-300" fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>`;
  }
  return `<svg class="w-4 h-4 text-violet-200" fill="currentColor" viewBox="0 0 24 24"><path d="M18 7l-1.41-1.42-6.34 6.34 1.41 1.41L18 7zm4.24-1.42L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.42zM.41 13.41L6 19l1.41-1.41L1.83 12 .41 13.41z"/></svg>`;
}

async function sendMessage() {
  const input = document.getElementById("msg-input");
  const text  = input.value.trim();
  if (!text || !currentPeer) return;

  input.value = "";
  input.style.height = "";

  const ts  = Date.now();
  const msg = { sender: currentUser, peer: currentPeer, text, ts, status: "sending" };
  if (!localMessages[currentPeer]) localMessages[currentPeer] = [];
  localMessages[currentPeer].push(msg);
  saveStoredMessages(currentUser, localMessages);
  appendBubble(msg);
  updateContactPreview(currentPeer, text, ts);

  try {
    const res = await apiFetch("/api/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ recipient: currentPeer, text })
    });
    if (res.ok) {
      msg.status = "sent";
      saveStoredMessages(currentUser, localMessages);
      renderMessages(currentPeer);
    }
  } catch (err) {
    console.error("Send error:", err);
  }
}

function openWebSocket() {
  if (socket) {
    socket.onclose = null;
    socket.close();
  }
  if (heartbeatId) clearInterval(heartbeatId);

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(`${proto}//${location.host}/ws?token=${encodeURIComponent(authToken || "")}`);

  socket.onopen = () => {
    heartbeatId = setInterval(() => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send("ping");
      }
    }, 25000);
  };

  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type !== "envelope") return;
    receiveQueue = receiveQueue
      .then(() => handleIncomingEnvelope(data.envelope))
      .catch(err => console.error("Incoming message queue error:", err));
  };

  socket.onclose = (ev) => {
    if (heartbeatId) clearInterval(heartbeatId);
    heartbeatId = null;
    if (ev.code === 4001) {
      resetToLogin();
      return;
    }
    setTimeout(() => { if (currentUser && authToken) openWebSocket(); }, 2000);
  };
}

async function syncPendingMessages() {
  try {
    const res = await apiFetch("/api/sync", { method: "POST" });
    if (!res.ok) return;
    const { messages } = await res.json();
    for (const m of (messages || [])) {
      deliverToUI(m.sender, m.text, m.ts);
    }
  } catch (e) {
    console.warn("Sync error:", e);
  }
}

async function handleIncomingEnvelope(envelope) {
  const res = await apiFetch("/api/receive", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(envelope)
  });
  if (!res.ok) {
    console.error("Failed to decrypt incoming message:", await res.text());
    return;
  }
  const { sender, text, ts } = await res.json();
  deliverToUI(sender, text, ts || Date.now());
}

function deliverToUI(sender, text, ts) {
  const msg = { sender, peer: sender, text, ts, status: "received" };
  if (!localMessages[sender]) localMessages[sender] = [];
  localMessages[sender].push(msg);
  saveStoredMessages(currentUser, localMessages);

  updateContactPreview(sender, text, ts);

  if (currentPeer === sender) {
    appendBubble(msg);
  } else {
    unreadCounts[sender] = (unreadCounts[sender] || 0) + 1;
    updateUnreadBadge(sender);
  }
}

async function showSafety() {
  if (!currentPeer) return;
  document.getElementById("safety-peer-label").textContent = capitalize(currentPeer);
  document.getElementById("safety-num").textContent = "Loading…";
  document.getElementById("safety-modal").classList.remove("hidden");

  const res = await apiFetch(`/api/safety-number/${currentPeer}`);
  if (res.ok) {
    const { safety_number } = await res.json();
    document.getElementById("safety-num").textContent = safety_number;
  } else {
    document.getElementById("safety-num").textContent = "Send a message first to establish a secure session.";
  }
}

function closeSafety() {
  document.getElementById("safety-modal").classList.add("hidden");
}

function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }
function escHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
          .replace(/"/g,"&quot;").replace(/\n/g,"<br>");
}
function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function autoResize(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 120) + "px";
}
function handleEnter(e) {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}
