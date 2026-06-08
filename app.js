/* ══════════════════════════════════════
   NARAX SECURITY TERMINAL — APP LOGIC
   ══════════════════════════════════════ */

'use strict';

/* ─────────────────────────────────────
   STATE
───────────────────────────────────── */
const state = {
  currentView: 'view-auth',
  isAdmin: false,
  currentUser: null,
  sessionId: null,
  loginTime: null,
  sessionDuration: 30 * 60,  // 30 min in seconds
  sessionRemaining: 30 * 60,
  inactivityLimit: 30 * 60,  // 30 min
  inactivityRemaining: 30 * 60,
  inactivityWarning: 60,      // warn at 60s remaining
  inactivityWarningActive: false,
  inactivityCountdownActive: false,
  otpTimer: 5 * 60,
  users: [
    { id: 'narax_admin', email: 'admin@narax.sec', role: 'ADMIN', status: 'ONLINE', joined: '2025-01-01' },
    { id: 'ghost_user1', email: 'ghost1@sec.io',   role: 'USER',  status: 'ONLINE', joined: '2025-03-14' },
    { id: 'cipher_02',   email: 'cipher@anon.net', role: 'USER',  status: 'OFFLINE',joined: '2025-04-22' },
    { id: 'void_walker', email: 'void@dark.web',   role: 'USER',  status: 'ONLINE', joined: '2025-05-10' },
  ],
  threats: { brute: 0, sql: 0, xss: 0, ddos: 0, port: 0 },
  sessionTimer: null,
  inactivityTimer: null,
  inactivityCountdownTimer: null,
  threatSimTimer: null,
  otpTimerInterval: null,
};

/* ─────────────────────────────────────
   INIT
───────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  resetInactivityTracking();
  document.addEventListener('mousemove', resetInactivityTracking);
  document.addEventListener('keydown',   resetInactivityTracking);
  document.addEventListener('click',     resetInactivityTracking);
  document.addEventListener('scroll',    resetInactivityTracking);
});

/* ─────────────────────────────────────
   PARTICLE SYSTEM
───────────────────────────────────── */
function initParticles() {
  const container = document.getElementById('particles');
  const count = 28;
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    const x = Math.random() * 100;
    const dur = 8 + Math.random() * 14;
    const delay = Math.random() * -20;
    const dx = (Math.random() - 0.5) * 80;
    const isP = Math.random() > 0.6;
    p.style.cssText = `
      left:${x}%;
      animation-duration:${dur}s;
      animation-delay:${delay}s;
      --dx:${dx}px;
      background:${isP ? 'var(--purple)' : 'var(--cyan)'};
      opacity:0.5;
    `;
    container.appendChild(p);
  }
}

/* ─────────────────────────────────────
   VIEW NAVIGATION
───────────────────────────────────── */
function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  state.currentView = id;
}

/* ─────────────────────────────────────
   TAB SWITCHING
───────────────────────────────────── */
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
  document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
  document.getElementById(`form-${tab}`).classList.add('active');
  const indicator = document.querySelector('.tab-indicator');
  indicator.classList.toggle('right', tab === 'register');
}

/* ─────────────────────────────────────
   ADMIN TOGGLE
───────────────────────────────────── */
function toggleAdminMode() {
  state.isAdmin = document.getElementById('adminToggle').checked;
  const badge = document.getElementById('adminBadge');
  badge.textContent = state.isAdmin ? 'ENABLED' : 'RESTRICTED';
  badge.classList.toggle('active', state.isAdmin);
}

/* ─────────────────────────────────────
   PASSWORD STRENGTH
───────────────────────────────────── */
function updateStrengthBar(value) {
  const checks = {
    len:   value.length >= 8,
    upper: /[A-Z]/.test(value),
    num:   /[0-9]/.test(value),
    sym:   /[^A-Za-z0-9]/.test(value),
  };
  let score = Object.values(checks).filter(Boolean).length;

  const fill  = document.getElementById('strengthFill');
  const label = document.getElementById('strengthLabel');

  const levels = [
    { w: '0%',   bg: 'transparent', txt: 'AWAITING INPUT' },
    { w: '25%',  bg: 'var(--red)',   txt: 'WEAK' },
    { w: '50%',  bg: 'var(--orange)',txt: 'FAIR' },
    { w: '75%',  bg: 'var(--cyan)',  txt: 'STRONG' },
    { w: '100%', bg: 'var(--green)', txt: 'FORTIFIED' },
  ];

  const lvl = value.length === 0 ? levels[0] : levels[score];
  fill.style.width      = lvl.w;
  fill.style.background = lvl.bg;
  label.textContent     = lvl.txt;

  const ids = ['chk-len','chk-upper','chk-num','chk-sym'];
  const keys = ['len','upper','num','sym'];
  const labels = ['8+ CHARS','UPPERCASE','NUMBER','SYMBOL'];
  ids.forEach((id, i) => {
    const el = document.getElementById(id);
    el.textContent = (checks[keys[i]] ? '✅' : '⬜') + ' ' + labels[i];
    el.classList.toggle('pass', checks[keys[i]]);
  });
}

/* ─────────────────────────────────────
   PASSWORD VISIBILITY TOGGLE
───────────────────────────────────── */
function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  btn.style.color = isHidden ? 'var(--cyan)' : 'var(--text-dim)';
}

/* ─────────────────────────────────────
   OTP NAVIGATION
───────────────────────────────────── */
function otpMove(input, idx) {
  const inputs = document.querySelectorAll('#otpGrid .otp-input');
  if (input.value && idx < inputs.length - 1) inputs[idx + 1].focus();
  input.value = input.value.replace(/\D/g, '');
}
function otpMove2fa(input, idx) {
  const inputs = document.querySelectorAll('#otpGrid2fa .otp-input');
  if (input.value && idx < inputs.length - 1) inputs[idx + 1].focus();
  input.value = input.value.replace(/\D/g, '');
}

/* ─────────────────────────────────────
   AUTH: LOGIN
───────────────────────────────────── */
function handleLogin(e) {
  e.preventDefault();
  const userId   = document.getElementById('login-userid').value.trim();
  const password = document.getElementById('login-password').value;

  if (!userId || !password) {
    showToast('ALL FIELDS REQUIRED', 'error'); return;
  }

  // Simulate auth — in production this hits your backend
  if (userId.length < 3) {
    showToast('INVALID USER ID', 'error'); return;
  }

  showToast('CREDENTIALS VERIFIED — INITIATING 2FA', 'info');
  setTimeout(() => {
    state.currentUser = userId;
    state.isAdmin = document.getElementById('adminToggle').checked;
    showView('view-2fa');
    start2FATimer();
  }, 900);
}

/* ─────────────────────────────────────
   AUTH: REGISTER
───────────────────────────────────── */
function handleRegister(e) {
  e.preventDefault();
  const userId   = document.getElementById('reg-userid').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const terms    = document.getElementById('termsCheck').checked;

  if (!userId || !email || !password) { showToast('ALL FIELDS REQUIRED', 'error'); return; }
  if (!terms) { showToast('ACCEPT SECURITY PROTOCOLS FIRST', 'error'); return; }
  if (password.length < 8) { showToast('KEY TOO SHORT — MIN 8 CHARS', 'error'); return; }

  // Simulate registration
  state.currentUser = userId;
  state.isAdmin = document.getElementById('adminToggle').checked;

  // Add to mock users list
  state.users.push({
    id: userId, email: email,
    role: state.isAdmin ? 'ADMIN' : 'USER',
    status: 'ONLINE',
    joined: new Date().toISOString().split('T')[0],
  });

  showToast('ACCOUNT INITIALIZED — VERIFY IDENTITY', 'success');
  setTimeout(() => {
    showView('view-2fa');
    start2FATimer();
  }, 900);
}

/* ─────────────────────────────────────
   AUTH: FORGOT
───────────────────────────────────── */
function handleForgot(e) {
  e.preventDefault();
  const email = document.getElementById('forgot-email').value.trim();
  if (!email) { showToast('ENTER REGISTERED EMAIL', 'error'); return; }
  showToast('RECOVERY CIPHER TRANSMITTED', 'success');
}

/* ─────────────────────────────────────
   2FA VERIFY
───────────────────────────────────── */
function verify2FA() {
  clearInterval(state.otpTimerInterval);
  showToast('IDENTITY CONFIRMED — ACCESS GRANTED', 'success');
  setTimeout(startSession, 800);
}

function start2FATimer() {
  state.otpTimer = 5 * 60;
  clearInterval(state.otpTimerInterval);
  state.otpTimerInterval = setInterval(() => {
    state.otpTimer--;
    const el = document.getElementById('otpCountdown');
    if (el) el.textContent = formatTime(state.otpTimer);
    if (state.otpTimer <= 0) {
      clearInterval(state.otpTimerInterval);
      showToast('OTP EXPIRED — REQUEST NEW CODE', 'error');
    }
  }, 1000);
}

/* ─────────────────────────────────────
   SESSION START / END
───────────────────────────────────── */
function startSession() {
  state.sessionId    = generateSessionId();
  state.loginTime    = new Date();
  state.sessionRemaining = state.sessionDuration;

  // Populate dashboard
  document.getElementById('dashUser').textContent      = state.currentUser;
  document.getElementById('dashSessionId').textContent = state.sessionId;
  document.getElementById('dashLoginTime').textContent = state.loginTime.toLocaleTimeString('en-US', { hour12: false });
  document.getElementById('dashAuthMode').textContent  = state.isAdmin ? 'ADMIN + 2FA' : 'USER + 2FA';
  document.getElementById('dashClearance').textContent = state.isAdmin ? 'LEVEL 5 — ALPHA' : 'LEVEL 2 — STANDARD';
  document.getElementById('dashContext').textContent   = state.isAdmin ? 'ADMIN TERMINAL' : 'USER TERMINAL';

  // Admin panel button
  const adminBtn = document.getElementById('adminPanelBtn');
  adminBtn.style.display = state.isAdmin ? 'inline-flex' : 'none';

  showView('view-dashboard');
  startSessionTimer();
  resetInactivityTracking();
  startThreatSimulation();
  populateAdminTable();
  showToast(`WELCOME, ${state.currentUser.toUpperCase()}`, 'success');
}

function handleLogout() {
  clearAllTimers();
  state.currentUser = null;
  state.sessionId   = null;
  state.loginTime   = null;
  state.isAdmin     = false;
  document.getElementById('adminToggle').checked = false;
  toggleAdminMode();
  clearThreatLog();
  showToast('SESSION TERMINATED — CHANNEL CLOSED', 'info');
  setTimeout(() => showView('view-auth'), 500);
}

function clearAllTimers() {
  clearInterval(state.sessionTimer);
  clearInterval(state.inactivityTimer);
  clearInterval(state.inactivityCountdownTimer);
  clearInterval(state.threatSimTimer);
  clearInterval(state.otpTimerInterval);
}

/* ─────────────────────────────────────
   SESSION EXPIRY TIMER
───────────────────────────────────── */
function startSessionTimer() {
  const total = state.sessionDuration;
  clearInterval(state.sessionTimer);

  state.sessionTimer = setInterval(() => {
    state.sessionRemaining--;
    const remaining = state.sessionRemaining;
    const pct = remaining / total;
    const dashOffset = 326.7 * (1 - pct);

    document.getElementById('expiryCountdown').textContent = formatTime(remaining);
    document.getElementById('expiryRingProgress').style.strokeDashoffset = dashOffset;
    document.getElementById('expiryFill').style.width = (pct * 100) + '%';

    // Color shift as time decreases
    const ring = document.getElementById('expiryRingProgress');
    if (pct < 0.25)       ring.style.stroke = 'var(--red)';
    else if (pct < 0.5)   ring.style.stroke = 'var(--orange)';
    else                  ring.style.stroke = 'var(--cyan)';

    if (remaining <= 0) {
      clearInterval(state.sessionTimer);
      showToast('SESSION EXPIRED — LOGGING OUT', 'error');
      setTimeout(handleLogout, 1500);
    }
  }, 1000);
}

/* ─────────────────────────────────────
   INACTIVITY TRACKING
───────────────────────────────────── */
function resetInactivityTracking() {
  state.inactivityRemaining = state.inactivityLimit;
  state.inactivityWarningActive = false;

  // Hide warning overlay if visible
  const overlay = document.getElementById('inactivityOverlay');
  overlay.classList.add('hidden');

  clearInterval(state.inactivityTimer);
  clearInterval(state.inactivityCountdownTimer);

  state.inactivityTimer = setInterval(() => {
    state.inactivityRemaining--;

    if (state.inactivityRemaining <= 0) {
      clearInterval(state.inactivityTimer);
      if (state.currentView === 'view-dashboard' || state.currentView === 'view-admin') {
        showToast('INACTIVITY TIMEOUT — SESSION TERMINATED', 'error');
        setTimeout(handleLogout, 1200);
      }
    }

    if (state.inactivityRemaining === state.inactivityWarning && !state.inactivityWarningActive) {
      if (state.currentView === 'view-dashboard' || state.currentView === 'view-admin') {
        state.inactivityWarningActive = true;
        showInactivityWarning();
      }
    }
  }, 1000);
}

function showInactivityWarning() {
  const overlay = document.getElementById('inactivityOverlay');
  overlay.classList.remove('hidden');
  let count = state.inactivityWarning;

  clearInterval(state.inactivityCountdownTimer);
  state.inactivityCountdownTimer = setInterval(() => {
    count--;
    const el = document.getElementById('inactivityCountdown');
    if (el) el.textContent = count;
    if (count <= 0) clearInterval(state.inactivityCountdownTimer);
  }, 1000);
}

function resetInactivity() {
  resetInactivityTracking();
}

/* ─────────────────────────────────────
   THREAT SIMULATION
───────────────────────────────────── */
const threatTypes = [
  { key: 'brute', label: 'BRUTE FORCE',   fillId: 'tf-brute', countId: 'tc-brute', cls: 'green'  },
  { key: 'sql',   label: 'SQL INJECTION',  fillId: 'tf-sql',   countId: 'tc-sql',   cls: 'cyan'   },
  { key: 'xss',   label: 'XSS ATTACK',     fillId: 'tf-xss',   countId: 'tc-xss',   cls: 'purple' },
  { key: 'ddos',  label: 'DDOS TRAFFIC',   fillId: 'tf-ddos',  countId: 'tc-ddos',  cls: 'orange' },
  { key: 'port',  label: 'PORT SCAN',      fillId: 'tf-port',  countId: 'tc-port',  cls: 'purple' },
];

function startThreatSimulation() {
  clearInterval(state.threatSimTimer);
  state.threatSimTimer = setInterval(() => {
    const t = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    const inc = Math.floor(Math.random() * 5) + 1;
    state.threats[t.key] += inc;

    const total = Object.values(state.threats).reduce((a, b) => a + b, 0);
    const max   = Math.max(...Object.values(state.threats), 1);

    threatTypes.forEach(tt => {
      const pct = Math.min((state.threats[tt.key] / max) * 100, 100);
      const fill = document.getElementById(tt.fillId);
      const cnt  = document.getElementById(tt.countId);
      if (fill) fill.style.width = pct + '%';
      if (cnt)  cnt.textContent  = state.threats[tt.key] + ' BLOCKED';
    });

    const totalEl = document.getElementById('threatsTotal');
    if (totalEl) totalEl.textContent = total;

    addThreatLogEntry(`[${timestamp()}] BLOCKED: ${t.label} — SOURCE 192.168.${rndByte()}.${rndByte()}`);
  }, 1800 + Math.random() * 2200);
}

function addThreatLogEntry(msg) {
  const log = document.getElementById('threatLog');
  if (!log) return;
  const entry = document.createElement('div');
  entry.className = 'log-entry blocked';
  entry.textContent = msg;
  log.insertBefore(entry, log.firstChild);
  if (log.children.length > 20) log.removeChild(log.lastChild);
}

function clearThreatLog() {
  const log = document.getElementById('threatLog');
  if (log) log.innerHTML = '';
  state.threats = { brute: 0, sql: 0, xss: 0, ddos: 0, port: 0 };
}

/* ─────────────────────────────────────
   ADMIN TABLE
───────────────────────────────────── */
function populateAdminTable() {
  const tbody = document.getElementById('userTableBody');
  if (!tbody) return;
  renderTable();
}

function renderTable() {
  const tbody = document.getElementById('userTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  state.users.forEach((user, idx) => {
    const tr = document.createElement('tr');
    const isCurrentUser = user.id === state.currentUser;
    tr.innerHTML = `
      <td style="color:var(--cyan);font-family:var(--font-mono)">${user.id}${isCurrentUser ? ' <span style="color:var(--green);font-size:0.55rem">[YOU]</span>' : ''}</td>
      <td>${user.email}</td>
      <td><span class="badge ${user.role === 'ADMIN' ? 'admin' : 'user'}">${user.role}</span></td>
      <td><span class="badge ${user.status === 'ONLINE' ? 'online' : 'offline'}">${user.status}</span></td>
      <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-dim)">${user.joined}</td>
      <td>
        <div class="action-btns">
          ${user.role !== 'ADMIN' ? `<button class="action-btn promote" onclick="promoteUser(${idx})">MAKE ADMIN</button>` : ''}
          ${user.role === 'ADMIN' && !isCurrentUser ? `<button class="action-btn demote" onclick="demoteUser(${idx})">REMOVE ADMIN</button>` : ''}
          ${!isCurrentUser ? `<button class="action-btn delete" onclick="deleteUser(${idx})">DELETE</button>` : ''}
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  // Update stats
  document.getElementById('statTotal').textContent  = state.users.length;
  document.getElementById('statAdmins').textContent = state.users.filter(u => u.role === 'ADMIN').length;
  document.getElementById('statActive').textContent = state.users.filter(u => u.status === 'ONLINE').length;
}

function promoteUser(idx) {
  state.users[idx].role = 'ADMIN';
  renderTable();
  showToast(`${state.users[idx].id} PROMOTED TO ADMIN`, 'success');
}
function demoteUser(idx) {
  state.users[idx].role = 'USER';
  renderTable();
  showToast(`${state.users[idx].id} CLEARANCE REVOKED`, 'info');
}
function deleteUser(idx) {
  const id = state.users[idx].id;
  state.users.splice(idx, 1);
  renderTable();
  showToast(`USER ${id} DELETED FROM REGISTRY`, 'error');
}

/* ─────────────────────────────────────
   AVATAR UPLOAD
───────────────────────────────────── */
function handleAvatarUpload(input) {
  if (!input.files || !input.files[0]) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = document.getElementById('avatarImg');
    const placeholder = document.getElementById('avatarPlaceholder');
    img.src = e.target.result;
    img.style.display = 'block';
    placeholder.style.display = 'none';
    showToast('OPERATOR PHOTO UPDATED', 'success');
  };
  reader.readAsDataURL(input.files[0]);
}

/* ─────────────────────────────────────
   TOAST SYSTEM
───────────────────────────────────── */
let toastTimer = null;
function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.className = `toast ${type}`;
  requestAnimationFrame(() => {
    toast.classList.add('show');
  });
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3500);
}

/* ─────────────────────────────────────
   UTILITIES
───────────────────────────────────── */
function generateSessionId() {
  return Array.from({length: 4}, () =>
    Math.random().toString(16).slice(2, 6).toUpperCase()
  ).join('-');
}

function formatTime(secs) {
  const m = String(Math.floor(Math.max(secs, 0) / 60)).padStart(2, '0');
  const s = String(Math.max(secs, 0) % 60).padStart(2, '0');
  return `${m}:${s}`;
}

function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function rndByte() {
  return Math.floor(Math.random() * 254) + 1;
}

/* ─────────────────────────────────────
   KEYBOARD: OTP BACKSPACE SUPPORT
───────────────────────────────────── */
document.addEventListener('keydown', (e) => {
  if (e.key === 'Backspace') {
    const active = document.activeElement;
    if (active && active.classList.contains('otp-input')) {
      if (!active.value) {
        const grid = active.closest('.otp-grid');
        if (grid) {
          const inputs = grid.querySelectorAll('.otp-input');
          const idx = Array.from(inputs).indexOf(active);
          if (idx > 0) inputs[idx - 1].focus();
        }
      }
    }
  }
});
