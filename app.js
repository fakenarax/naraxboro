/* ══════════════════════════════════════
   NARAX SECURITY TERMINAL — APP LOGIC
   API-Connected Version
   ══════════════════════════════════════ */

'use strict';

/* ─────────────────────────────────────
   API CONFIG
───────────────────────────────────── */
const API_BASE = 'https://naraxboro.onrender.com';  // Render backend

async function apiFetch(endpoint, options = {}) {
  const token = state.token;
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(API_BASE + endpoint, {
    ...options,
    headers,
  });

  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}

/* ─────────────────────────────────────
   STATE
───────────────────────────────────── */
const state = {
  currentView:              'view-auth',
  isAdmin:                  false,
  currentUser:              null,
  token:                    null,        // JWT — kept in memory only (never localStorage)
  sessionId:                null,
  loginTime:                null,
  sessionDuration:          30 * 60,    // 30 min in seconds (mirrors backend)
  sessionRemaining:         30 * 60,
  inactivityLimit:          30 * 60,
  inactivityRemaining:      30 * 60,
  inactivityWarning:        60,
  inactivityWarningActive:  false,
  inactivityCountdownActive:false,
  otpTimer:                 5 * 60,
  pendingUserId:            null,        // userId waiting for OTP verify
  pendingPurpose:           null,        // 'login' | 'register' | 'reset'
  pendingResetEmail:        null,        // email waiting for reset OTP
  users:                    [],          // populated from /api/admin/users
  threats:                  { brute: 0, sql: 0, xss: 0, ddos: 0, port: 0 },
  sessionTimer:             null,
  inactivityTimer:          null,
  inactivityCountdownTimer: null,
  threatSimTimer:           null,
  otpTimerInterval:         null,
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
    const p     = document.createElement('div');
    p.className = 'particle';
    const x     = Math.random() * 100;
    const dur   = 8 + Math.random() * 14;
    const delay = Math.random() * -20;
    const dx    = (Math.random() - 0.5) * 80;
    const isP   = Math.random() > 0.6;
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
  // This toggle is purely visual — admin access is granted by server role only
  const toggle = document.getElementById('adminToggle');
  const badge   = document.getElementById('adminBadge');
  if (toggle.checked) {
    badge.textContent = 'ENABLED';
    badge.classList.add('active');
    showToast('ADMIN CREDENTIALS REQUIRED — ENTER ADMIN USER ID & PASSWORD', 'info');
  } else {
    badge.textContent = 'RESTRICTED';
    badge.classList.remove('active');
  }
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
    { w: '0%',   bg: 'transparent',   txt: 'AWAITING INPUT' },
    { w: '25%',  bg: 'var(--red)',     txt: 'WEAK'          },
    { w: '50%',  bg: 'var(--orange)',  txt: 'FAIR'          },
    { w: '75%',  bg: 'var(--cyan)',    txt: 'STRONG'        },
    { w: '100%', bg: 'var(--green)',   txt: 'FORTIFIED'     },
  ];

  const lvl = value.length === 0 ? levels[0] : levels[score];
  fill.style.width      = lvl.w;
  fill.style.background = lvl.bg;
  label.textContent     = lvl.txt;

  const ids    = ['chk-len','chk-upper','chk-num','chk-sym'];
  const keys   = ['len','upper','num','sym'];
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
  const input  = document.getElementById(inputId);
  const isHidden = input.type === 'password';
  input.type   = isHidden ? 'text' : 'password';
  btn.style.color = isHidden ? 'var(--cyan)' : 'var(--text-dim)';
}

/* ─────────────────────────────────────
   OTP INPUT NAVIGATION
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
   HELPERS: read OTP grids
───────────────────────────────────── */
function readOtpGrid(gridId) {
  return Array.from(document.querySelectorAll(`#${gridId} .otp-input`))
    .map(i => i.value.trim())
    .join('');
}

function clearOtpGrid(gridId) {
  document.querySelectorAll(`#${gridId} .otp-input`).forEach(i => i.value = '');
  const first = document.querySelector(`#${gridId} .otp-input`);
  if (first) first.focus();
}

/* ─────────────────────────────────────
   AUTH: LOGIN  →  POST /api/auth/login
───────────────────────────────────── */
async function handleLogin(e) {
  e.preventDefault();
  const userId   = document.getElementById('login-userid').value.trim();
  const password = document.getElementById('login-password').value;

  if (!userId || !password) { showToast('ALL FIELDS REQUIRED', 'error'); return; }

  setFormLoading('form-login', true);
  showToast('AUTHENTICATING…', 'info');

  try {
    const { ok, data } = await apiFetch('/api/auth/login', {
      method: 'POST',
      body:   JSON.stringify({ userId, password }),
    });

    if (!ok) {
      showToast(data.message || 'AUTHENTICATION FAILED', 'error');
      return;
    }

    // Direct login — go straight to dashboard
    state.token   = data.token;
    const info    = data.sessionInfo;
    state.isAdmin = info.role === 'ADMIN';

    showToast('ACCESS GRANTED', 'success');
    setTimeout(() => startSession(info), 800);

  } catch {
    showToast('CONNECTION ERROR — CHECK SERVER', 'error');
  } finally {
    setFormLoading('form-login', false);
  }
}

/* ─────────────────────────────────────
   AUTH: REGISTER  →  POST /api/auth/register
───────────────────────────────────── */
async function handleRegister(e) {
  e.preventDefault();
  const userId   = document.getElementById('reg-userid').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const terms    = document.getElementById('termsCheck').checked;

  if (!userId || !email || !password) { showToast('ALL FIELDS REQUIRED', 'error'); return; }
  if (!terms)    { showToast('ACCEPT SECURITY PROTOCOLS FIRST', 'error'); return; }
  if (password.length < 8) { showToast('KEY TOO SHORT — MIN 8 CHARS', 'error'); return; }

  setFormLoading('form-register', true);
  showToast('INITIALIZING ACCOUNT…', 'info');

  try {
    const { ok, data } = await apiFetch('/api/auth/register', {
      method: 'POST',
      body:   JSON.stringify({ userId, email, password }),
    });

    if (!ok) {
      showToast(data.message || 'REGISTRATION FAILED', 'error');
      return;
    }

    showToast('ACCOUNT CREATED — PLEASE LOG IN', 'success');
    setTimeout(() => switchTab('login'), 900);

  } catch {
    showToast('CONNECTION ERROR — CHECK SERVER', 'error');
  } finally {
    setFormLoading('form-register', false);
  }
}

/* ─────────────────────────────────────
   AUTH: FORGOT  →  POST /api/auth/forgot-password
───────────────────────────────────── */
async function handleForgot(e) {
  e.preventDefault();
  const email = document.getElementById('forgot-email').value.trim();
  if (!email) { showToast('ENTER REGISTERED EMAIL', 'error'); return; }

  setFormLoading('form-forgot', true);
  showToast('TRANSMITTING RECOVERY LINK…', 'info');

  try {
    const { data } = await apiFetch('/api/auth/forgot-password', {
      method: 'POST',
      body:   JSON.stringify({ email }),
    });

    showToast(data.message || 'RECOVERY LINK TRANSMITTED', 'success');
    document.getElementById('forgot-email').value = '';
    const msg = document.getElementById('forgot-sent-msg');
    if (msg) msg.style.display = 'block';

  } catch {
    showToast('CONNECTION ERROR — CHECK SERVER', 'error');
  } finally {
    setFormLoading('form-forgot', false);
  }
}

/* ─────────────────────────────────────
   2FA: VERIFY OTP  →  POST /api/auth/verify-otp
         Also handles password reset OTP flow
───────────────────────────────────── */
async function verify2FA() {
  const otp = readOtpGrid('otpGrid') || readOtpGrid('otpGrid2fa');

  if (!otp || otp.length !== 6) {
    showToast('ENTER 6-DIGIT OTP', 'error'); return;
  }

  // ── Password reset branch ────────────────────────
  if (state.pendingPurpose === 'reset') {
    showView('view-reset-password');
    // Store OTP for the reset-password call
    state._resetOtp = otp;
    return;
  }

  // ── Login / Register branch ──────────────────────
  if (!state.pendingUserId) {
    showToast('SESSION LOST — PLEASE LOG IN AGAIN', 'error');
    showView('view-auth');
    return;
  }

  showToast('VERIFYING IDENTITY…', 'info');

  try {
    const { ok, data } = await apiFetch('/api/auth/verify-otp', {
      method: 'POST',
      body:   JSON.stringify({ userId: state.pendingUserId, otp }),
    });

    if (!ok) {
      showToast(data.message || 'INVALID OTP', 'error');
      clearOtpGrid('otpGrid');
      clearOtpGrid('otpGrid2fa');
      return;
    }

    clearInterval(state.otpTimerInterval);

    // Store token in memory
    state.token     = data.token;
    const info      = data.sessionInfo;
    state.isAdmin   = info.role === 'ADMIN';

    showToast('IDENTITY CONFIRMED — ACCESS GRANTED', 'success');
    setTimeout(() => startSession(info), 800);

  } catch {
    showToast('CONNECTION ERROR — CHECK SERVER', 'error');
  }
}

/* ─────────────────────────────────────
   RESET PASSWORD  →  POST /api/auth/reset-password
───────────────────────────────────── */
async function handleResetPassword(e) {
  e.preventDefault();
  const newPassword = document.getElementById('reset-password').value;
  const confirm     = document.getElementById('reset-confirm').value;

  if (!newPassword || !confirm)         { showToast('ALL FIELDS REQUIRED', 'error'); return; }
  if (newPassword !== confirm)          { showToast('PASSWORDS DO NOT MATCH', 'error'); return; }
  if (newPassword.length < 8)           { showToast('PASSWORD MINIMUM 8 CHARACTERS', 'error'); return; }
  if (!state.pendingResetEmail || !state._resetOtp) {
    showToast('SESSION EXPIRED — START OVER', 'error');
    showView('view-auth');
    return;
  }

  setFormLoading('form-reset', true);
  showToast('UPDATING CREDENTIALS…', 'info');

  try {
    const { ok, data } = await apiFetch('/api/auth/reset-password', {
      method: 'POST',
      body:   JSON.stringify({
        email:       state.pendingResetEmail,
        otp:         state._resetOtp,
        newPassword,
      }),
    });

    if (!ok) {
      showToast(data.message || 'RESET FAILED', 'error');
      return;
    }

    showToast('PASSWORD UPDATED — PLEASE LOG IN', 'success');
    state.pendingResetEmail = null;
    state._resetOtp         = null;
    state.pendingPurpose    = null;
    setTimeout(() => showView('view-auth'), 1200);

  } catch {
    showToast('CONNECTION ERROR — CHECK SERVER', 'error');
  } finally {
    setFormLoading('form-reset', false);
  }
}

/* ─────────────────────────────────────
   2FA TIMER
───────────────────────────────────── */
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
   SESSION START  (called after verify-otp)
───────────────────────────────────── */
function startSession(info) {
  // info = sessionInfo from /api/auth/verify-otp
  state.currentUser     = info.userId;
  state.sessionId       = info.sessionId;
  state.loginTime       = new Date(info.loginTime);
  state.isAdmin         = info.role === 'ADMIN';
  state.sessionRemaining= state.sessionDuration;
  state.pendingUserId   = null;
  state.pendingPurpose  = null;

  // Populate dashboard fields
  document.getElementById('dashUser').textContent      = info.userId;
  document.getElementById('dashEmail').textContent     = info.email || state.pendingEmail || '—';
  document.getElementById('dashSessionId').textContent = info.sessionId;
  document.getElementById('dashLoginTime').textContent = state.loginTime.toLocaleTimeString('en-US', { hour12: false });
  document.getElementById('dashAuthMode').textContent  = info.authMode   || (state.isAdmin ? 'ADMIN' : 'USER');
  document.getElementById('dashClearance').textContent = info.clearance  || (state.isAdmin ? 'LEVEL 5 — ALPHA' : 'LEVEL 2 — STANDARD');
  document.getElementById('dashContext').textContent   = state.isAdmin   ? 'ADMIN TERMINAL' : 'USER TERMINAL';

  // Show admin panel button only for admins
  const adminBtn = document.getElementById('adminPanelBtn');
  if (adminBtn) adminBtn.style.display = state.isAdmin ? 'inline-flex' : 'none';

  showView('view-dashboard');
  startSessionTimer();
  resetInactivityTracking();
  startThreatSimulation();
  showToast(`WELCOME, ${info.userId.toUpperCase()}`, 'success');
  loadAvatarLocally();

  // Load avatar from MongoDB (works across devices)
  apiFetch('/api/profile').then(({ ok, data }) => {
    console.log('PROFILE FETCH:', ok, JSON.stringify(data));
    if (ok && data.profile && data.profile.avatar) {
      const img = document.getElementById('avatarImg');
      const placeholder = document.getElementById('avatarPlaceholder');
      if (img) { img.src = data.profile.avatar; img.style.display = 'block'; }
      if (placeholder) placeholder.style.display = 'none';
      saveAvatarLocally(data.profile.avatar);
    }
  }).catch(err => console.error('PROFILE FETCH ERROR:', err));

  // Pre-fetch admin data in background if admin
  if (state.isAdmin) fetchAdminUsers();
}

/* ─────────────────────────────────────
   AVATAR — persist in localStorage
───────────────────────────────────── */
function saveAvatarLocally(base64) {
  try { localStorage.setItem('narax_avatar_' + state.currentUser, base64); } catch {}
}

function loadAvatarLocally() {
  try {
    const saved = localStorage.getItem('narax_avatar_' + state.currentUser);
    if (saved) {
      const img = document.getElementById('avatarImg');
      const placeholder = document.getElementById('avatarPlaceholder');
      if (img) { img.src = saved; img.style.display = 'block'; }
      if (placeholder) placeholder.style.display = 'none';
    }
  } catch {}
}

/* ─────────────────────────────────────
   LOGOUT  →  POST /api/auth/logout
───────────────────────────────────── */
async function handleLogout() {
  // Best-effort server-side logout — don't block UI on failure
  if (state.token) {
    apiFetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
  }

  clearAllTimers();
  state.token       = null;
  state.currentUser = null;
  state.sessionId   = null;
  state.loginTime   = null;
  state.isAdmin     = false;
  state.users       = [];

  document.getElementById('adminToggle').checked = false;
  toggleAdminMode();
  clearThreatLog();
  clearOtpGrid('otpGrid');
  clearOtpGrid('otpGrid2fa');

  showToast('SESSION TERMINATED — CHANNEL CLOSED', 'info');
  setTimeout(() => showView('view-auth'), 500);
}

/* ─────────────────────────────────────
   SESSION EXPIRY TIMER
───────────────────────────────────── */
function startSessionTimer() {
  const total = state.sessionDuration;
  clearInterval(state.sessionTimer);

  state.sessionTimer = setInterval(() => {
    state.sessionRemaining--;
    const remaining  = state.sessionRemaining;
    const pct        = remaining / total;
    const dashOffset = 326.7 * (1 - pct);

    document.getElementById('expiryCountdown').textContent = formatTime(remaining);
    document.getElementById('expiryRingProgress').style.strokeDashoffset = dashOffset;
    document.getElementById('expiryFill').style.width = (pct * 100) + '%';

    const ring = document.getElementById('expiryRingProgress');
    if (pct < 0.25)     ring.style.stroke = 'var(--red)';
    else if (pct < 0.5) ring.style.stroke = 'var(--orange)';
    else                ring.style.stroke = 'var(--cyan)';

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
  state.inactivityRemaining    = state.inactivityLimit;
  state.inactivityWarningActive= false;

  const overlay = document.getElementById('inactivityOverlay');
  if (overlay) overlay.classList.add('hidden');

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
  if (overlay) overlay.classList.remove('hidden');
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

function confirmDeleteAccount() {
  const modal = document.getElementById('deleteModal');
  modal.style.display = 'flex';
}

function closeDeleteModal() {
  const modal = document.getElementById('deleteModal');
  modal.style.animation = 'none';
  modal.style.opacity = '0';
  modal.style.transition = 'opacity 0.2s ease';
  setTimeout(() => {
    modal.style.display = 'none';
    modal.style.opacity = '';
    modal.style.transition = '';
  }, 200);
}

async function executeDeleteAccount() {
  closeDeleteModal();
  if (state.token) {
    apiFetch('/api/auth/delete-account', { method: 'DELETE' }).catch(() => {});
  }
  clearAllTimers();
  state.token = null;
  state.currentUser = null;
  state.sessionId = null;
  state.loginTime = null;
  state.isAdmin = false;
  showToast('ACCOUNT DELETED — ACCESS REVOKED', 'error');
  setTimeout(() => showView('view-auth'), 900);
}

/* ─────────────────────────────────────
   THREAT SIMULATION
───────────────────────────────────── */
const threatTypes = [
  { key: 'brute', label: 'BRUTE FORCE',  fillId: 'tf-brute', countId: 'tc-brute', cls: 'green'  },
  { key: 'sql',   label: 'SQL INJECTION', fillId: 'tf-sql',   countId: 'tc-sql',   cls: 'cyan'   },
  { key: 'xss',   label: 'XSS ATTACK',   fillId: 'tf-xss',   countId: 'tc-xss',   cls: 'purple' },
  { key: 'ddos',  label: 'DDOS TRAFFIC', fillId: 'tf-ddos',  countId: 'tc-ddos',  cls: 'orange' },
  { key: 'port',  label: 'PORT SCAN',    fillId: 'tf-port',  countId: 'tc-port',  cls: 'purple' },
];

function startThreatSimulation() {
  clearInterval(state.threatSimTimer);
  state.threatSimTimer = setInterval(() => {
    const t   = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    const inc = Math.floor(Math.random() * 5) + 1;
    state.threats[t.key] += inc;

    const max = Math.max(...Object.values(state.threats), 1);
    const total = Object.values(state.threats).reduce((a, b) => a + b, 0);

    threatTypes.forEach(tt => {
      const pct  = Math.min((state.threats[tt.key] / max) * 100, 100);
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
   ADMIN: FETCH USERS  →  GET /api/admin/users
───────────────────────────────────── */
async function fetchAdminUsers() {
  try {
    const { ok, data } = await apiFetch('/api/admin/users');
    if (ok && data.users) {
      state.users = data.users;
      renderTable();
    }
  } catch {
    // Silently fail — table will show empty
  }
}

/* ─────────────────────────────────────
   ADMIN TABLE
───────────────────────────────────── */
function populateAdminTable() {
  // If we already have users in state, render immediately
  if (state.users.length > 0) {
    renderTable();
  } else if (state.isAdmin) {
    fetchAdminUsers();
  }
}

function renderTable() {
  const tbody = document.getElementById('userTableBody');
  if (!tbody) return;
  tbody.innerHTML = '';

  state.users.forEach((user) => {
    const tr = document.createElement('tr');
    const isCurrentUser = user.id === state.currentUser;
    tr.innerHTML = `
      <td style="color:var(--cyan);font-family:var(--font-mono)">${user.id === 'narax_admin' ? '♛ ' : ''}${user.id}${isCurrentUser ? ' <span style="color:var(--green);font-size:0.55rem">[YOU]</span>' : ''}</td>
      <td>${user.email}</td>
      <td><span class="badge ${user.role === 'ADMIN' ? 'admin' : 'user'}">${user.role}</span></td>
      <td><span class="badge ${user.status === 'ONLINE' ? 'online' : 'offline'}">${user.status}</span></td>
      <td style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-dim)">${user.joined || ''}</td>
      <td>
        <div class="action-btns">
          ${user.role !== 'ADMIN' ? `<button class="action-btn promote" onclick="promoteUser('${user.id}')">MAKE ADMIN</button>` : ''}
          ${user.role === 'ADMIN' && !isCurrentUser && user.id !== 'narax_admin' ? `<button class="action-btn demote" onclick="demoteUser('${user.id}')">REMOVE ADMIN</button>` : ''}
          ${!isCurrentUser ? `<button class="action-btn delete" onclick="deleteUser('${user.id}')">DELETE</button>` : ''}
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });

  document.getElementById('statTotal').textContent  = state.users.length;
  document.getElementById('statAdmins').textContent = state.users.filter(u => u.role === 'ADMIN').length;
  document.getElementById('statActive').textContent = state.users.filter(u => u.status === 'ONLINE').length;
}

/* ─────────────────────────────────────
   ADMIN: PROMOTE  →  PATCH /api/admin/users/:id/role
───────────────────────────────────── */
async function promoteUser(userId) {
  try {
    const { ok, data } = await apiFetch(`/api/admin/users/${userId}/role`, {
      method: 'PATCH',
      body:   JSON.stringify({ role: 'ADMIN' }),
    });
    if (ok) {
      showToast(data.message || `${userId} PROMOTED TO ADMIN`, 'success');
      await fetchAdminUsers();
    } else {
      showToast(data.message || 'OPERATION FAILED', 'error');
    }
  } catch {
    showToast('CONNECTION ERROR', 'error');
  }
}

/* ─────────────────────────────────────
   ADMIN: DEMOTE  →  PATCH /api/admin/users/:id/role
───────────────────────────────────── */
async function demoteUser(userId) {
  try {
    const { ok, data } = await apiFetch(`/api/admin/users/${userId}/role`, {
      method: 'PATCH',
      body:   JSON.stringify({ role: 'USER' }),
    });
    if (ok) {
      showToast(data.message || `${userId} CLEARANCE REVOKED`, 'info');
      await fetchAdminUsers();
    } else {
      showToast(data.message || 'OPERATION FAILED', 'error');
    }
  } catch {
    showToast('CONNECTION ERROR', 'error');
  }
}

/* ─────────────────────────────────────
   ADMIN: DELETE  →  DELETE /api/admin/users/:id
───────────────────────────────────── */
async function deleteUser(userId) {
  try {
    const { ok, data } = await apiFetch(`/api/admin/users/${userId}`, {
      method: 'DELETE',
    });
    if (ok) {
      showToast(data.message || `USER ${userId} DELETED`, 'error');
      await fetchAdminUsers();
    } else {
      showToast(data.message || 'OPERATION FAILED', 'error');
    }
  } catch {
    showToast('CONNECTION ERROR', 'error');
  }
}

/* ─────────────────────────────────────
   AVATAR UPLOAD  →  POST /api/profile/avatar-base64
───────────────────────────────────── */
function handleAvatarUpload(input) {
  if (!input.files || !input.files[0]) return;
  const reader = new FileReader();

  reader.onload = async (e) => {
    const base64 = e.target.result;

    // Optimistic UI update first
    const img         = document.getElementById('avatarImg');
    const placeholder = document.getElementById('avatarPlaceholder');
    if (img) { img.src = base64; img.style.display = 'block'; }
    if (placeholder) placeholder.style.display = 'none';

    // Persist to backend
    try {
      const { ok, data } = await apiFetch('/api/profile/avatar-base64', {
        method: 'POST',
        body:   JSON.stringify({ base64 }),
      });
      if (ok) saveAvatarLocally(base64);
      showToast(ok ? 'OPERATOR PHOTO UPDATED' : (data.message || 'UPLOAD FAILED'), ok ? 'success' : 'error');
    } catch {
      showToast('CONNECTION ERROR — PHOTO SAVED LOCALLY ONLY', 'error');
    }
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
  toast.className   = `toast ${type}`;
  requestAnimationFrame(() => toast.classList.add('show'));
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3500);
}

/* ─────────────────────────────────────
   FORM LOADING STATE
───────────────────────────────────── */
function setFormLoading(formId, loading) {
  const form = document.getElementById(formId);
  if (!form) return;
  const btn = form.querySelector('button[type="submit"], .auth-btn');
  if (!btn) return;
  btn.disabled    = loading;
  btn.style.opacity = loading ? '0.6' : '1';
}

/* ─────────────────────────────────────
   CLEAR ALL TIMERS
───────────────────────────────────── */
function clearAllTimers() {
  clearInterval(state.sessionTimer);
  clearInterval(state.inactivityTimer);
  clearInterval(state.inactivityCountdownTimer);
  clearInterval(state.threatSimTimer);
  clearInterval(state.otpTimerInterval);
}

/* ─────────────────────────────────────
   UTILITIES
───────────────────────────────────── */
function generateSessionId() {
  return Array.from({ length: 4 }, () =>
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
        const grid   = active.closest('.otp-grid');
        if (grid) {
          const inputs = grid.querySelectorAll('.otp-input');
          const idx    = Array.from(inputs).indexOf(active);
          if (idx > 0) inputs[idx - 1].focus();
        }
      }
    }
  }
});