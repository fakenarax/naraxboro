/* ══════════════════════════════════════════════════════════════
   NARAX SECURITY TERMINAL — BACKEND SERVER
   Node.js / Express  |  Production-Ready
   ══════════════════════════════════════════════════════════════ */
require('dotenv').config();

'use strict';

/* ──────────────────────────────────────
   DEPENDENCIES
─────────────────────────────────────── */
const cors          = require('cors');
const express       = require('express');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const nodemailer    = require('nodemailer');
const multer        = require('multer');
const path          = require('path');
const fs            = require('fs');
const crypto        = require('crypto');
const { v4: uuidv4 }= require('uuid');
const mongoose      = require('mongoose');

/* ──────────────────────────────────────
   APP INIT
─────────────────────────────────────── */
const app  = express();

// ── CORS ─────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(cors({
  origin: [
    'https://naraxboro.netlify.app',
    'http://localhost:3000',
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
const PORT = process.env.PORT || 3000;

/* ──────────────────────────────────────
   MONGODB CONNECTION
─────────────────────────────────────── */
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 30000,
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000,
})
  .then(() => console.log('[DB] Connected to MongoDB Atlas'))
  .catch(err => console.error('[DB] Connection failed:', err.message));

/* ──────────────────────────────────────
   USER MODEL
─────────────────────────────────────── */
const userSchema = new mongoose.Schema({
  userId:       { type: String, required: true, unique: true, lowercase: true },
  email:        { type: String, required: true, unique: true, lowercase: true },
  passwordHash: { type: String, required: true, select: false },
  avatar:       { type: String, default: null },
  role:         { type: String, enum: ['USER', 'ADMIN'], default: 'USER' },
  status:       { type: String, enum: ['ONLINE', 'OFFLINE'], default: 'OFFLINE' },
  joined:       { type: String, default: () => new Date().toISOString().split('T')[0] },
  resetToken:   { type: String, default: null },  // ← ADD
  resetExpiry:  { type: Number, default: null },  // ← ADD
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

/* ── Seed primary admin on startup ───────────────────────── */
(async () => {
  try {
    const exists = await User.findOne({ userId: 'narax_admin' });
    if (!exists) {
      await User.create({
        userId:       'narax_admin',
        email:        'naraxboro@gmail.com',
        passwordHash: '$2a$08$ZF8nD3MLdvJC/ezcoWHTm.D8cvUv9Xr4tyDETOxRKLj0GiRV5aFsu',
        role:         'ADMIN',
        joined:       '2026-01-01',
      });
      console.log('[DB] Admin account seeded');
    }
  } catch (e) {
    console.error('[DB] Seed error:', e.message);
  }
})();

/* ──────────────────────────────────────
   ★ CONFIGURATION — EDIT THESE VALUES ★
─────────────────────────────────────── */
const CONFIG = {
  // ── JWT ──────────────────────────────────────────────────────
  JWT_SECRET:          process.env.JWT_SECRET || 'CHANGE_ME_USE_A_LONG_RANDOM_SECRET_256BIT',
  JWT_EXPIRES_IN:      '30m',   // Hard session expiry: 30 minutes

  // ── EMAIL CREDENTIALS ────────────────────────────────────────
  // Replace the values below (or set them as environment variables)
  // For Gmail: enable "App Passwords" at myaccount.google.com/apppasswords
  EMAIL_HOST:          process.env.EMAIL_HOST     || 'smtp.gmail.com',
  EMAIL_PORT:          process.env.EMAIL_PORT     || 587,
  EMAIL_SECURE:        false,                            // true for port 465
  EMAIL_USER:          process.env.EMAIL_USER     || 'YOUR_EMAIL@gmail.com',   // ← paste here
  EMAIL_PASS:          process.env.EMAIL_PASS     || 'YOUR_APP_PASSWORD_HERE', // ← paste here
  EMAIL_FROM_NAME:     'Narax',                          // Sender display name
  EMAIL_FROM_ADDRESS:  process.env.EMAIL_USER     || 'YOUR_EMAIL@gmail.com',   // ← paste here

  // ── SECURITY ──────────────────────────────────────────────────
  BCRYPT_ROUNDS:       8,
  OTP_EXPIRY_MS:       5 * 60 * 1000,   // 5 minutes
  SESSION_EXPIRY_MS:   30 * 60 * 1000,  // 30 minutes inactivity TTL (server-side)

  // ── UPLOADS ───────────────────────────────────────────────────
  AVATAR_UPLOAD_DIR:   path.join(__dirname, 'uploads', 'avatars'),
  AVATAR_MAX_SIZE_MB:  3,
};

/* ──────────────────────────────────────
   IN-MEMORY STORES
   (Replace with MongoDB/PostgreSQL in production)
─────────────────────────────────────── */

// users  → { [userId]: { id, email, passwordHash, role, joined, avatar, status } }
const users = {
  narax_admin: {
    id:           'narax_admin',
    email:        'naraxboro@gmail.com',
    passwordHash: '$2a$08$ZF8nD3MLdvJC/ezcoWHTm.D8cvUv9Xr4tyDETOxRKLj0GiRV5aFsu',
    role:         'ADMIN',
    joined:       '2026-01-01',
    avatar:       null,
    status:       'OFFLINE',
  },
};

// sessions → { [sessionId]: { userId, role, loginTime, lastActive, expiresAt } }
const sessions = {};

const sessionSchema = new mongoose.Schema({
  sessionId:  { type: String, required: true, unique: true },
  userId:     { type: String, required: true },
  role:       { type: String, required: true },
  loginTime:  { type: String },
  lastActive: { type: Number },
  expiresAt:  { type: Number },
}, { collection: 'sessions' });
const Session = mongoose.model('Session', sessionSchema);

// otpStore → { [email]: { otp, expiresAt, purpose: 'login'|'reset' } }
const otpStore = {};

/* ──────────────────────────────────────
   NODEMAILER TRANSPORTER
─────────────────────────────────────── */

const SibApiV3Sdk = require('@getbrevo/brevo');
const brevoApi = new SibApiV3Sdk.TransactionalEmailsApi();
brevoApi.authentications['api-key'].apiKey = process.env.BREVO_API_KEY;

/* ──────────────────────────────────────
   MULTER — AVATAR STORAGE
─────────────────────────────────────── */
if (!fs.existsSync(CONFIG.AVATAR_UPLOAD_DIR)) {
  fs.mkdirSync(CONFIG.AVATAR_UPLOAD_DIR, { recursive: true });
}

const avatarStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, CONFIG.AVATAR_UPLOAD_DIR),
  filename:    (req, file, cb) => {
    // userId_timestamp.ext — no path traversal risk
    const ext  = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '');
    const safe = `${req.user.id}_${Date.now()}${ext}`;
    cb(null, safe);
  },
});

const uploadAvatar = multer({
  storage: avatarStorage,
  limits:  { fileSize: CONFIG.AVATAR_MAX_SIZE_MB * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
    const ext = path.extname(file.originalname).toLowerCase();
    allowed.includes(ext)
      ? cb(null, true)
      : cb(new Error('Only JPG, PNG, WEBP, GIF images are allowed'));
  },
});

/* ══════════════════════════════════════════════════════════════
   GLOBAL MIDDLEWARE
   ══════════════════════════════════════════════════════════════ */

// 1. Secure HTTP headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// 2. Body parsers — cap at 1 MB to prevent payload attacks
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 3. Serve frontend & avatars statically
app.use(express.static(path.join(__dirname)));
app.use('/avatars', express.static(CONFIG.AVATAR_UPLOAD_DIR));

/* ──────────────────────────────────────
   RATE LIMITERS
─────────────────────────────────────── */

// Auth endpoints — aggressive throttle: 10 attempts / 15 min per IP
const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { success: false, message: 'TOO MANY ATTEMPTS — TRY AGAIN IN 15 MINUTES' },
});

// OTP / password-reset — 5 requests / 10 min per IP
const otpLimiter = rateLimit({
  windowMs:        10 * 60 * 1000,
  max:             5,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { success: false, message: 'OTP REQUEST LIMIT REACHED — WAIT 10 MINUTES' },
});

// General API — 200 requests / 15 min per IP
const generalLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             200,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { success: false, message: 'RATE LIMIT EXCEEDED' },
});

app.use('/api/', generalLimiter);

/* ══════════════════════════════════════════════════════════════
   UTILITY FUNCTIONS
   ══════════════════════════════════════════════════════════════ */

/**
 * Sanitize a string — strip characters used in injection attacks.
 * Removes: $ { } [ ] < > " ' ; \ null-bytes
 */
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/[\0\x08\x09\x1a\n\r"'\\\/<>{}$[\];%]/g, '')
    .trim()
    .slice(0, 256); // hard cap field length
}

/** Validate email format */
function isValidEmail(email) {
  return /^[^\s@]{1,64}@[^\s@]{1,253}\.[^\s@]{2,}$/.test(email);
}

/** Validate userId — alphanumeric + underscore, 3–32 chars */
function isValidUserId(id) {
  return /^[a-zA-Z0-9_]{3,32}$/.test(id);
}

/** Generate a cryptographically secure 6-digit OTP */
function generateOTP() {
  return String(crypto.randomInt(100000, 999999));
}

/** Generate a unique session ID (hex) */
function generateSessionId() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

/**
 * Purge expired server-side sessions.
 * Called on every protected request — lightweight O(n) scan.
 */
function purgeExpiredSessions() {
  const now = Date.now();
  for (const [sid, sess] of Object.entries(sessions)) {
    if (now > sess.expiresAt) delete sessions[sid];
  }
}

/* ══════════════════════════════════════════════════════════════
   MIDDLEWARE: JWT AUTHENTICATION
   ══════════════════════════════════════════════════════════════ */

/**
 * Verifies the Bearer JWT and validates the server-side session.
 * Attaches req.user = { id, role, sessionId } on success.
 */
async function authenticate(req, res, next) {
  purgeExpiredSessions();

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'AUTHORIZATION REQUIRED' });
  }

  const token = authHeader.slice(7);

  let decoded;
  try {
    decoded = jwt.verify(token, CONFIG.JWT_SECRET);
  } catch {
    return res.status(401).json({ success: false, message: 'TOKEN INVALID OR EXPIRED' });
  }

  // Validate the server-side session still exists & hasn't timed out
  let session = sessions[decoded.sessionId];
  if (!session) {
    // Fallback: check MongoDB (handles server restarts)
    const dbSession = await Session.findOne({ sessionId: decoded.sessionId, expiresAt: { $gt: Date.now() } });
    if (!dbSession) {
      return res.status(401).json({ success: false, message: 'SESSION EXPIRED — PLEASE LOG IN AGAIN' });
    }
    // Restore to memory
    sessions[decoded.sessionId] = { userId: dbSession.userId, role: dbSession.role, loginTime: dbSession.loginTime, lastActive: Date.now(), expiresAt: dbSession.expiresAt };
    session = sessions[decoded.sessionId];
  }

  // Slide the 30-minute inactivity window
  session.lastActive = Date.now();
  session.expiresAt  = Date.now() + CONFIG.SESSION_EXPIRY_MS;

  req.user = { id: decoded.userId, role: decoded.role, sessionId: decoded.sessionId };
  next();
}

/**
 * Requires req.user.role === 'ADMIN'.
 * Must be used after authenticate().
 */
function requireAdmin(req, res, next) {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ success: false, message: 'ADMIN CLEARANCE REQUIRED' });
  }
  next();
}

/* ══════════════════════════════════════════════════════════════
   EMAIL HELPER
   ══════════════════════════════════════════════════════════════ */

async function sendOTPEmail(toEmail, otp, purpose) {
  const subject = purpose === 'reset'
    ? 'Narax — Password Reset Code'
    : 'Narax — Two-Factor Authentication Code';

  const email = new SibApiV3Sdk.SendSmtpEmail();
  email.sender      = { name: 'Narax', email: process.env.EMAIL_USER };
  email.to          = [{ email: toEmail }];
  email.subject     = subject;
  email.htmlContent = `
    <div style="font-family:monospace;background:#0a0a0f;color:#00ffcc;padding:32px;border:1px solid #00ffcc22;border-radius:8px;max-width:480px;margin:auto">
      <h2 style="color:#00ffcc;letter-spacing:4px;margin-top:0">NARAX SECURITY</h2>
      <p style="color:#aaa;font-size:13px;letter-spacing:2px">${purpose === 'reset' ? 'PASSWORD RESET' : 'TWO-FACTOR AUTH'}</p>
      <div style="background:#111;border:1px solid #00ffcc44;border-radius:6px;padding:24px;text-align:center;margin:24px 0">
        <span style="font-size:36px;letter-spacing:12px;color:#00ffcc;font-weight:bold">${otp}</span>
      </div>
      <p style="color:#888;font-size:11px">This code expires in <b style="color:#fff">5 minutes</b>.<br>
      If you did not request this, ignore this message immediately.</p>
      <hr style="border-color:#222;margin-top:24px">
      <p style="color:#555;font-size:10px;margin:0">© Narax Security Terminal — Automated Message</p>
    </div>`;
  await brevoApi.sendTransacEmail(email);
}

async function sendResetLinkEmail(toEmail, resetLink) {
  const email = new SibApiV3Sdk.SendSmtpEmail();
  email.sender      = { name: 'Narax', email: process.env.EMAIL_USER };
  email.to          = [{ email: toEmail }];
  email.subject     = 'Narax — Access Key Recovery Link';
  email.htmlContent = `
    <div style="font-family:monospace;background:#0a0a0f;color:#00e5ff;padding:32px;border:1px solid #00e5ff22;border-radius:8px;max-width:480px;margin:auto">
      <h2 style="color:#00e5ff;letter-spacing:4px;margin-top:0">NARAX SECURITY</h2>
      <p style="color:#aaa;font-size:13px;letter-spacing:2px">PASSWORD RECOVERY</p>
      <p style="color:#ccc;font-size:13px;line-height:1.6">A key recovery was requested.<br>Click below to set a new access key. Expires in <b style="color:#fff">1 hour</b>.</p>
      <div style="text-align:center;margin:28px 0">
        <a href="${resetLink}" style="background:#00e5ff;color:#0a0a0f;text-decoration:none;padding:14px 32px;border-radius:4px;font-weight:bold;letter-spacing:3px;font-size:13px;display:inline-block">RESET ACCESS KEY</a>
      </div>
      <p style="color:#555;font-size:11px;word-break:break-all">${resetLink}</p>
      <hr style="border-color:#222;margin-top:24px">
      <p style="color:#555;font-size:10px;margin:0">© Narax Security Terminal</p>
    </div>`;
  await brevoApi.sendTransacEmail(email);
}

/* ══════════════════════════════════════════════════════════════
   ROUTES
   ══════════════════════════════════════════════════════════════ */

/* ──────────────────────────────────────
   POST /api/auth/register
   Body: { userId, email, password }
─────────────────────────────────────── */
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    // Sanitize all inputs
    const userId   = sanitize(req.body.userId   || '');
    const email    = sanitize(req.body.email    || '');
    const password = String(req.body.password   || '');

    // Validate
    if (!userId || !email || !password) {
      return res.status(400).json({ success: false, message: 'ALL FIELDS REQUIRED' });
    }
    if (!isValidUserId(userId)) {
      return res.status(400).json({ success: false, message: 'USER ID: 3-32 ALPHANUMERIC CHARS ONLY' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'INVALID EMAIL FORMAT' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'PASSWORD MINIMUM 8 CHARACTERS' });
    }
    if (!/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
      return res.status(400).json({ success: false, message: 'PASSWORD REQUIRES UPPERCASE, NUMBER, AND SYMBOL' });
    }

    // Uniqueness check — constant-time to prevent user enumeration via timing
    const existing = await User.findOne({
      $or: [{ userId: userId.toLowerCase() }, { email: email.toLowerCase() }]
    });
    if (existing) {
      await new Promise(r => setTimeout(r, 300 + Math.random() * 200));
      return res.status(409).json({ success: false, message: 'USER ID OR EMAIL ALREADY REGISTERED' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS);

    // Save to MongoDB
    const newUser = await User.create({
      userId: userId.toLowerCase(),
      email:  email.toLowerCase(),
      passwordHash,
      role:   'USER',
    });

    return res.status(201).json({
      success: true,
      message: 'ACCOUNT CREATED — PLEASE LOG IN',
      userId:  newUser.userId,
    });

  } catch (err) {
    console.error('[REGISTER ERROR]', err.message);
    return res.status(500).json({ success: false, message: 'INTERNAL SERVER ERROR' });
  }
});

/* ──────────────────────────────────────
   POST /api/auth/login
   Body: { userId, password }
─────────────────────────────────────── */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const userId   = sanitize(req.body.userId   || '');
    const password = String(req.body.password   || '');

    if (!userId || !password) {
      return res.status(400).json({ success: false, message: 'ALL FIELDS REQUIRED' });
    }

    const user = await User.findOne({ userId: userId.toLowerCase() }).select('+passwordHash');

    const dummyHash = '$2a$08$notarealhashjustpaddingtoconstanttime.......';
    const hashToCheck = user ? user.passwordHash : dummyHash;
    const match = await bcrypt.compare(password, hashToCheck);

    if (!user || !match) {
      return res.status(401).json({ success: false, message: 'INVALID CREDENTIALS' });
    }

    // Direct login — no OTP
    const sessionId = generateSessionId();
    const loginTime = new Date();
    const expiresAt = Date.now() + CONFIG.SESSION_EXPIRY_MS;

    sessions[sessionId] = {
      userId:   user.userId,
      role:       user.role,
      loginTime:  loginTime.toISOString(),
      lastActive: Date.now(),
      expiresAt,
    };

    Session.create({ sessionId, userId: user.userId, role: user.role, loginTime: loginTime.toISOString(), lastActive: Date.now(), expiresAt }).catch(() => {});

    await User.updateOne({ userId: user.userId }, { status: 'ONLINE' });
    user.status = 'ONLINE';

    const token = jwt.sign(
      { userId: user.userId, role: user.role, sessionId },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.JWT_EXPIRES_IN, algorithm: 'HS256' }
    );

    return res.status(200).json({
      success: true,
      message: 'ACCESS GRANTED',
      token,
      sessionInfo: {
        sessionId,
        userId:    user.userId,
        role:      user.role,
        authMode:  user.role === 'ADMIN' ? 'ADMIN' : 'USER',
        clearance: user.role === 'ADMIN' ? 'LEVEL 5 — ALPHA' : 'LEVEL 2 — STANDARD',
        loginTime: loginTime.toISOString(),
        expiresAt: new Date(expiresAt).toISOString(),
      },
    });

  } catch (err) {
    console.error('[LOGIN ERROR]', err.message);
    return res.status(500).json({ success: false, message: 'INTERNAL SERVER ERROR' });
  }
});

/* ──────────────────────────────────────
   POST /api/auth/verify-otp
   Body: { userId, otp }
   Returns: JWT + session metadata
─────────────────────────────────────── */
app.post('/api/auth/verify-otp', authLimiter, async (req, res) => {
  try {
    const userId = sanitize(req.body.userId || '');
    const otp    = sanitize(req.body.otp    || '');

    if (!userId || !otp) {
      return res.status(400).json({ success: false, message: 'USER ID AND OTP REQUIRED' });
    }
    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ success: false, message: 'OTP MUST BE 6 DIGITS' });
    }

    const user = await User.findOne({ userId: userId.toLowerCase() });
    if (!user) {
      return res.status(401).json({ success: false, message: 'USER NOT FOUND' });
    }

    const record = otpStore[user.email];
    if (!record || record.purpose !== 'login') {
      return res.status(401).json({ success: false, message: 'NO OTP ON FILE — REQUEST A NEW ONE' });
    }
    if (Date.now() > record.expiresAt) {
      delete otpStore[user.email];
      return res.status(401).json({ success: false, message: 'OTP EXPIRED — REQUEST A NEW ONE' });
    }
    if (record.otp !== otp) {
      return res.status(401).json({ success: false, message: 'INVALID OTP' });
    }

    // OTP consumed — delete immediately (one-time use)
    delete otpStore[user.email];

    // Create server-side session record
    const sessionId  = generateSessionId();
    const loginTime  = new Date();
    const expiresAt  = Date.now() + CONFIG.SESSION_EXPIRY_MS;

    sessions[sessionId] = {
      userId:   user.userId,
      role:       user.role,
      loginTime:  loginTime.toISOString(),
      lastActive: Date.now(),
      expiresAt,
    };

    // Update user status in MongoDB
    await User.updateOne({ userId: user.userId }, { status: 'ONLINE' });;

    // Sign JWT — embeds sessionId for server-side revocation support
    const token = jwt.sign(
      { userId: user.userId, role: user.role, sessionId },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.JWT_EXPIRES_IN, algorithm: 'HS256' }
    );

    return res.status(200).json({
      success:    true,
      message:    'IDENTITY CONFIRMED — ACCESS GRANTED',
      token,
      // Session metadata for the dashboard display
      sessionInfo: {
        sessionId,
        userId:     user.userId,
        role:       user.role,
        authMode:   user.role === 'ADMIN' ? 'ADMIN + 2FA' : 'USER + 2FA',
        clearance:  user.role === 'ADMIN' ? 'LEVEL 5 — ALPHA' : 'LEVEL 2 — STANDARD',
        loginTime:  loginTime.toISOString(),
        expiresAt:  new Date(expiresAt).toISOString(),
      },
    });

  } catch (err) {
    console.error('[VERIFY-OTP ERROR]', err.message);
    return res.status(500).json({ success: false, message: 'INTERNAL SERVER ERROR' });
  }
});

/* ──────────────────────────────────────
   POST /api/auth/forgot-password
   Body: { email }
─────────────────────────────────────── */
app.post('/api/auth/forgot-password', otpLimiter, async (req, res) => {
  try {
    const email = sanitize(req.body.email || '').toLowerCase();
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'VALID EMAIL REQUIRED' });
    }

    const user = await User.findOne({ email });

    if (user) {
      const resetToken  = crypto.randomBytes(32).toString('hex');
      const resetExpiry = Date.now() + 60 * 60 * 1000; // 1 hour
      await User.updateOne({ email }, { resetToken, resetExpiry });
      const resetLink = `https://naraxboro.netlify.app/reset-password.html?token=${resetToken}`;
      await sendResetLinkEmail(email, resetLink);
    }

    return res.status(200).json({
      success: true,
      message: 'IF THAT EMAIL IS REGISTERED, A RESET LINK HAS BEEN TRANSMITTED',
    });

  } catch (err) {
    console.error('[FORGOT-PASSWORD ERROR]', err.message);
    return res.status(500).json({ success: false, message: 'INTERNAL SERVER ERROR' });
  }
});

/* ──────────────────────────────────────
   POST /api/auth/reset-password
   Body: { email, otp, newPassword }
─────────────────────────────────────── */
app.post('/api/auth/reset-password', otpLimiter, async (req, res) => {
  try {
    const token       = sanitize(req.body.token       || '');
    const newPassword = String(req.body.newPassword   || '');

    if (!token || !newPassword) {
      return res.status(400).json({ success: false, message: 'ALL FIELDS REQUIRED' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'PASSWORD MINIMUM 8 CHARACTERS' });
    }

    const user = await User.findOne({ resetToken: token }).select('+passwordHash');

    if (!user || !user.resetExpiry || Date.now() > user.resetExpiry) {
      return res.status(401).json({ success: false, message: 'RESET LINK INVALID OR EXPIRED' });
    }

    const passwordHash = await bcrypt.hash(newPassword, CONFIG.BCRYPT_ROUNDS);
    await User.updateOne(
      { _id: user._id },
      { passwordHash, $unset: { resetToken: '', resetExpiry: '' } }
    );

    for (const [sid, sess] of Object.entries(sessions)) {
      if (sess.userId === user.userId) delete sessions[sid];
    }

    return res.status(200).json({ success: true, message: 'ACCESS KEY UPDATED — PLEASE LOG IN' });

  } catch (err) {
    console.error('[RESET-PASSWORD ERROR]', err.message);
    return res.status(500).json({ success: false, message: 'INTERNAL SERVER ERROR' });
  }
});

/* ──────────────────────────────────────
   POST /api/auth/logout
   Header: Authorization: Bearer <token>
─────────────────────────────────────── */
app.post('/api/auth/logout', authenticate, async (req, res) => {
  const { sessionId, id } = req.user;

  // Delete server-side session (token revocation)
  delete sessions[sessionId];

  // Mark user offline
  await User.updateOne({ userId: id }, { status: 'OFFLINE' });

  return res.status(200).json({ success: true, message: 'SESSION TERMINATED' });
});

/* ──────────────────────────────────────
   GET /api/auth/session
   Validates token & refreshes session TTL
─────────────────────────────────────── */
app.get('/api/auth/session', authenticate, (req, res) => {
  const session = sessions[req.user.sessionId];
  return res.status(200).json({
    success: true,
    session: {
      userId:    req.user.id,
      role:      req.user.role,
      sessionId: req.user.sessionId,
      loginTime: session.loginTime,
      expiresAt: new Date(session.expiresAt).toISOString(),
    },
  });
});

/* ══════════════════════════════════════════════════════════════
   PROFILE ROUTES
   ══════════════════════════════════════════════════════════════ */

/* ──────────────────────────────────────
   GET /api/profile
─────────────────────────────────────── */
app.get('/api/profile', authenticate, async (req, res) => {
  const user = await User.findOne({ userId: req.user.id });
  if (!user) return res.status(404).json({ success: false, message: 'USER NOT FOUND' });
  return res.status(200).json({ success: true, profile: user.toObject() });
});

/* ──────────────────────────────────────
   POST /api/profile/avatar — multipart/form-data upload
   Field name: "avatar"
   Alternative: POST /api/profile/avatar-base64 — JSON base64
─────────────────────────────────────── */
app.post('/api/profile/avatar', authenticate, uploadAvatar.single('avatar'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'NO FILE UPLOADED' });
  }
  // Read file from disk, convert to base64, then delete the temp file
  const fileBuffer = fs.readFileSync(req.file.path);
  const mimeType   = req.file.mimetype || 'image/jpeg';
  const base64     = `data:${mimeType};base64,${fileBuffer.toString('base64')}`;
  fs.unlink(req.file.path, () => {}); // delete temp file
  await User.updateOne({ userId: req.user.id }, { avatar: base64 });
  return res.status(200).json({ success: true, message: 'OPERATOR PHOTO UPDATED', avatarUrl: base64 });
});;

/* ──────────────────────────────────────
   POST /api/profile/avatar-base64
   Body: { base64: "data:image/png;base64,..." }
   Stores the raw base64 string (no disk write)
─────────────────────────────────────── */
app.post('/api/profile/avatar-base64', authenticate, async (req, res) => {
  const { base64 } = req.body;

  if (!base64 || typeof base64 !== 'string') {
    return res.status(400).json({ success: false, message: 'BASE64 IMAGE REQUIRED' });
  }
  if (!base64.startsWith('data:image/')) {
    return res.status(400).json({ success: false, message: 'INVALID IMAGE FORMAT' });
  }
  if (Buffer.byteLength(base64, 'utf8') > 5 * 1024 * 1024) {
    return res.status(413).json({ success: false, message: 'IMAGE TOO LARGE' });
  }

  await User.updateOne({ userId: req.user.id }, { avatar: base64 });

  return res.status(200).json({ success: true, message: 'OPERATOR PHOTO UPDATED' });
});

/* ══════════════════════════════════════════════════════════════
   ADMIN ROUTES  (authenticate + requireAdmin)
   ══════════════════════════════════════════════════════════════ */

/* ──────────────────────────────────────
   GET /api/admin/users
   Returns full user list (no hashes)
─────────────────────────────────────── */
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  const userList = await User.find({}).lean();
  return res.status(200).json({ success: true, users: userList.map(u => ({ ...u, id: u.userId })) });
});

/* ──────────────────────────────────────
   PATCH /api/admin/users/:userId/role
   Body: { role: 'ADMIN' | 'USER' }
─────────────────────────────────────── */
app.patch('/api/admin/users/:userId/role', authenticate, requireAdmin, async (req, res) => {
  const targetId = sanitize(req.params.userId || '');
  const role     = sanitize(req.body.role     || '');
 
  if (!['ADMIN', 'USER'].includes(role)) {
    return res.status(400).json({ success: false, message: 'ROLE MUST BE ADMIN OR USER' });
  }
 
  const target = await User.findOne({ userId: targetId.toLowerCase() });
  if (!target) {
    return res.status(404).json({ success: false, message: 'USER NOT FOUND' });
  }

  // Prevent self-demotion
  if (target.userId === req.user.id && role !== 'ADMIN') {
    return res.status(403).json({ success: false, message: 'CANNOT REVOKE YOUR OWN ADMIN CLEARANCE' });
  }

  await User.updateOne({ userId: targetId.toLowerCase() }, { role });

  return res.status(200).json({
    success: true,
    message: role === 'ADMIN'
      ? `${target.userId} PROMOTED TO ADMIN`
      : `${target.userId} CLEARANCE REVOKED`,
  });
})

/* ──────────────────────────────────────
   DELETE /api/admin/users/:userId
─────────────────────────────────────── */
app.delete('/api/admin/users/:userId', authenticate, requireAdmin, async (req, res) => {
  const targetId = sanitize(req.params.userId || '');

  if (targetId === req.user.id) {
    return res.status(403).json({ success: false, message: 'CANNOT DELETE YOUR OWN ACCOUNT' });
  }
  if (targetId === 'narax_admin') {
    return res.status(403).json({ success: false, message: 'PRIMARY ADMIN CANNOT BE DELETED' });
  }

  const target = await User.findOne({ userId: targetId.toLowerCase() });
  if (!target) return res.status(404).json({ success: false, message: 'USER NOT FOUND' });

  if (target.role === 'ADMIN' && req.user.id !== 'narax_admin') {
    return res.status(403).json({ success: false, message: 'ONLY PRIMARY ADMIN CAN DELETE ADMINS' });
  }

  for (const [sid, sess] of Object.entries(sessions)) {
    if (sess.userId === targetId) delete sessions[sid];
  }

  await User.deleteOne({ userId: targetId.toLowerCase() });

  return res.status(200).json({
    success: true,
    message: `USER ${targetId.toUpperCase()} DELETED FROM REGISTRY`,
  });
});

/* ──────────────────────────────────────
   GET /api/admin/sessions
   Lists all active sessions
─────────────────────────────────────── */
app.get('/api/admin/sessions', authenticate, requireAdmin, (req, res) => {
  purgeExpiredSessions();
  const activeSessions = Object.entries(sessions).map(([sid, s]) => ({
    sessionId:  sid,
    userId:     s.userId,
    role:       s.role,
    loginTime:  s.loginTime,
    lastActive: new Date(s.lastActive).toISOString(),
    expiresAt:  new Date(s.expiresAt).toISOString(),
  }));
  return res.status(200).json({ success: true, sessions: activeSessions });
});

/* ══════════════════════════════════════════════════════════════
   BACKGROUND TASK: Purge expired sessions every 5 minutes
   ══════════════════════════════════════════════════════════════ */
setInterval(() => {
  purgeExpiredSessions();
  // Also mark users with no active sessions as OFFLINE
  const activeUserIds = new Set(Object.values(sessions).map(s => s.userId));
  for (const user of Object.values(users)) {
    user.status = activeUserIds.has(user.id) ? 'ONLINE' : 'OFFLINE';
  }
}, 5 * 60 * 1000);

/* ──────────────────────────────────────
   GLOBAL ERROR HANDLER
─────────────────────────────────────── */
// Multer errors (file size, type)
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ success: false, message: `FILE TOO LARGE — MAX ${CONFIG.AVATAR_MAX_SIZE_MB}MB` });
  }
  if (err.message && err.message.includes('Only')) {
    return res.status(415).json({ success: false, message: err.message.toUpperCase() });
  }
  console.error('[UNHANDLED ERROR]', err);
  return res.status(500).json({ success: false, message: 'INTERNAL SERVER ERROR' });
});

const https = require('https');
setInterval(() => {
  https.get('https://naraxboro.onrender.com/api/health', () => {}).on('error', () => {});
}, 14 * 60 * 1000);

// Also add this health check route
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ONLINE' });
});

/* ──────────────────────────────────────
   START SERVER
─────────────────────────────────────── */
app.listen(PORT, () => {
  console.log(`
  ██╗   ██╗ █████╗ ██████╗  █████╗ ██╗  ██╗
  ███╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝
  ████╗ ██║███████║██████╔╝███████║ ╚███╔╝
  ██╔██╗██║██╔══██║██╔══██╗██╔══██║ ██╔██╗
  ██║╚████║██║  ██║██║  ██║██║  ██║██╔╝╚██╗
  ╚═╝ ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

  NARAX SECURITY TERMINAL — BACKEND ONLINE
  Port     : ${PORT}
  Mode     : PRODUCTION
  Sessions : In-Memory (swap for Redis in prod)
  `);
});

module.exports = app;
