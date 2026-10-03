import { Router } from 'express';
import { z } from 'zod';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { pool } from '../db.js';

const router = Router();

router.use(
  rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false })
);

const DEFAULT_PARAMS = { m: 65536, t: 3, p: 1 };
const DUMMY_HASH = await argon2.hash('dummy-password', { type: argon2.argon2id });

const emailSchema = z.string().trim().toLowerCase().email().max(254);
const b64 = z.string().min(8).max(1024).regex(/^[A-Za-z0-9+/=]+$/);

const registerSchema = z.object({
  email: emailSchema,
  kdfSalt: b64,
  kdfParams: z.object({
    m: z.number().int().min(19456).max(262144),
    t: z.number().int().min(2).max(10),
    p: z.number().int().min(1).max(4),
  }),
  authKey: b64,
  wrappedVaultKey: z.object({ iv: b64, ct: b64 }),
});

const loginSchema = z.object({ email: emailSchema, authKey: b64 });

// Same fake salt every time for an unknown email, so attackers can't tell
// whether an account exists.
function fakeSalt(email) {
  return crypto
    .createHmac('sha256', process.env.JWT_SECRET)
    .update('fake-salt:' + email)
    .digest()
    .subarray(0, 16)
    .toString('base64');
}

router.get('/prelogin', async (req, res) => {
  const parsed = emailSchema.safeParse(req.query.email);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });

  const { rows } = await pool.query(
    'select kdf_salt, kdf_params from users where email = $1',
    [parsed.data]
  );
  if (rows[0]) return res.json({ kdfSalt: rows[0].kdf_salt, kdfParams: rows[0].kdf_params });
  res.json({ kdfSalt: fakeSalt(parsed.data), kdfParams: DEFAULT_PARAMS });
});

router.post('/register', async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });
  const d = parsed.data;

  // Hash the client's authKey again, so a DB leak doesn't expose a usable login secret
  const authHash = await argon2.hash(d.authKey, { type: argon2.argon2id });

  try {
    await pool.query(
      `insert into users (email, kdf_salt, kdf_params, auth_hash, wrapped_vault_key, wrap_iv)
       values ($1, $2, $3, $4, $5, $6)`,
      [d.email, d.kdfSalt, d.kdfParams, authHash, d.wrappedVaultKey.ct, d.wrappedVaultKey.iv]
    );
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Registration failed' });
    throw e;
  }
  res.status(201).json({ ok: true });
});

router.post('/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });
  const { email, authKey } = parsed.data;

  const { rows } = await pool.query(
    'select id, auth_hash, wrapped_vault_key, wrap_iv from users where email = $1',
    [email]
  );
  const user = rows[0];

  // Always run a verify, even for unknown emails, so response time doesn't leak which exist
  const ok = await argon2.verify(user ? user.auth_hash : DUMMY_HASH, authKey);
  if (!user || !ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
  res.json({
    token,
    wrappedVaultKey: { iv: user.wrap_iv, ct: user.wrapped_vault_key },
  });
});

export default router;