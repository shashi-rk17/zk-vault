import { Router } from 'express';
import { z } from 'zod';
import { pool } from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();
router.use(requireAuth);

const itemSchema = z.object({
  iv: z.string().length(16).regex(/^[A-Za-z0-9+/=]+$/),
  ciphertext: z.string().min(8).max(70000).regex(/^[A-Za-z0-9+/=]+$/),
});
const idSchema = z.string().uuid();

// List all of this user's entries
router.get('/', async (req, res) => {
  const { rows } = await pool.query(
    'select id, ciphertext, iv, updated_at from vault_items where user_id = $1 order by updated_at desc',
    [req.userId]
  );
  res.json({ items: rows });
});

// Add an entry
router.post('/', async (req, res) => {
  const parsed = itemSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid request' });

  const { rows } = await pool.query(
    'insert into vault_items (user_id, ciphertext, iv) values ($1, $2, $3) returning id, updated_at',
    [req.userId, parsed.data.ciphertext, parsed.data.iv]
  );
  res.status(201).json(rows[0]);
});

// Edit an entry (the user_id check stops one user touching another's data)
router.put('/:id', async (req, res) => {
  const id = idSchema.safeParse(req.params.id);
  const parsed = itemSchema.safeParse(req.body);
  if (!id.success || !parsed.success) return res.status(400).json({ error: 'Invalid request' });

  const { rows } = await pool.query(
    `update vault_items set ciphertext = $1, iv = $2, updated_at = now()
     where id = $3 and user_id = $4 returning id, updated_at`,
    [parsed.data.ciphertext, parsed.data.iv, id.data, req.userId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json(rows[0]);
});

// Delete an entry
router.delete('/:id', async (req, res) => {
  const id = idSchema.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: 'Invalid request' });

  const { rowCount } = await pool.query(
    'delete from vault_items where id = $1 and user_id = $2',
    [id.data, req.userId]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  res.status(204).end();
});

export default router;