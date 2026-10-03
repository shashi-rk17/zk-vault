import { argon2id } from 'hash-wasm';

const enc = new TextEncoder();

export const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function randomSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

export async function deriveKeys(password, salt) {
  const master = await argon2id({
    password,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536, // 64 MB
    hashLength: 32,
    outputType: 'binary',
  });

  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ]);
  const params = (info) => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(0),
    info: enc.encode(info),
  });

  const authKey = b64(await crypto.subtle.deriveBits(params('auth'), base, 256));
  const encKey = await crypto.subtle.deriveKey(
    params('enc'),
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return { authKey, encKey };
}

export async function encrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(data))
  );
  return { iv: b64(iv), ct: b64(ct) };
}

export async function decrypt(key, { iv, ct }) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(iv) },
    key,
    unb64(ct)
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

// ---------- Vault key (random key that encrypts all entries) ----------

export async function generateVaultKey() {
  // extractable: true is needed only so we can wrap it right after creation
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
}

export async function wrapVaultKey(encKey, vaultKey) {
  const raw = await crypto.subtle.exportKey('raw', vaultKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, raw);
  return { iv: b64(iv), ct: b64(ct) };
}

export async function unwrapVaultKey(encKey, { iv, ct }, extractable = false) {
  const raw = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(iv) },
    encKey,
    unb64(ct)
  );
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, extractable, [
    'encrypt',
    'decrypt',
  ]);
}