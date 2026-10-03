import { describe, it, expect } from 'vitest';
import { deriveKeys, randomSalt, encrypt, decrypt, b64, unb64, generateVaultKey, wrapVaultKey, unwrapVaultKey } from './crypto.js';
const TIMEOUT = 30000; // Argon2 is slow on purpose

describe('crypto module', () => {
  it('encrypt then decrypt returns the original data', async () => {
    const { encKey } = await deriveKeys('my-master-pass', randomSalt());
    const data = { site: 'github.com', user: 'shashi', pass: 'p@ss123' };
    const box = await encrypt(encKey, data);
    expect(await decrypt(encKey, box)).toEqual(data);
  }, TIMEOUT);

  it('decrypt with a wrong key throws', async () => {
    const a = await deriveKeys('password-A', randomSalt());
    const b = await deriveKeys('password-B', randomSalt());
    const box = await encrypt(a.encKey, { x: 1 });
    await expect(decrypt(b.encKey, box)).rejects.toThrow();
  }, TIMEOUT);

  it('tampered ciphertext is rejected (GCM integrity)', async () => {
    const { encKey } = await deriveKeys('my-master-pass', randomSalt());
    const box = await encrypt(encKey, { x: 1 });
    const bytes = unb64(box.ct);
    bytes[0] ^= 1; // flip one bit
    await expect(decrypt(encKey, { iv: box.iv, ct: b64(bytes) })).rejects.toThrow();
  }, TIMEOUT);

  it('same data encrypts differently each time (random IV)', async () => {
    const { encKey } = await deriveKeys('my-master-pass', randomSalt());
    const b1 = await encrypt(encKey, { x: 1 });
    const b2 = await encrypt(encKey, { x: 1 });
    expect(b1.iv).not.toBe(b2.iv);
    expect(b1.ct).not.toBe(b2.ct);
  }, TIMEOUT);

  it('same password + salt gives same authKey; different salt does not', async () => {
    const salt = randomSalt();
    const k1 = await deriveKeys('my-master-pass', salt);
    const k2 = await deriveKeys('my-master-pass', salt);
    const k3 = await deriveKeys('my-master-pass', randomSalt());
    expect(k1.authKey).toBe(k2.authKey);
    expect(k1.authKey).not.toBe(k3.authKey);
  }, TIMEOUT);
});

describe('vault key', () => {
  it('wrap then unwrap gives a key that decrypts old entries', async () => {
    const { encKey } = await deriveKeys('master-1', randomSalt());
    const vaultKey = await generateVaultKey();
    const entry = await encrypt(vaultKey, { site: 'gmail.com', pass: 'abc' });

    const wrapped = await wrapVaultKey(encKey, vaultKey);
    const restored = await unwrapVaultKey(encKey, wrapped);
    expect(await decrypt(restored, entry)).toEqual({ site: 'gmail.com', pass: 'abc' });
  }, 30000);

  it('wrong master password cannot unwrap the vault key', async () => {
    const good = await deriveKeys('right-pass', randomSalt());
    const bad = await deriveKeys('wrong-pass', randomSalt());
    const wrapped = await wrapVaultKey(good.encKey, await generateVaultKey());
    await expect(unwrapVaultKey(bad.encKey, wrapped)).rejects.toThrow();
  }, 30000);

  it('password change: re-wrap only, old entries still decrypt', async () => {
    const oldKeys = await deriveKeys('old-pass', randomSalt());
    const vaultKey = await generateVaultKey();
    const entry = await encrypt(vaultKey, { n: 42 });
    const wrappedOld = await wrapVaultKey(oldKeys.encKey, vaultKey);

    // user logs in with old pass, then changes password
    const unwrapped = await unwrapVaultKey(oldKeys.encKey, wrappedOld, true);
    const newKeys = await deriveKeys('new-pass', randomSalt());
    const wrappedNew = await wrapVaultKey(newKeys.encKey, unwrapped);

    const afterLogin = await unwrapVaultKey(newKeys.encKey, wrappedNew);
    expect(await decrypt(afterLogin, entry)).toEqual({ n: 42 });
  }, 30000);

  it('unwrapped key is not extractable by default', async () => {
    const { encKey } = await deriveKeys('master-1', randomSalt());
    const wrapped = await wrapVaultKey(encKey, await generateVaultKey());
    const key = await unwrapVaultKey(encKey, wrapped);
    await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
  }, 30000);
});