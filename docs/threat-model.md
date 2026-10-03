# ZK Vault Threat Model

## What this protects
Saved credentials (site, username, password, notes). The goal is that the server operator, the database, and anyone who steals a database backup learn nothing about vault contents.

## Design summary
- Master password -> Argon2id (64 MiB, 3 iterations, 1 lane, random 16-byte salt) in the browser.
- HKDF splits the result into an auth key (sent to the server) and an encryption key (never leaves the browser).
- A random 256-bit vault key encrypts every entry (AES-256-GCM, fresh 96-bit IV per encryption). The vault key is itself wrapped by the encryption key.
- The server stores only: email, salt, KDF parameters, an Argon2id hash of the auth key, the wrapped vault key, and ciphertext blobs.
- Login uses the auth key. The server hashes it again, so a database leak does not expose a usable login secret.
- Sessions: 15-minute JWT (HS256), held in memory only. Keys live in memory only and are lost on refresh or lock.

## Adversaries and outcomes

| Adversary | Outcome |
|---|---|
| Attacker who steals the database | Gets ciphertext, salts and hashes. Cannot read entries without the master password. Can attempt offline guessing, slowed by Argon2id. |
| Curious or compromised server operator (data at rest) | Same as above. No plaintext is ever sent to the server. |
| Network attacker | TLS protects transport. Even without TLS, payloads contain only derived keys and ciphertext. |
| User A accessing user B's data | Blocked: every vault query filters by the user id from the verified token. |
| Online password guessing | Rate limiting on /auth routes (30 requests per 15 minutes per IP). Argon2 verification on every login. |
| Tampering with stored ciphertext | AES-GCM authentication fails, so modified entries are rejected on decrypt. |

## Mitigations implemented
- Per-entry random IVs, so identical plaintexts produce different ciphertexts.
- Whole entry encrypted, including the site name, so the server cannot see which sites a user has accounts on.
- Fake deterministic salt for unknown emails on /prelogin, and a dummy hash verify on login, to reduce account enumeration through responses and timing.
- Input validation (zod) on every route, request body size limit, helmet security headers.
- Parameterised SQL queries only.
- Row level security enabled on the tables so Supabase's public API cannot read them.
- Clipboard cleared 20 seconds after copying a password.

## Known limitations (out of scope or not yet addressed)
- Malicious or compromised server serving modified JavaScript. In any web-delivered E2E app, the server can ship code that steals the master password. Mitigations such as a browser extension or signed releases are future work.
- XSS in the client. A script injected into the page could read decrypted data in memory. React escaping helps, but no Content Security Policy is set on the frontend host yet.
- Malware or keyloggers on the user's device.
- Weak master passwords. Argon2id slows guessing but cannot fix a guessable password. The app only enforces a 12-character minimum.
- No account recovery. If the master password is lost, the data is unrecoverable by design.
- Metadata leakage: the server sees email, number of entries, entry sizes and timestamps.
- Registration returns a distinct response when an email already exists, so account existence can still be probed there.
- No refresh tokens, 2FA or session revocation. Tokens expire after 15 minutes.
- Rate limiting is per IP only, with no per-account lockout.
- Password change is not implemented yet. The design supports it (re-wrap the vault key without re-encrypting entries).

## Possible future work
Password change and key rotation, TOTP 2FA, strict CSP, per-account throttling, breach checking with the HaveIBeenPwned k-anonymity API, a browser extension, and an audit log.