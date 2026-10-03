import { useState, useEffect } from 'react';
import * as api from './api.js';
import {
  deriveKeys, randomSalt, encrypt, decrypt,
  generateVaultKey, wrapVaultKey, unwrapVaultKey, b64, unb64,
} from './crypto/crypto.js';

function Auth({ onLogin }) {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setMsg('');
    try {
      const em = email.trim().toLowerCase();
      if (mode === 'register') {
        if (password.length < 12) throw new Error('Use at least 12 characters');
        const salt = randomSalt();
        const { authKey, encKey } = await deriveKeys(password, salt);
        const vaultKey = await generateVaultKey();
        const wrappedVaultKey = await wrapVaultKey(encKey, vaultKey);
        await api.register({
          email: em,
          kdfSalt: b64(salt),
          kdfParams: { m: 65536, t: 3, p: 1 },
          authKey,
          wrappedVaultKey,
        });
        setMode('login');
        setPassword('');
        setMsg('Account created. Log in now.');
      } else {
        const pre = await api.prelogin(em);
        const { authKey, encKey } = await deriveKeys(password, unb64(pre.kdfSalt));
        const res = await api.login({ email: em, authKey });
        api.setToken(res.token);
        const vaultKey = await unwrapVaultKey(encKey, res.wrappedVaultKey);
        onLogin(vaultKey);
      }
    } catch (err) {
      setMsg(err.message || 'Something went wrong');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="card">
      <h2>{mode === 'login' ? 'Unlock vault' : 'Create account'}</h2>
      <input type="email" placeholder="Email" value={email}
        onChange={(e) => setEmail(e.target.value)} required />
      <input type="password" placeholder="Master password" value={password}
        onChange={(e) => setPassword(e.target.value)} required />
      <button disabled={busy}>
        {busy ? 'Working...' : mode === 'login' ? 'Log in' : 'Register'}
      </button>
      {msg && <p className="msg">{msg}</p>}
      {mode === 'register' && (
        <p className="warn">
          Your master password cannot be recovered. If you forget it, your data is gone.
        </p>
      )}
      <a href="#" onClick={(e) => { e.preventDefault(); setMsg(''); setMode(mode === 'login' ? 'register' : 'login'); }}>
        {mode === 'login' ? 'Need an account? Register' : 'Have an account? Log in'}
      </a>
    </form>
  );
}

function Vault({ vaultKey, onLock }) {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({ site: '', username: '', password: '' });
  const [shown, setShown] = useState({});
  const [msg, setMsg] = useState('');

  function handleErr(err) {
    if (err.message === 'Unauthorized') onLock();
    else setMsg(err.message);
  }

  async function load() {
    try {
      const { items: raw } = await api.listItems();
      const out = [];
      for (const it of raw) {
        try {
          out.push({ id: it.id, ...(await decrypt(vaultKey, { iv: it.iv, ct: it.ciphertext })) });
        } catch {
          // skip entries that fail to decrypt
        }
      }
      setItems(out);
    } catch (err) {
      handleErr(err);
    }
  }

  useEffect(() => { load(); }, []); // eslint-disable-line

  async function add(e) {
    e.preventDefault();
    if (!form.site || !form.password) return;
    try {
      const { iv, ct } = await encrypt(vaultKey, form);
      await api.addItem({ iv, ciphertext: ct });
      setForm({ site: '', username: '', password: '' });
      load();
    } catch (err) {
      handleErr(err);
    }
  }

  async function remove(id) {
    try {
      await api.deleteItem(id);
      load();
    } catch (err) {
      handleErr(err);
    }
  }

  async function copy(text) {
    await navigator.clipboard.writeText(text);
    setMsg('Copied. Clipboard clears in 20s.');
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 20000);
  }

  return (
    <div>
      <div className="row">
        <h2>Your vault</h2>
        <button className="ghost" onClick={onLock}>Lock</button>
      </div>

      <form onSubmit={add} className="card">
        <input placeholder="Site" value={form.site}
          onChange={(e) => setForm({ ...form, site: e.target.value })} required />
        <input placeholder="Username" value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <input type="password" placeholder="Password" value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })} required />
        <button>Add entry</button>
      </form>

      {msg && <p className="msg">{msg}</p>}
      {items.length === 0 && <p className="muted">No entries yet.</p>}

            {items.map((it) => (
        <div key={it.id} className="card">
          <div className="row">
            <div className="row left">
              <div className="avatar">{(it.site[0] || '?').toUpperCase()}</div>
              <div>
                <strong>{it.site}</strong>
                <div className="muted">{it.username || 'no username'}</div>
              </div>
            </div>
            <div className="mono pw">{shown[it.id] ? it.password : '••••••••••'}</div>
          </div>
          <div className="row actions">
            <button className="ghost" onClick={() => setShown({ ...shown, [it.id]: !shown[it.id] })}>
              {shown[it.id] ? 'Hide' : 'Show'}
            </button>
            <button className="ghost" onClick={() => copy(it.password)}>Copy</button>
            <button className="danger" onClick={() => remove(it.id)}>Delete</button>
          </div>
        </div>
      ))}
    </div>
  );
}

export default function App() {
  const [vaultKey, setVaultKey] = useState(null);
  const lock = () => { api.setToken(null); setVaultKey(null); };

  return (
    <main>
          <div className="brand">
        <div className="logo">🔐</div>
        <div>
          <h1>ZK Vault</h1>
          <p>Zero-knowledge password manager</p>
        </div>
      </div>
      {vaultKey ? <Vault vaultKey={vaultKey} onLock={lock} /> : <Auth onLogin={setVaultKey} />}
    </main>
  );
}