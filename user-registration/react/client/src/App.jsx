/**
 * App.jsx — React UI shell for the PingOne user-registration sample.
 *
 * All PingOne API calls happen in the Express backend (server/index.js). This
 * component is a pure UI state machine: it sends fetch requests to /api/*,
 * reads the JSON status field, and advances through the registration/login
 * stages accordingly.
 *
 * Stage transitions:
 *   signup  → verify     when /api/register returns VERIFICATION_REQUIRED
 *   signup  → success    when /api/register returns COMPLETED (no email verification)
 *   verify  → success    when /api/verify returns COMPLETED
 *   login   → dashboard  when /api/login returns COMPLETED (accessToken present)
 *   any     → error      on ERROR status or network failure
 *   any     → signup     on reset()
 *
 * credentials: 'include' on every fetch call is required so the browser sends
 * the httpOnly sid cookie that the server uses to look up the active PingOne
 * flow session. Without it the /api/verify and /api/login calls would arrive
 * without a session and fail.
 */
import React, { useState } from 'react';
import logoSrc from './logo.png';

const styles = {
  header: {
    background: '#B8002F',
    padding: '12px 24px',
    display: 'flex',
    alignItems: 'center',
    marginBottom: 0,
  },
  logo: {
    height: 35,
    width: 'auto',
  },
  pageWrap: {
    padding: '32px 40px',
    maxWidth: 900,
    margin: '0 auto',
  },
};

/** PageShell wraps every stage in the consistent Ping Identity branded header. */
function PageShell({ children }) {
  return (
    <div>
      <header style={styles.header}>
        <img src={logoSrc} style={styles.logo} alt="Ping Identity" />
      </header>
      <div style={styles.pageWrap}>
        {children}
      </div>
    </div>
  );
}

export default function App() {
  // stages: signup | verify | login | success | dashboard | error
  const [stage, setStage] = useState('signup');
  const [error, setError] = useState('');
  const [accessToken, setAccessToken] = useState('');

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');

  /**
   * api sends a POST to a backend endpoint and returns the parsed JSON.
   * credentials: 'include' ensures the sid cookie travels with every request
   * so the server can locate the active PingOne flow session.
   */
  async function api(path, body) {
    const resp = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body),
    });
    return resp.json();
  }

  async function handleRegister(e) {
    e.preventDefault();
    setError('');
    const json = await api('/api/register', { username, email, password });
    if (json.status === 'VERIFICATION_REQUIRED') setStage('verify');
    else if (json.status === 'COMPLETED') setStage('success');
    else { setError(json.message || 'Registration failed'); setStage('error'); }
  }

  async function handleVerify(e) {
    e.preventDefault();
    setError('');
    const json = await api('/api/verify', { code });
    if (json.status === 'COMPLETED') setStage('success');
    else { setError(json.message || 'Verification failed'); setStage('error'); }
  }

  async function handleLogin(e) {
    e.preventDefault();
    setError('');
    const json = await api('/api/login', { username, password });
    if (json.status === 'COMPLETED') { setAccessToken(json.accessToken); setStage('dashboard'); }
    else { setError(json.message || 'Login failed'); setStage('error'); }
  }

  function reset() {
    setStage('signup');
    setError(''); setAccessToken('');
    setUsername(''); setEmail(''); setPassword(''); setCode('');
  }

  if (stage === 'signup') {
    return (
      <PageShell>
        <h2>Sign Up</h2>
        <form onSubmit={handleRegister}>
          <label>Username:</label><br />
          <input value={username} onChange={e => setUsername(e.target.value)} required /><br /><br />
          <label>Email:</label><br />
          <input type="email" value={email} onChange={e => setEmail(e.target.value)} required /><br /><br />
          <label>Password:</label><br />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} required /><br /><br />
          <button type="submit">Register</button>
        </form>
        <br /><hr /><br />
        <p>Already have an account? <a href="#" onClick={(e) => { e.preventDefault(); setStage('login'); setPassword(''); }}>Log in here</a></p>
      </PageShell>
    );
  }

  if (stage === 'verify') {
    return (
      <PageShell>
        <h2>Check Your Email</h2>
        <p>We've sent a 6-digit verification code to your email address.</p>
        <form onSubmit={handleVerify}>
          <label>Verification Code:</label><br />
          <input value={code} onChange={e => setCode(e.target.value)} required /><br /><br />
          <button type="submit">Verify &amp; Complete</button>
        </form>
      </PageShell>
    );
  }

  if (stage === 'login') {
    return (
      <PageShell>
        <h2>Login</h2>
        <form onSubmit={handleLogin}>
          <label>Username:</label><br />
          <input value={username} onChange={e => setUsername(e.target.value)} required /><br /><br />
          <label>Password:</label><br />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} required /><br /><br />
          <button type="submit">Log In</button>
        </form>
      </PageShell>
    );
  }

  if (stage === 'success') {
    return (
      <PageShell>
        <h2 style={{ color: 'green' }}>Registration Complete!</h2>
        <p>Your account has been successfully created and verified via PingOne.</p>
        <a href="#" onClick={(e) => { e.preventDefault(); setStage('login'); setPassword(''); setCode(''); }}>Click here to Log In</a>
      </PageShell>
    );
  }

  if (stage === 'dashboard') {
    return (
      <PageShell>
        <h2 style={{ color: 'blue' }}>Welcome to your Dashboard!</h2>
        <p>You have successfully authenticated. Here is your Access Token:</p>
        <pre style={{ background: '#eee', padding: 15, whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>{accessToken}</pre>
        <button onClick={reset}>Log Out (Return to Home)</button>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <h2 style={{ color: 'red' }}>Something went wrong</h2>
      <pre>{error}</pre>
      <button onClick={reset}>Try Again</button>
    </PageShell>
  );
}
