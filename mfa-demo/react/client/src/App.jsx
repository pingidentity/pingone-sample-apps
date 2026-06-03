// App.jsx — React UI shell for the PingOne MFA demo.
//
// This component manages the full user-facing flow through four stages:
//   login   — username/password form; submits to POST /api/login
//   mfa     — OTP entry form shown when the server responds MFA_REQUIRED;
//             submits to POST /api/mfa-verify
//   done    — success screen displaying the access token returned by the server
//   error   — error screen with a retry option
//
// All PingOne API logic lives in the Express backend (server/index.js). This
// component only drives the UI and interprets the two JSON responses:
//
//   POST /api/login returns:
//     { status: 'COMPLETED',   accessToken: '<jwt>' }  — no MFA, token ready
//     { status: 'MFA_REQUIRED' }                       — OTP sent, show mfa stage
//     { status: 'ERROR',       message: '...' }         — show error stage
//
//   POST /api/mfa-verify returns:
//     { status: 'COMPLETED',   accessToken: '<jwt>' }  — OTP accepted, token ready
//     { status: 'ERROR',       message: '...' }         — OTP rejected or expired
//
// credentials: 'include' is required on both fetch calls so the browser sends
// the httpOnly `sid` cookie that ties this client to its server-side session.
// Without it the server cannot look up the PingOne flow state between the
// login and MFA steps.

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

// PageShell wraps each stage in the shared header + centered content layout.
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
  // stage drives which screen is shown. Transitions:
  //   login → mfa    (server returns MFA_REQUIRED)
  //   login → done   (server returns COMPLETED without MFA)
  //   mfa   → done   (server returns COMPLETED after OTP)
  //   any   → error  (server returns ERROR)
  //   any   → login  (user clicks "Log Out" or "Try Again")
  const [stage, setStage] = useState('login');
  const [error, setError] = useState('');
  const [accessToken, setAccessToken] = useState('');

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');

  async function handleLogin(e) {
    e.preventDefault();
    setError('');
    const resp = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // credentials: 'include' sends the httpOnly `sid` session cookie so the
      // server can store PingOne flow state between the login and MFA steps.
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });
    const json = await resp.json();
    if (json.status === 'COMPLETED') {
      setAccessToken(json.accessToken);
      setStage('done');
    } else if (json.status === 'MFA_REQUIRED') {
      // PingOne has sent an OTP to the user's registered email device.
      // Show the OTP entry form while keeping the server-side session alive.
      setStage('mfa');
    } else {
      setError(json.message || 'Login failed');
      setStage('error');
    }
  }

  async function handleMfa(e) {
    e.preventDefault();
    setError('');
    const resp = await fetch('/api/mfa-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // credentials: 'include' sends the `sid` cookie so the server can
      // correlate this OTP submission with the PingOne flow started in /api/login.
      credentials: 'include',
      body: JSON.stringify({ otp }),
    });
    const json = await resp.json();
    if (json.status === 'COMPLETED') {
      setAccessToken(json.accessToken);
      setStage('done');
    } else {
      setError(json.message || 'MFA failed');
      setStage('error');
    }
  }

  function reset() {
    setStage('login');
    setError('');
    setUsername('');
    setPassword('');
    setOtp('');
    setAccessToken('');
  }

  if (stage === 'login') {
    return (
      <PageShell>
        <h2>Secure Login</h2>
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

  if (stage === 'mfa') {
    return (
      <PageShell>
        <h2>Two-Factor Authentication</h2>
        <p>Please enter the verification code sent to your email.</p>
        <form onSubmit={handleMfa}>
          <label>MFA Code:</label><br />
          <input value={otp} onChange={e => setOtp(e.target.value)} required /><br /><br />
          <button type="submit">Verify</button>
        </form>
      </PageShell>
    );
  }

  if (stage === 'done') {
    return (
      <PageShell>
        <h2 style={{ color: 'green' }}>Login Successful!</h2>
        <p>You have securely authenticated. Here is your Access Token:</p>
        <pre style={{ background: '#eee', padding: 15, whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>{accessToken}</pre>
        <button onClick={reset}>Log Out</button>
      </PageShell>
    );
  }

  // error stage
  return (
    <PageShell>
      <h2 style={{ color: 'red' }}>Authentication Error</h2>
      <pre>{error}</pre>
      <button onClick={reset}>Try Again</button>
    </PageShell>
  );
}
