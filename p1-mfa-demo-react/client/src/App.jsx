import React, { useState } from 'react';

export default function App() {
  const [stage, setStage] = useState('login'); // login | mfa | done | error
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
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });
    const json = await resp.json();
    if (json.status === 'COMPLETED') {
      setAccessToken(json.accessToken);
      setStage('done');
    } else if (json.status === 'MFA_REQUIRED') {
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
      <div>
        <h2>Secure Login</h2>
        <form onSubmit={handleLogin}>
          <label>Username:</label><br />
          <input value={username} onChange={e => setUsername(e.target.value)} required /><br /><br />
          <label>Password:</label><br />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} required /><br /><br />
          <button type="submit">Log In</button>
        </form>
      </div>
    );
  }

  if (stage === 'mfa') {
    return (
      <div>
        <h2>Two-Factor Authentication</h2>
        <p>Please enter the verification code sent to your email.</p>
        <form onSubmit={handleMfa}>
          <label>MFA Code:</label><br />
          <input value={otp} onChange={e => setOtp(e.target.value)} required /><br /><br />
          <button type="submit">Verify</button>
        </form>
      </div>
    );
  }

  if (stage === 'done') {
    return (
      <div>
        <h2 style={{ color: 'green' }}>Login Successful!</h2>
        <p>You have securely authenticated. Here is your Access Token:</p>
        <pre style={{ background: '#eee', padding: 15, whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>{accessToken}</pre>
        <button onClick={reset}>Log Out</button>
      </div>
    );
  }

  return (
    <div>
      <h2 style={{ color: 'red' }}>Authentication Error</h2>
      <pre>{error}</pre>
      <button onClick={reset}>Try Again</button>
    </div>
  );
}
