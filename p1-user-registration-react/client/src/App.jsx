import React, { useState } from 'react';

export default function App() {
  // stages: signup | verify | login | success | dashboard | error
  const [stage, setStage] = useState('signup');
  const [error, setError] = useState('');
  const [accessToken, setAccessToken] = useState('');

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');

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
      <div>
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
      </div>
    );
  }

  if (stage === 'verify') {
    return (
      <div>
        <h2>Check Your Email</h2>
        <p>We've sent a 6-digit verification code to your email address.</p>
        <form onSubmit={handleVerify}>
          <label>Verification Code:</label><br />
          <input value={code} onChange={e => setCode(e.target.value)} required /><br /><br />
          <button type="submit">Verify &amp; Complete</button>
        </form>
      </div>
    );
  }

  if (stage === 'login') {
    return (
      <div>
        <h2>Login</h2>
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

  if (stage === 'success') {
    return (
      <div>
        <h2 style={{ color: 'green' }}>Registration Complete!</h2>
        <p>Your account has been successfully created and verified via PingOne.</p>
        <a href="#" onClick={(e) => { e.preventDefault(); setStage('login'); setPassword(''); setCode(''); }}>Click here to Log In</a>
      </div>
    );
  }

  if (stage === 'dashboard') {
    return (
      <div>
        <h2 style={{ color: 'blue' }}>Welcome to your Dashboard!</h2>
        <p>You have successfully authenticated. Here is your Access Token:</p>
        <pre style={{ background: '#eee', padding: 15, whiteSpace: 'pre-wrap', wordWrap: 'break-word' }}>{accessToken}</pre>
        <button onClick={reset}>Log Out (Return to Home)</button>
      </div>
    );
  }

  return (
    <div>
      <h2 style={{ color: 'red' }}>Something went wrong</h2>
      <pre>{error}</pre>
      <button onClick={reset}>Try Again</button>
    </div>
  );
}
