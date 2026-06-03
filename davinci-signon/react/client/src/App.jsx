/**
 * App.jsx — React UI for the PingOne DaVinci Sign-On workflow.
 *
 * All PingOne API calls are made by the Express backend (server/index.js).
 * This component shows a login form, POSTs credentials to /api/run, and
 * renders the step-by-step results returned as JSON.
 *
 * Three render stages:
 *   idle    — login form with username + password inputs
 *   loading — spinner / waiting message
 *   results — step cards + access token on success, or error detail on failure
 */
import React, { useState } from 'react';

const OK_COLOR  = '#0a7a0a';
const ERR_COLOR = '#b00020';

const styles = {
  h2: { marginBottom: 8 },
  description: { color: '#444', marginBottom: 24 },
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
  label: {
    display: 'block',
    marginBottom: 4,
    fontSize: 14,
    color: '#333',
  },
  input: {
    fontSize: 15,
    padding: '6px 8px',
    minWidth: 280,
    marginBottom: 14,
    display: 'block',
    border: '1px solid #ccc',
    borderRadius: 3,
  },
  submitBtn: {
    fontSize: 16,
    padding: '10px 20px',
    cursor: 'pointer',
    background: '#E1003B',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
  },
  loadingMsg: { color: '#555', fontStyle: 'italic', marginTop: 16 },
  banner: (ok) => ({
    padding: '10px 14px',
    marginBottom: 20,
    borderRadius: 4,
    background: ok ? '#e6f7e6' : '#fde8ea',
    color: ok ? OK_COLOR : ERR_COLOR,
    fontWeight: 600,
  }),
  tokenWrap: {
    marginTop: 16,
    marginBottom: 24,
  },
  tokenLabel: {
    fontSize: 13,
    color: '#555',
    marginBottom: 4,
  },
  tokenPre: {
    background: '#f4f4f4',
    padding: '10px 12px',
    borderLeft: '3px solid #888',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-all',
    margin: 0,
    fontSize: 12,
  },
  card: {
    marginTop: 18,
    padding: '12px 16px',
    border: '1px solid #ddd',
    borderRadius: 4,
    background: '#fafafa',
  },
  cardTitle: (ok) => ({
    margin: '0 0 6px 0',
    color: ok ? OK_COLOR : ERR_COLOR,
    fontSize: 15,
    fontWeight: 600,
  }),
  urlBadge: {
    display: 'inline-block',
    fontFamily: 'monospace',
    fontSize: 12,
    color: '#555',
    background: '#f0f0f0',
    padding: '3px 8px',
    borderRadius: 3,
    marginBottom: 6,
    wordBreak: 'break-all',
  },
  detail: { margin: '4px 0 0 0', fontSize: 14, color: '#333' },
  summary: { cursor: 'pointer', fontSize: 13, color: '#444', userSelect: 'none', padding: '2px 0' },
  pre: {
    background: '#f4f4f4',
    padding: '10px 12px',
    borderLeft: '3px solid #888',
    whiteSpace: 'pre-wrap',
    wordWrap: 'break-word',
    margin: '6px 0 0 0',
    fontSize: 12,
  },
  againBtn: {
    marginTop: 24,
    fontSize: 15,
    padding: '8px 20px',
    cursor: 'pointer',
    background: '#555',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
  },
};

/**
 * StepCard renders a single workflow step result as a card.
 *
 * collapsed=true (set by the backend for verbose responses) starts the
 * <details> element closed so the page does not overwhelm the reader.
 * The user can expand any card manually.
 */
function StepCard({ step }) {
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle(step.ok)}>
        {step.title} {step.ok ? '(ok)' : '(failed)'}
      </h3>
      {step.url    && <div style={styles.urlBadge}>{step.url}</div>}
      {step.detail && <p style={styles.detail}>{step.detail}</p>}
      {step.body   && (
        <details open={!step.collapsed}>
          <summary style={styles.summary}>Response</summary>
          <pre style={styles.pre}>{step.body}</pre>
        </details>
      )}
    </div>
  );
}

export default function App() {
  // stage controls which view is shown: idle (login form), loading (spinner),
  // or results (step cards + token / error).
  const [stage,    setStage]    = useState('idle');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [result,   setResult]   = useState(null);

  /**
   * signOn — submits the credentials to the Express backend, which drives the
   * full three-step DaVinci sign-on flow and returns { success, steps[], accessToken? }.
   */
  async function signOn(e) {
    e.preventDefault();
    setStage('loading');
    try {
      const resp = await fetch('/api/run', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ username, password }),
      });
      const json = await resp.json();
      setResult(json);
      setStage('results');
    } catch (err) {
      // Network-level error (server unreachable, JSON parse failure, etc.).
      setResult({
        success: false,
        steps: [{
          title:     'Network error',
          ok:        false,
          detail:    err.message,
          body:      '',
          url:       '',
          collapsed: false,
        }],
      });
      setStage('results');
    }
  }

  function reset() {
    setStage('idle');
    setResult(null);
    setPassword('');
  }

  // ── idle: login form ──────────────────────────────────────────────────────
  if (stage === 'idle') {
    return (
      <div>
        <header style={styles.header}>
          <img src="/logo.png" style={styles.logo} alt="Ping Identity" />
        </header>
        <div style={styles.pageWrap}>
          <h2 style={styles.h2}>DaVinci Sign-On Flow with PingOne Auth</h2>
          <p style={styles.description}>
            Sign in with credentials. The PingOne authorize endpoint hands the
            request to the assigned DaVinci flow policy; this app drives the flow
            to completion and exchanges the resulting code for a token.
          </p>
          <form onSubmit={signOn}>
            <label style={styles.label} htmlFor="username">Username:</label>
            <input
              id="username"
              type="text"
              style={styles.input}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
            />
            <label style={styles.label} htmlFor="password">Password:</label>
            <input
              id="password"
              type="password"
              style={styles.input}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
            <button type="submit" style={styles.submitBtn}>Sign On</button>
          </form>
        </div>
      </div>
    );
  }

  // ── loading ───────────────────────────────────────────────────────────────
  if (stage === 'loading') {
    return (
      <div>
        <header style={styles.header}>
          <img src="/logo.png" style={styles.logo} alt="Ping Identity" />
        </header>
        <div style={styles.pageWrap}>
          <h2 style={styles.h2}>DaVinci Sign-On Flow with PingOne Auth</h2>
          <p style={styles.loadingMsg}>Signing in, please wait...</p>
        </div>
      </div>
    );
  }

  // ── results ───────────────────────────────────────────────────────────────
  return (
    <div>
      <header style={styles.header}>
        <img src="/logo.png" style={styles.logo} alt="Ping Identity" />
      </header>
      <div style={styles.pageWrap}>
        <h2 style={styles.h2}>Sign-On Result</h2>
        <div style={styles.banner(result.success)}>
          {result.success ? 'Sign-on successful.' : 'Sign-on failed.'}
        </div>

        {result.success && result.accessToken && (
          <div style={styles.tokenWrap}>
            <div style={styles.tokenLabel}>Access token:</div>
            <pre style={styles.tokenPre}>{result.accessToken}</pre>
          </div>
        )}

        {result.steps.map((step, i) => (
          <StepCard key={i} step={step} />
        ))}

        <button style={styles.againBtn} onClick={reset}>Sign In Again</button>
      </div>
    </div>
  );
}
