// App.jsx — React UI for the M2M Client Credentials + PingOne Protect demo.
//
// This component is a thin display shell. All PingOne protocol logic lives in
// the Express backend (server/index.js). The frontend's only job is to:
//   1. Present a "Run Flow" button.
//   2. POST to /api/run (no body needed — the server uses its own credentials).
//   3. Receive { success, steps[] } and render each step as a card.
//
// /api/run response shape:
//   {
//     success: boolean,       // true if all non-divider steps passed
//     steps: Step[]           // ordered list of workflow steps
//   }
//
// Step shape:
//   {
//     title:     string,      // displayed as the card heading
//     ok:        boolean,     // green (ok) or red (failed) heading
//     detail:    string,      // one-line explanation; may contain \n but no HTML
//     body:      string,      // pretty-printed JSON response (may be empty)
//     url:       string,      // "METHOD https://..." shown as monospace badge
//     collapsed: boolean,     // if true, <details> starts closed
//     divider?:  boolean      // if true, render as a section separator, not a card
//   }
//
// UI stages:
//   idle     — landing page with description and "Run Flow" button.
//   loading  — shown while the POST /api/run request is in flight.
//   results  — step cards plus a "Run Again" button.

import React, { useState } from 'react';
import logoSrc from './logo.png';

const OK_COLOR  = '#0a7a0a';
const ERR_COLOR = '#b00020';

const styles = {
  h2: { marginBottom: 8 },
  description: { color: '#444', marginBottom: 8, lineHeight: 1.6 },
  ul: { color: '#444', marginBottom: 16, lineHeight: 1.6 },
  configNote: { color: '#666', fontSize: 13, marginTop: 30 },
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
    maxWidth: 980,
    margin: '0 auto',
  },
  runBtn: {
    fontSize: 16,
    padding: '10px 24px',
    cursor: 'pointer',
    background: '#E1003B',
    color: '#fff',
    border: 'none',
    borderRadius: 4,
  },
  loadingMsg: { color: '#555', fontStyle: 'italic', marginTop: 16 },
  // banner color depends on overall success/failure of the run
  banner: (ok) => ({
    padding: '10px 14px',
    marginBottom: 20,
    borderRadius: 4,
    background: ok ? '#e6f7e6' : '#fde8ea',
    color: ok ? OK_COLOR : ERR_COLOR,
    fontWeight: 600,
  }),
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
  // urlBadge presents the "METHOD url" string in a monospace pill
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
  detail: { margin: '4px 0 0 0', fontSize: 14, color: '#333', whiteSpace: 'pre-wrap' },
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
  // divider renders as a dark-red bar between User A and User B sections
  divider: {
    marginTop: 30,
    marginBottom: 4,
    padding: '8px 14px',
    background: '#B8002F',
    color: '#fff',
    borderRadius: 4,
    fontWeight: 600,
    fontSize: 15,
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

// PingHeader is the branded top bar rendered on every page stage.
function PingHeader() {
  return (
    <header style={styles.header}>
      <img src={logoSrc} style={styles.logo} alt="Ping Identity" />
    </header>
  );
}

// StepCard renders one workflow step as a card.
//
// Steps with divider=true render as a dark-red section header (e.g.
// "User A — trusted"). Regular steps show:
//   - A green/red heading (title + ok/failed badge).
//   - An optional monospace URL badge.
//   - A detail paragraph (plain text, line breaks preserved).
//   - A collapsible <details> block with the raw JSON response body.
function StepCard({ step }) {
  if (step.divider) {
    return <div style={styles.divider}>{step.title}</div>;
  }
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle(step.ok)}>
        {step.title} {step.ok ? '(ok)' : '(failed)'}
      </h3>
      {step.url && <div style={styles.urlBadge}>{step.url}</div>}
      {step.detail && <p style={styles.detail}>{step.detail}</p>}
      {step.body && (
        // open={!step.collapsed} means collapsed=false → starts open (readable).
        // The JWKS step sets collapsed=true because the key list is verbose.
        <details open={!step.collapsed}>
          <summary style={styles.summary}>Response</summary>
          <pre style={styles.pre}>{step.body}</pre>
        </details>
      )}
    </div>
  );
}

// App is the root component. It manages three UI stages:
//   idle     — landing page with description and Run Flow button.
//   loading  — spinner/message while the server runs the workflow.
//   results  — step cards from /api/run plus a "Run Again" button.
export default function App() {
  const [stage, setStage]   = useState('idle');   // idle | loading | results
  const [result, setResult] = useState(null);     // WorkflowResponse | null

  // runWorkflow posts to /api/run and stores the step array for rendering.
  // No body is required — the server uses its own environment variables to
  // authenticate with PingOne. The browser never sees credentials.
  async function runWorkflow() {
    setStage('loading');
    try {
      const resp = await fetch('/api/run', { method: 'POST' });
      const json = await resp.json();
      setResult(json);
      setStage('results');
    } catch (err) {
      // Network-level errors (server unreachable, JSON parse failure) are
      // surfaced as a synthetic failed step so the UI remains consistent.
      setResult({
        success: false,
        steps: [{ title: 'Network error', ok: false, detail: err.message, body: '', url: '', collapsed: false }],
      });
      setStage('results');
    }
  }

  function reset() {
    setStage('idle');
    setResult(null);
  }

  if (stage === 'idle') {
    return (
      <div>
        <PingHeader />
        <div style={styles.pageWrap}>
          <h2 style={styles.h2}>OAuth 2.0 Client Credentials (M2M) + PingOne Protect</h2>
          <p style={styles.description}>
            This sample walks through the OAuth 2.0 <strong>client_credentials</strong> grant. There is no user, no
            browser redirect, and no PKCE. The client authenticates directly with the PingOne token endpoint using its
            own credentials, receives an access token, and calls <strong>PingOne Protect</strong> for two risk
            evaluations:
          </p>
          <ul style={styles.ul}>
            <li>
              <strong>User A — trusted:</strong> real client IP, <code>type=EXTERNAL</code> — expected to score LOW or
              MEDIUM, API call proceeds.
            </li>
            <li>
              <strong>User B — suspicious:</strong> Tor exit node IP (<code>185.220.101.1</code>),{' '}
              <code>type=ANONYMOUS</code> — expected to score HIGH via Anonymous Network Detection, API call blocked.
            </li>
          </ul>
          <p style={styles.description}>
            Both paths are rendered side-by-side so you can compare what PingOne Protect returns and see how the
            application gates the downstream call differently in each case.
          </p>
          <button style={styles.runBtn} onClick={runWorkflow}>Run Flow</button>
          <p style={styles.configNote}>
            PingOne config required: Worker application with Token Endpoint Auth Method = Client Secret Basic. The
            Worker app must have roles for Identity Data (read) and PingOne Protect (risk evaluation). A Protect risk
            policy set must exist with Anonymous Network Detection enabled and scored above the HIGH threshold; its ID
            goes in <code>PINGONE_RISK_POLICY_SET_ID</code>.
          </p>
        </div>
      </div>
    );
  }

  if (stage === 'loading') {
    return (
      <div>
        <PingHeader />
        <div style={styles.pageWrap}>
          <h2 style={styles.h2}>OAuth 2.0 Client Credentials (M2M) + PingOne Protect</h2>
          <p style={styles.loadingMsg}>Running workflow, please wait...</p>
        </div>
      </div>
    );
  }

  // results stage — render the step cards returned by /api/run
  return (
    <div>
      <PingHeader />
      <div style={styles.pageWrap}>
        {result.steps.map((step, i) => (
          <StepCard key={i} step={step} />
        ))}
        <button style={styles.againBtn} onClick={reset}>Run Again</button>
      </div>
    </div>
  );
}
