/**
 * App.jsx — React UI shell for the PingOne Custom Admin Role workflow.
 *
 * All PingOne API calls are made by the Express backend (server/index.js).
 * This component simply POSTs to /api/run and renders the step-by-step
 * results returned as JSON. Three render stages: idle → loading → results.
 */
import React, { useState } from 'react';
import logoSrc from './logo.png';

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
 * collapsed=true (set by the backend for verbose responses like the
 * platform-roles list) starts the <details> element closed so the page
 * does not overwhelm the reader. The user can expand any card manually.
 */
function StepCard({ step }) {
  return (
    <div style={styles.card}>
      <h3 style={styles.cardTitle(step.ok)}>
        {step.title} {step.ok ? '(ok)' : '(failed)'}
      </h3>
      {step.url && <div style={styles.urlBadge}>{step.url}</div>}
      {step.detail && <p style={styles.detail}>{step.detail}</p>}
      {step.body && (
        <details open={!step.collapsed}>
          <summary style={styles.summary}>Response</summary>
          <pre style={styles.pre}>{step.body}</pre>
        </details>
      )}
    </div>
  );
}

export default function App() {
  // stage controls which view is shown: idle (start screen), loading (spinner),
  // or results (step cards + success/failure banner).
  const [stage, setStage]     = useState('idle');
  const [result, setResult]   = useState(null);

  // runWorkflow triggers the server-side workflow via POST /api/run.
  // The backend runs all PingOne API calls and returns { success, steps[] }.
  async function runWorkflow() {
    setStage('loading');
    try {
      const resp = await fetch('/api/run', { method: 'POST' });
      const json = await resp.json();
      setResult(json);
      setStage('results');
    } catch (err) {
      // Network-level error (server unreachable, JSON parse failure, etc.).
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
        <header style={styles.header}>
          <img src={logoSrc} style={styles.logo} alt="Ping Identity" />
        </header>
        <div style={styles.pageWrap}>
          <h2 style={styles.h2}>Custom Admin Role Workflow</h2>
          <p style={styles.description}>
            Creates a trimmed-down application admin role, assigns it to a group scoped to a population,
            registers a user into that population, and verifies the inherited role assignment.
          </p>
          <button style={styles.runBtn} onClick={runWorkflow}>Run Workflow</button>
        </div>
      </div>
    );
  }

  if (stage === 'loading') {
    return (
      <div>
        <header style={styles.header}>
          <img src={logoSrc} style={styles.logo} alt="Ping Identity" />
        </header>
        <div style={styles.pageWrap}>
          <h2 style={styles.h2}>Custom Admin Role Workflow</h2>
          <p style={styles.loadingMsg}>Running workflow, please wait...</p>
        </div>
      </div>
    );
  }

  // results stage
  return (
    <div>
      <header style={styles.header}>
        <img src={logoSrc} style={styles.logo} alt="Ping Identity" />
      </header>
      <div style={styles.pageWrap}>
        <h2 style={styles.h2}>Workflow Result</h2>
        <div style={styles.banner(result.success)}>
          {result.success ? 'All steps completed successfully.' : 'Workflow halted on error.'}
        </div>
        {result.steps.map((step, i) => (
          <StepCard key={i} step={step} />
        ))}
        <button style={styles.againBtn} onClick={reset}>Run Again</button>
      </div>
    </div>
  );
}
