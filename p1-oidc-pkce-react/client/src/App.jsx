import React, { useState, useEffect } from 'react';
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

function StepCard({ card }) {
  return (
    <div style={{ marginTop: 18, padding: '14px 16px', border: '1px solid #ddd', borderRadius: 4 }}>
      <h3 style={{ margin: '0 0 6px 0', color: card.ok ? '#0a7a0a' : '#b00020' }}>
        {card.title} {card.ok ? '(ok)' : '(failed)'}
      </h3>
      {card.url && (
        <div style={{ fontFamily: 'monospace', fontSize: 13, color: '#555', background: '#eef', padding: '4px 8px', borderRadius: 3, margin: '6px 0', wordBreak: 'break-all' }}>
          {card.url}
        </div>
      )}
      {card.detail && <div dangerouslySetInnerHTML={{ __html: card.detail }} />}
      {card.body && (
        <details open={!card.collapsed} style={{ marginTop: 6 }}>
          <summary style={{ cursor: 'pointer', fontSize: 13, color: '#444', userSelect: 'none' }}>
            {card.collapsed ? 'Show response' : 'Hide'}
          </summary>
          <pre style={{ background: '#f4f4f4', padding: 12, borderLeft: '3px solid #888', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
            {card.body}
          </pre>
        </details>
      )}
    </div>
  );
}

function CardList({ cards }) {
  return <div>{cards.map((c, i) => <StepCard key={i} card={c} />)}</div>;
}

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
  const [stage, setStage] = useState('start');
  const [prepareCards, setPrepareCards] = useState([]);
  const [authorizeURL, setAuthorizeURL] = useState('');
  const [callbackCards, setCallbackCards] = useState([]);
  const [refreshCards, setRefreshCards] = useState([]);
  const [hasRefreshToken, setHasRefreshToken] = useState(false);
  const [error, setError] = useState('');

  // On mount: check for callbackDone=1 in the URL
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('callbackDone') === '1') {
      setStage('loading-callback');
      fetch('/api/callback-result', { credentials: 'include' })
        .then(r => r.json())
        .then(data => {
          setPrepareCards(data.prepareCards || []);
          setCallbackCards(data.callbackCards || []);
          setHasRefreshToken(!!data.hasRefreshToken);
          history.replaceState(null, '', '/');
          setStage('callback-done');
        })
        .catch(err => {
          setError(err.message || 'Failed to load callback result');
          setStage('error');
        });
    } else if (params.get('callbackError') === '1') {
      history.replaceState(null, '', '/');
      setError('PingOne returned an error or state mismatch during callback. Check the server logs.');
      setStage('error');
    } else if (params.get('error') === 'nosession') {
      history.replaceState(null, '', '/');
      setError('No session found. Cookies may have been blocked.');
      setStage('error');
    }
  }, []);

  async function handleBeginLogin() {
    setStage('preparing');
    setError('');
    try {
      const resp = await fetch('/api/prepare', {
        method: 'POST',
        credentials: 'include',
      });
      if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
      const data = await resp.json();
      setPrepareCards(data.prepareCards || []);
      setAuthorizeURL(data.authorizeURL || '');
      setStage('prepared');
    } catch (err) {
      setError(err.message || 'Failed to prepare PKCE artifacts');
      setStage('error');
    }
  }

  async function handleRefresh() {
    setStage('refreshing');
    setError('');
    try {
      const resp = await fetch('/api/refresh', {
        method: 'POST',
        credentials: 'include',
      });
      if (!resp.ok) throw new Error(`Server error: ${resp.status}`);
      const data = await resp.json();
      setRefreshCards(data.refreshCards || []);
      setStage('refresh-done');
    } catch (err) {
      setError(err.message || 'Failed to use refresh token');
      setStage('error');
    }
  }

  function handleStartOver() {
    setPrepareCards([]);
    setAuthorizeURL('');
    setCallbackCards([]);
    setRefreshCards([]);
    setHasRefreshToken(false);
    setError('');
    setStage('start');
  }

  if (stage === 'start') {
    return (
      <PageShell>
        <h2>OIDC Authorization Code + PKCE (confidential client)</h2>
        <p>
          This sample walks through every artifact in the OIDC Authorization Code flow with PKCE so
          you can see exactly what each value is, how it&apos;s derived, and how it&apos;s validated.
        </p>
        <p>
          The client is <strong>confidential</strong> — the token endpoint is called with HTTP Basic
          auth (client ID + secret) AND the PKCE <code>code_verifier</code>.
        </p>
        <button
          onClick={handleBeginLogin}
          style={{ fontSize: 16, padding: '10px 20px', cursor: 'pointer', background: '#E1003B', color: '#fff', border: 'none', borderRadius: 4 }}
        >
          Begin Login
        </button>
        <p style={{ color: '#666', fontSize: 13, marginTop: 30 }}>
          PingOne config required: OIDC Web App with PKCE Enforcement = REQUIRED, Token Endpoint Auth
          Method = Client Secret Basic, redirect URI = http://localhost:3000/callback
        </p>
      </PageShell>
    );
  }

  if (stage === 'preparing') {
    return (
      <PageShell>
        <p>Preparing PKCE artifacts...</p>
      </PageShell>
    );
  }

  if (stage === 'prepared') {
    return (
      <PageShell>
        <h2>Step 1 — PKCE artifacts prepared</h2>
        <CardList cards={prepareCards} />
        <p style={{ marginTop: 24 }}>
          <a href={authorizeURL}>
            <button style={{ fontSize: 16, padding: '10px 20px', cursor: 'pointer', background: '#E1003B', color: '#fff', border: 'none', borderRadius: 4 }}>
              Continue to PingOne →
            </button>
          </a>
        </p>
      </PageShell>
    );
  }

  if (stage === 'loading-callback') {
    return (
      <PageShell>
        <p>Loading callback results...</p>
      </PageShell>
    );
  }

  if (stage === 'callback-done') {
    return (
      <PageShell>
        <h2>Prepare</h2>
        <CardList cards={prepareCards} />
        <h2 style={{ marginTop: 32 }}>Callback</h2>
        <CardList cards={callbackCards} />
        {hasRefreshToken && (
          <p style={{ marginTop: 24 }}>
            <button
              onClick={handleRefresh}
              style={{ fontSize: 16, padding: '10px 20px', cursor: 'pointer', background: '#E1003B', color: '#fff', border: 'none', borderRadius: 4 }}
            >
              Use refresh token →
            </button>
          </p>
        )}
        <p style={{ marginTop: 20 }}>
          <a href="#" onClick={e => { e.preventDefault(); handleStartOver(); }}>Start over</a>
        </p>
      </PageShell>
    );
  }

  if (stage === 'refreshing') {
    return (
      <PageShell>
        <p>Refreshing...</p>
      </PageShell>
    );
  }

  if (stage === 'refresh-done') {
    return (
      <PageShell>
        <h2>Refresh result</h2>
        <CardList cards={refreshCards} />
        <p style={{ marginTop: 20 }}>
          <a href="#" onClick={e => { e.preventDefault(); handleStartOver(); }}>Start over</a>
        </p>
      </PageShell>
    );
  }

  // error stage
  return (
    <PageShell>
      <h2 style={{ color: '#b00020' }}>Error</h2>
      <pre style={{ background: '#fff0f0', padding: 12, border: '1px solid #f00', borderRadius: 4 }}>
        {error}
      </pre>
      <button
        onClick={handleStartOver}
        style={{ fontSize: 16, padding: '10px 20px', cursor: 'pointer', marginTop: 12 }}
      >
        Start over
      </button>
    </PageShell>
  );
}
