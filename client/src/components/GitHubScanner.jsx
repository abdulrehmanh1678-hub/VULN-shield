import React, { useState } from 'react';
import { GitBranch, AlertCircle, Loader2, FileCode, Terminal } from 'lucide-react';
import { apiUrl } from '../api';

const SAMPLE_REPOS = [
  { label: 'DVWA (PHP vulnerable app)', url: 'https://github.com/digininja/DVWA' },
  { label: 'NodeGoat (Node.js vulns)', url: 'https://github.com/OWASP/NodeGoat' },
  { label: 'WebGoat (Java vulns)', url: 'https://github.com/WebGoat/WebGoat' }
];

export default function GitHubScanner({ onResults, isScanning, setIsScanning }) {
  const [repoUrl, setRepoUrl] = useState('');
  const [progress, setProgress] = useState([]);
  const [error, setError] = useState('');

  const runGitHubScan = async () => {
    if (!repoUrl.startsWith('https://github.com/')) {
      setError('Enter a valid public GitHub HTTPS URL.');
      return;
    }

    setIsScanning(true);
    setProgress([]);
    setError('');

    try {
      const res = await fetch(apiUrl('/api/github'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl })
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        setError(data.error || 'GitHub scan failed');
      } else {
        setProgress(data.progressLogs || []);
        onResults(data);
      }
    } catch (err) {
      setError('Could not reach the server. Make sure it is running on port 5000.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div>
        <h2 style={{ fontSize: '15px', fontWeight: 700 }}>GitHub Repository Scanner</h2>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Clone and scan any public repository for security vulnerabilities</p>
      </div>

      {/* URL Input */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}>Repository URL</label>
        <div style={{ display: 'flex', gap: '8px' }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <GitBranch size={15} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              type="text"
              value={repoUrl}
              onChange={e => { setRepoUrl(e.target.value); setError(''); }}
              placeholder="https://github.com/owner/repository"
              disabled={isScanning}
              style={{
                width: '100%', padding: '10px 12px 10px 34px',
                background: 'var(--bg-primary)', color: 'var(--text-primary)',
                border: `1px solid ${error ? 'var(--color-critical)' : 'var(--border-color)'}`,
                borderRadius: '8px', fontSize: '13px', fontFamily: 'var(--font-mono)',
                outline: 'none', transition: 'border-color 0.2s'
              }}
              onFocus={e => e.target.style.borderColor = 'var(--accent-primary)'}
              onBlur={e => e.target.style.borderColor = error ? 'var(--color-critical)' : 'var(--border-color)'}
            />
          </div>
        </div>
      </div>

      {/* Sample repos */}
      <div>
        <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '6px' }}>Try a known vulnerable repository:</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
          {SAMPLE_REPOS.map(repo => (
            <button key={repo.url} onClick={() => setRepoUrl(repo.url)} className="glass-panel" style={{ padding: '7px 12px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', textAlign: 'left', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileCode size={12} style={{ color: 'var(--accent-primary)', flexShrink: 0 }} />
              <span style={{ color: 'var(--text-secondary)' }}>{repo.label}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '10px', fontFamily: 'var(--font-mono)', marginLeft: 'auto' }}>{repo.url.split('/').slice(-1)[0]}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-critical)', fontSize: '12px', padding: '10px', background: 'rgba(239,68,68,0.07)', borderRadius: '8px' }}>
          <AlertCircle size={13} /> {error}
        </div>
      )}

      {/* Progress */}
      {isScanning && (
        <div style={{ background: '#04060a', border: '1px solid var(--border-color)', borderRadius: '10px', padding: '12px', maxHeight: '150px', overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#34d399' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', color: '#c084fc' }}>
            <Loader2 size={12} className="animate-spin" /> Cloning and scanning repository...
          </div>
          {progress.map((log, i) => (
            <div key={i} style={{ color: '#e2e8f0', lineHeight: 1.6 }}>
              <span style={{ color: '#6366f1' }}>[{log.step}]</span> {log.message}
            </div>
          ))}
        </div>
      )}

      {/* Warning */}
      <div style={{ padding: '10px 12px', background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)', borderRadius: '8px', fontSize: '11px', color: 'var(--color-medium)' }}>
        ⚠ Only public repositories are supported. Scanning may take 1–3 minutes depending on repo size.
      </div>

      <button onClick={runGitHubScan} disabled={isScanning || !repoUrl} className="btn-primary" style={{ width: '100%' }}>
        {isScanning ? <><Loader2 size={16} className="animate-spin" /> Cloning & Scanning...</> : <><GitBranch size={16} /> Scan Repository</>}
      </button>
    </div>
  );
}
