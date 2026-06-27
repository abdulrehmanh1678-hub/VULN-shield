import React, { useEffect, useState } from 'react';
import { Clock, Trash2, X, Shield, ChevronRight, AlertTriangle } from 'lucide-react';
import { getHistory, getScan, deleteScan as removeScan } from '../lib/history';

const SEVERITY_COLORS = {
  Critical: 'var(--color-critical)', High: 'var(--color-high)',
  Medium: 'var(--color-medium)', Low: 'var(--color-low)', Secure: 'var(--color-info)'
};

export default function HistorySidebar({ onSelect, onClose, refresh }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    setLoading(true);
    try {
      setScans(getHistory());
    } catch {
      setError('Could not load history.');
    } finally {
      setLoading(false);
    }
  }, [refresh]);

  const deleteScan = (e, id) => {
    e.stopPropagation();
    removeScan(id);
    setScans(prev => prev.filter(s => s.id !== id));
  };

  const handleSelect = (scan) => {
    const full = getScan(scan.id);
    if (full) onSelect(full);
  };

  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: '320px',
      background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border-color)',
      zIndex: 50, display: 'flex', flexDirection: 'column', boxShadow: '-8px 0 32px rgba(0,0,0,0.5)'
    }}>
      {/* Header */}
      <div style={{ padding: '20px', borderBottom: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Clock size={16} style={{ color: 'var(--accent-primary)' }} />
          <h3 style={{ fontSize: '15px', fontWeight: 700 }}>Scan History</h3>
        </div>
        <button onClick={onClose} className="glass-panel" style={{ padding: '5px', cursor: 'pointer', borderRadius: '6px' }}>
          <X size={16} />
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px' }}>
        {loading && (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>Loading history...</div>
        )}
        {error && (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--color-critical)', fontSize: '13px' }}>{error}</div>
        )}
        {!loading && !error && scans.length === 0 && (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>
            <Shield size={32} style={{ opacity: 0.3, marginBottom: '8px' }} />
            <p>No scan history yet.</p>
          </div>
        )}
        {scans.map(scan => {
          const riskColor = SEVERITY_COLORS[scan.risk_label] || 'var(--text-muted)';
          const date = new Date(scan.created_at);
          return (
            <div key={scan.id} onClick={() => handleSelect(scan)} className="glass-panel-interactive" style={{ padding: '12px', marginBottom: '8px', cursor: 'pointer' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '6px' }}>
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  <p style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {scan.filename}
                  </p>
                  <p style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                    {date.toLocaleDateString()} {date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>
                <button onClick={e => deleteScan(e, scan.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '2px', flexShrink: 0 }}>
                  <Trash2 size={13} />
                </button>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span className={`badge badge-${scan.risk_label?.toLowerCase()}`} style={{ fontSize: '10px', padding: '2px 7px' }}>
                  {scan.risk_label}
                </span>
                <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>
                  {scan.total_vulnerabilities} vuln · {scan.language}
                </span>
                {scan.ai_generated ? (
                  <span style={{ fontSize: '9px', fontWeight: 600, color: 'var(--accent-primary)', letterSpacing: '0.3px' }}>AI</span>
                ) : (
                  <span style={{ fontSize: '9px', fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.3px' }}>STATIC</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
