import React, { useState, useMemo } from 'react';
import {
  ShieldAlert, ShieldCheck, ChevronDown, ChevronUp, AlertCircle, FileCode,
  CheckCircle2, Copy, Check, Search, ArrowDownWideNarrow, Rows3, FileDown, ExternalLink
} from 'lucide-react';
import { getVulnMeta, sortFindings, buildMarkdownReport, SEVERITY_ORDER } from '../lib/vulnMeta';
import { useToast } from './Toast';

const SEV_CONFIG = {
  Critical: { color: 'var(--color-critical)', activeBg: 'rgba(239,68,68,0.15)', border: 'rgba(239,68,68,0.5)' },
  High:     { color: 'var(--color-high)',     activeBg: 'rgba(249,115,22,0.15)', border: 'rgba(249,115,22,0.5)' },
  Medium:   { color: 'var(--color-medium)',   activeBg: 'rgba(234,179,8,0.15)',  border: 'rgba(234,179,8,0.5)' },
  Low:      { color: 'var(--color-low)',      activeBg: 'rgba(59,130,246,0.15)', border: 'rgba(59,130,246,0.5)' },
};

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <button onClick={handleCopy} className={`copy-btn ${copied ? 'copied' : ''}`}>
      {copied ? <><Check size={9} /> Copied</> : <><Copy size={9} /> Copy</>}
    </button>
  );
}

export default function ResultsViewer({ results }) {
  const notify = useToast();
  const [expandedIds, setExpandedIds] = useState(() => new Set());
  const [activeFilter, setActiveFilter] = useState('All');
  const [query, setQuery] = useState('');
  const [sortKey, setSortKey] = useState('severity');

  const findings = results?.findings || [];

  // Filter by severity chip + free-text search, then sort.
  // (Declared before the early return so hook order stays stable across renders.)
  const visibleFindings = useMemo(() => {
    let list = activeFilter === 'All' ? findings : findings.filter(f => f.severity === activeFilter);
    const q = query.trim().toLowerCase();
    if (q) {
      list = list.filter(f =>
        [f.title, f.category, f.file, f.evidence, f.description]
          .filter(Boolean)
          .some(v => String(v).toLowerCase().includes(q))
      );
    }
    return sortFindings(list, sortKey);
  }, [findings, activeFilter, query, sortKey]);

  if (!results) {
    return (
      <div className="glass-panel" style={{ padding: '40px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
        <ShieldCheck size={48} style={{ color: 'var(--text-muted)', marginBottom: '12px' }} />
        <h3 style={{ marginBottom: '8px', fontWeight: 600 }}>No active scan</h3>
        <p style={{ color: 'var(--text-secondary)', textAlign: 'center', fontSize: '14px', maxWidth: '300px' }}>
          Paste code in the editor and click "Run Security Scan" to check for vulnerabilities.
        </p>
      </div>
    );
  }

  const { summary } = results;

  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const toggleExpand = (id) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const allExpanded = visibleFindings.length > 0 && visibleFindings.every(f => expandedIds.has(f.id));
  const toggleAll = () => {
    setExpandedIds(allExpanded ? new Set() : new Set(visibleFindings.map(f => f.id)));
  };

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(buildMarkdownReport(results));
      notify('Markdown report copied to clipboard', 'success');
    } catch {
      notify('Clipboard unavailable in this browser', 'error');
    }
  };

  const getSeverityBadgeClass = (severity) => {
    const map = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
    return map[severity.toLowerCase()] || 'badge-info';
  };

  // Highest CVSS across findings, for the summary card.
  const maxCvss = findings.reduce((m, f) => Math.max(m, f.cvss || 0), 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

      {/* Scan Summary Header */}
      <div className="glass-panel animate-fade-up" style={{ padding: '20px', background: 'var(--gradient-card)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', fontWeight: 700 }}>
            <ShieldAlert style={{ color: findings.length > 0 ? 'var(--color-critical)' : 'var(--color-info)' }} />
            Scan Results
          </h3>
          <button onClick={copyReport} className="copy-btn" title="Copy full report as Markdown">
            <FileDown size={11} /> Copy report
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(80px, 1fr))', gap: '12px', marginBottom: findings.length > 0 ? '14px' : 0 }}>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Language</div>
            <div style={{ fontSize: '15px', fontWeight: 600 }}>{summary.language || 'Unknown'}</div>
          </div>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Framework</div>
            <div style={{ fontSize: '15px', fontWeight: 600 }}>{summary.framework || 'None'}</div>
          </div>
          <div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Total Issues</div>
            <div style={{ fontSize: '22px', fontWeight: 700, color: findings.length > 0 ? 'var(--color-critical)' : 'var(--color-info)' }}>
              {summary.totalVulnerabilities}
            </div>
          </div>
          {findings.length > 0 && (
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Max CVSS</div>
              <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--color-high)' }}>{maxCvss.toFixed(1)}</div>
            </div>
          )}
        </div>

        {/* Severity distribution bar + badges */}
        {findings.length > 0 && (
          <>
            <div className="sev-distribution">
              {Object.keys(SEV_CONFIG).map(sev => {
                const count = severityCounts[sev] || 0;
                if (!count) return null;
                return (
                  <div
                    key={sev}
                    title={`${count} ${sev}`}
                    style={{ width: `${(count / findings.length) * 100}%`, background: SEV_CONFIG[sev].color }}
                  />
                );
              })}
            </div>
            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '12px' }}>
              {Object.keys(SEV_CONFIG).map(sev => {
                const count = severityCounts[sev] || 0;
                if (!count) return null;
                return (
                  <span key={sev} className={`badge badge-${sev.toLowerCase()}`}>
                    {count} {sev}
                  </span>
                );
              })}
            </div>
          </>
        )}
      </div>

      {findings.length === 0 ? (
        <div className="glass-panel animate-fade-up" style={{ padding: '32px', textAlign: 'center' }}>
          <ShieldCheck size={36} style={{ color: 'var(--color-info)', marginBottom: '8px' }} />
          <h4 style={{ color: 'var(--text-primary)', marginBottom: '4px' }}>No Vulnerabilities Found!</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>Static rules engine found no matching patterns.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>

          {/* Search + sort + expand toolbar */}
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div className="search-box">
              <Search size={13} />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search findings, files, evidence…"
              />
            </div>
            <div className="select-wrap">
              <ArrowDownWideNarrow size={13} />
              <select value={sortKey} onChange={e => setSortKey(e.target.value)}>
                <option value="severity">Severity</option>
                <option value="cvss">CVSS score</option>
                <option value="file">File name</option>
              </select>
            </div>
            <button onClick={toggleAll} className="filter-chip" style={{ display: 'flex', alignItems: 'center', gap: '5px', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>
              <Rows3 size={12} /> {allExpanded ? 'Collapse all' : 'Expand all'}
            </button>
          </div>

          {/* Severity filter chips */}
          <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Filter:</span>
            <button
              onClick={() => setActiveFilter('All')}
              className="filter-chip"
              style={{
                background: activeFilter === 'All' ? 'var(--bg-tertiary)' : 'transparent',
                color: activeFilter === 'All' ? 'var(--text-primary)' : 'var(--text-secondary)',
                border: `1px solid ${activeFilter === 'All' ? 'var(--border-color-active)' : 'var(--border-color)'}`,
              }}
            >
              All ({findings.length})
            </button>
            {Object.entries(SEV_CONFIG).map(([sev, cfg]) => {
              const count = severityCounts[sev] || 0;
              if (!count) return null;
              const isActive = activeFilter === sev;
              return (
                <button
                  key={sev}
                  onClick={() => setActiveFilter(isActive ? 'All' : sev)}
                  className="filter-chip"
                  style={{
                    background: isActive ? cfg.activeBg : 'transparent',
                    color: cfg.color,
                    border: `1px solid ${isActive ? cfg.border : 'rgba(255,255,255,0.1)'}`,
                  }}
                >
                  {sev} ({count})
                </button>
              );
            })}
          </div>

          {visibleFindings.length === 0 && (
            <div className="glass-panel" style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)', fontSize: '13px' }}>
              No findings match "{query}".
            </div>
          )}

          {/* Finding cards */}
          {visibleFindings.map((finding, index) => {
            const isExpanded = expandedIds.has(finding.id);
            const meta = getVulnMeta(finding);
            return (
              <div
                key={finding.id}
                className="glass-panel animate-fade-up"
                style={{
                  overflow: 'hidden',
                  borderLeft: `4px solid var(--color-${finding.severity.toLowerCase()})`,
                  padding: 0,
                  animationDelay: `${index * 40}ms`,
                }}
              >
                {/* Collapsible Header */}
                <div
                  onClick={() => toggleExpand(finding.id)}
                  style={{ padding: '14px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer', userSelect: 'none' }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity} · CVSS {finding.cvss || 'N/A'}
                      </span>
                      <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {finding.title}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                      <FileCode size={12} />
                      <span>{finding.file} : Line {finding.line}</span>
                      <span className="tag-pill">{meta.owasp}</span>
                      <span className="tag-pill">{meta.cwe}</span>
                    </div>
                  </div>
                  <div style={{ color: 'var(--text-secondary)', marginLeft: '10px' }}>
                    {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div style={{ padding: '18px 20px', borderTop: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '14px', background: 'var(--bg-code-deep)' }}>
                    <div>
                      <h5 style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px', letterSpacing: '0.5px' }}>DESCRIPTION</h5>
                      <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6 }}>{finding.description}</p>
                    </div>

                    <div>
                      <h5 style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-critical)', marginBottom: '4px', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <AlertCircle size={12} /> WHY IT IS DANGEROUS
                      </h5>
                      <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6 }}>{finding.danger}</p>
                    </div>

                    <div>
                      <h5 style={{ fontSize: '11px', fontWeight: 700, color: 'var(--color-info)', marginBottom: '4px', letterSpacing: '0.5px', display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <CheckCircle2 size={12} /> HOW TO FIX IT
                      </h5>
                      <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6, marginBottom: '8px' }}>{finding.fix}</p>

                      {finding.safeCode && (
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                            <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.5px' }}>REMEDIATION EXAMPLE</span>
                            <CopyButton text={finding.safeCode} />
                          </div>
                          <pre style={{ background: '#05070a', color: '#818cf8', padding: '12px', borderRadius: '8px', fontSize: '12px', fontFamily: 'var(--font-mono)', overflowX: 'auto', border: '1px solid rgba(255,255,255,0.05)' }}>
                            {finding.safeCode}
                          </pre>
                        </div>
                      )}
                    </div>

                    <div style={{ borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                        <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.5px' }}>EVIDENCE</span>
                        <CopyButton text={`${finding.line}: ${finding.evidence}`} />
                      </div>
                      <pre style={{ background: '#190a0a', color: '#f87171', padding: '8px 12px', borderRadius: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)', overflowX: 'auto', border: '1px solid rgba(239,68,68,0.1)' }}>
                        {finding.line}: {finding.evidence}
                      </pre>
                    </div>

                    <a href={meta.cweUrl} target="_blank" rel="noreferrer" className="ref-link">
                      <ExternalLink size={11} /> Learn more about {meta.cwe} on MITRE
                    </a>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
