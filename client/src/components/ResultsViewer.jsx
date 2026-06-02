import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, ChevronDown, ChevronUp, AlertCircle, FileCode, CheckCircle2 } from 'lucide-react';

export default function ResultsViewer({ results }) {
  const [expandedId, setExpandedId] = useState(null);

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

  const { summary, findings } = results;

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'badge-info';
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Scan Summary Header */}
      <div className="glass-panel" style={{ padding: '20px', background: 'var(--gradient-card)' }}>
        <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', fontWeight: 700 }}>
          <ShieldAlert style={{ color: findings.length > 0 ? 'var(--color-critical)' : 'var(--color-info)' }} />
          Scan Results
        </h3>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Detected Language</div>
            <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>{summary.language || 'Unknown'}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Detected Framework</div>
            <div style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>{summary.framework || 'None'}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Total Vulnerabilities</div>
            <div style={{ fontSize: '20px', fontWeight: 700, color: findings.length > 0 ? 'var(--color-critical)' : 'var(--color-info)' }}>
              {summary.totalVulnerabilities}
            </div>
          </div>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="glass-panel" style={{ padding: '32px', textAlign: 'center' }}>
          <ShieldCheck size={36} style={{ color: 'var(--color-info)', marginBottom: '8px' }} />
          <h4 style={{ color: 'var(--text-primary)', marginBottom: '4px' }}>No Vulnerabilities Found!</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>Static rules engine couldn't find any immediate match patterns.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <h4 style={{ color: 'var(--text-secondary)', fontSize: '14px', fontWeight: 500 }}>VULNERABILITIES DETECTED</h4>
          
          {findings.map((finding) => {
            const isExpanded = expandedId === finding.id;
            return (
              <div 
                key={finding.id} 
                className="glass-panel" 
                style={{ 
                  overflow: 'hidden', 
                  borderLeft: `4px solid var(--color-${finding.severity.toLowerCase()})`,
                  padding: '0'
                }}
              >
                {/* Expandable Header */}
                <div 
                  onClick={() => toggleExpand(finding.id)}
                  style={{ 
                    padding: '16px 20px', 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    cursor: 'pointer',
                    userSelect: 'none'
                  }}
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                      <span className={`badge ${getSeverityBadgeClass(finding.severity)}`}>
                        {finding.severity} (CVSS {finding.cvss || 'N/A'})
                      </span>
                      <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {finding.title}
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      <FileCode size={14} />
                      <span>{finding.file} : Line {finding.line}</span>
                    </div>
                  </div>
                  
                  <div style={{ color: 'var(--text-secondary)', marginLeft: '12px' }}>
                    {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div style={{ padding: '20px', borderTop: '1px solid var(--border-color)', display: 'flex', flexDirection: 'column', gap: '16px', background: '#0e111a' }}>
                    <div>
                      <h5 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>DESCRIPTION</h5>
                      <p style={{ fontSize: '14px', color: 'var(--text-primary)' }}>{finding.description}</p>
                    </div>

                    <div>
                      <h5 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-critical)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <AlertCircle size={14} /> WHY IT IS DANGEROUS
                      </h5>
                      <p style={{ fontSize: '14px', color: 'var(--text-primary)' }}>{finding.danger}</p>
                    </div>

                    <div>
                      <h5 style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-info)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <CheckCircle2 size={14} /> HOW TO FIX IT
                      </h5>
                      <p style={{ fontSize: '14px', color: 'var(--text-primary)', marginBottom: '10px' }}>{finding.fix}</p>
                      
                      {finding.safeCode && (
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>CODE REMEDIATION EXAMPLE:</div>
                          <pre style={{ 
                            background: '#05070a', 
                            color: '#818cf8', 
                            padding: '12px', 
                            borderRadius: '8px', 
                            fontSize: '13px', 
                            fontFamily: 'var(--font-mono)',
                            overflowX: 'auto',
                            border: '1px solid rgba(255, 255, 255, 0.05)'
                          }}>
                            {finding.safeCode}
                          </pre>
                        </div>
                      )}
                    </div>

                    <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '12px' }}>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>EVIDENCE:</span>
                      <pre style={{ 
                        background: '#190a0a', 
                        color: '#f87171', 
                        padding: '8px 12px', 
                        borderRadius: '6px', 
                        fontSize: '13px', 
                        fontFamily: 'var(--font-mono)',
                        overflowX: 'auto',
                        marginTop: '4px',
                        border: '1px solid rgba(239, 68, 68, 0.1)'
                      }}>
                        {finding.line}: {finding.evidence}
                      </pre>
                    </div>
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
