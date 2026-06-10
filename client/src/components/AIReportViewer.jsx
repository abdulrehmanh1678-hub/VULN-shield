import React from 'react';
import { ShieldAlert, ShieldCheck, Zap, CheckCircle2, AlertCircle, Lock, Target } from 'lucide-react';

export default function AIReportViewer({ report, aiGenerated }) {
  if (!report) {
    return (
      <div className="glass-panel" style={{ padding: '40px', textAlign: 'center' }}>
        <ShieldAlert size={40} style={{ color: 'var(--text-muted)', marginBottom: '12px', opacity: 0.4 }} />
        <p style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>No AI report available for this scan yet.</p>
      </div>
    );
  }

  const riskColors = {
    Critical: 'var(--color-critical)', High: 'var(--color-high)',
    Medium: 'var(--color-medium)', Low: 'var(--color-low)', Secure: 'var(--color-info)'
  };
  const riskColor = riskColors[report.riskLabel] || 'var(--accent-primary)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>

      {/* AI Badge */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '11px' }}>
        <span style={{ background: aiGenerated ? 'rgba(192, 132, 252, 0.15)' : 'rgba(99,102,241,0.15)', color: aiGenerated ? '#c084fc' : 'var(--accent-primary)', border: `1px solid ${aiGenerated ? 'rgba(192,132,252,0.3)' : 'rgba(99,102,241,0.3)'}`, padding: '3px 10px', borderRadius: '20px', fontWeight: 600 }}>
          {aiGenerated ? '🤖 AI Enhanced Report' : '⚙️ Static Analysis Report'}
        </span>
      </div>

      {/* Risk Score Card */}
      <div className="glass-panel animate-fade-up" style={{ padding: '20px', background: `linear-gradient(135deg, ${riskColor}12, transparent)`, borderLeft: `4px solid ${riskColor}`, display: 'flex', gap: '20px', alignItems: 'center' }}>
        <div style={{ textAlign: 'center', minWidth: '80px', flexShrink: 0 }}>
          <div style={{ fontSize: '46px', fontWeight: 800, color: riskColor, lineHeight: 1 }}>{report.riskScore ?? 'N/A'}</div>
          <div style={{ fontSize: '9px', color: 'var(--text-secondary)', marginTop: '4px', letterSpacing: '0.5px' }}>RISK SCORE</div>
          {report.riskScore != null && (
            <div className="risk-gauge-track" style={{ marginTop: '8px' }}>
              <div className="risk-gauge-fill" style={{ width: `${report.riskScore}%`, background: riskColor }} />
            </div>
          )}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '18px', fontWeight: 700, color: riskColor, marginBottom: '2px' }}>{report.riskLabel}</div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '10px' }}>{report.totalFindings} vulnerabilities identified</div>
          <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6 }}>{report.executiveSummary}</p>
        </div>
      </div>

      {/* Prioritized Actions */}
      {report.prioritizedActions?.length > 0 && (
        <div className="glass-panel animate-fade-up" style={{ padding: '16px', animationDelay: '80ms' }}>
          <h4 style={{ fontSize: '13px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-high)' }}>
            <Target size={15} /> Prioritized Remediation Actions
          </h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {report.prioritizedActions.map((action, i) => (
              <div key={i} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', padding: '8px 10px', borderRadius: '8px', background: 'var(--bg-primary)', fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                <span style={{ color: 'var(--accent-primary)', fontWeight: 700, minWidth: '16px' }}>{i + 1}.</span>
                <span>{action}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Architecture Recommendations */}
      {report.secureArchitectureRecommendations?.length > 0 && (
        <div className="glass-panel animate-fade-up" style={{ padding: '16px', animationDelay: '160ms' }}>
          <h4 style={{ fontSize: '13px', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--color-info)' }}>
            <Lock size={15} /> Secure Architecture Recommendations
          </h4>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {report.secureArchitectureRecommendations.map((rec, i) => (
              <li key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                <CheckCircle2 size={13} style={{ color: 'var(--color-info)', marginTop: '2px', flexShrink: 0 }} /> {rec}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Compliance Notes */}
      {report.complianceNotes && (
        <div className="glass-panel" style={{ padding: '14px', background: 'rgba(234, 179, 8, 0.05)', borderLeft: '4px solid var(--color-medium)' }}>
          <h4 style={{ fontSize: '12px', fontWeight: 700, color: 'var(--color-medium)', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <AlertCircle size={13} /> Compliance Notes
          </h4>
          <p style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.6 }}>{report.complianceNotes}</p>
        </div>
      )}
    </div>
  );
}
