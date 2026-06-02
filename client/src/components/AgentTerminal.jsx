import React from 'react';
import { Terminal, Shield, Play, Settings, Check } from 'lucide-react';

export default function AgentTerminal({ logs = [] }) {
  if (logs.length === 0) return null;

  return (
    <div className="glass-panel" style={{ 
      padding: '16px', 
      background: '#04060a', 
      border: '1px solid rgba(255, 255, 255, 0.05)',
      fontFamily: 'var(--font-mono)',
      fontSize: '12px',
      color: '#34d399',
      display: 'flex',
      flexDirection: 'column',
      gap: '8px'
    }}>
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between', 
        borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
        paddingBottom: '8px',
        color: 'var(--text-secondary)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Terminal size={14} style={{ color: 'var(--accent-primary)' }} />
          <span style={{ fontWeight: 600, fontSize: '11px', letterSpacing: '0.5px' }}>AGENT DECISION LOG</span>
        </div>
        <div style={{ display: 'flex', gap: '4px' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#ef4444' }} />
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#eab308' }} />
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22c55e' }} />
        </div>
      </div>

      <div style={{ 
        maxHeight: '160px', 
        overflowY: 'auto', 
        display: 'flex', 
        flexDirection: 'column', 
        gap: '6px',
        paddingRight: '4px'
      }}>
        {logs.map((log, idx) => {
          let stepColor = '#818cf8'; // indigo
          if (log.step.includes('COMPLETE') || log.step.includes('SUCCESS') || log.step.includes('FINISHED')) {
            stepColor = '#34d399'; // green
          } else if (log.step.includes('ERROR') || log.step.includes('FAIL')) {
            stepColor = '#f87171'; // red
          } else if (log.step.includes('ROUTING') || log.step.includes('DECISION')) {
            stepColor = '#c084fc'; // purple
          }

          return (
            <div key={idx} style={{ lineHeight: '1.4' }}>
              <span style={{ color: 'var(--text-muted)' }}>[{log.timestamp.split('T')[1].substring(0, 8)}]</span>{' '}
              <span style={{ color: stepColor, fontWeight: 600 }}>{log.step}</span>:{' '}
              <span style={{ color: '#e2e8f0' }}>{log.message}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
