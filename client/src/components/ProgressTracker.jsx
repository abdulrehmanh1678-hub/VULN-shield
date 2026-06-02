import React from 'react';
import { Loader2, CheckCircle2, Circle, Eye, Database, Cpu } from 'lucide-react';

export default function ProgressTracker({ steps = [], currentStep = 0 }) {
  if (steps.length === 0) return null;

  const calculatePercentage = () => {
    return Math.round((currentStep / (steps.length - 1)) * 100);
  };

  const getStepIcon = (status, StepIcon) => {
    switch (status) {
      case 'completed':
        return <CheckCircle2 size={18} style={{ color: 'var(--color-info)' }} />;
      case 'active':
        return <Loader2 size={18} className="animate-spin" style={{ color: 'var(--accent-primary)' }} />;
      default:
        return <Circle size={18} style={{ color: 'var(--text-muted)' }} />;
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h4 style={{ fontWeight: 600, fontSize: '15px' }}>Agent Workflow Status</h4>
        <span style={{ fontSize: '13px', color: 'var(--text-secondary)', fontWeight: 500 }}>
          {calculatePercentage()}% Complete
        </span>
      </div>

      {/* Progress Bar */}
      <div className="progress-bar-container">
        <div 
          className="progress-bar-fill" 
          style={{ width: `${calculatePercentage()}%` }}
        />
      </div>

      {/* Steps List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '4px' }}>
        {steps.map((step, idx) => {
          const isActive = idx === currentStep;
          const isCompleted = idx < currentStep;
          let status = 'pending';
          if (isActive) status = 'active';
          if (isCompleted) status = 'completed';

          return (
            <div 
              key={step.id} 
              style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '12px',
                opacity: status === 'pending' ? 0.5 : 1,
                transition: 'opacity var(--transition-normal)'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center' }}>
                {getStepIcon(status, step.icon)}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ 
                  fontSize: '14px', 
                  fontWeight: isActive ? 600 : 400, 
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)'
                }}>
                  {step.label}
                </span>
                {isActive && step.subtext && (
                  <span style={{ fontSize: '11px', color: 'var(--accent-primary)', marginTop: '2px' }}>
                    {step.subtext}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
