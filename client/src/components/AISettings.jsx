import { useState } from 'react';
import { X, Server, Cpu, Cloud, Zap, CheckCircle2, Loader2, AlertCircle } from 'lucide-react';
import { getAiConfig, setAiConfig, checkOllama } from '../lib/aiConfig';
import { useToast } from './Toast';

const PROVIDERS = [
  { id: 'auto',       label: 'Auto',           desc: 'Use the cloud function if configured, otherwise local Ollama.', icon: Zap },
  { id: 'ollama',     label: 'Local · Ollama', desc: 'Fully offline. Runs a model (e.g. Qwen) on your own machine.',  icon: Cpu },
  { id: 'serverless', label: 'Cloud · OpenAI', desc: 'The Vercel serverless function backed by OPENAI_API_KEY.',     icon: Cloud },
  { id: 'static',     label: 'Static only',    desc: 'No LLM. Fast rule-based report with no external calls.',        icon: Server },
];

export default function AISettings({ onClose, onSaved }) {
  const notify = useToast();
  const init = getAiConfig();
  const [provider, setProvider] = useState(init.provider);
  const [ollamaUrl, setOllamaUrl] = useState(init.ollamaUrl);
  const [ollamaModel, setOllamaModel] = useState(init.ollamaModel);
  const [openaiKey, setOpenaiKey] = useState(init.openaiKey);
  const [openaiModel, setOpenaiModel] = useState(init.openaiModel);
  const [testing, setTesting] = useState(false);
  const [models, setModels] = useState(null);
  const [testError, setTestError] = useState('');

  const showOllama = provider === 'ollama' || provider === 'auto';
  const showOpenAI = provider === 'serverless' || provider === 'auto';

  const test = async () => {
    setTesting(true); setTestError(''); setModels(null);
    try {
      const list = await checkOllama(ollamaUrl);
      setModels(list);
      const has = list.some(m => m === ollamaModel || m.startsWith(`${ollamaModel}:`));
      if (list.length === 0) notify('Connected, but no models are pulled yet', 'error');
      else if (!has) notify(`Connected — but "${ollamaModel}" isn't pulled. Run: ollama pull ${ollamaModel}`, 'error');
      else notify('Ollama connected and model ready', 'success');
    } catch (e) {
      setTestError(e?.message || 'Could not reach Ollama');
    } finally {
      setTesting(false);
    }
  };

  const save = () => {
    setAiConfig({
      provider,
      ollamaUrl: ollamaUrl.trim(),
      ollamaModel: ollamaModel.trim(),
      openaiKey: openaiKey.trim(),
      openaiModel: openaiModel.trim() || 'gpt-4o-mini',
    });
    notify('AI settings saved', 'success');
    onSaved?.();
    onClose?.();
  };

  return (
    <div
      onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,12,0.6)', backdropFilter: 'blur(4px)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }}
    >
      <div
        className="glass-panel animate-fade-up"
        onClick={e => e.stopPropagation()}
        style={{ width: '100%', maxWidth: '480px', padding: '22px', maxHeight: '90vh', overflowY: 'auto' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700 }}>
            <Cpu size={18} style={{ color: 'var(--accent-primary)' }} /> AI Report Engine
          </h3>
          <button onClick={onClose} className="glass-panel" style={{ padding: '5px', cursor: 'pointer', borderRadius: '8px', display: 'flex' }}>
            <X size={15} />
          </button>
        </div>
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          Choose how AI security reports are generated. The vulnerability scan itself always runs locally in your browser.
        </p>

        {/* Provider choices */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '18px' }}>
          {PROVIDERS.map(p => {
            const Icon = p.icon;
            const active = provider === p.id;
            return (
              <button
                key={p.id}
                onClick={() => setProvider(p.id)}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: '10px', textAlign: 'left', padding: '12px',
                  borderRadius: '10px', cursor: 'pointer',
                  background: active ? 'rgba(80,227,194,0.1)' : 'var(--bg-primary)',
                  border: `1px solid ${active ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                }}
              >
                <Icon size={16} style={{ color: active ? 'var(--accent-primary)' : 'var(--text-secondary)', marginTop: '1px', flexShrink: 0 }} />
                <div>
                  <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>{p.label}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>{p.desc}</div>
                </div>
              </button>
            );
          })}
        </div>

        {/* Ollama configuration */}
        {showOllama && (
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px', marginBottom: '18px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: '0.5px', marginBottom: '10px' }}>
              LOCAL OLLAMA
            </div>
            <label style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Server URL</label>
            <input
              value={ollamaUrl}
              onChange={e => setOllamaUrl(e.target.value)}
              placeholder="http://localhost:11434"
              style={inputStyle}
            />
            <label style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '10px', display: 'block' }}>Model</label>
            <input
              value={ollamaModel}
              onChange={e => setOllamaModel(e.target.value)}
              placeholder="qwen2.5-coder"
              style={inputStyle}
            />
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '12px', flexWrap: 'wrap' }}>
              <button onClick={test} disabled={testing} className="filter-chip" style={{ display: 'flex', alignItems: 'center', gap: '6px', border: '1px solid var(--border-color)', color: 'var(--text-primary)', cursor: testing ? 'default' : 'pointer' }}>
                {testing ? <Loader2 size={12} className="spin" /> : <Zap size={12} />} Test connection
              </button>
              {models && (
                <span style={{ fontSize: '11px', color: 'var(--color-info)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <CheckCircle2 size={12} /> {models.length} model{models.length !== 1 ? 's' : ''} installed
                </span>
              )}
              {testError && (
                <span style={{ fontSize: '11px', color: 'var(--color-critical)', display: 'flex', alignItems: 'center', gap: '5px' }}>
                  <AlertCircle size={12} /> {testError}
                </span>
              )}
            </div>
            <p style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '10px', lineHeight: 1.5 }}>
              First time? Install Ollama, then run <code style={codeStyle}>ollama pull {ollamaModel || 'qwen2.5-coder'}</code>.
              If the browser is blocked by CORS, start Ollama with <code style={codeStyle}>OLLAMA_ORIGINS=*</code>.
            </p>
          </div>
        )}

        {/* OpenAI configuration */}
        {showOpenAI && (
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '16px', marginBottom: '18px' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', letterSpacing: '0.5px', marginBottom: '10px' }}>
              CLOUD · OPENAI
            </div>
            <label style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>API key</label>
            <input
              type="password"
              value={openaiKey}
              onChange={e => setOpenaiKey(e.target.value)}
              placeholder="sk-..."
              autoComplete="off"
              style={inputStyle}
            />
            <label style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '10px', display: 'block' }}>Model</label>
            <input
              value={openaiModel}
              onChange={e => setOpenaiModel(e.target.value)}
              placeholder="gpt-4o-mini"
              style={inputStyle}
            />
            <p style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '10px', lineHeight: 1.5 }}>
              Enter a key to call OpenAI directly — this works in local dev. The key is stored only in this
              browser (localStorage). Leave it blank to use the deployed Vercel serverless function instead
              (which keeps the key server-side). Get a key at <code style={codeStyle}>platform.openai.com/api-keys</code>.
            </p>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
          <button onClick={onClose} className="filter-chip" style={{ border: '1px solid var(--border-color)', color: 'var(--text-secondary)', cursor: 'pointer' }}>
            Cancel
          </button>
          <button onClick={save} className="glass-panel" style={{ padding: '7px 16px', fontSize: '12px', fontWeight: 600, cursor: 'pointer', borderRadius: '8px', background: 'var(--gradient-accent)', color: 'white', border: 'none' }}>
            Save
          </button>
        </div>
      </div>
    </div>
  );
}

const inputStyle = {
  width: '100%', marginTop: '4px', padding: '8px 10px', fontSize: '12px',
  fontFamily: 'var(--font-mono)', background: 'var(--bg-code-deep, #05070a)',
  color: 'var(--text-primary)', border: '1px solid var(--border-color)', borderRadius: '8px',
};
const codeStyle = {
  fontFamily: 'var(--font-mono)', background: 'var(--bg-primary)', padding: '1px 5px',
  borderRadius: '4px', color: 'var(--accent-primary)', fontSize: '10px',
};
