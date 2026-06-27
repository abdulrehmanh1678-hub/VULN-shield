import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Terminal, RefreshCw, Clock, GitBranch, Upload,
  Download, FileJson, FileText, Trash2, ChevronRight, Cpu, Wifi, Sun, Moon, Settings, Cloud, Globe, Search, AlertCircle
} from 'lucide-react';
import { useToast } from './components/Toast';
import CodeEditor from './components/CodeEditor';
import ResultsViewer from './components/ResultsViewer';
import AIReportViewer from './components/AIReportViewer';
import ProgressTracker from './components/ProgressTracker';
import AgentTerminal from './components/AgentTerminal';
import HistorySidebar from './components/HistorySidebar';
import GitHubScanner from './components/GitHubScanner';
import FileUploader from './components/FileUploader';
import AISettings from './components/AISettings';
import { runScan as runScanEngine, scanFiles } from './lib/scanner';
import { scanHeaders } from './lib/headerScanner';
import { generateReport, checkAiEnabled } from './lib/report';
import { saveScan } from './lib/history';
import { exportJSON as downloadJSON, exportPDF as downloadPDF } from './lib/export';

const AGENT_STEPS = [
  { id: 'recon', label: 'Step 1: Reconnaissance', subtext: 'Detecting language and framework...' },
  { id: 'routing', label: 'Step 2: Module Routing', subtext: 'Selecting scanner modules...' },
  { id: 'scan', label: 'Step 3: Static Analysis', subtext: 'Running vulnerability rules...' },
  { id: 'ai', label: 'Step 4: AI Report Generation', subtext: 'Enriching findings with AI...' },
  { id: 'done', label: 'Step 5: Report Complete', subtext: 'Results ready.' }
];

const TABS = ['Code Editor', 'File Upload', 'GitHub Repo', 'Live URL'];

export default function App() {
  const notify = useToast();
  const [theme, setTheme] = useState(() => localStorage.getItem('vs-theme') || 'dark');
  const [activeTab, setActiveTab] = useState('Code Editor');
  const [code, setCode] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [serverOnline, setServerOnline] = useState(null);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiProvider, setAiProvider] = useState('static');
  const [showAiSettings, setShowAiSettings] = useState(false);
  const [activeReportTab, setActiveReportTab] = useState('findings');
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [scanDuration, setScanDuration] = useState(null);
  const scanStartRef = useRef(null);
  const runScanRef = useRef(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('vs-theme', theme);
  }, [theme]);

  const refreshAiStatus = () => {
    checkAiEnabled().then(({ enabled, provider }) => {
      setAiEnabled(enabled);
      setAiProvider(provider);
    });
  };

  useEffect(() => {
    // The scan engine runs entirely in the browser, so it is always "online".
    setServerOnline(true);
    refreshAiStatus();
  }, []);

  // Keyboard shortcut: Ctrl+Enter to scan
  useEffect(() => {
    runScanRef.current = () => {
      if (!isScanning && activeTab !== 'GitHub Repo') runScan();
    };
  });

  useEffect(() => {
    const handleKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        runScanRef.current?.();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  const runScan = async () => {
    setIsScanning(true);
    setCurrentStep(0);
    setScanResults(null);
    setError('');
    setScanDuration(null);
    scanStartRef.current = Date.now();

    try {
      let scan;
      let filename;

      if (activeTab === 'Live URL') {
        if (!targetUrl.trim()) { setError('Please enter a URL to scan (e.g. https://example.com).'); setIsScanning(false); return; }
        await delay(400); setCurrentStep(1);
        setCurrentStep(2);
        scan = await scanHeaders(targetUrl.trim());
        await delay(200); setCurrentStep(3);
        filename = scan.recon?.target?.finalUrl || targetUrl.trim();
      } else if (activeTab === 'File Upload') {
        if (uploadedFiles.length === 0) { setError('Please add at least one file to scan.'); setIsScanning(false); return; }
        await delay(500); setCurrentStep(1);
        const files = await Promise.all(uploadedFiles.map(async f => ({ name: f.name, code: await f.text() })));
        await delay(400); setCurrentStep(2);
        await delay(400); setCurrentStep(3);
        scan = scanFiles(files);
        filename = files.map(f => f.name).join(', ');
      } else {
        if (!code.trim()) { setError('Please paste some code first.'); setIsScanning(false); return; }
        await delay(500); setCurrentStep(1);
        await delay(400); setCurrentStep(2);
        await delay(400); setCurrentStep(3);
        scan = runScanEngine(code, 'pasted_code.js');
        filename = 'pasted_code.js';
      }

      // Step 4: AI report (serverless) with automatic static fallback.
      setCurrentStep(4);
      const { report, aiGenerated, verificationIssues } = await generateReport(scan);

      const results = { ...scan, filename, scanId: crypto.randomUUID(), aiReport: report, aiGenerated, verificationIssues };
      setScanResults(results);
      saveScan(results);
      setHistoryRefresh(h => h + 1);
      setScanDuration(((Date.now() - scanStartRef.current) / 1000).toFixed(1));

      const count = scan.findings?.length || 0;
      if (count === 0) notify('Scan complete — no vulnerabilities found', 'success');
      else notify(`Scan complete — ${count} issue${count > 1 ? 's' : ''} detected`, 'error');
    } catch (err) {
      setError('Scan failed: ' + (err.message || 'unknown error'));
      notify('Scan failed', 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const loadHistoryScan = (results) => {
    setScanResults(results);
    setActiveReportTab('findings');
    setShowHistory(false);
  };

  const exportPDF = () => { if (scanResults) downloadPDF(scanResults); };
  const exportJSON = () => { if (scanResults) downloadJSON(scanResults); };

  const clearAll = () => { setCode(''); setTargetUrl(''); setScanResults(null); setError(''); setCurrentStep(0); setUploadedFiles([]); setScanDuration(null); };

  return (
    <div className="app-container">
      <div className="glow-orb glow-orb-1" />
      <div className="glow-orb glow-orb-2" />

      {/* HEADER */}
      <header className="glass-panel" style={{ margin: '16px 16px 0', padding: '14px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', zIndex: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'var(--bg-tertiary)', padding: '8px', borderRadius: '8px', display: 'flex', border: '1px solid var(--border-color)' }}>
            <Shield size={20} color="var(--accent-primary)" />
          </div>
          <div>
            <h1 style={{ fontSize: '17px', fontWeight: 800, letterSpacing: '0.5px' }}>VULN<span className="text-gradient">SHIELD</span></h1>
            <p style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '-2px' }}>Find the flaw before the breach.</p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--color-info)', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Wifi size={12} /> Scan Engine Ready
          </span>
          <button
            onClick={() => setShowAiSettings(true)}
            title="Configure AI report engine (local Ollama / cloud / static)"
            style={{ fontSize: '11px', color: aiEnabled ? 'var(--accent-primary)' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '5px', background: 'transparent', border: 'none', cursor: 'pointer' }}
          >
            {aiProvider === 'ollama' ? <Cpu size={12} /> : aiProvider === 'serverless' ? <Cloud size={12} /> : <Cpu size={12} />}
            {aiProvider === 'ollama' ? 'AI: Local (Ollama)'
              : aiProvider === 'serverless' ? 'AI: Cloud'
              : aiEnabled ? 'AI Reports Active' : 'AI: Static Mode'}
            <Settings size={11} style={{ opacity: 0.6 }} />
          </button>
          <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className="glass-panel" title="Toggle theme" style={{ padding: '6px 10px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            {theme === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
          </button>
          <button onClick={() => setShowHistory(!showHistory)} className="glass-panel" style={{ padding: '6px 12px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Clock size={13} /> History
          </button>
          <button onClick={clearAll} className="glass-panel" style={{ padding: '6px 12px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <RefreshCw size={13} /> Clear
          </button>
        </div>
      </header>

      {/* AI ENGINE SETTINGS */}
      {showAiSettings && (
        <AISettings onClose={() => setShowAiSettings(false)} onSaved={refreshAiStatus} />
      )}

      {/* HISTORY SIDEBAR */}
      {showHistory && (
        <HistorySidebar
          refresh={historyRefresh}
          onSelect={loadHistoryScan}
          onClose={() => setShowHistory(false)}
        />
      )}

      {/* MAIN LAYOUT */}
      <main className="main-grid">

        {/* LEFT: Input Panel */}
        <div className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px', overflow: 'auto' }}>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: '4px', background: 'var(--bg-primary)', borderRadius: '10px', padding: '4px' }}>
            {TABS.map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)} style={{
                flex: 1, padding: '8px', borderRadius: '8px', border: 'none', cursor: 'pointer', fontSize: '12px', fontWeight: 600, fontFamily: 'var(--font-sans)',
                background: activeTab === tab ? 'var(--accent-primary)' : 'transparent',
                color: activeTab === tab ? '#04121a' : 'var(--text-secondary)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', transition: 'all 0.2s'
              }}>
                {tab === 'Code Editor' && <Terminal size={13} />}
                {tab === 'File Upload' && <Upload size={13} />}
                {tab === 'GitHub Repo' && <GitBranch size={13} />}
                {tab === 'Live URL' && <Globe size={13} />}
                {tab}
              </button>
            ))}
          </div>

          {/* Active Tab Content */}
          {activeTab === 'Code Editor' && (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <h2 style={{ fontSize: '15px', fontWeight: 700 }}>Source Code Analysis</h2>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Paste source code or load a sample to scan for vulnerabilities</p>
                </div>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', background: 'var(--bg-primary)', border: '1px solid var(--border-color)', padding: '3px 8px', borderRadius: '6px', flexShrink: 0 }}>
                  Ctrl+Enter
                </span>
              </div>
              <CodeEditor code={code} setCode={setCode} onScan={runScan} isScanning={isScanning} />
            </>
          )}

          {activeTab === 'File Upload' && (
            <>
              <div>
                <h2 style={{ fontSize: '15px', fontWeight: 700 }}>Multi-File Upload</h2>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Upload up to 10 source code files for batch scanning</p>
              </div>
              <FileUploader files={uploadedFiles} setFiles={setUploadedFiles} onScan={runScan} isScanning={isScanning} />
            </>
          )}

          {activeTab === 'Live URL' && (
            <>
              <div>
                <h2 style={{ fontSize: '15px', fontWeight: 700 }}>Live URL Security Headers</h2>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Scan a deployed site's HTTP response headers & cookies (CSP, HSTS, clickjacking, cookie flags) and get an A+–F grade.
                </p>
              </div>
              <form
                onSubmit={(e) => { e.preventDefault(); if (!isScanning) runScan(); }}
                style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}
              >
                <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                  <Globe size={15} style={{ position: 'absolute', left: '12px', color: 'var(--text-muted)' }} />
                  <input
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://example.com"
                    inputMode="url"
                    autoCapitalize="off"
                    spellCheck={false}
                    style={{
                      width: '100%', padding: '12px 12px 12px 36px', fontSize: '13px',
                      fontFamily: 'var(--font-mono)', background: 'var(--bg-primary)',
                      border: '1px solid var(--border-color)', borderRadius: '10px',
                      color: 'var(--text-primary)', outline: 'none'
                    }}
                  />
                </div>
                <button
                  type="submit"
                  disabled={isScanning}
                  style={{
                    padding: '12px', borderRadius: '10px', border: 'none', cursor: isScanning ? 'default' : 'pointer',
                    fontSize: '13px', fontWeight: 700, fontFamily: 'var(--font-sans)', color: 'white',
                    background: 'var(--gradient-accent)', opacity: isScanning ? 0.6 : 1,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px'
                  }}
                >
                  <Globe size={15} /> {isScanning ? 'Scanning…' : 'Scan Headers'}
                </button>
              </form>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Checks: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
                X-Content-Type-Options, Referrer-Policy, Permissions-Policy, version disclosure,
                and Secure / HttpOnly / SameSite cookie flags. Maps to OWASP A05 (Security Misconfiguration).
              </div>
            </>
          )}

          {activeTab === 'GitHub Repo' && (
            <GitHubScanner onResults={async (data) => {
              if (!data.success) return;
              const { report, aiGenerated, verificationIssues } = await generateReport(data);
              const results = { ...data, filename: data.repoUrl, scanId: crypto.randomUUID(), aiReport: report, aiGenerated, verificationIssues };
              setScanResults(results);
              saveScan(results);
              setHistoryRefresh(h => h + 1);
            }} isScanning={isScanning} setIsScanning={setIsScanning} />
          )}
        </div>

        {/* RIGHT: Results Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', overflow: 'auto' }}>

          {/* Progress */}
          {isScanning && activeTab !== 'GitHub Repo' && (
            <ProgressTracker steps={AGENT_STEPS} currentStep={currentStep} />
          )}

          {/* Error */}
          {error && (
            <div className="glass-panel" style={{ padding: '14px 16px', borderLeft: '3px solid var(--color-critical)', background: 'rgba(255,95,87,0.06)', display: 'flex', alignItems: 'center', gap: '9px' }}>
              <AlertCircle size={15} style={{ color: 'var(--color-critical)', flexShrink: 0 }} />
              <p style={{ color: 'var(--color-critical)', fontWeight: 600, fontSize: '13px' }}>{error}</p>
            </div>
          )}

          {/* Results with sub-tabs */}
          {scanResults && (
            <>
              {/* Export buttons + scan duration */}
              {scanResults.scanId && (
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <button onClick={exportPDF} className="glass-panel" style={{ padding: '7px 14px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px', flex: 1, justifyContent: 'center' }}>
                    <FileText size={13} /> Export PDF
                  </button>
                  <button onClick={exportJSON} className="glass-panel" style={{ padding: '7px 14px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px', flex: 1, justifyContent: 'center' }}>
                    <FileJson size={13} /> Export JSON
                  </button>
                  {scanDuration && (
                    <span className="stat-pill" style={{ flexShrink: 0 }}>
                      <Clock size={11} /> {scanDuration}s
                    </span>
                  )}
                </div>
              )}

              {/* Sub-tabs: Findings | AI Report | Agent Log */}
              <div style={{ display: 'flex', gap: '4px', background: 'var(--bg-primary)', borderRadius: '9px', padding: '4px', border: '1px solid var(--border-color)' }}>
                {[
                  { id: 'findings', label: 'Findings', icon: <Search size={12} /> },
                  { id: 'ai_report', label: 'AI Report', icon: <Cpu size={12} /> },
                  { id: 'agent_log', label: 'Agent Log', icon: <Terminal size={12} /> },
                ].map(t => (
                  <button key={t.id} onClick={() => setActiveReportTab(t.id)} style={{
                    flex: 1, padding: '7px', borderRadius: '6px', border: 'none', cursor: 'pointer',
                    fontSize: '11px', fontWeight: 600, fontFamily: 'var(--font-sans)',
                    background: activeReportTab === t.id ? 'var(--bg-tertiary)' : 'transparent',
                    color: activeReportTab === t.id ? 'var(--text-primary)' : 'var(--text-muted)',
                    transition: 'all 0.15s', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '5px'
                  }}>
                    {t.icon} {t.label}
                  </button>
                ))}
              </div>

              {activeReportTab === 'findings' && <ResultsViewer results={scanResults} />}
              {activeReportTab === 'ai_report' && <AIReportViewer report={scanResults.aiReport} aiGenerated={scanResults.aiGenerated} verificationIssues={scanResults.verificationIssues} />}
              {activeReportTab === 'agent_log' && <AgentTerminal logs={scanResults.agentLogs || []} />}
            </>
          )}

          {!scanResults && !isScanning && !error && (
            <div className="glass-panel" style={{ padding: '40px 36px', display: 'flex', flexDirection: 'column', alignItems: 'flex-start', justifyContent: 'center', textAlign: 'left' }}>
              <span className="mono-label" style={{ display: 'inline-flex', alignItems: 'center', gap: '7px', marginBottom: '20px' }}>
                <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'var(--accent-primary)' }} />
                OWASP-aligned · 13 rules · AI-verified
              </span>
              <h3 style={{ fontWeight: 600, marginBottom: '14px', fontSize: '28px', lineHeight: 1.12, letterSpacing: '-0.03em', maxWidth: '360px' }}>
                Catch the vulnerability <span style={{ color: 'var(--accent-primary)' }}>before it ships.</span>
              </h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '13.5px', maxWidth: '380px', marginBottom: '28px', lineHeight: 1.65 }}>
                VulnShield audits your code the way an attacker would, then hands you fix-it-today remediation — not raw scanner noise.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', width: '100%', maxWidth: '420px' }}>
                {[
                  { icon: <Terminal size={15} />, title: '13 Vuln Rules', desc: 'SQLi, XSS, SSRF & more' },
                  { icon: <Globe size={15} />, title: 'Live URL Scan', desc: 'Headers, cookies & grade' },
                  { icon: <GitBranch size={15} />, title: 'GitHub Scan', desc: 'Audit any public repo' },
                  { icon: <Cpu size={15} />, title: 'AI Reports', desc: 'Risk scoring & remediation' },
                ].map((f, i) => (
                  <div key={i} className="feature-card">
                    <span style={{ color: 'var(--accent-primary)' }}>{f.icon}</span>
                    <div style={{ textAlign: 'left' }}>
                      <div style={{ fontSize: '12px', fontWeight: 600 }}>{f.title}</div>
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{f.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </main>

      <footer style={{ padding: '12px 16px', textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)', borderTop: '1px solid var(--border-color)' }}>
        VulnShield v2.0 — Find the flaw before the attacker does · OWASP-aligned static + live-URL analysis
      </footer>
    </div>
  );
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
