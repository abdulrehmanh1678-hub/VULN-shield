import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Terminal, RefreshCw, Clock, GitBranch, Upload,
  Download, FileJson, FileText, Trash2, ChevronRight, Cpu, Wifi, Sun, Moon
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
import { runScan as runScanEngine, scanFiles } from './lib/scanner';
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

const TABS = ['Code Editor', 'File Upload', 'GitHub Repo'];

export default function App() {
  const notify = useToast();
  const [theme, setTheme] = useState(() => localStorage.getItem('vs-theme') || 'dark');
  const [activeTab, setActiveTab] = useState('Code Editor');
  const [code, setCode] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [serverOnline, setServerOnline] = useState(null);
  const [aiEnabled, setAiEnabled] = useState(false);
  const [activeReportTab, setActiveReportTab] = useState('findings');
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [scanDuration, setScanDuration] = useState(null);
  const scanStartRef = useRef(null);
  const runScanRef = useRef(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('vs-theme', theme);
  }, [theme]);

  useEffect(() => {
    // The scan engine runs entirely in the browser, so it is always "online".
    setServerOnline(true);
    checkAiEnabled().then(setAiEnabled);
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

      if (activeTab === 'File Upload') {
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
      const { report, aiGenerated } = await generateReport(scan);

      const results = { ...scan, filename, scanId: crypto.randomUUID(), aiReport: report, aiGenerated };
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

  const clearAll = () => { setCode(''); setScanResults(null); setError(''); setCurrentStep(0); setUploadedFiles([]); setScanDuration(null); };

  return (
    <div className="app-container">
      <div className="glow-orb glow-orb-1" />
      <div className="glow-orb glow-orb-2" />

      {/* HEADER */}
      <header className="glass-panel" style={{ margin: '16px 16px 0', padding: '14px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', zIndex: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'var(--gradient-accent)', padding: '8px', borderRadius: '10px', display: 'flex' }}>
            <Shield size={20} color="white" />
          </div>
          <div>
            <h1 style={{ fontSize: '17px', fontWeight: 800, letterSpacing: '0.5px' }}>VULN<span className="text-gradient">SHIELD</span></h1>
            <p style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '-2px' }}>AI-Powered Agentic Security Scanner</p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--color-info)', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Wifi size={12} /> Scan Engine Ready
          </span>
          <span style={{ fontSize: '11px', color: aiEnabled ? '#c084fc' : 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '5px' }}>
            <Cpu size={12} /> {aiEnabled ? 'AI Reports Active' : 'AI: Static Mode'}
          </span>
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
                background: activeTab === tab ? 'var(--gradient-accent)' : 'transparent',
                color: activeTab === tab ? 'white' : 'var(--text-secondary)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', transition: 'all 0.2s'
              }}>
                {tab === 'Code Editor' && <Terminal size={13} />}
                {tab === 'File Upload' && <Upload size={13} />}
                {tab === 'GitHub Repo' && <GitBranch size={13} />}
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

          {activeTab === 'GitHub Repo' && (
            <GitHubScanner onResults={async (data) => {
              if (!data.success) return;
              const { report, aiGenerated } = await generateReport(data);
              const results = { ...data, filename: data.repoUrl, scanId: crypto.randomUUID(), aiReport: report, aiGenerated };
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
            <div className="glass-panel" style={{ padding: '16px', borderLeft: '4px solid var(--color-critical)', background: 'rgba(239, 68, 68, 0.05)' }}>
              <p style={{ color: 'var(--color-critical)', fontWeight: 600, fontSize: '13px' }}>⚠ {error}</p>
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
                      ⏱ {scanDuration}s
                    </span>
                  )}
                </div>
              )}

              {/* Sub-tabs: Findings | AI Report | Agent Log */}
              <div style={{ display: 'flex', gap: '4px', background: 'var(--bg-primary)', borderRadius: '10px', padding: '4px' }}>
                {['findings', 'ai_report', 'agent_log'].map(t => (
                  <button key={t} onClick={() => setActiveReportTab(t)} style={{
                    flex: 1, padding: '7px', borderRadius: '7px', border: 'none', cursor: 'pointer',
                    fontSize: '11px', fontWeight: 600, fontFamily: 'var(--font-sans)',
                    background: activeReportTab === t ? 'var(--bg-tertiary)' : 'transparent',
                    color: activeReportTab === t ? 'var(--text-primary)' : 'var(--text-muted)',
                    transition: 'all 0.2s'
                  }}>
                    {t === 'findings' ? '🔍 Findings' : t === 'ai_report' ? '🤖 AI Report' : '🖥 Agent Log'}
                  </button>
                ))}
              </div>

              {activeReportTab === 'findings' && <ResultsViewer results={scanResults} />}
              {activeReportTab === 'ai_report' && <AIReportViewer report={scanResults.aiReport} aiGenerated={scanResults.aiGenerated} />}
              {activeReportTab === 'agent_log' && <AgentTerminal logs={scanResults.agentLogs || []} />}
            </>
          )}

          {!scanResults && !isScanning && !error && (
            <div className="glass-panel" style={{ padding: '48px 32px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
              <Shield size={52} style={{ color: 'var(--accent-primary)', marginBottom: '16px', opacity: 0.85 }} />
              <h3 style={{ fontWeight: 700, marginBottom: '8px', fontSize: '17px' }}>Ready to Scan</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '13px', maxWidth: '300px', marginBottom: '24px' }}>
                Paste code, upload files, or enter a GitHub URL on the left to start the agentic security analysis.
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px', width: '100%', maxWidth: '380px' }}>
                {[
                  { icon: <Terminal size={15} />, title: '8 Vuln Rules', desc: 'SQLi, XSS, secrets & more' },
                  { icon: <Cpu size={15} />, title: 'AI Reports', desc: 'Risk scoring & remediation' },
                  { icon: <GitBranch size={15} />, title: 'GitHub Scan', desc: 'Audit any public repo' },
                  { icon: <FileText size={15} />, title: 'PDF / JSON', desc: 'Exportable evidence' },
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
        VulnShield v2.0 — AI-Powered Security Analysis Platform • Portfolio Project
      </footer>
    </div>
  );
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
