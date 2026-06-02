import React, { useState, useEffect } from 'react';
import {
  Shield, Terminal, RefreshCw, Clock, GitBranch, Upload,
  Download, FileJson, FileText, Trash2, ChevronRight, Cpu, Wifi, WifiOff
} from 'lucide-react';
import CodeEditor from './components/CodeEditor';
import ResultsViewer from './components/ResultsViewer';
import AIReportViewer from './components/AIReportViewer';
import ProgressTracker from './components/ProgressTracker';
import AgentTerminal from './components/AgentTerminal';
import HistorySidebar from './components/HistorySidebar';
import GitHubScanner from './components/GitHubScanner';
import FileUploader from './components/FileUploader';
import { apiUrl } from './api';

const AGENT_STEPS = [
  { id: 'recon', label: 'Step 1: Reconnaissance', subtext: 'Detecting language and framework...' },
  { id: 'routing', label: 'Step 2: Module Routing', subtext: 'Selecting scanner modules...' },
  { id: 'scan', label: 'Step 3: Static Analysis', subtext: 'Running vulnerability rules...' },
  { id: 'ai', label: 'Step 4: AI Report Generation', subtext: 'Enriching findings with AI...' },
  { id: 'done', label: 'Step 5: Report Complete', subtext: 'Results ready.' }
];

const TABS = ['Code Editor', 'File Upload', 'GitHub Repo'];

export default function App() {
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

  // Check server health on mount
  useEffect(() => {
    fetch(apiUrl('/api/health'))
      .then(r => r.json())
      .then(data => { setServerOnline(true); setAiEnabled(data.aiEnabled); })
      .catch(() => setServerOnline(false));
  }, []);

  const runScan = async () => {
    setIsScanning(true);
    setCurrentStep(0);
    setScanResults(null);
    setError('');

    try {
      let response;
      await delay(600); setCurrentStep(1);
      await delay(600); setCurrentStep(2);

      if (activeTab === 'File Upload' && uploadedFiles.length > 0) {
        const formData = new FormData();
        uploadedFiles.forEach(f => formData.append('files', f));
        await delay(600); setCurrentStep(3);
        response = await fetch(apiUrl('/api/scan'), { method: 'POST', body: formData });
      } else {
        if (!code.trim()) { setError('Please paste some code first.'); setIsScanning(false); return; }
        await delay(600); setCurrentStep(3);
        response = await fetch(apiUrl('/api/scan'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, filename: 'pasted_code.js' })
        });
      }

      if (!response.ok) throw new Error(`Server error: ${response.status}`);
      const data = await response.json();

      await delay(400); setCurrentStep(4);
      if (data.success !== false) {
        setScanResults(data);
        setHistoryRefresh(h => h + 1);
      } else {
        setError(data.error || 'Scan failed');
      }
    } catch (err) {
      setError('Could not connect to the backend. Make sure the server is running on port 5000.');
    } finally {
      setIsScanning(false);
    }
  };

  const loadHistoryScan = (scan) => {
    if (scan.full_report) {
      const { scanResults: sr, aiReport: ar } = scan.full_report;
      setScanResults({ ...sr, aiReport: ar?.report, aiGenerated: ar?.aiGenerated, scanId: scan.id });
      setActiveReportTab('findings');
    }
    setShowHistory(false);
  };

  const exportPDF = () => {
    if (!scanResults?.scanId) return;
    window.open(apiUrl(`/api/export/${scanResults.scanId}/pdf`), '_blank');
  };

  const exportJSON = () => {
    if (!scanResults?.scanId) return;
    window.open(apiUrl(`/api/export/${scanResults.scanId}/json`), '_blank');
  };

  const clearAll = () => { setCode(''); setScanResults(null); setError(''); setCurrentStep(0); setUploadedFiles([]); };

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
          <span style={{ fontSize: '11px', color: serverOnline ? 'var(--color-info)' : 'var(--color-critical)', display: 'flex', alignItems: 'center', gap: '5px' }}>
            {serverOnline ? <Wifi size={12} /> : <WifiOff size={12} />}
            {serverOnline === null ? 'Connecting...' : serverOnline ? 'Server Online' : 'Server Offline'}
          </span>
          {aiEnabled && (
            <span style={{ fontSize: '11px', color: '#c084fc', display: 'flex', alignItems: 'center', gap: '5px' }}>
              <Cpu size={12} /> AI Reports Active
            </span>
          )}
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
      <main style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', padding: '16px', zIndex: 1, overflow: 'hidden' }}>

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
              <div>
                <h2 style={{ fontSize: '15px', fontWeight: 700 }}>Source Code Analysis</h2>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Paste source code or load a sample to scan for vulnerabilities</p>
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
            <GitHubScanner onResults={(data) => { setScanResults(data); setHistoryRefresh(h => h + 1); }} isScanning={isScanning} setIsScanning={setIsScanning} />
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
              {/* Export buttons */}
              {scanResults.scanId && (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button onClick={exportPDF} className="glass-panel" style={{ padding: '7px 14px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px', flex: 1, justifyContent: 'center' }}>
                    <FileText size={13} /> Export PDF
                  </button>
                  <button onClick={exportJSON} className="glass-panel" style={{ padding: '7px 14px', fontSize: '12px', cursor: 'pointer', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px', flex: 1, justifyContent: 'center' }}>
                    <FileJson size={13} /> Export JSON
                  </button>
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
            <div className="glass-panel" style={{ padding: '60px 40px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center' }}>
              <Shield size={52} style={{ color: 'var(--text-muted)', marginBottom: '16px', opacity: 0.4 }} />
              <h3 style={{ fontWeight: 600, marginBottom: '8px', fontSize: '16px' }}>Ready to Scan</h3>
              <p style={{ color: 'var(--text-secondary)', fontSize: '13px', maxWidth: '280px' }}>
                Paste code, upload files, or enter a GitHub URL on the left to start the agentic security analysis.
              </p>
            </div>
          )}
        </div>
      </main>

      <footer style={{ padding: '12px 16px', textAlign: 'center', fontSize: '11px', color: 'var(--text-muted)', borderTop: '1px solid var(--border-color)' }}>
        VulnShield v1.0 — AI-Powered Security Analysis Platform • Portfolio Project
      </footer>
    </div>
  );
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }
