import React, { useState } from 'react';
import { Upload, X, File, FileCode, CheckCircle2, Terminal } from 'lucide-react';

const ALLOWED_EXT = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.java', '.php', '.rb', '.cs', '.cpp', '.c', '.txt', '.html'];

export default function FileUploader({ files, setFiles, onScan, isScanning }) {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(e.type !== 'dragleave');
  };

  const addFiles = (newFiles) => {
    const valid = Array.from(newFiles).filter(f => {
      const ext = '.' + f.name.split('.').pop().toLowerCase();
      return ALLOWED_EXT.includes(ext) && f.size < 5 * 1024 * 1024;
    });
    setFiles(prev => {
      const existing = new Set(prev.map(f => f.name));
      return [...prev, ...valid.filter(f => !existing.has(f.name))].slice(0, 10);
    });
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    addFiles(e.dataTransfer.files);
  };

  const removeFile = (name) => setFiles(prev => prev.filter(f => f.name !== name));

  const formatSize = (bytes) => bytes < 1024 ? `${bytes}B` : `${(bytes / 1024).toFixed(1)}KB`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>

      {/* Drop Zone */}
      <div
        onDragEnter={handleDrag} onDragOver={handleDrag} onDragLeave={handleDrag} onDrop={handleDrop}
        onClick={() => !isScanning && document.getElementById('file-input').click()}
        style={{
          border: `2px dashed ${dragActive ? 'var(--accent-primary)' : 'var(--border-color)'}`,
          borderRadius: '12px',
          padding: '40px 20px',
          textAlign: 'center',
          cursor: 'pointer',
          background: dragActive ? 'rgba(99,102,241,0.05)' : 'var(--bg-primary)',
          transition: 'all 0.2s',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px'
        }}
      >
        <Upload size={32} style={{ color: dragActive ? 'var(--accent-primary)' : 'var(--text-muted)', opacity: 0.7 }} />
        <div>
          <p style={{ fontSize: '14px', fontWeight: 600, color: dragActive ? 'var(--accent-primary)' : 'var(--text-primary)' }}>
            {dragActive ? 'Drop files here' : 'Click or drag files to upload'}
          </p>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Supports: .js .ts .py .go .java .php .cs .rb and more (max 5MB each, up to 10 files)
          </p>
        </div>
        <input
          id="file-input" type="file" multiple accept={ALLOWED_EXT.join(',')}
          style={{ display: 'none' }}
          onChange={e => addFiles(e.target.files)}
        />
      </div>

      {/* File List */}
      {files.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
          <p style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 500 }}>
            {files.length} file{files.length > 1 ? 's' : ''} queued for scanning:
          </p>
          {files.map(f => (
            <div key={f.name} className="glass-panel" style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <FileCode size={16} style={{ color: 'var(--accent-primary)', flexShrink: 0 }} />
              <div style={{ flex: 1, overflow: 'hidden' }}>
                <p style={{ fontSize: '13px', fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{f.name}</p>
                <p style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{formatSize(f.size)}</p>
              </div>
              <button onClick={() => removeFile(f.name)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: '2px' }}>
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Scan Button */}
      <button
        onClick={onScan}
        disabled={isScanning || files.length === 0}
        className="btn-primary"
        style={{ width: '100%', marginTop: '4px' }}
      >
        <Terminal size={16} />
        {isScanning ? 'Scanning files...' : `Scan ${files.length} File${files.length !== 1 ? 's' : ''}`}
      </button>
    </div>
  );
}
