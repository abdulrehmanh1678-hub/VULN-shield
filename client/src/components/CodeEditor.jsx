import React, { useState } from 'react';
import { Terminal, Upload, AlertCircle, FileCode } from 'lucide-react';

const SAMPLES = {
  sqli: `// Vulnerable Express endpoint exposing SQL Injection
const express = require('express');
const router = express.Router();
const db = require('../db');

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // VULNERABLE: Direct concatenation of input in SQL query string
  const query = "SELECT * FROM accounts WHERE user = '" + username + "' AND pass = '" + password + "'";
  
  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err);
    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ error: "Invalid credentials" });
    }
  });
});`,
  xss: `// Vulnerable DOM manipulation causing XSS
function displayComment(userInput) {
  const commentList = document.getElementById('comments');
  const commentItem = document.createElement('div');
  commentItem.className = 'comment-card';
  
  // VULNERABLE: Inserting raw, unsanitized HTML directly into the DOM
  commentItem.innerHTML = '<h4>User Comment:</h4><p>' + userInput + '</p>';
  
  commentList.appendChild(commentItem);
}`,
  secrets: `// Hardcoded configurations & sensitive credentials
const AWS = require('aws-sdk');

const s3 = new AWS.S3({
  // VULNERABLE: Hardcoded secrets committed directly to source code
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  region: "us-east-1"
});

const JWT_SECRET = "super_secret_jwt_token_12345_dont_share";`,
  crypto: `// Vulnerable user password hashing using deprecated algorithms
const crypto = require('crypto');

function hashUserPassword(password) {
  // VULNERABLE: MD5 is insecure and prone to rapid collision attacks
  const hash = crypto.createHash('md5').update(password).digest('hex');
  return hash;
}`
};

export default function CodeEditor({ code, setCode, onScan, isScanning }) {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        setCode(event.target.result);
      };
      reader.readAsText(file);
    }
  };

  const loadSample = (key) => {
    setCode(SAMPLES[key]);
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Sample presets */}
      <div style={{ marginBottom: '16px' }}>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '8px', fontWeight: 500 }}>
          Load sample vulnerable code:
        </p>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button
            onClick={() => loadSample('sqli')}
            className="glass-panel"
            style={{ padding: '6px 12px', fontSize: '13px', cursor: 'pointer', borderRadius: '8px' }}
          >
            SQL Injection
          </button>
          <button
            onClick={() => loadSample('xss')}
            className="glass-panel"
            style={{ padding: '6px 12px', fontSize: '13px', cursor: 'pointer', borderRadius: '8px' }}
          >
            DOM XSS
          </button>
          <button
            onClick={() => loadSample('secrets')}
            className="glass-panel"
            style={{ padding: '6px 12px', fontSize: '13px', cursor: 'pointer', borderRadius: '8px' }}
          >
            Hardcoded Secrets
          </button>
          <button
            onClick={() => loadSample('crypto')}
            className="glass-panel"
            style={{ padding: '6px 12px', fontSize: '13px', cursor: 'pointer', borderRadius: '8px' }}
          >
            Weak Hashing
          </button>
        </div>
      </div>

      {/* Editor area */}
      <div 
        onDragEnter={handleDrag}
        onDragOver={handleDrag}
        onDragLeave={handleDrag}
        onDrop={handleDrop}
        style={{
          position: 'relative',
          borderRadius: '12px',
          border: dragActive ? '2px dashed var(--accent-primary)' : '1px solid var(--border-color)',
          background: 'var(--bg-code-deep)',
          transition: 'all 0.2s'
        }}
      >
        <textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Paste your source code here, drag a code file, or select a sample above..."
          className="editor-textarea"
          disabled={isScanning}
          style={{ border: 'none' }}
        />
        
        {dragActive && (
          <div style={{
            position: 'absolute',
            inset: 0,
            background: 'rgba(80, 227, 194, 0.08)',
            backdropFilter: 'blur(2px)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            borderRadius: '12px',
            color: 'var(--accent-primary)',
            pointerEvents: 'none'
          }}>
            <Upload size={48} style={{ marginBottom: '8px' }} />
            <span style={{ fontWeight: 600 }}>Drop code file to import</span>
          </div>
        )}
      </div>

      <button
        onClick={onScan}
        disabled={isScanning || !code.trim()}
        className="btn-primary"
        style={{ marginTop: '12px', width: '100%' }}
      >
        <Terminal size={18} />
        {isScanning ? 'Agent analyzing...' : 'Run Security Scan'}
      </button>
    </div>
  );
}
