/**
 * GitHub Repository Scanner (Phase 9)
 * Clones a public GitHub repository and runs the agentic scanner
 * on all source code files found within it.
 */

const simpleGit = require('simple-git');
const path = require('path');
const fs = require('fs');
const orchestrator = require('./agent/orchestrator');

const TEMP_DIR = path.join(__dirname, 'temp_repos');
const SOURCE_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.java', '.php', '.rb', '.cs', '.cpp', '.c'];
const MAX_FILE_SIZE_BYTES = 200 * 1024; // 200 KB per file
const MAX_FILES = 100;

/**
 * Parse GitHub URL to extract owner/repo name for folder naming.
 * @param {string} url
 * @returns {string}
 */
function parseRepoName(url) {
  const parts = url.replace(/\.git$/, '').split('/');
  return parts[parts.length - 2] + '_' + parts[parts.length - 1];
}

/**
 * Recursively gather all source files from a directory.
 * @param {string} dir
 * @returns {string[]}
 */
function collectSourceFiles(dir, files = [], depth = 0) {
  if (depth > 5 || files.length >= MAX_FILES) return files;

  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return files;
  }

  // Skip common non-source dirs
  const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'vendor', '.next', 'coverage']);

  for (const entry of entries) {
    if (files.length >= MAX_FILES) break;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        collectSourceFiles(fullPath, files, depth + 1);
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SOURCE_EXTENSIONS.includes(ext)) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

/**
 * Clone a GitHub repository and scan all source files.
 * @param {string} repoUrl - Public GitHub repo URL
 * @param {function} onProgress - Optional callback for progress updates
 * @returns {object} - Aggregated multi-file scan results
 */
async function scanGitHubRepo(repoUrl, onProgress = () => {}) {
  const repoName = parseRepoName(repoUrl);
  const cloneDir = path.join(TEMP_DIR, repoName + '_' + Date.now());

  try {
    // Ensure temp directory exists
    if (!fs.existsSync(TEMP_DIR)) {
      fs.mkdirSync(TEMP_DIR, { recursive: true });
    }

    onProgress({ step: 'CLONE_START', message: `Cloning repository: ${repoUrl}` });
    const git = simpleGit();
    await git.clone(repoUrl, cloneDir, ['--depth', '1']); // Shallow clone for speed
    onProgress({ step: 'CLONE_DONE', message: 'Repository cloned successfully.' });

    // Collect source files
    const sourceFiles = collectSourceFiles(cloneDir);
    onProgress({ step: 'FILES_FOUND', message: `Found ${sourceFiles.length} source files to analyze.` });

    if (sourceFiles.length === 0) {
      return {
        success: false,
        error: 'No supported source files found in this repository.'
      };
    }

    // Scan each file
    const allFindings = [];
    const fileSummaries = [];

    for (let i = 0; i < sourceFiles.length; i++) {
      const filePath = sourceFiles[i];
      const relPath = path.relative(cloneDir, filePath);

      try {
        const stats = fs.statSync(filePath);
        if (stats.size > MAX_FILE_SIZE_BYTES) {
          onProgress({ step: 'FILE_SKIP', message: `Skipping large file: ${relPath}` });
          continue;
        }

        const code = fs.readFileSync(filePath, 'utf8');
        onProgress({ step: 'FILE_SCAN', message: `[${i + 1}/${sourceFiles.length}] Scanning: ${relPath}` });

        const scanResult = await orchestrator.runScan(code, relPath);
        
        fileSummaries.push({
          file: relPath,
          findings: scanResult.findings.length,
          language: scanResult.recon.language
        });

        allFindings.push(...scanResult.findings);

      } catch (fileErr) {
        onProgress({ step: 'FILE_ERROR', message: `Error scanning ${relPath}: ${fileErr.message}` });
      }
    }

    onProgress({ step: 'SCAN_COMPLETE', message: `Repository scan complete. Total findings: ${allFindings.length}` });

    return {
      success: true,
      repoUrl,
      summary: {
        totalFiles: sourceFiles.length,
        totalVulnerabilities: allFindings.length,
        language: 'Multiple',
        framework: 'Multiple',
        timestamp: new Date().toISOString()
      },
      fileSummaries,
      findings: allFindings,
      recon: { language: 'Multi-language', framework: 'Multi-framework' },
      agentLogs: orchestrator.logs || []
    };

  } finally {
    // Always cleanup the cloned directory
    try {
      if (fs.existsSync(cloneDir)) {
        fs.rmSync(cloneDir, { recursive: true, force: true });
      }
    } catch (cleanupErr) {
      console.warn('[GitHub Scanner] Failed to cleanup temp dir:', cleanupErr.message);
    }
  }
}

module.exports = { scanGitHubRepo };
