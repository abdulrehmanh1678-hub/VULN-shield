/**
 * Browser-side GitHub repository scanner.
 * Replaces the original `git clone` backend. It uses two GitHub API calls
 * (repo metadata + recursive tree) and then fetches each source file from the
 * raw.githubusercontent.com CDN — which is CORS-enabled and not subject to the
 * API rate limit — before running the in-browser static scanner.
 */

import { runScan } from './scanner';

const SOURCE_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.java', '.php', '.rb', '.cs', '.cpp', '.c'];
const SKIP_DIRS = ['node_modules/', '.git/', 'dist/', 'build/', '__pycache__/', '.venv/', 'vendor/', '.next/', 'coverage/'];
const MAX_FILES = 40;
const MAX_FILE_SIZE = 200 * 1024; // 200 KB

function parseRepo(url) {
  const m = url.replace(/\.git$/, '').match(/github\.com\/([^/]+)\/([^/]+)/);
  if (!m) return null;
  return { owner: m[1], repo: m[2] };
}

function isSource(path) {
  if (SKIP_DIRS.some(d => path.includes(d))) return false;
  const lower = path.toLowerCase();
  return SOURCE_EXTENSIONS.some(ext => lower.endsWith(ext));
}

/**
 * Clone-free scan of a public GitHub repo.
 * @param {string} repoUrl
 * @param {(log: {step:string, message:string}) => void} onProgress
 * @returns {Promise<object>} aggregated scan results (same shape the UI expects)
 */
export async function scanGitHubRepo(repoUrl, onProgress = () => {}) {
  const parsed = parseRepo(repoUrl);
  if (!parsed) return { success: false, error: 'Enter a valid public GitHub HTTPS URL.' };
  const { owner, repo } = parsed;

  onProgress({ step: 'REPO_INFO', message: `Looking up ${owner}/${repo}...` });
  const infoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`);
  if (infoRes.status === 404) return { success: false, error: 'Repository not found or is private.' };
  if (infoRes.status === 403) return { success: false, error: 'GitHub API rate limit reached. Please try again later.' };
  if (!infoRes.ok) return { success: false, error: `GitHub API error (${infoRes.status}).` };
  const info = await infoRes.json();
  const branch = info.default_branch || 'main';

  onProgress({ step: 'TREE', message: `Fetching file tree from branch "${branch}"...` });
  const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`);
  if (!treeRes.ok) return { success: false, error: `Could not read repository tree (${treeRes.status}).` };
  const tree = await treeRes.json();

  let sourceFiles = (tree.tree || [])
    .filter(n => n.type === 'blob' && isSource(n.path) && (n.size == null || n.size <= MAX_FILE_SIZE))
    .map(n => n.path);

  if (tree.truncated) {
    onProgress({ step: 'TREE_TRUNCATED', message: 'Large repo: file list was truncated by GitHub.' });
  }

  onProgress({ step: 'FILES_FOUND', message: `Found ${sourceFiles.length} source files. Scanning up to ${MAX_FILES}.` });
  sourceFiles = sourceFiles.slice(0, MAX_FILES);

  if (sourceFiles.length === 0) {
    return { success: false, error: 'No supported source files found in this repository.' };
  }

  const allFindings = [];
  const fileSummaries = [];
  const agentLogs = [];

  for (let i = 0; i < sourceFiles.length; i++) {
    const filePath = sourceFiles[i];
    onProgress({ step: 'FILE_SCAN', message: `[${i + 1}/${sourceFiles.length}] Scanning: ${filePath}` });
    try {
      const rawRes = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`);
      if (!rawRes.ok) continue;
      const code = await rawRes.text();
      const result = runScan(code, filePath);
      allFindings.push(...result.findings);
      agentLogs.push(...result.agentLogs);
      fileSummaries.push({ file: filePath, findings: result.findings.length, language: result.recon.language });
    } catch {
      onProgress({ step: 'FILE_ERROR', message: `Error scanning ${filePath}` });
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
    agentLogs
  };
}
