/**
 * VerifiedBadge — drop this into whatever component renders each finding
 * (e.g. AIReportViewer or a FindingCard). It makes the verified-findings
 * architecture VISIBLE, not just true under the hood.
 *
 * Usage inside a finding's JSX:
 *   <VerifiedBadge verified={finding.verified} />
 *
 * `finding.verified` is set to true by verifyReport() in aiPrompt.js for
 * every finding that survived the cross-check against the static engine's
 * ground truth. Findings from buildStaticReport() are always verified:true
 * since they ARE the ground truth.
 */
export function VerifiedBadge({ verified }) {
  if (verified) {
    return (
      <span
        title="This finding was confirmed by the deterministic static-analysis engine. The AI only explained it — it did not detect it."
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '4px',
          fontSize: '11px',
          fontWeight: 600,
          padding: '2px 8px',
          borderRadius: '999px',
          background: 'rgba(34,197,94,0.12)',
          color: '#16a34a',
          border: '1px solid rgba(34,197,94,0.35)'
        }}
      >
        ✓ Verified by static analysis
      </span>
    );
  }
  return (
    <span
      title="This was not in the confirmed findings list and may be AI commentary only."
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        fontSize: '11px',
        fontWeight: 600,
        padding: '2px 8px',
        borderRadius: '999px',
        background: 'rgba(234,179,8,0.12)',
        color: '#ca8a04',
        border: '1px solid rgba(234,179,8,0.35)'
      }}
    >
      ⚠ Unverified
    </span>
  );
}

/**
 * Optional: a small banner to show at the top of the report when
 * result.verificationIssues has entries — proves to a viewer/mentor that
 * the cross-check is live and actually catching things, not just decorative.
 *
 * Usage: <VerificationBanner issues={result.verificationIssues} />
 */
export function VerificationBanner({ issues = [] }) {
  if (!issues.length) return null;
  return (
    <div
      style={{
        fontSize: '12px',
        padding: '8px 12px',
        borderRadius: '8px',
        background: 'rgba(234,179,8,0.08)',
        border: '1px solid rgba(234,179,8,0.3)',
        color: '#92400e',
        marginBottom: '12px'
      }}
    >
      <strong>Verification layer caught {issues.length} issue(s) in the AI output:</strong>
      <ul style={{ margin: '4px 0 0 16px' }}>
        {issues.map((issue, i) => <li key={i}>{issue}</li>)}
      </ul>
    </div>
  );
}
