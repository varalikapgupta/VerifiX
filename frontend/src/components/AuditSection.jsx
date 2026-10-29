import React from 'react';
import { CheckCircleIcon, AlertCircleIcon, TerminalIcon, LockIcon } from './Icons';

/**
 * AuditSection — Section F: Tamper-Evident SHA-256 Audit Ledger
 *
 * Displays live verifiable audit records and chain integrity from audit_log.jsonl.
 * Never fabricates data; displays real sequence continuity, hash chaining,
 * and canonical serialization properties.
 */
export default function AuditSection({
  auditData,
  isLoadingAudit,
  onRefreshAudit,
}) {
  const isValid = auditData?.valid === true;
  const records = auditData?.records || [];
  const recordsChecked = auditData?.records_checked ?? records.length;
  const totalRecords = auditData?.total_records ?? records.length;

  return (
    <section id="audit" className="verifix-page-section">
      <div className="section-header-block">
        <div className="section-badge font-mono">
          <span className="badge-dot dot-cyan" />
          <span>PHASE 05 · CRYPTOGRAPHIC ASSURANCE</span>
        </div>
        <h2 className="section-title">
          Tamper-Evident SHA-256 Audit Ledger
        </h2>
        <p className="section-subtitle">
          Cryptographically chained, append-only security ledger (<code>audit_log.jsonl</code>)
          guaranteeing non-repudiation and structural verification across all scans, patches, and tests.
        </p>
      </div>

      {/* Integrity Verification Summary Banner */}
      <div className="audit-integrity-banner glass-panel">
        <div className="integrity-status-col">
          <div className="integrity-icon-wrap">
            {isValid ? (
              <CheckCircleIcon size={24} className="text-emerald-400" />
            ) : (
              <AlertCircleIcon size={24} className="text-rose-400" />
            )}
          </div>
          <div>
            <div className="integrity-title-row">
              <h3 className="integrity-heading">
                {isValid
                  ? 'Cryptographic Hash-Chain Integrity: VERIFIED'
                  : 'Audit Chain Check: PENDING / RE-VERIFYING'}
              </h3>
              <span className={`integrity-status-pill font-mono ${isValid ? 'pill-safe' : 'pill-vuln'}`}>
                {isValid ? 'CHAIN VALID' : 'CHECKING'}
              </span>
            </div>
            <p className="integrity-subtext">
              {recordsChecked} records sequentially linked from genesis (<code>00000000...00000000</code>).
              Every record recomputed via deterministic canonical serialization (<code>canonical_serialize</code>).
            </p>
          </div>
        </div>

        <div className="integrity-actions-col">
          <button
            type="button"
            className="btn btn-secondary font-mono"
            onClick={onRefreshAudit}
            disabled={isLoadingAudit}
            title="Re-verify entire audit log via backend verify_audit_log()"
          >
            {isLoadingAudit ? (
              <>
                <span className="inline-spinner" />
                <span>VERIFYING CHAIN...</span>
              </>
            ) : (
              <>
                <TerminalIcon size={13} />
                <span>RE-VERIFY LEDGER</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Security Guarantees Cards */}
      <div className="audit-guarantees-grid">
        <div className="guarantee-box glass-panel">
          <div className="guarantee-header font-mono">
            <LockIcon size={14} className="text-cyan-400" />
            <span>CONFIDENTIALITY GUARANTEE</span>
          </div>
          <p className="guarantee-body">
            Source code text and private variables are strictly excluded from audit events.
            Only finding counts, triggered rule IDs, and SHA-256 file hashes are stored.
          </p>
        </div>

        <div className="guarantee-box glass-panel">
          <div className="guarantee-header font-mono">
            <TerminalIcon size={14} className="text-indigo-400" />
            <span>IMMUTABILITY &amp; CHAINING</span>
          </div>
          <p className="guarantee-body">
            Each record embeds the SHA-256 digest of the previous record. Any retroactive
            tampering, deletion, or sequence disruption causes mathematical verification failure.
          </p>
        </div>

        <div className="guarantee-box glass-panel">
          <div className="guarantee-header font-mono">
            <span className="font-mono text-emerald-400 font-bold">#</span>
            <span>TOTAL VERIFIED EVENTS</span>
          </div>
          <div className="guarantee-stat font-mono text-cyan-300">
            {totalRecords.toLocaleString()} RECORDS
          </div>
          <p className="guarantee-body text-xs">
            Persistent ledger stored at <code>backend/audit_log.jsonl</code>.
          </p>
        </div>
      </div>

      {/* Audit Log Events Table */}
      <div className="audit-log-table-wrapper glass-panel">
        <div className="table-header-bar">
          <span className="table-title font-mono">RECENT AUDIT EVENTS (LATEST 30 RECORDS)</span>
          <span className="table-badge font-mono">APPEND-ONLY JSONL</span>
        </div>

        <div className="table-scroll-container">
          <table className="audit-records-table">
            <thead>
              <tr className="font-mono">
                <th>SEQ #</th>
                <th>TIMESTAMP (UTC)</th>
                <th>EVENT TYPE</th>
                <th>DATA SUMMARY</th>
                <th>PREVIOUS SHA-256</th>
                <th>RECORD HASH</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {records.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-6 text-muted">
                    No audit records loaded. Click &quot;Re-Verify Ledger&quot; to fetch the live ledger.
                  </td>
                </tr>
              ) : (
                records.slice().reverse().map((rec, i) => (
                  <tr key={`${rec.sequence}-${i}`} className="audit-row">
                    <td className="font-bold text-cyan-300">#{rec.sequence}</td>
                    <td className="text-muted">{rec.timestamp}</td>
                    <td>
                      <span className={`event-type-chip ${
                        rec.event_type === 'verification_workflow'
                          ? 'chip-type-verify'
                          : rec.event_type === 'sandbox_patch'
                          ? 'chip-type-patch'
                          : 'chip-type-scan'
                      }`}>
                        {rec.event_type}
                      </span>
                    </td>
                    <td className="event-data-cell">
                      {rec.event_data ? (
                        <div className="data-preview" title={JSON.stringify(rec.event_data, null, 2)}>
                          {rec.event_data.rule && <span className="data-tag">Rule: {rec.event_data.rule}</span>}
                          {rec.event_data.status && <span className="data-tag">Status: {rec.event_data.status}</span>}
                          {rec.event_data.finding_count !== undefined && (
                            <span className="data-tag">Findings: {rec.event_data.finding_count}</span>
                          )}
                          {rec.event_data.overall_verdict && (
                            <span className="data-tag text-emerald-400">Verdict: {rec.event_data.overall_verdict}</span>
                          )}
                        </div>
                      ) : '—'}
                    </td>
                    <td className="hash-cell" title={rec.previous_hash}>
                      {rec.previous_hash ? `${rec.previous_hash.slice(0, 8)}...${rec.previous_hash.slice(-6)}` : 'GENESIS'}
                    </td>
                    <td className="hash-cell text-cyan-400 font-semibold" title={rec.current_hash}>
                      {rec.current_hash ? `${rec.current_hash.slice(0, 8)}...${rec.current_hash.slice(-6)}` : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
