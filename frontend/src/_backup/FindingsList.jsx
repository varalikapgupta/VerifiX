import React, { useState } from 'react';
import FindingCard from './FindingCard';
import { CheckCircleIcon, TerminalIcon } from './Icons';

export default function FindingsList({
  findings = [],
  findingCount = 0,
  targetName = '',
  disclaimer = '',
  scanMode = 'analyze',
}) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const criticalCount = findings.filter(
    (f) => (f.severity || '').toLowerCase() === 'critical'
  ).length;
  const highCount = findings.filter(
    (f) => (f.severity || '').toLowerCase() === 'high'
  ).length;
  const mediumCount = findings.filter(
    (f) => (f.severity || '').toLowerCase() === 'medium'
  ).length;
  const lowCount = findings.filter(
    (f) => (f.severity || '').toLowerCase() === 'low'
  ).length;

  const rulesTriggered = Array.from(new Set(findings.map((f) => f.rule))).filter(Boolean);

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity === 'ALL') return true;
    return (f.severity || '').toUpperCase() === filterSeverity;
  });

  return (
    <section className="panel-container findings-panel">
      {/* Triage Dashboard Header */}
      <div className="panel-header">
        <div className="panel-title-group">
          <span className="panel-eyebrow">TRIAGE REPORT</span>
          <h2 className="panel-title">
            Analysis Findings &amp; Evidence
            {targetName && <span className="target-pill">Target: {targetName}</span>}
          </h2>
        </div>

        {/* Audit Log Confirmation Notice */}
        <div className="audit-ledger-notice">
          <TerminalIcon size={14} className="audit-icon" />
          <span className="audit-text">
            <strong>SHA-256 Audit Trail:</strong> Scan logged to local hash-chain (
            <code>audit_log.jsonl</code>). Source contents are not stored.
          </span>
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="kpi-summary-grid">
        <div className="kpi-metric-box kpi-total">
          <span className="kpi-count">{findingCount}</span>
          <span className="kpi-description">Total Findings</span>
        </div>
        <div className="kpi-metric-box kpi-high">
          <span className="kpi-count">{criticalCount + highCount}</span>
          <span className="kpi-description">Critical / High</span>
        </div>
        <div className="kpi-metric-box kpi-medium">
          <span className="kpi-count">{mediumCount}</span>
          <span className="kpi-description">Medium Severity</span>
        </div>
        <div className="kpi-metric-box kpi-rules">
          <span className="kpi-count">{rulesTriggered.length}</span>
          <span className="kpi-description">Rules Triggered</span>
        </div>
        <div className="kpi-metric-box kpi-verdict">
          <span className="kpi-count kpi-verdict-text">
            {findingCount === 0 ? 'CLEAN' : 'UNVALIDATED'}
          </span>
          <span className="kpi-description">Runtime Status</span>
        </div>
      </div>

      {/* Severity Filter Buttons */}
      {findings.length > 0 && (
        <div className="severity-filter-bar">
          <span className="filter-prompt">Filter findings:</span>
          <div className="filter-pills-list">
            <button
              type="button"
              className={`filter-pill ${filterSeverity === 'ALL' ? 'active' : ''}`}
              onClick={() => setFilterSeverity('ALL')}
            >
              All ({findings.length})
            </button>
            {(criticalCount > 0 || highCount > 0) && (
              <button
                type="button"
                className={`filter-pill pill-high ${filterSeverity === 'HIGH' ? 'active' : ''}`}
                onClick={() => setFilterSeverity('HIGH')}
              >
                High / Critical ({criticalCount + highCount})
              </button>
            )}
            {mediumCount > 0 && (
              <button
                type="button"
                className={`filter-pill pill-medium ${filterSeverity === 'MEDIUM' ? 'active' : ''}`}
                onClick={() => setFilterSeverity('MEDIUM')}
              >
                Medium ({mediumCount})
              </button>
            )}
            {lowCount > 0 && (
              <button
                type="button"
                className={`filter-pill pill-low ${filterSeverity === 'LOW' ? 'active' : ''}`}
                onClick={() => setFilterSeverity('LOW')}
              >
                Low ({lowCount})
              </button>
            )}
          </div>
        </div>
      )}

      {/* Clean / Negative Baseline State */}
      {findings.length === 0 && (
        <div className="clean-status-card">
          <CheckCircleIcon size={32} className="clean-status-icon" />
          <h3 className="clean-status-title">Zero Static AST Violations Identified</h3>
          <p className="clean-status-text">
            The submitted Python source passed all registered AST checks (PY001, PY002, PY003,
            PY004, PY005, AUTH001). No dynamic code evaluations, unsafe path joins, unparameterized
            SQL queries, or hardcoded secrets were detected.
          </p>
          <div className="clean-status-checks">
            <span className="check-item">Parameterized queries verified</span>
            <span className="check-item">Path join containment verified</span>
            <span className="check-item">No dynamic eval/exec calls</span>
          </div>
        </div>
      )}

      {/* Findings Cards List */}
      <div className="findings-container-list">
        {filteredFindings.map((finding, idx) => (
          <FindingCard
            key={`${finding.rule}-${finding.line}-${idx}`}
            finding={finding}
            index={idx}
          />
        ))}
      </div>

      {/* Official Backend Disclaimer */}
      {disclaimer && (
        <div className="backend-disclaimer-panel">
          <div className="disclaimer-header-row">
            <span className="disclaimer-title">Engine Disclaimer:</span>
          </div>
          <p className="disclaimer-body">{disclaimer}</p>
        </div>
      )}
    </section>
  );
}
