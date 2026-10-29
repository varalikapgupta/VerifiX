import React, { useState } from 'react';
import { ChevronDownIcon, ChevronUpIcon, AlertCircleIcon } from './Icons';

export default function FindingCard({ finding, index }) {
  const [isExpanded, setIsExpanded] = useState(true);

  const severity = (finding.severity || 'medium').toLowerCase();
  let badgeClass = 'badge-medium';
  if (severity === 'high') badgeClass = 'badge-high';
  if (severity === 'critical') badgeClass = 'badge-critical';
  if (severity === 'low') badgeClass = 'badge-low';

  const hasHypothesis = Boolean(finding.hypothesis);
  const confidence = (finding.confidence || 'unknown').toLowerCase();
  const recommendedProbes = finding.recommended_probes || [];

  return (
    <article className={`finding-card severity-${severity}`}>
      {/* Top Banner / Triage Bar */}
      <div
        className="finding-card-header"
        onClick={() => setIsExpanded(!isExpanded)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setIsExpanded(!isExpanded);
          }
        }}
      >
        <div className="finding-header-primary">
          <span className="finding-index-num">#{index + 1}</span>
          <span className={`severity-badge ${badgeClass}`}>{severity.toUpperCase()}</span>
          <span className="rule-identifier">{finding.rule}</span>
          <span className="source-line-indicator">Line {finding.line}</span>
          <h3 className="finding-title">{finding.type}</h3>
        </div>
        <div className="finding-header-toggle">
          <span className="toggle-text-hint">{isExpanded ? 'Collapse' : 'Details'}</span>
          {isExpanded ? <ChevronUpIcon size={14} /> : <ChevronDownIcon size={14} />}
        </div>
      </div>

      {isExpanded && (
        <div className="finding-card-content">
          {/* TIER 1: Static AST Finding Evidence */}
          <section className="analysis-tier tier-static">
            <div className="tier-header-row">
              <span className="tier-heading">1. Static AST Match</span>
              <span className="tier-pill-label">Syntactic Pattern Match</span>
            </div>
            <div className="tier-body">
              <div className="syntax-evidence-panel">
                <div className="evidence-panel-bar">
                  <span>Syntax Token Excerpt (Line {finding.line}):</span>
                </div>
                <pre className="evidence-code-block">
                  <code>{finding.evidence || 'No direct syntax excerpt captured.'}</code>
                </pre>
              </div>
            </div>
          </section>

          {/* TIER 2: AI Reasoning Hypothesis */}
          {hasHypothesis && (
            <section className="analysis-tier tier-reasoning">
              <div className="tier-header-row">
                <span className="tier-heading">2. Offline Reasoning Hypothesis</span>
                <div className="tier-hypothesis-meta">
                  <span className="tier-pill-label">Deterministic Rule Model</span>
                  <span className={`confidence-indicator conf-${confidence}`}>
                    Confidence: {(finding.confidence || 'Medium').toUpperCase()}
                  </span>
                </div>
              </div>
              <div className="tier-body">
                <div className="hypothesis-statement">
                  <span className="field-title">Hypothesis:</span>
                  <p className="field-content">{finding.hypothesis}</p>
                </div>
                {finding.reasoning && (
                  <div className="reasoning-statement">
                    <span className="field-title">Context &amp; Causal Analysis:</span>
                    <p className="field-content-box">{finding.reasoning}</p>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* TIER 3: Validation Boundary & Recommended Probes */}
          <section className="analysis-tier tier-validation">
            <div className="tier-header-row">
              <span className="tier-heading">3. Runtime Verification Status</span>
              <span className="status-unvalidated-badge">
                Status: Unvalidated Hypothesis
              </span>
            </div>
            <div className="tier-body">
              <div className="guardrail-callout-box">
                <AlertCircleIcon size={16} className="guardrail-icon" />
                <div className="guardrail-text">
                  <strong>Verification Separation Guarantee:</strong>
                  <p>
                    This finding represents an AST syntax match and an offline reasoning
                    hypothesis. It does not confirm an active exploit in the runtime environment.
                    No runtime probes have been automatically fired against this target.
                  </p>
                </div>
              </div>

              {recommendedProbes.length > 0 ? (
                <div className="recommended-probes-container">
                  <span className="field-title">Registered Validation Probes:</span>
                  <div className="probe-chips-list">
                    {recommendedProbes.map((probeId) => (
                      <span key={probeId} className="probe-chip">
                        <code>{probeId}</code>
                      </span>
                    ))}
                  </div>
                  <p className="probe-execution-note">
                    Probes must be authorized and scheduled independently through the loopback test
                    harness.
                  </p>
                </div>
              ) : (
                <p className="no-probes-note">
                  No automated probe is currently registered for rule {finding.rule}. Manual code
                  review required.
                </p>
              )}
            </div>
          </section>
        </div>
      )}
    </article>
  );
}
