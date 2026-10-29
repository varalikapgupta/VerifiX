import React from 'react';

/**
 * InspectorPanel — Floating Bottom-Left HUD Inspector
 * Shows detailed specifications of whichever 3D node is focused or clicked.
 * Faithfully mirrors the Stitch inspector panel layout while rendering
 * real VerifiX security telemetry and AST findings.
 */
export default function InspectorPanel({
  selectedNode,
  onOpenWorkspace,
  onResetView,
}) {
  if (!selectedNode) {
    return (
      <div className="inspector-panel glass-panel glass-panel-glow">
        <div className="inspector-top-bar">
          <span className="spec-label font-mono">SELECTED NODE SPEC</span>
          <span className="badge-tag font-mono">STANDBY</span>
        </div>
        <p className="empty-inspector-text font-mono">
          Click any plate on the 3D sphere to inspect AST rules or detected findings.
        </p>
      </div>
    );
  }

  const isVulnerability = Boolean(selectedNode.isVulnerability);
  const severity = (selectedNode.severity || 'info').toLowerCase();
  const primaryColor = isVulnerability ? '#A31C1B' : '#22c55e';

  return (
    <div
      className={`inspector-panel glass-panel glass-panel-glow ${
        isVulnerability ? 'border-crimson-glow' : 'border-green-glow'
      }`}
      id="inspector-card"
    >
      {/* Top Header Row */}
      <div className="inspector-top-bar">
        <span className="spec-label font-mono">SELECTED NODE SPEC</span>
        <div className="inspector-badge-row">
          <span
            className={`node-status-badge font-mono ${
              isVulnerability ? 'badge-crimson' : 'badge-emerald'
            }`}
          >
            {isVulnerability
              ? `RISK: ${severity.toUpperCase()}`
              : 'VERIFIED COMPLIANT'}
          </span>
          <span className="node-engine-badge font-mono">AST CORE</span>
        </div>
      </div>

      {/* Embedded High-Fidelity Cyber Shield Thumbnail Visualizer */}
      <div className="inspector-thumbnail-frame">
        <div className="thumbnail-cyber-grid" />
        <svg
          className="thumbnail-shield-svg"
          viewBox="0 0 100 100"
          fill="none"
          stroke={primaryColor}
          strokeWidth="2"
        >
          <path
            d="M50 12 L80 24 V50 C80 68 50 86 50 86 C50 86 20 68 20 50 V24 Z"
            fill={isVulnerability ? 'rgba(163,28,27,0.22)' : 'rgba(34,197,94,0.18)'}
          />
          {isVulnerability ? (
            <path
              d="M50 32 V54 M50 64 V66"
              stroke="#fca5a5"
              strokeWidth="4"
              strokeLinecap="round"
            />
          ) : (
            <path
              d="M38 50 L46 58 L64 40"
              stroke="#86efac"
              strokeWidth="3.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}
        </svg>

        <div className="thumbnail-hud-overlay">
          <div className="thumbnail-mode-pill font-mono">
            <span
              className={`thumbnail-pulse-dot ${
                isVulnerability ? 'bg-red-400' : 'bg-emerald-400'
              }`}
            />
            <span>
              {isVulnerability
                ? `VIOLATION // LINE ${selectedNode.line || 0}`
                : `RULE // ${selectedNode.tag || 'AST'}`}
            </span>
          </div>
          <div className="thumbnail-fidelity-tag font-mono">
            {isVulnerability ? 'UNVALIDATED HYPOTHESIS' : 'SYNTAX ENFORCED'}
          </div>
        </div>
      </div>

      {/* Title & Tag Row */}
      <div className="inspector-title-row">
        <h3 className="inspector-title">{selectedNode.title}</h3>
        <span
          className="inspector-tag-pill font-mono"
          style={{
            borderColor: primaryColor + '66',
            color: isVulnerability ? '#fca5a5' : '#86efac',
            backgroundColor: primaryColor + '22',
          }}
        >
          {selectedNode.tag}
        </span>
      </div>

      {/* Description / Evidence Box */}
      <p className="inspector-desc">{selectedNode.desc}</p>

      {/* Evidence code snippet if vulnerability */}
      {selectedNode.evidence && (
        <div className="inspector-evidence-box">
          <span className="evidence-header font-mono">SYNTAX EVIDENCE:</span>
          <code className="evidence-snippet font-mono">{selectedNode.evidence}</code>
        </div>
      )}

      {/* Reasoning Hypothesis snippet */}
      {selectedNode.hypothesis && (
        <div className="inspector-hypothesis-box">
          <span className="hypothesis-header font-mono">OFFLINE HYPOTHESIS:</span>
          <p className="hypothesis-text">{selectedNode.hypothesis}</p>
        </div>
      )}

      {/* Recommended probes chips */}
      {selectedNode.recommended_probes && selectedNode.recommended_probes.length > 0 && (
        <div className="inspector-probes-row">
          <span className="probes-label font-mono">APPROVED PROBES:</span>
          <div className="probes-list">
            {selectedNode.recommended_probes.map((probeId) => (
              <span key={probeId} className="probe-pill font-mono">
                {probeId}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Action Footer */}
      <div className="inspector-footer-bar">
        <button
          type="button"
          className="inspector-inspect-btn font-mono"
          onClick={onOpenWorkspace}
        >
          Open in Triage Console
        </button>
        <button
          type="button"
          className="inspector-zoomout-btn font-mono"
          onClick={onResetView}
        >
          Zoom Out
        </button>
        <span className="inspector-normal-vector font-mono">
          NODE // #{selectedNode.id || '01'}
        </span>
      </div>
    </div>
  );
}

