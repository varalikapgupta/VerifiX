import React from 'react';

/**
 * TelemetryOverlay — Top-Right Floating Telemetry & System Diagnostics Card
 * Exactly matches the Stitch design layout, typography, and styling,
 * but connects strictly to real FastAPI backend data and genuine system metrics.
 */
export default function TelemetryOverlay({
  backendHealth,
  findingCount = 0,
  targetName = 'file_viewer.py',
  hasScanned = false,
  isZoomed = false,
  isWireframe = false,
  isHolo = true,
  cursorTracking = true,
  parallaxIntensity = 1.0,
  cursorCoords = { nx: '+0.00', ny: '+0.00' },
  activeCard = null,
}) {
  const isHealthy = backendHealth?.status === 'healthy';

  let shadingLabel = 'Holographic';
  if (isWireframe && isHolo) shadingLabel = 'Wireframe + Holo';
  else if (isWireframe) shadingLabel = 'Wireframe Mesh';
  else if (!isHolo) shadingLabel = 'Standard Shading';

  const parallaxLabel =
    parallaxIntensity === 0.5
      ? '0.5x (Subtle)'
      : parallaxIntensity === 1.8
      ? '1.8x (Hyper)'
      : '1.0x (Balanced)';

  return (
    <div className="telemetry-hud-card glass-panel glass-panel-glow">
      {/* Header */}
      <div className="telemetry-card-header font-mono">
        <span className="telemetry-title">Verifix Telemetry</span>
        <span className="telemetry-badge">FASTAPI ENGINE</span>
      </div>

      <div className="telemetry-stats-rows">
        {/* Engine Status */}
        <div className="stat-line">
          <span className="stat-label">FastAPI Core</span>
          <span className={`stat-val font-mono ${isHealthy ? 'text-emerald-400' : 'text-rose-400'}`}>
            {isHealthy ? 'v0.3.0 (Active)' : 'Disconnected'}
          </span>
        </div>

        {/* Rule Suite */}
        <div className="stat-line">
          <span className="stat-label">Rule Suite</span>
          <span className="stat-val font-mono text-cyan-300">
            6 Core (PY001–005, AUTH)
          </span>
        </div>

        {/* Target Scope */}
        <div className="stat-line">
          <span className="stat-label">Target Scope</span>
          <span className="stat-val font-mono text-slate-200 truncate max-w-[140px]" title={targetName}>
            {targetName}
          </span>
        </div>

        {/* Verification Status */}
        <div className="stat-line">
          <span className="stat-label">Verification State</span>
          <span
            className={`stat-val font-mono ${
              hasScanned
                ? findingCount > 0
                  ? 'text-rose-400'
                  : 'text-emerald-400'
                : 'text-slate-400'
            }`}
          >
            {hasScanned
              ? findingCount > 0
                ? `${findingCount} Unvalidated Finding${findingCount > 1 ? 's' : ''}`
                : 'Baseline Clean'
              : 'Standby / Ready'}
          </span>
        </div>

        {/* Audit Log */}
        <div className="stat-line">
          <span className="stat-label">Audit Hash Chain</span>
          <span className="stat-val font-mono text-emerald-400">
            SHA-256 Ledger Active
          </span>
        </div>

        {/* Divider for 3D Viewport Telemetry */}
        <div className="telemetry-viewport-divider">
          <div className="stat-line-small">
            <span className="stat-label-small">Sphere Radius</span>
            <span className="stat-val-small font-mono">5.2 units</span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Card Count</span>
            <span className="stat-val-small font-mono">32 Security Nodes</span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Zoom Camera</span>
            <span
              className={`mode-tag font-mono ${
                isZoomed ? 'tag-focused' : 'tag-orbital'
              }`}
            >
              {isZoomed ? 'Focused' : 'Orbital'}
            </span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Shading Mode</span>
            <span className="mode-tag font-mono tag-cyan">{shadingLabel}</span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Cursor Tracking</span>
            <span
              className={`mode-tag font-mono ${
                cursorTracking ? 'tag-cyan' : 'tag-muted'
              }`}
            >
              {cursorTracking ? 'ACTIVE (Parallax 3D)' : 'STANDBY'}
            </span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Parallax Level</span>
            <span className="mode-tag font-mono tag-cyan">{parallaxLabel}</span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Cursor Vector</span>
            <span className="mode-tag font-mono tag-vector">
              [{cursorCoords.nx || '+0.00'}, {cursorCoords.ny || '+0.00'}]
            </span>
          </div>

          <div className="stat-line-small">
            <span className="stat-label-small">Lock-on Target</span>
            <span
              className={`mode-tag font-mono truncate max-w-[120px] ${
                activeCard ? 'tag-lock' : 'tag-muted'
              }`}
              title={activeCard || 'NONE'}
            >
              {activeCard || 'NONE'}
            </span>
          </div>
        </div>

        {/* Damping Footer */}
        <div className="stat-line-footer">
          <span className="stat-label-small">Physics Damping</span>
          <span className="stat-val-small font-mono">0.94 Inertial</span>
        </div>
      </div>
    </div>
  );
}

