import React from 'react';

/**
 * StitchHeader — Faithfully matches the Google Stitch reference design:
 * Brand badge, live engine status indicator, keyboard-shortcut action buttons,
 * and seamless workspace toggles.
 */
export default function StitchHeader({
  backendHealth,
  onRefreshHealth,
  isCheckingHealth,
  cursorTracking,
  onToggleCursor,
  holoFilter,
  onToggleHolo,
  wireframe,
  onToggleWireframe,
  autoRotate,
  onToggleOrbit,
  onResetView,
  activeView,
  setActiveView,
  isWorkspaceOpen,
  onToggleWorkspace,
  findingCount = 0,
}) {
  const isHealthy = backendHealth?.status === 'healthy';

  return (
    <header className="stitch-header">
      {/* Brand & Subtitle Block */}
      <div className="header-brand-group">
        <div className="brand-logo-hex">
          <div className="logo-inner-ring">
            <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
              <circle cx="12" cy="12" r="9" />
              <path d="M12 3a15.3 15.3 0 0 1 4 9 15.3 15.3 0 0 1-4 9 15.3 15.3 0 0 1-4-9 15.3 15.3 0 0 1 4-9z" />
              <path d="M2.5 9h19" />
              <path d="M2.5 15h19" />
            </svg>
          </div>
        </div>

        <div className="brand-copy-stack">
          <div className="brand-headline-row">
            <span className="brand-title">VerifiX</span>
            <span className="brand-badge-kicker">VERIFIX x THREEUI</span>
            <span className="brand-version-pill">v0.3.0</span>
          </div>
          <p className="brand-tagline">
            Verifix Telemetry Hub // Automated AST Security Verification
          </p>
        </div>
      </div>

      {/* Center Live Backend Status Indicator */}
      <div className="header-center-status">
        <div className="status-pill glass-panel">
          <span
            className={`status-pulse-dot ${
              isCheckingHealth
                ? 'bg-amber-400'
                : isHealthy
                ? 'bg-emerald-400 animate-ping'
                : 'bg-rose-500'
            }`}
          />
          <span className="status-text font-mono">
            {isCheckingHealth
              ? 'PINGING API...'
              : isHealthy
              ? 'LIVE FASTAPI 8000'
              : 'FASTAPI OFFLINE'}
          </span>
          <span className="status-divider">|</span>
          <span className="status-subinfo font-mono">
            {findingCount > 0
              ? `${findingCount} RISKS IDENTIFIED`
              : '32 NODES ACTIVE'}
          </span>
          <button
            type="button"
            className="status-refresh-btn"
            onClick={onRefreshHealth}
            disabled={isCheckingHealth}
            title="Refresh backend health via GET /health"
          >
            ↻
          </button>
        </div>
      </div>

      {/* Right Controls Group */}
      <div className="header-actions-group">
        {/* Cursor Tracking Toggle Button [C] */}
        <button
          type="button"
          className={`glass-panel control-action-btn ${cursorTracking ? 'btn-active-cyan' : ''}`}
          onClick={onToggleCursor}
          title="Toggle Cursor Tracking (C)"
        >
          <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="7" strokeDasharray="2 2" />
            <circle cx="12" cy="12" r="3" />
            <path d="M12 2v3m0 14v3M2 12h3m14 0h3" strokeLinecap="round" />
          </svg>
          <span className="control-btn-label">Cursor Tracking</span>
          <kbd className="control-key-hint">C</kbd>
        </button>

        {/* Holo Filter Toggle Button [H] */}
        <button
          type="button"
          className={`glass-panel control-action-btn ${holoFilter ? 'btn-active-cyan' : ''}`}
          onClick={onToggleHolo}
          title="Toggle Holo Filter (H)"
        >
          <svg className="w-3.5 h-3.5 text-cyan-300" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M13 10V3L4 14h7v7l9-11h-7z" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="control-btn-label">Holo Filter</span>
          <kbd className="control-key-hint">H</kbd>
        </button>

        {/* Wireframe Mode Toggle Button [W] */}
        <button
          type="button"
          className={`glass-panel control-action-btn ${wireframe ? 'btn-active-cyan' : ''}`}
          onClick={onToggleWireframe}
          title="Toggle Wireframe Mode (W)"
        >
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M4 6a2 2 0 012-2h12a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V6z" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M4 12h16M12 4v16M4 4l16 16M20 4L4 20" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="control-btn-label">Wireframe</span>
          <kbd className="control-key-hint">W</kbd>
        </button>

        {/* Reset Camera View Button [R] */}
        <button
          type="button"
          className="glass-panel control-action-btn"
          onClick={onResetView}
          title="Reset Camera View (R)"
        >
          <svg className="w-3.5 h-3.5 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            <path d="M3 12a9 9 0 109-9 9.75 9.75 0 00-6.74 2.74L3 8" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M3 3v5h5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="control-btn-label">Reset View</span>
          <kbd className="control-key-hint">R</kbd>
        </button>

        {/* Pause/Resume Orbit Button [Space] */}
        <button
          type="button"
          className="glass-panel control-action-btn"
          onClick={onToggleOrbit}
          title="Pause / Resume Rotation (Space)"
        >
          <svg className="w-3.5 h-3.5 text-indigo-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
            {autoRotate ? (
              <path d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />
            ) : (
              <path d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
            )}
          </svg>
          <span className="control-btn-label">{autoRotate ? 'Pause Orbit' : 'Resume Orbit'}</span>
        </button>

        {/* View Switcher: 3D Threat Matrix vs ThreeUI Registered Exhibition */}
        <div className="view-mode-pill glass-panel">
          <button
            type="button"
            className={`view-tab-btn ${activeView === 'matrix' ? 'active-view' : ''}`}
            onClick={() => setActiveView('matrix')}
          >
            Threat Matrix 3D
          </button>
          <button
            type="button"
            className={`view-tab-btn ${activeView === 'threeui' ? 'active-view' : ''}`}
            onClick={() => setActiveView('threeui')}
            title="Exhibition of exact registered ThreeUI Orb Gallery"
          >
            ThreeUI Source
          </button>
        </div>

        {/* Code & AST Analysis Drawer Trigger */}
        <button
          type="button"
          className={`workspace-toggle-cta ${isWorkspaceOpen ? 'cta-active' : ''}`}
          onClick={onToggleWorkspace}
        >
          <span className="cta-icon">🛡️</span>
          <span>{isWorkspaceOpen ? 'Hide Editor' : 'Code & Triage Console'}</span>
        </button>
      </div>
    </header>
  );
}

