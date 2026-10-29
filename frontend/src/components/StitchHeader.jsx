import React from 'react';

/**
 * StitchHeader — Single-Page Navigation & Telemetry Bar
 *
 * Sticky top navigation bar featuring:
 * - VerifiX brand identity & product tagline
 * - Smooth-scroll navigation links: Overview, Scan, Findings, Patch, Verification, Audit
 * - Active section tracking with highlight
 * - Real-time FastAPI backend health status
 * - Quick action trigger for security scan
 */
export default function StitchHeader({
  backendHealth,
  onRefreshHealth,
  isCheckingHealth,
  findingCount = 0,
  activeSection = 'overview',
  onNavigate,
  onStartScan,
  cursorTracking,
  onToggleCursor,
  wireframe,
  onToggleWireframe,
  autoRotate,
  onToggleOrbit,
  onResetView,
}) {
  const isHealthy = backendHealth?.status === 'healthy';

  const NAV_ITEMS = [
    { id: 'overview', label: 'Overview' },
    { id: 'scan', label: 'Scan' },
    { id: 'findings', label: 'Findings', badge: findingCount > 0 ? findingCount : null },
    { id: 'patch', label: 'Patch' },
    { id: 'verification', label: 'Verification' },
    { id: 'audit', label: 'Audit' },
  ];

  const handleNavClick = (e, id) => {
    e.preventDefault();
    if (onNavigate) {
      onNavigate(id);
    } else {
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
      }
    }
  };

  return (
    <header className="stitch-header sticky-header">
      {/* Brand & Subtitle Block */}
      <div className="header-brand-group">
        <a href="#overview" onClick={(e) => handleNavClick(e, 'overview')} className="brand-logo-hex-link">
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
        </a>

        <div className="brand-copy-stack">
          <div className="brand-headline-row">
            <span className="brand-title">VerifiX</span>
            <span className="brand-badge-kicker">APPSEC ENGINE</span>
            <span className="brand-version-pill">v0.3.0</span>
          </div>
          <p className="brand-tagline">
            From Vulnerability to Verified Security.
          </p>
        </div>
      </div>

      {/* Sticky Smooth-Scroll Navigation Links */}
      <nav className="header-smooth-nav" aria-label="Main Navigation">
        {NAV_ITEMS.map((item) => {
          const isActive = activeSection === item.id;
          return (
            <a
              key={item.id}
              href={`#${item.id}`}
              onClick={(e) => handleNavClick(e, item.id)}
              className={`nav-scroll-link font-mono ${isActive ? 'nav-active' : ''}`}
            >
              <span>{item.label}</span>
              {item.badge !== null && item.badge !== undefined && (
                <span className="nav-badge-pill">{item.badge}</span>
              )}
              {isActive && <span className="nav-active-bar" />}
            </a>
          );
        })}
      </nav>

      {/* Right Controls: Health Status & Actions */}
      <div className="header-actions-group">
        {/* Live Backend Status Indicator */}
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
              ? 'PINGING...'
              : isHealthy
              ? 'LIVE FASTAPI 8000'
              : 'FASTAPI OFFLINE'}
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

        {/* 3D Scene Controls Shortcuts */}
        <div className="header-3d-toggles-group">
          {onToggleOrbit && (
            <button
              type="button"
              className={`glass-panel mini-tool-btn ${autoRotate ? 'btn-active-cyan' : ''}`}
              onClick={onToggleOrbit}
              title={autoRotate ? 'Pause 3D Orbit' : 'Resume 3D Orbit'}
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                {autoRotate ? (
                  <path d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" strokeLinecap="round" strokeLinejoin="round" />
                ) : (
                  <path d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                )}
              </svg>
            </button>
          )}

          {onToggleWireframe && (
            <button
              type="button"
              className={`glass-panel mini-tool-btn ${wireframe ? 'btn-active-cyan' : ''}`}
              onClick={onToggleWireframe}
              title="Toggle Wireframe (W)"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path d="M4 6a2 2 0 012-2h12a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V6z" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          )}

          {onResetView && (
            <button
              type="button"
              className="glass-panel mini-tool-btn"
              onClick={onResetView}
              title="Reset 3D Camera (R)"
            >
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path d="M3 12a9 9 0 109-9 9.75 9.75 0 00-6.74 2.74L3 8" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          )}
        </div>

        {/* Quick CTA to jump to Scan */}
        <button
          type="button"
          className="header-scan-cta font-mono"
          onClick={onStartScan || ((e) => handleNavClick(e, 'scan'))}
        >
          <span className="cta-dot" />
          <span>SCAN NOW</span>
        </button>
      </div>
    </header>
  );
}
