import React from 'react';
import { ShieldIcon, RefreshIcon } from './Icons';

export default function Header({ backendHealth, onRefreshHealth, isCheckingHealth }) {
  const isHealthy = backendHealth?.status === 'healthy';

  return (
    <header className="verifix-header">
      <div className="header-brand-block">
        <div className="brand-logo-frame">
          <ShieldIcon size={20} className="brand-logo-icon" />
        </div>
        <div className="brand-text-group">
          <div className="brand-title-row">
            <span className="brand-title">VerifiX</span>
            <span className="brand-version-badge">v0.3.0</span>
            <span className="brand-engine-tag">AST Security Analyzer</span>
          </div>
          <p className="brand-subtitle">
            Static Abstract Syntax Tree Analysis &amp; Offline Reasoning Engine
          </p>
        </div>
      </div>

      <div className="header-actions-group">
        <div className="engine-capability-chips">
          <span className="capability-chip">AST Parser</span>
          <span className="capability-chip">Offline Reasoning</span>
          <span className="capability-chip">SHA-256 Audit Trail</span>
        </div>

        <div className="backend-connection-badge">
          <span
            className={`connection-dot ${
              isCheckingHealth
                ? 'status-checking'
                : isHealthy
                ? 'status-online'
                : 'status-offline'
            }`}
          />
          <span className="connection-text">
            {isCheckingHealth
              ? 'Checking API...'
              : isHealthy
              ? 'API: 127.0.0.1:8000 (Connected)'
              : 'API: Disconnected'}
          </span>
          <button
            type="button"
            className="refresh-btn"
            onClick={onRefreshHealth}
            disabled={isCheckingHealth}
            title="Verify FastAPI liveness via GET /health"
          >
            <RefreshIcon size={12} className={isCheckingHealth ? 'spin-icon' : ''} />
            <span>Check</span>
          </button>
        </div>
      </div>
    </header>
  );
}
