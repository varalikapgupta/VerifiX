import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import CyberOrb from './components/CyberOrb';
import SourceEditor from './components/SourceEditor';
import FindingsList from './components/FindingsList';
import { PRESET_SNIPPETS } from './data/presets';
import { checkHealth, analyzeSource, scanTargetFile, ApiError } from './api/client';
import { AlertCircleIcon, CloseIcon } from './components/Icons';

export default function App() {
  // Backend health status
  const [backendHealth, setBackendHealth] = useState(null);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);

  // Editor states (init with Path Traversal PY002 preset)
  const [source, setSource] = useState(PRESET_SNIPPETS[0].code);
  const [filename, setFilename] = useState(PRESET_SNIPPETS[0].filename);
  const [activePresetId, setActivePresetId] = useState(PRESET_SNIPPETS[0].id);

  // Analysis result states
  const [isLoading, setIsLoading] = useState(false);
  const [loadingAction, setLoadingAction] = useState(null);
  const [findings, setFindings] = useState([]);
  const [findingCount, setFindingCount] = useState(0);
  const [targetName, setTargetName] = useState(PRESET_SNIPPETS[0].filename);
  const [disclaimer, setDisclaimer] = useState('');
  const [scanMode, setScanMode] = useState('analyze');
  const [hasScanned, setHasScanned] = useState(false);

  // Error handling
  const [errorMessage, setErrorMessage] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);

  // Query health on load
  const refreshHealth = async () => {
    setIsCheckingHealth(true);
    try {
      const data = await checkHealth();
      setBackendHealth(data);
    } catch {
      setBackendHealth({ status: 'offline' });
    } finally {
      setIsCheckingHealth(false);
    }
  };

  useEffect(() => {
    refreshHealth();
  }, []);

  // Compute 3D CyberOrb state from real API outcomes
  let orbState = 'idle';
  if (isLoading) {
    orbState = 'scanning';
  } else if (errorMessage) {
    orbState = 'error';
  } else if (hasScanned) {
    orbState = findingCount > 0 ? 'alert' : 'secure';
  }

  // Handle /analyze submission
  const handleAnalyze = async () => {
    if (!source.trim()) return;

    setIsLoading(true);
    setLoadingAction('analyze');
    setErrorMessage(null);
    setErrorStatus(null);
    setScanMode('analyze');

    try {
      const result = await analyzeSource(source, filename);
      setFindings(result.findings || []);
      setFindingCount(result.finding_count || 0);
      setDisclaimer(result.disclaimer || '');
      setTargetName(filename);
      setHasScanned(true);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
        setErrorStatus(err.status);
      } else {
        setErrorMessage(`Unexpected error: ${err.message}`);
        setErrorStatus(500);
      }
    } finally {
      setIsLoading(false);
      setLoadingAction(null);
    }
  };

  // Handle /scan submission
  const handleScanTarget = async () => {
    setIsLoading(true);
    setLoadingAction('scan');
    setErrorMessage(null);
    setErrorStatus(null);
    setScanMode('scan');

    try {
      const result = await scanTargetFile();
      setFindings(result.findings || []);
      setFindingCount(result.finding_count || 0);
      setTargetName(result.target || 'vulnerable_app.py');
      setDisclaimer(
        'Direct static scan of backend disk file. Findings reflect AST pattern matches; runtime validation probes must be run separately to test exploitability.'
      );
      setHasScanned(true);
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
        setErrorStatus(err.status);
      } else {
        setErrorMessage(`Failed to scan target file: ${err.message}`);
        setErrorStatus(500);
      }
    } finally {
      setIsLoading(false);
      setLoadingAction(null);
    }
  };

  return (
    <div className="verifix-app">
      {/* Header with real connection status */}
      <Header
        backendHealth={backendHealth}
        onRefreshHealth={refreshHealth}
        isCheckingHealth={isCheckingHealth}
      />

      <main className="verifix-main-content">
        {/* Integrated 3D Telemetry Command Strip */}
        <section className="telemetry-command-strip">
          <div className="telemetry-briefing">
            <div className="briefing-eyebrow-row">
              <span className="telemetry-kicker">VERIFIX ENGINE TELEMETRY</span>
              <span className="telemetry-mode-tag">AST STATIC CORE</span>
            </div>
            <h2 className="telemetry-headline">
              Security Telemetry &amp; Vulnerability Analysis Hub
            </h2>
            <p className="telemetry-subtext">
              Deterministic Python grammar verification paired with offline causal reasoning hypotheses
              and cryptographic SHA-256 audit logging. Target source code is analyzed strictly without
              execution.
            </p>

            <div className="telemetry-metrics-bar">
              <div className="telemetry-metric-item">
                <span className="metric-title">Rule Suite</span>
                <span className="metric-val">6 Core (PY001–005, AUTH001)</span>
              </div>
              <div className="telemetry-metric-item">
                <span className="metric-title">Target Scope</span>
                <span className="metric-val">{targetName}</span>
              </div>
              <div className="telemetry-metric-item">
                <span className="metric-title">Verification Boundary</span>
                <span className="metric-val">
                  {hasScanned
                    ? findingCount > 0
                      ? `${findingCount} Unvalidated Finding${findingCount > 1 ? 's' : ''}`
                      : 'Baseline Clean'
                    : 'Standby / Ready'}
                </span>
              </div>
            </div>
          </div>

          <div className="telemetry-orb-frame">
            <CyberOrb state={orbState} findingCount={findingCount} />
          </div>
        </section>

        {/* Global Error Banner */}
        {errorMessage && (
          <div className="error-alert-banner" role="alert">
            <AlertCircleIcon size={18} className="error-alert-icon" />
            <div className="error-alert-body">
              <strong>
                {errorStatus === 400
                  ? 'Python Syntax Error (400 Bad Request)'
                  : errorStatus === 422
                  ? 'Validation Error (422 Unprocessable Entity)'
                  : errorStatus === 0
                  ? 'Connection Error (FastAPI Unreachable)'
                  : `API Error (HTTP ${errorStatus || 500})`}
              </strong>
              <p>{errorMessage}</p>
            </div>
            <button
              type="button"
              className="error-dismiss-btn"
              onClick={() => setErrorMessage(null)}
              aria-label="Dismiss error"
            >
              <CloseIcon size={14} />
            </button>
          </div>
        )}

        {/* Primary Workspace: Source Code & Triage Findings */}
        <div className="workspace-layout-grid">
          <SourceEditor
            source={source}
            setSource={setSource}
            filename={filename}
            setFilename={setFilename}
            onAnalyze={handleAnalyze}
            onScanTarget={handleScanTarget}
            isLoading={isLoading}
            loadingAction={loadingAction}
            activePresetId={activePresetId}
            setActivePresetId={setActivePresetId}
          />

          <FindingsList
            findings={findings}
            findingCount={findingCount}
            targetName={targetName}
            disclaimer={disclaimer}
            scanMode={scanMode}
          />
        </div>
      </main>

      {/* Sober AppSec Footer */}
      <footer className="verifix-footer">
        <div className="footer-left">
          <span>VerifiX Security Platform · DualByte T2-03</span>
          <span className="footer-divider">/</span>
          <span>FastAPI Engine: <code>http://127.0.0.1:8000</code></span>
        </div>
        <div className="footer-right">
          <span>Non-Executable Static AST Scanner</span>
          <span className="footer-divider">/</span>
          <span>SHA-256 Audit Logged</span>
        </div>
      </footer>
    </div>
  );
}
