import React, { useState, useEffect, useCallback } from 'react';
import StitchHeader from './components/StitchHeader';
import CyberReticle from './components/CyberReticle';
import Verifix3DMatrix, { DEFAULT_SECURITY_NODES } from './components/Verifix3DMatrix';
import SourceEditor from './components/SourceEditor';
import FindingsList from './components/FindingsList';
import InspectorPanel from './components/InspectorPanel';
import PatchSection from './components/PatchSection';
import VerificationSection from './components/VerificationSection';
import AuditSection from './components/AuditSection';
import { PRESET_SNIPPETS } from './data/presets';
import { AlertCircleIcon, CloseIcon, TerminalIcon, ShieldCheckIcon } from './components/Icons';
import {
  checkHealth,
  analyzeSource,
  scanTargetFile,
  applySandboxPatch,
  runVerification,
  fetchAuditTrail,
  ApiError,
} from './api/client';

export default function App() {
  // ── Navigation & Active Section ──────────────────────────────────────────
  const [activeSection, setActiveSection] = useState('overview');

  // ── Backend Health ───────────────────────────────────────────────────────
  const [backendHealth, setBackendHealth] = useState(null);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);

  // ── Code Scanner Input State ─────────────────────────────────────────────
  const [source, setSource] = useState(PRESET_SNIPPETS[0].code);
  const [filename, setFilename] = useState(PRESET_SNIPPETS[0].filename);
  const [activePresetId, setActivePresetId] = useState(PRESET_SNIPPETS[0].id);

  // ── Scanning & Triage Results ────────────────────────────────────────────
  const [isLoading, setIsLoading] = useState(false);
  const [loadingAction, setLoadingAction] = useState(null);
  const [findings, setFindings] = useState([]);
  const [findingCount, setFindingCount] = useState(0);
  const [targetName, setTargetName] = useState(PRESET_SNIPPETS[0].filename);
  const [disclaimer, setDisclaimer] = useState('');
  const [scanMode, setScanMode] = useState('analyze');
  const [hasScanned, setHasScanned] = useState(false);

  const [errorMessage, setErrorMessage] = useState(null);
  const [errorStatus, setErrorStatus] = useState(null);

  // ── Sandbox Patching State ───────────────────────────────────────────────
  const [patchResult, setPatchResult] = useState(null);
  const [isPatching, setIsPatching] = useState(false);
  const [patchError, setPatchError] = useState(null);

  // ── Runtime Verification State ───────────────────────────────────────────
  const [verificationReport, setVerificationReport] = useState(null);
  const [isVerifying, setIsVerifying] = useState(false);

  // ── Audit Ledger State ───────────────────────────────────────────────────
  const [auditData, setAuditData] = useState(null);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);

  // ── 3D Scene Interactive Controls ────────────────────────────────────────
  const [cursorTracking, setCursorTracking] = useState(true);
  const [holoFilter, setHoloFilter] = useState(true);
  const [wireframe, setWireframe] = useState(false);
  const [autoRotate, setAutoRotate] = useState(true);
  const [parallaxIntensity, setParallaxIntensity] = useState(1.0);

  const [isZoomed, setIsZoomed] = useState(false);
  const [zoomFocusTitle, setZoomFocusTitle] = useState(null);
  const [selectedNode, setSelectedNode] = useState(DEFAULT_SECURITY_NODES[0]);

  const [cursorCoords, setCursorCoords] = useState({
    x: 0,
    y: 0,
    nx: '+0.00',
    ny: '+0.00',
  });
  const [activeLockTarget, setActiveLockTarget] = useState(null);
  const [isVulnerableTarget, setIsVulnerableTarget] = useState(false);

  // ── Smooth Navigation ────────────────────────────────────────────────────
  const scrollToSection = useCallback((id) => {
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  }, []);

  // ── Intersection Observer for Active Nav Link ─────────────────────────────
  useEffect(() => {
    const sectionIds = ['overview', 'scan', 'findings', 'patch', 'verification', 'audit'];
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      {
        rootMargin: '-20% 0px -60% 0px',
        threshold: 0,
      }
    );

    sectionIds.forEach((id) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, []);

  // ── Backend Health Query ──────────────────────────────────────────────────
  const refreshHealth = useCallback(async () => {
    setIsCheckingHealth(true);
    try {
      const data = await checkHealth();
      setBackendHealth(data);
    } catch {
      setBackendHealth({ status: 'offline' });
    } finally {
      setIsCheckingHealth(false);
    }
  }, []);

  // ── Audit Trail Query ─────────────────────────────────────────────────────
  const refreshAudit = useCallback(async () => {
    setIsLoadingAudit(true);
    try {
      const data = await fetchAuditTrail();
      setAuditData(data);
    } catch {
      // Backend may be offline on initial mount
    } finally {
      setIsLoadingAudit(false);
    }
  }, []);

  useEffect(() => {
    refreshHealth();
    refreshAudit();
  }, [refreshHealth, refreshAudit]);

  // ── Handle Source AST Analysis (/analyze) ─────────────────────────────────
  const handleAnalyze = async () => {
    if (!source.trim()) return;

    setIsLoading(true);
    setLoadingAction('analyze');
    setErrorMessage(null);
    setErrorStatus(null);
    setPatchResult(null);
    setPatchError(null);
    setScanMode('analyze');

    try {
      const result = await analyzeSource(source, filename);
      const returnedFindings = result.findings || [];

      setFindings(returnedFindings);
      setFindingCount(result.finding_count || 0);
      setDisclaimer(result.disclaimer || '');
      setTargetName(filename);
      setHasScanned(true);

      if (returnedFindings.length > 0) {
        const topFinding = returnedFindings[0];
        setSelectedNode({
          id: `finding-0-${topFinding.rule}`,
          title: `${topFinding.type || topFinding.rule} (Line ${topFinding.line})`,
          tag: `${topFinding.rule} // ${(topFinding.severity || 'MEDIUM').toUpperCase()}`,
          color: '#A31C1B',
          bg: '#171717',
          severity: topFinding.severity,
          isVulnerability: true,
          rule: topFinding.rule,
          line: topFinding.line,
          evidence: topFinding.evidence,
          hypothesis: topFinding.hypothesis,
          confidence: topFinding.confidence,
          reasoning: topFinding.reasoning,
          recommended_probes: topFinding.recommended_probes || [],
          desc: topFinding.hypothesis || `Static AST rule match: ${topFinding.rule} at line ${topFinding.line}.`,
        });
      }

      // Refresh audit trail since /analyze logs a scan event
      refreshAudit();

      // Smooth scroll to findings section
      scrollToSection('findings');
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

  // ── Handle Disk Target Scan (/scan) ──────────────────────────────────────
  const handleScanTarget = async () => {
    setIsLoading(true);
    setLoadingAction('scan');
    setErrorMessage(null);
    setErrorStatus(null);
    setPatchResult(null);
    setPatchError(null);
    setScanMode('scan');

    try {
      const result = await scanTargetFile();
      const returnedFindings = result.findings || [];

      setFindings(returnedFindings);
      setFindingCount(result.finding_count || 0);
      setTargetName(result.target || 'vulnerable_app.py');
      setDisclaimer(
        'Direct static scan of backend disk file. Findings reflect AST pattern matches; runtime validation probes must be run separately to test exploitability.'
      );
      setHasScanned(true);

      if (returnedFindings.length > 0) {
        const topFinding = returnedFindings[0];
        setSelectedNode({
          id: `finding-0-${topFinding.rule}`,
          title: `${topFinding.type || topFinding.rule} (Line ${topFinding.line})`,
          tag: `${topFinding.rule} // ${(topFinding.severity || 'MEDIUM').toUpperCase()}`,
          color: '#A31C1B',
          bg: '#171717',
          severity: topFinding.severity,
          isVulnerability: true,
          rule: topFinding.rule,
          line: topFinding.line,
          evidence: topFinding.evidence,
          hypothesis: topFinding.hypothesis,
          confidence: topFinding.confidence,
          reasoning: topFinding.reasoning,
          recommended_probes: topFinding.recommended_probes || [],
          desc: topFinding.hypothesis || `Static AST rule match: ${topFinding.rule} at line ${topFinding.line}.`,
        });
      }

      refreshAudit();
      scrollToSection('findings');
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

  // ── Handle Sandbox Patch Application (/patch) ─────────────────────────────
  const handleApplyPatch = async (rule = 'PY002') => {
    setIsPatching(true);
    setPatchError(null);
    setPatchResult(null);

    try {
      const result = await applySandboxPatch(rule);
      setPatchResult(result);
      refreshAudit();
      scrollToSection('patch');
    } catch (err) {
      setPatchError(err.message || 'Sandbox patch failed.');
    } finally {
      setIsPatching(false);
    }
  };

  // ── Handle Runtime Verification Suite (/verify) ───────────────────────────
  const handleRunVerification = async () => {
    setIsVerifying(true);
    try {
      const report = await runVerification();
      setVerificationReport(report);
      refreshAudit();
    } catch (err) {
      setVerificationReport({
        verdict: 'FAILED',
        error: err.message || 'Verification workflow request failed.',
      });
    } finally {
      setIsVerifying(false);
    }
  };

  // ── 3D Camera & Interaction Helpers ───────────────────────────────────────
  const handleResetCamera = useCallback(() => {
    window.dispatchEvent(new CustomEvent('orbgallery-reset-camera'));
    setIsZoomed(false);
    setZoomFocusTitle(null);
    setAutoRotate(true);
  }, []);

  const handleCursorMove = useCallback((data) => {
    setCursorCoords({
      x: data.x,
      y: data.y,
      nx: data.nx,
      ny: data.ny,
    });
    setActiveLockTarget(data.activeCard);
    setIsVulnerableTarget(Boolean(data.isVulnerability));
  }, []);

  const handleZoomStatusChange = useCallback((zoomed, title) => {
    setIsZoomed(zoomed);
    setZoomFocusTitle(title);
    if (zoomed) setAutoRotate(false);
  }, []);

  return (
    <div className="verifix-viewport-root">
      {/* Background Ambient Glow Layer */}
      <div className="fixed-ambient-glow-layer" aria-hidden="true">
        <div className="ambient-blob blob-indigo" />
        <div className="ambient-blob blob-cyan" />
        <div className="ambient-radial-grid" />
      </div>

      {/* Cyber Reticle Cursor Tracker */}
      <CyberReticle
        active={cursorTracking}
        cursorCoords={cursorCoords}
        activeTarget={activeLockTarget}
        isVulnerableTarget={isVulnerableTarget}
      />

      {/* Sticky Top Navigation Bar */}
      <StitchHeader
        backendHealth={backendHealth}
        onRefreshHealth={refreshHealth}
        isCheckingHealth={isCheckingHealth}
        findingCount={findingCount}
        activeSection={activeSection}
        onNavigate={scrollToSection}
        onStartScan={() => scrollToSection('scan')}
        cursorTracking={cursorTracking}
        onToggleCursor={() => setCursorTracking((prev) => !prev)}
        wireframe={wireframe}
        onToggleWireframe={() => setWireframe((prev) => !prev)}
        autoRotate={autoRotate}
        onToggleOrbit={() => setAutoRotate((prev) => !prev)}
        onResetView={handleResetCamera}
      />

      {/* Main Single-Page Content Stream */}
      <main className="verifix-single-page-content">

        {/* ─────────────────────────────────────────────────────────────────
            SECTION A: HERO & OVERVIEW (#overview)
            ───────────────────────────────────────────────────────────────── */}
        <section id="overview" className="verifix-page-section hero-section">
          <div className="hero-single-page-grid">
            {/* Left Hero Column: Brand, Heading, Actions */}
            <div className="hero-text-column">
              <div className="hud-kicker-badge font-mono">
                <span className="kicker-pulse-dot" />
                <span>VERIFIX · AUTOMATED CODE SECURITY</span>
              </div>

              <h1 className="hud-hero-title">
                <span>See the Threat.</span>
                <br />
                <span className="hero-gradient-text">Fix the Flaw.</span>
                <br />
                <span>Verify the Fix.</span>
              </h1>

              <div className="hud-hero-tagline">
                From Vulnerability to Verified Security.
              </div>

              <p className="hud-hero-subtitle">
                Detect vulnerabilities, apply sandbox patches, and verify security fixes with evidence.
              </p>

              <div className="hero-cta-group">
                <button
                  type="button"
                  className="btn btn-primary font-mono header-scan-cta"
                  onClick={() => scrollToSection('scan')}
                >
                  <span className="cta-dot" />
                  <span>START SECURITY SCAN</span>
                </button>

                <button
                  type="button"
                  className="btn btn-secondary font-mono"
                  onClick={handleScanTarget}
                  disabled={isLoading}
                  title="Directly scan vulnerable_app.py on backend server"
                >
                  <TerminalIcon size={14} />
                  <span>SCAN SERVER TARGET (/scan)</span>
                </button>

                <button
                  type="button"
                  className="btn btn-secondary font-mono"
                  onClick={() => scrollToSection('findings')}
                >
                  <span>VIEW FINDINGS ({findingCount})</span>
                </button>
              </div>

              <div className="hero-kpi-strip font-mono">
                <div className="hero-kpi-card">
                  <span className="hero-kpi-val">PY001 - PY005</span>
                  <span className="hero-kpi-label">AST Scanner Rules</span>
                </div>
                <div className="hero-kpi-card">
                  <span className="hero-kpi-val">PY002 SANITIZED</span>
                  <span className="hero-kpi-label">Sandbox Patching</span>
                </div>
                <div className="hero-kpi-card">
                  <span className="hero-kpi-val">SHA-256 LEDGER</span>
                  <span className="hero-kpi-label">Audit Hash Chaining</span>
                </div>
              </div>

              {/* Parallax & 3D Interactive Controls Strip */}
              <div className="parallax-control-strip glass-panel font-mono">
                <span className="parallax-strip-label">
                  <svg className="w-3 h-3 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                  Sphere Parallax:
                </span>
                <div className="parallax-btn-group">
                  {[
                    { val: 0.5, label: '0.5x' },
                    { val: 1.0, label: '1.0x' },
                    { val: 1.8, label: '1.8x' },
                  ].map(({ val, label }) => (
                    <button
                      key={val}
                      type="button"
                      className={`parallax-toggle-btn font-mono ${parallaxIntensity === val ? 'btn-active-cyan' : ''}`}
                      onClick={() => setParallaxIntensity(val)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Hero Column: Interactive 3D Threat Matrix Sphere */}
            <div className="hero-3d-stage">
              <div className="hero-3d-stage-canvas">
                <Verifix3DMatrix
                  findings={findings}
                  findingCount={findingCount}
                  targetName={targetName}
                  isWireframe={wireframe}
                  isHolo={holoFilter}
                  autoRotate={autoRotate}
                  cursorTracking={cursorTracking}
                  parallaxIntensity={parallaxIntensity}
                  onSelectNode={setSelectedNode}
                  onZoomStatusChange={handleZoomStatusChange}
                  onCursorMove={handleCursorMove}
                  selectedNodeId={selectedNode?.id}
                />
              </div>

              {/* Mini HUD Status Bar Overlay */}
              <div className="hero-stage-overlay-hud font-mono">
                <div className="glass-panel px-3 py-1.5 rounded-md pointer-events-auto text-xs">
                  <span className="text-muted">TARGET:</span>{' '}
                  <strong className="text-white">{activeLockTarget || selectedNode?.title || 'Sphere Ready'}</strong>
                </div>

                <div className="glass-panel px-3 py-1.5 rounded-md pointer-events-auto text-xs">
                  <span className="text-cyan-400">POS: {cursorCoords.nx}, {cursorCoords.ny}</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ─────────────────────────────────────────────────────────────────
            SECTION B: SOURCE SCANNING (#scan)
            ───────────────────────────────────────────────────────────────── */}
        <section id="scan" className="verifix-page-section">
          <div className="section-header-block">
            <div className="section-badge font-mono">
              <span className="badge-dot dot-cyan" />
              <span>PHASE 01 · INPUT INGESTION</span>
            </div>
            <h2 className="section-title">Python Source Code Security Scanner</h2>
            <p className="section-subtitle">
              Submit Python source code for AST-based vulnerability detection and offline reasoning,
              or trigger an immediate static scan of the configured backend target file.
            </p>
          </div>

          {/* Error Alert Banner */}
          {errorMessage && (
            <div className="error-alert-banner" role="alert">
              <AlertCircleIcon size={18} className="error-alert-icon" />
              <div className="error-alert-body font-mono">
                <strong>
                  {errorStatus === 400
                    ? 'Request or Syntax Error (400)'
                    : errorStatus === 422
                    ? 'Validation Error (422)'
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

          {/* Reusable SourceEditor Component */}
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
        </section>

        {/* ─────────────────────────────────────────────────────────────────
            SECTION C: VULNERABILITY FINDINGS (#findings)
            ───────────────────────────────────────────────────────────────── */}
        <section id="findings" className="verifix-page-section">
          <div className="section-header-block">
            <div className="section-badge font-mono">
              <span className="badge-dot dot-red" />
              <span>PHASE 02 · CONTEXTUAL TRIAGE</span>
            </div>
            <h2 className="section-title">Vulnerability Findings &amp; Evidence</h2>
            <p className="section-subtitle">
              Engineered static AST rule detections enriched with offline vulnerability reasoning,
              confidence ratings, and recommended runtime security probes.
            </p>
          </div>

          {/* Two-Column Findings & Deep-Dive Inspector Grid */}
          <div className="findings-workspace-grid">
            <div className="findings-list-column">
              <FindingsList
                findings={findings}
                findingCount={findingCount}
                targetName={targetName}
                disclaimer={disclaimer}
                scanMode={scanMode}
              />
            </div>

            <div className="findings-inspector-column">
              <InspectorPanel
                selectedNode={selectedNode}
                onOpenWorkspace={() => scrollToSection('patch')}
                onResetView={handleResetCamera}
              />
            </div>
          </div>
        </section>

        {/* ─────────────────────────────────────────────────────────────────
            SECTION D: PATCH WORKSPACE (#patch)
            ───────────────────────────────────────────────────────────────── */}
        <PatchSection
          findings={findings}
          onApplyPatch={handleApplyPatch}
          patchResult={patchResult}
          isPatching={isPatching}
          patchError={patchError}
          targetName={targetName}
        />

        {/* ─────────────────────────────────────────────────────────────────
            SECTION E: RUNTIME VERIFICATION (#verification)
            ───────────────────────────────────────────────────────────────── */}
        <VerificationSection
          verificationReport={verificationReport}
          isVerifying={isVerifying}
          onRunVerification={handleRunVerification}
          patchResult={patchResult}
          targetName={targetName}
        />

        {/* ─────────────────────────────────────────────────────────────────
            SECTION F: CRYPTOGRAPHIC AUDIT (#audit)
            ───────────────────────────────────────────────────────────────── */}
        <AuditSection
          auditData={auditData}
          isLoadingAudit={isLoadingAudit}
          onRefreshAudit={refreshAudit}
        />

        {/* ─────────────────────────────────────────────────────────────────
            FOOTER: CREDITS & PROJECT RECAP
            ───────────────────────────────────────────────────────────────── */}
        <footer className="verifix-single-page-footer font-mono">
          <div className="footer-brand-summary">
            <div className="font-bold text-white">VerifiX Security Verification Engine v0.3.0</div>
            <div className="text-xs text-muted">
              Detect. Understand. Patch Safely. Verify. // From Vulnerability to Verified Security.
            </div>
          </div>

          <button
            type="button"
            className="footer-top-btn font-mono text-xs"
            onClick={() => scrollToSection('overview')}
          >
            ↑ BACK TO TOP
          </button>
        </footer>

      </main>
    </div>
  );
}