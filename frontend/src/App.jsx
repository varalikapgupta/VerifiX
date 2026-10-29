import React, { useState, useEffect, useCallback } from 'react';
import StitchHeader from './components/StitchHeader';
import CyberReticle from './components/CyberReticle';
import Verifix3DMatrix, { DEFAULT_SECURITY_NODES } from './components/Verifix3DMatrix';
import TelemetryOverlay from './components/TelemetryOverlay';
import InspectorPanel from './components/InspectorPanel';
import AnalysisDrawer from './components/AnalysisDrawer';
import { OrbGallery } from './shaders/orb-gallery/OrbGallery';
import { PRESET_SNIPPETS } from './data/presets';
import {
  checkHealth,
  analyzeSource,
  scanTargetFile,
  applySandboxPatch,
  ApiError,
} from './api/client';

export default function App() {
  const [backendHealth, setBackendHealth] = useState(null);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);

  const [activeView, setActiveView] = useState('matrix');
  const [isWorkspaceOpen, setIsWorkspaceOpen] = useState(false);

  const [source, setSource] = useState(PRESET_SNIPPETS[0].code);
  const [filename, setFilename] = useState(PRESET_SNIPPETS[0].filename);
  const [activePresetId, setActivePresetId] = useState(PRESET_SNIPPETS[0].id);

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

  // Sandbox patch workflow
  const [patchResult, setPatchResult] = useState(null);
  const [isPatching, setIsPatching] = useState(false);
  const [patchError, setPatchError] = useState(null);

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

  useEffect(() => {
    refreshHealth();
  }, [refreshHealth]);

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

  const handleApplyPatch = async () => {
    if (!findings.some((finding) => finding.rule === 'PY002')) return;

    setIsPatching(true);
    setPatchError(null);
    setPatchResult(null);

    try {
      const result = await applySandboxPatch('PY002');
      setPatchResult(result);
    } catch (err) {
      setPatchError(err.message || 'Sandbox patch failed.');
    } finally {
      setIsPatching(false);
    }
  };

  const handleResetCamera = useCallback(() => {
    window.dispatchEvent(new CustomEvent('orbgallery-reset-camera'));
    setIsZoomed(false);
    setZoomFocusTitle(null);
    setAutoRotate(true);
  }, []);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

      if (e.key === 'c' || e.key === 'C') {
        setCursorTracking((prev) => !prev);
      } else if (e.key === 'w' || e.key === 'W') {
        setWireframe((prev) => !prev);
      } else if (e.key === 'h' || e.key === 'H') {
        setHoloFilter((prev) => !prev);
      } else if (e.key === 'r' || e.key === 'R') {
        handleResetCamera();
      } else if (e.key === ' ' || e.code === 'Space') {
        e.preventDefault();
        setAutoRotate((prev) => !prev);
      } else if (e.key === 'Escape') {
        if (isWorkspaceOpen) setIsWorkspaceOpen(false);
        else handleResetCamera();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isWorkspaceOpen, handleResetCamera]);

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
      <div className="fixed-ambient-glow-layer" aria-hidden="true">
        <div className="ambient-blob blob-indigo" />
        <div className="ambient-blob blob-cyan" />
        <div className="ambient-radial-grid" />
      </div>

      <CyberReticle
        active={cursorTracking}
        cursorCoords={cursorCoords}
        activeTarget={activeLockTarget}
        isVulnerableTarget={isVulnerableTarget}
      />

      <StitchHeader
        backendHealth={backendHealth}
        onRefreshHealth={refreshHealth}
        isCheckingHealth={isCheckingHealth}
        cursorTracking={cursorTracking}
        onToggleCursor={() => setCursorTracking((prev) => !prev)}
        holoFilter={holoFilter}
        onToggleHolo={() => setHoloFilter((prev) => !prev)}
        wireframe={wireframe}
        onToggleWireframe={() => setWireframe((prev) => !prev)}
        autoRotate={autoRotate}
        onToggleOrbit={() => setAutoRotate((prev) => !prev)}
        onResetView={handleResetCamera}
        activeView={activeView}
        setActiveView={setActiveView}
        isWorkspaceOpen={isWorkspaceOpen}
        onToggleWorkspace={() => setIsWorkspaceOpen((prev) => !prev)}
        findingCount={findingCount}
      />

      <div className="verifix-3d-scene-layer">
        {activeView === 'matrix' ? (
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
        ) : (
          <div className="threeui-showcase-wrapper">
            <OrbGallery className="threeui-full-scene" />
          </div>
        )}
      </div>

      <main className="floating-hud-overlay-container">
        <div className="hud-top-row">
          <div className="hud-top-left-panel pointer-events-auto">
            <div className="hud-kicker-badge font-mono">
              <span className="kicker-pulse-dot" />
              <span>Fibonacci Spherical Distribution</span>
            </div>

            <h1 className="hud-hero-title">
              Spherical Interactive{' '}
              <span className="hero-gradient-text">&lt;OrbGallery /&gt;</span>
            </h1>

            <p className="hud-hero-subtitle">
              Hover over any plate to pop it forward along its spherical normal.
              Click and drag anywhere to tumble the sphere with smooth inertial momentum.
            </p>

            <div className="parallax-control-strip glass-panel">
              <span className="parallax-strip-label font-mono">
                <svg className="w-3 h-3 text-cyan-400" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Parallax:
              </span>
              <div className="parallax-btn-group">
                {[
                  { val: 0.5, label: '0.5x Subtle' },
                  { val: 1.0, label: '1.0x Balanced' },
                  { val: 1.8, label: '1.8x Hyper' },
                ].map(({ val, label }) => (
                  <button
                    key={val}
                    type="button"
                    className={`parallax-toggle-btn font-mono ${parallaxIntensity === val ? 'btn-active-cyan' : ''
                      }`}
                    onClick={() => setParallaxIntensity(val)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {isZoomed && (
              <div className="zoom-focus-pill glass-panel font-mono">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
                </span>
                <span>
                  Card Focused: <strong className="text-white">{zoomFocusTitle || 'Active Node'}</strong>
                </span>
                <span className="text-cyan-400/50">|</span>
                <span className="text-xs text-cyan-300/80">(Click canvas or Reset to zoom out)</span>
                <button
                  type="button"
                  className="pill-reset-close"
                  onClick={handleResetCamera}
                  title="Reset Camera View"
                >
                  ✕
                </button>
              </div>
            )}
          </div>

          <div className="hud-top-right-panel pointer-events-auto">
            <TelemetryOverlay
              backendHealth={backendHealth}
              findingCount={findingCount}
              targetName={targetName}
              hasScanned={hasScanned}
              isZoomed={isZoomed}
              isWireframe={wireframe}
              isHolo={holoFilter}
              cursorTracking={cursorTracking}
              parallaxIntensity={parallaxIntensity}
              cursorCoords={cursorCoords}
              activeCard={activeLockTarget}
            />
          </div>
        </div>

        <div className="hud-bottom-row">
          <div className="hud-bottom-left-panel pointer-events-auto">
            <InspectorPanel
              selectedNode={selectedNode}
              onOpenWorkspace={() => setIsWorkspaceOpen(true)}
              onResetView={handleResetCamera}
            />
          </div>

          <div className="hud-bottom-right-panel pointer-events-auto">
            <div className="interaction-hints-bar glass-panel font-mono">
              <div className="hint-item">
                <kbd className="hint-kbd">DRAG</kbd>
                <span>Rotate Sphere</span>
              </div>
              <span className="hint-divider">|</span>
              <div className="hint-item">
                <kbd className="hint-kbd">HOVER</kbd>
                <span>Pop Card</span>
              </div>
              <span className="hint-divider">|</span>
              <div className="hint-item">
                <kbd className="hint-kbd">CLICK</kbd>
                <span>Zoom In</span>
              </div>
            </div>
          </div>
        </div>
      </main>

      <AnalysisDrawer
        isOpen={isWorkspaceOpen}
        onClose={() => setIsWorkspaceOpen(false)}
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
        findings={findings}
        findingCount={findingCount}
        targetName={targetName}
        disclaimer={disclaimer}
        scanMode={scanMode}
        errorMessage={errorMessage}
        errorStatus={errorStatus}
        onDismissError={() => setErrorMessage(null)}
        onApplyPatch={handleApplyPatch}
        patchResult={patchResult}
        isPatching={isPatching}
        patchError={patchError}
      />
    </div>
  );
}