import React from 'react';
import SourceEditor from './SourceEditor';
import FindingsList from './FindingsList';
import { AlertCircleIcon, CloseIcon } from './Icons';

export default function AnalysisDrawer({
  isOpen,
  onClose,
  source,
  setSource,
  filename,
  setFilename,
  onAnalyze,
  onScanTarget,
  isLoading,
  loadingAction,
  activePresetId,
  setActivePresetId,
  findings,
  findingCount,
  targetName,
  disclaimer,
  scanMode,
  errorMessage,
  errorStatus,
  onDismissError,
  onApplyPatch,
  patchResult,
  isPatching,
  patchError,
}) {
  if (!isOpen) return null;

  const hasPy002 = findings.some((finding) => finding.rule === 'PY002');

  return (
    <div className="analysis-drawer-backdrop" onClick={onClose}>
      <div
        className="analysis-drawer-panel glass-panel"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="VerifiX AST Code & Triage Console"
      >
        <div className="drawer-header-bar">
          <div className="drawer-header-left">
            <span className="drawer-eyebrow font-mono">WORKSPACE INTERFACE</span>
            <h2 className="drawer-headline">
              AST Code &amp; Vulnerability Triage Console
            </h2>
          </div>

          <div className="drawer-header-actions">
            <span className="drawer-status-chip font-mono">
              FASTAPI LIVE: <code>/analyze</code> + <code>/scan</code> + <code>/patch</code>
            </span>
            <button
              type="button"
              className="drawer-close-btn"
              onClick={onClose}
              aria-label="Close console"
            >
              <CloseIcon size={16} />
            </button>
          </div>
        </div>

        {errorMessage && (
          <div className="error-alert-banner" role="alert">
            <AlertCircleIcon size={18} className="error-alert-icon" />
            <div className="error-alert-body">
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
              onClick={onDismissError}
              aria-label="Dismiss error"
            >
              <CloseIcon size={14} />
            </button>
          </div>
        )}

        <div className="drawer-grid-content">
          <div className="drawer-editor-col">
            <SourceEditor
              source={source}
              setSource={setSource}
              filename={filename}
              setFilename={setFilename}
              onAnalyze={onAnalyze}
              onScanTarget={onScanTarget}
              isLoading={isLoading}
              loadingAction={loadingAction}
              activePresetId={activePresetId}
              setActivePresetId={setActivePresetId}
            />
          </div>

          <div className="drawer-findings-col">
            <FindingsList
              findings={findings}
              findingCount={findingCount}
              targetName={targetName}
              disclaimer={disclaimer}
              scanMode={scanMode}
            />

            {hasPy002 && (
              <section
                className="panel-container"
                style={{ marginTop: '16px', padding: '20px' }}
              >
                <h3 style={{ marginTop: 0 }}>Sandbox Remediation</h3>
                <p>
                  Apply the approved PY002 patch to a temporary sandbox copy.
                  The original vulnerable source file must remain unchanged.
                </p>

                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={onApplyPatch}
                  disabled={isPatching || isLoading}
                >
                  {isPatching ? 'Applying Sandbox Patch...' : 'Apply Sandbox Patch (PY002)'}
                </button>

                {patchError && (
                  <p role="alert" style={{ color: '#ff7777', marginTop: '12px' }}>
                    Patch failed: {patchError}
                  </p>
                )}

                {patchResult && (
                  <div
                    style={{
                      marginTop: '16px',
                      padding: '14px',
                      border: '1px solid #3a7',
                      borderRadius: '8px',
                      overflowWrap: 'anywhere',
                    }}
                    role="status"
                  >
                    <strong>Patch response: {patchResult.status}</strong>
                    <p>{patchResult.message}</p>
                    <p>
                      Rule: {patchResult.rule} | Syntax valid:{' '}
                      {String(patchResult.syntax_valid)}
                    </p>
                    <p>
                      Original file modified:{' '}
                      {String(patchResult.original_modified)}
                    </p>
                    <p>
                      Runtime verification: {patchResult.verification || 'Pending'}
                    </p>
                    <p>
                      <strong>Important:</strong> Patch application and syntax
                      validation do not by themselves prove the vulnerability is fixed.
                    </p>
                  </div>
                )}
              </section>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}