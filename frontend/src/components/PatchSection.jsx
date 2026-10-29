import React from 'react';
import { LockIcon, CheckCircleIcon, AlertCircleIcon, TerminalIcon } from './Icons';

/**
 * PatchSection — Section D: Sandbox Patching Workspace
 *
 * Implements approved sandbox patching for rule PY002.
 * Enforces and displays the immutability guarantee: the original source file
 * is strictly immutable, with patches applied only to a temporary sandbox copy.
 */
export default function PatchSection({
  findings = [],
  onApplyPatch,
  patchResult,
  isPatching,
  patchError,
  targetName = 'vulnerable_app.py',
}) {
  const hasPy002 = findings.some((f) => f.rule === 'PY002');

  return (
    <section id="patch" className="verifix-page-section">
      <div className="section-header-block">
        <div className="section-badge font-mono">
          <span className="badge-dot dot-cyan" />
          <span>PHASE 03 · SANDBOX REMEDIATION</span>
        </div>
        <h2 className="section-title">
          Controlled Sandbox Patching Workspace
        </h2>
        <p className="section-subtitle">
          Apply approved automated security fixes strictly to an isolated temporary sandbox copy.
          The production source code remains completely unmodified.
        </p>
      </div>

      {/* Immutability Guarantee Banner */}
      <div className="patch-guarantee-banner glass-panel">
        <div className="guarantee-icon-col">
          <LockIcon size={24} className="text-cyan-400" />
        </div>
        <div className="guarantee-text-col">
          <h4 className="guarantee-title">VerifiX Immutability &amp; Isolation Protocol</h4>
          <p className="guarantee-desc">
            To prevent accidental corruption or unintended changes to production code, all remediation
            operations are performed on an ephemeral working copy created via <code>create_sandbox_copy()</code>.
            Both the original source file and the sandbox copy are cryptographically fingerprinted using SHA-256.
          </p>
        </div>
        <div className="guarantee-badges-col font-mono">
          <div className="mini-badge-item">
            <span className="badge-bullet text-emerald-400">✓</span>
            <span>Target: <code>{targetName}</code></span>
          </div>
          <div className="mini-badge-item">
            <span className="badge-bullet text-emerald-400">✓</span>
            <span>Original Modified: <code>FALSE</code></span>
          </div>
          <div className="mini-badge-item">
            <span className="badge-bullet text-emerald-400">✓</span>
            <span>AST Syntax Validation: <code>ast.parse()</code></span>
          </div>
        </div>
      </div>

      {/* Patch Action & Code Diff Container */}
      <div className="patch-workspace-grid">
        {/* Left Col: Patch Trigger & Status */}
        <div className="patch-controls-card glass-panel">
          <div className="card-kicker font-mono">REMEDIATION TARGET</div>
          <h3 className="card-title">Rule PY002: Path Traversal Remediation</h3>
          <p className="card-desc">
            Replaces raw <code>os.path.join()</code> concatenation with strict <code>os.path.basename()</code> filename
            sanitization and confines path resolution strictly to <code>DEMO_PUBLIC_DIR</code>.
          </p>

          <div className="patch-action-box">
            <button
              type="button"
              className="btn btn-primary btn-apply-patch font-mono"
              onClick={() => onApplyPatch('PY002')}
              disabled={isPatching}
            >
              {isPatching ? (
                <>
                  <span className="inline-spinner" />
                  <span>CREATING SANDBOX &amp; APPLYING...</span>
                </>
              ) : (
                <>
                  <TerminalIcon size={14} />
                  <span>APPLY SANDBOX PATCH (PY002)</span>
                </>
              )}
            </button>

            {!hasPy002 && (
              <span className="patch-hint-text font-mono">
                Note: PY002 was not triggered in current findings, but you can still run sandbox patching against the target file.
              </span>
            )}
          </div>

          {patchError && (
            <div className="patch-error-box glass-panel font-mono" role="alert">
              <AlertCircleIcon size={16} className="text-rose-400" />
              <span>Patch failed: {patchError}</span>
            </div>
          )}

          {patchResult && (
            <div className="patch-result-card glass-panel" role="status">
              <div className="result-header-row">
                <span className="result-status-chip chip-applied font-mono">
                  <CheckCircleIcon size={14} /> {patchResult.status}
                </span>
                <span className="result-rule-chip font-mono">RULE {patchResult.rule}</span>
              </div>

              <p className="result-message font-mono text-xs">{patchResult.message}</p>

              <div className="result-hashes-grid font-mono">
                <div className="hash-item">
                  <span className="hash-label">ORIGINAL SHA-256:</span>
                  <code className="hash-val" title={patchResult.original_hash}>
                    {patchResult.original_hash ? `${patchResult.original_hash.slice(0, 16)}...` : '—'}
                  </code>
                </div>
                <div className="hash-item">
                  <span className="hash-label">PATCHED SHA-256:</span>
                  <code className="hash-val text-cyan-300" title={patchResult.patched_hash}>
                    {patchResult.patched_hash ? `${patchResult.patched_hash.slice(0, 16)}...` : '—'}
                  </code>
                </div>
              </div>

              <div className="result-meta-row font-mono">
                <span className="meta-tag">Syntax Valid: <strong>{String(patchResult.syntax_valid)}</strong></span>
                <span className="meta-tag">Original Modified: <strong>{String(patchResult.original_modified)}</strong></span>
              </div>

              {patchResult.sandbox_path && (
                <div className="result-sandbox-path font-mono">
                  <span className="path-label">SANDBOX COPY:</span>
                  <code className="path-text" title={patchResult.sandbox_path}>{patchResult.sandbox_path}</code>
                </div>
              )}

              <div className="result-next-step-prompt font-mono">
                <span className="next-step-arrow">↓</span>
                <span>Proceed to <strong>Phase 04 Verification</strong> below to run runtime security probes.</span>
              </div>
            </div>
          )}
        </div>

        {/* Right Col: Code Transformation Diff Viewer */}
        <div className="patch-code-preview-card glass-panel font-mono">
          <div className="diff-header-bar">
            <span className="diff-title">PROPOSED CODE TRANSFORMATION (PY002)</span>
            <span className="diff-tag">AST BOUNDARY ENFORCEMENT</span>
          </div>

          <div className="diff-content-wrapper">
            <div className="diff-block diff-vulnerable">
              <div className="diff-line-header font-bold text-rose-400">
                <span>BEFORE (Vulnerable Concatenation):</span>
              </div>
              <pre className="diff-code text-xs">
{`# Vulnerable: path traversal outside public root
candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), name)
resolved_path = Path(candidate_path).resolve()

if not resolved_path.is_relative_to(DEMO_STORAGE_DIR):
    return jsonify({"error": "Access denied"}), 403`}
              </pre>
            </div>

            <div className="diff-block diff-patched">
              <div className="diff-line-header font-bold text-emerald-400">
                <span>AFTER (Sanitized Sandbox Remediation):</span>
              </div>
              <pre className="diff-code text-xs">
{`# PATCHED (PY002): sanitize filename with os.path.basename
safe_name = os.path.basename(name)
candidate_path = os.path.join(str(DEMO_PUBLIC_DIR), safe_name)
resolved_path = Path(candidate_path).resolve()

# Strict boundary confined to public directory only
if not resolved_path.is_relative_to(DEMO_PUBLIC_DIR):
    return jsonify({"error": "Access denied"}), 403`}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
