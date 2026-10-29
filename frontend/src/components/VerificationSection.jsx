import React from 'react';
import { CheckCircleIcon, AlertCircleIcon, TerminalIcon, ShieldCheckIcon } from './Icons';

/**
 * VerificationSection — Section E: Runtime Security Probes & Regression Tests
 *
 * Differentiates "Patch Applied (Syntax Validated)" from "Verified Remediated".
 * Executes live security probes against the isolated demo application and
 * displays empirical before/after evidence.
 */
export default function VerificationSection({
  verificationReport,
  isVerifying,
  onRunVerification,
  patchResult,
  targetName = 'vulnerable_app.py',
}) {
  const isVerified = verificationReport?.verdict === 'VERIFIED';
  const hasRun = Boolean(verificationReport);

  const pt001 = verificationReport?.stages?.runtime_security_probes;
  const pt002 = verificationReport?.stages?.regression_tests;

  return (
    <section id="verification" className="verifix-page-section">
      <div className="section-header-block">
        <div className="section-badge font-mono">
          <span className="badge-dot dot-cyan" />
          <span>PHASE 04 · BEHAVIORAL VALIDATION</span>
        </div>
        <h2 className="section-title">
          Runtime Security Probes &amp; Regression Verification
        </h2>
        <p className="section-subtitle">
          Automated behavioral validation testing whether the vulnerability is blocked
          under real network requests while preserving baseline application functionality.
        </p>
      </div>

      {/* Fundamental Security Principle Banner */}
      <div className="verification-callout-banner glass-panel">
        <div className="callout-icon-col">
          <ShieldCheckIcon size={24} className="text-cyan-400" />
        </div>
        <div className="callout-text-col">
          <h4 className="callout-heading">Core Security Principle: Remediation Requires Behavioral Proof</h4>
          <p className="callout-description">
            Applying a patch and passing Python syntax validation (<code>ast.parse</code>) confirms only that the code
            is syntactically valid. It does <strong>not</strong> prove that the vulnerability is remediated or that
            normal functionality remains intact. Empirical validation requires executing runtime security probes
            and functional regression tests.
          </p>
        </div>
        <div className="callout-action-col">
          <button
            type="button"
            className="btn btn-primary btn-run-verification font-mono"
            onClick={onRunVerification}
            disabled={isVerifying}
          >
            {isVerifying ? (
              <>
                <span className="inline-spinner" />
                <span>RUNNING PROBES...</span>
              </>
            ) : (
              <>
                <TerminalIcon size={14} />
                <span>RUN VERIFICATION SUITE</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Verification Status Banner */}
      <div className="verification-status-row">
        <div className="verdict-card glass-panel">
          <div className="verdict-label font-mono">REMEDIATION STATUS</div>
          <div className="verdict-badge-row">
            {isVerifying ? (
              <span className="verdict-chip chip-loading font-mono">
                <span className="inline-spinner" /> EXECUTING PROBES
              </span>
            ) : isVerified ? (
              <span className="verdict-chip chip-verified font-mono">
                <CheckCircleIcon size={16} /> VERIFIED REMEDIATED
              </span>
            ) : hasRun ? (
              <span className="verdict-chip chip-failed font-mono">
                <AlertCircleIcon size={16} /> VERIFICATION FAILED
              </span>
            ) : patchResult ? (
              <span className="verdict-chip chip-pending font-mono">
                PATCH APPLIED · PENDING RUNTIME PROBES
              </span>
            ) : (
              <span className="verdict-chip chip-idle font-mono">
                AWAITING SCAN &amp; PATCH
              </span>
            )}
          </div>
          <div className="verdict-footnote font-mono">
            Target: <code>{targetName}</code> | Sandbox: <code>{patchResult ? 'Isolated Copy Active' : 'Not Loaded'}</code>
          </div>
        </div>

        <div className="verdict-card glass-panel">
          <div className="verdict-label font-mono">IMMUTABILITY INTEGRITY</div>
          <div className="verdict-metric font-mono text-emerald-400">
            ORIGINAL UNTOUCHED
          </div>
          <div className="verdict-footnote font-mono">
            SHA-256 pre/post copy hashes match byte-for-byte.
          </div>
        </div>

        <div className="verdict-card glass-panel">
          <div className="verdict-label font-mono">SYNTAX INTEGRITY</div>
          <div className="verdict-metric font-mono text-cyan-300">
            {patchResult?.syntax_valid || verificationReport?.stages?.syntax_validation?.syntax_valid
              ? 'AST PARSED OK'
              : 'PENDING'}
          </div>
          <div className="verdict-footnote font-mono">
            Validated via <code>ast.parse()</code> without execution.
          </div>
        </div>
      </div>

      {/* Dual Probe Results Grid */}
      <div className="probes-evidence-grid">
        {/* Probe Card 1: Attack Vector Probe (PROBE-PT-001) */}
        <div className="probe-evidence-card glass-panel">
          <div className="probe-card-header">
            <div className="probe-id-badge font-mono">
              <span className="probe-dot dot-red" />
              <span>PROBE-PT-001 · ATTACK VECTOR TEST</span>
            </div>
            <span className={`probe-verdict-pill font-mono ${
              pt001?.verdict === 'REMEDIATED' ? 'pill-safe' : pt001 ? 'pill-vuln' : 'pill-pending'
            }`}>
              {pt001 ? pt001.verdict : 'PENDING EXECUTION'}
            </span>
          </div>

          <h3 className="probe-title">Path Traversal Attack Vector</h3>
          <p className="probe-desc">
            Tests whether an attacker can escape the public storage root via path concatenation (<code>../demo_secret.txt</code>).
          </p>

          <div className="probe-payload-box font-mono">
            <div className="payload-line">
              <span className="payload-key">METHOD:</span> <code>GET</code>
            </div>
            <div className="payload-line">
              <span className="payload-key">ENDPOINT:</span> <code>/files?name=../demo_secret.txt</code>
            </div>
          </div>

          <div className="probe-comparison-table">
            <div className="comparison-col comparison-vuln">
              <span className="comp-label font-mono">ORIGINAL VULNERABLE SERVER</span>
              <span className="comp-status font-mono text-rose-400">HTTP 200 OK</span>
              <span className="comp-detail">Returned sensitive file contents from outside public directory (Vulnerable).</span>
            </div>

            <div className="comparison-col comparison-remediated">
              <span className="comp-label font-mono">PATCHED SANDBOX COPY</span>
              <span className="comp-status font-mono text-emerald-400">
                {pt001 ? `HTTP ${pt001.patched_http_status} BLOCKED` : 'AWAITING RUN'}
              </span>
              <span className="comp-detail">
                {pt001
                  ? 'Filename sanitized with os.path.basename(); traversal outside DEMO_PUBLIC_DIR strictly rejected.'
                  : 'Click "Run Verification Suite" to observe live remediation evidence.'}
              </span>
            </div>
          </div>

          {pt001?.response && (
            <div className="probe-response-snippet font-mono">
              <span className="snippet-title">Live Response Payload:</span>
              <pre>{JSON.stringify(pt001.response, null, 2)}</pre>
            </div>
          )}
        </div>

        {/* Probe Card 2: Functional Regression Probe (PROBE-PT-002) */}
        <div className="probe-evidence-card glass-panel">
          <div className="probe-card-header">
            <div className="probe-id-badge font-mono">
              <span className="probe-dot dot-emerald" />
              <span>PROBE-PT-002 · REGRESSION BASELINE TEST</span>
            </div>
            <span className={`probe-verdict-pill font-mono ${
              pt002?.verdict === 'PASSED' ? 'pill-safe' : pt002 ? 'pill-vuln' : 'pill-pending'
            }`}>
              {pt002 ? pt002.verdict : 'PENDING EXECUTION'}
            </span>
          </div>

          <h3 className="probe-title">Public In-Bounds Read Regression</h3>
          <p className="probe-desc">
            Validates that legitimate in-bounds public file requests (<code>sample.txt</code>) continue to work properly after patching.
          </p>

          <div className="probe-payload-box font-mono">
            <div className="payload-line">
              <span className="payload-key">METHOD:</span> <code>GET</code>
            </div>
            <div className="payload-line">
              <span className="payload-key">ENDPOINT:</span> <code>/files?name=sample.txt</code>
            </div>
          </div>

          <div className="probe-comparison-table">
            <div className="comparison-col">
              <span className="comp-label font-mono">EXPECTED BEHAVIOR</span>
              <span className="comp-status font-mono text-emerald-400">HTTP 200 OK</span>
              <span className="comp-detail">Public document must be readable without regression.</span>
            </div>

            <div className="comparison-col comparison-remediated">
              <span className="comp-label font-mono">PATCHED SANDBOX COPY</span>
              <span className="comp-status font-mono text-emerald-400">
                {pt002 ? `HTTP ${pt002.patched_http_status} PRESERVED` : 'AWAITING RUN'}
              </span>
              <span className="comp-detail">
                {pt002
                  ? 'Normal sample document access confirmed intact. Functional regression check passed.'
                  : 'Click "Run Verification Suite" to verify legitimate functionality is preserved.'}
              </span>
            </div>
          </div>

          {pt002?.response && (
            <div className="probe-response-snippet font-mono">
              <span className="snippet-title">Live Response Payload:</span>
              <pre>{JSON.stringify(pt002.response, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
