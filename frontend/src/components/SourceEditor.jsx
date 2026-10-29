import React from 'react';
import { PRESET_SNIPPETS } from '../data/presets';
import { LockIcon, TerminalIcon, PlayIcon } from './Icons';

export default function SourceEditor({
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
}) {
  const lineCount = (source.match(/\n/g) || []).length + 1;
  const byteCount = new Blob([source]).size;
  const maxBytes = 512 * 1024;
  const bytePercentage = Math.min(100, Math.round((byteCount / maxBytes) * 100));

  const handleSelectPreset = (preset) => {
    setActivePresetId(preset.id);
    setSource(preset.code);
    setFilename(preset.filename);
  };

  const handleClear = () => {
    setActivePresetId(null);
    setSource('');
    setFilename('custom_input.py');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = e.target.selectionStart;
      const end = e.target.selectionEnd;
      const newSource = source.substring(0, start) + '    ' + source.substring(end);
      setSource(newSource);
      setTimeout(() => {
        e.target.selectionStart = e.target.selectionEnd = start + 4;
      }, 0);
    }
  };

  return (
    <section className="panel-container editor-panel">
      <div className="panel-header">
        <div className="panel-title-group">
          <span className="panel-eyebrow">INPUT WORKSPACE</span>
          <h2 className="panel-title">Python Source Code</h2>
        </div>
        <div className="filename-input-group">
          <label htmlFor="filename-input" className="filename-label">
            Target File:
          </label>
          <input
            id="filename-input"
            type="text"
            className="text-input filename-field"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            placeholder="target_script.py"
            disabled={isLoading}
            maxLength={256}
          />
        </div>
      </div>

      {/* Preset Snippets Tab Bar */}
      <div className="presets-container">
        <span className="presets-header-label">Reference Test Cases:</span>
        <div className="presets-tabs-list">
          {PRESET_SNIPPETS.map((preset) => {
            const isActive = activePresetId === preset.id;
            let badgeClass = 'badge-high';
            if (preset.severity === 'critical') badgeClass = 'badge-critical';
            if (preset.severity === 'medium') badgeClass = 'badge-medium';
            if (preset.severity === 'safe') badgeClass = 'badge-safe';
            if (preset.severity === 'error') badgeClass = 'badge-error';

            return (
              <button
                key={preset.id}
                type="button"
                className={`preset-tab ${isActive ? 'preset-tab-active' : ''}`}
                onClick={() => handleSelectPreset(preset)}
                disabled={isLoading}
                title={preset.description}
              >
                <span className={`preset-rule-tag ${badgeClass}`}>{preset.rule}</span>
                <span className="preset-title-text">{preset.title}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Code Area with Line Numbers */}
      <div className="code-editor-viewport">
        <div className="code-gutter" aria-hidden="true">
          {Array.from({ length: Math.max(1, lineCount) }).map((_, i) => (
            <span key={i + 1} className="gutter-number">
              {i + 1}
            </span>
          ))}
        </div>
        <textarea
          className="code-input-area"
          value={source}
          onChange={(e) => {
            setSource(e.target.value);
            setActivePresetId(null);
          }}
          onKeyDown={handleKeyDown}
          placeholder="# Enter or paste Python source code for static AST analysis...&#10;# (Source is parsed into an abstract syntax tree and never executed)"
          spellCheck="false"
          disabled={isLoading}
        />
      </div>

      {/* Footer Controls & Actions */}
      <div className="editor-controls-footer">
        <div className="editor-status-indicators">
          <span className="telemetry-item">Lines: {lineCount}</span>
          <span className="telemetry-item">
            Payload: {byteCount.toLocaleString()} / {maxBytes.toLocaleString()} B ({bytePercentage}%)
          </span>
          <span className="safe-input-indicator" title="Source is analyzed by AST parse only; never executed.">
            <LockIcon size={12} />
            <span>Non-Executable Input</span>
          </span>
        </div>

        <div className="action-buttons-group">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleClear}
            disabled={isLoading || !source}
          >
            Clear
          </button>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={onScanTarget}
            disabled={isLoading}
            title="Scan vulnerable_app.py on backend server disk (/scan)"
          >
            {isLoading && loadingAction === 'scan' ? (
              <span className="inline-spinner" />
            ) : (
              <TerminalIcon size={13} />
            )}
            <span>Scan Server Disk (/scan)</span>
          </button>

          <button
            type="button"
            className="btn btn-primary"
            onClick={onAnalyze}
            disabled={isLoading || !source.trim()}
            title="Execute AST parsing, offline reasoning, and audit logging (/analyze)"
          >
            {isLoading && loadingAction === 'analyze' ? (
              <>
                <span className="inline-spinner" />
                <span>Analyzing AST...</span>
              </>
            ) : (
              <>
                <PlayIcon size={12} />
                <span>Analyze Code (/analyze)</span>
              </>
            )}
          </button>
        </div>
      </div>
    </section>
  );
}
