import React, { useEffect, useRef, useState } from 'react';

/**
 * CyberReticle — Floating Cybernetic HUD Crosshair & Target Tracker
 * Follows mouse position with smooth spring interpolation and zero pointer interference.
 * Color adapts dynamically:
 * - Crimson Red (#A31C1B): targeting security risk / vulnerability finding
 * - Emerald / Forest Green (#22c55e / #06110C): targeting clean verified node
 * - Cyan / Sky (#38bdf8): idle scanning / general orbital tracking
 */
export default function CyberReticle({
  active = true,
  cursorCoords = { x: 0, y: 0, nx: '+0.00', ny: '+0.00' },
  activeTarget = null,
  isVulnerableTarget = false,
}) {
  const containerRef = useRef(null);
  const targetPos = useRef({ x: window.innerWidth / 2, y: window.innerHeight / 2 });
  const currentPos = useRef({ x: window.innerWidth / 2, y: window.innerHeight / 2 });
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const handleMouseMove = (e) => {
      targetPos.current.x = e.clientX;
      targetPos.current.y = e.clientY;
      if (!isVisible) setIsVisible(true);
    };

    const handleMouseLeave = () => {
      setIsVisible(false);
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    document.addEventListener('mouseleave', handleMouseLeave);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, [isVisible]);

  useEffect(() => {
    let animId;

    const renderLoop = () => {
      if (active) {
        currentPos.current.x += (targetPos.current.x - currentPos.current.x) * 0.22;
        currentPos.current.y += (targetPos.current.y - currentPos.current.y) * 0.22;

        if (containerRef.current) {
          containerRef.current.style.transform = `translate3d(${currentPos.current.x}px, ${currentPos.current.y}px, 0)`;
        }
      }
      animId = requestAnimationFrame(renderLoop);
    };

    animId = requestAnimationFrame(renderLoop);
    return () => cancelAnimationFrame(animId);
  }, [active]);

  if (!active) return null;

  const coordText = `[${cursorCoords.nx || '+0.00'}, ${cursorCoords.ny || '+0.00'}]`;
  const hasLock = Boolean(activeTarget);

  return (
    <div
      ref={containerRef}
      className={`cursor-hud-tracker ${isVisible ? 'opacity-100' : 'opacity-0'} ${
        isVulnerableTarget ? 'theme-crimson' : hasLock ? 'theme-green' : 'theme-cyan'
      }`}
      aria-hidden="true"
    >
      {/* Subtle ambient light glow following cursor */}
      <div className="cursor-ambient-glow" />

      {/* Cyber Crosshair Reticle Center */}
      <div className="reticle-core-group">
        {/* Outer Rotating Calibration Ring */}
        <div className="reticle-outer-ring" />

        {/* Targeted Lock Ring */}
        <div className={`reticle-lock-ring ${hasLock ? 'locked' : ''}`}>
          <div className="reticle-lock-arc" />
        </div>

        {/* Crosshair Spikes */}
        <div className="crosshair-tick tick-left" />
        <div className="crosshair-tick tick-right" />
        <div className="crosshair-tick tick-top" />
        <div className="crosshair-tick tick-bottom" />

        {/* Center Core Dot */}
        <div className={`reticle-center-dot ${hasLock ? 'dot-locked' : ''}`} />

        {/* Floating Coordinates Tag & Lock-On Indicator */}
        <div className="reticle-tags-stack">
          <div className="reticle-coords-badge">
            <span className="coords-ping-dot" />
            <span className="font-mono">{coordText}</span>
          </div>

          {hasLock && (
            <div className={`reticle-lock-badge ${isVulnerableTarget ? 'badge-danger' : 'badge-safe'}`}>
              <span className="lock-label">LOCK:</span>
              <span className="lock-target font-mono">{activeTarget}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

