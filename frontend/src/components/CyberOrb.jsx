import React, { useEffect, useRef, useState } from 'react';

/**
 * CyberOrb — 3D Security Telemetry Visual Centerpiece
 * Inspired by spatial depth and rotational mechanics of the ThreeUI Orb Gallery.
 * Built with native HTML5 Canvas 2D + 3D mathematical perspective projection.
 *
 * Strict Brand Palette:
 * - Charcoal Black: #171717
 * - Forest Green:   #06110C (accents: #16a34a, #22c55e)
 * - Crimson Red:    #A31C1B (accents: #dc2626, #ef4444)
 * - Muted Grays & Off-White (#737373, #a3a3a3, #f5f5f5)
 */

export default function CyberOrb({ state = 'idle', findingCount = 0 }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);

  // Rotational physics state
  const rotRef = useRef({ x: 18, y: 0, vx: 0, vy: 0 });
  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const [hudCoords, setHudCoords] = useState({ x: 18, y: 0 });

  // Determine state-driven color palette and velocity parameters
  const getTheme = () => {
    switch (state) {
      case 'scanning':
        return {
          primary: '#f5f5f5',
          accent: '#22c55e',
          alert: '#A31C1B',
          glowCore: 'rgba(255, 255, 255, 0.18)',
          glowRing: 'rgba(34, 197, 94, 0.45)',
          scanBeam: 'rgba(255, 255, 255, 0.75)',
          baseSpeedY: 0.038,
          label: 'SCANNING AST & REASONING',
          badgeClass: 'orb-badge-scanning',
        };
      case 'alert':
        return {
          primary: '#ef4444',
          accent: '#A31C1B',
          alert: '#A31C1B',
          glowCore: 'rgba(163, 28, 27, 0.35)',
          glowRing: 'rgba(220, 38, 38, 0.45)',
          scanBeam: 'rgba(239, 68, 68, 0.4)',
          baseSpeedY: 0.012,
          label: `${findingCount} VULNERABILITY FINDING${findingCount > 1 ? 'S' : ''}`,
          badgeClass: 'orb-badge-alert',
        };
      case 'secure':
        return {
          primary: '#22c55e',
          accent: '#16a34a',
          alert: '#06110C',
          glowCore: 'rgba(22, 163, 74, 0.28)',
          glowRing: 'rgba(34, 197, 94, 0.4)',
          scanBeam: 'rgba(34, 197, 94, 0.3)',
          baseSpeedY: 0.01,
          label: 'ZERO AST VIOLATIONS (CLEAN)',
          badgeClass: 'orb-badge-secure',
        };
      case 'error':
        return {
          primary: '#f87171',
          accent: '#A31C1B',
          alert: '#A31C1B',
          glowCore: 'rgba(163, 28, 27, 0.25)',
          glowRing: 'rgba(248, 113, 113, 0.4)',
          scanBeam: 'rgba(248, 113, 113, 0.3)',
          baseSpeedY: 0.008,
          label: 'PARSER REJECTED (400)',
          badgeClass: 'orb-badge-error',
        };
      case 'idle':
      default:
        return {
          primary: '#e5e5e5',
          accent: '#16a34a',
          alert: '#A31C1B',
          glowCore: 'rgba(255, 255, 255, 0.1)',
          glowRing: 'rgba(115, 115, 115, 0.35)',
          scanBeam: 'rgba(255, 255, 255, 0.15)',
          baseSpeedY: 0.008,
          label: 'SYSTEM STANDBY · AST IDLE',
          badgeClass: 'orb-badge-idle',
        };
    }
  };

  const theme = getTheme();

  // Mouse drag interaction
  const handleMouseDown = (e) => {
    isDraggingRef.current = true;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e) => {
    if (!isDraggingRef.current) return;
    const deltaX = e.clientX - lastMouseRef.current.x;
    const deltaY = e.clientY - lastMouseRef.current.y;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };

    rotRef.current.vx = deltaX * 0.35;
    rotRef.current.vy = -deltaY * 0.35;
  };

  const handleMouseUp = () => {
    isDraggingRef.current = false;
  };

  // Main 3D Canvas Rendering Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;

    // Check prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Generate 3D Spherical Fibonacci Nodes
    const nodeCount = 110;
    const sphereRadius = 92;
    const nodes = [];

    const goldenAngle = Math.PI * (3 - Math.sqrt(5)); // ~2.3999 rad
    for (let i = 0; i < nodeCount; i++) {
      const y = 1 - (i / (nodeCount - 1)) * 2; // y goes from 1 to -1
      const radiusAtY = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = goldenAngle * i;

      const x = Math.cos(theta) * radiusAtY;
      const z = Math.sin(theta) * radiusAtY;

      // Classify node roles: telemetry plates, alert markers, baseline nodes
      const isAnchor = i % 7 === 0;
      const isAlertMarker = state === 'alert' && i % 4 === 0;

      nodes.push({
        x: x * sphereRadius,
        y: y * sphereRadius,
        z: z * sphereRadius,
        isAnchor,
        isAlertMarker,
        pulseOffset: Math.random() * Math.PI * 2,
        baseSize: isAnchor ? 2.6 : 1.4,
      });
    }

    // Concentric 3D Rings definition (equator and polar ring)
    const ringSegments = 48;
    const rings = [
      { radius: sphereRadius * 1.08, tiltX: 0, tiltZ: 0.1, color: theme.glowRing },
      { radius: sphereRadius * 1.22, tiltX: 0.65, tiltZ: -0.35, color: 'rgba(115, 115, 115, 0.22)' },
    ];

    let scanBeamY = -sphereRadius;
    let scanDirection = 1;
    let timeTick = 0;

    const render = () => {
      timeTick += 0.02;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const cx = canvas.width / 2;
      const cy = canvas.height / 2;

      // Apply rotation physics with inertial dampening
      if (!isDraggingRef.current) {
        rotRef.current.vx *= 0.94;
        rotRef.current.vy *= 0.94;
      }

      if (!prefersReducedMotion) {
        rotRef.current.y += (rotRef.current.vx + (isDraggingRef.current ? 0 : theme.baseSpeedY * 57.3));
        rotRef.current.x += rotRef.current.vy;
      }

      // Constrain vertical tilt
      rotRef.current.x = Math.max(-65, Math.min(65, rotRef.current.x));
      rotRef.current.y = rotRef.current.y % 360;

      const radX = (rotRef.current.x * Math.PI) / 180;
      const radY = (rotRef.current.y * Math.PI) / 180;

      // Update scan sweep
      if (state === 'scanning' && !prefersReducedMotion) {
        scanBeamY += 2.4 * scanDirection;
        if (scanBeamY > sphereRadius || scanBeamY < -sphereRadius) {
          scanDirection *= -1;
        }
      }

      // Draw Central Radial Atmosphere
      const coreGrad = ctx.createRadialGradient(cx, cy, 10, cx, cy, sphereRadius * 1.25);
      coreGrad.addColorStop(0, theme.glowCore);
      coreGrad.addColorStop(0.5, 'rgba(23, 23, 23, 0.2)');
      coreGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = coreGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, sphereRadius * 1.3, 0, Math.PI * 2);
      ctx.fill();

      // Transform 3D Nodes
      const cosY = Math.cos(radY);
      const sinY = Math.sin(radY);
      const cosX = Math.cos(radX);
      const sinX = Math.sin(radX);

      const projectedNodes = nodes.map((n) => {
        // Y rotation
        const x1 = n.x * cosY + n.z * sinY;
        const z1 = -n.x * sinY + n.z * cosY;

        // X rotation
        const y2 = n.y * cosX - z1 * sinX;
        const z2 = n.y * sinX + z1 * cosX;

        // Perspective depth projection
        const focal = 240;
        const depth = focal / (focal + z2);

        return {
          sx: cx + x1 * depth,
          sy: cy + y2 * depth,
          z: z2,
          depth,
          isAnchor: n.isAnchor,
          isAlertMarker: n.isAlertMarker,
          baseSize: n.baseSize,
          pulseOffset: n.pulseOffset,
        };
      });

      // Sort back-to-front
      projectedNodes.sort((a, b) => a.z - b.z);

      // Render 3D Rings
      rings.forEach((ring) => {
        ctx.beginPath();
        let first = true;
        for (let i = 0; i <= ringSegments; i++) {
          const theta = (i / ringSegments) * Math.PI * 2;
          let rx = Math.cos(theta) * ring.radius;
          let ry = Math.sin(theta) * ring.radius * Math.sin(ring.tiltX);
          let rz = Math.sin(theta) * ring.radius * Math.cos(ring.tiltX);

          // Apply global rotation
          const x1 = rx * cosY + rz * sinY;
          const z1 = -rx * sinY + rz * cosY;
          const y2 = ry * cosX - z1 * sinX;
          const z2 = ry * sinX + z1 * cosX;

          const focal = 240;
          const depth = focal / (focal + z2);
          const px = cx + x1 * depth;
          const py = cy + y2 * depth;

          if (first) {
            ctx.moveTo(px, py);
            first = false;
          } else {
            ctx.lineTo(px, py);
          }
        }
        ctx.strokeStyle = ring.color;
        ctx.lineWidth = 1;
        ctx.stroke();
      });

      // Render Connecting Geodesic Mesh Arcs (between front nodes only)
      ctx.lineWidth = 0.6;
      for (let i = 0; i < projectedNodes.length; i++) {
        const p1 = projectedNodes[i];
        if (p1.z < 0) continue; // Skip back hemisphere

        for (let j = i + 1; j < projectedNodes.length; j++) {
          const p2 = projectedNodes[j];
          if (p2.z < 0) continue;

          const dx = p1.sx - p2.sx;
          const dy = p1.sy - p2.sy;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 34) {
            const alpha = (1 - dist / 34) * 0.3 * ((p1.z + sphereRadius) / (2 * sphereRadius));
            ctx.strokeStyle = state === 'alert'
              ? `rgba(163, 28, 27, ${alpha * 1.5})`
              : `rgba(245, 245, 245, ${alpha})`;
            ctx.beginPath();
            ctx.moveTo(p1.sx, p1.sy);
            ctx.lineTo(p2.sx, p2.sy);
            ctx.stroke();
          }
        }
      }

      // Render 3D Spherical Nodes
      projectedNodes.forEach((p) => {
        const alpha = Math.max(0.12, Math.min(1, (p.z + sphereRadius) / (2 * sphereRadius)));
        ctx.globalAlpha = alpha;

        const size = Math.max(0.7, p.baseSize * p.depth);

        if (p.isAlertMarker) {
          // Crimson threat marker node
          ctx.fillStyle = '#ef4444';
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, size * 1.5, 0, Math.PI * 2);
          ctx.fill();

          ctx.strokeStyle = '#A31C1B';
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, size * 2.8, 0, Math.PI * 2);
          ctx.stroke();
        } else if (p.isAnchor) {
          // Major telemetry node
          ctx.fillStyle = theme.primary;
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, size * 1.3, 0, Math.PI * 2);
          ctx.fill();

          if (p.z > sphereRadius * 0.3) {
            ctx.strokeStyle = theme.accent;
            ctx.lineWidth = 0.8;
            ctx.beginPath();
            ctx.arc(p.sx, p.sy, size * 2.2, 0, Math.PI * 2);
            ctx.stroke();
          }
        } else {
          // Regular geodesic node
          ctx.fillStyle = p.z > 0 ? '#e5e5e5' : '#737373';
          ctx.beginPath();
          ctx.arc(p.sx, p.sy, size, 0, Math.PI * 2);
          ctx.fill();
        }
      });

      // Render Active Radar / Scanning Laser Sweep Line
      if (state === 'scanning' && !prefersReducedMotion) {
        ctx.globalAlpha = 0.8;
        ctx.strokeStyle = theme.scanBeam;
        ctx.lineWidth = 1.6;

        const chordHalfWidth = Math.sqrt(Math.max(0, sphereRadius * sphereRadius - scanBeamY * scanBeamY));
        const focal = 240;
        const depth = focal / (focal + 0);

        ctx.beginPath();
        ctx.moveTo(cx - chordHalfWidth * depth, cy + scanBeamY * depth);
        ctx.lineTo(cx + chordHalfWidth * depth, cy + scanBeamY * depth);
        ctx.stroke();

        ctx.fillStyle = 'rgba(255, 255, 255, 0.08)';
        ctx.fillRect(
          cx - chordHalfWidth * depth,
          cy + scanBeamY * depth - 4,
          chordHalfWidth * 2 * depth,
          8
        );
      }

      ctx.globalAlpha = 1.0;

      // Update HUD coordinate state occasionally without thrashing renders
      if (Math.round(timeTick * 10) % 15 === 0) {
        setHudCoords({
          x: Math.round(rotRef.current.x),
          y: Math.round(rotRef.current.y),
        });
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [state, theme]);

  return (
    <div
      ref={containerRef}
      className={`cyber-orb-wrapper orb-state-${state}`}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      title="3D Security Verification Core (Drag to rotate sphere)"
    >
      <div className="orb-viewport">
        <canvas
          ref={canvasRef}
          width={240}
          height={240}
          className="orb-canvas"
        />

        {/* HUD Telemetry Overlay */}
        <div className="orb-hud-tag-bar">
          <span className={`orb-status-pill ${theme.badgeClass}`}>
            <span className="orb-status-dot" />
            {theme.label}
          </span>
          <span className="orb-telemetry-coords">
            P_X: {hudCoords.x}° · P_Y: {hudCoords.y}°
          </span>
        </div>
      </div>
    </div>
  );
}
