import React, { useEffect, useRef, useCallback } from 'react';
import * as THREE from 'three';

// 32 Distinct Security Telemetry & Rule Nodes
export const DEFAULT_SECURITY_NODES = [
  { id: 'node-py002', title: 'Path Traversal (PY002)', tag: 'AST RULE', color: '#A31C1B', bg: '#171717', severity: 'high', desc: 'Direct concatenation to os.path.join without normalization.' },
  { id: 'node-py003', title: 'SQL Injection (PY003)', tag: 'AST RULE', color: '#A31C1B', bg: '#171717', severity: 'high', desc: 'Dynamic f-string formatting in SQL statements.' },
  { id: 'node-auth001', title: 'BOLA Authorization (AUTH001)', tag: 'AST RULE', color: '#f59e0b', bg: '#171717', severity: 'medium', desc: 'Missing document ownership verification on ID lookup.' },
  { id: 'node-py001', title: 'Dynamic Eval (PY001)', tag: 'AST RULE', color: '#A31C1B', bg: '#171717', severity: 'critical', desc: 'eval() called on untrusted dynamic variable input.' },
  { id: 'node-py004', title: 'Shell Injection (PY004)', tag: 'AST RULE', color: '#A31C1B', bg: '#171717', severity: 'critical', desc: 'Insecure subprocess execution with shell=True.' },
  { id: 'node-py005', title: 'Unsafe Deserialization (PY005)', tag: 'AST RULE', color: '#A31C1B', bg: '#171717', severity: 'high', desc: 'pickle.loads() or yaml.load() called without safe loader.' },
  { id: 'node-audit', title: 'SHA-256 Audit Ledger', tag: 'INTEGRITY', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Cryptographic hash chaining of scan events in audit_log.jsonl.' },
  { id: 'node-reasoning', title: 'Causal Reasoning Engine', tag: 'OFFLINE AI', color: '#38bdf8', bg: '#082f49', severity: 'info', desc: 'Rule-backed causal hypotheses generated without remote API leaks.' },
  { id: 'node-grammar', title: 'AST Parser Boundary', tag: 'SYNTAX', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Strict AST analysis without runtime code execution.' },
  { id: 'node-probes', title: 'Runtime Probe Allow-List', tag: 'VALIDATION', color: '#38bdf8', bg: '#082f49', severity: 'info', desc: 'Strictly sandboxed authorization probes requiring manual approval.' },
  { id: 'node-bandit', title: 'Bandit Rule Baseline', tag: 'BENCHMARK', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Deterministic comparison against Bandit static analyzer baseline.' },
  { id: 'node-nonexec', title: 'Zero-Execution Guarantee', tag: 'SANDBOX', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Untrusted user payloads parsed via Python ast.parse() only.' },
  { id: 'node-symbol', title: 'Static Symbol Table', tag: 'ANALYSIS', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Lexical and syntactic scope tracking across function definitions.' },
  { id: 'node-sqli-guard', title: 'Parameterized SQL Gate', tag: 'SECURITY', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Ensures database queries use positional parameter placeholders.' },
  { id: 'node-path-canon', title: 'Path Canonicalization', tag: 'SECURITY', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Enforces Path.resolve() sandbox boundary verification.' },
  { id: 'node-acl', title: 'ACL Ownership Validator', tag: 'AUTH GUARD', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Validates user token ownership against resource tenancy.' },
  { id: 'node-crypto', title: 'Audit Hash Chainer', tag: 'LEDGER', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Tamper-evident audit trail with SHA-256 rolling digest.' },
  { id: 'node-telemetry', title: 'Telemetry Command Core', tag: 'COMMAND', color: '#38bdf8', bg: '#082f49', severity: 'info', desc: 'Live system status, active rule suite, and scope monitoring.' },
  { id: 'node-payload', title: 'Payload Size Enforcer', tag: 'GATEWAY', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Strict 512 KB payload ceiling to prevent DoS attacks.' },
  { id: 'node-err-mask', title: 'Internal Error Masking', tag: 'HARDENING', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Zero stack trace leakage; generic 500 error sanitization.' },
  { id: 'node-fastapi', title: 'FastAPI High-Speed Core', tag: 'BACKEND', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Asynchronous Python scanner service on port 8000.' },
  { id: 'node-offline', title: 'Offline-First Engine', tag: 'COMPLIANCE', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Air-gapped security analysis; no third-party data telemetry.' },
  { id: 'node-evidence', title: 'Evidence Trace Logger', tag: 'AUDIT', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Pinpoints exact source line numbers and code snippets.' },
  { id: 'node-disclaimer', title: 'Verification Boundary', tag: 'ASSURANCE', color: '#38bdf8', bg: '#082f49', severity: 'info', desc: 'Honest distinction between AST matches and verified exploits.' },
  { id: 'node-cors', title: 'Reverse Proxy Shield', tag: 'NETWORK', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Vite reverse proxy isolation (/api -> 127.0.0.1:8000).' },
  { id: 'node-eval-report', title: 'Evaluation Benchmark Suite', tag: 'METRICS', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Precision, recall, and F1 scoring against ground truth.' },
  { id: 'node-yaml-safe', title: 'PyYAML SafeLoader Enforcer', tag: 'PARSER', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Prevents arbitrary Python object instantiation from YAML.' },
  { id: 'node-shell-args', title: 'Subprocess Argument List', tag: 'EXECUTION', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'Enforces array arguments without shell interpretation.' },
  { id: 'node-reticle', title: 'Cybernetic HUD Telemetry', tag: 'INTERFACE', color: '#38bdf8', bg: '#082f49', severity: 'info', desc: 'Spatial coordinate tracking and threat lock-on reticle.' },
  { id: 'node-threejs', title: 'WebGL 3D Matrix', tag: 'VISUALIZER', color: '#38bdf8', bg: '#082f49', severity: 'info', desc: 'Fibonacci spherical distribution of security indicators.' },
  { id: 'node-ground-truth', title: 'Vulnerable App Testbed', tag: 'TEST SUITE', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'vulnerable_app.py target for automated verification.' },
  { id: 'node-verifix-root', title: 'VerifiX Unified Security', tag: 'CORE PLATFORM', color: '#22c55e', bg: '#06110C', severity: 'safe', desc: 'AI-assisted deterministic static analysis platform.' }
];

export default function Verifix3DMatrix({
  findings = [],
  findingCount = 0,
  targetName = 'file_viewer.py',
  isWireframe = false,
  isHolo = true,
  autoRotate = true,
  cursorTracking = true,
  parallaxIntensity = 1.0,
  onSelectNode,
  onZoomStatusChange,
  onCursorMove,
}) {
  const mountRef = useRef(null);
  const cardMeshesRef = useRef([]);

  // Stable Refs for Props used in render loop (prevents re-mounting Three.js on prop toggles)
  const autoRotateRef = useRef(autoRotate);
  autoRotateRef.current = autoRotate;

  const cursorTrackingRef = useRef(cursorTracking);
  cursorTrackingRef.current = cursorTracking;

  const parallaxIntensityRef = useRef(parallaxIntensity);
  parallaxIntensityRef.current = parallaxIntensity;

  const isHoloRef = useRef(isHolo);
  isHoloRef.current = isHolo;

  const isWireframeRef = useRef(isWireframe);
  isWireframeRef.current = isWireframe;

  const onCursorMoveRef = useRef(onCursorMove);
  onCursorMoveRef.current = onCursorMove;

  const onSelectNodeRef = useRef(onSelectNode);
  onSelectNodeRef.current = onSelectNode;

  const onZoomStatusChangeRef = useRef(onZoomStatusChange);
  onZoomStatusChangeRef.current = onZoomStatusChange;

  // Animation & Camera State
  const DEFAULT_CAM_DIST = 13.5;
  const ZOOM_CAM_DIST = 8.2;
  const targetCamDistRef = useRef(DEFAULT_CAM_DIST);
  const currentCamDistRef = useRef(DEFAULT_CAM_DIST);
  const targetQuatRef = useRef(new THREE.Quaternion());
  const isZoomingRef = useRef(false);
  const selectedCardMeshRef = useRef(null);

  // Drag & Inertia
  const isDraggingRef = useRef(false);
  const prevMouseRef = useRef({ x: 0, y: 0 });
  const rotVelRef = useRef({ x: 0.001, y: 0.0024 });
  const hoveredMeshRef = useRef(null);
  const damping = 0.94;

  // Normalized Cursor for Parallax
  const cursorNormRef = useRef({ x: 0, y: 0 });
  const targetCursorNormRef = useRef({ x: 0, y: 0 });

  // Map findings into 32 nodes
  const activeNodesData = useRef([]);

  const buildNodesData = useCallback(() => {
    const list = [...DEFAULT_SECURITY_NODES];

    if (findings && findings.length > 0) {
      findings.forEach((finding, idx) => {
        if (idx < list.length) {
          const sev = (finding.severity || 'medium').toLowerCase();
          let color = '#f59e0b';
          if (sev === 'critical' || sev === 'high') color = '#A31C1B';
          if (sev === 'low') color = '#38bdf8';

          list[idx] = {
            id: `finding-${idx}-${finding.rule}`,
            title: `${finding.type || finding.rule} (Line ${finding.line})`,
            tag: `${finding.rule} // ${sev.toUpperCase()}`,
            color: color,
            bg: '#171717',
            severity: sev,
            isVulnerability: true,
            findingIndex: idx,
            rule: finding.rule,
            line: finding.line,
            evidence: finding.evidence,
            hypothesis: finding.hypothesis,
            confidence: finding.confidence,
            reasoning: finding.reasoning,
            recommended_probes: finding.recommended_probes || [],
            desc: finding.hypothesis || `Static AST rule match: ${finding.rule} at line ${finding.line}.`,
          };
        }
      });
    }

    activeNodesData.current = list;
    return list;
  }, [findings]);

  // Render 2D Canvas Texture for Each Card
  const renderCardCanvas = useCallback((item, index, isVulnerability, holoMode) => {
    const canvas = document.createElement('canvas');
    canvas.width = 512;
    canvas.height = 360;
    const ctx = canvas.getContext('2d');

    const brandCrimson = '#A31C1B';
    const brandCharcoal = '#171717';
    const brandForest = '#06110C';
    const brandGreen = '#22c55e';
    const brandCyan = '#38bdf8';

    const primaryColor = isVulnerability ? brandCrimson : item.color || brandGreen;

    if (holoMode) {
      // Holographic Mode
      const grad = ctx.createLinearGradient(0, 0, 512, 360);
      if (isVulnerability) {
        grad.addColorStop(0, '#260404');
        grad.addColorStop(0.5, '#380a0a');
        grad.addColorStop(1, '#171717');
      } else {
        grad.addColorStop(0, '#041226');
        grad.addColorStop(0.5, '#061d38');
        grad.addColorStop(1, '#020b18');
      }
      ctx.fillStyle = grad;
      if (ctx.roundRect) ctx.roundRect(0, 0, 512, 360, 20); else ctx.rect(0, 0, 512, 360);
      ctx.fill();

      const imgX = 14, imgY = 14, imgW = 484, imgH = 210, imgR = 14;
      ctx.save();
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(imgX, imgY, imgW, imgH, imgR); else ctx.rect(imgX, imgY, imgW, imgH);
      ctx.clip();

      const innerGrad = ctx.createLinearGradient(imgX, imgY, imgX + imgW, imgY + imgH);
      if (isVulnerability) {
        innerGrad.addColorStop(0, '#590a0a');
        innerGrad.addColorStop(1, '#171717');
      } else {
        innerGrad.addColorStop(0, '#0e3a53');
        innerGrad.addColorStop(1, '#031020');
      }
      ctx.fillStyle = innerGrad;
      ctx.fillRect(imgX, imgY, imgW, imgH);

      // Scanline grid
      ctx.strokeStyle = isVulnerability ? 'rgba(239, 68, 68, 0.28)' : 'rgba(56, 189, 248, 0.22)';
      ctx.lineWidth = 1;
      for (let y = imgY; y < imgY + imgH; y += 6) {
        ctx.beginPath();
        ctx.moveTo(imgX, y);
        ctx.lineTo(imgX + imgW, y);
        ctx.stroke();
      }

      // Procedural Circuit Geometry
      ctx.strokeStyle = isVulnerability ? 'rgba(239, 68, 68, 0.45)' : 'rgba(56, 189, 248, 0.4)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.arc(imgX + imgW / 2, imgY + imgH / 2, 45, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(imgX + 40, imgY + imgH / 2);
      ctx.lineTo(imgX + imgW - 40, imgY + imgH / 2);
      ctx.stroke();

      const vignette = ctx.createLinearGradient(imgX, imgY, imgX, imgY + imgH);
      vignette.addColorStop(0, 'rgba(0,0,0,0.1)');
      vignette.addColorStop(1, isVulnerability ? 'rgba(23,23,23,0.92)' : 'rgba(4,18,38,0.92)');
      ctx.fillStyle = vignette;
      ctx.fillRect(imgX, imgY, imgW, imgH);
      ctx.restore();

      // Outer Border
      ctx.strokeStyle = primaryColor;
      ctx.lineWidth = 3;
      if (ctx.roundRect) ctx.roundRect(0, 0, 512, 360, 20); else ctx.rect(0, 0, 512, 360);
      ctx.stroke();

      // Header Tag Badge
      ctx.fillStyle = isVulnerability ? 'rgba(163, 28, 27, 0.35)' : 'rgba(6, 182, 212, 0.2)';
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(26, 26, 140, 28, 8); else ctx.rect(26, 26, 140, 28);
      ctx.fill();
      ctx.strokeStyle = primaryColor;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.font = 'bold 12px monospace';
      ctx.fillStyle = isVulnerability ? '#fca5a5' : '#67e8f9';
      ctx.fillText(`VERIFIX // ${index < 9 ? '0' : ''}${index + 1}`, 36, 45);

      // Status Pill
      ctx.fillStyle = primaryColor;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(310, 26, 176, 28, 8); else ctx.rect(310, 26, 176, 28);
      ctx.fill();
      ctx.font = '700 11px monospace';
      ctx.fillStyle = '#ffffff';
      ctx.fillText(item.tag.toUpperCase().slice(0, 22), 320, 45);

      // Title & Subtitle
      ctx.font = '700 24px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#ffffff';
      const truncatedTitle = item.title.length > 26 ? item.title.slice(0, 24) + '...' : item.title;
      ctx.fillText(truncatedTitle, 24, 265);

      ctx.font = '13px monospace';
      ctx.fillStyle = isVulnerability ? '#f87171' : brandCyan;
      const subtitle = isVulnerability
        ? `ALERT: LINE ${item.line} AST VIOLATION`
        : 'TELEMETRY AST VERIFICATION NODE';
      ctx.fillText(subtitle, 24, 294);

      // Action Cue Dot
      ctx.fillStyle = primaryColor;
      ctx.beginPath();
      ctx.arc(28, 326, 4, 0, Math.PI * 2);
      ctx.fill();

      ctx.font = '600 12px monospace';
      ctx.fillStyle = isVulnerability ? '#fca5a5' : '#7dd3fc';
      ctx.fillText('CLICK TO CENTER & ZOOM', 38, 330);
    } else {
      // Standard Charcoal / Forest Mode
      const grad = ctx.createLinearGradient(0, 0, 512, 360);
      grad.addColorStop(0, brandCharcoal);
      grad.addColorStop(1, brandForest);
      ctx.fillStyle = grad;
      if (ctx.roundRect) ctx.roundRect(0, 0, 512, 360, 20); else ctx.rect(0, 0, 512, 360);
      ctx.fill();

      const imgX = 14, imgY = 14, imgW = 484, imgH = 210, imgR = 14;
      ctx.save();
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(imgX, imgY, imgW, imgH, imgR); else ctx.rect(imgX, imgY, imgW, imgH);
      ctx.clip();

      const fallbackGrad = ctx.createLinearGradient(imgX, imgY, imgX + imgW, imgY + imgH);
      fallbackGrad.addColorStop(0, isVulnerability ? '#2c0808' : '#0a1d13');
      fallbackGrad.addColorStop(1, '#0e0e11');
      ctx.fillStyle = fallbackGrad;
      ctx.fillRect(imgX, imgY, imgW, imgH);

      const vignette = ctx.createLinearGradient(imgX, imgY, imgX + imgW, imgY + imgH);
      vignette.addColorStop(0, 'rgba(0,0,0,0.1)');
      vignette.addColorStop(1, 'rgba(23,23,23,0.95)');
      ctx.fillStyle = vignette;
      ctx.fillRect(imgX, imgY, imgW, imgH);
      ctx.restore();

      ctx.strokeStyle = primaryColor + '99';
      ctx.lineWidth = 3;
      if (ctx.roundRect) ctx.roundRect(0, 0, 512, 360, 20); else ctx.rect(0, 0, 512, 360);
      ctx.stroke();

      ctx.fillStyle = 'rgba(0, 0, 0, 0.65)';
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(26, 26, 120, 28, 8); else ctx.rect(26, 26, 120, 28);
      ctx.fill();
      ctx.strokeStyle = primaryColor;
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.font = 'bold 12px monospace';
      ctx.fillStyle = '#ffffff';
      ctx.fillText(`PLATE // ${index < 9 ? '0' : ''}${index + 1}`, 36, 45);

      ctx.fillStyle = primaryColor;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(310, 26, 176, 28, 8); else ctx.rect(310, 26, 176, 28);
      ctx.fill();
      ctx.font = '700 11px system-ui, sans-serif';
      ctx.fillStyle = '#ffffff';
      ctx.fillText(item.tag.toUpperCase().slice(0, 22), 320, 45);

      ctx.font = '700 24px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = '#ffffff';
      const truncatedTitle = item.title.length > 26 ? item.title.slice(0, 24) + '...' : item.title;
      ctx.fillText(truncatedTitle, 24, 265);

      ctx.font = '13px system-ui, -apple-system, sans-serif';
      ctx.fillStyle = 'rgba(255, 255, 255, 0.65)';
      ctx.fillText((item.desc || '').slice(0, 48) + '...', 24, 294);

      ctx.fillStyle = primaryColor;
      ctx.beginPath();
      ctx.arc(28, 326, 4, 0, Math.PI * 2);
      ctx.fill();

      ctx.font = '600 12px monospace';
      ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
      ctx.fillText('CLICK TO CENTER & ZOOM', 38, 330);
    }

    return canvas;
  }, []);

  // Refresh existing card textures & wireframe when findings or modes change
  const refreshAllCards = useCallback(() => {
    if (!cardMeshesRef.current || cardMeshesRef.current.length === 0) return;
    const nodes = activeNodesData.current;
    const holo = isHoloRef.current;
    const wire = isWireframeRef.current;

    cardMeshesRef.current.forEach((mesh, i) => {
      const item = nodes[i] || DEFAULT_SECURITY_NODES[i % DEFAULT_SECURITY_NODES.length];
      const canvas = renderCardCanvas(item, i, Boolean(item.isVulnerability), holo);
      mesh.userData.texture.image = canvas;
      mesh.userData.texture.needsUpdate = true;
      mesh.userData.data = item;
      mesh.material.wireframe = wire;
      if (wire) {
        mesh.material.color.setHex(item.isVulnerability ? 0xef4444 : 0x38bdf8);
      } else {
        mesh.material.color.setHex(0xffffff);
      }
    });
  }, [renderCardCanvas]);

  // Synchronize findings & modes into existing 3D mesh instances
  useEffect(() => {
    buildNodesData();
    refreshAllCards();
  }, [findings, isHolo, isWireframe, buildNodesData, refreshAllCards]);

  // Zoom / Focus Camera on Node
  const focusOnCard = useCallback((mesh) => {
    if (!mesh) return;

    if (selectedCardMeshRef.current === mesh && isZoomingRef.current) {
      isZoomingRef.current = false;
      targetCamDistRef.current = DEFAULT_CAM_DIST;
      selectedCardMeshRef.current = null;
      if (onZoomStatusChangeRef.current) onZoomStatusChangeRef.current(false, null);
      return;
    }

    selectedCardMeshRef.current = mesh;
    isZoomingRef.current = true;
    targetCamDistRef.current = ZOOM_CAM_DIST;

    const localNormal = mesh.userData.normal.clone().normalize();
    const forwardVec = new THREE.Vector3(0, 0, 1);
    targetQuatRef.current.setFromUnitVectors(localNormal, forwardVec);

    if (onSelectNodeRef.current) onSelectNodeRef.current(mesh.userData.data);
    if (onZoomStatusChangeRef.current) onZoomStatusChangeRef.current(true, mesh.userData.data.title);
  }, []);

  // Reset Camera View
  const resetCamera = useCallback(() => {
    isZoomingRef.current = false;
    targetCamDistRef.current = DEFAULT_CAM_DIST;
    selectedCardMeshRef.current = null;
    if (onZoomStatusChangeRef.current) onZoomStatusChangeRef.current(false, null);
  }, []);

  // Listen to reset view event
  useEffect(() => {
    const handleReset = () => resetCamera();
    window.addEventListener('orbgallery-reset-camera', handleReset);
    return () => window.removeEventListener('orbgallery-reset-camera', handleReset);
  }, [resetCamera]);

  // Primary Three.js Initialization (Mounts once, never unmounted on prop changes)
  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || window.innerWidth;
    const height = container.clientHeight || window.innerHeight;

    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
    } catch {
      console.warn('WebGL is not supported or context could not be created.');
      return;
    }

    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 0, DEFAULT_CAM_DIST);

    // Ambient & Point Lighting
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.25);
    scene.add(ambientLight);

    const pointLight1 = new THREE.PointLight(0x6366f1, 2.8, 40);
    pointLight1.position.set(12, 14, 12);
    scene.add(pointLight1);

    const pointLight2 = new THREE.PointLight(0x06b6d4, 2.4, 40);
    pointLight2.position.set(-12, -12, 10);
    scene.add(pointLight2);

    const cursorLight = new THREE.PointLight(0x38bdf8, 2.2, 25);
    cursorLight.position.set(0, 0, 8);
    scene.add(cursorLight);

    // Gallery Root Group & Parallax Tilt Rig
    const gallerySphere = new THREE.Group();
    const rigGroup = new THREE.Group();
    scene.add(rigGroup);
    rigGroup.add(gallerySphere);

    // Inner wireframe core (radius 4.3)
    const innerGeo = new THREE.IcosahedronGeometry(4.3, 2);
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x164e63,
      wireframe: true,
      transparent: true,
      opacity: 0.16,
    });
    const innerOrb = new THREE.Mesh(innerGeo, innerMat);
    gallerySphere.add(innerOrb);

    // Fibonacci Sphere Distribution (5.2 Radius / 32 Cards)
    const numCards = 32;
    const radius = 5.2;
    const cardGeo = new THREE.PlaneGeometry(1.45, 1.02, 6, 4);
    const phi = (1 + Math.sqrt(5)) / 2;
    const meshes = [];

    const nodes = buildNodesData();

    for (let i = 0; i < numCards; i++) {
      const y = 1 - (i / (numCards - 1)) * 2;
      const radiusAtY = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = (2 * Math.PI * i) / phi;

      const x = Math.cos(theta) * radiusAtY;
      const z = Math.sin(theta) * radiusAtY;

      const normal = new THREE.Vector3(x, y, z).normalize();
      const position = normal.clone().multiplyScalar(radius);

      const item = nodes[i] || DEFAULT_SECURITY_NODES[i % DEFAULT_SECURITY_NODES.length];
      const initialCanvas = renderCardCanvas(item, i, Boolean(item.isVulnerability), isHoloRef.current);
      const texture = new THREE.CanvasTexture(initialCanvas);
      texture.minFilter = THREE.LinearFilter;

      const material = new THREE.MeshStandardMaterial({
        map: texture,
        side: THREE.DoubleSide,
        roughness: 0.25,
        metalness: 0.35,
        transparent: true,
        opacity: 0.98,
        wireframe: isWireframeRef.current,
      });

      const mesh = new THREE.Mesh(cardGeo, material);
      mesh.position.copy(position);
      mesh.lookAt(position.clone().add(normal));

      mesh.userData = {
        id: i,
        data: item,
        texture: texture,
        basePos: position.clone(),
        normal: normal.clone(),
        hoverOffset: 0,
      };

      gallerySphere.add(mesh);
      meshes.push(mesh);
    }

    cardMeshesRef.current = meshes;

    // Raycaster & Mouse Tracking
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2(-100, -100);

    const getEventCoords = (e) => {
      if (e.touches && e.touches.length > 0) return { x: e.touches[0].clientX, y: e.touches[0].clientY };
      return { x: e.clientX, y: e.clientY };
    };

    const onPointerDown = (e) => {
      isDraggingRef.current = true;
      const coords = getEventCoords(e);
      prevMouseRef.current = { x: coords.x, y: coords.y };
    };

    const onPointerMove = (e) => {
      const coords = getEventCoords(e);
      const rect = renderer.domElement.getBoundingClientRect();
      const nx = ((coords.x - rect.left) / rect.width) * 2 - 1;
      const ny = -((coords.y - rect.top) / rect.height) * 2 + 1;

      mouse.x = nx;
      mouse.y = ny;

      targetCursorNormRef.current.x = nx;
      targetCursorNormRef.current.y = ny;

      const signX = nx >= 0 ? '+' : '';
      const signY = ny >= 0 ? '+' : '';

      if (onCursorMoveRef.current) {
        onCursorMoveRef.current({
          x: coords.x,
          y: coords.y,
          nx: `${signX}${nx.toFixed(2)}`,
          ny: `${signY}${ny.toFixed(2)}`,
          activeCard: hoveredMeshRef.current ? hoveredMeshRef.current.userData.data.title : null,
          isVulnerability: hoveredMeshRef.current ? Boolean(hoveredMeshRef.current.userData.data.isVulnerability) : false,
        });
      }

      if (isDraggingRef.current) {
        isZoomingRef.current = false;
        const deltaX = coords.x - prevMouseRef.current.x;
        const deltaY = coords.y - prevMouseRef.current.y;
        rotVelRef.current.y = deltaX * 0.0045;
        rotVelRef.current.x = deltaY * 0.0045;
        prevMouseRef.current = { x: coords.x, y: coords.y };
      }
    };

    const onPointerUp = () => {
      isDraggingRef.current = false;
    };

    const onClick = () => {
      if (hoveredMeshRef.current) {
        focusOnCard(hoveredMeshRef.current);
      }
    };

    const dom = renderer.domElement;
    dom.addEventListener('mousedown', onPointerDown);
    window.addEventListener('mousemove', onPointerMove, { passive: true });
    window.addEventListener('mouseup', onPointerUp);

    dom.addEventListener('touchstart', onPointerDown, { passive: true });
    window.addEventListener('touchmove', onPointerMove, { passive: true });
    window.addEventListener('touchend', onPointerUp);
    dom.addEventListener('click', onClick);

    const onResize = () => {
      if (!container) return;
      const newWidth = container.clientWidth || window.innerWidth;
      const newHeight = container.clientHeight || window.innerHeight;
      camera.aspect = newWidth / newHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(newWidth, newHeight);
    };

    window.addEventListener('resize', onResize);

    // Continuous Animation Loop
    let animId;
    const animate = () => {
      animId = requestAnimationFrame(animate);

      // Smooth cursor lerp
      cursorNormRef.current.x += (targetCursorNormRef.current.x - cursorNormRef.current.x) * 0.08;
      cursorNormRef.current.y += (targetCursorNormRef.current.y - cursorNormRef.current.y) * 0.08;

      const pIntensity = parallaxIntensityRef.current;
      if (cursorTrackingRef.current && !isDraggingRef.current) {
        rigGroup.rotation.y = cursorNormRef.current.x * (0.28 * pIntensity);
        rigGroup.rotation.x = -cursorNormRef.current.y * (0.22 * pIntensity);

        cursorLight.position.x = cursorNormRef.current.x * 6.5;
        cursorLight.position.y = cursorNormRef.current.y * 5.0;
        cursorLight.position.z = 7.5;
      } else {
        rigGroup.rotation.x *= 0.92;
        rigGroup.rotation.y *= 0.92;
      }

      if (isZoomingRef.current) {
        gallerySphere.quaternion.slerp(targetQuatRef.current, 0.085);
        rotVelRef.current.x = 0;
        rotVelRef.current.y = 0;
      } else {
        if (!isDraggingRef.current && autoRotateRef.current) {
          gallerySphere.rotation.y += rotVelRef.current.y;
          gallerySphere.rotation.x += rotVelRef.current.x;
          rotVelRef.current.x *= damping;
          rotVelRef.current.y = rotVelRef.current.y * damping + 0.0016 * (1 - damping);
        } else if (isDraggingRef.current) {
          gallerySphere.rotation.y += rotVelRef.current.y;
          gallerySphere.rotation.x += rotVelRef.current.x;
        } else {
          gallerySphere.rotation.y += rotVelRef.current.y;
          gallerySphere.rotation.x += rotVelRef.current.x;
          rotVelRef.current.x *= damping;
          rotVelRef.current.y *= damping;
        }
      }

      // Camera Distance Lerp
      currentCamDistRef.current += (targetCamDistRef.current - currentCamDistRef.current) * 0.09;
      camera.position.z = currentCamDistRef.current;

      // Raycaster
      raycaster.setFromCamera(mouse, camera);
      const intersects = raycaster.intersectObjects(meshes);

      if (intersects.length > 0) {
        hoveredMeshRef.current = intersects[0].object;
        dom.style.cursor = 'pointer';
      } else {
        hoveredMeshRef.current = null;
        dom.style.cursor = isDraggingRef.current ? 'grabbing' : 'crosshair';
      }

      // Card Pop-Forward Animation
      for (let i = 0; i < meshes.length; i++) {
        const mesh = meshes[i];
        const isHovered = mesh === hoveredMeshRef.current;
        const isSelected = mesh === selectedCardMeshRef.current && isZoomingRef.current;
        const targetOffset = isSelected ? 0.95 : isHovered ? 0.75 : 0;
        mesh.userData.hoverOffset += (targetOffset - mesh.userData.hoverOffset) * 0.14;

        mesh.position.copy(mesh.userData.basePos).addScaledVector(mesh.userData.normal, mesh.userData.hoverOffset);
        mesh.scale.setScalar(1 + mesh.userData.hoverOffset * 0.24);
      }

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', onResize);
      window.removeEventListener('mousemove', onPointerMove);
      window.removeEventListener('mouseup', onPointerUp);
      window.removeEventListener('touchmove', onPointerMove);
      window.removeEventListener('touchend', onPointerUp);

      dom.removeEventListener('mousedown', onPointerDown);
      dom.removeEventListener('touchstart', onPointerDown);
      dom.removeEventListener('click', onClick);

      meshes.forEach((mesh) => {
        mesh.geometry.dispose();
        mesh.material.dispose();
        if (mesh.userData.texture) mesh.userData.texture.dispose();
      });
      innerGeo.dispose();
      innerMat.dispose();
      renderer.dispose();
      if (dom.parentNode) dom.parentNode.removeChild(dom);
    };
  }, [buildNodesData, renderCardCanvas, focusOnCard]);

  return (
    <div
      ref={mountRef}
      className="verifix-3d-canvas-container"
      aria-label="VerifiX 3D Threat Telemetry Matrix"
    />
  );
}
