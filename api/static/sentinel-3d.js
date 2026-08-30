/**
 * ABHIMANYU X — 3D Immune Laboratory
 *
 * Vanilla Three.js (no build step, no React) driven entirely by real
 * WebSocket events from the SentinelOrchestrator — see the SentinelScene
 * API at the bottom. Nothing here is decorative-only: node color/state,
 * particle flow, camera position, and the DNA helix all reflect actual
 * pipeline state (see dashboard.py's socket handlers, which call into
 * this module's functions alongside the existing 2D panel updates).
 */
import * as THREE from '/static/three.module.min.js';

const STATE_COLOR = {
    inactive: 0x3a4a48,
    active: 0x2de2c9,
    completed: 0x3ddc84,
    error: 0xff5470,
    ai: 0x8a6bff,
};

function makeGlowTexture() {
    const size = 128;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = size;
    const ctx = canvas.getContext('2d');
    const grad = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    grad.addColorStop(0, 'rgba(255,255,255,1)');
    grad.addColorStop(0.35, 'rgba(255,255,255,0.5)');
    grad.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, size, size);
    const tex = new THREE.CanvasTexture(canvas);
    return tex;
}

function easeInOutCubic(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

class Tween {
    constructor() { this.active = null; }
    to(from, to, duration, onUpdate, onComplete) {
        this.active = { from, to, duration, elapsed: 0, onUpdate, onComplete };
    }
    update(dt) {
        if (!this.active) return;
        const t = this.active;
        t.elapsed += dt;
        const p = Math.min(1, t.elapsed / t.duration);
        const e = easeInOutCubic(p);
        const cur = {};
        for (const k in t.from) cur[k] = t.from[k] + (t.to[k] - t.from[k]) * e;
        t.onUpdate(cur);
        if (p >= 1) {
            if (t.onComplete) t.onComplete();
            this.active = null;
        }
    }
}

export function initSentinelScene(container, { performanceMode = false } = {}) {
    const glowTex = makeGlowTexture();
    let particleBudget = performanceMode ? 120 : 400;
    let dpr = performanceMode ? 1 : Math.min(window.devicePixelRatio || 1, 2);

    const scene = new THREE.Scene();
    scene.background = null;

    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    const camState = { pos: new THREE.Vector3(0, 2.2, 11), look: new THREE.Vector3(0, 0, 0) };
    camera.position.copy(camState.pos);
    camera.lookAt(camState.look);
    const camTween = new Tween();
    const lookTween = new Tween();

    const renderer = new THREE.WebGLRenderer({ antialias: !performanceMode, alpha: true });
    renderer.setPixelRatio(dpr);
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);

    // ---- lighting: minimal, this is a holographic/emissive look, not PBR ----
    scene.add(new THREE.AmbientLight(0x2a3a38, 1.2));

    // ---- central immune core ----
    const coreGroup = new THREE.Group();
    scene.add(coreGroup);

    const coreGeo = new THREE.IcosahedronGeometry(1.15, 2);
    const coreMat = new THREE.MeshBasicMaterial({ color: 0x2de2c9, wireframe: true, transparent: true, opacity: 0.85 });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    coreGroup.add(coreMesh);

    const coreInner = new THREE.Mesh(
        new THREE.IcosahedronGeometry(0.55, 1),
        new THREE.MeshBasicMaterial({ color: 0xeafcf6, transparent: true, opacity: 0.9 })
    );
    coreGroup.add(coreInner);

    const coreGlow = new THREE.Sprite(new THREE.SpriteMaterial({
        map: glowTex, color: 0x2de2c9, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false,
    }));
    coreGlow.scale.set(4.2, 4.2, 1);
    coreGroup.add(coreGlow);

    // orbital rings
    const rings = [];
    [1.8, 2.3, 2.8].forEach((r, i) => {
        const ring = new THREE.Mesh(
            new THREE.TorusGeometry(r, 0.012, 8, 96),
            new THREE.MeshBasicMaterial({ color: 0x2de2c9, transparent: true, opacity: 0.28 })
        );
        ring.rotation.x = Math.PI / 2 + i * 0.35;
        ring.rotation.y = i * 0.6;
        coreGroup.add(ring);
        rings.push({ mesh: ring, speed: 0.05 + i * 0.03 });
    });

    // ---- 5 stage nodes, pentagon layout ----
    const STAGE_KEYS = ['discover', 'understand', 'repair', 'verify', 'remember'];
    const STAGE_LABELS = { discover: 'DISCOVER', understand: 'UNDERSTAND', repair: 'REPAIR', verify: 'VERIFY', remember: 'REMEMBER' };
    const nodeRadius = 4.6;
    const nodes = {};
    STAGE_KEYS.forEach((key, i) => {
        const angle = -Math.PI / 2 + (i / STAGE_KEYS.length) * Math.PI * 2;
        const pos = new THREE.Vector3(Math.cos(angle) * nodeRadius, Math.sin(angle * 0.4) * 0.6, Math.sin(angle) * nodeRadius);

        const mesh = new THREE.Mesh(
            new THREE.OctahedronGeometry(0.42, 0),
            new THREE.MeshBasicMaterial({ color: STATE_COLOR.inactive, transparent: true, opacity: 0.85 })
        );
        mesh.position.copy(pos);
        scene.add(mesh);

        const glow = new THREE.Sprite(new THREE.SpriteMaterial({
            map: glowTex, color: STATE_COLOR.inactive, transparent: true, opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false,
        }));
        glow.scale.set(1.6, 1.6, 1);
        glow.position.copy(pos);
        scene.add(glow);

        const lineGeo = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, 0, 0), pos]);
        const line = new THREE.Line(lineGeo, new THREE.LineBasicMaterial({ color: STATE_COLOR.inactive, transparent: true, opacity: 0.35 }));
        scene.add(line);

        nodes[key] = { mesh, glow, line, pos, state: 'inactive', pulse: 0 };
    });

    // ---- ANVIL AI sphere (off to the side) ----
    const anvilPos = new THREE.Vector3(nodeRadius * 0.55, 1.6, -nodeRadius * 1.15);
    const anvilGroup = new THREE.Group();
    anvilGroup.position.copy(anvilPos);
    scene.add(anvilGroup);
    const anvilMesh = new THREE.Mesh(
        new THREE.IcosahedronGeometry(0.7, 1),
        new THREE.MeshBasicMaterial({ color: STATE_COLOR.ai, wireframe: true, transparent: true, opacity: 0.3 })
    );
    anvilGroup.add(anvilMesh);
    const anvilNodesGeo = new THREE.BufferGeometry();
    const anvilPts = [];
    for (let i = 0; i < 24; i++) {
        const p = new THREE.Vector3().randomDirection().multiplyScalar(0.55 + Math.random() * 0.15);
        anvilPts.push(p.x, p.y, p.z);
    }
    anvilNodesGeo.setAttribute('position', new THREE.Float32BufferAttribute(anvilPts, 3));
    const anvilPoints = new THREE.Points(anvilNodesGeo, new THREE.PointsMaterial({ color: STATE_COLOR.ai, size: 0.06, transparent: true, opacity: 0.35 }));
    anvilGroup.add(anvilPoints);
    const anvilGlow = new THREE.Sprite(new THREE.SpriteMaterial({
        map: glowTex, color: STATE_COLOR.ai, transparent: true, opacity: 0.35, blending: THREE.AdditiveBlending, depthWrite: false,
    }));
    anvilGlow.scale.set(2.4, 2.4, 1);
    anvilGroup.add(anvilGlow);

    // ---- verification chamber: 5 rings in a row ----
    const chamberPos = new THREE.Vector3(0, -2.6, 2.2);
    const chamberGroup = new THREE.Group();
    chamberGroup.position.copy(chamberPos);
    scene.add(chamberGroup);
    const VERIFY_KEYS = ['build', 'exploit', 'regression', 'sanitizer', 'behaviour'];
    const verifyRings = {};
    VERIFY_KEYS.forEach((key, i) => {
        const ring = new THREE.Mesh(
            new THREE.TorusGeometry(0.32, 0.045, 10, 32),
            new THREE.MeshBasicMaterial({ color: STATE_COLOR.inactive, transparent: true, opacity: 0.55 })
        );
        ring.position.x = (i - 2) * 0.85;
        chamberGroup.add(ring);
        verifyRings[key] = { mesh: ring, state: 'inactive' };
    });
    chamberGroup.visible = false;

    // ---- DNA double helix (Immune Memory) ----
    const dnaGroup = new THREE.Group();
    dnaGroup.position.set(-nodeRadius * 0.9, -0.6, -1.2);
    dnaGroup.visible = false;
    dnaGroup.scale.setScalar(0.001);
    scene.add(dnaGroup);
    {
        const turns = 3.2, pointsPerTurn = 14, height = 3.2, radius = 0.5;
        const total = Math.floor(turns * pointsPerTurn);
        const strandA = [], strandB = [];
        const rungGeo = [];
        for (let i = 0; i <= total; i++) {
            const t = i / pointsPerTurn * Math.PI * 2;
            const y = (i / total) * height - height / 2;
            const ax = Math.cos(t) * radius, az = Math.sin(t) * radius;
            const bx = Math.cos(t + Math.PI) * radius, bz = Math.sin(t + Math.PI) * radius;
            strandA.push(ax, y, az);
            strandB.push(bx, y, bz);
            if (i % 3 === 0) rungGeo.push(ax, y, az, bx, y, bz);
        }
        const mkStrand = (pts, color) => {
            const geo = new THREE.BufferGeometry();
            geo.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
            return new THREE.Points(geo, new THREE.PointsMaterial({ color, size: 0.09, transparent: true, opacity: 0.9 }));
        };
        dnaGroup.add(mkStrand(strandA, 0x3ddc84));
        dnaGroup.add(mkStrand(strandB, 0x2de2c9));
        const rungGeo2 = new THREE.BufferGeometry();
        rungGeo2.setAttribute('position', new THREE.Float32BufferAttribute(rungGeo, 3));
        dnaGroup.add(new THREE.LineSegments(rungGeo2, new THREE.LineBasicMaterial({ color: 0xe8b23d, transparent: true, opacity: 0.4 })));
    }

    // ---- particle flow system: a small pool, reused per active connection ----
    const MAX_PARTICLES = particleBudget;
    const particleGeo = new THREE.BufferGeometry();
    const particlePos = new Float32Array(MAX_PARTICLES * 3);
    particleGeo.setAttribute('position', new THREE.Float32BufferAttribute(particlePos, 3));
    const particleMat = new THREE.PointsMaterial({ color: 0x2de2c9, size: 0.06, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false });
    const particlePoints = new THREE.Points(particleGeo, particleMat);
    scene.add(particlePoints);
    let particles = []; // {from, to, t, speed, color}

    function spawnFlow(fromVec, toVec, color, count, speed) {
        for (let i = 0; i < count && particles.length < MAX_PARTICLES; i++) {
            particles.push({ from: fromVec, to: toVec, t: Math.random() * -0.6, speed: speed * (0.85 + Math.random() * 0.3), color });
        }
    }
    function clearFlows() { particles = []; }

    // ---- caption overlay (simple DOM, not 3D geometry — cheap & always crisp) ----
    const caption = document.createElement('div');
    caption.className = 'scene-caption';
    container.appendChild(caption);
    let captionTimer = null;
    function showCaption(lines, holdMs = 2600) {
        caption.innerHTML = lines.map((l, i) => `<div class="cap-line ${i === 0 ? 'cap-primary' : 'cap-secondary'}">${l}</div>`).join('');
        caption.classList.add('show');
        if (captionTimer) clearTimeout(captionTimer);
        captionTimer = setTimeout(() => caption.classList.remove('show'), holdMs);
    }

    // ---- camera shots ----
    function moveCamera(pos, look, duration = 1400) {
        camTween.to(
            { x: camera.position.x, y: camera.position.y, z: camera.position.z },
            { x: pos.x, y: pos.y, z: pos.z }, duration,
            (c) => camera.position.set(c.x, c.y, c.z)
        );
        lookTween.to(
            { x: camState.look.x, y: camState.look.y, z: camState.look.z },
            { x: look.x, y: look.y, z: look.z }, duration,
            (c) => { camState.look.set(c.x, c.y, c.z); }
        );
    }

    const SHOTS = {
        idle: [new THREE.Vector3(0, 2.2, 11), new THREE.Vector3(0, 0, 0)],
        repository: [new THREE.Vector3(2.5, 1.4, 6.5), new THREE.Vector3(nodes.discover.pos.x * 0.5, 0, nodes.discover.pos.z * 0.5)],
        discover: [new THREE.Vector3(nodes.discover.pos.x * 1.4, 1.6, nodes.discover.pos.z * 1.4 + 2), nodes.discover.pos],
        understand: [new THREE.Vector3(nodes.understand.pos.x * 1.5, 1.8, nodes.understand.pos.z * 1.5), nodes.understand.pos],
        anvil: [new THREE.Vector3(anvilPos.x - 1.5, anvilPos.y + 0.8, anvilPos.z + 3), anvilPos],
        repair: [new THREE.Vector3(nodes.repair.pos.x * 1.4, 1.4, nodes.repair.pos.z * 1.4), nodes.repair.pos],
        verify: [new THREE.Vector3(chamberPos.x, chamberPos.y + 1.8, chamberPos.z + 4.5), chamberPos],
        remember: [new THREE.Vector3(-nodeRadius * 0.5, 1.5, 4), new THREE.Vector3(0, 0, 0)],
        final: [new THREE.Vector3(0, 4.5, 13), new THREE.Vector3(0, 0, 0)],
    };
    function goTo(shotKey, duration) { const [p, l] = SHOTS[shotKey]; moveCamera(p, l, duration); }

    // ---- state transitions driven by real events ----
    function setNodeState(key, state) {
        const n = nodes[key];
        if (!n) return;
        n.state = state;
        n.pulse = state === 'active' || state === 'ai' ? 1 : 0;
        const color = STATE_COLOR[state] ?? STATE_COLOR.inactive;
        n.mesh.material.color.setHex(color);
        n.glow.material.color.setHex(color);
        n.line.material.color.setHex(color);
        n.line.material.opacity = state === 'inactive' ? 0.35 : 0.8;
    }

    let clock = new THREE.Clock();
    let coreThreatUntil = 0;

    function pulseCoreThreat() {
        coreThreatUntil = clock.getElapsedTime() + 2.2;
    }

    // ---- resize ----
    function onResize() {
        const w = container.clientWidth, h = container.clientHeight;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
    }
    const resizeObserver = new ResizeObserver(onResize);
    resizeObserver.observe(container);

    // ---- animation loop ----
    let rafId;
    function animate() {
        rafId = requestAnimationFrame(animate);
        const dt = Math.min(clock.getDelta(), 0.05);
        const t = clock.getElapsedTime();

        camTween.update(dt);
        lookTween.update(dt);
        camera.lookAt(camState.look);

        coreGroup.rotation.y += dt * 0.12;
        coreInner.rotation.y -= dt * 0.2;
        rings.forEach(r => { r.mesh.rotation.z += dt * r.speed; });

        const threatActive = t < coreThreatUntil;
        const coreColor = threatActive ? STATE_COLOR.error : 0x2de2c9;
        coreMat.color.setHex(coreColor);
        coreGlow.material.color.setHex(coreColor);
        const pulseScale = 1 + Math.sin(t * (threatActive ? 8 : 1.4)) * (threatActive ? 0.12 : 0.04);
        coreGroup.scale.setScalar(pulseScale);

        Object.values(nodes).forEach(n => {
            if (n.pulse > 0) {
                const s = 1 + Math.sin(t * 5) * 0.18;
                n.mesh.scale.setScalar(s);
                n.glow.material.opacity = 0.4 + Math.sin(t * 5) * 0.2;
            } else {
                n.mesh.scale.setScalar(1);
                n.glow.material.opacity = 0.3;
            }
        });

        anvilGroup.rotation.y += dt * 0.3;
        anvilPoints.rotation.y -= dt * 0.15;

        rings2Animate();

        // particles
        const posAttr = particleGeo.attributes.position;
        for (let i = 0; i < MAX_PARTICLES; i++) {
            if (i < particles.length) {
                const p = particles[i];
                p.t += dt * p.speed;
                if (p.t > 1) p.t = -0.15 + (p.t % 0.2);
                const tt = Math.max(0, Math.min(1, p.t));
                const x = p.from.x + (p.to.x - p.from.x) * tt;
                const y = p.from.y + (p.to.y - p.from.y) * tt;
                const z = p.from.z + (p.to.z - p.from.z) * tt;
                posAttr.setXYZ(i, x, y, z);
            } else {
                posAttr.setXYZ(i, 9999, 9999, 9999);
            }
        }
        posAttr.needsUpdate = true;

        if (dnaGroup.visible && dnaGroup.scale.x < 1) {
            dnaGroup.scale.setScalar(Math.min(1, dnaGroup.scale.x + dt * 0.8));
        }
        if (dnaGroup.visible) dnaGroup.rotation.y += dt * 0.25;

        renderer.render(scene, camera);
    }

    function rings2Animate() {
        Object.values(verifyRings).forEach(r => {
            if (r.state === 'active') {
                const s = 1 + Math.sin(clock.getElapsedTime() * 6) * 0.08;
                r.mesh.scale.setScalar(s);
            } else {
                r.mesh.scale.setScalar(1);
            }
        });
    }

    animate();

    // =========================================================
    // Public API — called from dashboard.py's socket handlers
    // =========================================================
    const STAGE_TO_GROUP = {
        INIT: 'discover', INGEST: 'discover', REWIND: 'discover', STATIC_ANALYSIS: 'discover',
        DYNAMIC_ANALYSIS: 'understand', FUZZ: 'understand', DISCOVERY: 'understand', ANALYZE: 'understand',
        PATCH: 'repair', BUILD: 'repair',
        EXPLOIT_REPLAY: 'verify', REGRESSION: 'verify', BEHAVIOUR_CHECK: 'verify',
        MEMORY_COMMIT: 'remember', COMPLETE: 'remember',
    };
    const doneGroups = new Set();

    const api = {
        onStageUpdate(stage, message) {
            const group = STAGE_TO_GROUP[stage];
            if (group) {
                const order = ['discover', 'understand', 'repair', 'verify', 'remember'];
                const idx = order.indexOf(group);
                order.slice(0, idx).forEach(g => { if (!doneGroups.has(g)) { doneGroups.add(g); setNodeState(g, 'completed'); } });
                if (!doneGroups.has(group)) setNodeState(group, group === 'understand' && stage === 'ANALYZE' ? 'ai' : 'active');
            }
            if (stage === 'INGEST') { goTo('repository', 1600); showCaption(['REPOSITORY INGESTION', 'CODE ANALYSIS INITIALIZED']); }
            if (stage === 'REWIND') { goTo('discover', 1400); spawnFlow(nodes.discover.pos.clone().multiplyScalar(1), new THREE.Vector3(0, 0, 0), 0x2de2c9, 14, 0.7); showCaption(['REWIND ENGINE', message]); }
            if (stage === 'STATIC_ANALYSIS') { showCaption(['STATIC ANALYSIS', message]); }
            if (stage === 'DYNAMIC_ANALYSIS') { goTo('understand', 1400); showCaption(['DYNAMIC ANALYSIS', message]); }
            if (stage === 'FUZZ') {
                spawnFlow(nodes.understand.pos, new THREE.Vector3(0, 0, 0), 0xe8b23d, 40, 1.1);
                showCaption(['FUZZ ENGINE — AFL++', message]);
            }
            if (stage === 'DISCOVERY') { pulseCoreThreat(); showCaption(['THREAT DETECTED', message], 2400); }
            if (stage === 'ANALYZE') {
                goTo('anvil', 1500);
                spawnFlow(new THREE.Vector3(0, 0, 0), anvilPos, 0x8a6bff, 20, 0.8);
                showCaption(['ANVIL', 'AUTONOMOUS SECURITY REASONING', message]);
            }
            if (stage === 'PATCH') {
                goTo('repair', 1400);
                spawnFlow(anvilPos, nodes.repair.pos, 0x8a6bff, 20, 0.8);
                showCaption(['PATCH GENERATED', message]);
            }
            if (stage === 'BUILD') { chamberGroup.visible = true; goTo('verify', 1500); showCaption(['VERIFICATION', message]); }
            if (stage === 'EXPLOIT_REPLAY') { showCaption(['EXPLOIT REPLAY', message]); }
            if (stage === 'REGRESSION') { showCaption(['REGRESSION TESTS', message]); }
            if (stage === 'BEHAVIOUR_CHECK') { showCaption(['BEHAVIOUR VALIDATION', message]); }
            if (stage === 'MEMORY_COMMIT') { goTo('remember', 1800); showCaption(['IMMUNE MEMORY', message]); }
            if (stage === 'COMPLETE') {
                const order = ['discover', 'understand', 'repair', 'verify', 'remember'];
                order.forEach(g => setNodeState(g, 'completed'));
                clearFlows();
                setTimeout(() => goTo('final', 2200), 300);
                showCaption(['ABHIMANYU X', 'SECURITY REPAIR VERIFIED'], 3200);
            }
        },
        onVerifyStep(key, passed) {
            const r = verifyRings[key];
            if (!r) return;
            r.state = passed ? 'completed' : 'error';
            r.mesh.material.color.setHex(passed ? STATE_COLOR.completed : STATE_COLOR.error);
            r.mesh.material.opacity = 0.9;
        },
        onImmuneMemoryCreated() {
            dnaGroup.visible = true;
            dnaGroup.scale.setScalar(0.001);
            showCaption(['VULNERABILITY DNA CREATED'], 2600);
        },
        onFutureLearning(similarityPct) {
            goTo('remember', 1600);
            showCaption(['IMMUNE MEMORY MATCH', similarityPct + '% SIMILARITY', 'KNOWN VULNERABILITY PATTERN'], 3200);
        },
        reset() {
            Object.keys(nodes).forEach(k => setNodeState(k, 'inactive'));
            doneGroups.clear();
            chamberGroup.visible = false;
            dnaGroup.visible = false;
            Object.values(verifyRings).forEach(r => { r.state = 'inactive'; r.mesh.material.color.setHex(STATE_COLOR.inactive); r.mesh.material.opacity = 0.55; });
            clearFlows();
            goTo('idle', 1600);
            caption.classList.remove('show');
        },
        setPerformanceMode(on) {
            renderer.setPixelRatio(on ? 1 : Math.min(window.devicePixelRatio || 1, 2));
            particleMat.size = on ? 0.05 : 0.06;
        },
        dispose() {
            cancelAnimationFrame(rafId);
            resizeObserver.disconnect();
            renderer.dispose();
        },
    };
    return api;
}

export function webglAvailable() {
    try {
        const canvas = document.createElement('canvas');
        return !!(window.WebGLRenderingContext && (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')));
    } catch (e) {
        return false;
    }
}
