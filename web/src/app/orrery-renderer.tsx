import * as React from "react";
import * as THREE from "three";

import type { BigBoardRendererProps } from "./skin";
import type { ClearanceLevel, FleetViewModel } from "./presentation-model";

// B4.5 Orrery hero (iec3.2.25). A three.js celestial orrery over a cinematic
// mountain "Vale" backdrop: the guard core at centre, one ring per operating
// level (I·II·III·IV, each its own clearance color), and one orbiting body per
// active lane — orbital speed ∝ activity (grammar: motion = activity, color =
// clearance). Loaded only through the lazy/code-split orrery3d renderer seam and
// only when WebGL is present and motion is allowed; every other client gets the
// mandatory 2D fallback. No external asset is fetched (procedural geometry +
// solid colors only), so the strict CSP (script-src self, no unsafe-eval) holds.

const CLEARANCE_COLOR: Record<ClearanceLevel, number> = {
  READ_ONLY: 0x8ea98c, // sage
  READ_WRITE: 0xc7a34a, // gold
  DDL: 0xd97748, // copper
  ADMIN: 0xc25048 // rust
};
const LEVEL_ORDER: ClearanceLevel[] = ["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"];
const RING_RADIUS = (index: number): number => 1.8 + Math.max(0, index) * 1.15;

function fleetSignature(model: FleetViewModel): string {
  return model.sessions.map((s) => `${s.laneId}:${s.clearance}:${s.activity.toFixed(2)}`).join("|");
}

export default function OrreryRenderer({
  model,
  renderer
}: BigBoardRendererProps): React.ReactElement {
  const mountRef = React.useRef<HTMLDivElement | null>(null);
  const modelRef = React.useRef<FleetViewModel>(model);
  modelRef.current = model;
  const [failed, setFailed] = React.useState(false);

  React.useEffect(() => {
    const mount = mountRef.current;
    if (!mount) {
      return;
    }
    let gl: THREE.WebGLRenderer;
    try {
      gl = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: "low-power" });
    } catch {
      setFailed(true);
      return;
    }

    const HEIGHT = 380;
    const width = mount.clientWidth || 640;
    gl.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    gl.setSize(width, HEIGHT, false);
    gl.setClearColor(0x0c0b09, 1);
    gl.domElement.setAttribute("aria-hidden", "true");
    mount.appendChild(gl.domElement);

    const scene = new THREE.Scene();
    scene.fog = new THREE.Fog(0x0c0b09, 9, 28);
    const camera = new THREE.PerspectiveCamera(45, width / HEIGHT, 0.1, 100);
    camera.position.set(0, 4.2, 11);
    camera.lookAt(0, 0.4, 0);

    const disposables: Array<{ dispose(): void }> = [];
    scene.add(new THREE.AmbientLight(0x2b261b, 1.5));
    const key = new THREE.DirectionalLight(0xc7a34a, 1.1);
    key.position.set(5, 8, 6);
    scene.add(key);

    // Layered mountain "Vale" silhouettes receding into the fog.
    const addRidge = (z: number, colorHex: number, amp: number): void => {
      const shape = new THREE.Shape();
      shape.moveTo(-34, -7);
      const peaks = 10;
      for (let i = 0; i <= peaks; i += 1) {
        const x = -34 + (68 * i) / peaks;
        const y = (Math.sin(i * 1.7) + Math.cos(i * 0.9)) * amp;
        shape.lineTo(x, y);
      }
      shape.lineTo(34, -7);
      shape.lineTo(-34, -7);
      const geo = new THREE.ShapeGeometry(shape);
      const mat = new THREE.MeshBasicMaterial({ color: colorHex });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.set(0, -1.6, z);
      scene.add(mesh);
      disposables.push(geo, mat);
    };
    addRidge(-15, 0x1e1913, 1.5);
    addRidge(-11, 0x282119, 1.15);
    addRidge(-7.5, 0x2b261b, 0.85);

    // Guard core.
    const coreGeo = new THREE.SphereGeometry(0.7, 32, 32);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0xc7a34a,
      emissive: 0xc7a34a,
      emissiveIntensity: 0.55,
      roughness: 0.35,
      metalness: 0.4
    });
    const core = new THREE.Mesh(coreGeo, coreMat);
    scene.add(core);
    disposables.push(coreGeo, coreMat);

    // One ring per operating level.
    LEVEL_ORDER.forEach((level, index) => {
      const r = RING_RADIUS(index);
      const ringGeo = new THREE.RingGeometry(r - 0.012, r + 0.012, 96);
      const ringMat = new THREE.MeshBasicMaterial({
        color: CLEARANCE_COLOR[level],
        transparent: true,
        opacity: 0.35,
        side: THREE.DoubleSide
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.rotation.x = -Math.PI / 2;
      scene.add(ring);
      disposables.push(ringGeo, ringMat);
    });

    // Orbiting lane bodies (rebuilt when the fleet signature changes).
    const bodyGroup = new THREE.Group();
    scene.add(bodyGroup);
    const bodyGeo = new THREE.SphereGeometry(0.16, 20, 20);
    disposables.push(bodyGeo);
    const bodyMat = new Map<ClearanceLevel, THREE.Material>();
    LEVEL_ORDER.forEach((level) => {
      const mat = new THREE.MeshStandardMaterial({
        color: CLEARANCE_COLOR[level],
        emissive: CLEARANCE_COLOR[level],
        emissiveIntensity: 0.5,
        roughness: 0.4
      });
      bodyMat.set(level, mat);
      disposables.push(mat);
    });

    type Body = { mesh: THREE.Mesh; radius: number; speed: number; phase: number };
    let bodies: Body[] = [];
    const rebuild = (m: FleetViewModel): void => {
      for (const body of bodies) {
        bodyGroup.remove(body.mesh);
      }
      bodies = m.sessions.map((session, index) => {
        const level = LEVEL_ORDER.indexOf(session.clearance);
        const mesh = new THREE.Mesh(bodyGeo, bodyMat.get(session.clearance) ?? bodyMat.get("READ_ONLY"));
        bodyGroup.add(mesh);
        return {
          mesh,
          radius: RING_RADIUS(level),
          speed: 0.15 + session.activity * 0.9,
          phase: index * 2.399
        };
      });
    };
    rebuild(model);
    let signature = fleetSignature(model);

    const onResize = (): void => {
      const w = mount.clientWidth || width;
      gl.setSize(w, HEIGHT, false);
      camera.aspect = w / HEIGHT;
      camera.updateProjectionMatrix();
    };
    const observer = new ResizeObserver(onResize);
    observer.observe(mount);

    const start = performance.now();
    let raf = 0;
    const animate = (): void => {
      raf = requestAnimationFrame(animate);
      const elapsed = (performance.now() - start) / 1000;
      const current = modelRef.current;
      const sig = fleetSignature(current);
      if (sig !== signature) {
        signature = sig;
        rebuild(current);
      }
      core.rotation.y += 0.004;
      for (const body of bodies) {
        const angle = body.phase + elapsed * body.speed;
        body.mesh.position.set(Math.cos(angle) * body.radius, 0.05, Math.sin(angle) * body.radius);
      }
      gl.render(scene, camera);
    };
    animate();

    return () => {
      cancelAnimationFrame(raf);
      observer.disconnect();
      for (const item of disposables) {
        item.dispose();
      }
      gl.dispose();
      gl.domElement.parentNode?.removeChild(gl.domElement);
    };
  }, []);

  if (failed) {
    return <OrreryFallback model={model} renderer={renderer} />;
  }

  return (
    <section
      aria-label="big board orrery"
      data-renderer={renderer.kind}
      data-grammar-version={model.grammarVersion}
      className="relative overflow-hidden rounded-lg border border-[var(--om-border)] bg-[var(--om-bg)] shadow-sm"
    >
      <div ref={mountRef} className="h-[380px] w-full" />
      <div className="pointer-events-none absolute inset-x-4 top-3 flex items-start justify-between gap-3">
        <div>
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            Big Board · Orrery
          </p>
          <p className="mt-1 font-mono text-2xl font-bold leading-none text-[var(--om-text-bright)]">
            {model.verdict}
          </p>
        </div>
        <div className="flex flex-wrap justify-end gap-1.5">
          {LEVEL_ORDER.map((level, index) => (
            <span
              key={level}
              className="inline-flex items-center gap-1 rounded-sm border border-[var(--om-border)] bg-[color-mix(in_srgb,var(--om-surface)_70%,transparent)] px-1.5 py-0.5 font-mono text-2xs font-bold text-[var(--om-text)]"
            >
              <span
                aria-hidden="true"
                className="inline-block size-2 rounded-full"
                style={{ backgroundColor: `#${CLEARANCE_COLOR[level].toString(16).padStart(6, "0")}` }}
              />
              {["I", "II", "III", "IV"][index]}
            </span>
          ))}
        </div>
      </div>
      <p className="pointer-events-none absolute bottom-3 left-4 font-mono text-2xs text-[var(--om-text-muted)]">
        {model.totals.activeLanes} lanes · {model.totals.requests} req
      </p>
      <span className="sr-only">
        Orrery hero: {model.verdict}, {model.totals.activeLanes} active lanes across the
        READ_ONLY/READ_WRITE/DDL/ADMIN operating levels.
      </span>
    </section>
  );
}

// Runtime WebGL-failure fallback (the capability-based fallback to the 2D board
// happens upstream in the skin; this guards a lost/denied context at mount).
function OrreryFallback({ model, renderer }: BigBoardRendererProps): React.ReactElement {
  return (
    <section
      aria-label="big board orrery fallback"
      data-renderer={renderer.kind}
      data-grammar-version={model.grammarVersion}
      className="overflow-hidden rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] shadow-sm"
    >
      <div className="flex items-center justify-between gap-3 border-b border-[var(--om-border)] px-4 py-3">
        <div>
          <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
            Big Board · Orrery
          </p>
          <p className="mt-1 font-mono text-2xl font-bold leading-none text-[var(--om-text-bright)]">
            {model.verdict}
          </p>
        </div>
        <span className="rounded-md border border-[var(--om-border)] px-2 py-1 text-xs font-semibold text-[var(--om-text-muted)]">
          2D fallback
        </span>
      </div>
      <div className="grid gap-3 p-4 sm:grid-cols-3">
        <OrreryFact label="Verdict" value={model.verdict} />
        <OrreryFact label="Active" value={model.totals.activeLanes} />
        <OrreryFact label="Requests" value={model.totals.requests} />
      </div>
    </section>
  );
}

function OrreryFact({
  label,
  value
}: {
  label: string;
  value: number | string;
}): React.ReactElement {
  return (
    <div className="rounded-md border border-[var(--om-border)] bg-[var(--om-surface-muted)] p-3">
      <p className="text-2xs font-semibold uppercase tracking-[var(--tracking-label)] text-[var(--om-text-muted)]">
        {label}
      </p>
      <p className="mt-2 font-mono text-sm font-bold text-[var(--om-text-bright)]">{value}</p>
    </div>
  );
}
