import "./styles.css";

type Probe = {
  label: string;
  path: string;
  state: "loading" | "ok" | "warn" | "off";
  value: string;
  detail: string;
};

const probes: Probe[] = [
  {
    label: "Liveness",
    path: "/healthz",
    state: "loading",
    value: "checking",
    detail: "process"
  },
  {
    label: "Readiness",
    path: "/readyz",
    state: "loading",
    value: "checking",
    detail: "database gate"
  },
  {
    label: "Metrics",
    path: "/metrics",
    state: "loading",
    value: "checking",
    detail: "prometheus"
  }
];

const app = document.querySelector<HTMLElement>("#app");

if (!app) {
  throw new Error("missing #app root");
}

const root = app;

function render(items: Probe[]): void {
  root.innerHTML = `
    <section class="shell">
      <header class="topbar">
        <div>
          <p class="eyebrow">Operator Surface</p>
          <h1>oraclemcp</h1>
        </div>
        <span class="build">service mode</span>
      </header>

      <section class="status-grid" aria-label="service probes">
        ${items.map(renderProbe).join("")}
      </section>

      <section class="panel" aria-label="operator API">
        <div>
          <p class="eyebrow">API</p>
          <h2>/operator/v1</h2>
        </div>
        <p class="panel-status">typed JSON only</p>
      </section>
    </section>
  `;
}

function renderProbe(probe: Probe): string {
  return `
    <article class="probe probe-${probe.state}">
      <div class="probe-head">
        <span class="dot" aria-hidden="true"></span>
        <span>${probe.label}</span>
      </div>
      <strong>${probe.value}</strong>
      <small>${probe.detail}</small>
    </article>
  `;
}

async function loadProbe(probe: Probe): Promise<Probe> {
  try {
    const response = await fetch(probe.path, {
      headers: { accept: probe.path === "/metrics" ? "text/plain" : "application/json" },
      cache: "no-store"
    });
    if (response.status === 404) {
      return { ...probe, state: "off", value: "not mounted" };
    }
    if (response.ok) {
      return { ...probe, state: "ok", value: "ok" };
    }
    return { ...probe, state: "warn", value: `HTTP ${response.status}` };
  } catch {
    return { ...probe, state: "warn", value: "unreachable" };
  }
}

render(probes);

const settled = await Promise.all(probes.map(loadProbe));
render(settled);
