"use strict";

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

const SEV_COLORS = {
  CRITICAL: "#f43f5e",
  HIGH: "#fb923c",
  MEDIUM: "#fbbf24",
  LOW: "#38bdf8",
};

const RISK_CLASS = { CRITICO: "critical", ALTO: "high", MEDIO: "medium", BAJO: "low" };

const MODULES = [
  { dir: "01_Sistema", title: "Informacion del Sistema" },
  { dir: "02_Usuarios", title: "Usuarios y Permisos" },
  { dir: "03_Procesos", title: "Procesos y Servicios" },
  { dir: "04_Red", title: "Analisis de Red" },
  { dir: "05_Eventos", title: "Eventos de Seguridad" },
  { dir: "06_Archivos", title: "Archivos y Persistencia" },
  { dir: "07_Configuracion", title: "Configuracion de Seguridad" },
  { dir: "08_LOLBAS", title: "Deteccion LOLBAS" },
  { dir: "09_Drivers", title: "Analisis de Drivers" },
  { dir: "10_Hardware", title: "Informacion de Hardware" },
];

const state = {
  view: "dashboard",
  audits: [],
  selectedAuditId: null,
  audit: null,
  moduleView: null,
  pollTimer: null,
  source: null,
  running: false,
};

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

function esc(v) {
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function csrfToken() {
  if (window.csrfToken) return window.csrfToken;
  const match = document.cookie.match(/(?:^|;\s*)audit_csrf=([^;]+)/);
  return match ? match[1] : "";
}

async function api(path, opts = {}) {
  const method = (opts.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  // Las mutaciones requieren el token de la sesion; el backend lo exige siempre.
  if (method !== "GET" && method !== "HEAD") {
    const token = csrfToken();
    if (token) headers["X-CSRF-Token"] = token;
  }
  const res = await fetch(path, {
    ...opts,
    method,
    headers,
  });
  if (res.status === 401) {
    // La sesion caduco por inactividad: mostrar el acceso y no dejar la UI a medias.
    if (typeof showLogin === "function") showLogin("La sesion ha caducado. Vuelve a iniciar sesion.");
    throw new Error("No hay sesion activa");
  }
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      msg = body.detail || msg;
    } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

function toast(msg, type = "") {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "toast show " + type;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = "toast"), 3600);
}

function fmt(v) {
  if (v === null || v === undefined) return '<span class="text-muted">—</span>';
  if (typeof v === "boolean") return v ? "Si" : "No";
  if (typeof v === "number") return esc(v.toLocaleString("es-ES"));
  if (typeof v === "object") {
    const s = JSON.stringify(v);
    return '<span class="mono text-muted">' + esc(s) + "</span>";
  }
  return esc(v);
}

function folderToDate(folder) {
  const m = folder.match(/Auditoria_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
  if (!m) return folder;
  return `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]}:${m[6]}`;
}

function riskClass(level) {
  return RISK_CLASS[level] || "low";
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

function severityBadge(sev) {
  const cls = (sev || "LOW").toLowerCase();
  const label = sev === "MEDIUM" ? "Media" : sev === "HIGH" ? "Alta" : sev === "CRITICAL" ? "Critica" : "Baja";
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

function riskBadge(level) {
  const cls = riskClass(level);
  const label = level === "CRITICO" ? "CRITICO" : level === "ALTO" ? "ALTO" : level === "MEDIO" ? "MEDIO" : "BAJO";
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

function emptyState(icon, title, sub, action = "") {
  return `<div class="empty">
    <svg viewBox="0 0 24 24"><path d="${icon}"/></svg>
    <div class="t">${title}</div>
    <div class="s">${sub}</div>
    ${action}
  </div>`;
}

function renderDonut(counts) {
  const total = (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0);
  const r = 62;
  const c = 2 * Math.PI * r;

  if (total === 0) {
    return `<div class="donut-wrap">
      <div class="donut"><svg width="170" height="170" viewBox="0 0 170 170">
        <circle cx="85" cy="85" r="${r}" fill="none" stroke="var(--border)" stroke-width="18"/>
      </svg><div class="donut-center"><div class="num">0</div><div class="lbl">Amenazas</div></div></div>
      <div class="text-muted" style="text-align:center">Sin amenazas detectadas</div>
    </div>`;
  }

  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  let offset = 0;
  let segs = "";
  for (const sev of order) {
    const n = counts[sev] || 0;
    if (n === 0) continue;
    const frac = n / total;
    const dash = frac * c;
    segs += `<circle cx="85" cy="85" r="${r}" fill="none" stroke="${SEV_COLORS[sev]}" stroke-width="18"
      stroke-dasharray="${dash} ${c - dash}" stroke-dashoffset="${-offset}"></circle>`;
    offset += dash;
  }

  const legend = order
    .filter((sev) => (counts[sev] || 0) > 0)
    .map(
      (sev) => `<div class="legend-item">
        <span class="legend-dot" style="background:${SEV_COLORS[sev]}"></span>
        <span class="lbl">${esc(sev === "MEDIUM" ? "Medias" : sev === "HIGH" ? "Altas" : sev === "CRITICAL" ? "Criticas" : "Bajas")}</span>
        <span class="val">${counts[sev]}</span>
      </div>`
    )
    .join("");

  return `<div class="donut-wrap">
    <div class="donut"><svg width="170" height="170" viewBox="0 0 170 170">
      <circle cx="85" cy="85" r="${r}" fill="none" stroke="var(--border)" stroke-width="18"/>
      ${segs}
    </svg><div class="donut-center"><div class="num">${total}</div><div class="lbl">Amenazas</div></div></div>
    <div class="legend">${legend}</div>
  </div>`;
}

function renderTable(data) {
  if (!Array.isArray(data)) {
    if (data && typeof data === "object") {
      const rows = Object.entries(data)
        .map(
          ([k, v]) => `<tr><td class="mono" style="color:var(--text-muted)">${esc(k)}</td><td>${fmt(v)}</td></tr>`
        )
        .join("");
      return `<table><tbody>${rows}</tbody></table>`;
    }
    return `<div class="text-muted">Sin datos</div>`;
  }

  if (data.length === 0) return `<div class="text-muted">Sin registros</div>`;

  const keys = [];
  for (const row of data) {
    if (row && typeof row === "object" && !Array.isArray(row)) {
      for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k);
    }
  }

  const head = keys.map((k) => `<th>${esc(k)}</th>`).join("");
  const MAX = 500;
  const body = data
    .slice(0, MAX)
    .map((row) => {
      if (row && typeof row === "object" && !Array.isArray(row)) {
        const cells = keys.map((k) => `<td>${fmt(row[k])}</td>`).join("");
        return `<tr>${cells}</tr>`;
      }
      return `<tr><td>${fmt(row)}</td></tr>`;
    })
    .join("");

  const note =
    data.length > MAX
      ? `<div class="text-muted" style="margin-top:10px">Mostrando ${MAX} de ${data.length} registros</div>`
      : "";

  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${note}`;
}

// ---------------------------------------------------------------------------
// Vistas
// ---------------------------------------------------------------------------

// La URL refleja la pestaña y la auditoria abierta: #/dashboard, #/audits,
// #/run y #/audit/<id>. Sin esto, compartir o recargar una pestaña concreta
// siempre devolvía al Panel General.
const VIEWS = ["dashboard", "audits", "run", "baseline", "integrations", "admin"];

function parseHash() {
  const raw = (location.hash || "").replace(/^#\/?/, "");
  if (!raw) return { view: "dashboard", auditId: null };
  const parts = raw.split("/");
  if (parts[0] === "audit" && parts[1]) {
    return { view: "dashboard", auditId: decodeURIComponent(parts[1]) };
  }
  return { view: VIEWS.includes(parts[0]) ? parts[0] : "dashboard", auditId: null };
}

function setHash(view, auditId) {
  const target = auditId ? `#/audit/${encodeURIComponent(auditId)}` : `#/${view}`;
  if (location.hash !== target) location.hash = target;
}

function setActiveView(view, auditId) {
  if (auditId) state.selectedAuditId = auditId;
  state.view = view;
  setHash(view, view === "dashboard" ? state.selectedAuditId : null);
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.getElementById("view-" + view).classList.add("active");

  const titles = {
    dashboard: "Panel General",
    audits: "Auditorias",
    run: "Nueva Auditoria",
    baseline: "Baseline",
    integrations: "Integraciones",
    admin: "Administracion",
  };
  document.getElementById("topbar-title").textContent = titles[view] || "Security Audit";

  if (view === "dashboard") renderDashboard();
  if (view === "audits") renderAudits();
  if (view === "run") renderRun();
  if (view === "baseline") renderBaseline();
  if (view === "integrations") renderIntegrations();
  if (view === "admin") renderAdmin();
}

async function renderDashboard() {
  const el = document.getElementById("view-dashboard");
  const audits = state.audits;

  // Si la seleccion actual ya no existe (borrada o cambio de contexto), volver a la mas reciente.
  if (state.selectedAuditId && !audits.some((a) => a.id === state.selectedAuditId)) {
    state.selectedAuditId = audits.length > 0 ? audits[0].id : null;
  }

  if (!state.selectedAuditId && audits.length > 0) {
    state.selectedAuditId = audits[0].id;
  }

  if (!state.selectedAuditId || audits.length === 0) {
    el.innerHTML = emptyState(
      "M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3zM8.5 12l2.5 2.5L15.5 9",
      "No hay auditorias",
      "Ejecute una auditoria para generar resultados, o verifique que el directorio de resultados contiene carpetas Auditoria_*.",
      `<button class="btn btn-primary" data-goto="run">Ejecutar auditoria</button>`
    );
    bindGoto(el);
    return;
  }

  try {
    state.audit = await api("/api/audits/" + encodeURIComponent(state.selectedAuditId));
    el.innerHTML = dashboardHtml(state.audit);
    bindDashboard(el, state.audit);
  } catch (e) {
    el.innerHTML = `<div class="card"><div class="text-muted">Error al cargar la auditoria: ${esc(e.message)}</div></div>`;
  }
}

function dashboardHtml(a) {
  const s = a.summary || {};
  const counts = a.severity_counts || {};
  const selector = `<select class="select" id="audit-select">${state.audits
    .map((x) => `<option value="${esc(x.id)}" ${x.id === a.id ? "selected" : ""}>${esc(folderToDate(x.folder))}</option>`)
    .join("")}</select>`;

  const kpis = [
    { cls: "neutral", label: "Amenazas totales", value: a.threats_count },
    { cls: "critical", label: "Criticas", value: counts.CRITICAL || 0 },
    { cls: "high", label: "Altas", value: counts.HIGH || 0 },
    { cls: "medium", label: "Medias", value: counts.MEDIUM || 0 },
    { cls: "low", label: "Bajas", value: counts.LOW || 0 },
    { cls: "neutral", label: "Errores", value: s.errores ?? "—" },
  ]
    .map(
      (k) => `<div class="kpi ${k.cls}"><div class="kpi-value">${esc(k.value)}</div><div class="kpi-label">${esc(k.label)}</div></div>`
    )
    .join("");

  const recs = (a.recommendations || []).length
    ? `<ul class="recs">${a.recommendations.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`
    : `<div class="text-muted">Sin recomendaciones pendientes.</div>`;

  const gaps = a.coverage_gaps || [];
  const coverage = gaps.length
    ? `<div class="card" style="border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);padding:12px">
        <div style="font-size:12px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.5px">Cobertura: PARCIAL (${gaps.length} omisiones)</div>
        <ul class="recs" style="margin-top:8px">${gaps.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>
        <div class="text-muted" style="margin-top:6px;font-size:12px">Ejecuta la auditoria elevada para cerrar estas omisiones.</div>
      </div>`
    : "";

  const suppressed = a.suppressed || [];
  const suppressedCard = suppressed.length
    ? `<div class="card" style="border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);padding:12px">
        <div style="font-size:12px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.5px">Suprimidas por allowlist (${suppressed.length})</div>
        <ul class="recs" style="margin-top:8px">${suppressed.map((s) => `<li><strong>${esc(s.type)}</strong> (${esc(s.severity)}) — ${esc(s.description)}<br><span class="text-muted" style="font-size:12px">Motivo: ${esc(s.reason || "—")} [${esc(s.allowlist_id || "")}]</span></li>`).join("")}</ul>
        <div class="text-muted" style="margin-top:6px;font-size:12px">No cuentan en el nivel de riesgo. Edita la allowlist en el script o pasa -AllowlistPath con un JSON propio.</div>
      </div>`
    : "";

  const trend = a.trend || {};
  const trendCard = trend.previous
    ? `<div class="card" style="border:1px solid var(--border);border-radius:var(--radius);background:var(--surface);padding:12px">
        <div style="font-size:12px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.5px">Tendencia frente a ${esc(trend.previous)}</div>
        <div class="flex" style="gap:14px;margin-top:8px;flex-wrap:wrap">
          <span>Amenazas: ${trend.previous_threats} → ${a.threats_count} (${trend.delta > 0 ? "+" : ""}${trend.delta})</span>
          <span>Riesgo: ${esc(trend.previous_risk)} → ${esc(a.risk_level)}${trend.risk_change === "sin cambio" ? " (sin cambio)" : ""}</span>
          <span>Nuevas: ${trend.new.length}</span>
          <span>Resueltas: ${trend.resolved.length}</span>
          <span>Recurrentes: ${trend.persistent}</span>
        </div>
        ${trend.new.length ? `<ul class="recs" style="margin-top:8px">${trend.new.map((t) => `<li>[${esc(t.severity)}] ${esc(t.type)} — ${esc(t.description)}</li>`).join("")}</ul>` : ""}
        ${trend.resolved.length ? `<ul class="recs" style="margin-top:8px">${trend.resolved.map((t) => `<li>Resuelta: [${esc(t.severity)}] ${esc(t.type)} — ${esc(t.description)}</li>`).join("")}</ul>` : ""}
      </div>`
    : "";

  const modules = a.modules
    .map(
      (m) => `<button class="card" style="text-align:left;cursor:pointer;padding:16px;border:1px solid var(--border);background:var(--surface);border-radius:var(--radius);color:var(--text);font-family:inherit" data-module="${esc(m.name)}">
        <div style="display:flex;align-items:center;gap:10px">
          <span class="mono" style="color:var(--text-faint);font-size:12px">${esc(m.name.split("_")[0])}</span>
          <span style="font-weight:600;flex:1">${esc(m.title)}</span>
          <span class="text-muted" style="font-size:12px">${m.datasets.length} dataset${m.datasets.length === 1 ? "" : "s"}</span>
        </div>
      </button>`
    )
    .join("");

  return `
  <div class="card summary-hero">
    <div class="hero-meta">
      <div class="hero-audit">${esc(folderToDate(a.folder))}</div>
      <div class="hero-sub">${esc(a.folder)}</div>
      <dl>
        <div><dt>Sistema</dt><dd>${esc(s.sistema || "—")}</dd></div>
        <div><dt>Usuario</dt><dd>${esc(s.usuario || "—")}</dd></div>
        <div><dt>Privilegios</dt><dd>${esc(s.privilegios || "—")}</dd></div>
        <div><dt>Duracion</dt><dd>${esc(s.duracion || "—")}</dd></div>
        <div><dt>Modulos</dt><dd>${esc(s.modulos || "—")}</dd></div>
        <div><dt>Inicio</dt><dd>${esc(s.fecha_inicio || "—")}</dd></div>
      </dl>
    </div>
    <div class="flex" style="flex-direction:column;gap:10px;align-items:flex-end">
      <div style="font-size:12px;color:var(--text-faint);text-transform:uppercase;letter-spacing:0.5px">Nivel de riesgo</div>
      ${riskBadge(a.risk_level)}
      <div class="flex" style="gap:8px">${selector}</div>
      <div class="flex" style="gap:6px">
        <button class="btn btn-ghost" data-dl="pdf" title="Descargar reporte en PDF">PDF</button>
        <button class="btn btn-ghost" data-dl="json" title="Descargar exportacion completa en JSON">JSON</button>
        <button class="btn btn-ghost" data-dl="csv" title="Descargar amenazas en CSV">CSV</button>
        <button class="btn btn-ghost" data-dl="log" title="Exportar log unificado (JSON Lines) para el Visor de Logs">LOG</button>
      </div>
      <button class="btn btn-ghost" id="btn-cleanup-dash">Limpiar auditorias</button>
    </div>
  </div>

  <div class="kpi-grid" style="margin-top:18px">${kpis}</div>

  ${coverage}
  ${suppressedCard}
  ${trendCard}

  <div class="chart-row" style="margin-top:18px">
    <div class="card">${renderDonut(counts)}</div>
    <div class="card">
      <div class="card-head"><span class="card-title">Recomendaciones</span></div>
      ${recs}
    </div>
  </div>

  <div class="card" style="margin-top:18px">
    <div class="card-head">
      <span class="card-title">Amenazas Detectadas</span>
      <span class="card-sub">${a.threats.length} resultados</span>
    </div>
    <div class="toolbar" style="margin-bottom:14px">
      <div class="search">
        <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.35-4.35"/></svg>
        <input type="text" id="threat-search" placeholder="Buscar en amenazas..." />
      </div>
      <div class="seg" id="threat-filter">
        <button data-f="ALL" class="active">Todas</button>
        <button data-f="CRITICAL">Criticas</button>
        <button data-f="HIGH">Altas</button>
        <button data-f="MEDIUM">Medias</button>
        <button data-f="LOW">Bajas</button>
      </div>
    </div>
    <div id="threat-table"></div>
  </div>

  ${aiCardHtml()}

  <div class="card" style="margin-top:18px">
    <div class="card-head"><span class="card-title">Modulos de Auditoria</span></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px">${modules}</div>
  </div>
  `;
}

function threatsTableHtml(threats) {
  if (!threats.length) return `<div class="text-muted">No se detectaron amenazas.</div>`;
  const rows = threats
    .map(
      (t) => `<tr>
        <td>${severityBadge(t.severity)}</td>
        <td class="mono" style="white-space:nowrap;color:var(--text-muted)">${esc(t.timestamp || "—")}</td>
        <td style="font-weight:600">${esc(t.type || "—")}</td>
        <td>${esc(t.description || "—")}</td>
        <td class="mono" style="white-space:nowrap">${t.mitre_technique ? `<a href="${esc(t.mitre_url)}" target="_blank" rel="noopener noreferrer" title="${esc(t.mitre_name || "")} - ${esc(t.mitre_tactic || "")}">${esc(t.mitre_technique)}</a>` : "—"}</td>
        <td><details><summary style="cursor:pointer;color:var(--accent)">Detalle</summary><div class="mono text-muted" style="margin-top:6px;white-space:pre-wrap">${esc(typeof t.details === "string" ? t.details : JSON.stringify(t.details, null, 2))}</div></details></td>
      </tr>`
    )
    .join("");
  return `<div class="table-wrap"><table>
    <thead><tr><th>Severidad</th><th>Fecha</th><th>Tipo</th><th>Descripcion</th><th>MITRE</th><th>Detalle</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function aiCardHtml() {
  return `
  <div class="card" style="margin-top:18px">
    <div class="card-head">
      <span class="card-title">IA — Veredictos (Jev) y Explicaciones Tecnicas (LLM local)</span>
      <span class="card-sub">Opcional, referencial: enriquece el informe sin cambiar los datos</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:10px;margin-top:12px">
      <div class="flex" style="gap:8px;align-items:center;flex-wrap:wrap">
        <span class="mono text-muted" style="min-width:150px">Jev (TypeSafe)</span>
        <input class="input mono" id="ai-jev-key" type="password" placeholder="API key (solo memoria)" style="max-width:340px" />
        <button class="btn btn-ghost" id="btn-ai-save-jev">Guardar Jev</button>
        <button class="btn btn-ghost" id="btn-ai-test-jev">Probar Jev</button>
      </div>
      <div class="flex" style="gap:8px;align-items:center;flex-wrap:wrap">
        <span class="mono text-muted" style="min-width:150px">Backend veredictos</span>
        <select class="select mono" id="ai-backend" style="max-width:120px">
          <option value="cloud">cloud (Jev)</option>
          <option value="local">local (LAYA)</option>
        </select>
        <input class="input mono" id="ai-laya-url" placeholder="http://127.0.0.1:8787/v1/systemone" style="max-width:260px" />
        <input class="input mono" id="ai-laya-model" placeholder="multilingual" style="max-width:140px" />
        <button class="btn btn-ghost" id="btn-ai-save-backend">Guardar backend</button>
      </div>
      <div class="flex" style="gap:8px;align-items:center;flex-wrap:wrap">
        <span class="mono text-muted" style="min-width:150px">LLM local (tecnico)</span>
        <input class="input mono" id="ai-llm-url" placeholder="http://127.0.0.1:8099" style="max-width:220px" />
        <input class="input mono" id="ai-llm-model" placeholder="modelo" style="max-width:220px" />
        <button class="btn btn-ghost" id="btn-ai-save-llm">Guardar LLM</button>
        <button class="btn btn-ghost" id="btn-ai-test-llm">Probar LLM</button>
      </div>
      <div class="flex" style="gap:8px;align-items:center">
        <button class="btn btn-primary" id="btn-ai-enrich">Enriquecer informe con IA</button>
        <span class="text-muted" id="ai-status"></span>
      </div>
    </div>
    <div id="ai-results" style="margin-top:16px"></div>
  </div>`;
}

function aiVerdictsTableHtml(a, jev) {
  const verdicts = jev.verdicts || {};
  const rows = Object.keys(verdicts)
    .map((i) => ({ i: Number(i), v: verdicts[i] }))
    .filter((x) => x.i < a.threats.length)
    .sort((p, q) => p.i - q.i)
    .map(({ i, v }) => {
      const t = a.threats[i];
      const fp = v.prob_false_positive == null ? "—" : Math.round(v.prob_false_positive * 100) + "%";
      return `<tr>
        <td>${severityBadge(t.severity)}</td>
        <td style="font-weight:600">${esc(t.type || "—")}</td>
        <td class="mono">${esc(v.verdict || "—")}</td>
        <td class="num">${v.confidence == null ? "—" : esc(String(v.confidence))}</td>
        <td class="num" style="font-weight:600">${fp}</td>
        <td class="num">${v.severity_score == null ? "—" : esc(String(v.severity_score))} / 3</td>
        <td class="num">${v.immediate_action == null ? "—" : esc(String(v.immediate_action))}</td>
      </tr>`;
    })
    .join("");
  if (!rows) return `<div class="text-muted">Sin veredictos Jev.</div>`;
  return `<div class="table-wrap"><table>
    <thead><tr><th>Severidad</th><th>Amenaza</th><th>Veredicto Jev</th><th>Confianza</th><th>Prob. falso positivo</th><th>Severidad IA</th><th>Accion inmediata (0-1)</th></tr></thead>
    <tbody>${rows}</tbody>
  </table></div>`;
}

function aiResultsHtml(a, data) {
  if (!data) return "";
  const parts = [];
  const ex = data.executive_summary || {};
  if (ex.status === "ok") {
    parts.push(`<div class="card" style="background:var(--surface-2,transparent);border:1px solid var(--border)">
      <div class="card-head"><span class="card-title">Resumen Ejecutivo (LLM local)</span></div>
      <p style="margin:8px 0;line-height:1.5">${esc(ex.resumen_ejecutivo || "")}</p>
      ${ex.riesgo_principal ? `<p style="margin:6px 0"><strong>Riesgo principal:</strong> ${esc(ex.riesgo_principal)}</p>` : ""}
      ${(ex.acciones_prioritarias || []).length ? `<ul style="margin:8px 0 0;padding-left:20px">${ex.acciones_prioritarias.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    </div>`);
  }
  const jev = data.jev || {};
  if (jev.status === "ok") {
    parts.push(`<div class="card" style="border:1px solid var(--border)">
      <div class="card-head"><span class="card-title">Veredictos Jev</span><span class="card-sub">Prob. falso positivo derivada de veredicto + confianza</span></div>
      ${aiVerdictsTableHtml(a, jev)}
    </div>`);
  }
  const expls = data.llm_explanations || [];
  if (expls.length) {
    parts.push(`<div class="card" style="border:1px solid var(--border)">
      <div class="card-head"><span class="card-title">Explicaciones Tecnicas (LLM local)</span></div>
      ${expls.map((e) => `
        <details style="margin-bottom:8px">
          <summary style="cursor:pointer;font-weight:600">${esc(e.type || "—")} <span class="text-muted" style="font-weight:400">(${esc(e.severity || "")})</span></summary>
          ${e.status === "unavailable"
            ? `<div class="text-muted" style="margin-top:6px">Explicacion no disponible (${esc(e.reason || "")})</div>`
            : `<div style="margin-top:8px;line-height:1.5">
                <p><strong>Que es:</strong> ${esc(e.resumen || "")}</p>
                <p style="margin:4px 0"><strong>Por que importa:</strong> ${esc(e.porque || "")}</p>
                <p style="margin:4px 0"><strong>Sugerencia:</strong> ${esc(e.sugerencia || "")}</p>
              </div>`}
        </details>`).join("")}
    </div>`);
  }
  if (!parts.length) return `<div class="text-muted">Sin datos IA (configurarlo y pulsar \u201cEnriquecer informe con IA\u201d).</div>`;
  return parts.join("");
}

function bindDashboard(el, a) {
  const cleanupBtn = el.querySelector("#btn-cleanup-dash");
  if (cleanupBtn) cleanupBtn.addEventListener("click", cleanupAudits);

  el.querySelectorAll("[data-dl]").forEach((b) => {
    b.addEventListener("click", () => {
      window.open(`/api/audits/${encodeURIComponent(a.id)}/download/${b.dataset.dl}`, "_blank");
    });
  });

  const select = el.querySelector("#audit-select");
  if (select) {
    select.addEventListener("change", () => {
      state.selectedAuditId = select.value;
      setHash("dashboard", state.selectedAuditId);
      renderDashboard();
    });
  }

  el.querySelectorAll("[data-module]").forEach((b) => {
    b.addEventListener("click", () => renderModule(a.id, b.dataset.module));
  });

  const input = el.querySelector("#threat-search");
  const seg = el.querySelector("#threat-filter");
  const tableEl = el.querySelector("#threat-table");
  let filter = "ALL";

  const apply = () => {
    const q = input.value.toLowerCase();
    const list = a.threats.filter((t) => {
      const okSev = filter === "ALL" || (t.severity || "").toUpperCase() === filter;
      if (!okSev) return false;
      if (!q) return true;
      const hay = [t.type, t.description, t.timestamp, t.severity].join(" ").toLowerCase();
      return hay.includes(q);
    });
    tableEl.innerHTML = threatsTableHtml(list);
  };

  input.addEventListener("input", apply);
  seg.querySelectorAll("button").forEach((b) => {
    b.addEventListener("click", () => {
      seg.querySelectorAll("button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      filter = b.dataset.f;
      apply();
    });
  });

  bindAiCard(el, a);

  apply();
}

async function bindAiCard(el, a) {
  const resultsEl = el.querySelector("#ai-results");
  const statusEl = el.querySelector("#ai-status");
  if (!resultsEl) return;

  // Prellenar config (key Jev llega maskeda; se reescribe solo si el usuario la cambia).
  try {
    const cfg = await api("/api/ai/config");
    const jk = el.querySelector("#ai-jev-key");
    const lu = el.querySelector("#ai-llm-url");
    const lm = el.querySelector("#ai-llm-model");
    if (jk) jk.value = cfg.jev_api_key || "";
    if (lu) lu.value = cfg.llm_base_url || "";
    if (lm) lm.value = cfg.llm_model || "";
    const bk = el.querySelector("#ai-backend");
    const lurl = el.querySelector("#ai-laya-url");
    const lmod = el.querySelector("#ai-laya-model");
    if (bk) bk.value = cfg.backend || "cloud";
    if (lurl) lurl.value = cfg.laya_base_url || "";
    if (lmod) lmod.value = cfg.laya_model || "";
  } catch (e) { /* config no disponible */ }

  // Cargar enriquecimiento guardado, si existe.
  try {
    const data = await api("/api/ai/enrich/" + encodeURIComponent(a.id));
    resultsEl.innerHTML = aiResultsHtml(a, data);
  } catch (e) { /* sin enriquecimiento todavia */ }

  const saveJev = el.querySelector("#btn-ai-save-jev");
  if (saveJev) saveJev.addEventListener("click", async () => {
    const key = (el.querySelector("#ai-jev-key") || {}).value || "";
    try {
      await api("/api/ai/config", { method: "POST", body: JSON.stringify({ jev_enabled: true, jev_api_key: key }) });
      toast("Config Jev guardada (solo memoria).", "success");
    } catch (e) { toast(e.message, "error"); }
  });

  const saveBackend = el.querySelector("#btn-ai-save-backend");
  if (saveBackend) saveBackend.addEventListener("click", async () => {
    const backend = (el.querySelector("#ai-backend") || {}).value || "cloud";
    const url = ((el.querySelector("#ai-laya-url") || {}).value || "").trim();
    const model = ((el.querySelector("#ai-laya-model") || {}).value || "").trim();
    try {
      const body = { backend };
      if (url) body.laya_base_url = url;
      if (model) body.laya_model = model;
      await api("/api/ai/config", { method: "POST", body: JSON.stringify(body) });
      toast(`Backend guardado: ${backend} (solo memoria).`, "success");
    } catch (e) { toast(e.message, "error"); }
  });

  const saveLlm = el.querySelector("#btn-ai-save-llm");
  if (saveLlm) saveLlm.addEventListener("click", async () => {
    const url = ((el.querySelector("#ai-llm-url") || {}).value || "").trim();
    const model = ((el.querySelector("#ai-llm-model") || {}).value || "").trim();
    try {
      await api("/api/ai/config", { method: "POST", body: JSON.stringify({ llm_enabled: true, llm_base_url: url, llm_model: model }) });
      toast("Config LLM local guardada (solo memoria).", "success");
    } catch (e) { toast(e.message, "error"); }
  });

  const testJev = el.querySelector("#btn-ai-test-jev");
  if (testJev) testJev.addEventListener("click", async () => {
    try {
      const r = await api("/api/ai/test", { method: "POST", body: JSON.stringify({ target: "jev" }) });
      toast(r.ok ? `Jev OK (modelo ${r.model || "?"}).` : `Jev fallo: ${r.error || "?"}`, r.ok ? "success" : "error");
    } catch (e) { toast(e.message, "error"); }
  });

  const testLlm = el.querySelector("#btn-ai-test-llm");
  if (testLlm) testLlm.addEventListener("click", async () => {
    try {
      const r = await api("/api/ai/test", { method: "POST", body: JSON.stringify({ target: "llm" }) });
      toast(r.status === "ok" ? `LLM local OK (modelo ${r.model || "?"}).` : `LLM local fallo: ${r.reason || "?"}`, r.status === "ok" ? "success" : "error");
    } catch (e) { toast(e.message, "error"); }
  });

  const enrichBtn = el.querySelector("#btn-ai-enrich");
  if (enrichBtn) enrichBtn.addEventListener("click", async () => {
    enrichBtn.disabled = true;
    if (statusEl) statusEl.textContent = "En curso... puede tardar varios minutos (Jev + LLM local).";
    try {
      const data = await api("/api/ai/enrich", { method: "POST", body: JSON.stringify({ audit_id: a.id }) });
      resultsEl.innerHTML = aiResultsHtml(a, data);
      if (statusEl) statusEl.textContent = `Completado (${data.generated_at || ""}).`;
      toast("Informe enriquecido con IA.", "success");
    } catch (e) {
      if (statusEl) statusEl.textContent = "";
      toast(e.message, "error");
    } finally {
      enrichBtn.disabled = false;
    }
  });
}

function bindGoto(el) {
  el.querySelectorAll("[data-goto]").forEach((b) => {
    b.addEventListener("click", () => setActiveView(b.dataset.goto));
  });
}

async function cleanupAudits() {
  const ok = confirm(
    "Limpiar todas las auditorias guardadas?\n\n" +
      "Se borraran las carpetas Auditoria_* y los estados de .runs.\n" +
      "Esta accion no se puede deshacer."
  );
  if (!ok) return;
  try {
    const r = await api("/api/audits/cleanup", { method: "POST" });
    state.audits = [];
    state.selectedAuditId = null;
    state.audit = null;
    toast(
      `Limpiado: ${r.audits_removed} auditoria(s), ${r.run_files_removed} estado(s), ${r.freed_mb} MB liberados`,
      "success"
    );
    await loadAudits();
    if (state.view === "dashboard") renderDashboard();
    if (state.view === "audits") renderAudits();
  } catch (e) {
    toast("Error al limpiar auditorias: " + e.message, "error");
  }
}

async function renderAudits() {
  const el = document.getElementById("view-audits");
  if (!state.audits.length) {
    el.innerHTML = emptyState(
      "M4 5h16M4 12h16M4 19h16",
      "Sin auditorias registradas",
      "Aun no se ha ejecutado ninguna auditoria.",
      `<button class="btn btn-primary" data-goto="run">Ejecutar auditoria</button>`
    );
    bindGoto(el);
    return;
  }

  const rows = state.audits
    .map(
      (a) => `<tr style="cursor:pointer" data-open="${esc(a.id)}">
        <td class="mono">${esc(folderToDate(a.folder))}</td>
        <td>${esc(a.summary.sistema || "—")}</td>
        <td>${esc(a.summary.usuario || "—")}</td>
        <td>${riskBadge(a.risk_level)}</td>
        <td class="num">${a.threats_count}</td>
        <td class="num">${esc(a.summary.errores ?? "—")}</td>
        <td class="text-muted" style="font-size:12px">${esc(a.summary.duracion || "—")}</td>
      </tr>`
    )
    .join("");

  el.innerHTML = `<div class="card">
    <div class="card-head">
      <span class="card-title">Historial de Auditorias</span>
      <span class="card-sub">${state.audits.length} auditoria${state.audits.length === 1 ? "" : "s"}</span>
      <button class="btn btn-ghost" id="btn-cleanup-hist">Limpiar auditorias</button>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th>Fecha</th><th>Sistema</th><th>Usuario</th><th>Riesgo</th><th>Amenazas</th><th>Errores</th><th>Duracion</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>`;

  const cleanupBtn = el.querySelector("#btn-cleanup-hist");
  if (cleanupBtn) cleanupBtn.addEventListener("click", cleanupAudits);

  el.querySelectorAll("[data-open]").forEach((tr) => {
    tr.addEventListener("click", () => {
      setActiveView("dashboard", tr.dataset.open);
    });
  });
}

async function renderModule(auditId, moduleName) {
  const el = document.getElementById("view-dashboard");
  try {
    const m = await api(`/api/audits/${encodeURIComponent(auditId)}/modules/${encodeURIComponent(moduleName)}`);
    const datasets = m.datasets
      .map(
        (d) => `<div class="card">
          <div class="card-head">
            <span class="card-title">${esc(d.title)}</span>
            <span class="card-sub">${d.is_list ? `${d.data.length} registros` : "Objeto"}</span>
          </div>
          ${renderTable(d.data)}
        </div>`
      )
      .join("");

    el.innerHTML = `
      <button class="back-link" id="module-back">
        <svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>
        Volver al panel
      </button>
      <div class="card summary-hero">
        <div class="hero-meta">
          <div class="hero-audit">${esc(m.title)}</div>
          <div class="hero-sub">${esc(m.name)} · ${m.datasets.length} dataset${m.datasets.length === 1 ? "" : "s"}</div>
        </div>
      </div>
      ${datasets}
    `;
    el.querySelector("#module-back").addEventListener("click", () => renderDashboard());
  } catch (e) {
    el.innerHTML = `<div class="card"><div class="text-muted">Error: ${esc(e.message)}</div></div>`;
  }
}

// ---------------------------------------------------------------------------
// Ejecucion de auditoria
// ---------------------------------------------------------------------------

function renderRun() {
  const el = document.getElementById("view-run");
  if (state.running) {
    renderRunProgress(el);
    return;
  }

  el.innerHTML = `<div class="card run-controls">
    <svg viewBox="0 0 24 24" style="width:44px;height:44px;fill:none;stroke:var(--accent);stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round"><path d="M12 2l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V5l7-3z"/></svg>
    <div style="font-size:19px;font-weight:600">Ejecutar Auditoria de Seguridad</div>
    <p class="hint">
      La auditoria recopila informacion del sistema, analiza la red, procesos, eventos de seguridad,
      persistencia y detecta indicadores de compromiso. Los resultados se guardan en
      <span class="mono" id="run-dir"></span>.
    </p>
    <p class="hint" style="color:var(--medium)">
      Advertencia: se recomienda ejecutar como administrador para una cobertura completa.
      La auditoria puede tardar varios minutos.
    </p>
    <div class="run-buttons">
      <button class="btn btn-primary" id="btn-run">
        <svg viewBox="0 0 24 24"><path d="M7 4l14 8-14 8z"/></svg>
        Ejecutar auditoria
      </button>
      <button class="btn" id="btn-run-elevated">
        Ejecutar como administrador
      </button>
    </div>
  </div>`;

  el.querySelector("#btn-run").addEventListener("click", () => startRun(false));
  el.querySelector("#btn-run-elevated").addEventListener("click", () => startRun(true));

  api("/api/config")
    .then((c) => (el.querySelector("#run-dir").textContent = c.results_dir))
    .catch(() => {});
}

async function startRun(elevated) {
  state.running = true;
  state.runStatus = { phase: "starting", percent: 0, module: 0, total: 10, threats: 0 };
  renderRun();
  try {
    const r = await api("/api/audits/run", {
      method: "POST",
      body: JSON.stringify({ elevated }),
    });
    state.runId = r.run_id;
    streamRun(r.run_id);
  } catch (e) {
    state.running = false;
    toast("Error al iniciar la auditoria: " + e.message, "error");
    renderRun();
  }
}

function renderRunProgress(el) {
  const st = state.runStatus;
  const pct = st.percent || 0;
  const r = 62;
  const c = 2 * Math.PI * r;
  const dash = (pct / 100) * c;

  const modules = MODULES.map((m, i) => {
    const idx = i + 1;
    let cls = "";
    let mark = "";
    if (idx < st.module || (st.phase === "done" && idx <= st.total)) {
      cls = "done";
      mark = '<svg viewBox="0 0 24 24"><path d="M4 12l5 5L20 7"/></svg>';
    } else if (idx === st.module && st.phase === "running") {
      cls = "active";
    }
    return `<div class="module-row">
      <div class="module-status ${cls}">${mark}</div>
      <div class="module-name"><span class="idx">${String(idx).padStart(2, "0")}</span>${esc(m.title)}</div>
    </div>`;
  }).join("");

  const phaseLabel =
    st.phase === "done" ? "Completada" : st.phase === "error" ? "Error" : st.name || "Inicializando";

  let controls = "";
  if (st.phase === "done" || st.phase === "error") {
    controls = `<div class="run-buttons" style="margin-top:18px">
      <button class="btn btn-primary" id="btn-view-results">Ver resultados</button>
      <button class="btn" id="btn-run-again">Ejecutar otra</button>
    </div>`;
  } else {
    controls = `<div class="run-buttons" style="margin-top:18px">
      <button class="btn" id="btn-cancel">Cancelar</button>
    </div>`;
  }

  el.innerHTML = `<div class="card">
    <div class="progress-hero">
      <div class="progress-ring">
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--border)" stroke-width="12"/>
          <circle cx="70" cy="70" r="${r}" fill="none" stroke="${st.phase === "error" ? "var(--danger)" : "var(--accent)"}" stroke-width="12"
            stroke-linecap="round" stroke-dasharray="${dash} ${c - dash}" stroke-dashoffset="${0}"/>
        </svg>
        <div class="pct">${pct}%</div>
      </div>
      <div style="font-size:17px;font-weight:600">${esc(phaseLabel)}</div>
      <div class="text-muted" style="margin-top:4px">
        Modulo ${Math.max(0, st.module || 0)} de ${st.total || 10} · Amenazas detectadas: ${st.threats || 0}
      </div>
      ${st.message ? `<div class="text-muted mono" style="margin-top:8px;font-size:12px">${esc(st.message)}</div>` : ""}
      ${controls}
    </div>
    <div class="module-list">${modules}</div>
  </div>`;

  const bind = (id, fn) => {
    const b = el.querySelector(id);
    if (b) b.addEventListener("click", fn);
  };
  bind("#btn-cancel", () => {
    api(`/api/runs/${state.runId}/cancel`, { method: "POST" }).catch(() => {});
    stopPolling();
    state.running = false;
    toast("Auditoria cancelada");
    renderRun();
  });
  bind("#btn-view-results", () => {
    stopPolling();
    state.running = false;
    loadAudits().then(() => {
      state.selectedAuditId = state.audits[0]?.id || null;
      setActiveView("dashboard");
    });
  });
  bind("#btn-run-again", () => {
    stopPolling();
    state.running = false;
    renderRun();
  });
}

function handleRunUpdate(r) {
  state.runStatus = r.status;
  const el = document.getElementById("view-run");
  if (state.running) renderRunProgress(el);
  if (!r.finished) return false;
  state.running = false;
  const st = r.status;
  if (st.phase === "done") {
    toast("Auditoria completada", "success");
  } else if (st.phase === "error") {
    toast("La auditoria termino con errores", "error");
  }
  // Refrescar la lista para que Panel General e Historial muestren la
  // auditoria terminada sin necesidad de recargar la pagina.
  loadAudits().then(() => {
    if (st.phase === "done" && st.auditPath) {
      const folder = String(st.auditPath).split(/[\\/]/).pop();
      if (state.audits.some((a) => a.id === folder)) {
        state.selectedAuditId = folder;
      }
    }
    renderRun();
  });
  return true;
}

function pollRun(runId) {
  stopPolling();
  state.pollTimer = setInterval(async () => {
    try {
      const r = await api("/api/runs/" + runId);
      if (handleRunUpdate(r)) stopPolling();
    } catch (_) {}
  }, 700);
}

function streamRun(runId) {
  stopPolling();
  if (typeof EventSource !== "function") {
    pollRun(runId);
    return;
  }
  const source = new EventSource("/api/runs/" + encodeURIComponent(runId) + "/stream");
  state.source = source;
  source.onmessage = (event) => {
    try {
      const r = JSON.parse(event.data);
      if (handleRunUpdate(r)) source.close();
    } catch (_) {}
  };
  source.addEventListener("end", () => source.close());
  source.addEventListener("timeout", () => {
    source.close();
    state.source = null;
    pollRun(runId);
  });
  source.onerror = () => {
    // Si el SSE falla (proxy, navegador antiguo), volver al polling.
    source.close();
    state.source = null;
    pollRun(runId);
  };
}

function stopPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  if (state.source) {
    state.source.close();
    state.source = null;
  }
}

// ---------------------------------------------------------------------------
// Inicio
// ---------------------------------------------------------------------------

async function loadAudits() {
  try {
    const data = await api("/api/audits");
    state.audits = data.audits || [];
  } catch (e) {
    toast("Error al cargar auditorias: " + e.message, "error");
  }
}

function bindNav() {
  document.querySelectorAll(".nav-item").forEach((b) => {
    b.addEventListener("click", () => {
      if (state.running) {
        toast("Hay una auditoria en curso. Cancele o espere a que termine.");
        return;
      }
      setActiveView(b.dataset.view);
    });
  });
  // Navegar con el hash (pegar una URL, atras, editar la dirección).
  window.addEventListener("hashchange", () => {
    const { view, auditId } = parseHash();
    if (view !== state.view || (auditId && auditId !== state.selectedAuditId)) {
      setActiveView(view, auditId);
    }
  });
  document.getElementById("btn-refresh").addEventListener("click", async () => {
    await loadAudits();
    if (state.view === "dashboard") renderDashboard();
    if (state.view === "audits") renderAudits();
    toast("Datos actualizados", "success");
  });
}

async function init() {
  bindNav();
  if (!(await checkAuth())) return;   // sin sesion no tiene sentido cargar nada
  api("/api/config")
    .then((c) => (document.getElementById("sidebar-version").textContent = "v" + c.version))
    .catch(() => {});
  await loadAudits();
  const { view, auditId } = parseHash();
  if (auditId && state.audits.some((a) => a.id === auditId)) {
    state.selectedAuditId = auditId;
  }
  setActiveView(view);
}

document.addEventListener("DOMContentLoaded", init);
