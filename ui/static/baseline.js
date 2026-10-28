// ---------------------------------------------------------------------------
// Baseline (SQLite): historial acumulado de hallazgos y triage
// ---------------------------------------------------------------------------

const STATUS_LABELS = {
  open: "Abierto",
  investigating: "En investigacion",
  accepted: "Aceptado (riesgo conocido)",
  false_positive: "Falso positivo",
  resolved: "Resuelto",
};

async function renderBaseline() {
  const el = document.getElementById("view-baseline");
  try {
    const base = await api("/api/baseline");
    const threats = await api("/api/threats?limit=300");
    const allow = await api("/api/allowlist");

    const kpis = [
      { cls: "neutral", label: "Auditorias indexadas", value: base.audits },
      { cls: "neutral", label: "Hallazgos distintos", value: base.distinct_threats },
      { cls: "high", label: "Recurrentes (>=2)", value: base.recurring },
      { cls: "critical", label: "Abiertos", value: base.open },
      { cls: "low", label: "Resueltos", value: base.resolved },
      { cls: "neutral", label: "Falsos positivos", value: base.false_positive },
    ]
      .map(
        (k) =>
          '<div class="kpi ' + k.cls + '"><div class="kpi-value">' + esc(k.value) +
          '</div><div class="kpi-label">' + esc(k.label) + "</div></div>"
      )
      .join("");

    const rows = (threats.threats || [])
      .map((t) => {
        const sev = (t.severity || "LOW").toUpperCase();
        const mitre = t.mitre_technique
          ? '<a href="' + esc(t.mitre_url) + '" target="_blank" rel="noopener noreferrer">' + esc(t.mitre_technique) + "</a>"
          : "—";
        const opts = Object.keys(STATUS_LABELS)
          .map(
            (s) =>
              '<option value="' + s + '"' + (t.status === s ? " selected" : "") +
              ">" + esc(STATUS_LABELS[s]) + "</option>"
          )
          .join("");
        return (
          "<tr>" +
          '<td><strong>' + esc(t.type) + "</strong>" +
          '<div class="text-muted" style="font-size:12px">' + esc(t.description || "") + "</div></td>" +
          '<td class="mono" style="color:' + (SEV_COLORS[sev] || "var(--text)") + '">' + esc(sev) + "</td>" +
          '<td class="num">' + t.occurrences + "</td>" +
          '<td class="mono">' + esc(t.first_seen || "—") + "</td>" +
          '<td class="mono">' + esc(t.last_seen || "—") + "</td>" +
          '<td class="mono">' + mitre + "</td>" +
          '<td><select class="select mono" data-sig="' + esc(t.signature) + '" data-note="' + esc(t.note || "") + '">' + opts + "</select></td>" +
          "</tr>"
        );
      })
      .join("");

    const series = (base.series || [])
      .map(
        (s) =>
          "<tr><td class=\"mono\">" + esc(s.id) + "</td><td class=\"mono\">" + esc(s.started_at || "—") +
          "</td><td class=\"mono\">" + esc(s.duration || "—") + "</td><td class=\"num\">" + s.threats +
          "</td><td class=\"num\">" + s.suppressed + "</td><td>" + riskBadge(s.risk) + "</td></tr>"
      )
      .join("");

    const allowRows = (allow.entries || [])
      .map((e) => {
        const ports = (e.ports || []).join(", ") || "-";
        return (
          "<tr>" +
          '<td class="mono">' + esc(e.id) + "</td>" +
          "<td>" + esc(e.threat_type || "-") + "</td>" +
          '<td class="mono">' + esc(e.process || "-") + "</td>" +
          '<td class="mono">' + ports + "</td>" +
          '<td class="text-muted" style="font-size:12px">' + esc(e.reason || "") + "</td>" +
          '<td class="mono">' + esc(e.source || "") + "</td>" +
          '<td><button class="btn btn-ghost" data-del="' + esc(e.id) + '">Borrar</button></td>' +
          "</tr>"
        );
      })
      .join("");

    el.innerHTML =
      '<div class="card">' +
      '<div class="card-head"><span class="card-title">Baseline acumulada</span>' +
      '<span class="card-sub">Historial en SQLite: cuando aparecio cada hallazgo, cuantas veces se repite y su estado</span></div>' +
      '<div class="kpi-grid" style="margin-top:14px">' + kpis + "</div>" +
      '<div class="flex" style="gap:8px;margin-top:14px">' +
      '<button class="btn btn-ghost" id="btn-reingest">Reconstruir baseline desde las carpetas</button>' +
      '<span class="text-muted" id="baseline-status"></span></div>' +
      "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Hallazgos</span>' +
      '<span class="card-sub">Cada fila es una firma unica; cambiar el estado alimenta el triage</span></div>' +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Hallazgo</th><th>Severidad</th><th>Ocurrencias</th><th>Primera vez</th><th>Ultima vez</th><th>MITRE</th><th>Estado</th></tr></thead>" +
      "<tbody>" + (rows || '<tr><td colspan="7" class="text-muted">Sin hallazgos indexados. Ejecute una auditoria.</td></tr>') + "</tbody>" +
      "</table></div></div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Allowlist derivada del triage</span>' +
      '<span class="card-sub">Un hallazgo marcado como falso positivo se convierte en regla para la siguiente auditoria</span></div>' +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Id</th><th>Amenaza</th><th>Proceso</th><th>Puertos</th><th>Motivo</th><th>Origen</th><th></th></tr></thead>" +
      "<tbody>" + (allowRows || '<tr><td colspan="7" class="text-muted">Sin entradas derivadas del triage. La allowlist built-in vive en el script PowerShell.</td></tr>') + "</tbody>" +
      "</table></div></div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Serie de ejecuciones</span></div>' +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Auditoria</th><th>Inicio</th><th>Duracion</th><th>Amenazas</th><th>Suprimidas</th><th>Riesgo</th></tr></thead>" +
      "<tbody>" + series + "</tbody></table></div></div>";

    el.querySelectorAll("select[data-sig]").forEach((sel) => {
      sel.addEventListener("change", async () => {
        try {
          await api("/api/threats/" + encodeURIComponent(sel.dataset.sig) + "/status", {
            method: "PATCH",
            body: JSON.stringify({ status: sel.value, note: sel.dataset.note || "" }),
          });
          toast("Hallazgo marcado como " + STATUS_LABELS[sel.value], "success");
        } catch (e) {
          toast("No se pudo actualizar el estado: " + e.message, "error");
        }
      });
    });

    el.querySelectorAll("button[data-del]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          await api("/api/allowlist/" + encodeURIComponent(btn.dataset.del), { method: "DELETE" });
          toast("Entrada de allowlist eliminada", "success");
          renderBaseline();
        } catch (e) {
          toast("No se pudo eliminar: " + e.message, "error");
        }
      });
    });

    const reingest = el.querySelector("#btn-reingest");
    if (reingest) {
      reingest.addEventListener("click", async () => {
        const statusEl = el.querySelector("#baseline-status");
        statusEl.textContent = "Reconstruyendo...";
        try {
          const r = await api("/api/baseline/reingest", { method: "POST" });
          statusEl.textContent = r.audits_ingested + " auditorias, " + r.distinct_threats + " hallazgos";
          renderBaseline();
        } catch (e) {
          statusEl.textContent = "Error: " + e.message;
        }
      });
    }
  } catch (e) {
    el.innerHTML = '<div class="card"><div class="text-muted">Error al cargar la baseline: ' + esc(e.message) + "</div></div>";
  }
}
