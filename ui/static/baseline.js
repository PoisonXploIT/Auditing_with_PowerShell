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
    const sla = await api("/api/sla");

    const kpis = [
      { cls: "neutral", label: "Auditorias indexadas", value: base.audits },
      { cls: "neutral", label: "Hallazgos distintos", value: base.distinct_threats },
      { cls: "high", label: "Recurrentes (>=2)", value: base.recurring },
      { cls: "critical", label: "Abiertos", value: base.open },
      { cls: "low", label: "Resueltos", value: base.resolved },
      { cls: "neutral", label: "Falsos positivos", value: base.false_positive },
      { cls: "critical", label: "SLA vencido", value: base.overdue },
    ]
      .map(
        (k) =>
          '<div class="kpi ' + k.cls + '"><div class="kpi-value">' + esc(k.value) +
          '</div><div class="kpi-label">' + esc(k.label) + "</div></div>"
      )
      .join("");

    const allThreats = threats.threats || [];
    const PAGE_SIZE = 25;
    state.threatPage = state.threatPage || 1;

    const threatRow = (t) => {
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
        const due = t.due_at
          ? (t.overdue
              ? '<span class="badge-overdue">Vencido ' + Math.abs(t.days_left) + " d</span>"
              : esc(t.due_at) + " (" + t.days_left + " d)")
          : "—";
        return (
          "<tr>" +
          '<td><strong>' + esc(t.type) + "</strong>" +
          '<div class="text-muted" style="font-size:12px">' + esc(t.description || "") + "</div></td>" +
          '<td class="mono" style="color:' + (SEV_COLORS[sev] || "var(--text)") + '">' + esc(sev) + "</td>" +
          '<td class="num">' + t.occurrences + "</td>" +
          '<td class="mono">' + esc(t.first_seen || "—") + "</td>" +
          '<td class="mono">' + esc(t.last_seen || "—") + "</td>" +
          '<td class="mono">' + due + "</td>" +
          '<td class="mono">' + mitre + "</td>" +
          '<td><select class="select mono" data-sig="' + esc(t.signature) + '" data-note="' + esc(t.note || "") + '">' + opts + "</select></td>" +
          "</tr>"
        );
      };

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

    const slaRows = Object.entries(sla.by_severity || {})
      .map(([sev, b]) => {
        const pct = b.open ? Math.round((b.overdue / b.open) * 100) : 0;
        return (
          "<tr>" +
          '<td class="mono" style="color:' + (SEV_COLORS[sev] || "var(--text)") + '">' + esc(sev) + "</td>" +
          '<td class="num">' + b.sla_days + "</td>" +
          '<td class="num">' + b.open + "</td>" +
          '<td class="num">' + b.overdue + "</td>" +
          '<td class="num">' + pct + "%</td>" +
          '<td class="mono">' + esc(b.oldest || "—") + "</td>" +
          "</tr>"
        );
      })
      .join("");

    const overdueRows = (sla.overdue_list || [])
      .map(
        (o) =>
          "<tr>" +
          "<td>" + esc(o.type) + "</td>" +
          '<td class="mono">' + esc(o.severity) + "</td>" +
          '<td class="mono">' + esc(o.due_at) + "</td>" +
          '<td class="num badge-overdue">' + o.days_overdue + " d</td>" +
          '<td class="num">' + o.occurrences + "</td>" +
          "</tr>"
      )
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
      "<thead><tr><th>Hallazgo</th><th>Severidad</th><th>Ocurrencias</th><th>Primera vez</th><th>Ultima vez</th><th>Vencimiento</th><th>MITRE</th><th>Estado</th></tr></thead>" +
      '<tbody id="threat-body"></tbody>' +
      "</table></div>" +
      '<div class="pagination" id="threat-pagination"></div>' +
      "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">SLA por severidad</span>' +
      '<span class="card-sub">Plazo desde la primera aparicion hasta que alguien lo tria</span></div>' +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Severidad</th><th>SLA (dias)</th><th>Abiertos</th><th>Vencidos</th><th>% vencido</th><th>Mas antiguo</th></tr></thead>" +
      "<tbody>" + (slaRows || '<tr><td colspan="6" class="text-muted">Sin hallazgos abiertos.</td></tr>') + "</tbody>" +
      "</table></div>" +
      (overdueRows
        ? '<div class="table-wrap" style="margin-top:12px"><table>' +
          "<thead><tr><th>Hallazgo vencido</th><th>Severidad</th><th>Vencia</th><th>Dias</th><th>Ocurrencias</th></tr></thead>" +
          "<tbody>" + overdueRows + "</tbody></table></div>"
        : '<div class="text-muted">Ningun hallazgo abierto ha superado su plazo.</div>') +
      '<div class="flex" style="gap:8px;margin-top:12px">' +
      '<button class="btn btn-ghost" id="btn-sla-alert">Notificar vencidos a Splunk</button>' +
      '<span class="text-muted" id="sla-alert-result"></span>' +
      "</div>" +
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

    // Paginacion real: 300 hallazgos en una sola tabla son ilegibles en movil y
    // dificiles de triar. Se corta por paginas y se re-renderiza el tbody.
    const body = el.querySelector("#threat-body");
    const pager = el.querySelector("#threat-pagination");
    const totalPages = Math.max(1, Math.ceil(allThreats.length / PAGE_SIZE));
    state.threatPage = Math.min(Math.max(1, state.threatPage), totalPages);

    function renderThreatPage(page) {
      state.threatPage = page;
      const slice = allThreats.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
      body.innerHTML = slice.length
        ? slice.map(threatRow).join("")
        : '<tr><td colspan="8" class="text-muted">Sin hallazgos en esta pagina.</td></tr>';
      pager.innerHTML =
        '<button data-page="prev" ' + (page === 1 ? "disabled" : "") + ' aria-label="Pagina anterior">Anterior</button>' +
        '<span class="page-info">Pagina ' + page + " de " + totalPages + " · " + allThreats.length + " hallazgos</span>" +
        '<button data-page="next" ' + (page === totalPages ? "disabled" : "") + ' aria-label="Pagina siguiente">Siguiente</button>';
      body.querySelectorAll("select[data-sig]").forEach((sel) => {
        sel.addEventListener("change", async () => {
          try {
            await api("/api/threats/" + encodeURIComponent(sel.dataset.sig) + "/status", {
              method: "PATCH",
              body: JSON.stringify({ status: sel.value, note: sel.dataset.note || "" }),
            });
            toast("Estado actualizado", "success");
            renderBaseline();
          } catch (e) {
            toast("No se pudo cambiar el estado: " + e.message, "error");
          }
        });
      });
    }
    renderThreatPage(state.threatPage);
    pager.addEventListener("click", (e) => {
      const dir = e.target.dataset.page;
      if (!dir || e.target.disabled) return;
      renderThreatPage(dir === "prev" ? state.threatPage - 1 : state.threatPage + 1);
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

    const slaAlert = el.querySelector("#btn-sla-alert");
    if (slaAlert) {
      slaAlert.addEventListener("click", async () => {
        const out = el.querySelector("#sla-alert-result");
        out.textContent = "Notificando...";
        try {
          const r = await api("/api/sla/alert", { method: "POST" });
          out.textContent = r.ok
            ? r.overdue + " hallazgos vencidos enviados a Splunk"
            : "No enviado: " + r.reason;
        } catch (e) {
          out.textContent = "Error: " + e.message;
        }
      });
    }
  } catch (e) {
    el.innerHTML = '<div class="card"><div class="text-muted">Error al cargar la baseline: ' + esc(e.message) + "</div></div>";
  }
}
