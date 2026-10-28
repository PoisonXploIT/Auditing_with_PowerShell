// ---------------------------------------------------------------------------
// Integraciones: Splunk HEC, IOCs y capa MITRE Navigator
// ---------------------------------------------------------------------------

async function renderIntegrations() {
  const el = document.getElementById("view-integrations");
  try {
    const status = await api("/api/integrations");
    const auditId = state.selectedAuditId || (state.audits[0] && state.audits[0].id);

    const statusRow = (name, s) =>
      "<tr><td>" + esc(name) + "</td>" +
      '<td class="mono">' + (s.configured ? "configurada" : "no configurada") + "</td>" +
      '<td class="mono">' + esc(s.url || s.token || s.key || "-") + "</td></tr>";

    let iocBlock = '<div class="text-muted">Selecciona una auditoria para extraer sus indicadores.</div>';
    let navBlock = "";

    if (auditId) {
      const iocs = await api("/api/audits/" + encodeURIComponent(auditId) + "/iocs");
      const rows = (iocs.iocs || [])
        .map((i) =>
          "<tr><td class=\"mono\">" + esc(i.type) + "</td><td class=\"mono\">" + esc(i.value) +
          "</td><td class=\"mono\">" + esc(i.severity) + "</td><td>" + esc(i.threat_type) +
          "</td><td class=\"mono\">" + esc(i.mitre_technique || "-") + "</td></tr>"
        )
        .join("");

      iocBlock =
        '<div class="table-wrap"><table>' +
        "<thead><tr><th>Tipo</th><th>Valor</th><th>Severidad</th><th>Hallazgo</th><th>MITRE</th></tr></thead>" +
        "<tbody>" + (rows || '<tr><td colspan="5" class="text-muted">Sin indicadores en esta auditoria.</td></tr>') + "</tbody>" +
        "</table></div>" +
        '<div class="flex" style="gap:8px;margin-top:10px">' +
        '<button class="btn btn-ghost" data-enrich>Enriquecer con VirusTotal</button>' +
        '<span class="text-muted">' + (status.virustotal.configured ? "VIRUSTOTAL_API_KEY definida" : "VIRUSTOTAL_API_KEY no definida: el boton no hara llamadas") + "</span>" +
        "</div>";

      navBlock =
        '<div class="flex" style="gap:8px">' +
        '<a class="btn btn-ghost" href="/api/audits/' + encodeURIComponent(auditId) + '/navigator">Descargar capa MITRE Navigator</a>' +
        '<button class="btn btn-primary" data-splunk>Enviar a Splunk (HEC)</button>' +
        '<span class="text-muted" id="splunk-result"></span>' +
        "</div>";
    }

    el.innerHTML =
      '<div class="card">' +
      '<div class="card-head"><span class="card-title">Estado de las integraciones</span>' +
      '<span class="card-sub">Las credenciales se leen del entorno; aqui no se muestran valores</span></div>' +
      '<div class="table-wrap"><table><thead><tr><th>Integracion</th><th>Estado</th><th>Referencia</th></tr></thead><tbody>' +
      statusRow("Splunk HEC", status.splunk) +
      statusRow("VirusTotal", status.virustotal) +
      statusRow("MITRE Navigator", status.navigator) +
      "</tbody></table></div></div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Indicadores (IOCs) de ' + esc(auditId || "—") + "</span>" +
      '<span class="card-sub">IP, puertos, procesos y rutas derivados de los hallazgos</span></div>' +
      iocBlock + "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Salidas</span>' +
      '<span class="card-sub">Capa del Navigator para abrirla en attack.mitre.org y envio al collector</span></div>' +
      navBlock + "</div>";

    const enrichBtn = el.querySelector("[data-enrich]");
    if (enrichBtn) {
      enrichBtn.addEventListener("click", async () => {
        try {
          const r = await api("/api/audits/" + encodeURIComponent(auditId) + "/iocs?enrich=true");
          const notes = (r.iocs || []).filter((i) => i.enrichment_note).map((i) => i.enrichment_note);
          toast("Enriquecimiento: " + r.count + " IOCs" + (notes.length ? " (" + notes[0] + ")" : ""), "success");
        } catch (e) {
          toast("Enriquecimiento fallido: " + e.message, "error");
        }
      });
    }

    const splunkBtn = el.querySelector("[data-splunk]");
    if (splunkBtn) {
      splunkBtn.addEventListener("click", async () => {
        const out = el.querySelector("#splunk-result");
        out.textContent = "Enviando...";
        try {
          const r = await api("/api/audits/" + encodeURIComponent(auditId) + "/splunk", { method: "POST" });
          out.textContent = r.ok ? "Enviado a Splunk (HTTP " + r.status + ")" : "No enviado: " + r.reason;
        } catch (e) {
          out.textContent = "Error: " + e.message;
        }
      });
    }
  } catch (e) {
    el.innerHTML = '<div class="card"><div class="text-muted">Error al cargar integraciones: ' + esc(e.message) + "</div></div>";
  }
}
