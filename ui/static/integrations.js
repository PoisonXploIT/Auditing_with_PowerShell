// ---------------------------------------------------------------------------
// Integraciones: Splunk HEC, IOCs y capa MITRE Navigator
// ---------------------------------------------------------------------------

async function renderIntegrations() {
  const el = document.getElementById("view-integrations");
  try {
    const status = await api("/api/integrations");
    const soc = status.opervanta_soc || {};
    const auditId = state.selectedAuditId || (state.audits[0] && state.audits[0].id);

    const statusRow = (name, s) =>
      "<tr><td>" + esc(name) + "</td>" +
      '<td class="mono">' + (s.configured ? "configurada" : "no configurada") + "</td>" +
      '<td class="mono">' + esc(s.url || s.token || s.key || "-") + "</td></tr>";

    let iocBlock = '<div class="text-muted">Selecciona una auditoria para extraer sus indicadores.</div>';
    let navBlock = "";
    let integrityBlock = "";
    let exportBlock = "";

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

      const verify = await api("/api/audits/" + encodeURIComponent(auditId) + "/verify", { method: "POST" });
      integrityBlock =
        '<div class="flex" style="gap:8px;flex-wrap:wrap">' +
        '<span class="badge ' + (verify.ok ? "low" : "critical") + '">' + esc(verify.status) + "</span>" +
        '<span class="mono text-muted">' + (verify.file_count || 0) + " ficheros</span>" +
        '<span class="mono text-muted">root SHA-256 ' + esc((verify.root_sha256 || "-").slice(0, 16)) + "</span>" +
        "</div>" +
        (verify.mismatches && verify.mismatches.length
          ? '<div class="table-wrap" style="margin-top:10px"><table><thead><tr><th>Fichero</th><th>Problema</th></tr></thead><tbody>' +
            verify.mismatches.map((m) => '<tr><td class="mono">' + esc(m.path) + "</td><td>" + esc(m.problem) + "</td></tr>").join("") +
            "</tbody></table></div>"
          : "");

      const exports = await api("/api/exports");
      const exportRows = (exports.exports || [])
        .map((e) =>
          "<tr><td class=\"mono\">" + esc(e.file) + "</td><td class=\"num\">" + e.bytes + "</td>" +
          '<td class="mono">' + esc((e.sha256 || "-").slice(0, 16)) + "</td>" +
          '<td class="badge ' + (e.signed ? "low" : "medium") + '">' + (e.signed ? "firmado" : "sin firma") + "</td>" +
          '<td class="mono">' + esc(e.status) + "</td></tr>"
        )
        .join("");
      exportBlock =
        '<div class="table-wrap"><table><thead><tr><th>Fichero</th><th>Bytes</th><th>SHA-256</th><th>Firma</th><th>Verificacion</th></tr></thead><tbody>' +
        (exportRows || '<tr><td colspan="5" class="text-muted">Aun no se ha descargado ningun export.</td></tr>') +
        "</tbody></table></div>";
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
      '<div class="card-head"><span class="card-title">Opervanta SOC</span>' +
      '<span class="card-sub">Publica los hallazgos en el SOC de Opervanta por el ingress firmado</span></div>' +
      '<div class="flex" style="gap:8px;align-items:center;flex-wrap:wrap">' +
      '<span class="badge ' + (soc.enabled ? "low" : "medium") + '">' + (soc.enabled ? "activado" : "apagado") + "</span>" +
      '<span class="mono text-muted">' + esc(soc.url || "-") + "</span>" +
      '<span class="text-muted">sensor ' + esc(soc.sensor || "-") + "</span>" +
      '<span class="text-muted">' + (soc.secret_defined ? "secreto definido" : "sin secreto") + "</span>" +
      '<span class="text-muted">' + (soc.strict_mode ? "estricto" : "laxo") + "</span>" +
      "</div>" +
      (soc.enabled
        ? '<button class="btn btn-primary" style="margin-top:10px" data-soc>Publicar hallazgos en el SOC</button>' +
          '<span class="text-muted" id="soc-result"></span>'
        : '<div class="text-muted" style="margin-top:6px">Activa PILOOP_SOC_ENABLED=1 y define el secreto para publicar.</div>') +
      "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Indicadores (IOCs) de ' + esc(auditId || "—") + "</span>" +
      '<span class="card-sub">IP, puertos, procesos y rutas derivados de los hallazgos</span></div>' +
      iocBlock + "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Integridad de la evidencia</span>' +
      '<span class="card-sub">SHA-256 de cada fichero declarado en MANIFEST_EVIDENCIA.json</span></div>' +
      (integrityBlock || '<div class="text-muted">Sin auditoria seleccionada.</div>') + "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Exports firmados</span>' +
      '<span class="card-sub">Cada descarga se guarda en .exports/ con su sidecar .sig</span></div>' +
      exportBlock + "</div>" +
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

    const socBtn = el.querySelector("[data-soc]");
    if (socBtn) {
      socBtn.addEventListener("click", async () => {
        const out = el.querySelector("#soc-result");
        out.textContent = "Publicando...";
        try {
          const r = await api("/api/audits/" + encodeURIComponent(auditId) + "/soc", { method: "POST" });
          out.textContent = r.ok
            ? "Publicado (" + (r.sent || 0) + " eventos" + (r.pending ? ", " + r.pending + " pendientes" : "") + ")"
            : "No publicado: " + (r.reason || r.motivo || "?");
        } catch (e) {
          out.textContent = "Error: " + e.message;
        }
      });
    }
  } catch (e) {
    el.innerHTML = '<div class="card"><div class="text-muted">Error al cargar integraciones: ' + esc(e.message) + "</div></div>";
  }
}
