// ---------------------------------------------------------------------------
// Opervanta: actividad recibida por el ingress de la direccion B (firma v2).
// ---------------------------------------------------------------------------

async function renderOpervanta() {
  const el = document.getElementById("view-opervanta");
  try {
    const r = await api("/opervanta/eventos");
    const eventos = (r && r.eventos) || [];
    const orden = eventos.slice().reverse();
    const filas = orden
      .map((e) => {
        const sev = e.sev || "info";
        const badge = sev === "alta" || sev === "critica" ? "critical" : sev === "media" ? "medium" : "low";
        const ts = e.ts
          ? (typeof e.ts === "number" ? new Date(e.ts * 1000).toLocaleString() : esc(String(e.ts)))
          : "-";
        return (
          '<tr><td class="mono">' + esc(e.tipo || "-") + "</td>" +
          '<td class="badge ' + badge + '">' + esc(sev) + "</td>" +
          "<td>" + esc(e.mensaje || "-") + "</td>" +
          '<td class="mono text-muted">' + ts + "</td></tr>"
        );
      })
      .join("");

    el.innerHTML =
      '<div class="card">' +
      '<div class="card-head"><span class="card-title">Actividad de Opervanta</span>' +
      '<span class="card-sub">Eventos que Opervanta publica en este ingress (firma v2): auth, denegaciones y alertas</span></div>' +
      '<div class="flex" style="gap:8px;align-items:center">' +
      '<span class="badge ' + (eventos.length ? "low" : "medium") + '">' +
      (eventos.length ? eventos.length + " eventos" : "sin eventos") + "</span>" +
      '<span class="text-muted">' + (eventos.length ? "Receptor recibiendo." : "A la espera de eventos.") + "</span>" +
      "</div>" +
      (filas
        ? '<div class="table-wrap" style="margin-top:10px"><table><thead><tr>' +
          "<th>Tipo</th><th>Severidad</th><th>Mensaje</th><th>Fecha</th></tr></thead><tbody>" +
          filas + "</tbody></table></div>"
        : '<div class="text-muted" style="margin-top:10px">Todavia no ha llegado ningun evento. Activa la direccion B en Opervanta (PILOOP_AUDITING_URL + PILOOP_AUDITING_SECRET).</div>') +
      "</div>";
  } catch (e) {
    el.innerHTML = '<div class="card"><div class="text-muted">Error al cargar la actividad: ' + esc(e.message) + "</div></div>";
  }
}
