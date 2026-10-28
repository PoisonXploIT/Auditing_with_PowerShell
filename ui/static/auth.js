// ---------------------------------------------------------------------------
// Autenticacion y panel de administrador
// ---------------------------------------------------------------------------

let currentUser = null;

function showLogin(message) {
  const overlay = document.getElementById("login-overlay");
  overlay.hidden = false;
  document.getElementById("login-error").textContent = message || "";
  document.querySelectorAll(".nav-item").forEach((b) => (b.disabled = true));
}

function hideLogin() {
  document.getElementById("login-overlay").hidden = true;
  document.querySelectorAll(".nav-item").forEach((b) => (b.disabled = false));
}

async function checkAuth() {
  try {
    currentUser = await api("/api/auth/me");
    hideLogin();
    const navAdmin = document.getElementById("nav-admin");
    navAdmin.hidden = currentUser.role !== "admin";
    const foot = document.getElementById("sidebar-user");
    if (foot) foot.textContent = currentUser.username + " (" + currentUser.role + ")";
    return true;
  } catch (e) {
    showLogin(e.message);
    return false;
  }
}

async function doLogin() {
  const username = document.getElementById("login-user").value.trim();
  const password = document.getElementById("login-pass").value;
  const err = document.getElementById("login-error");
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const body = await res.json();
    if (!res.ok) {
      err.textContent = body.detail || "Credenciales invalidas";
      return;
    }
    document.getElementById("login-pass").value = "";
    err.textContent = "";
    await checkAuth();
    toast("Sesion iniciada como " + body.username, "success");
    loadAudits();
  } catch (e) {
    err.textContent = "No se pudo conectar con el backend: " + e.message;
  }
}

async function renderAdmin() {
  const el = document.getElementById("view-admin");
  try {
    const users = await api("/api/admin/users");
    const sessions = await api("/api/admin/sessions");
    const trail = await api("/api/admin/trail?limit=40");

    const userRows = (users.users || [])
      .map((u) => {
        const locked = u.locked_until ? "bloqueada hasta " + esc(u.locked_until) : "activa";
        return (
          "<tr>" +
          '<td class="mono">' + esc(u.username) + "</td>" +
          '<td class="mono">' + esc(u.role) + "</td>" +
          '<td class="mono">' + esc(u.last_login || "nunca") + "</td>" +
          '<td class="num">' + u.failed_attempts + "</td>" +
          '<td class="mono">' + locked + "</td>" +
          '<td><button class="btn btn-ghost" data-del-user="' + esc(u.username) + '">Borrar</button></td>' +
          "</tr>"
        );
      })
      .join("");

    const sessionRows = (sessions.sessions || [])
      .map((s) =>
        "<tr>" +
        '<td class="mono">' + esc(s.token) + "…</td>" +
        '<td class="mono">' + esc(s.username) + "</td>" +
        '<td class="mono">' + esc(s.last_activity) + "</td>" +
        '<td class="mono">' + esc(s.expires_at) + "</td>" +
        '<td class="mono">' + esc(s.ip || "-") + "</td>" +
        '<td><button class="btn btn-ghost" data-revoke="' + esc(s.token) + '">Expulsar</button></td>' +
        "</tr>"
      )
      .join("");

    const trailRows = (trail.trail || [])
      .map((t) =>
        "<tr><td class=\"mono\">" + esc(t.at) + "</td><td class=\"mono\">" + esc(t.username || "-") +
        "</td><td class=\"mono\">" + esc(t.action) + "</td><td>" + esc(t.detail || "") +
        "</td><td class=\"mono\">" + esc(t.ip || "-") + "</td></tr>"
      )
      .join("");

    el.innerHTML =
      '<div class="card">' +
      '<div class="card-head"><span class="card-title">Sesion</span>' +
      '<span class="card-sub">Caduca a los ' + users.session_ttl_minutes + ' minutos de inactividad y se renueva con cada peticion</span></div>' +
      '<div class="text-muted">' + esc(currentUser.username) + " · rol " + esc(currentUser.role) + "</div>" +
      '<button class="btn btn-ghost" id="btn-logout" style="margin-top:10px">Cerrar sesion</button>' +
      "</div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Usuarios</span>' +
      '<span class="card-sub">admin, analyst y viewer (este ultimo, solo lectura)</span></div>' +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Usuario</th><th>Rol</th><th>Ultimo acceso</th><th>Intentos fallidos</th><th>Estado</th><th></th></tr></thead>" +
      "<tbody>" + (userRows || '<tr><td colspan="6" class="text-muted">Sin usuarios. Crea el administrador con AUDIT_ADMIN_USER y AUDIT_ADMIN_PASSWORD en el entorno.</td></tr>') + "</tbody>" +
      "</table></div>" +
      '<div class="flex" style="gap:8px;margin-top:12px">' +
      '<input class="input mono" id="new-user" placeholder="usuario" />' +
      '<input class="input mono" id="new-pass" type="password" placeholder="contraseña (min 8)" />' +
      '<select class="select mono" id="new-role"><option value="analyst">analyst</option><option value="admin">admin</option><option value="viewer">viewer</option></select>' +
      '<button class="btn btn-primary" id="btn-create-user">Crear usuario</button>' +
      "</div></div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Sesiones activas</span>' +
      '<span class="card-sub">Se expulsan al caducar por inactividad; aqui se pueden revocar a mano</span></div>' +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Token</th><th>Usuario</th><th>Ultima actividad</th><th>Caduca</th><th>IP</th><th></th></tr></thead>" +
      "<tbody>" + (sessionRows || '<tr><td colspan="6" class="text-muted">Ninguna sesion activa.</td></tr>') + "</tbody>" +
      "</table></div></div>" +
      '<div class="card" style="margin-top:18px">' +
      '<div class="card-head"><span class="card-title">Registro de actividad</span>' +
      '<span class="card-sub">Quien ejecuto que, cuando y desde que IP · retencion ' + esc(trail.stats.retention_days) + ' dias</span></div>' +
      '<div class="flex" style="gap:8px;margin-bottom:10px;flex-wrap:wrap">' +
      '<select class="select mono" id="trail-action"><option value="">todas las acciones</option>' +
      (trail.actions || []).map((a) => '<option value="' + esc(a.action) + '">' + esc(a.action) + ' (' + a.n + ')</option>').join("") +
      "</select>" +
      '<input class="input mono" id="trail-user" placeholder="usuario" />' +
      '<input class="input mono" id="trail-since" placeholder="desde YYYY-MM-DD" />' +
      '<button class="btn btn-ghost" id="trail-filter">Filtrar</button>' +
      '<a class="btn btn-ghost" id="trail-csv" href="#">Exportar CSV</a>' +
      '<a class="btn btn-ghost" id="trail-json" href="#">Exportar JSON</a>' +
      '<span class="text-muted" id="trail-count">' + (trail.trail || []).length + " eventos</span>" +
      "</div>" +
      '<div class="table-wrap"><table>' +
      "<thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Detalle</th><th>IP</th></tr></thead>" +
      "<tbody id=\"view-trail-body\">" + (trailRows || '<tr><td colspan="5" class="text-muted">Sin eventos registrados.</td></tr>') + "</tbody>" +
      "</table></div></div>";

    const trailQuery = () => {
      const p = new URLSearchParams();
      const action = document.getElementById("trail-action").value;
      const user = document.getElementById("trail-user").value.trim();
      const since = document.getElementById("trail-since").value.trim();
      if (action) p.set("action", action);
      if (user) p.set("user", user);
      if (since) p.set("since", since);
      return p.toString();
    };

    document.getElementById("trail-filter").addEventListener("click", async () => {
      try {
        const t = await api("/api/admin/trail?limit=200&" + trailQuery());
        const rows = (t.trail || []).map((x) =>
          "<tr><td class=\"mono\">" + esc(x.at) + "</td><td class=\"mono\">" + esc(x.username || "-") +
          "</td><td class=\"mono\">" + esc(x.action) + "</td><td>" + esc(x.detail || "") +
          "</td><td class=\"mono\">" + esc(x.ip || "-") + "</td></tr>"
        ).join("");
        el.querySelector("#trail-count").textContent = (t.trail || []).length + " eventos";
        el.querySelector("#view-trail-body").innerHTML = rows || '<tr><td colspan="5" class="text-muted">Ningun evento coincide con el filtro.</td></tr>';
      } catch (e) {
        toast("No se pudo filtrar el registro: " + e.message, "error");
      }
    });
    document.getElementById("trail-csv").addEventListener("click", (e) => {
      e.preventDefault();
      window.location = "/api/admin/trail/export?format=csv&" + trailQuery();
    });
    document.getElementById("trail-json").addEventListener("click", (e) => {
      e.preventDefault();
      window.location = "/api/admin/trail/export?format=json&" + trailQuery();
    });

    el.querySelector("#btn-logout").addEventListener("click", async () => {
      try {
        await api("/api/auth/logout", { method: "POST" });
        currentUser = null;
        showLogin("Sesion cerrada");
      } catch (e) {
        toast("No se pudo cerrar la sesion: " + e.message, "error");
      }
    });

    el.querySelector("#btn-create-user").addEventListener("click", async () => {
      try {
        const r = await api("/api/admin/users", {
          method: "POST",
          body: JSON.stringify({
            username: document.getElementById("new-user").value,
            password: document.getElementById("new-pass").value,
            role: document.getElementById("new-role").value,
          }),
        });
        toast("Usuario " + r.username + " creado", "success");
        renderAdmin();
      } catch (e) {
        toast("No se pudo crear: " + e.message, "error");
      }
    });

    el.querySelectorAll("button[data-del-user]").forEach((b) =>
      b.addEventListener("click", async () => {
        try {
          await api("/api/admin/users/" + encodeURIComponent(b.dataset.delUser), { method: "DELETE" });
          toast("Usuario eliminado y sesiones revocadas", "success");
          renderAdmin();
        } catch (e) {
          toast("No se pudo eliminar: " + e.message, "error");
        }
      })
    );

    el.querySelectorAll("button[data-revoke]").forEach((b) =>
      b.addEventListener("click", async () => {
        try {
          await api("/api/admin/sessions/" + encodeURIComponent(b.dataset.revoke), { method: "DELETE" });
          toast("Sesion revocada", "success");
          renderAdmin();
        } catch (e) {
          toast("No se pudo expulsar: " + e.message, "error");
        }
      })
    );
  } catch (e) {
    el.innerHTML = '<div class="card"><div class="text-muted">Error al cargar la administracion: ' + esc(e.message) + "</div></div>";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-login").addEventListener("click", doLogin);
  document.getElementById("login-pass").addEventListener("keydown", (e) => {
    if (e.key === "Enter") doLogin();
  });
});
