"use strict";
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const view = $("#view");
  const CATS = { outdated: "Outdated images", credentials: "Credential leakage", config: "Configuration flaws", practices: "Best practices", errors: "Critical errors", runtime: "Security breaches" };
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  let S = null;          // last /api/state
  let H = [];            // last /api/hosts
  let poll = null;
  const ui = { cat: "", sev: "", q: "", showSup: false, overdue: false, openRow: "", host: "" };
  try { ui.host = localStorage.getItem("kw-host") || ""; } catch { /* storage blocked */ }
  // Endpoints that act on the selected host get ?host= appended.
  const HOST_SCOPED = /^\/api\/(state|alerts|images|settings|export|scan|findings)\b/;
  const withHost = (path) => ui.host && HOST_SCOPED.test(path) ? path + (path.includes("?") ? "&" : "?") + "host=" + encodeURIComponent(ui.host) : path;

  // ---------- helpers ----------
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const rich = (v) => esc(v).replace(/`([^`]+)`/g, "<code>$1</code>");
  const ago = (t) => {
    if (!t) return "never";
    const s = (Date.now() - new Date(t)) / 1000;
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + " min ago";
    if (s < 86400) return Math.floor(s / 3600) + " h ago";
    return Math.floor(s / 86400) + " d ago";
  };
  const bytes = (n) => { if (!n) return "0 B"; const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(4, Math.floor(Math.log(n) / Math.log(1024))); return (n / 1024 ** i).toFixed(i ? 1 : 0) + " " + u[i]; };
  const scoreColor = (s) => s >= 90 ? "var(--ok)" : s >= 80 ? "var(--accent)" : s >= 70 ? "var(--med)" : s >= 60 ? "var(--high)" : "var(--crit)";
  const pill = (sev, solid) => `<span class="pill ${esc(sev)}${solid ? " solid" : ""}">${esc(sev)}</span>`;
  const toast = (msg) => { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); clearTimeout(t._h); t._h = setTimeout(() => t.classList.remove("show"), 2600); };

  async function api(path, opts = {}) {
    const o = { credentials: "same-origin", ...opts, headers: { "X-Keelwatch": "1", ...(opts.body ? { "Content-Type": "application/json" } : {}), ...(opts.headers || {}) } };
    const r = await fetch(withHost(path).replace(/^\//, ""), o); // relative: works under a base path
    if (r.status === 401 && path !== "/api/login") { showLogin(); throw new Error("login required"); }
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((data && data.error) || r.statusText);
    return data;
  }

  // ---------- auth ----------
  function showLogin() { $("#app").hidden = true; $("#login").hidden = false; clearInterval(poll); $("#pw").focus(); }
  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#login-err").textContent = "";
    try {
      await api("/api/login", { method: "POST", body: JSON.stringify({ password: $("#pw").value }) });
      $("#pw").value = "";
      start();
    } catch (err) { $("#login-err").textContent = err.message; }
  });

  // ---------- data ----------
  async function refresh() {
    try { H = await api("/api/hosts"); } catch { H = []; }
    if (ui.host && !H.some((h) => h.id === ui.host)) setHost("");
    const sel = $("#host-sel");
    sel.hidden = H.length < 2;
    sel.innerHTML = H.map((h) => `<option value="${esc(h.id)}" ${h.id === ui.host ? "selected" : ""}>${esc(h.name)}${h.stale ? " (stale)" : ""}</option>`).join("");
    try { S = await api("/api/state"); } catch { return; }
    const snap = S.snapshot;
    const open = snap ? snap.findings.filter((f) => !f.suppressed && SEV_RANK[f.severity] >= 3).length : 0;
    $("#nav-findings").textContent = open || "";
    $("#nav-alerts").textContent = S.openAlerts || "";
    $("#demo-badge").hidden = !S.demo;
    const ver = String(S.version).replace(/^v/, ""); // CI builds pass the tag (v0.1.6)
    $("#version").textContent = /^\d/.test(ver) ? "v" + ver : ver + " build"; // local source builds report "dev"
    const btn = $("#scan-btn");
    btn.hidden = !!ui.host; // remote hosts scan on their agent's schedule
    btn.disabled = S.scanning;
    btn.innerHTML = S.scanning ? '<span class="spin"></span>Scanning' : "Scan now";
    const stale = (H.find((h) => h.id === ui.host) || {}).stale;
    $("#scan-meta").textContent = snap
      ? `${ui.host ? `agent ${ui.host} → ` : ""}${snap.host.name || "docker"}${stale ? " · ⚠ agent has not reported recently" : ""} · Docker ${snap.host.engineVersion} · scanned ${ago(snap.scannedAt)} in ${snap.durationMs < 1000 ? snap.durationMs + " ms" : (snap.durationMs / 1000).toFixed(1) + " s"}`
      : (S.scanning ? "First scan running…" : ui.host ? `Waiting for the first report from agent ${ui.host}…` : "Waiting for first scan…");
    render();
  }
  function setHost(id) {
    ui.host = id; ui.openRow = "";
    try { localStorage.setItem("kw-host", id); } catch { /* storage blocked */ }
  }
  $("#host-sel").addEventListener("change", (e) => { setHost(e.target.value); refresh(); });

  $("#scan-btn").addEventListener("click", async () => {
    await api("/api/scan", { method: "POST" });
    toast("Scan started");
    setTimeout(refresh, 600);
  });

  // ---------- routing ----------
  const routes = { overview: renderOverview, findings: renderFindings, containers: renderContainers, network: renderNetwork, images: renderImages, runtime: renderRuntime, settings: renderSettings };
  const titles = { overview: "Overview", findings: "Findings", containers: "Containers", network: "Network", images: "Images", runtime: "Runtime", settings: "Settings" };
  function route() {
    const h = location.hash.replace(/^#\/?/, "");
    const [name, qs] = h.split("?");
    const r = routes[name] ? name : "overview";
    const p = new URLSearchParams(qs || "");
    if (r === "findings" && p.has("cat")) { ui.cat = p.get("cat"); ui.sev = p.get("sev") || ""; }
    if (r === "findings" && p.has("overdue")) { ui.overdue = true; ui.cat = ""; ui.sev = ""; }
    return r;
  }
  window.addEventListener("hashchange", render);
  function render() {
    const r = route();
    $$(".side a").forEach((a) => a.classList.toggle("active", a.dataset.route === r));
    $("#page-title").textContent = titles[r];
    document.title = titles[r] + " · Keelwatch";
    if (r === "runtime" || r === "settings") { routes[r](); return; }
    if (!S || !S.snapshot) { view.innerHTML = `<div class="card empty">${ui.host ? `No report from agent <b>${esc(ui.host)}</b> yet. Check its logs for "push to hub failed".` : S && S.scanning ? '<span class="spin"></span>Running the first scan. This takes a few seconds, longer if registry checks are slow.' : "No scan yet. Check that Keelwatch can reach the Docker API (see container logs)."}</div>`; return; }
    routes[r]();
  }

  // ---------- overview ----------
  function dial(score) {
    const r = 52, c = 2 * Math.PI * r, arc = c * 0.75, v = arc * score / 100;
    return `<div class="dial"><svg viewBox="0 0 120 120" aria-hidden="true"><circle class="track" cx="60" cy="60" r="${r}" stroke-dasharray="${arc} ${c}"/><circle class="val" cx="60" cy="60" r="${r}" stroke="${scoreColor(score)}" stroke-dasharray="${v} ${c}"/></svg><div class="num"><div><b>${score}</b><span>of 100</span></div></div></div>`;
  }
  function trend(hist, key = "score", unit = "points", label = "Score trend") {
    if (!hist || hist.length < 2) return `<div class="empty small">The trend appears after a few scans.</div>`;
    const pts = hist.slice(-60), W = 300, H = 100;
    const max = key === "score" ? 100 : Math.max(1, ...pts.map((p) => p[key] || 0));
    const xs = (i) => (i / (pts.length - 1)) * W, ys = (s) => H - ((s || 0) / max) * H;
    const d = pts.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p[key]).toFixed(1)}`).join("");
    const first = pts[0], last = pts[pts.length - 1], delta = (last[key] || 0) - (first[key] || 0);
    return `<div class="trend"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${label}">
      ${[25, 50, 75].map((g) => `<line class="grid" x1="0" x2="${W}" y1="${ys(g)}" y2="${ys(g)}"/>`).join("")}
      <path class="area" d="${d}L${W},${H}L0,${H}Z"/><path class="line" d="${d}"/></svg>
      <div class="muted small">${pts.length} scans since ${new Date(first.time).toLocaleString()} · ${delta === 0 ? "no change" : (delta > 0 ? "▲ " : "▼ ") + Math.abs(delta) + " " + unit}</div></div>`;
  }
  function sevCounts(fs) { const c = {}; fs.forEach((f) => { if (!f.suppressed) c[f.severity] = (c[f.severity] || 0) + 1; }); return c; }

  function renderOverview() {
    const s = S.snapshot, c = sevCounts(s.findings), h = s.host;
    const active = s.findings.filter((f) => !f.suppressed && f.severity !== "info");
    const top = active.slice(0, 7);
    const risky = [...s.containers].sort((a, b) => a.score - b.score).slice(0, 6);
    view.innerHTML = `
    <section class="grid-hero">
      <div class="card"><h2>Security posture</h2>
        <div class="score">${dial(s.score)}
          <div><span class="grade" style="background:color-mix(in srgb, ${scoreColor(s.score)} 18%, transparent);color:${scoreColor(s.score)}">Grade ${esc(s.grade)}</span>
            <div class="muted small">${active.length} open issues across ${s.containers.length} containers</div>
            <div class="sev-row">${["critical", "high", "medium", "low"].map((k) => `<a href="#/findings?cat=&sev=${k}" class="pill ${k}" style="text-decoration:none">${c[k] || 0} ${k}</a>`).join("")}</div>
          </div></div></div>
      <div class="card"><h2>Trend</h2>${trend(S.history)}
        <div class="host-facts">
          <div><b>${h.running}/${h.containers}</b><span>containers running</span></div>
          <div><b>${h.images}</b><span>images · ${bytes(h.imagesSize)}</span></div>
          <div><b>${esc(h.arch || "")}</b><span>${esc(h.os || "")}</span></div>
          <div><b>${bytes(h.reclaimable)}</b><span>unused image space</span></div>
        </div></div>
    </section>
    <section class="cats">${s.categories.map((k) => `
      <a class="cat" href="#/findings?cat=${k.category}">
        <div class="cat-head"><b>${esc(k.label)}</b><span class="n" style="color:${scoreColor(k.score)}">${k.score}</span></div>
        <div class="bar"><i style="width:${k.score}%;background:${scoreColor(k.score)}"></i></div>
        <p>${k.count ? `${k.count} issue${k.count > 1 ? "s" : ""}${k.counts.critical ? ` · <span class="c-critical">${k.counts.critical} critical</span>` : ""} · ${esc(k.top || "")}` : '<span class="c-ok">No issues</span>'}</p>
      </a>`).join("")}</section>
    <section class="grid-2">${debtCard(s.debt)}${H.length > 1 ? fleetCard() : `<div class="card"><h2>Overdue trend</h2>${trend(S.history, "overdue", "overdue", "Overdue findings trend")}</div>`}</section>
    <section class="grid-2">
      <div class="card"><h2>Fix first</h2><div class="list">${top.length ? top.map((f) => `
        <a class="row" href="#/findings?cat=${f.category}" style="text-decoration:none">${pill(f.severity, f.severity === "critical")}<div class="t"><b>${esc(f.title)}</b><span>${esc(f.target)} · ${CATS[f.category]}</span></div><span class="muted small hide-sm">${ago(f.firstSeen)}</span></a>`).join("") : '<div class="empty">Nothing to fix. Nice.</div>'}</div></div>
      <div class="card"><h2>Containers at risk</h2><div class="list">${risky.map((k) => `
        <a class="row" href="#/containers" style="text-decoration:none"><span class="score-badge" style="background:color-mix(in srgb, ${scoreColor(k.score)} 18%, transparent);color:${scoreColor(k.score)}">${k.score}</span><div class="t"><b>${esc(k.name)}</b><span>${esc(k.image)}</span></div>${counts(k.counts)}</a>`).join("")}</div>
        ${(S.recentAlerts || []).length ? `<h2 style="margin-top:18px">Latest runtime alerts</h2><div class="list">${S.recentAlerts.slice(0, 3).map((a) => `<a class="row" href="#/runtime" style="text-decoration:none">${pill(a.severity)}<div class="t"><b>${esc(a.title)}</b><span>${esc(a.detail)}</span></div><span class="muted small">${ago(a.time)}</span></a>`).join("")}</div>` : ""}
      </div>
    </section>
    ${s.errors && s.errors.length ? `<div class="card"><h2>Scan warnings</h2>${s.errors.map((e) => `<div class="muted small">${esc(e)}</div>`).join("")}</div>` : ""}`;
    $$("[data-host]", view).forEach((tr) => tr.onclick = () => { setHost(tr.dataset.host); refresh(); });
    $$("[data-rm]", view).forEach((b) => b.onclick = (e) => { e.stopPropagation(); removeHost(b.dataset.rm); });
  }
  const overdueTag = (f) => f.overdue ? ` <span class="pill critical" title="Fix-by date ${new Date(f.dueAt).toLocaleDateString()}">overdue ${Math.max(1, Math.floor((Date.now() - new Date(f.dueAt)) / 86400000))} d</span>` : "";
  const FIX_DAYS = { critical: 7, high: 30, medium: 90, low: 180 };
  function debtCard(d) {
    d = d || { open: 0, overdue: 0, ages: [0, 0, 0, 0], overdueBySeverity: {} };
    const ages = d.ages || [0, 0, 0, 0], labels = ["< 7 days", "7–30 days", "30–90 days", "> 90 days"], top = Math.max(1, ...ages);
    const bys = d.overdueBySeverity || {};
    return `<div class="card"><h2>Security debt</h2>
      <div class="host-facts" style="margin-top:0">
        <a href="#/findings?overdue=1" style="text-decoration:none;color:inherit"><b class="${d.overdue ? "c-critical" : "c-ok"}">${d.overdue}</b><span>overdue of ${d.open} open</span></a>
        <div><b>${d.debtDays || 0}</b><span>days past due, total</span></div>
        <div><b>${d.oldestDays || 0} d</b><span>oldest open issue</span></div>
      </div>
      <div class="sev-row">${["critical", "high", "medium", "low"].map((k) => `<span class="pill ${k}" title="fix within ${FIX_DAYS[k]} days">${bys[k] || 0} ${k} overdue</span>`).join("")}</div>
      ${labels.map((l, i) => `<div class="small" style="display:flex;gap:10px;align-items:center"><span style="width:84px" class="muted">${l}</span><div class="bar" style="flex:1;margin:6px 0"><i style="width:${(ages[i] / top) * 100}%;background:${["var(--ok)", "var(--accent)", "var(--high)", "var(--crit)"][i]}"></i></div><b style="width:28px;text-align:right">${ages[i]}</b></div>`).join("")}
      <p class="muted small">Fix within: critical 7 d · high 30 d · medium 90 d · low 180 d, counted from first seen.</p></div>`;
  }
  function fleetCard() {
    return `<div class="card"><h2>Fleet</h2><div class="table-wrap"><table>
      <thead><tr><th>Score</th><th>Host</th><th>Issues <span class="muted">C·H·M·L</span></th><th>Overdue</th><th class="hide-sm">Last scan</th><th><span class="muted small">Remove</span></th></tr></thead>
      <tbody>${H.map((h) => `<tr class="clickable" data-host="${esc(h.id)}"${h.id === ui.host ? ' aria-current="true" style="background:color-mix(in srgb, var(--accent) 10%, transparent)"' : ""}>
        <td>${h.reported ? `<span class="score-badge" style="background:color-mix(in srgb, ${scoreColor(h.score)} 18%, transparent);color:${scoreColor(h.score)}">${h.score}</span>` : '<span class="muted">—</span>'}</td>
        <td><b>${esc(h.name)}</b>${h.remote ? ' <span class="pill info">agent</span>' : ""}${h.stale ? ' <span class="pill high" title="No report for more than two scan intervals">stale</span>' : ""}</td>
        <td>${counts(h.counts)}</td>
        <td class="${h.debt && h.debt.overdue ? "c-critical" : "muted"}">${h.debt ? h.debt.overdue : 0}</td>
        <td class="hide-sm small">${h.reported ? ago(h.scannedAt) : "waiting"}</td>
        <td>${h.remote ? `<button class="icon-btn" data-rm="${esc(h.id)}" title="Remove host" aria-label="Remove host ${esc(h.name)}">✕</button>` : ""}</td></tr>`).join("")}</tbody></table></div></div>`;
  }
  async function removeHost(id) {
    if (!confirm(`Remove host "${id}"?\n\nIts data on this dashboard is deleted and its agent's reports are refused until you restore it in Settings. To revoke it for good, also delete its line from KEELWATCH_AGENT_TOKENS.`)) return;
    try { await api(`/api/hosts/${encodeURIComponent(id)}`, { method: "DELETE" }); } catch (e) { toast("Failed: " + e.message); return; }
    if (ui.host === id) setHost("");
    toast(`Removed ${id}`);
    refresh();
  }
  function counts(c) {
    c = c || {};
    return `<div class="counts" title="critical / high / medium / low">${["critical", "high", "medium", "low"].map((k) => `<span class="c-${k}${c[k] ? "" : " z"}">${c[k] || 0}</span>`).join("")}</div>`;
  }

  // ---------- findings ----------
  function findingHTML(f) {
    return `<details class="finding${f.suppressed ? " suppressed" : ""}" data-id="${esc(f.id)}">
      <summary>${pill(f.severity, f.severity === "critical")}<div class="t"><b>${esc(f.title)}</b><span>${esc(f.target)} · ${CATS[f.category]}${f.cis ? " · CIS " + esc(f.cis) : ""}${f.suppressed ? " · suppressed" : ""}</span></div><span class="muted small hide-sm">since ${ago(f.firstSeen)}${overdueTag(f)}</span></summary>
      <div class="f-body">
        ${f.detail ? `<div><h4>Why it matters</h4><p>${rich(f.detail)}</p></div>` : ""}
        ${f.evidence ? `<div><h4>Evidence</h4><div class="evidence">${esc(f.evidence)}</div></div>` : ""}
        ${f.remediation ? `<div><h4>How to fix</h4><p>${rich(f.remediation)}</p></div>` : ""}
        <div class="f-actions">${f.suppressed
          ? `<button class="btn small" data-act="unsup" data-id="${esc(f.id)}">Restore</button>`
          : `<button class="btn small" data-act="sup" data-id="${esc(f.id)}">Accept risk / suppress</button>`}
          <span class="muted small">Rule <span class="mono">${esc(f.rule)}</span></span></div>
      </div></details>`;
  }
  function renderFindings() {
    const all = S.snapshot.findings;
    const byCat = {}; all.forEach((f) => { if (!f.suppressed && f.severity !== "info") byCat[f.category] = (byCat[f.category] || 0) + 1; });
    const q = ui.q.toLowerCase();
    const list = all.filter((f) => (ui.showSup || !f.suppressed) && (!ui.cat || f.category === ui.cat) && (!ui.sev || f.severity === ui.sev) && (!ui.overdue || f.overdue) &&
      (!q || (f.title + " " + f.target + " " + f.detail + " " + f.rule).toLowerCase().includes(q)));
    view.innerHTML = `
    <div class="filters">
      <button class="chip ${!ui.cat ? "on" : ""}" data-cat="">All<b>${all.filter((f) => !f.suppressed && f.severity !== "info").length}</b></button>
      ${Object.entries(CATS).map(([k, v]) => `<button class="chip ${ui.cat === k ? "on" : ""}" data-cat="${k}">${v}<b>${byCat[k] || 0}</b></button>`).join("")}
    </div>
    <div class="filters">
      <input type="search" id="q" placeholder="Search title, container, rule…" value="${esc(ui.q)}" aria-label="Search findings">
      <select id="sev" aria-label="Severity"><option value="">All severities</option>${SEVS.map((s) => `<option ${ui.sev === s ? "selected" : ""}>${s}</option>`).join("")}</select>
      <label class="muted small"><input type="checkbox" id="sup" ${ui.showSup ? "checked" : ""}> show suppressed</label>
      <label class="muted small"><input type="checkbox" id="od" ${ui.overdue ? "checked" : ""}> overdue only</label>
    </div>
    <div>${list.length ? list.map(findingHTML).join("") : '<div class="card empty">No findings match these filters.</div>'}</div>`;
    $$(".chip", view).forEach((b) => b.onclick = () => { ui.cat = b.dataset.cat; history.replaceState(null, "", "#/findings"); renderFindings(); });
    $("#q").oninput = (e) => { ui.q = e.target.value; const pos = e.target.selectionStart; renderFindings(); const n = $("#q"); n.focus(); n.setSelectionRange(pos, pos); };
    $("#sev").onchange = (e) => { ui.sev = e.target.value; renderFindings(); };
    $("#sup").onchange = (e) => { ui.showSup = e.target.checked; renderFindings(); };
    $("#od").onchange = (e) => { ui.overdue = e.target.checked; history.replaceState(null, "", "#/findings"); renderFindings(); };
    bindFindingActions(view);
  }
  function bindFindingActions(root) {
    $$("[data-act=sup]", root).forEach((b) => b.onclick = async () => {
      const note = prompt("Why is this acceptable? (shown in Settings → Suppressed)", "Accepted risk");
      if (note === null) return;
      await api(`/api/findings/${b.dataset.id}/suppress`, { method: "POST", body: JSON.stringify({ note }) });
      toast("Suppressed"); refresh();
    });
    $$("[data-act=unsup]", root).forEach((b) => b.onclick = async () => {
      await api(`/api/findings/${b.dataset.id}/suppress`, { method: "DELETE" }); toast("Restored"); refresh();
    });
  }

  // ---------- containers ----------
  function renderContainers() {
    const s = S.snapshot;
    const fsFor = (c) => s.findings.filter((f) => !f.suppressed && (f.targetId === c.id || (f.targetType === "image" && f.targetId === c.imageId)));
    view.innerHTML = `<div class="card table-wrap"><table>
      <thead><tr><th>Score</th><th>Container</th><th class="hide-sm">Image</th><th>State</th><th class="hide-sm">CPU / Mem</th><th>Issues <span class="muted">C·H·M·L</span></th></tr></thead>
      <tbody>${s.containers.map((c) => `
        <tr class="clickable" data-id="${esc(c.id)}"><td><span class="score-badge" style="background:color-mix(in srgb, ${scoreColor(c.score)} 18%, transparent);color:${scoreColor(c.score)}">${c.score}</span></td>
        <td><b>${esc(c.name)}</b>${c.ports && c.ports.length ? `<div class="muted small mono">${esc(c.ports.join("  "))}</div>` : ""}</td>
        <td class="hide-sm mono small">${esc(c.image)}</td>
        <td><span class="dot ${esc(c.health || c.state)}"></span>${esc(c.state)}${c.health ? ` · ${esc(c.health)}` : ""}${c.restarts ? ` · <span class="c-high">${c.restarts} restarts</span>` : ""}</td>
        <td class="hide-sm small">${c.state === "running" ? `${c.cpu}% · ${c.mem}%` : "—"}</td>
        <td>${counts(c.counts)}</td></tr>
        ${ui.openRow === c.id ? `<tr class="detail"><td colspan="6">${fsFor(c).map(findingHTML).join("") || '<div class="empty">No open findings.</div>'}</td></tr>` : ""}`).join("")}
      </tbody></table>${s.containers.length ? "" : '<div class="empty">No containers on this host.</div>'}</div>`;
    $$("tr.clickable", view).forEach((tr) => tr.onclick = () => { ui.openRow = ui.openRow === tr.dataset.id ? "" : tr.dataset.id; renderContainers(); });
    bindFindingActions(view);
  }

  // ---------- network map ----------
  const trunc = (t, n) => (t = String(t || "")).length > n ? t.slice(0, n - 1) + "…" : t;
  const isLoopback = (ip) => ip.startsWith("127.") || ip === "::1" || ip === "[::1]";
  const isProxy = (c) => /socket-proxy/.test(c.image || "");
  function exposure(c) {
    const pub = [], loc = [];
    (c.ports || []).forEach((p) => {
      const [bind, inner] = p.split("→"), i = bind.lastIndexOf(":");
      (isLoopback(bind.slice(0, i)) ? loc : pub).push(bind.slice(i + 1) + (inner ? "→" + inner.replace("/tcp", "") : ""));
    });
    return { pub, loc };
  }
  function netModel(s) {
    const info = new Map((s.networks || []).map((n) => [n.name, n]));
    const cs = s.containers.map((c) => ({ ...c, x: exposure(c), nets: c.networkMode === "host" ? [] : (c.networks || []).filter((n) => n !== "none" && n !== "host") }));
    const members = new Map();
    cs.forEach((c) => c.nets.forEach((n) => { if (!members.has(n)) members.set(n, []); members.get(n).push(c.name); }));
    const nets = [...members.keys()].sort((a, b) => members.get(b).length - members.get(a).length || a.localeCompare(b));
    const order = (c) => c.nets.length ? Math.min(...c.nets.map((n) => nets.indexOf(n))) : nets.length;
    cs.sort((a, b) => order(a) - order(b) || a.name.localeCompare(b.name)); // fewer crossing lines
    const src = [
      { id: "src:pub", label: "Network / internet", sub: "ports published on 0.0.0.0", color: "var(--high)", has: (c) => c.x.pub.length > 0 },
      { id: "src:loc", label: "This host only", sub: "ports on 127.0.0.1", color: "var(--ok)", has: (c) => c.x.loc.length > 0 },
      { id: "src:host", label: "Host network stack", sub: "network_mode: host", color: "var(--high)", has: (c) => c.networkMode === "host" },
      { id: "src:sock", label: "Docker daemon", sub: "docker.sock = root on host", color: "var(--crit)", has: (c) => !!c.dockerSocket },
    ].filter((x) => cs.some(x.has));
    return { info, cs, members, nets, src };
  }
  const internalNet = (m, n) => !!(m.info.get(n) || {}).internal;
  function netInsights(m) {
    const out = [];
    const pub = m.cs.filter((c) => c.x.pub.length);
    if (pub.length) out.push(["high", `${pub.length} container${pub.length > 1 ? "s are" : " is"} reachable from the network: ${pub.map((c) => `${c.name} (${c.x.pub.map((p) => p.split("→")[0]).join(", ")})`).join(", ")}. Docker-published ports bypass UFW; bind to 127.0.0.1 and go through a reverse proxy.`]);
    pub.filter((c) => c.nets.some((n) => internalNet(m, n))).forEach((c) => {
      const nets = c.nets.filter((n) => internalNet(m, n));
      const peers = [...new Set(nets.flatMap((n) => m.members.get(n)).filter((p) => p !== c.name))];
      out.push(["critical", `${c.name} is exposed and also joins internal network ${nets.join(", ")}. If it is compromised, an attacker can reach ${peers.join(", ") || "that network"}.`]);
    });
    const sock = m.cs.filter((c) => c.dockerSocket && !isProxy(c));
    if (sock.length) out.push(["critical", `Docker daemon access (root-equivalent on the host): ${sock.map((c) => c.name).join(", ")}. Put a read-only socket proxy in between.`]);
    const host = m.cs.filter((c) => c.networkMode === "host");
    if (host.length) out.push(["medium", `${host.map((c) => c.name).join(", ")} use${host.length > 1 ? "" : "s"} the host's network stack: every port opened inside is open on the host.`]);
    return out;
  }
  function renderNetwork() {
    const s = S.snapshot, m = netModel(s);
    if (!m.cs.length) { view.innerHTML = '<div class="card empty">No containers on this host.</div>'; return; }
    const W = 960, RH = 54, top = 40;
    const rows = Math.max(m.src.length, m.cs.length, m.nets.length);
    const H = top + rows * RH + 10;
    const col = { src: { x: 10, w: 200 }, c: { x: 340, w: 270 }, n: { x: 740, w: 210 } };
    const pos = {};
    const place = (ids, key) => ids.forEach((id, i) => { pos[id] = { x: col[key].x, w: col[key].w, y: top + (i + 0.5) * ((H - top - 10) / ids.length) }; });
    place(m.src.map((x) => x.id), "src");
    place(m.cs.map((c) => "c:" + c.name), "c");
    place(m.nets.map((n) => "n:" + n), "n");
    const edges = [];
    m.src.forEach((x) => m.cs.forEach((c) => { if (x.has(c)) edges.push({ a: x.id, b: "c:" + c.name, color: x.id === "src:sock" && isProxy(c) ? "var(--med)" : x.color }); }));
    m.cs.forEach((c) => c.nets.forEach((n) => edges.push({ a: "c:" + c.name, b: "n:" + n, color: internalNet(m, n) ? "var(--ok)" : "var(--muted)" })));
    const sel = ui.mapSel && pos[ui.mapSel] ? ui.mapSel : "";
    const linked = (e) => !sel || e.a === sel || e.b === sel;
    const near = new Set(edges.filter((e) => sel && linked(e)).flatMap((e) => [e.a, e.b]));
    const curve = (e) => { const p = pos[e.a], q = pos[e.b], x1 = p.x + p.w, x2 = q.x, mx = (x1 + x2) / 2; return `M${x1},${p.y} C${mx},${p.y} ${mx},${q.y} ${x2},${q.y}`; };
    const node = (id, label, sub, color) => {
      const p = pos[id], on = sel === id, dim = sel && !on && !near.has(id);
      return `<g class="nm-node${dim ? " nm-dim" : ""}${on ? " on" : ""}" data-sel="${esc(id)}" tabindex="0" role="button" aria-pressed="${on}" aria-label="${esc(label + ": " + sub)}" transform="translate(${p.x},${(p.y - 20).toFixed(1)})">
        <rect width="${p.w}" height="40" rx="8" style="stroke:${color}"/><text x="12" y="17" class="nm-t">${esc(trunc(label, 32))}</text><text x="12" y="32" class="nm-s">${esc(trunc(sub, 40))}</text></g>`;
    };
    const cSub = (c) => [c.x.pub.length ? "public " + c.x.pub.map((p) => p.split("→")[0]).join(" ") : "", c.x.loc.length ? "local " + c.x.loc.map((p) => p.split("→")[0]).join(" ") : "", c.state !== "running" ? c.state : ""].filter(Boolean).join(" · ") || c.image;
    const nSub = (n) => `${n === "bridge" ? "default bridge" : internalNet(m, n) ? "internal" : (m.info.get(n) || {}).driver || "network"} · ${m.members.get(n).length} container${m.members.get(n).length > 1 ? "s" : ""}`;
    const ins = netInsights(m);
    view.innerHTML = `
      ${ins.length ? `<div class="card"><h2>What the map shows</h2><div class="list">${ins.map(([sev, t]) => `<div class="row">${pill(sev, sev === "critical")}<div class="t"><span style="color:var(--text)">${esc(t)}</span></div></div>`).join("")}</div></div>` : ""}
      <div class="card"><h2>Connectivity · ${esc(s.host.name || "docker")}</h2>
        <div class="nm"><svg viewBox="0 0 ${W} ${H}" role="group" aria-label="Who can reach which container, and which networks connect them">
          <text x="${col.src.x}" y="16" class="nm-head">Reachable from</text><text x="${col.c.x}" y="16" class="nm-head">Containers</text><text x="${col.n.x}" y="16" class="nm-head">Networks</text>
          ${edges.map((e) => `<path class="nm-edge${linked(e) ? "" : " nm-dim"}" d="${curve(e)}" style="stroke:${e.color}"/>`).join("")}
          ${m.src.map((x) => node(x.id, x.label, x.sub, x.color)).join("")}
          ${m.cs.map((c) => node("c:" + c.name, c.name, cSub(c), scoreColor(c.score))).join("")}
          ${m.nets.map((n) => node("n:" + n, n, nSub(n), internalNet(m, n) ? "var(--ok)" : "var(--line-2)")).join("")}
        </svg></div>
        <div class="nm-legend muted small"><span><i style="background:var(--high)"></i>reachable from the network</span><span><i style="background:var(--ok)"></i>localhost only / internal network</span><span><i style="background:var(--crit)"></i>Docker daemon (root)</span><span><i style="background:var(--muted)"></i>shared network: containers can talk</span><span>Box outline = container score. Click a box to trace it.</span></div>
      </div>
      <div class="card" id="nm-detail">${netDetail(m, sel)}</div>`;
    $$(".nm-node", view).forEach((g) => {
      const pick = () => { ui.mapSel = ui.mapSel === g.dataset.sel ? "" : g.dataset.sel; renderNetwork(); const n = $(`.nm-node[data-sel="${CSS.escape(g.dataset.sel)}"]`, view); if (n) n.focus(); };
      g.onclick = pick;
      g.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } };
    });
    const go = $("[data-open]", view); if (go) go.onclick = () => { ui.openRow = go.dataset.open; location.hash = "#/containers"; };
  }
  function netDetail(m, sel) {
    if (!sel) return '<p class="muted small" style="margin:0">Select a container, network or entry point to see exactly what it connects to.</p>';
    const li = (items) => items.length ? `<ul class="small" style="margin:4px 0 12px;padding-left:18px">${items.map((x) => `<li>${x}</li>`).join("")}</ul>` : '<p class="muted small">None.</p>';
    if (sel.startsWith("c:")) {
      const c = m.cs.find((x) => "c:" + x.name === sel);
      const from = [...c.x.pub.map((p) => `<b class="c-high">network / internet</b> on <span class="mono">${esc(p)}</span>`), ...c.x.loc.map((p) => `this host only on <span class="mono">${esc(p)}</span>`)];
      if (c.networkMode === "host") from.push('<b class="c-high">host network stack</b>: all its ports are host ports');
      if (c.dockerSocket) from.push(`<b class="c-critical">Docker daemon</b> via docker.sock${isProxy(c) ? " (socket proxy)" : ": root-equivalent access to the host"}`);
      const peers = c.nets.map((n) => `<span class="mono">${esc(n)}</span>${internalNet(m, n) ? ' <span class="pill ok">internal</span>' : ""}: ${esc(m.members.get(n).filter((p) => p !== c.name).join(", ") || "no other containers")}`);
      return `<h2>${esc(c.name)}</h2><p class="muted small">${esc(c.image)} · ${esc(c.state)} · score ${c.score}</p>
        <h4>Connections in</h4>${li(from)}<h4>Can talk to (shared networks)</h4>${li(peers)}
        <button class="btn small" data-open="${esc(c.id)}">Show its findings</button>`;
    }
    if (sel.startsWith("n:")) {
      const n = sel.slice(2), mem = m.members.get(n) || [];
      return `<h2>${esc(n)}</h2><p class="small">${internalNet(m, n) ? '<span class="pill ok">internal</span> No route outside the host.' : n === "bridge" ? "Docker's default bridge. Containers here can reach each other unless inter-container traffic (ICC) is disabled." : "Containers on this network can reach each other by name."}</p>
        <h4>Members</h4>${li(mem.map((x) => esc(x)))}`;
    }
    const x = m.src.find((s) => s.id === sel);
    return `<h2>${esc(x.label)}</h2><p class="muted small">${esc(x.sub)}</p><h4>Containers</h4>${li(m.cs.filter(x.has).map((c) => esc(c.name) + (c.x.pub.length && x.id === "src:pub" ? ` <span class="mono muted">${esc(c.x.pub.join(", "))}</span>` : "")))}`;
  }

  // ---------- images ----------
  function updBadge(u) {
    if (!u) return '<span class="muted small">not checked</span>';
    if (u.error) return `<span class="muted small" title="${esc(u.error)}">unknown</span>`;
    const parts = [];
    if (u.bump) parts.push(`<span class="pill ${u.bump === "patch" ? "medium" : "low"}">${esc(u.bump)} → ${esc(u.newestTag)}</span>`);
    if (u.digestNew) parts.push('<span class="pill medium">new build</span>');
    return parts.join(" ") || '<span class="pill ok">current</span>';
  }
  function cveCell(im) {
    if (!S.cveEnabled && !im.scan) return '<span class="muted small">Trivy off</span>';
    if (!im.scan) return im.inUseBy && im.inUseBy.length ? '<span class="muted small"><span class="spin"></span>queued</span>' : '<span class="muted small">—</span>';
    if (im.scan.error) return `<span class="c-high small" title="${esc(im.scan.error)}">scan failed</span>`;
    const c = im.scan.counts || {};
    return `<button class="btn small" data-cve="${esc(im.id)}" data-ref="${esc(im.ref)}">${counts(c)}</button>`;
  }
  function renderImages() {
    const ims = S.snapshot.images;
    view.innerHTML = `<div class="card table-wrap"><table>
      <thead><tr><th>Image</th><th>Used by</th><th class="hide-sm">Built</th><th class="hide-sm">Size</th><th>Updates</th><th>CVEs <span class="muted">C·H·M·L</span></th></tr></thead>
      <tbody>${ims.map((im) => `<tr>
        <td><b class="mono small">${esc(im.ref || "<untagged>")}</b>${im.dangling ? ' <span class="pill info">dangling</span>' : ""}${im.runsAsRoot && im.inUseBy && im.inUseBy.length ? ' <span class="pill low" title="Image default user is root">root</span>' : ""}</td>
        <td class="small">${im.inUseBy && im.inUseBy.length ? esc(im.inUseBy.join(", ")) : '<span class="muted">unused</span>'}</td>
        <td class="hide-sm small">${ago(im.created)}</td><td class="hide-sm small">${bytes(im.size)}</td>
        <td>${updBadge(im.update)}</td><td>${cveCell(im)}</td></tr>`).join("")}</tbody></table></div>
      ${S.cveEnabled ? "" : `<div class="card muted small">CVE scanning is off. It needs Trivy, which the official Keelwatch image includes. Set <code>KEELWATCH_TRIVY=trivy</code> if you built your own image.</div>`}`;
    $$("[data-cve]", view).forEach((b) => b.onclick = () => showCVEs(b.dataset.cve, b.dataset.ref));
  }
  async function showCVEs(id, ref) {
    $("#modal-title").textContent = "Vulnerabilities in " + ref;
    $("#modal-body").innerHTML = '<div class="empty"><span class="spin"></span>Loading…</div>';
    $("#modal").showModal();
    try {
      const r = await api(`/api/images/${encodeURIComponent(id)}/cves`);
      const sec = r.secrets && r.secrets.length ? `<div class="card" style="margin:10px 0;border-color:var(--crit)"><b class="c-critical">Secrets found in image layers</b>${r.secrets.map((s) => `<div class="small mono">${esc(s)}</div>`).join("")}</div>` : "";
      $("#modal-body").innerHTML = `<p class="muted small">Scanned ${ago(r.scannedAt)} with Trivy · ${r.fixable} fixable · showing ${r.cves.length}</p>${sec}
        <div class="table-wrap"><table><thead><tr><th>Severity</th><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed in</th></tr></thead><tbody>
        ${r.cves.map((c) => `<tr><td>${pill(c.severity)}</td><td><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}" target="_blank" rel="noopener noreferrer" class="mono small">${esc(c.id)}</a>${c.title ? `<div class="muted small">${esc(c.title)}</div>` : ""}</td><td class="mono small">${esc(c.pkg)}</td><td class="mono small">${esc(c.installed)}</td><td class="mono small ${c.fixed ? "c-ok" : "muted"}">${esc(c.fixed || "no fix yet")}</td></tr>`).join("")}
        </tbody></table></div>`;
    } catch (e) { $("#modal-body").innerHTML = `<div class="empty">${esc(e.message)}</div>`; }
  }
  $("#modal-close").onclick = () => $("#modal").close();

  // ---------- runtime ----------
  async function renderRuntime() {
    let alerts = [];
    try { alerts = await api("/api/alerts"); } catch { return; }
    if (route() !== "runtime") return;
    const rtFindings = S && S.snapshot ? S.snapshot.findings.filter((f) => f.category === "runtime" && f.rule !== "runtime-alert" && !f.suppressed) : [];
    const open = alerts.filter((a) => !a.acked).length;
    view.innerHTML = `
      ${rtFindings.length ? `<div class="card"><h2>Live process findings</h2>${rtFindings.map(findingHTML).join("")}</div>` : ""}
      <div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><h2 style="margin:0">Alerts (${open} open)</h2>${open ? '<button class="btn small" id="ackall">Acknowledge all</button>' : ""}</div>
      <div class="list" style="margin-top:8px">${alerts.length ? alerts.slice(0, 300).map((a) => `
        <div class="row" style="${a.acked ? "opacity:.55" : ""}">${pill(a.severity, a.severity === "critical" && !a.acked)}
          <div class="t"><b>${esc(a.title)}</b><span>${esc(a.detail)}</span><span> · ${esc(a.source)} · ${new Date(a.time).toLocaleString()}</span></div>
          ${a.acked ? '<span class="muted small">acked</span>' : `<button class="btn small" data-ack="${esc(a.id)}">Ack</button>`}</div>`).join("")
        : '<div class="empty">No runtime alerts. Keelwatch watches Docker events (exec, OOM, crashes, health) and running processes. Connect Falco for kernel-level detection (Settings).</div>'}</div></div>`;
    $$("[data-ack]", view).forEach((b) => b.onclick = async () => { await api(`/api/alerts/${b.dataset.ack}/ack`, { method: "POST" }); refresh(); });
    const aa = $("#ackall"); if (aa) aa.onclick = async () => { await api("/api/alerts/ack-all", { method: "POST" }); toast("All alerts acknowledged"); refresh(); };
    bindFindingActions(view);
  }

  // ---------- settings ----------
  async function renderSettings() {
    let st;
    try { st = await api("/api/settings"); } catch { return; }
    if (route() !== "settings") return;
    const kv = Object.entries(st.settings || {});
    view.innerHTML = `
      <div class="grid-2">
        <div class="card"><h2>Configuration</h2><dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono small">${esc(Array.isArray(v) ? (v.join(", ") || "—") : (v === "" ? "—" : v))}</dd>`).join("")}</dl>
          <p class="muted small">Set these with environment variables in your compose file. See the README.</p></div>
        <div class="card"><h2>Notifications</h2>
          <p>${(st.channels = st.channels || []).length ? st.channels.map((c) => `<span class="pill ok">${esc(c)}</span>`).join(" ") : '<span class="muted">No channel configured.</span>'}</p>
          <p class="muted small">Supported: ntfy, Discord, Slack, Telegram, generic webhook. Keelwatch sends new findings at or above the configured severity, plus runtime alerts.</p>
          <button class="btn small" id="testn" ${st.channels.length ? "" : "disabled"}>Send test notification</button>
          <h2 style="margin-top:20px">Falco (optional)</h2>
          <p class="small">${st.falcoReady ? 'Ready. Point Falcosidekick at <code>' + esc(new URL("api/falco", document.baseURI).href) + '</code> with header <code>Authorization: Bearer &lt;KEELWATCH_FALCO_TOKEN&gt;</code>.' : 'Off. Set <code>KEELWATCH_FALCO_TOKEN</code> to accept Falcosidekick webhooks for kernel-level runtime detection.'}</p>
        </div>
      </div>
      <div class="card"><h2>Suppressed findings (${st.suppressed ? st.suppressed.length : 0})</h2><div class="list">
        ${st.suppressed && st.suppressed.length ? st.suppressed.map((x) => `<div class="row"><span class="pill info">muted</span><div class="t"><b>${esc(x.Title || x.ID)}</b><span>${esc(x.Target || "no longer detected")} · “${esc(x.Note)}”</span></div><button class="btn small" data-act="unsup" data-id="${esc(x.ID)}">Restore</button></div>`).join("") : '<div class="empty">Nothing suppressed.</div>'}
      </div></div>
      ${!ui.host && st.removedHosts && st.removedHosts.length ? `<div class="card"><h2>Removed hosts (${st.removedHosts.length})</h2><div class="list">${st.removedHosts.map((n) => `<div class="row"><span class="pill info">removed</span><div class="t"><b>${esc(n)}</b><span>Reports from this agent are refused. Restore it to accept them again.</span></div><button class="btn small" data-restore="${esc(n)}">Restore</button></div>`).join("")}</div></div>` : ""}
      ${ui.host ? `<div class="card"><h2>Remove this host</h2><p class="muted small">Deletes this host's data from the dashboard and refuses its agent's reports until restored.</p><button class="btn small" id="rm-host">Remove ${esc(ui.host)}</button></div>` : ""}
      <div class="card"><h2>Data</h2><div class="f-actions"><a class="btn small" href="${esc(withHost("/api/export").slice(1))}" download>Export latest report (JSON)</a><button class="btn small" id="logout">Sign out</button></div></div>`;
    const t = $("#testn"); if (t) t.onclick = async () => { try { await api("/api/notify/test", { method: "POST" }); toast("Test sent"); } catch (e) { toast("Failed: " + e.message); } };
    $("#logout").onclick = async () => { await api("/api/logout", { method: "POST" }); showLogin(); };
    const rm = $("#rm-host"); if (rm) rm.onclick = () => removeHost(ui.host);
    $$("[data-restore]", view).forEach((b) => b.onclick = async () => {
      await api(`/api/hosts/${encodeURIComponent(b.dataset.restore)}/restore`, { method: "POST" });
      toast(`Restored ${b.dataset.restore}. It reappears after its agent's next scan.`); renderSettings();
    });
    bindFindingActions(view);
  }

  // ---------- boot ----------
  // Under a base path (/keelwatch), keep the URL ending in "/" so hash links stay on this page.
  if (!location.pathname.endsWith("/")) history.replaceState(null, "", location.pathname + "/" + location.search + location.hash);
  async function start() {
    const s = await fetch("api/session", { credentials: "same-origin" }).then((r) => r.json());
    if (s.authRequired && !s.authenticated) { showLogin(); return; }
    $("#login").hidden = true; $("#app").hidden = false;
    await refresh();
    clearInterval(poll);
    poll = setInterval(() => { if (!document.hidden && !$("#modal").open && !document.activeElement.matches("input, select") && !$(".finding[open]")) refresh(); }, 10000);
  }
  start();
})();
