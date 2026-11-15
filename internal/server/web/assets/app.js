"use strict";
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];
  const view = $("#view");
  const CATS = { outdated: "Outdated images", credentials: "Credential leakage", config: "Configuration flaws", practices: "Best practices", errors: "Critical errors", runtime: "Security breaches" };
  const SEVS = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  let S = null;          // last /api/state
  let poll = null;
  const ui = { cat: "", sev: "", q: "", showSup: false, openRow: "" };

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
    const r = await fetch(path.replace(/^\//, ""), o); // relative: works under a base path
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
    try { S = await api("/api/state"); } catch { return; }
    const snap = S.snapshot;
    const open = snap ? snap.findings.filter((f) => !f.suppressed && SEV_RANK[f.severity] >= 3).length : 0;
    $("#nav-findings").textContent = open || "";
    $("#nav-alerts").textContent = S.openAlerts || "";
    $("#demo-badge").hidden = !S.demo;
    $("#version").textContent = "v" + S.version;
    const btn = $("#scan-btn");
    btn.disabled = S.scanning;
    btn.innerHTML = S.scanning ? '<span class="spin"></span>Scanning' : "Scan now";
    $("#scan-meta").textContent = snap
      ? `${snap.host.name || "docker"} · Docker ${snap.host.engineVersion} · scanned ${ago(snap.scannedAt)} in ${snap.durationMs < 1000 ? snap.durationMs + " ms" : (snap.durationMs / 1000).toFixed(1) + " s"}`
      : (S.scanning ? "First scan running…" : "Waiting for first scan…");
    render();
  }

  $("#scan-btn").addEventListener("click", async () => {
    await api("/api/scan", { method: "POST" });
    toast("Scan started");
    setTimeout(refresh, 600);
  });

  // ---------- routing ----------
  const routes = { overview: renderOverview, findings: renderFindings, containers: renderContainers, images: renderImages, runtime: renderRuntime, settings: renderSettings };
  const titles = { overview: "Overview", findings: "Findings", containers: "Containers", images: "Images", runtime: "Runtime", settings: "Settings" };
  function route() {
    const h = location.hash.replace(/^#\/?/, "");
    const [name, qs] = h.split("?");
    const r = routes[name] ? name : "overview";
    const p = new URLSearchParams(qs || "");
    if (r === "findings" && p.has("cat")) { ui.cat = p.get("cat"); ui.sev = p.get("sev") || ""; }
    return r;
  }
  window.addEventListener("hashchange", render);
  function render() {
    const r = route();
    $$(".side a").forEach((a) => a.classList.toggle("active", a.dataset.route === r));
    $("#page-title").textContent = titles[r];
    document.title = titles[r] + " · Keelwatch";
    if (r === "runtime" || r === "settings") { routes[r](); return; }
    if (!S || !S.snapshot) { view.innerHTML = `<div class="card empty">${S && S.scanning ? '<span class="spin"></span>Running the first scan. This takes a few seconds, longer if registry checks are slow.' : "No scan yet. Check that Keelwatch can reach the Docker API (see container logs)."}</div>`; return; }
    routes[r]();
  }

  // ---------- overview ----------
  function dial(score) {
    const r = 52, c = 2 * Math.PI * r, arc = c * 0.75, v = arc * score / 100;
    return `<div class="dial"><svg viewBox="0 0 120 120" aria-hidden="true"><circle class="track" cx="60" cy="60" r="${r}" stroke-dasharray="${arc} ${c}"/><circle class="val" cx="60" cy="60" r="${r}" stroke="${scoreColor(score)}" stroke-dasharray="${v} ${c}"/></svg><div class="num"><div><b>${score}</b><span>of 100</span></div></div></div>`;
  }
  function trend(hist) {
    if (!hist || hist.length < 2) return `<div class="empty small">The trend appears after a few scans.</div>`;
    const pts = hist.slice(-60), W = 300, H = 100;
    const xs = (i) => (i / (pts.length - 1)) * W, ys = (s) => H - (s / 100) * H;
    const d = pts.map((p, i) => `${i ? "L" : "M"}${xs(i).toFixed(1)},${ys(p.score).toFixed(1)}`).join("");
    const first = pts[0], last = pts[pts.length - 1], delta = last.score - first.score;
    return `<div class="trend"><svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Score trend">
      ${[25, 50, 75].map((g) => `<line class="grid" x1="0" x2="${W}" y1="${ys(g)}" y2="${ys(g)}"/>`).join("")}
      <path class="area" d="${d}L${W},${H}L0,${H}Z"/><path class="line" d="${d}"/></svg>
      <div class="muted small">${pts.length} scans since ${new Date(first.time).toLocaleString()} · ${delta === 0 ? "no change" : (delta > 0 ? "▲ " : "▼ ") + Math.abs(delta) + " points"}</div></div>`;
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
    <section class="grid-2">
      <div class="card"><h2>Fix first</h2><div class="list">${top.length ? top.map((f) => `
        <a class="row" href="#/findings?cat=${f.category}" style="text-decoration:none">${pill(f.severity, f.severity === "critical")}<div class="t"><b>${esc(f.title)}</b><span>${esc(f.target)} · ${CATS[f.category]}</span></div><span class="muted small hide-sm">${ago(f.firstSeen)}</span></a>`).join("") : '<div class="empty">Nothing to fix. Nice.</div>'}</div></div>
      <div class="card"><h2>Containers at risk</h2><div class="list">${risky.map((k) => `
        <a class="row" href="#/containers" style="text-decoration:none"><span class="score-badge" style="background:color-mix(in srgb, ${scoreColor(k.score)} 18%, transparent);color:${scoreColor(k.score)}">${k.score}</span><div class="t"><b>${esc(k.name)}</b><span>${esc(k.image)}</span></div>${counts(k.counts)}</a>`).join("")}</div>
        ${(S.recentAlerts || []).length ? `<h2 style="margin-top:18px">Latest runtime alerts</h2><div class="list">${S.recentAlerts.slice(0, 3).map((a) => `<a class="row" href="#/runtime" style="text-decoration:none">${pill(a.severity)}<div class="t"><b>${esc(a.title)}</b><span>${esc(a.detail)}</span></div><span class="muted small">${ago(a.time)}</span></a>`).join("")}</div>` : ""}
      </div>
    </section>
    ${s.errors && s.errors.length ? `<div class="card"><h2>Scan warnings</h2>${s.errors.map((e) => `<div class="muted small">${esc(e)}</div>`).join("")}</div>` : ""}`;
  }
  function counts(c) {
    c = c || {};
    return `<div class="counts" title="critical / high / medium / low">${["critical", "high", "medium", "low"].map((k) => `<span class="c-${k}${c[k] ? "" : " z"}">${c[k] || 0}</span>`).join("")}</div>`;
  }

  // ---------- findings ----------
  function findingHTML(f) {
    return `<details class="finding${f.suppressed ? " suppressed" : ""}" data-id="${esc(f.id)}">
      <summary>${pill(f.severity, f.severity === "critical")}<div class="t"><b>${esc(f.title)}</b><span>${esc(f.target)} · ${CATS[f.category]}${f.cis ? " · CIS " + esc(f.cis) : ""}${f.suppressed ? " · suppressed" : ""}</span></div><span class="muted small hide-sm">since ${ago(f.firstSeen)}</span></summary>
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
    const list = all.filter((f) => (ui.showSup || !f.suppressed) && (!ui.cat || f.category === ui.cat) && (!ui.sev || f.severity === ui.sev) &&
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
    </div>
    <div>${list.length ? list.map(findingHTML).join("") : '<div class="card empty">No findings match these filters.</div>'}</div>`;
    $$(".chip", view).forEach((b) => b.onclick = () => { ui.cat = b.dataset.cat; history.replaceState(null, "", "#/findings"); renderFindings(); });
    $("#q").oninput = (e) => { ui.q = e.target.value; const pos = e.target.selectionStart; renderFindings(); const n = $("#q"); n.focus(); n.setSelectionRange(pos, pos); };
    $("#sev").onchange = (e) => { ui.sev = e.target.value; renderFindings(); };
    $("#sup").onchange = (e) => { ui.showSup = e.target.checked; renderFindings(); };
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
      <div class="card"><h2>Data</h2><div class="f-actions"><a class="btn small" href="api/export" download>Export latest report (JSON)</a><button class="btn small" id="logout">Sign out</button></div></div>`;
    const t = $("#testn"); if (t) t.onclick = async () => { try { await api("/api/notify/test", { method: "POST" }); toast("Test sent"); } catch (e) { toast("Failed: " + e.message); } };
    $("#logout").onclick = async () => { await api("/api/logout", { method: "POST" }); showLogin(); };
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
