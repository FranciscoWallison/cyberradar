// Lista de CVEs filtrável no cliente (lê /data/vulns.json). Sem innerHTML com dados externos.
(function () {
  "use strict";
  const base = window.CR.base;
  const form = document.getElementById("filters");
  const tbody = document.querySelector("#cve-table tbody");
  const more = document.getElementById("more");
  const count = document.getElementById("result-count");
  const SEV = { CRITICAL: ["crítica", "critical"], HIGH: ["alta", "high"], MEDIUM: ["média", "medium"], LOW: ["baixa", "low"] };
  const PAGE = 100;
  let rows = [], shown = PAGE;

  // filtros iniciais pela URL (?q=CVE-...&k=1)
  const params = new URLSearchParams(location.search);
  for (const [k, v] of params) {
    const el = form.elements[k];
    if (!el) continue;
    if (el.type === "checkbox") el.checked = v === "1"; else el.value = v;
  }

  function td(text, cls) { const c = document.createElement("td"); if (cls) c.className = cls; c.append(text); return c; }
  function sevSpan(r) {
    const s = document.createElement("span");
    s.className = "sev sev-" + (r.s || "none").toLowerCase();
    s.textContent = r.s ? `${SEV[r.s] ? SEV[r.s][0] : r.s} ${r.c != null ? r.c.toFixed(1) : ""}` : "sem CVSS";
    return s;
  }

  function apply() {
    const f = form.elements;
    const q = f.q.value.trim().toLowerCase();
    const favs = window.CR.favs();
    const minP = Number(f.pr.value || 0);
    let list = rows.filter((r) => {
      if (f.k.checked && !r.k) return false;
      if (f.x.checked && !r.x) return false;
      if (r.pr < minP) return false;
      if (f.s.value === "-" ? r.s : (f.s.value && r.s !== f.s.value)) return false;
      const hay = [r.id, r.t, ...(r.v || []), ...(r.pd || [])].join(" ").toLowerCase();
      if (q && !q.split(/\s+/).every((w) => hay.includes(w))) return false;
      if (f.fav.checked && !window.CR.matchesFav(favs, hay)) return false;
      return true;
    });
    const o = f.o.value;
    const key = { pr: (r) => r.pr, p: (r) => r.p, e: (r) => r.e || 0, c: (r) => r.c || 0 }[o];
    list.sort((a, b) => (key(b) > key(a) ? 1 : key(b) < key(a) ? -1 : 0));
    count.textContent = `${list.length} resultado(s)`;
    tbody.textContent = "";
    const frag = document.createDocumentFragment();
    list.slice(0, shown).forEach((r) => {
      const tr = document.createElement("tr");
      tr.dataset.vendors = (r.v || []).join(" ");
      const a = document.createElement("a");
      a.href = r.d ? `${base}/cve/${r.id}/` : `https://nvd.nist.gov/vuln/detail/${r.id}`;
      if (!r.d) a.rel = "noopener";
      a.textContent = r.id;
      const c1 = td(a);
      if (r.k) { const b = document.createElement("span"); b.className = "badge k-kev"; b.textContent = "KEV"; c1.append(" ", b); }
      tr.append(c1, td(r.t || ""), td((r.pd || []).slice(0, 3).join(", ") || "—"), td(sevSpan(r)),
        td(r.e != null ? (r.e * 100).toFixed(1) + "%" : "—"), td(String(Math.round(r.pr)), "prio"), td(r.p || ""));
      if (favs.length && window.CR.matchesFav(favs, tr.dataset.vendors + " " + (r.pd || []).join(" "))) tr.classList.add("fav");
      frag.append(tr);
    });
    tbody.append(frag);
    more.hidden = list.length <= shown;
  }

  function renderFavs() {
    const ul = document.getElementById("fav-tags");
    const favs = window.CR.favs();
    document.getElementById("fav-count").textContent = favs.length;
    ul.textContent = "";
    favs.forEach((v) => {
      const li = document.createElement("li");
      const b = document.createElement("button");
      b.type = "button"; b.textContent = "×"; b.setAttribute("aria-label", "remover " + v);
      b.addEventListener("click", () => window.CR.removeFav(v));
      li.append(v, b); ul.append(li);
    });
  }

  form.addEventListener("submit", (e) => e.preventDefault());
  form.addEventListener("input", () => { shown = PAGE; apply(); });
  more.addEventListener("click", () => { shown += PAGE; apply(); });
  const ff = document.getElementById("fav-form");
  ff.addEventListener("submit", (e) => { e.preventDefault(); window.CR.addFav(ff.elements.fav.value); ff.reset(); });
  document.addEventListener("favs-changed", () => { renderFavs(); apply(); });
  renderFavs();

  fetch(base + "/data/vulns.json").then((r) => r.json()).then((data) => { rows = data; apply(); })
    .catch(() => { tbody.textContent = ""; tbody.append(Object.assign(document.createElement("tr"), { textContent: "Falha ao carregar dados." })); });
})();
