// Utilitários comuns: favoritos ("minhas tecnologias") salvos só no navegador.
(function () {
  "use strict";
  const KEY = "cr.favs";
  const base = document.body.dataset.base || "";

  function load() {
    try { return JSON.parse(localStorage.getItem(KEY) || "[]").filter(Boolean); } catch (e) { return []; }
  }
  function save(list) {
    try { localStorage.setItem(KEY, JSON.stringify([...new Set(list)].slice(0, 60))); } catch (e) { /* modo privado */ }
    document.dispatchEvent(new CustomEvent("favs-changed"));
  }
  function matches(favs, text) {
    const t = (text || "").toLowerCase();
    return favs.some((f) => t.includes(f));
  }
  window.CR = { base, favs: load, saveFavs: save, matchesFav: matches,
    addFav(v) { v = (v || "").trim().toLowerCase(); if (v) save([...load(), v]); },
    removeFav(v) { save(load().filter((x) => x !== v)); } };

  // destaca linhas de tabela de tecnologias favoritas
  function highlight() {
    const favs = load();
    document.querySelectorAll("tr[data-vendors]").forEach((tr) => {
      tr.classList.toggle("fav", favs.length > 0 && matches(favs, tr.dataset.vendors + " " + tr.textContent));
    });
  }
  // botão "acompanhar" nas páginas de CVE
  document.querySelectorAll(".fav-btn").forEach((b) => {
    const v = b.dataset.fav;
    if (!v) { b.hidden = true; return; }
    const sync = () => { const on = load().includes(v); b.textContent = (on ? "★ Acompanhando " : "☆ Acompanhar ") + v; };
    b.addEventListener("click", () => { load().includes(v) ? CR.removeFav(v) : CR.addFav(v); sync(); });
    sync();
  });
  // caixa "minhas tecnologias" no painel
  async function favBox() {
    const box = document.getElementById("fav-box");
    const favs = load();
    if (!box || !favs.length) return;
    try {
      const rows = await (await fetch(base + "/data/vulns.json")).json();
      const hits = rows.filter((r) => matches(favs, [r.id, r.t, ...(r.v || []), ...(r.pd || [])].join(" ")))
        .sort((a, b) => b.pr - a.pr).slice(0, 12);
      const list = document.getElementById("fav-list");
      list.textContent = "";
      if (!hits.length) { list.textContent = "Nada recente para: " + favs.join(", "); }
      hits.forEach((r) => {
        const p = document.createElement("div");
        const a = document.createElement("a");
        a.href = r.d ? `${base}/cve/${r.id}/` : `https://nvd.nist.gov/vuln/detail/${r.id}`;
        a.textContent = r.id;
        p.append(a, ` — ${(r.pd || []).slice(0, 2).join(", ")} · prioridade ${Math.round(r.pr)}${r.k ? " · KEV" : ""}`);
        list.append(p);
      });
      box.hidden = false;
    } catch (e) { /* sem dados */ }
  }
  highlight(); favBox();
  document.addEventListener("favs-changed", highlight);
})();

// Tradução no próprio navegador (Chrome 138+ — Translator API, roda no dispositivo, sem custo para o site).
(function () {
  "use strict";
  const items = document.querySelectorAll("article[data-translate]");
  if (!items.length || !("Translator" in self)) return;
  let translator = null;
  async function getTranslator() {
    if (translator) return translator;
    const opts = { sourceLanguage: "en", targetLanguage: "pt" };
    const av = await self.Translator.availability(opts);
    if (av === "unavailable") throw new Error("indisponível");
    translator = await self.Translator.create(opts);
    return translator;
  }
  items.forEach((art) => {
    const btn = art.querySelector(".tr-btn");
    if (!btn) return;
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      btn.disabled = true; btn.textContent = "Traduzindo…";
      try {
        const t = await getTranslator();
        for (const el of art.querySelectorAll(".st-title, p.muted[lang='en']")) {
          el.textContent = await t.translate(el.textContent);
          el.setAttribute("lang", "pt-BR");
        }
        btn.textContent = "Traduzido automaticamente pelo seu navegador";
      } catch (e) {
        btn.textContent = "Tradução indisponível neste navegador"; 
      }
    });
  });
})();
