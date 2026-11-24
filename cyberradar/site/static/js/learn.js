// Flashcards e questões com repetição espaçada FSRS (ts-fsrs 5.2.3, MIT, embutido em /static/vendor).
import { fsrs, generatorParameters, createEmptyCard, Rating } from "../vendor/ts-fsrs-5.2.3.mjs";

const base = document.body.dataset.base || "";
const scheduler = fsrs(generatorParameters({ enable_fuzz: true, request_retention: 0.9 }));
const KEY = "cr.learn.v1";
const $ = (id) => document.getElementById(id);

function loadState() {
  try { return JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { return {}; }
}
function saveState(st) {
  try { localStorage.setItem(KEY, JSON.stringify(st)); } catch (e) { /* armazenamento indisponível */ }
}
function revive(c) {
  return { ...c, due: new Date(c.due), last_review: c.last_review ? new Date(c.last_review) : undefined };
}

let state = loadState();
state.cards ??= {}; state.xp ??= 0; state.streak ??= 0; state.lastDay ??= "";
let deck = null, current = null;

function stats() {
  const now = new Date();
  const items = deck ? deck.items : [];
  const due = items.filter((it) => { const c = state.cards[it.id]; return !c || new Date(c.due) <= now; }).length;
  const seen = items.filter((it) => state.cards[it.id]).length;
  $("learn-stats").textContent = `${due} para revisar agora · ${seen}/${items.length} vistos`;
  $("xp").textContent = state.xp; $("streak").textContent = state.streak;
}

function nextItem() {
  const now = new Date();
  const items = deck.items;
  const dueSeen = items.filter((it) => state.cards[it.id] && new Date(state.cards[it.id].due) <= now)
    .sort((a, b) => new Date(state.cards[a.id].due) - new Date(state.cards[b.id].due));
  if (dueSeen.length) return dueSeen[0];
  return items.find((it) => !state.cards[it.id]) || null;
}

function show() {
  stats();
  current = nextItem();
  $("card").hidden = !current; $("done").hidden = !!current;
  if (!current) return;
  $("card-meta").textContent = [current.type === "flashcard" ? "Cartão" : "Questão",
    ...(current.objectives || []).map((o) => `${o.exam} ${o.code}`)].join(" · ");
  $("card-prompt").textContent = current.prompt;
  const opts = $("card-options"); opts.textContent = "";
  $("card-answer").hidden = true; $("grades").hidden = true; $("reveal").hidden = false;
  if (Array.isArray(current.options) && current.options.length) {
    $("reveal").hidden = true;
    current.options.forEach((txt, i) => {
      const b = document.createElement("button"); b.type = "button"; b.textContent = txt;
      b.addEventListener("click", () => answer(i, b));
      opts.append(b);
    });
  }
}

function answer(i, btn) {
  const correct = Array.isArray(current.answer) ? current.answer.includes(i) : current.answer === i;
  [...$("card-options").children].forEach((b, j) => {
    b.disabled = true;
    const ok = Array.isArray(current.answer) ? current.answer.includes(j) : current.answer === j;
    if (ok) b.classList.add("right"); else if (b === btn) b.classList.add("wrong");
  });
  reveal(correct ? null : Rating.Again);
}

function reveal(forced) {
  const a = $("card-answer"); a.textContent = "";
  if (current.type === "flashcard" && typeof current.answer === "string") {
    const p = document.createElement("p"); const s = document.createElement("strong"); s.textContent = current.answer; p.append(s); a.append(p);
  }
  const ex = document.createElement("p"); ex.textContent = current.explanation; a.append(ex);
  (current.sources || []).slice(0, 2).forEach((u) => {
    const l = document.createElement("a"); l.href = u; l.rel = "noopener"; l.textContent = "Fonte"; a.append(l, " ");
  });
  a.hidden = false; $("reveal").hidden = true;
  if (forced === Rating.Again) { grade(Rating.Again, true); return; }
  $("grades").hidden = false;
}

function grade(g, auto) {
  const now = new Date();
  const prev = state.cards[current.id] ? revive(state.cards[current.id]) : createEmptyCard(now);
  const { card } = scheduler.next(prev, now, g);
  state.cards[current.id] = card;
  state.xp += g >= Rating.Good ? 10 : 3;
  const today = now.toISOString().slice(0, 10);
  if (state.lastDay !== today) {
    const y = new Date(now - 864e5).toISOString().slice(0, 10);
    state.streak = state.lastDay === y ? state.streak + 1 : 1;
    state.lastDay = today;
  }
  saveState(state);
  if (auto) { const b = document.createElement("button"); b.type = "button"; b.textContent = "Próximo"; b.addEventListener("click", show); $("card-answer").append(b); stats(); }
  else show();
}

async function loadDeck(slug) {
  const opt = document.querySelector(`#deck-select option[value="${CSS.escape(slug)}"]`);
  $("deck-desc").textContent = opt ? opt.dataset.desc || "" : "";
  deck = await (await fetch(`${base}/data/learning/${slug}.json`)).json();
  show();
}

$("reveal").addEventListener("click", () => reveal(null));
document.querySelectorAll("#grades button").forEach((b) => b.addEventListener("click", () => grade(Number(b.dataset.g), false)));
$("reset").addEventListener("click", () => { if (confirm("Apagar todo o progresso salvo neste navegador?")) { state = { cards: {}, xp: 0, streak: 0, lastDay: "" }; saveState(state); show(); } });
const sel = $("deck-select");
if (sel && sel.value) { sel.addEventListener("change", () => loadDeck(sel.value)); loadDeck(sel.value); }
