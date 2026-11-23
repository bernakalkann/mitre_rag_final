"use strict";

const byId = (id) => document.getElementById(id);
const form = byId("analysis-form");
const incident = byId("incident");
const results = byId("sonuclar");
const sourceGroups = byId("source-groups");
const desktopEvidence = byId("kanit-paneli");
const wide = matchMedia("(min-width: 1100px)");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const duration = new Intl.NumberFormat("tr-TR", { maximumFractionDigits: 1 });
const sourceInfo = {
  attack: { name: "MITRE ATT&CK", purpose: "Olay hangi tekniklerle ilişkili olabilir?", label: "TEKNİK" },
  nist: { name: "NIST CSF 2.0", purpose: "Hangi savunma başlıklarını inceleyebilirim?", label: "ALT KATEGORİ" },
};
const modeLabels = {
  semantic: "Anlamsal arama", bm25: "Anahtar kelime (BM25)", hybrid: "Hibrit arama", rag: "Kaynaklı açıklama",
};
const scores = {
  semantic: { label: "Benzerlik", detail: "Kosinüs benzerliği olay ile kaynak metni arasındaki anlamsal yakınlığı gösterir.", digits: 3 },
  bm25: { label: "BM25 skoru", detail: "BM25, ortak terimlerin belge sıklığını ve belge uzunluğunu hesaba katar.", digits: 3 },
  hybrid: { label: "RRF skoru", detail: "Hibrit arama, BM25 ve anlamsal aramadaki sıraları birleştirir.", digits: 5 },
};
const functions = {
  GV: "GOVERN", ID: "IDENTIFY", PR: "PROTECT", DE: "DETECT", RS: "RESPOND", RC: "RECOVER",
};

let examples = {};
let modelReady = null;
let modelName = "qwen3:8b";
let lastResult = null;
let selected = null;
let running = false;
let exportUrl = null;
const rows = new Map();
const mapButtons = new Map();

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function button(label, callback, className = "text-button") {
  const node = element("button", label, className);
  node.type = "button";
  node.addEventListener("click", callback);
  return node;
}

function officialLink(url, label) {
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    const link = element("a", label + " ↗");
    link.href = parsed.href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.setAttribute("aria-label", label + " (yeni sekmede açılır)");
    return link;
  } catch {
    return null;
  }
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "İstek tamamlanamadı.");
  return data;
}

function mode() {
  return form.elements.mode.value;
}

function updateModelWarning() {
  byId("model-warning").hidden = mode() !== "rag" || modelReady !== false;
}

function updateInput() {
  byId("char-count").textContent = `${Array.from(incident.value).length} karakter`;
  if (lastResult) byId("changed").hidden = incident.value === lastResult.export.query;
  if (!incident.value.trim()) return;
  incident.removeAttribute("aria-invalid");
  incident.setAttribute("aria-describedby", "composer-help");
  byId("input-error").hidden = true;
}

function renderError(target, message, detail, retry = true) {
  target.replaceChildren(element("p", message));
  if (detail) {
    const technical = element("details");
    technical.append(element("summary", "Teknik ayrıntı"), element("p", detail));
    target.append(technical);
  }
  if (retry) target.append(button("Tekrar dene", () => form.requestSubmit(), "secondary"));
  target.hidden = false;
}

function setBusy(busy) {
  running = busy;
  byId("submit").disabled = busy;
  byId("examples").disabled = busy || !Object.keys(examples).length;
  for (const card of byId("example-cards").children) card.disabled = busy;
  byId("limit").disabled = busy;
  for (const option of form.elements.mode) option.disabled = busy;
  incident.readOnly = busy;
  byId("spinner").hidden = !busy;
  byId("submit-label").textContent = busy ? "Analiz ediliyor…" : "Analiz et";
  results.setAttribute("aria-busy", String(busy));
  byId("result-content").inert = busy;
  byId("previous").hidden = !busy || !lastResult;
  byId("previous").textContent = busy ? "Önceki sonuçlar · yeni analiz sürüyor" : "";
}

function showPrevious() {
  if (!lastResult) return;
  byId("previous").textContent = "Önceki analiz";
  byId("previous").hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (running) return;

  const text = incident.value;
  if (!text.trim()) {
    incident.setAttribute("aria-invalid", "true");
    incident.setAttribute("aria-describedby", "composer-help input-error");
    byId("input-error").hidden = false;
    incident.focus();
    return;
  }
  const requestedMode = mode();
  const k = Number(byId("limit").value);
  byId("analysis-error").hidden = true;
  setBusy(true);
  const started = performance.now();
  const progress = () => {
    const elapsed = Math.floor((performance.now() - started) / 1000);
    byId("analysis-status").textContent = `ATT&CK ve NIST aranıyor · ${elapsed} sn`
      + (requestedMode === "rag" ? " · Yerel model yorumu daha uzun sürebilir." : "");
  };
  progress();
  const timer = setInterval(progress, 1000);
  let data;
  try {
    data = await fetchJson("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: requestedMode, k }),
    });
  } catch (error) {
    renderError(byId("analysis-error"), error instanceof TypeError
      ? "Analiz sunucusuna ulaşılamadı. Sunucunun çalıştığını kontrol edin." : "Analiz tamamlanamadı.", error.message);
  } finally {
    clearInterval(timer);
    setBusy(false);
  }

  if (!data?.export) {
    if (data) renderError(byId("analysis-error"), "Analiz tamamlanamadı.",
      [data.attack.error, data.nist.error].filter(Boolean).join(" · "));
    byId("analysis-status").textContent = "";
    showPrevious();
    return;
  }

  lastResult = data;
  renderResults(data, requestedMode, k);
  const status = [data.attack, data.nist, data.explanation].some((source) => source?.status === "error")
    ? "Analiz kısmen tamamlandı" : "Analiz tamamlandı";
  byId("analysis-status").textContent = `${status} · ATT&CK ${data.attack.items.length} aday · NIST ${data.nist.items.length} aday`;
  results.dispatchEvent(new Event("analysisCompleted"));
});

results.addEventListener("analysisCompleted", () => {
  const heading = byId("result-title");
  const top = heading.parentElement;
  top.classList.remove("flash");
  requestAnimationFrame(() => {
    top.classList.add("flash");
    heading.scrollIntoView({ block: "start", behavior: reducedMotion.matches ? "auto" : "smooth" });
    heading.focus({ preventScroll: true });
  });
});

incident.addEventListener("input", updateInput);
incident.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    form.requestSubmit();
  }
});

byId("mode-options").addEventListener("change", updateModelWarning);
byId("examples").addEventListener("change", (event) => {
  const label = event.target.value;
  event.target.value = "";
  loadExample(label);
});

function loadExample(label) {
  const text = examples[label];
  if (running || !text) return;
  if (incident.value.trim() && incident.value !== text &&
      !window.confirm("Mevcut olay açıklaması örnekle değiştirilsin mi?")) return;
  incident.value = text;
  updateInput();
  incident.focus();
}

function scoreInfo(kind) {
  return scores[kind === "attack" ? lastResult.export.method : "semantic"] ?? scores.semantic;
}

function rowData(kind, item, index, total) {
  if (kind === "attack") {
    const tactics = [...new Set((item.tactics || []).map((value) => value.replaceAll("-", " ").replace(/\b\w/g, (c) => c.toUpperCase())))];
    const parent = item.parent_attack_id;
    return { kind, code: item.attack_id, title: item.name, rank: index + 1, total,
      score: item.score ?? item.retrieval_score, url: item.source_url, filterValues: tactics,
      body: item.evidence_excerpt ?? item.excerpt,
      fields: [["Taktik", tactics.join(", ")], ["Üst teknik", parent],
        ["Anlamsal sıra", item.component_ranks?.semantic], ["BM25 sırası", item.component_ranks?.bm25]],
      subtitle: [tactics.join(", "), parent && `Üst teknik: ${parent}`].filter(Boolean).join(" · ") };
  }
  const fn = functions[item.id.slice(0, 2)] || item.function;
  return { kind, code: item.id, title: item.category, rank: index + 1, total, score: item.score,
    url: lastResult.export.nist_csf?.source_document || lastResult.export.nist_csf?.source_url,
    body: item.description, filterValues: fn ? [fn] : [],
    fields: [["İşlev", fn], ["Kategori", item.category]], subtitle: fn };
}

function rowKey(row) {
  return `${row.kind}:${row.code}`;
}

function scoreText(score, kind) {
  return Number.isFinite(score) ? score.toFixed(scoreInfo(kind).digits) : "—";
}

function renderSource(kind, source) {
  const info = sourceInfo[kind];
  const section = element("section", undefined, `source-section source-${kind}`);
  const header = element("div", undefined, "source-title");
  const name = element("div");
  name.append(element("h3", info.name), element("p", info.purpose));
  const count = element("span", `${source.items.length} aday`, "count mono");
  count.id = `${kind}-visible-count`;
  header.append(name, count);
  section.append(header);
  if (kind === "nist" && (lastResult.explanation || ["bm25", "hybrid"].includes(lastResult.export.method))) {
    section.append(element("p", "NIST sonuçları bağımsız anlamsal aramadan gelir.", "source-note"));
  }

  if (source.status === "error") {
    const error = element("div", undefined, "source-error");
    const other = kind === "attack" ? "nist" : "attack";
    const message = `${info.name} araması tamamlanamadı.`;
    renderError(error, lastResult[other].status === "ok"
      ? `${message} ${sourceInfo[other].name} sonuçları kullanılabilir.` : message, source.error);
    section.append(error);
  } else if (source.status === "empty") {
    section.append(element("p", "Bu kaynakta aday bulunamadı."),
      element("p", "Olayı somut davranışlarla yazmayı deneyin: süreç, komut veya etkilenen sistem.", "muted"));
  } else {
    const columns = element("div", undefined, "column-head");
    for (const title of ["Sıra", "Kod", "Ad"]) columns.append(element("span", title));
    const help = element("details", undefined, "score-help");
    const score = scoreInfo(kind);
    help.append(element("summary", score.label + " ⓘ"), element("p",
      `${score.detail} Skoru yalnızca bu kaynak içindeki adayları sıralamak için kullanın.`));
    columns.append(help);
    section.append(columns);
    const list = element("ol", undefined, "candidate-list");
    const buttons = [];
    for (const [index, item] of source.items.entries()) {
      const row = rowData(kind, item, index, source.items.length);
      const key = rowKey(row);
      const li = element("li");
      const trigger = button(undefined, () => selectRow(key, true), "candidate");
      const title = element("span", row.title, "title");
      title.title = row.title;
      trigger.append(element("span", row.rank, "rank mono"), element("code", row.code, "code mono"),
        title, element("span", scoreText(row.score, kind), "score mono"));
      if (row.subtitle) trigger.append(element("small", row.subtitle));
      rows.set(key, { row, li, trigger });
      buttons.push(trigger);
      li.append(trigger);
      list.append(li);
    }
    list.addEventListener("keydown", (event) => {
      if (!["ArrowUp", "ArrowDown"].includes(event.key)) return;
      const visibleButtons = buttons.filter((candidate) => !candidate.parentElement.hidden);
      const index = visibleButtons.indexOf(event.target);
      if (index < 0) return;
      event.preventDefault();
      visibleButtons[Math.min(visibleButtons.length - 1, Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)))].focus();
    });
    section.append(list);
  }
  return section;
}

function copyCode(code, status) {
  navigator.clipboard.writeText(code).then(() => {
    status.textContent = "Kopyalandı";
    setTimeout(() => { status.textContent = ""; }, 2000);
  }).catch(() => { status.textContent = "Kopyalanamadı"; });
}

function renderEvidence(row) {
  const info = sourceInfo[row.kind];
  const panel = element("article", undefined, `evidence-card source-${row.kind}`);
  const title = element("h3");
  title.append(element("code", row.code), document.createTextNode(" · " + row.title));
  panel.append(element("p", `${info.name} · ${info.label}`, "evidence-label"), title,
    element("p", `Sıra ${row.rank} / ${row.total} · ${scoreInfo(row.kind).label} ${scoreText(row.score, row.kind)}`, "evidence-meta"));
  const fields = element("dl");
  for (const [label, value] of row.fields) {
    if (!value) continue;
    const field = element("div");
    field.append(element("dt", label), element("dd", value));
    fields.append(field);
  }
  if (fields.childElementCount) panel.append(fields);
  const link = officialLink(row.url, row.kind === "attack" ? "ATT&CK’te aç" : "NIST yayınında aç");
  if (link) panel.append(link);

  if (row.body) {
    const source = element("section", undefined, "source-content");
    const body = element("p", undefined, "source-text");
    if (row.kind === "nist") body.lang = "en";
    const raw = row.body.replace(/\[([^\]]+)\]\(https?:\/\/[^)]+\)/g, "$1");
    for (const [i, segment] of raw.split(/(\(Citation:[^)]+\))/g).entries()) {
      body.append(i % 2 ? element("span", segment) : document.createTextNode(segment));
    }
    source.append(element("h4", `Kaynak metni · ${info.name}`), body);
    panel.append(source);
  }

  const match = row.kind === "attack" && lastResult.explanation?.sources.find((item) => item.attack_id === row.code);
  if (match) {
    const comment = element("section", undefined, "candidate-comment");
    comment.append(element("h4", "Modelin bu aday için açıklaması"), element("p", match.explanation));
    if (match.evidence_quote) comment.append(element("blockquote", match.evidence_quote, "source-text"));
    panel.append(comment);
  }
  const copy = element("div", undefined, "copy-row");
  const status = element("span");
  status.setAttribute("role", "status");
  copy.append(button("Kodu kopyala", () => copyCode(row.code, status)), status);
  panel.append(copy);
  return panel;
}

function renderEvidenceMap() {
  const map = byId("evidence-map");
  const branches = byId("map-branches");
  mapButtons.clear();
  branches.replaceChildren();
  map.hidden = rows.size === 0;

  for (const [kind, source] of Object.entries(sourceInfo)) {
    const candidates = Array.from(rows).filter(([, entry]) => entry.row.kind === kind);
    if (!candidates.length) continue;

    const branch = element("div", undefined, `map-branch source-${kind}`);
    const heading = element("h4", source.name, "map-source");
    const list = element("ul", undefined, "map-nodes");
    list.setAttribute("aria-label", source.name + " adayları");
    for (const [key, { row }] of candidates) {
      const node = button(undefined, () => {
        selectRow(key);
        const panel = wide.matches ? desktopEvidence : rows.get(key).li.querySelector(".evidence-inline");
        const title = panel?.querySelector("h3");
        if (!title) return;
        const bounds = title.getBoundingClientRect();
        // Move focus only when we need to reveal evidence outside the viewport.
        if (bounds.top < 100 || bounds.bottom > window.innerHeight) {
          title.tabIndex = -1;
          title.scrollIntoView({ block: "center", behavior: reducedMotion.matches ? "auto" : "smooth" });
          title.focus({ preventScroll: true });
        }
      }, "map-node");
      node.setAttribute("aria-label", `${source.name} · ${row.code} · ${row.title}`);
      node.append(element("code", row.code), element("span", row.title));
      mapButtons.set(key, node);
      const item = element("li");
      item.append(node);
      list.append(item);
    }
    branch.append(heading, list);
    branches.append(branch);
  }
}

function applySourceFilter(kind, value) {
  let firstVisible = null;
  let visible = 0;
  let total = 0;
  for (const [key, { row, li }] of rows) {
    if (row.kind !== kind) continue;
    total += 1;
    const show = value === null || row.filterValues.includes(value);
    li.hidden = !show;
    const node = mapButtons.get(key);
    if (node) node.parentElement.hidden = !show;
    if (show) {
      firstVisible ??= key;
      visible += 1;
    }
  }
  for (const option of byId(`${kind}-filter-options`).children) {
    option.setAttribute("aria-pressed", String(option.dataset.filterValue === (value ?? "")));
  }
  const count = value === null ? `${total} aday` : `${visible} / ${total} aday`;
  byId(`${kind}-visible-count`).textContent = count;
  byId(`${kind}-filter-status`).textContent = `${count} gösteriliyor`;
  const current = rows.get(selected);
  if (current?.row.kind === kind && current.li.hidden) selectRow(wide.matches ? firstVisible : null);
}

function renderSourceFilter(kind) {
  const section = byId(`${kind}-filter`);
  const options = byId(`${kind}-filter-options`);
  const counts = new Map();
  let total = 0;
  options.replaceChildren();
  for (const { row } of rows.values()) {
    if (row.kind !== kind) continue;
    total += 1;
    for (const value of row.filterValues) counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  section.hidden = counts.size === 0;
  if (section.hidden) return;

  const sorted = [...counts].sort(([a, countA], [b, countB]) => countB - countA || a.localeCompare(b));
  for (const [value, count] of [[null, total], ...sorted]) {
    const option = button(`${value ?? "Tümü"} · ${count}`, () => applySourceFilter(kind, value), "source-filter-option");
    option.dataset.filterValue = value ?? "";
    options.append(option);
  }
  applySourceFilter(kind, null);
}

function selectRow(key, toggle = false) {
  const entryToSelect = rows.get(key);
  if (entryToSelect?.li.hidden) applySourceFilter(entryToSelect.row.kind, null);
  selected = !wide.matches && toggle && selected === key ? null : key;
  for (const [id, node] of mapButtons) {
    node.setAttribute("aria-pressed", String(id === selected));
    if (wide.matches) node.setAttribute("aria-controls", "kanit-paneli");
    else node.removeAttribute("aria-controls");
  }
  desktopEvidence.replaceChildren();
  for (const [id, entry] of rows) {
    entry.li.querySelector(".evidence-inline")?.remove();
    entry.trigger.removeAttribute("aria-pressed");
    entry.trigger.removeAttribute("aria-expanded");
    if (wide.matches) {
      entry.trigger.setAttribute("aria-pressed", String(id === selected));
      entry.trigger.setAttribute("aria-controls", "kanit-paneli");
    } else {
      entry.trigger.setAttribute("aria-expanded", String(id === selected));
      entry.trigger.removeAttribute("aria-controls");
    }
  }
  const entry = rows.get(selected);
  if (!entry) return;
  const panel = renderEvidence(entry.row);
  if (wide.matches) {
    desktopEvidence.append(panel);
    desktopEvidence.scrollTop = 0;
  } else {
    panel.classList.add("evidence-inline");
    panel.id = "satir-kaniti";
    entry.trigger.setAttribute("aria-controls", panel.id);
    mapButtons.get(selected)?.setAttribute("aria-controls", panel.id);
    entry.li.append(panel);
  }
}

function clampToggle(text, control, lines) {
  control.setAttribute("aria-expanded", "false");
  control.textContent = "Tamamını göster";
  text.classList.add("clamped");
  requestAnimationFrame(() => {
    const computed = parseFloat(getComputedStyle(text).lineHeight);
    control.hidden = text.scrollHeight <= computed * lines + 1;
  });
  control.onclick = () => {
    const expanded = text.classList.toggle("clamped") === false;
    control.setAttribute("aria-expanded", String(expanded));
    control.textContent = expanded ? "Daha az göster" : "Tamamını göster";
  };
}

function renderModel(explanation) {
  const block = byId("model-block");
  block.replaceChildren();
  block.hidden = !explanation;
  if (!explanation) return;

  const title = element("h3", `Model yorumu · ${modelName} (yerel, Ollama)`);
  title.id = "model-title";
  block.append(title);
  if (explanation.status === "error") {
    const failure = element("div");
    renderError(failure, "Model yorumu üretilemedi. Aday sonuçları kullanılabilir.", explanation.error);
    block.append(failure);
    return;
  }

  const text = element("p", explanation.text, "model-text");
  text.id = "model-text";
  const expand = button("Tamamını göster", () => {});
  expand.setAttribute("aria-controls", text.id);
  block.append(element("p", "Yerel modelin ATT&CK kaynaklarına dayalı yorumu.", "muted"), text, expand);
  clampToggle(text, expand, 8);

  if (explanation.additional_data_needed?.length) {
    const extra = element("ul");
    for (const item of explanation.additional_data_needed) extra.append(element("li", item));
    block.append(element("p", "İnceleme için ek bilgiler", "muted"), extra);
  }
  if (explanation.sources.length) {
    const citations = element("p");
    citations.append(element("span", "Dayandığı kaynaklar: ", "muted"));
    for (const source of explanation.sources) {
      const key = `attack:${source.attack_id}`;
      const control = rows.has(key)
        ? button(source.attack_id, () => selectRow(key), "text-button mono")
        : officialLink(source.source_url, source.attack_id);
      if (control) citations.append(control);
    }
    block.append(citations);
  }
}

function renderResults(data, requestedMode, k) {
  rows.clear();
  sourceGroups.replaceChildren(renderSource("attack", data.attack), renderSource("nist", data.nist));
  renderEvidenceMap();
  renderSourceFilter("attack");
  renderSourceFilter("nist");
  results.hidden = false;
  byId("skip-results").hidden = false;
  byId("composer").classList.add("compact");
  byId("source-preview").hidden = true;
  incident.rows = 3;
  incident.style.removeProperty("height");
  byId("workspace-empty").hidden = true;
  const label = modeLabels[requestedMode];
  const elapsed = data.duration_ms < 100 ? "<0,1" : duration.format(data.duration_ms / 1000);
  byId("result-meta").textContent = `${label} · Kaynak başına en çok ${k} aday · ${elapsed} sn`;
  byId("analyzed-text").textContent = data.export.query;
  clampToggle(byId("analyzed-text"), byId("expand-incident"), 3);
  updateInput();
  selectRow(wide.matches ? (rows.keys().next().value ?? null) : null);
  renderModel(data.explanation);
  if (exportUrl) URL.revokeObjectURL(exportUrl);
  exportUrl = URL.createObjectURL(new Blob([JSON.stringify(data.export, null, 2)], { type: "application/json" }));
  byId("download").href = exportUrl;
}

wide.addEventListener("change", () => {
  if (!lastResult) return;
  const firstVisible = [...rows].find(([, entry]) => !entry.li.hidden)?.[0] ?? null;
  selectRow(wide.matches ? selected ?? firstVisible : null);
});

fetchJson("/api/examples").then((data) => {
  examples = data.examples;
  if (!byId("limit").matches(":focus") && byId("limit").selectedOptions[0].defaultSelected) {
    byId("limit").value = data.default_k;
  }
  for (const [label, text] of Object.entries(examples)) {
    byId("examples").add(new Option(label, label));
    const card = button(undefined, () => loadExample(label), "example-card");
    const title = element("strong", label);
    const arrow = element("span", "↗");
    arrow.setAttribute("aria-hidden", "true");
    title.append(arrow);
    card.append(title, element("span", text));
    card.disabled = running;
    byId("example-cards").append(card);
  }
  byId("examples").disabled = running;
  byId("examples-status").hidden = true;
}).catch(() => {
  byId("examples").disabled = true;
  byId("examples-status").textContent = "Örnekler yüklenemedi. Olay açıklamanızı doğrudan yazabilirsiniz.";
});

fetchJson("/api/health").then((data) => {
  modelReady = data.ollama.model_ready;
  modelName = data.model;
  byId("health").textContent = [
    data.attack_ready ? "ATT&CK hazır" : "ATT&CK hazır değil",
    data.nist_ready ? `NIST CSF · ${data.nist_count} alt kategori` : "NIST hazır değil",
    modelReady ? "Ollama erişilebilir" : (data.ollama.reachable ? `${data.model} kurulu değil` : "Ollama erişilemiyor"),
  ].join(" · ");
  updateModelWarning();
}).catch(() => { byId("health").textContent = "Analiz sunucusuna ulaşılamıyor"; });
