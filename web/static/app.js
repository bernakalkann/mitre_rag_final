"use strict";

const byId = (id) => document.getElementById(id);
const form = byId("analysis-form");
const incident = byId("incident");
const results = byId("sonuclar");
const sourceGroups = byId("source-groups");
const desktopEvidence = byId("kanit-paneli");

const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const duration = new Intl.NumberFormat("tr-TR", { maximumFractionDigits: 1 });
const sourceInfo = {
  attack: { name: "MITRE ATT&CK", label: "TEKNİK" },
  nist: { name: "NIST CSF 2.0", label: "ALT KATEGORİ" },
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

const examples = new Map();
const exampleVariants = {
  "PowerShell": [
    ["Windows uç nokta uyarısı"],
    ["Ofis belgesi sonrası alarm", "EDR, bir Word belgesi açıldıktan hemen sonra Word’ün alt süreci olarak PowerShell’in başladığını kaydetti. Kullanıcı belgeyi açtığını, kendisinin PowerShell çalıştırmadığını belirtti."],
    ["Mesai dışı sunucu etkinliği", "Bir dosya sunucusunda gece yarısı bir hizmet hesabına ait PowerShell oturumu kaydedildi. O saat için onaylı bakım kaydı bulunamadı."],
    ["İmzalı bakım betiği", "EDR, planlı bakım sırasında PowerShell etkinliği bildirdi. Çalışan betiğin imzası doğrulandı ve süreç kaydı onaylı bakım kaydıyla eşleşti."],
  ],
  "Zamanlanmış görev": [
    ["Oturum açma etkinliği"],
    ["Yeni görev kaydı", "Bir Windows istemcisinde zamanlanmış görev kaydı oluşturuldu. Görev, yeniden başlatma sonrasında tanınmayan bir uygulamayı çalıştıracak şekilde yapılandırılmış görünüyor."],
    ["Mevcut görevin değiştirilmesi", "Uç nokta kaydı, haftalık rapor görevinin normalde çalıştırdığı uygulamanın değiştiğini gösteriyor. Değişiklik için onaylı bir iş kaydı bulunamadı."],
    ["Yedekleme planı güncellemesi", "Zamanlanmış yedekleme görevinin saati değiştirildi. Görev geçmişi, değişiklik zamanının ve hesabın planlanan bakım kaydıyla eşleştiğini gösteriyor."],
  ],
  "Kimlik bilgilerine erişim": [
    ["Süreç telemetrisi"],
    ["Tarayıcı veri deposu uyarısı", "Uç nokta alarmı, tanınmayan bir sürecin tarayıcının kayıtlı parola veritabanını okuduğunu gösteriyor. O sırada tarayıcı kapalıydı."],
    ["Olağan dışı kasa sorguları", "Gizli bilgi kasasının denetim kayıtlarında, bir hizmet hesabının kendi uygulaması dışındaki gizli bilgilere arka arkaya erişim istediği görüldü. İsteklerin çoğu reddedildi."],
    ["Ardışık giriş hataları", "Kimlik sağlayıcısı, kısa süre içinde çok sayıda farklı kullanıcı hesabında başarısız parola denemesi kaydetti. İstekler aynı kaynaktan geldi ve hesapların çoğunda daha önce giriş hatası yoktu."],
  ],
  "Yetersiz bağlam": [
    ["Gündelik kullanıcı etkinliği"],
    ["Eksik oturum kaydı", "Destek kaydında yalnızca “olağan dışı giriş” yazıyor. Hesap, zaman, kaynak adresi ve giriş sonucu belirtilmemiş."],
    ["Tek başına dosya adı", "Bir çalışan masaüstünde rapor adlı bir dosya gördüğünü bildirdi. Dosyanın türü, kaynağı veya çalıştırılıp çalıştırılmadığı bilinmiyor."],
    ["Bağlamsız ağ uyarısı", "İzleme panelinde kısa süreli ağ trafiği artışı görüldü. İlgili cihaz, hedef adres ve işlem kaydı mevcut değil."],
  ],
};
let modelName = "qwen3:8b";
let modelIssue = "";
let lastResult = null;
let selected = null;
let running = false;
let exportUrl = null;
let caseLabel = "";
let caseSettings = null;
let conversation = [];
let activeCitation = null;
let activeChatId = null;
let activeRevision = null;
let unsavedChat = false;
let saveConflict = false;
const historyKey = "mitre-rag.chats.v1";
const historyDate = new Intl.DateTimeFormat("tr-TR", {day: "numeric", month: "short", hour: "2-digit", minute: "2-digit"});
let savedChats = [];
const initialPrompts = [
  ["Hangi ATT&CK tekniğiyle ilişkili olabilir?", "Örnek PowerShell olayını yükle.", "PowerShell"],
  ["Bu uyarıyı nasıl incelemeliyim?", "Örnek zamanlanmış görev olayını yükle.", "Zamanlanmış görev"],
  ["Eldeki bilgi yeterli mi?", "Yetersiz bağlam örneğini yükle.", "Yetersiz bağlam"],
];
const followupPrompts = [
  ["Neden bu teknik?", "Olay metnindeki dayanağı göster."],
  ["Hangi bilgi eksik?", "Eşleşmeyi doğrulamak için gerekenleri açıkla."],
  ["NIST hangi başlıkları öneriyor?", "Savunma ve izleme başlıklarını açıkla."],
];
const rows = new Map();
const mapButtons = new Map();
const evidenceBoard = new EvidenceBoard();
let evidenceTrigger = null;

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
  if (response.status === 204) return null;
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(typeof data.detail === "string" ? data.detail : "Alanları kontrol edip tekrar dene.");
    error.status = response.status;
    throw error;
  }
  return data;
}

function updateAnswerRoute() {
  const followup = Boolean(lastResult);
  const useSources = followup && isReadyQuestion(incident.value);
  const route = byId("answer-route");
  const label = useSources ? "Olay kaynakları" : modelName;
  if (route.textContent !== label) route.textContent = label;
  route.hidden = !followup;

  const warning = byId("model-warning");
  const needsModel = followup ? !useSources : byId("with-model").value === "local";
  warning.hidden = !modelIssue || !needsModel;
  const message = followup
    ? `${modelIssue} Hazır sorular kullanılabilir.`
    : `${modelIssue} Arama sonuçları yine gösterilir.`;
  if (!warning.hidden && warning.textContent !== message) warning.textContent = message;
}

function updateInput() {
  incident.removeAttribute("aria-invalid");
  incident.setAttribute("aria-describedby", "composer-help");
  byId("input-error").hidden = true;
  updateAnswerRoute();
  for (const card of byId("example-cards").children) {
    card.setAttribute("aria-pressed", String(card.dataset.example === caseLabel));
  }
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
  for (const id of ["submit", "mode", "limit", "with-model", "new-case", "open-profile", "import-chats", "retry-save"]) byId(id).disabled = busy;
  for (const control of document.querySelectorAll(".example-card, .prompt-button, #saved-chats button")) {
    control.disabled = busy;
  }
  incident.readOnly = busy;
  form.setAttribute("aria-busy", String(busy));
}

function showView(name) {
  byId("view-map").hidden = name !== "map";
  byId("view-case").hidden = name !== "case";
  for (const control of document.querySelectorAll("[data-view][aria-pressed]")) {
    control.setAttribute("aria-pressed", String(control.dataset.view === name));
  }
  if (name === "case") clampToggle(byId("analyzed-text"), byId("expand-incident"), 3);
}

function openView(name) {
  if (name !== "chat") showView(name);
  const target = name === "chat" ? incident : name === "map" ? byId("board-viewport") : byId("result-title");
  target.focus({preventScroll: true});
  nudgeTo(target);
}

function displayEvidence(open) {
  byId("evidence-sidebar").hidden = !open;
  if (!open && evidenceTrigger?.isConnected) evidenceTrigger.focus({preventScroll: true});
  if (!open) evidenceTrigger = null;
}

function setConversationMode(ready) {
  incident.maxLength = ready ? 500 : 4000;
  incident.placeholder = ready ? "Bu olay hakkında bir takip sorusu yaz…" :
    "Bir olayı anlat veya alarm metnini yapıştır…";
  byId("composer-label").textContent = ready ? "Takip sorusu" : "Olay açıklaması";
  byId("mode-options").hidden = ready;
  byId("answer-mode").hidden = ready;
  byId("prompts-title").textContent = ready ? "Sorabileceklerin" : "Örnek başlangıçlar";
  byId("case-context").hidden = !ready;
  byId("workflow").hidden = ready;
  byId("source-preview").hidden = ready;
  byId("download").hidden = !ready;
  byId("nav-attack").disabled = !ready;
  document.querySelector('[data-view="case"]').disabled = !ready;
  renderPrompts(ready);
  updateAnswerRoute();
}

function renderPrompts(ready) {
  const prompts = ready ? followupPrompts : initialPrompts;
  byId("prompt-grid").replaceChildren(...prompts.map(([question, description, sample]) => {
    const control = button(undefined, () => {
      if (ready) {
        incident.value = question;
        updateInput();
        incident.focus();
      } else {
        loadExample(sample);
      }
    }, "prompt-button");
    control.disabled = running || (!ready && !examples.has(sample));
    control.append(element("strong", question), element("span", description));
    return control;
  }));
}

function readChats() {
  const stored = JSON.parse(localStorage.getItem(historyKey) ?? "[]");
  if (!Array.isArray(stored)) throw new Error("Geçersiz sohbet geçmişi");
  return stored;
}

function showHistoryError(message) {
  const notice = byId("history-error");
  notice.textContent = message;
  notice.hidden = !message;
}

function renderSavedChats() {
  const list = byId("saved-chats");
  list.replaceChildren(...savedChats.map(chat => {
    const item = element("li");
    const open = button(undefined, () => openSavedChat(chat), "saved-chat");
    if (chat.id === activeChatId) open.setAttribute("aria-current", "true");
    open.append(element("strong", chat.title), element("span", historyDate.format(chat.updatedAt)));
    const remove = button("Sil", () => removeSavedChat(chat), "remove-chat");
    remove.setAttribute("aria-label", `${chat.title} sohbetini sil`);
    open.disabled = remove.disabled = running;
    item.append(open, remove);
    return item;
  }));
  byId("history-empty").hidden = Boolean(savedChats.length) || byId("history-error").textContent !== "";
}

function chatTitle() {
  const text = caseLabel || lastResult.export.query.replace(/\s+/g, " ");
  return text.length > 56 ? text.slice(0, 55) + "…" : text;
}

async function saveChat() {
  activeChatId ??= crypto.randomUUID();
  evidenceBoard.bind(activeChatId);
  const chat = {
    title: chatTitle(), label: caseLabel, settings: caseSettings,
    result: lastResult, conversation, revision: activeRevision,
  };
  unsavedChat = true;
  try {
    const saved = await accountRequest("/api/chats/" + activeChatId, jsonRequest("PUT", chat));
    activeRevision = saved.revision;
    savedChats = [saved, ...savedChats.filter(item => item.id !== saved.id)];
    unsavedChat = false;
    saveConflict = false;
    showHistoryError("");
  } catch (error) {
    saveConflict = error.status === 409;
    showHistoryError("Sohbet kaydedilemedi. " + error.message);
  }
  byId("retry-save").hidden = !unsavedChat;
  byId("retry-save").textContent = saveConflict ? "Yeni sohbet olarak kaydet" : "Kaydetmeyi tekrar dene";
  renderSavedChats();
}

function mayLeaveChat() {
  return !unsavedChat || window.confirm("Bu sohbette kaydedilmemiş değişiklikler var. Ayrılmak istiyor musun?");
}

async function openSavedChat(summary) {
  if (running || summary.id === activeChatId || !mayLeaveChat()) return;
  setBusy(true);
  let chat;
  try {
    chat = await accountRequest("/api/chats/" + summary.id);
    showHistoryError("");
  } catch (error) {
    showHistoryError(error.message);
    return;
  } finally {
    setBusy(false);
  }
  resetCase(false);
  activeChatId = chat.id;
  activeRevision = chat.revision;
  caseLabel = chat.label;
  caseSettings = chat.settings;
  lastResult = chat.result;
  conversation = chat.conversation.slice();
  renderResults(lastResult, caseSettings.method, caseSettings.k);
  for (const {question, answer} of conversation) renderFollowup(question, answer, false);
  setConversationMode(true);
  updateInput();
  renderSavedChats();
  byId("result-title").focus({preventScroll: true});
  nudgeTo(byId("result-title"));
}

async function removeSavedChat(chat) {
  if (running || !window.confirm("Bu sohbet hesabındaki geçmişten silinsin mi?")) return;
  setBusy(true);
  try {
    await accountRequest("/api/chats/" + chat.id + "?revision=" + chat.revision, {method: "DELETE"});
    showHistoryError("");
  } catch (error) {
    showHistoryError(error.message);
    return;
  } finally {
    setBusy(false);
  }
  savedChats = savedChats.filter(item => item.id !== chat.id);
  if (activeChatId === chat.id) resetCase();
  else {
    renderSavedChats();
    byId("new-case").focus();
  }
}

function resetCase(focus = true) {
  if (running) return;
  activeChatId = null;
  activeRevision = null;
  unsavedChat = false;
  saveConflict = false;
  byId("retry-save").hidden = true;
  lastResult = null;
  caseLabel = "";
  caseSettings = null;
  conversation = [];
  activeCitation = null;
  selected = null;
  rows.clear();
  mapButtons.clear();
  displayEvidence(false);
  evidenceBoard.render([], [], null);
  showView("map");
  desktopEvidence.replaceChildren();
  byId("chat-history").replaceChildren();
  byId("model-block").replaceChildren();
  byId("result-title").textContent = "Analiz Masası";
  byId("analysis-error").hidden = true;
  byId("skip-results").hidden = true;
  byId("workspace-empty").hidden = false;
  results.hidden = true;
  incident.value = "";
  if (exportUrl) URL.revokeObjectURL(exportUrl);
  exportUrl = null;
  updateInput();
  setConversationMode(false);
  renderSavedChats();
  if (focus) incident.focus();
}

function loadExample(label) {
  const group = examples.get(label);
  if (running || !group || !mayLeaveChat()) return;
  const [context, text] = group.samples[group.next];
  group.next = (group.next + 1) % group.samples.length;
  if (lastResult) resetCase(false);
  caseLabel = label;
  group.preview.textContent = context;
  incident.value = text;
  updateInput();
  incident.focus();
}

function nudgeTo(element) {
  const bounds = element.getBoundingClientRect();
  const scrollPanel = element.closest("#assistant-log, #view-case, #evidence-sidebar");
  const viewport = scrollPanel?.getBoundingClientRect();
  if (!viewport || bounds.top < viewport.top || bounds.bottom > viewport.bottom) {
    element.scrollIntoView({block: "nearest", behavior: reducedMotion.matches ? "auto" : "smooth"});
  }
}

function updateExport() {
  if (exportUrl) URL.revokeObjectURL(exportUrl);
  const payload = conversation.length ? {...lastResult.export, conversation} : lastResult.export;
  exportUrl = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], {type: "application/json"}));
  byId("download").href = exportUrl;
}

function makeTurn(label, text, kind) {
  const turn = element("article", undefined, `chat-turn ${kind}-turn`);
  turn.append(element("h3", label), element("p", text, "chat-text"));
  return turn;
}

function appendSources(panel, sources, needed, heading = "h4") {
  if (sources.length) {
    const citations = element("ul", undefined, "model-citations");
    for (const [index, source] of sources.entries()) {
      const id = source.attack_id ?? source.nist_id;
      const key = source.attack_id ? `attack:${id}` : `nist:${id}`;
      const label = `[${index + 1}] ${id}`;
      const control = rows.has(key)
        ? button(label, () => revealEvidence(key, true, source.explanation ? source : null), "mono")
        : officialLink(source.source_url, label);
      if (!control) continue;
      const item = element("li");
      item.append(control);
      citations.append(item);
    }
    panel.append(element(heading, "Yanıtın kaynakları"), citations);
  }
  if (needed?.length) {
    const list = element("ul", undefined, "missing-context");
    for (const item of needed) list.append(element("li", item));
    panel.append(element(heading, "İnceleme için ek bilgiler"), list);
  }
}

function renderFollowup(question, answer, focus = true) {
  const history = byId("chat-history");
  const response = makeTurn("MITRE-RAG", answer.text, "assistant");
  const origin = answer.model || (isReadyQuestion(question) ? "Olay kaynakları" : "");
  if (origin) response.firstElementChild.append(element("span", origin, "answer-origin"));
  appendSources(response, answer.sources, answer.additional_data_needed);
  history.append(makeTurn("Sen", question, "analyst"), response);
  if (focus) {
    response.tabIndex = -1;
    response.focus({preventScroll: true});
    nudgeTo(response);
  }
}

async function submitAnalysis(text) {
  const method = byId("mode").value;
  const k = Number(byId("limit").value);
  const wantsExplanation = byId("with-model").value === "local";
  const data = await fetchJson("/api/analyze", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({text, mode: method, k, attack_method: method}),
  });
  if (!data.export) {
    throw new Error([data.attack.error, data.nist.error].filter(Boolean).join(" · "));
  }
  caseSettings = {method, k};
  lastResult = data;
  const waitingForExplanation = wantsExplanation && data.attack.items.length > 0;
  renderResults(data, method, k, waitingForExplanation);
  byId("pending-message").hidden = true;
  setConversationMode(true);
  byId("result-title").focus({preventScroll: true});
  nudgeTo(byId("model-title"));

  await saveChat();
  if (waitingForExplanation) {
    await requestOllamaExplanation();
    await saveChat();
  }
}

async function requestOllamaExplanation() {
  try {
    const complete = await fetchJson("/api/analyze", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({text: lastResult.export.query, mode: "rag", k: caseSettings.k, attack_method: caseSettings.method}),
      signal: AbortSignal.timeout(95_000),
    });
    if (complete.explanation?.status === "ok") {
      lastResult = {...complete, search_duration_ms: lastResult.search_duration_ms ?? lastResult.duration_ms};
    } else {
      lastResult.explanation = {status: "error", error: complete.explanation?.error};
    }
  } catch (error) {
    lastResult.explanation = {status: "error", error: error.name === "TimeoutError" ? "Zaman aşımı." : error.message};
  }
  renderOllamaAnswer(byId("ollama-answer"), lastResult);
  updateExport();
  if (selected && !activeCitation) selectRow(selected);
}

async function retryOllamaExplanation() {
  if (running) return;
  setBusy(true);
  try {
    renderOllamaAnswer(byId("ollama-answer"), lastResult, true);
    byId("ollama-answer-title").focus({preventScroll: true});
    await requestOllamaExplanation();
    byId("ollama-answer-title").focus({preventScroll: true});
    await saveChat();
  } finally {
    setBusy(false);
  }
}

function readyQuestionIndex(question) {
  const normalize = text => text.toLocaleLowerCase("tr-TR").trim().replace(/[?.!]+$/, "");
  return followupPrompts.findIndex(([label]) => normalize(label) === normalize(question));
}

function isReadyQuestion(question) {
  return readyQuestionIndex(question) >= 0;
}

function answerFromCase(question, data) {
  const prompt = readyQuestionIndex(question);
  const explanation = data.explanation?.status === "ok" ? data.explanation : null;
  const answer = {text: "", sources: [], additional_data_needed: []};

  switch (prompt) {
    case 0: {
      if (explanation?.sources.length) {
        answer.text = explanation.sources.map(source =>
          `${source.name} (${source.attack_id}) — ${source.explanation}`).join("\n");
        answer.sources = explanation.sources;
        break;
      }
      const candidates = explanation ? [] : mentionedTechniques(data);
      if (candidates.length) {
        answer.text = `Olay metninde ${candidates.map(item => `${item.name} (${item.attack_id})`).join(", ")} ile örtüşen ad veya kod geçiyor. Bu kayıtlar olası eşleşmenin dayanağını incelemek için kullanılabilir. Eşleşmeyi doğrulamak için sürecin ne yaptığını gösteren kayıtlara bakmak gerekir.`;
        answer.sources = candidates.map(({attack_id, source_url}) => ({attack_id, source_url}));
      } else {
        answer.text = "Bu olay metni belirli bir ATT&CK tekniğini destekleyecek davranış ayrıntısı içermiyor. Olay dosyasındaki adaylar aramanın bulduğu en yakın kayıtlar. Eşleşmeyi değerlendirmek için uygulamayı hangi sürecin başlattığı, hangi hesabın kullandığı ve alarmı neyin tetiklediği gibi bilgiler gerekir.";
      }
      break;
    }
    case 1:
      answer.text = "Eşleşmeyi netleştirmek için olayın hangi davranışı kaydettiğini ve bu davranışın hangi koşullarda gerçekleştiğini gösteren kayıtlar gerekir.";
      answer.additional_data_needed = explanation?.additional_data_needed?.length
        ? explanation.additional_data_needed
        : ["İşlemi başlatan süreç ve varsa üst süreç", "Olayın zamanı, cihazı ve kullanıcı hesabı", "Alarmı tetikleyen davranışı gösteren işlem veya denetim kaydı"];
      break;
    case 2: {
      const candidates = data.nist.items.slice(0, 3);
      answer.text = candidates.length
        ? `Olay için incelenebilecek NIST CSF başlıkları ${candidates.map(item => `${item.id} (${item.category})`).join(", ")}. Bu başlıklar savunma ve izleme değerlendirmesine yardımcı olur. Kaynak numaralarını seçerek her başlığın dayanağını açabilirsin.`
        : "Bu olayda incelenebilecek bir NIST CSF başlığı bulunamadı.";
      answer.sources = candidates.map(({id}) => ({nist_id: id, source_url: data.export.nist_csf?.source_url}));
      break;
    }
    default:
      return null;
  }
  return answer;
}

async function submitFollowup(question, answer) {
  const history = conversation.slice(-3).map(({question, answer}) => ({
    question, answer: answer.text.slice(0, 800),
  }));
  answer ??= await fetchJson("/api/ask", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({incident: lastResult.export.query, question, history, ...caseSettings}),
    signal: AbortSignal.timeout(95_000),
  });
  conversation.push({question, answer});
  incident.value = "";
  updateAnswerRoute();
  renderFollowup(question, answer);
  updateExport();
  await saveChat();
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (running || !currentAccount) return;
  const text = incident.value.trim();
  if (!text) {
    incident.setAttribute("aria-invalid", "true");
    incident.setAttribute("aria-describedby", "composer-help input-error");
    byId("input-error").textContent = lastResult ? "Bir takip sorusu yaz." : "Analiz için bir olay açıklaması yaz.";
    byId("input-error").hidden = false;
    incident.focus();
    return;
  }

  const followup = Boolean(lastResult);
  const readyAnswer = followup ? answerFromCase(text, lastResult) : null;
  const draft = incident.value;
  byId("analysis-error").hidden = true;
  setBusy(true);
  incident.value = "";
  const pending = byId("pending-message");
  const progress = element("div", undefined, "pending-response");
  progress.setAttribute("role", "status");
  const spinner = element("span", undefined, "spinner");
  const elapsed = element("span", "0 sn", "pending-elapsed mono");
  spinner.setAttribute("aria-hidden", "true");
  elapsed.setAttribute("aria-hidden", "true");
  const progressLabel = followup
    ? (readyAnswer ? "Olay kaynakları inceleniyor…" : `${modelName} yanıt hazırlıyor…`)
    : "Adaylar aranıyor…";
  progress.append(spinner, element("span", progressLabel), elapsed);
  pending.replaceChildren(makeTurn("Sen", text, "analyst"), progress);
  pending.hidden = false;
  nudgeTo(pending);
  if (!followup) byId("workspace-empty").hidden = true;
  const started = performance.now();
  const timer = setInterval(() => {
    elapsed.textContent = `${Math.floor((performance.now() - started) / 1000)} sn`;
  }, 1000);
  try {
    if (followup) await submitFollowup(text, readyAnswer);
    else await submitAnalysis(text);
  } catch (error) {
    incident.value = draft;
    renderError(byId("analysis-error"), followup
      ? "Yerel model bu soruyu tamamlayamadı. Tekrar deneyebilir veya hazır sorulardan birini kullanabilirsin."
      : "Olay analizi tamamlanamadı.", followup ? null : error.message);
  } finally {
    clearInterval(timer);
    pending.replaceChildren();
    pending.hidden = true;
    byId("workspace-empty").hidden = Boolean(lastResult);
    updateAnswerRoute();
    setBusy(false);
  }
});

incident.addEventListener("input", () => {
  if (!lastResult) caseLabel = "";
  updateInput();
});
incident.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (!event.shiftKey || event.ctrlKey || event.metaKey) && !event.isComposing) {
    event.preventDefault();
    form.requestSubmit();
  }
});
byId("with-model").addEventListener("change", updateAnswerRoute);
byId("new-case").addEventListener("click", () => {
  if (mayLeaveChat()) resetCase();
});
byId("retry-save").addEventListener("click", async () => {
  if (running || !unsavedChat) return;
  if (saveConflict) {
    activeChatId = null;
    activeRevision = null;
  }
  setBusy(true);
  try {
    await saveChat();
  } finally {
    setBusy(false);
  }
});
window.addEventListener("beforeunload", event => {
  if (unsavedChat) event.preventDefault();
});
byId("show-case").addEventListener("click", () => openView("case"));
byId("board-start").addEventListener("click", () => openView("chat"));
byId("nav-attack").addEventListener("click", () => {
  showView("case");
  const attack = sourceGroups.querySelector(".source-attack h3");
  if (!attack) return;
  attack.tabIndex = -1;
  attack.focus({preventScroll: true});
  nudgeTo(attack);
});
byId("close-evidence").addEventListener("click", () => displayEvidence(false));
byId("evidence-sidebar").addEventListener("keydown", event => {
  if (event.key === "Escape") displayEvidence(false);
});
byId("toggle-navigation").addEventListener("click", event => {
  const control = event.currentTarget;
  const collapsed = byId("workbench").classList.toggle("navigation-compact");
  const label = collapsed ? "Gezinmeyi genişlet" : "Gezinmeyi daralt";
  control.setAttribute("aria-expanded", String(!collapsed));
  control.setAttribute("aria-label", label);
  control.title = label;
  control.textContent = collapsed ? "»" : "«";
});
function applyTheme(light) {
  document.documentElement.dataset.theme = light ? "light" : "dark";
  const control = byId("theme-toggle");
  control.setAttribute("aria-pressed", String(light));
}
try {
  applyTheme(localStorage.getItem("mitre-rag.theme") === "light");
} catch {
  applyTheme(false);
}
byId("theme-toggle").addEventListener("click", () => {
  const light = document.documentElement.dataset.theme !== "light";
  applyTheme(light);
  try {
    localStorage.setItem("mitre-rag.theme", light ? "light" : "dark");
  } catch {
    // Theme remains active for this page when storage is unavailable.
  }
});
for (const control of document.querySelectorAll("[data-view]")) {
  control.addEventListener("click", () => openView(control.dataset.view));
}
renderPrompts(false);

function scoreInfo(kind) {
  return scores[kind === "attack" ? (lastResult.export.method ?? lastResult.export.retrieval?.method) : "semantic"] ?? scores.semantic;
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
  name.append(element("h3", info.name), element("p", kind === "attack" ? "Teknik adayları" : "Savunma başlıkları"));
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
    for (const title of ["#", "Kod", "Aday"]) columns.append(element("span", title));
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
      const trigger = button(undefined, () => revealEvidence(key), "candidate");
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
  Promise.resolve().then(() => navigator.clipboard.writeText(code)).then(() => {
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

  const match = activeCitation ?? (row.kind === "attack"
    ? lastResult.explanation?.sources?.find((item) => item.attack_id === row.code) : null);
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

function renderEvidenceMap(data, method) {
  const query = data.export.query;
  const count = rows.size;
  const excerpt = query.length > 154 ? query.slice(0, 151) + "…" : query;
  const cards = [
    {id: "incident", type: "incident", label: "Olay kaydı", text: excerpt, x: 0, y: 84,
      action: () => openView("case")},
    {id: "analysis", type: "analysis", label: "Analiz sonucu", x: 228, y: 162,
      text: count ? `${count} aday eşleşme` : "Aday eşleşme bulunamadı",
      meta: modeLabels[method], action: () => openView("case")},
  ];
  const links = [["incident", "analysis"]];
  let baseY = 0;
  for (const [kind, source] of Object.entries(sourceInfo)) {
    const candidates = [...rows].filter(([, entry]) => entry.row.kind === kind);
    if (!candidates.length) continue;
    const sourced = candidates.filter(([, {row}]) => row.url || row.body);
    const reference = kind + "-source";
    for (const [index, [key, {row}]] of candidates.entries()) {
      cards.push({id: key, type: kind, label: kind === "attack" ? "Teknik adayı" : "NIST başlığı",
        code: row.code, text: row.title, x: 476 + (index % 2) * 22, y: baseY + index * 107,
        action: () => revealEvidence(key, true)});
      links.push(["analysis", key]);
      if (row.url || row.body) links.push([key, reference]);
    }
    if (sourced.length) {
      cards.push({id: reference, type: "reference", label: "Kaynaklar", text: source.name,
        meta: `${sourced.length} kaynaklı aday`, x: 725, y: baseY + 107 * (candidates.length - 1) / 2,
        action: () => {
          const visible = sourced.filter(([, {li}]) => !li.hidden);
          const [key] = visible.find(([candidate]) => candidate === selected) ?? visible[0] ?? sourced[0];
          revealEvidence(key, true);
        }});
    }
    baseY += candidates.length * 107 + 24;
  }
  mapButtons.clear();
  for (const [key, control] of evidenceBoard.render(cards, links, activeChatId)) {
    if (rows.has(key)) mapButtons.set(key, control);
  }
}

function applySourceFilter(kind, value) {
  let firstVisible = null;
  let visible = 0;
  let total = 0;
  const boardVisibility = [];
  for (const [key, { row, li }] of rows) {
    if (row.kind !== kind) continue;
    total += 1;
    const show = value === null || row.filterValues.includes(value);
    li.hidden = !show;
    boardVisibility.push([key, show]);
    if (show) {
      firstVisible ??= key;
      visible += 1;
    }
  }
  evidenceBoard.updateVisibility(boardVisibility);
  for (const option of byId(`${kind}-filter-options`).children) {
    option.setAttribute("aria-pressed", String(option.dataset.filterValue === (value ?? "")));
  }
  const count = value === null ? `${total} aday` : `${visible} / ${total} aday`;
  byId(`${kind}-visible-count`).textContent = count;
  byId(`${kind}-filter-status`).textContent = `${count} gösteriliyor`;
  const current = rows.get(selected);
  if (current?.row.kind === kind && current.li.hidden) selectRow(firstVisible);
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

function selectRow(key, citation = null) {
  const entry = rows.get(key);
  if (entry?.li.hidden) applySourceFilter(entry.row.kind, null);
  selected = key;
  activeCitation = citation;
  for (const [id, node] of mapButtons) {
    node.setAttribute("aria-pressed", String(id === selected));
    node.setAttribute("aria-controls", "kanit-paneli");
  }
  for (const [id, {trigger}] of rows) {
    trigger.setAttribute("aria-pressed", String(id === selected));
    trigger.setAttribute("aria-controls", "kanit-paneli");
  }
  desktopEvidence.replaceChildren(entry
    ? renderEvidence(entry.row) : element("p", "Bu olayda gösterilecek aday yok.", "evidence-placeholder"));
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

function revealEvidence(key, moveFocus = false, citation = null) {
  if (!byId("evidence-sidebar").contains(document.activeElement)) evidenceTrigger = document.activeElement;
  selectRow(key, citation);
  const title = desktopEvidence.querySelector("h3");
  if (!title) return;
  displayEvidence(true);
  byId("evidence-sidebar").scrollTop = 0;
  const bounds = byId("evidence-sidebar").getBoundingClientRect();
  if (bounds.top < 0 || bounds.bottom > window.innerHeight) {
    byId("evidence-sidebar").scrollIntoView({block: "nearest"});
  }
  if (moveFocus) {
    title.tabIndex = -1;
    title.focus({preventScroll: true});
  }
}

function mentionedTechniques(data) {
  const normalize = (value) => ` ${value.toLocaleLowerCase("en-US").replace(/[^\p{L}\p{N}]+/gu, " ").trim()} `;
  const query = normalize(data.export.query);
  return data.attack.items.filter(item => {
    const name = normalize(item.name).trim();
    return query.includes(normalize(item.attack_id)) ||
      (name.length >= 4 && query.includes(` ${name} `)) ||
      (item.attack_id === "T1053.002" && query.includes(" at exe "));
  }).slice(0, 2);
}

function renderSearchAssessment(block, data) {
  const attack = data.attack.items;
  const nist = data.nist.items;
  const named = mentionedTechniques(data);
  const names = (items) => items.map(item => `${item.name} (${item.attack_id})`).join(", ");

  let assessment = "Olay metninden öne çıkan bir ATT&CK tekniği belirlenemedi.";
  if (named.length) {
    assessment = `Olay açıklamasında doğrudan geçen ad veya kodlara göre en güçlü ${named.length === 1 ? "aday" : "adaylar"} ${names(named)}. Bu eşleşmeyi değerlendirmek için alarmı tetikleyen davranışı ve ilgili süreç kayıtlarını incele.`;
  } else if (attack.length) {
    assessment = `Aramada ilk sırada ${names(attack.slice(0, 2))} yer alıyor. Eldeki açıklama bu teknikleri güçlü aday olarak göstermek için yetersiz. Alarmın hangi davranışı kaydettiği ve süreç bağlamı değerlendirmeyi netleştirir.`;
  }
  if (nist.length) {
    assessment += ` Savunma tarafında NIST ${nist[0].id} incelenebilir.`;
  }
  block.append(element("p", assessment, "model-text"));
}

function renderOllamaAnswer(section, data, pending = false) {
  const explanation = data.explanation;
  section.hidden = !pending && !explanation;
  if (section.hidden) return;

  const header = element("header", undefined, "model-heading");
  const title = element("h4", "Ollama’nın cevabı");
  title.id = "ollama-answer-title";
  title.tabIndex = -1;
  header.append(title);
  section.replaceChildren(header);
  if (pending || explanation.status !== "ok") {
    const timedOut = /zaman (sınır|aşım)/i.test(explanation?.error ?? "");
    const message = pending ? "Ollama’dan ek açıklama bekleniyor…" : timedOut
      ? "Ollama ayrılan süre içinde yanıt veremedi."
      : "Ollama açıklamayı tamamlayamadı.";
    const status = element("p", message, "response-progress");
    status.setAttribute("role", "status");
    section.append(status);
    if (!pending && data.attack.items.length) {
      section.append(button("Açıklamayı tekrar iste", retryOllamaExplanation, "text-button ollama-retry"));
    }
  } else {
    const generation = data.export.generation;
    if (Number.isFinite(generation?.seconds)) {
      header.append(element("p", `${generation.model ?? modelName} · ${duration.format(generation.seconds)} sn`, "model-runtime mono"));
    }
    section.append(element("p", explanation.text, "model-text"));
    const matches = explanation.sources.filter(source => source.attack_id);
    if (matches.length) {
      const candidates = element("p");
      candidates.className = "response-candidates";
      candidates.append(element("strong", matches.length === 1 ? "En güçlü aday" : "En güçlü adaylar"),
        document.createTextNode(` · ${matches.map(source => `${source.name} (${source.attack_id})`).join(", ")}`));
      section.append(candidates);
    }
    appendSources(section, explanation.sources, explanation.additional_data_needed, "h5");
  }
}

function renderModel(data, method, k, waitingForExplanation) {
  const block = byId("model-block");
  block.replaceChildren();
  block.hidden = false;
  const header = element("header", undefined, "model-heading");
  const title = element("h3", "MITRE-RAG");
  title.id = "model-title";
  title.tabIndex = -1;
  header.append(title, element("p", "Kaynak taramasına dayalı ön değerlendirme", "model-runtime mono"));
  block.append(header);
  renderSearchAssessment(block, data);

  const answer = element("section", undefined, "ollama-answer");
  answer.id = "ollama-answer";
  answer.setAttribute("aria-labelledby", "ollama-answer-title");
  renderOllamaAnswer(answer, data, waitingForExplanation);
  block.append(answer);

  const footer = element("footer", undefined, "response-footer");
  const actions = element("div", undefined, "response-actions");
  for (const [view, label] of [["case", "Olay dosyasını aç"], ["map", "Kanıt haritasını aç"]]) {
    const action = button(label, () => openView(view), "response-action");
    action.setAttribute("aria-controls", `view-${view}`);
    const arrow = element("span", "→");
    arrow.setAttribute("aria-hidden", "true");
    action.append(arrow);
    actions.append(action);
  }
  const searchTime = data.search_duration_ms ?? data.duration_ms;
  const elapsed = searchTime < 100 ? "<0,1" : duration.format(searchTime / 1000);
  const timeLabel = data.search_duration_ms == null && data.explanation?.status === "ok" ? "Analiz" : "Arama";
  footer.append(actions, element("p", `${modeLabels[method]} · Kaynak başına en çok ${k} aday · ${timeLabel} ${elapsed} sn`, "response-meta"));
  block.append(footer);
}

function renderResults(data, method, k, waitingForExplanation = false) {
  rows.clear();
  sourceGroups.replaceChildren(renderSource("attack", data.attack), renderSource("nist", data.nist));
  showView("map");
  renderEvidenceMap(data, method);
  renderSourceFilter("attack");
  renderSourceFilter("nist");
  results.hidden = false;
  byId("skip-results").hidden = false;
  byId("workspace-empty").hidden = true;
  const title = chatTitle();
  byId("case-name").textContent = title;
  byId("result-title").textContent = title;
  byId("first-message").textContent = data.export.query;
  byId("analyzed-text").textContent = data.export.query;
  selectRow(rows.keys().next().value ?? null);
  renderModel(data, method, k, waitingForExplanation);
  updateExport();
}

fetchJson("/api/examples").then((data) => {
  if (!byId("limit").matches(":focus") && byId("limit").selectedOptions[0].defaultSelected) {
    byId("limit").value = data.default_k;
  }
  for (const [label, text] of Object.entries(data.examples)) {
    const [[context], ...variants] = exampleVariants[label] ?? [[label]];
    const preview = element("span", context);
    examples.set(label, {samples: [[context, text], ...variants], next: 0, preview});
    const card = button(undefined, () => loadExample(label), "example-card");
    card.dataset.example = label;
    card.setAttribute("aria-pressed", "false");
    const arrow = element("small", variants.length ? "↻" : "›", "example-arrow");
    arrow.setAttribute("aria-hidden", "true");
    card.title = variants.length ? "Sıradaki örneği yükle" : "Örneği yükle";
    card.append(element("strong", label), preview, arrow);
    card.disabled = running;
    byId("example-cards").append(card);
  }
  byId("examples-status").hidden = true;
  renderPrompts(Boolean(lastResult));
}).catch(() => {
  byId("examples-status").textContent = "Örnekler yüklenemedi.";
});

fetchJson("/api/health").then((data) => {
  modelName = data.model;
  byId("source-status").textContent = [
    data.attack_ready ? "ATT&CK hazır" : "ATT&CK hazır değil",
    data.nist_ready ? `NIST CSF · ${data.nist_count} alt kategori` : "NIST hazır değil",
  ].join(" / ");
  byId("local-model-option").textContent = `${modelName} · Yerel model`;
  if (!data.ollama.model_ready) {
    modelIssue = data.ollama.reachable ? `${modelName} kurulu değil.` : "Ollama erişilemiyor.";
  }
  updateAnswerRoute();
}).catch(() => {
  byId("source-status").textContent = "Analiz sunucusuna ulaşılamıyor";
  modelIssue = "Yerel modelin durumu kontrol edilemedi.";
  updateAnswerRoute();
});
