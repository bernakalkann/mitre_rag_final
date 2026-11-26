"use strict";

let currentAccount = null;
let creatingAccount = false;

function jsonRequest(method, body) {
  return {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)};
}

function accountRequest(url, options = {}) {
  return fetchJson(url, {
    ...options,
    headers: {...options.headers, "X-Workbench-Account": currentAccount.id},
  });
}

function setNotice(id, message = "") {
  const notice = byId(id);
  notice.textContent = message;
  notice.hidden = !message;
}

function showAccountForm(register = false) {
  creatingAccount = register;
  byId("auth-loading").hidden = true;
  byId("auth-form").hidden = false;
  byId("auth-title").textContent = register ? "Hesap oluştur" : "Oturum aç";
  byId("registration-name").hidden = !register;
  byId("password-hint").hidden = !register;
  byId("auth-name").required = register;
  byId("auth-password").minLength = register ? 12 : 1;
  byId("auth-password").autocomplete = register ? "new-password" : "current-password";
  byId("auth-submit").textContent = byId("auth-title").textContent;
  byId("switch-auth").textContent = register ? "Oturum aç" : "Hesap oluştur";
  setNotice("auth-error");
}

function showProfileName(account) {
  currentAccount = account;
  byId("open-profile").textContent = account.name;
  byId("open-profile").setAttribute("aria-label", `Profil · ${account.name}`);
}

async function refreshChats() {
  try {
    savedChats = await accountRequest("/api/chats");
    showHistoryError("");
  } catch (error) {
    showHistoryError("Geçmiş yüklenemedi. " + error.message);
  }
  renderSavedChats();
}

function offerLegacyImport() {
  try {
    byId("import-chats").hidden = readChats().length === 0;
  } catch {
    byId("import-chats").hidden = true;
    showHistoryError("Tarayıcıdaki eski sohbetler okunamadı.");
  }
}

async function openAccount(account) {
  showProfileName(account);
  byId("auth-page").hidden = true;
  for (const id of ["open-profile", "workbench", "health"]) byId(id).hidden = false;
  setBusy(true);
  try {
    await refreshChats();
    offerLegacyImport();
  } finally {
    setBusy(false);
  }
}

byId("switch-auth").addEventListener("click", () => showAccountForm(!creatingAccount));
byId("auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  const submit = byId("auth-submit");
  if (submit.disabled) return;
  submit.disabled = byId("switch-auth").disabled = true;
  setNotice("auth-error");
  const email = byId("auth-email").value.trim();
  const password = byId("auth-password").value;
  const name = byId("auth-name").value.trim();
  try {
    const endpoint = creatingAccount ? "register" : "login";
    const account = await fetchJson("/api/auth/" + endpoint, jsonRequest("POST", {email, password, name}));
    byId("auth-form").reset();
    await openAccount(account);
    incident.focus();
  } catch (error) {
    setNotice("auth-error", error.message);
  } finally {
    submit.disabled = byId("switch-auth").disabled = false;
  }
});

const profileDialog = byId("profile-dialog");
byId("open-profile").addEventListener("click", () => {
  byId("profile-name").value = currentAccount.name;
  byId("profile-email").textContent = currentAccount.email;
  setNotice("profile-error");
  profileDialog.showModal();
});
byId("close-profile").addEventListener("click", () => profileDialog.close());
byId("profile-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (byId("save-profile").disabled) return;
  byId("save-profile").disabled = byId("logout").disabled = true;
  setNotice("profile-error");
  try {
    const name = byId("profile-name").value.trim();
    showProfileName(await accountRequest("/api/profile", jsonRequest("PATCH", {name})));
    profileDialog.close();
  } catch (error) {
    setNotice("profile-error", error.message);
  } finally {
    byId("save-profile").disabled = byId("logout").disabled = false;
  }
});

byId("logout").addEventListener("click", async () => {
  if (!mayLeaveChat()) return;
  byId("save-profile").disabled = byId("logout").disabled = true;
  try {
    await accountRequest("/api/auth/logout", {method: "POST"});
    currentAccount = null;
    savedChats = [];
    resetCase(false);
    showHistoryError("");
    profileDialog.close();
    for (const id of ["open-profile", "workbench", "health", "import-chats"]) byId(id).hidden = true;
    byId("profile-form").reset();
    byId("profile-email").textContent = "";
    byId("auth-page").hidden = false;
    showAccountForm();
    byId("auth-email").focus();
  } catch (error) {
    setNotice("profile-error", error.message);
  } finally {
    byId("save-profile").disabled = byId("logout").disabled = false;
  }
});

byId("import-chats").addEventListener("click", async () => {
  if (running || !window.confirm(`Bu tarayıcıdaki eski sohbetler ${currentAccount.email} hesabına aktarılsın mı?`)) return;
  setBusy(true);
  const migrated = new Set();
  let failure;
  try {
    const legacy = readChats();
    for (const {id, title, label, settings, result, conversation, updatedAt} of legacy) {
      try {
        await accountRequest("/api/chats/" + id, jsonRequest("PUT", {
          title, label, settings, result, conversation, importedAt: updatedAt,
        }));
        migrated.add(id);
      } catch (error) {
        failure = error;
        if (error.status === 401) break;
      }
    }
    localStorage.setItem(historyKey, JSON.stringify(readChats().filter(chat => !migrated.has(chat.id))));
  } catch (error) {
    failure = error;
  } finally {
    await refreshChats();
    offerLegacyImport();
    if (failure) showHistoryError("Bazı tarayıcı sohbetleri aktarılamadı. " + failure.message);
    setBusy(false);
  }
});

fetchJson("/api/profile").then(openAccount).catch(error => {
  showAccountForm();
  if (error.status !== 401) setNotice("auth-error", "Oturum kontrol edilemedi. " + error.message);
});
