const serverList = document.getElementById("serverList");
const serverForm = document.getElementById("serverForm");
const serverPage = document.getElementById("serverPage");
const serverCheckList = document.getElementById("serverCheckList");
const checkServersBtn = document.getElementById("checkServersBtn");
const clearServersBtn = document.getElementById("clearServersBtn");
const refreshBtn = document.getElementById("refreshBtn");
const usersRoot = document.getElementById("users");
const statusBox = document.getElementById("statusBox");
const serverCount = document.getElementById("serverCount");
const clientCount = document.getElementById("clientCount");

const state = {
  servers: [],
  users: [],
  selectedServerId: null,
};

async function request(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return response.json();
}

function showStatus(message, type = "info") {
  statusBox.textContent = message;
  statusBox.className = `status-box ${type}`;
}

function clearStatus() {
  statusBox.textContent = "";
  statusBox.className = "status-box hidden";
}

function safeFilename(value) {
  return (value || "client").replace(/[\\/:*?"<>|]/g, "_").trim() || "client";
}

function downloadTextFile(filename, content) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const href = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = href;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(href);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function formatDateTime(value) {
  if (!value) {
    return "Не указано";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString("ru-RU");
}

function formatDateForInput(value) {
  if (!value) {
    return "";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "";
  }
  return parsed.toISOString().slice(0, 10);
}

function renderUsers() {
  usersRoot.innerHTML = "";
  clientCount.textContent = String(state.users.length);
  if (!state.users.length) {
    usersRoot.appendChild(el("p", "hint", "Пока нет клиентов. Первый появится после выдачи ключа."));
    return;
  }

  state.users.forEach((user) => {
    const card = el("article", "mini-user");
    card.appendChild(el("strong", "", user.name));
    card.appendChild(el("p", "muted", user.contact || "Контакт не указан"));
    const meta = `${user.keys_total || 0} ключ(ей), активных: ${user.active_keys || 0}`;
    card.appendChild(el("p", "hint", meta));
    usersRoot.appendChild(card);
  });
}

function renderServerList() {
  serverList.innerHTML = "";
  serverCount.textContent = String(state.servers.length);
  if (!state.servers.length) {
    serverList.appendChild(el("p", "hint", "Пока нет серверов. Добавьте первый сервер ниже."));
    return;
  }

  state.servers.forEach((server) => {
    const item = el("div", `server-item${state.selectedServerId === server.id ? " active" : ""}`);
    const top = el("div", "server-item-top");
    const title = el("button", "server-select");
    title.type = "button";
    title.textContent = server.name;
    title.addEventListener("click", () => {
      state.selectedServerId = server.id;
      renderServerList();
      loadSelectedServer();
    });
    top.appendChild(title);

    const remove = el("button", "ghost mini-button", "Удалить");
    remove.type = "button";
    remove.addEventListener("click", async () => {
      try {
        await request(`/api/servers?id=${encodeURIComponent(server.id)}`, { method: "DELETE" });
        if (state.selectedServerId === server.id) {
          state.selectedServerId = null;
        }
        showStatus(`Сервер ${server.name} удалён.`, "success");
        await boot();
      } catch (error) {
        showStatus(`Ошибка удаления сервера: ${error.message}`, "error");
      }
    });
    top.appendChild(remove);
    item.appendChild(top);

    item.appendChild(el("p", "muted", server.location || server.host));
    item.appendChild(el("code", "", server.host));

    const stats = el("div", "server-badges");
    stats.appendChild(el("span", "badge", `Активных: ${server.active_keys || 0}`));
    stats.appendChild(el("span", "badge", `Заблок.: ${server.blocked_keys || 0}`));
    stats.appendChild(el("span", "badge", `Истекли: ${server.expired_keys || 0}`));
    item.appendChild(stats);

    serverList.appendChild(item);
  });
}

async function loadServers() {
  const payload = await request("/api/servers");
  state.servers = payload.servers || [];
  if (!state.selectedServerId && state.servers.length) {
    state.selectedServerId = state.servers[0].id;
  }
  if (state.selectedServerId && !state.servers.some((server) => server.id === state.selectedServerId)) {
    state.selectedServerId = state.servers[0]?.id || null;
  }
  renderServerList();
}

async function loadUsers() {
  const payload = await request("/api/users");
  state.users = payload.users || [];
  renderUsers();
}

async function loadServerChecks() {
  serverCheckList.innerHTML = "";
  serverCheckList.appendChild(el("p", "hint", "Проверяю SSH-доступ..."));
  const payload = await request("/api/server-check");
  serverCheckList.innerHTML = "";
  payload.servers.forEach((server) => {
    const card = el("div", `server-check ${server.ok ? "ok" : "bad"}`);
    card.appendChild(el("strong", "", server.server_name));
    card.appendChild(el("span", "", server.message));
    serverCheckList.appendChild(card);
  });
}

function statusLabel(key) {
  if (key.status === "active") {
    return "Активен";
  }
  if (key.status === "blocked") {
    return "Заблокирован";
  }
  if (key.status === "expired") {
    return "Истёк";
  }
  return key.status;
}

function renderKeyCard(key, server) {
  const card = el("article", "key-card");

  const head = el("div", "key-head");
  const titleWrap = el("div", "key-title-wrap");
  titleWrap.appendChild(el("strong", "", key.user_name));
  titleWrap.appendChild(el("p", "muted", key.user_contact || "Контакт не указан"));
  head.appendChild(titleWrap);

  const keyActions = el("div", "key-actions");
  keyActions.appendChild(el("span", `status ${key.status}`, statusLabel(key)));
  head.appendChild(keyActions);
  card.appendChild(head);

  if (key.user_note) {
    card.appendChild(el("p", "note", key.user_note));
  }

  const infoGrid = el("div", "info-grid");
  infoGrid.appendChild(el("p", "mono", `Public: ${key.public_key}`));
  infoGrid.appendChild(el("p", "mono", `Private: ${key.private_key_masked}`));
  infoGrid.appendChild(el("p", "hint", `Выдан: ${formatDateTime(key.created_at)}`));
  infoGrid.appendChild(
    el("p", "hint", key.is_perpetual ? "Годен: бессрочно" : `Годен до: ${formatDateTime(key.expires_at)}`)
  );
  if (key.blocked_at) {
    infoGrid.appendChild(el("p", "hint", `Блокировка: ${formatDateTime(key.blocked_at)}`));
  }
  if (key.block_reason) {
    infoGrid.appendChild(el("p", "hint", `Причина: ${key.block_reason}`));
  }
  card.appendChild(infoGrid);

  const actionRow = el("div", "key-actions wrap");
  const baseName = safeFilename(key.user_name);

  const downloadVpnBtn = el("button", "", "Скачать .vpn");
  downloadVpnBtn.type = "button";
  downloadVpnBtn.addEventListener("click", () => {
    downloadTextFile(`${baseName}.vpn`, key.vpn_uri || "");
  });
  actionRow.appendChild(downloadVpnBtn);

  const downloadConfBtn = el("button", "ghost", "Скачать .conf");
  downloadConfBtn.type = "button";
  downloadConfBtn.addEventListener("click", () => {
    downloadTextFile(`${baseName}.conf`, key.config_blob || "");
  });
  actionRow.appendChild(downloadConfBtn);

  const copyBtn = el("button", "ghost", "Копировать ключ");
  copyBtn.type = "button";
  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(key.vpn_uri || "");
      showStatus(`Ключ для ${key.user_name} скопирован.`, "success");
    } catch (error) {
      showStatus(`Не удалось скопировать ключ: ${error.message}`, "error");
    }
  });
  actionRow.appendChild(copyBtn);

  if (key.status === "active") {
    const blockBtn = el("button", "ghost danger", "Заблокировать");
    blockBtn.type = "button";
    blockBtn.addEventListener("click", async () => {
      try {
        await request("/api/keys/block", {
          method: "POST",
          body: JSON.stringify({ key_id: key.id }),
        });
        showStatus(`Ключ ${key.user_name} заблокирован на сервере ${server.name}.`, "success");
        await Promise.all([loadServers(), loadUsers(), loadSelectedServer()]);
      } catch (error) {
        showStatus(`Ошибка блокировки: ${error.message}`, "error");
      }
    });
    actionRow.appendChild(blockBtn);
  } else {
    const unblockBtn = el("button", "", "Разблокировать");
    unblockBtn.type = "button";
    unblockBtn.addEventListener("click", async () => {
      try {
        await request("/api/keys/unblock", {
          method: "POST",
          body: JSON.stringify({ key_id: key.id }),
        });
        showStatus(`Ключ ${key.user_name} снова активен.`, "success");
        await Promise.all([loadServers(), loadUsers(), loadSelectedServer()]);
      } catch (error) {
        showStatus(`Ошибка разблокировки: ${error.message}`, "error");
      }
    });
    actionRow.appendChild(unblockBtn);
  }

  const deleteBtn = el("button", "ghost danger", "Удалить");
  deleteBtn.type = "button";
  deleteBtn.addEventListener("click", async () => {
    try {
      await request(`/api/keys?id=${encodeURIComponent(key.id)}`, { method: "DELETE" });
      showStatus(`Ключ ${key.user_name} удалён.`, "success");
      await Promise.all([loadServers(), loadUsers(), loadSelectedServer()]);
    } catch (error) {
      showStatus(`Ошибка удаления ключа: ${error.message}`, "error");
    }
  });
  actionRow.appendChild(deleteBtn);

  card.appendChild(actionRow);

  const validityForm = el("form", "validity-form");
  const dateLabel = el("label", "");
  dateLabel.appendChild(el("span", "", "Годен до"));
  const dateInput = el("input", "");
  dateInput.type = "date";
  dateInput.name = "expires_at";
  dateInput.value = formatDateForInput(key.expires_at);
  dateInput.disabled = Boolean(key.is_perpetual);
  dateLabel.appendChild(dateInput);
  validityForm.appendChild(dateLabel);

  const perpetualLabel = el("label", "checkbox-row");
  const perpetualInput = el("input", "");
  perpetualInput.type = "checkbox";
  perpetualInput.name = "is_perpetual";
  perpetualInput.checked = Boolean(key.is_perpetual);
  perpetualInput.addEventListener("change", () => {
    dateInput.disabled = perpetualInput.checked;
  });
  perpetualLabel.appendChild(perpetualInput);
  perpetualLabel.appendChild(el("span", "", "Бессрочный ключ"));
  validityForm.appendChild(perpetualLabel);

  const saveValidityBtn = el("button", "ghost", "Сохранить срок");
  saveValidityBtn.type = "submit";
  validityForm.appendChild(saveValidityBtn);

  validityForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await request("/api/keys/validity", {
        method: "POST",
        body: JSON.stringify({
          key_id: key.id,
          expires_at: dateInput.value,
          is_perpetual: perpetualInput.checked,
        }),
      });
      showStatus(`Срок действия ключа ${key.user_name} обновлён.`, "success");
      await Promise.all([loadServers(), loadSelectedServer()]);
    } catch (error) {
      showStatus(`Ошибка обновления срока: ${error.message}`, "error");
    }
  });
  card.appendChild(validityForm);

  const vpnArea = el("textarea", "vpn-uri");
  vpnArea.readOnly = true;
  vpnArea.rows = 4;
  vpnArea.value = key.vpn_uri || "";
  card.appendChild(vpnArea);

  const confArea = el("textarea", "config");
  confArea.readOnly = true;
  confArea.rows = 8;
  confArea.value = key.config_blob || "";
  card.appendChild(confArea);

  return card;
}

function renderIssueForm(server) {
  const panel = el("section", "panel inner-panel");
  panel.appendChild(el("h3", "", `Выдать ключ на сервер ${server.name}`));

  const hint = el(
    "p",
    "muted",
    "Можно создать бессрочный ключ или задать дату окончания. После истечения срок будет применён автоматически."
  );
  panel.appendChild(hint);

  const form = el("form", "form");

  const nameLabel = el("label", "");
  nameLabel.appendChild(el("span", "", "Имя клиента"));
  const nameInput = el("input", "");
  nameInput.name = "name";
  nameInput.required = true;
  nameInput.placeholder = "Например: barabuka";
  nameLabel.appendChild(nameInput);
  form.appendChild(nameLabel);

  const contactLabel = el("label", "");
  contactLabel.appendChild(el("span", "", "Контакт"));
  const contactInput = el("input", "");
  contactInput.name = "contact";
  contactInput.placeholder = "Telegram, email, CRM ID";
  contactLabel.appendChild(contactInput);
  form.appendChild(contactLabel);

  const noteLabel = el("label", "");
  noteLabel.appendChild(el("span", "", "Заметка"));
  const noteInput = el("textarea", "");
  noteInput.name = "note";
  noteInput.rows = 3;
  noteInput.placeholder = "Тариф, источник, комментарий";
  noteLabel.appendChild(noteInput);
  form.appendChild(noteLabel);

  const dateLabel = el("label", "");
  dateLabel.appendChild(el("span", "", "Годен до"));
  const dateInput = el("input", "");
  dateInput.type = "date";
  dateInput.name = "expires_at";
  dateLabel.appendChild(dateInput);
  form.appendChild(dateLabel);

  const perpetualLabel = el("label", "checkbox-row");
  const perpetualInput = el("input", "");
  perpetualInput.type = "checkbox";
  perpetualInput.name = "is_perpetual";
  perpetualInput.checked = true;
  perpetualInput.addEventListener("change", () => {
    dateInput.disabled = perpetualInput.checked;
  });
  dateInput.disabled = true;
  perpetualLabel.appendChild(perpetualInput);
  perpetualLabel.appendChild(el("span", "", "Бессрочный ключ"));
  form.appendChild(perpetualLabel);

  const submitBtn = el("button", "", "Выдать ключ");
  submitBtn.type = "submit";
  form.appendChild(submitBtn);

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      submitBtn.disabled = true;
      showStatus(`Выдаю ключ на сервере ${server.name}...`, "info");
      await request("/api/keys", {
        method: "POST",
        body: JSON.stringify({
          server_id: server.id,
          name: nameInput.value,
          contact: contactInput.value,
          note: noteInput.value,
          expires_at: dateInput.value,
          is_perpetual: perpetualInput.checked,
        }),
      });
      form.reset();
      perpetualInput.checked = true;
      dateInput.disabled = true;
      showStatus(`Ключ на сервере ${server.name} успешно выдан.`, "success");
      await Promise.all([loadServers(), loadUsers(), loadSelectedServer()]);
    } catch (error) {
      showStatus(`Ошибка выдачи ключа: ${error.message}`, "error");
    } finally {
      submitBtn.disabled = false;
    }
  });

  panel.appendChild(form);
  return panel;
}

function renderServerPage(payload) {
  const { server, keys } = payload;
  serverPage.innerHTML = "";

  const header = el("div", "section-head server-header");
  const titleWrap = el("div", "");
  titleWrap.appendChild(el("h2", "", server.name));
  titleWrap.appendChild(el("p", "muted", `${server.location || server.host} • ${server.host}`));
  header.appendChild(titleWrap);

  const badges = el("div", "server-badges");
  badges.appendChild(el("span", "badge", `Всего: ${server.total_keys || 0}`));
  badges.appendChild(el("span", "badge", `Активных: ${server.active_keys || 0}`));
  badges.appendChild(el("span", "badge", `Заблок.: ${server.blocked_keys || 0}`));
  badges.appendChild(el("span", "badge", `Истекли: ${server.expired_keys || 0}`));
  header.appendChild(badges);
  serverPage.appendChild(header);

  const layout = el("div", "server-layout");
  layout.appendChild(renderIssueForm(server));

  const keysSection = el("section", "panel inner-panel");
  keysSection.appendChild(el("h3", "", "Клиенты и ключи"));
  if (!keys.length) {
    keysSection.appendChild(el("p", "hint", "На этом сервере пока нет выданных ключей."));
  } else {
    const list = el("div", "keys");
    keys.forEach((key) => list.appendChild(renderKeyCard(key, server)));
    keysSection.appendChild(list);
  }
  layout.appendChild(keysSection);

  serverPage.appendChild(layout);
}

async function loadSelectedServer() {
  if (!state.selectedServerId) {
    serverPage.innerHTML = "";
    serverPage.appendChild(el("p", "hint", "Добавьте сервер или выберите его слева, чтобы увидеть клиентов и выдать ключ."));
    return;
  }
  const payload = await request(`/api/server-details?id=${encodeURIComponent(state.selectedServerId)}`);
  renderServerPage(payload);
}

serverForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(serverForm);
  try {
    showStatus("Подключаюсь к серверу и устанавливаю SSH-ключ...", "info");
    await request("/api/servers", {
      method: "POST",
      body: JSON.stringify({
        id: formData.get("id"),
        name: formData.get("name"),
        host: formData.get("host"),
        endpoint_host: formData.get("endpoint_host"),
        location: formData.get("location"),
        ssh_user: formData.get("ssh_user"),
        ssh_port: formData.get("ssh_port"),
        password: formData.get("password"),
      }),
    });
    serverForm.reset();
    serverForm.querySelector('[name="ssh_user"]').value = "root";
    serverForm.querySelector('[name="ssh_port"]').value = "22";
    showStatus("Сервер добавлен и готов к выдаче ключей.", "success");
    await boot();
  } catch (error) {
    showStatus(`Ошибка добавления сервера: ${error.message}`, "error");
  }
});

checkServersBtn.addEventListener("click", async () => {
  try {
    await loadServerChecks();
    showStatus("Проверка серверов завершена.", "info");
  } catch (error) {
    showStatus(`Ошибка проверки серверов: ${error.message}`, "error");
  }
});

clearServersBtn.addEventListener("click", async () => {
  try {
    await request("/api/servers/all", { method: "DELETE" });
    state.selectedServerId = null;
    showStatus("Список серверов очищен.", "success");
    await boot();
  } catch (error) {
    showStatus(`Ошибка очистки серверов: ${error.message}`, "error");
  }
});

refreshBtn.addEventListener("click", async () => {
  try {
    await Promise.all([loadUsers(), loadServers(), loadSelectedServer()]);
    showStatus("Данные обновлены.", "info");
  } catch (error) {
    showStatus(`Ошибка обновления: ${error.message}`, "error");
  }
});

async function boot() {
  try {
    clearStatus();
    await Promise.all([loadServers(), loadUsers(), loadServerChecks()]);
    await loadSelectedServer();
  } catch (error) {
    showStatus(`Ошибка загрузки: ${error.message}`, "error");
    serverPage.innerHTML = "";
    serverPage.appendChild(el("p", "hint", `Ошибка загрузки: ${error.message}`));
  }
}

boot();
