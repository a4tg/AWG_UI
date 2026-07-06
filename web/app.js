const serverList = document.getElementById("serverList");
const usersRoot = document.getElementById("users");
const userForm = document.getElementById("userForm");
const userCount = document.getElementById("userCount");
const refreshBtn = document.getElementById("refreshBtn");
const statusBox = document.getElementById("statusBox");
const userCardTemplate = document.getElementById("userCardTemplate");
const keyCardTemplate = document.getElementById("keyCardTemplate");

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

async function loadServers() {
  const payload = await request("/api/servers");
  serverList.innerHTML = "";
  payload.servers.forEach((server) => {
    const node = document.createElement("div");
    node.className = "server-item";
    node.innerHTML = `
      <strong>${server.name}</strong>
      <span>${server.location}</span>
      <code>${server.host}</code>
    `;
    serverList.appendChild(node);
  });
}

function renderKey(key) {
  const node = keyCardTemplate.content.firstElementChild.cloneNode(true);
  node.querySelector("strong").textContent = key.server_name;
  node.querySelector(".public-key").textContent = `Public: ${key.public_key}`;
  node.querySelector(".private-key").textContent = `Private: ${key.private_key_masked}`;
  node.querySelector(".config").value = key.config_blob;
  return node;
}

function renderUser(user) {
  const node = userCardTemplate.content.firstElementChild.cloneNode(true);
  node.dataset.userId = String(user.id);
  node.querySelector("h3").textContent = user.name;
  node.querySelector(".meta").textContent = user.contact || "Контакт не указан";
  node.querySelector(".note").textContent = user.note || "Без заметки";

  const keysRoot = node.querySelector(".keys");
  if (!user.keys.length) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "Ключи ещё не выпущены.";
    keysRoot.appendChild(empty);
  } else {
    user.keys.forEach((key) => keysRoot.appendChild(renderKey(key)));
  }

  node.querySelector(".provision-btn").addEventListener("click", async () => {
    const button = node.querySelector(".provision-btn");
    try {
      button.disabled = true;
      showStatus(`Выдаю ключи для ${user.name}...`, "info");
      await request("/api/provision", {
        method: "POST",
        body: JSON.stringify({ user_id: user.id }),
      });
      showStatus(`Ключи для ${user.name} успешно выданы.`, "success");
      await loadUsers();
    } catch (error) {
      showStatus(`Ошибка выдачи ключей: ${error.message}`, "error");
    } finally {
      button.disabled = false;
    }
  });

  node.querySelector(".delete-btn").addEventListener("click", async () => {
    try {
      await request(`/api/users?id=${user.id}`, { method: "DELETE" });
      showStatus(`Пользователь ${user.name} удалён.`, "success");
      await loadUsers();
    } catch (error) {
      showStatus(`Ошибка удаления: ${error.message}`, "error");
    }
  });

  return node;
}

async function loadUsers() {
  const payload = await request("/api/users");
  usersRoot.innerHTML = "";
  userCount.textContent = String(payload.users.length);
  if (!payload.users.length) {
    usersRoot.innerHTML = '<p class="hint">Пока нет пользователей. Создайте первого клиента слева.</p>';
    return;
  }
  payload.users.forEach((user) => usersRoot.appendChild(renderUser(user)));
}

userForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(userForm);
  try {
    await request("/api/users", {
      method: "POST",
      body: JSON.stringify({
        name: formData.get("name"),
        contact: formData.get("contact"),
        note: formData.get("note"),
      }),
    });
    userForm.reset();
    showStatus("Пользователь создан.", "success");
    await loadUsers();
  } catch (error) {
    showStatus(`Ошибка создания пользователя: ${error.message}`, "error");
  }
});

refreshBtn.addEventListener("click", async () => {
  try {
    await loadUsers();
    showStatus("Список пользователей обновлён.", "info");
  } catch (error) {
    showStatus(`Ошибка обновления: ${error.message}`, "error");
  }
});

async function boot() {
  try {
    clearStatus();
    await Promise.all([loadServers(), loadUsers()]);
  } catch (error) {
    showStatus(`Ошибка загрузки: ${error.message}`, "error");
    usersRoot.innerHTML = `<p class="hint">Ошибка загрузки: ${error.message}</p>`;
  }
}

boot();
