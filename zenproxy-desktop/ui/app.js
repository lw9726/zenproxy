const invoke = window.__TAURI_INTERNALS__.invoke;

const state = {
  settings: null,
  status: null,
  remoteProxies: [],
  localProxies: [],
  bindings: [],
  subscriptions: [],
  selectedRemote: new Set(),
  selectedLocal: new Set(),
  toastTimer: null,
};

const viewMeta = {
  dashboard: ["总览", "管理本地 `zenproxy-client`，把在线节点顺手落到本地池。"],
  remote: ["在线代理池", "从服务端采样预览，再导入本地代理池。"],
  local: ["本地代理池", "本地 store、批量绑定和端口释放都在这里。"],
  subscriptions: ["本地订阅", "订阅写入本地池后，后续刷新也在这里做。"],
  settings: ["设置", "服务端连接、本地控制器和端口范围。"],
};

function $(id) {
  return document.getElementById(id);
}

function showToast(message, isError = false) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  toast.style.color = isError ? "var(--danger)" : "var(--text)";
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.add("hidden"), 2600);
}

function logActivity(message) {
  const node = $("activity-log");
  const time = new Date().toLocaleTimeString();
  if (node.classList.contains("empty")) {
    node.classList.remove("empty");
    node.textContent = "";
  }
  node.textContent = `[${time}] ${message}\n` + node.textContent;
}

function setTheme(isDark) {
  document.body.classList.toggle("dark", isDark);
}

function switchView(view) {
  document.querySelectorAll(".nav-item").forEach((node) => {
    node.classList.toggle("active", node.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((node) => {
    node.classList.toggle("active", node.id === `view-${view}`);
  });
  $("view-title").textContent = viewMeta[view][0];
  $("view-subtitle").textContent = viewMeta[view][1];
}

function formatBool(value) {
  return value ? "是" : "否";
}

function fillSettings(settings) {
  state.settings = settings;
  $("server-url").value = settings.serverUrl;
  $("api-key").value = settings.apiKey;
  $("controller-input").value = settings.controllerUrl;
  $("controller-secret").value = settings.controllerSecret;
  $("binary-input").value = settings.binaryPath;
  $("config-input").value = settings.localConfigPath;
  $("port-start").value = settings.portStart;
  $("port-end").value = settings.portEnd;
  $("default-fetch-count").value = settings.defaultFetchCount;
  $("default-country").value = settings.defaultCountry;
  $("default-proxy-type").value = settings.defaultProxyType;
  $("settings-auto-bind").checked = settings.autoBindAfterImport;
  $("settings-dark").checked = settings.preferDark;
  $("quick-count").value = settings.defaultFetchCount;
  $("quick-country").value = settings.defaultCountry;
  $("quick-type").value = settings.defaultProxyType;
  $("quick-auto-bind").checked = settings.autoBindAfterImport;
  $("remote-count").value = settings.defaultFetchCount;
  $("remote-country").value = settings.defaultCountry;
  $("remote-type").value = settings.defaultProxyType;
  $("default-count").textContent = settings.defaultFetchCount;
  $("controller-url").textContent = settings.controllerUrl;
  setTheme(settings.preferDark);
}

function renderStatus(status) {
  state.status = status;
  $("run-pill").textContent = status.running ? "进程运行中" : "进程未启动";
  $("run-pill").className = `pill ${status.running ? "ok" : "bad"}`;
  $("reach-pill").textContent = status.reachable ? "API 已连接" : "API 未连接";
  $("reach-pill").className = `pill ${status.reachable ? "ok" : "bad"}`;
  $("binary-path").textContent = status.binaryPath || "未发现 `zenproxy-client`";
  $("controller-url").textContent = state.settings?.controllerUrl || "-";
  $("port-range").textContent = status.portRange;
  $("config-path").textContent = status.configPath || "-";
}

function renderRemoteTable() {
  const tbody = $("remote-table");
  if (!state.remoteProxies.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="subtle">还没有在线采样结果</td></tr>`;
    $("remote-meta").textContent = "暂无数据";
    return;
  }
  $("remote-meta").textContent = `当前采样 ${state.remoteProxies.length} 个节点`;
  tbody.innerHTML = state.remoteProxies.map((proxy) => {
    const quality = proxy.quality || {};
    const checked = state.selectedRemote.has(proxy.id) ? "checked" : "";
    return `
      <tr>
        <td><input type="checkbox" data-remote-id="${proxy.id}" ${checked}></td>
        <td>${proxy.name || proxy.id}</td>
        <td><span class="badge">${proxy.type || "-"}</span></td>
        <td>${quality.country || "-"}</td>
        <td>${proxy.server || "-"}:${proxy.port || "-"}</td>
        <td>${formatBool(quality.is_residential)}</td>
        <td>${quality.risk_level || "-"}</td>
      </tr>
    `;
  }).join("");
}

function renderLocalTable() {
  const tbody = $("local-table");
  if (!state.localProxies.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="subtle">本地代理池为空</td></tr>`;
    $("local-meta").textContent = "暂无数据";
    return;
  }
  $("local-meta").textContent = `本地池 ${state.localProxies.length} 个节点`;
  tbody.innerHTML = state.localProxies.map((proxy) => {
    const checked = state.selectedLocal.has(proxy.id) ? "checked" : "";
    return `
      <tr>
        <td><input type="checkbox" data-local-id="${proxy.id}" ${checked}></td>
        <td>${proxy.name || proxy.id}</td>
        <td><span class="badge">${proxy.type || "-"}</span></td>
        <td>${proxy.source || "-"}</td>
        <td>${proxy.server || "-"}:${proxy.port || "-"}</td>
        <td>${proxy.local_port || "-"}</td>
        <td class="actions">
          <button class="link-btn" data-delete-proxy="${proxy.id}">删除</button>
        </td>
      </tr>
    `;
  }).join("");
  $("local-count").textContent = state.localProxies.length;
}

function renderBindings() {
  const tbody = $("bindings-table");
  if (!state.bindings.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="subtle">当前没有活跃绑定</td></tr>`;
    $("binding-count").textContent = "0";
    return;
  }
  $("binding-count").textContent = state.bindings.length;
  tbody.innerHTML = state.bindings.map((binding) => `
    <tr>
      <td>${binding.tag}</td>
      <td>${binding.proxy_id || "-"}</td>
      <td>${binding.listen_port}</td>
      <td><button class="link-btn" data-delete-binding="${binding.tag}">删除</button></td>
    </tr>
  `).join("");
}

function renderSubscriptions() {
  const tbody = $("subscriptions-table");
  if (!state.subscriptions.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="subtle">还没有本地订阅</td></tr>`;
    $("subscription-count").textContent = "0";
    return;
  }
  $("subscription-count").textContent = state.subscriptions.length;
  tbody.innerHTML = state.subscriptions.map((sub) => `
    <tr>
      <td>${sub.name}</td>
      <td>${sub.type}</td>
      <td>${sub.proxy_count}</td>
      <td>${sub.updated_at || "-"}</td>
      <td class="actions">
        <button class="link-btn" data-refresh-sub="${sub.id}">刷新</button>
        <button class="link-btn" data-delete-sub="${sub.id}">删除</button>
      </td>
    </tr>
  `).join("");
}

function gatherSettings() {
  return {
    serverUrl: $("server-url").value.trim(),
    apiKey: $("api-key").value.trim(),
    controllerUrl: $("controller-input").value.trim(),
    controllerSecret: $("controller-secret").value.trim(),
    binaryPath: $("binary-input").value.trim(),
    localConfigPath: $("config-input").value.trim(),
    portStart: Number($("port-start").value),
    portEnd: Number($("port-end").value),
    autoBindAfterImport: $("settings-auto-bind").checked,
    defaultFetchCount: Number($("default-fetch-count").value),
    defaultCountry: $("default-country").value.trim(),
    defaultProxyType: $("default-proxy-type").value.trim(),
    preferDark: $("settings-dark").checked,
  };
}

async function call(command, payload = {}) {
  return invoke(command, payload);
}

async function refreshStatus() {
  renderStatus(await call("get_local_status"));
}

async function refreshLocalPool() {
  const data = await call("list_local_pool");
  state.localProxies = data.proxies || [];
  renderLocalTable();
}

async function refreshBindings() {
  state.bindings = await call("list_bindings");
  renderBindings();
}

async function refreshSubscriptions() {
  const data = await call("list_subscriptions");
  state.subscriptions = data.subscriptions || [];
  renderSubscriptions();
}

async function refreshAllLocalData() {
  await Promise.all([refreshLocalPool(), refreshBindings(), refreshSubscriptions()]);
}

async function boot() {
  try {
    const bootData = await call("bootstrap");
    fillSettings(bootData.settings);
    renderStatus(bootData.status);
    await refreshAllLocalData();
  } catch (error) {
    showToast(String(error), true);
  }
}

document.addEventListener("click", async (event) => {
  const remoteId = event.target.dataset.remoteId;
  const localId = event.target.dataset.localId;
  const deleteProxy = event.target.dataset.deleteProxy;
  const deleteBindingTag = event.target.dataset.deleteBinding;
  const refreshSub = event.target.dataset.refreshSub;
  const deleteSub = event.target.dataset.deleteSub;

  if (remoteId) {
    event.target.checked ? state.selectedRemote.add(remoteId) : state.selectedRemote.delete(remoteId);
    return;
  }
  if (localId) {
    event.target.checked ? state.selectedLocal.add(localId) : state.selectedLocal.delete(localId);
    return;
  }
  if (deleteProxy) {
    try {
      await call("delete_local_proxy", { proxyId: deleteProxy });
      state.selectedLocal.delete(deleteProxy);
      await refreshLocalPool();
      logActivity(`已从本地池删除代理 ${deleteProxy}`);
    } catch (error) {
      showToast(String(error), true);
    }
    return;
  }
  if (deleteBindingTag) {
    try {
      await call("delete_binding", { tag: deleteBindingTag });
      await refreshBindings();
      await refreshLocalPool();
      logActivity(`已删除绑定 ${deleteBindingTag}`);
    } catch (error) {
      showToast(String(error), true);
    }
    return;
  }
  if (refreshSub) {
    try {
      const result = await call("refresh_subscription", { subscriptionId: refreshSub });
      await refreshSubscriptions();
      await refreshLocalPool();
      logActivity(result.message || `已刷新订阅 ${refreshSub}`);
    } catch (error) {
      showToast(String(error), true);
    }
    return;
  }
  if (deleteSub) {
    try {
      await call("delete_subscription", { subscriptionId: deleteSub });
      await refreshSubscriptions();
      await refreshLocalPool();
      logActivity(`已删除订阅 ${deleteSub}`);
    } catch (error) {
      showToast(String(error), true);
    }
  }
});

document.querySelectorAll(".nav-item").forEach((node) => {
  node.addEventListener("click", () => switchView(node.dataset.view));
});

$("theme-toggle").addEventListener("click", () => {
  const next = !document.body.classList.contains("dark");
  $("settings-dark").checked = next;
  setTheme(next);
});

$("save-settings").addEventListener("click", async () => {
  try {
    const saved = await call("save_settings", { settings: gatherSettings() });
    fillSettings(saved);
    showToast("设置已保存");
    logActivity("已保存桌面端设置");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("start-client").addEventListener("click", async () => {
  try {
    renderStatus(await call("start_local_client"));
    await refreshAllLocalData();
    showToast("本地客户端已启动");
    logActivity("已启动本地 zenproxy-client");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("stop-client").addEventListener("click", async () => {
  try {
    renderStatus(await call("stop_local_client"));
    showToast("本地客户端已停止");
    logActivity("已停止本地 zenproxy-client");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("go-remote").addEventListener("click", () => switchView("remote"));

$("quick-import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await call("import_remote_pool", {
      request: {
        serverUrl: state.settings.serverUrl,
        apiKey: state.settings.apiKey,
        count: Number($("quick-count").value),
        country: $("quick-country").value.trim(),
        proxyType: $("quick-type").value.trim(),
        chatgpt: $("quick-chatgpt").checked,
        autoBind: $("quick-auto-bind").checked,
      },
    });
    await refreshAllLocalData();
    showToast(result.message || "导入完成");
    logActivity(`快捷导入完成，新增 ${result.added || 0} 个节点`);
  } catch (error) {
    showToast(String(error), true);
  }
});

$("remote-preview").addEventListener("click", async () => {
  try {
    const result = await call("preview_remote_pool", {
      request: {
        serverUrl: $("server-url").value.trim(),
        apiKey: $("api-key").value.trim(),
        count: Number($("remote-count").value),
        country: $("remote-country").value.trim(),
        proxyType: $("remote-type").value.trim(),
        chatgpt: $("remote-chatgpt").checked,
      },
    });
    state.remoteProxies = result.proxies || [];
    state.selectedRemote = new Set(state.remoteProxies.map((proxy) => proxy.id));
    $("remote-select-all").checked = true;
    renderRemoteTable();
    logActivity(`已预览在线池 ${state.remoteProxies.length} 个节点`);
  } catch (error) {
    showToast(String(error), true);
  }
});

async function importRemote(autoBind) {
  if (!state.remoteProxies.length) {
    showToast("先预览在线代理池", true);
    return;
  }
  const selected = state.remoteProxies.filter((proxy) => state.selectedRemote.has(proxy.id));
  if (!selected.length) {
    showToast("先选择要导入的在线代理", true);
    return;
  }
  try {
    const result = await call("import_previewed_proxies", {
      request: {
        proxies: selected,
        autoBind,
      },
    });
    await refreshAllLocalData();
    showToast(result.message || "导入完成");
    logActivity(`从在线池导入 ${result.added || 0} 个节点${autoBind ? "，并已自动绑定" : ""}`);
  } catch (error) {
    showToast(String(error), true);
  }
}

$("remote-import").addEventListener("click", () => importRemote(false));
$("remote-import-bind").addEventListener("click", () => importRemote(true));

$("remote-select-all").addEventListener("change", (event) => {
  state.selectedRemote = event.target.checked
    ? new Set(state.remoteProxies.map((proxy) => proxy.id))
    : new Set();
  renderRemoteTable();
});

$("refresh-local").addEventListener("click", refreshLocalPool);
$("refresh-bindings").addEventListener("click", refreshBindings);
$("refresh-subscriptions").addEventListener("click", refreshSubscriptions);

$("local-select-all").addEventListener("change", (event) => {
  state.selectedLocal = event.target.checked
    ? new Set(state.localProxies.map((proxy) => proxy.id))
    : new Set();
  renderLocalTable();
});

$("bind-selected").addEventListener("click", async () => {
  if (!state.selectedLocal.size) {
    showToast("先选择本地代理", true);
    return;
  }
  try {
    const result = await call("batch_bind_selected", {
      request: { proxyIds: [...state.selectedLocal] },
    });
    await refreshBindings();
    await refreshLocalPool();
    showToast(`已创建 ${result.created || 0} 个绑定`);
    logActivity(`已绑定 ${result.created || 0} 个本地代理`);
  } catch (error) {
    showToast(String(error), true);
  }
});

$("bind-all").addEventListener("click", async () => {
  try {
    const result = await call("bind_all_local_pool");
    await refreshBindings();
    await refreshLocalPool();
    showToast(`已创建 ${result.created || 0} 个绑定`);
    logActivity("已对本地池执行全量绑定");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("clear-local").addEventListener("click", async () => {
  try {
    const result = await call("clear_local_pool");
    state.selectedLocal.clear();
    await refreshLocalPool();
    showToast(result.message || "本地池已清空");
    logActivity("已清空本地代理池");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("clear-bindings").addEventListener("click", async () => {
  try {
    const result = await call("clear_bindings");
    await refreshBindings();
    await refreshLocalPool();
    showToast(result.message || "绑定已清空");
    logActivity("已清空全部绑定");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("add-manual").addEventListener("click", async () => {
  const uri = $("manual-uri").value.trim();
  if (!uri) {
    showToast("先输入代理 URI", true);
    return;
  }
  try {
    await call("add_manual_proxy", { request: { uri } });
    $("manual-uri").value = "";
    await refreshLocalPool();
    showToast("已加入本地代理池");
    logActivity("已手动添加 1 个本地代理");
  } catch (error) {
    showToast(String(error), true);
  }
});

$("add-subscription").addEventListener("click", async () => {
  try {
    await call("add_subscription", {
      request: {
        name: $("sub-name").value.trim(),
        url: $("sub-url").value.trim(),
        subType: $("sub-type").value.trim(),
        content: $("sub-content").value.trim(),
      },
    });
    await refreshSubscriptions();
    await refreshLocalPool();
    $("sub-name").value = "";
    $("sub-url").value = "";
    $("sub-content").value = "";
    showToast("订阅已添加");
    logActivity("已添加本地订阅");
  } catch (error) {
    showToast(String(error), true);
  }
});

setInterval(() => {
  refreshStatus().catch(() => {});
}, 5000);

boot();
