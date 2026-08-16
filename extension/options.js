// options.js — reads and writes chrome.storage.local directly; there is no
// server-side settings API, so "save" here IS the whole persistence layer.

const serverUrlEl = document.getElementById("serverUrl");
const extensionTokenEl = document.getElementById("extensionToken");
const connectionStatusEl = document.getElementById("connectionStatus");
const mappingTbody = document.querySelector("#mappingTable tbody");
const newHostEl = document.getElementById("newHost");
const newCredIdEl = document.getElementById("newCredId");

async function loadAll() {
  const { serverUrl, extensionToken, siteMappings } = await chrome.storage.local.get([
    "serverUrl",
    "extensionToken",
    "siteMappings",
  ]);
  serverUrlEl.value = serverUrl || "";
  extensionTokenEl.value = extensionToken || "";
  renderMappings(siteMappings || {});
}

function renderMappings(mappings) {
  mappingTbody.innerHTML = "";
  for (const [host, credentialId] of Object.entries(mappings)) {
    const tr = document.createElement("tr");

    const hostTd = document.createElement("td");
    hostTd.textContent = host;

    const credTd = document.createElement("td");
    credTd.textContent = String(credentialId);

    const actionTd = document.createElement("td");
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "Remove";
    removeBtn.addEventListener("click", () => removeMapping(host));
    actionTd.appendChild(removeBtn);

    tr.append(hostTd, credTd, actionTd);
    mappingTbody.appendChild(tr);
  }
}

async function removeMapping(host) {
  const { siteMappings } = await chrome.storage.local.get("siteMappings");
  const next = { ...(siteMappings || {}) };
  delete next[host];
  await chrome.storage.local.set({ siteMappings: next });
  renderMappings(next);
}

document.getElementById("addMapping").addEventListener("click", async () => {
  const host = newHostEl.value.trim().toLowerCase();
  const credentialId = parseInt(newCredIdEl.value, 10);
  if (!host || !Number.isInteger(credentialId) || credentialId < 1) {
    return;
  }
  const { siteMappings } = await chrome.storage.local.get("siteMappings");
  const next = { ...(siteMappings || {}), [host]: credentialId };
  await chrome.storage.local.set({ siteMappings: next });
  renderMappings(next);
  newHostEl.value = "";
  newCredIdEl.value = "";
});

document.getElementById("saveConnection").addEventListener("click", async () => {
  const serverUrl = serverUrlEl.value.trim().replace(/\/+$/, "");
  const extensionToken = extensionTokenEl.value.trim();
  connectionStatusEl.textContent = "";
  connectionStatusEl.className = "status";
  if (!serverUrl || !extensionToken) {
    connectionStatusEl.textContent = "Both fields are required.";
    connectionStatusEl.className = "status err";
    return;
  }
  try {
    // eslint-disable-next-line no-new
    new URL(serverUrl);
  } catch {
    connectionStatusEl.textContent = "That does not look like a valid URL.";
    connectionStatusEl.className = "status err";
    return;
  }
  await chrome.storage.local.set({ serverUrl, extensionToken });
  connectionStatusEl.textContent = "Saved.";
  connectionStatusEl.className = "status ok";
});

loadAll();
