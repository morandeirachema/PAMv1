// background.js — the only place this extension talks to a PAMv1 server.
// The extension token and server URL live in chrome.storage.local; nothing
// here persists in memory between events, since an MV3 service worker can be
// killed and restarted at any time between them.

// Clicking the toolbar icon opens the options page — there is no popup UI.
chrome.action.onClicked.addListener(() => {
  chrome.runtime.openOptionsPage();
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "reveal") {
    return false; // not ours; let another listener (if any) handle it
  }
  revealCredential(message.credentialId)
    .then((result) => sendResponse({ ok: true, ...result }))
    .catch((err) => sendResponse({ ok: false, error: String(err?.message || err) }));
  return true; // keep the message channel open for the async response above
});

// revealCredential calls the existing, already-audited
// POST /api/credentials/{id}/reveal — the extension holds a narrowly-scoped
// token (Phase 147) that this is the ONLY route it can reach; every other
// call with it is refused by the server, so a bug here cannot be leveraged
// into anything broader than what this one route already allows.
async function revealCredential(credentialId) {
  const { serverUrl, extensionToken } = await chrome.storage.local.get(["serverUrl", "extensionToken"]);
  if (!serverUrl || !extensionToken) {
    throw new Error("PAMv1 Autofill is not configured yet — open the extension's settings page.");
  }
  const url = new URL(`/api/credentials/${encodeURIComponent(credentialId)}/reveal`, serverUrl);
  const resp = await fetch(url, {
    method: "POST",
    headers: { "X-API-Key": extensionToken },
  });
  if (resp.status === 403) {
    throw new Error("This token cannot reveal that credential — check the credential ID and your access grant.");
  }
  if (resp.status === 401) {
    throw new Error("This token is invalid or has expired — mint a new one from the PAMv1 portal.");
  }
  if (!resp.ok) {
    throw new Error(`PAMv1 returned ${resp.status}`);
  }
  const body = await resp.json();
  if (body.secret_type && body.secret_type !== "password") {
    throw new Error(`Credential ${credentialId} holds a ${body.secret_type}, not a password — nothing to autofill.`);
  }
  return { username: body.username, secret: body.secret };
}
