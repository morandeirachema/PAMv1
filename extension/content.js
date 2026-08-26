// content.js — runs on every page. It does two things only: look for a
// password field, and (only if this hostname has a configured credential
// mapping) offer a button that asks the background script to reveal and
// fill it. It never reads or writes anything except the form fields it
// itself fills, and never sends page content anywhere.

const PROCESSED_ATTR = "data-pamv1-autofill-processed";

async function credentialIdForThisSite() {
  const { siteMappings } = await chrome.storage.local.get("siteMappings");
  return (siteMappings || {})[location.hostname.toLowerCase()] || null;
}

// findUsernameField looks near a password field for the username input a
// real login form almost always has beside it — by autocomplete hint first
// (the most reliable signal a site can give), then by common name/type
// patterns, scoped to the same <form> so a page with several unrelated
// inputs does not fill the wrong one.
function findUsernameField(passwordField) {
  const form = passwordField.closest("form") || document;
  const candidates = form.querySelectorAll(
    'input[autocomplete="username"], input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]'
  );
  for (const el of candidates) {
    if (el !== passwordField && el.type !== "password") {
      return el;
    }
  }
  return null;
}

function setFieldValue(field, value) {
  const proto = Object.getPrototypeOf(field);
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
  if (setter) {
    setter.call(field, value);
  } else {
    field.value = value;
  }
  // Most frameworks (React et al.) listen for "input", not a direct value
  // assignment, to notice the change.
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
}

function makeAutofillButton(passwordField, credentialId) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "🔑 PAMv1";
  button.title = "Fill from PAMv1";
  button.style.cssText =
    "position:absolute;z-index:2147483647;font-size:11px;padding:2px 6px;" +
    "border:1px solid #888;border-radius:4px;background:#fff;color:#222;cursor:pointer;";

  const place = () => {
    const rect = passwordField.getBoundingClientRect();
    button.style.top = `${window.scrollY + rect.top}px`;
    button.style.left = `${window.scrollX + rect.right + 4}px`;
  };
  place();
  window.addEventListener("resize", place);
  window.addEventListener("scroll", place, true);

  button.addEventListener("click", async (ev) => {
    ev.preventDefault();
    button.disabled = true;
    button.textContent = "…";
    try {
      const result = await chrome.runtime.sendMessage({ type: "reveal", credentialId });
      if (!result?.ok) {
        throw new Error(result?.error || "reveal failed");
      }
      const userField = findUsernameField(passwordField);
      if (userField) {
        setFieldValue(userField, result.username);
      }
      setFieldValue(passwordField, result.secret);
      button.textContent = "✓";
    } catch (err) {
      button.textContent = "✗";
      button.title = String(err?.message || err);
    } finally {
      setTimeout(() => {
        button.disabled = false;
        button.textContent = "🔑 PAMv1";
        button.title = "Fill from PAMv1";
      }, 2000);
    }
  });

  document.body.appendChild(button);
}

async function scan() {
  const credentialId = await credentialIdForThisSite();
  if (!credentialId) {
    return; // no mapping for this site — nothing to offer
  }
  const passwordFields = document.querySelectorAll(`input[type="password"]:not([${PROCESSED_ATTR}])`);
  for (const field of passwordFields) {
    field.setAttribute(PROCESSED_ATTR, "1");
    makeAutofillButton(field, credentialId);
  }
}

scan();

// Single-page apps render their login form after the initial load, so keep
// watching — debounced, since a busy page can mutate the DOM constantly.
let rescanTimer = null;
new MutationObserver(() => {
  clearTimeout(rescanTimer);
  rescanTimer = setTimeout(scan, 300);
}).observe(document.documentElement, { childList: true, subtree: true });
