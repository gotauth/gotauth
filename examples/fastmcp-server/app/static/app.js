// Every change goes straight to GotAuth's JSON endpoints, which check the Origin
// header: sign-in, sign-up, sign-out and revoking an app.
"use strict";

const AUTH = "/api/auth";

async function post(path, body) {
  const response = await fetch(AUTH + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body ?? {}),
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, data };
}

// Only GotAuth's own authorize endpoint on this origin: never an open redirect.
function safeCallback(value) {
  try {
    const url = new URL(value, window.location.origin);
    if (url.origin !== window.location.origin) return "/";
    const paths = [AUTH + "/oauth2/authorize", "/connected-apps", "/"];
    return paths.includes(url.pathname) ? url.href : "/";
  } catch {
    return "/";
  }
}

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-sign-in]");
  if (!form) return;
  event.preventDefault();
  const action = event.submitter?.value === "sign-up" ? "/sign-up/email" : "/sign-in/email";
  const fields = new FormData(form);
  const { ok, data } = await post(action, {
    email: fields.get("email"),
    password: fields.get("password"),
  });
  if (ok) {
    window.location.assign(safeCallback(form.dataset.callback));
  } else {
    form.querySelector("[data-message]").textContent =
      data?.error?.message ?? "That did not work. Try again.";
  }
});

function fail(element, message) {
  const note = document.createElement("p");
  note.setAttribute("role", "alert");
  note.textContent = message;
  element.after(note);
}

document.addEventListener("click", async (event) => {
  const revoke = event.target.closest("[data-revoke]");
  if (revoke) {
    const { ok } = await post("/oauth2/grants/revoke", { client_id: revoke.dataset.revoke });
    if (ok) window.location.reload();
    else fail(revoke, "Revoking failed: the app still has access. Reload and try again.");
    return;
  }
  const signOut = event.target.closest("[data-sign-out]");
  if (signOut) {
    const { ok } = await post("/sign-out");
    if (ok) window.location.assign("/");
    else fail(signOut, "Signing out failed. Reload and try again.");
  }
});
