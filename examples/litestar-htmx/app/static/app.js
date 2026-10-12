// GotAuth's endpoints take JSON. This htmx extension (hx-ext="gotauth-json" on <body>)
// sends form fields as JSON; names listed in data-lists are always arrays.
htmx.defineExtension("gotauth-json", {
  onEvent(name, event) {
    if (name === "htmx:configRequest" && event.detail.verb !== "get") {
      event.detail.headers["Content-Type"] = "application/json"
    }
  },
  encodeParameters(xhr, parameters, element) {
    xhr.overrideMimeType("text/json")
    const lists = (element.dataset.lists || "").split(" ").filter(Boolean)
    const body = {}
    for (const key of lists) body[key] = []
    parameters.forEach((value, key) => {
      if (lists.includes(key)) body[key].push(value)
      else body[key] = value
    })
    return JSON.stringify(body)
  },
})

// What to do with GotAuth's answer, set by data-done on the form or button.
document.addEventListener("htmx:afterRequest", (event) => {
  const element = event.detail.elt
  const done = element.dataset.done
  if (!done) return
  const message = document.getElementById("message")
  let body = null
  try {
    body = JSON.parse(event.detail.xhr.responseText)
  } catch {
    body = null
  }
  if (!event.detail.successful) {
    message.textContent = body?.error?.message ?? "Something went wrong. Try again."
    return
  }
  message.textContent = ""
  if (done === "redirect") window.location.assign(element.dataset.to || "/")
  if (done === "message") message.textContent = element.dataset.text
  if (done === "new-key") {
    // The raw key is in this answer only: show it, never store it.
    const box = document.getElementById("new-key")
    box.querySelector("code").textContent = body.key
    box.hidden = false
    element.reset()
  }
  if (done === "new-key" || done === "reload") htmx.trigger("#keys", "reload")
})
