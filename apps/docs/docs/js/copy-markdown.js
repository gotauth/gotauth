// "Copy page as Markdown": every page has a Markdown copy next to it
// (/docs/quickstart/ -> /docs/quickstart.md), written by hooks.py.
;(function () {
  function markdownURL() {
    // Material's page config holds the relative path to the site root ("." or "..").
    var config = JSON.parse(document.getElementById("__config").textContent)
    var root = new URL(config.base.replace(/\/?$/, "/"), location.href).pathname
    var path = location.pathname.replace(/index\.html$/, "")
    if (!path.endsWith("/")) path += "/"
    // The home page's copy is index.md.
    if (path === root) return root + "index.md"
    return path.replace(/\/$/, "") + ".md"
  }

  function addButton() {
    var article = document.querySelector("article.md-content__inner")
    if (!article || article.querySelector(".gotauth-copy-md")) return
    var heading = article.querySelector("h1")
    var button = document.createElement("button")
    button.type = "button"
    button.className = "md-button gotauth-copy-md"
    button.textContent = "Copy page as Markdown"
    var status = document.createElement("span")
    status.className = "gotauth-copy-status"
    status.setAttribute("role", "status")
    status.setAttribute("aria-live", "polite")
    button.addEventListener("click", function () {
      fetch(markdownURL())
        .then(function (response) {
          if (!response.ok) throw new Error("HTTP " + response.status)
          return response.text()
        })
        .then(function (text) {
          return navigator.clipboard.writeText(text)
        })
        .then(function () {
          status.textContent = "Copied."
        })
        .catch(function () {
          status.textContent = "Copying didn't work. Open " + markdownURL() + " instead."
        })
    })
    var bar = document.createElement("div")
    bar.className = "gotauth-copy-bar"
    bar.appendChild(button)
    bar.appendChild(status)
    if (heading) heading.insertAdjacentElement("afterend", bar)
    else article.prepend(bar)
  }

  // Material's instant navigation swaps pages without a reload.
  if (window.document$) window.document$.subscribe(addButton)
  else document.addEventListener("DOMContentLoaded", addButton)
})()
