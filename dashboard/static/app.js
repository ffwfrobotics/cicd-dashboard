// Theme (auto, light, dark) and the live-connection indicator. Loaded in <head> so the theme is set before paint.
(function () {
  var root = document.documentElement, order = ["auto", "light", "dark"];
  function get() { try { return localStorage.getItem("theme") || "auto"; } catch (e) { return "auto"; } }
  function apply(t) {
    if (t === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
    var b = document.getElementById("theme");
    if (b) {
      b.title = "Theme: " + t;
      b.querySelector("use").setAttribute("href", "/static/icons.svg#" + { auto: "auto", light: "sun", dark: "moon" }[t]);
    }
  }
  apply(get());
  document.addEventListener("DOMContentLoaded", function () { apply(get()); });
  document.addEventListener("click", function (e) {
    if (!e.target.closest || !e.target.closest("#theme")) return;
    var t = order[(order.indexOf(get()) + 1) % order.length];
    try { localStorage.setItem("theme", t); } catch (err) { /* private mode: lasts for this page */ }
    apply(t);
  });
  function conn(on) {
    var c = document.getElementById("conn");
    if (!c) return;
    c.classList.toggle("on", on);
    c.title = on ? "Live updates" : "Reconnecting";
    c.lastElementChild.textContent = on ? "Connected" : "Offline";
  }
  // a form that asks the forge for something takes a few seconds: show it was taken, and don't send it twice
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (!f.method || f.method.toLowerCase() !== "post") return;
    if (f.dataset.sent) { e.preventDefault(); return; }
    f.dataset.sent = "1";
    f.querySelectorAll("button").forEach(function (b) { b.setAttribute("aria-busy", "true"); });
  });
  window.addEventListener("pageshow", function (e) {    // back to a page from the cache: usable again
    if (!e.persisted) return;
    document.querySelectorAll("form[data-sent]").forEach(function (f) {
      delete f.dataset.sent;
      f.querySelectorAll("button").forEach(function (b) { b.removeAttribute("aria-busy"); });
    });
  });
  document.addEventListener("htmx:sseOpen", function () { conn(true); });
  document.addEventListener("htmx:sseError", function () { conn(false); });
  document.addEventListener("htmx:sseClose", function () { conn(false); });
})();
