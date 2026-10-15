(function () {
  "use strict";
  var c = window.STKX || {};

  // Só aceita links https (evita javascript: e similares vindos de config).
  function safeUrl(u) {
    try { var x = new URL(u); return x.protocol === "https:" ? x.href : null; } catch (e) { return null; }
  }

  // Instagram + WhatsApp
  document.querySelectorAll("[data-ig]").forEach(function (el) { if (c.instagramHandle) el.textContent = c.instagramHandle; });
  document.querySelectorAll("[data-ig-link]").forEach(function (el) {
    var u = safeUrl(c.instagramUrl); if (u) el.href = u;
  });
  document.querySelectorAll("[data-wa-link]").forEach(function (el) {
    var u = safeUrl(c.whatsappUrl); if (u) el.href = u;
  });

  // Marquee: dois grupos idênticos => loop contínuo de -50% (montado via DOM, sem innerHTML)
  var track = document.querySelector(".marquee-track");
  if (track) {
    var makeUnit = function () {
      var s = document.createElement("span"); s.className = "m-item";
      var img = new Image(); img.src = "assets/stkx-logo.png"; img.alt = ""; img.width = 143; img.height = 64;
      var t = document.createElement("span"); t.className = "m-ig"; t.textContent = c.instagramHandle || "STKX";
      s.append(img, t); return s;
    };
    var makeGroup = function (hidden) {
      var g = document.createElement("div"); g.className = "m-group";
      if (hidden) g.setAttribute("aria-hidden", "true");
      for (var i = 0; i < 5; i++) g.appendChild(makeUnit());
      return g;
    };
    track.replaceChildren(makeGroup(false), makeGroup(true));
  }

  // Menu mobile
  var btn = document.querySelector(".menu-btn"), nav = document.querySelector(".nav");
  if (btn && nav) btn.addEventListener("click", function () {
    var open = nav.classList.toggle("open");
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  });
  document.querySelectorAll(".nav a").forEach(function (a) {
    a.addEventListener("click", function () { if (nav) nav.classList.remove("open"); if (btn) btn.setAttribute("aria-expanded", "false"); });
  });
  document.querySelectorAll("[data-year]").forEach(function (el) { el.textContent = new Date().getFullYear(); });
})();
