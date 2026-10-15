(function () {
  "use strict";
  var form = document.getElementById("inq"), box = document.getElementById("box");
  var formErr = document.getElementById("formErr"), sendBtn = document.getElementById("send");
  var token = "";
  var errs = {
    name: "Informe seu nome.",
    email: "Informe um e-mail válido.",
    details: "Descreva o projeto com pelo menos 20 caracteres.",
    consent: "É necessário concordar para enviar."
  };

  function loadToken() {
    return fetch("/api/form-token", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (j) { token = j.token || ""; })
      .catch(function () {});
  }
  loadToken();

  function check(el) {
    var f = el.closest(".f"); if (!f) return true;
    var ok = el.checkValidity();
    f.classList.toggle("err", !ok);
    f.querySelector(".msg").textContent = ok ? "" : (errs[el.id] || "Campo inválido.");
    return ok;
  }
  var required = "input[required]:not([type=radio]),textarea[required]";
  form.querySelectorAll(required).forEach(function (el) {
    el.addEventListener("blur", function () { check(el); });
    el.addEventListener(el.type === "checkbox" ? "change" : "input", function () {
      if (el.closest(".f").classList.contains("err")) check(el);
    });
  });

  function showError(msg) { formErr.textContent = msg; formErr.hidden = false; }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    formErr.hidden = true;
    var ok = true, first;
    form.querySelectorAll(required).forEach(function (el) { if (!check(el)) { ok = false; first = first || el; } });
    var t = form.querySelector("input[name=type]:checked");
    document.getElementById("typeMsg").classList.toggle("show", !t);
    if (!t) { ok = false; first = first || form.querySelector("input[name=type]"); }
    if (!ok) { first.focus(); return; }

    var v = function (id) { return document.getElementById(id).value; };
    var payload = {
      name: v("name"), email: v("email"), company: v("company"), contact: v("contact"),
      type: t.value, budget: v("budget"), deadline: v("deadline"), details: v("details"),
      consent: document.getElementById("consent").checked,
      website: v("website"), token: token
    };
    sendBtn.disabled = true; sendBtn.setAttribute("aria-busy", "true");

    fetch("/api/inquiries", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { return { r: r, j: j }; }); })
      .then(function (x) {
        if (x.r.ok) {
          document.getElementById("who").textContent = payload.name.trim().split(" ")[0];
          box.classList.add("sent");
          box.querySelector(".done").focus();
          return;
        }
        if (x.j.code === "token") loadToken();
        if (x.j.fields) {
          Object.keys(x.j.fields).forEach(function (k) {
            var el = document.getElementById(k), f = el && el.closest(".f");
            if (f) { f.classList.add("err"); f.querySelector(".msg").textContent = x.j.fields[k]; }
          });
        }
        showError(x.j.error || "Não foi possível enviar o pedido. Tente novamente.");
      })
      .catch(function () { showError("Não foi possível enviar o pedido. Verifique sua conexão e tente novamente."); })
      .then(function () { sendBtn.disabled = false; sendBtn.removeAttribute("aria-busy"); });
  });
})();
