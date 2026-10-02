// CyberTrack console behavior. Vanilla JS, no dependencies, works offline.
(function () {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));
  const typing = (el) => el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT" || el.isContentEditable);

  // ---------------------------------------------------------------- clock + shift
  const clock = $("#clock");
  const badge = $("#shift-badge");
  function tick() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    if (clock) clock.textContent = `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}Z`;
    if (badge) {
      const h = d.getHours();
      badge.textContent = h >= 7 && h < 15 ? "DAY SHIFT" : h >= 15 && h < 23 ? "SWING SHIFT" : "MID SHIFT";
    }
  }
  tick();
  setInterval(tick, 1000);

  // ---------------------------------------------------------------- mobile nav
  $$("[data-toggle-nav]").forEach((b) => b.addEventListener("click", () => document.body.classList.toggle("nav-open")));
  document.addEventListener("click", (e) => {
    if (document.body.classList.contains("nav-open") && !e.target.closest("#sidebar") && !e.target.closest("[data-toggle-nav]")) {
      document.body.classList.remove("nav-open");
    }
  });

  // ---------------------------------------------------------------- tooltips
  // data-tip="value||label". Built with textContent: labels are data, never markup.
  const tip = $("#tip");
  function showTip(el, x, y) {
    const raw = el.getAttribute("data-tip");
    if (!raw || !tip) return;
    const [value, label] = raw.split("||");
    tip.replaceChildren();
    const b = document.createElement("b");
    b.textContent = value;
    tip.appendChild(b);
    if (label) tip.appendChild(document.createTextNode(label));
    tip.classList.add("on");
    const r = tip.getBoundingClientRect();
    let left = x + 14, top = y - r.height - 10;
    if (left + r.width > window.innerWidth - 8) left = x - r.width - 14;
    if (top < 8) top = y + 16;
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }
  function hideTip() { tip && tip.classList.remove("on"); }

  function crosshair(hit, on) {
    const svg = hit.ownerSVGElement;
    if (!svg) return;
    const xh = $(".xhair", svg), dot = $(".hdot", svg);
    if (!xh) return;
    if (!on) { xh.style.opacity = 0; if (dot) dot.style.opacity = 0; return; }
    const x = hit.getAttribute("data-x"), y = hit.getAttribute("data-y");
    xh.setAttribute("x1", x); xh.setAttribute("x2", x); xh.style.opacity = 0.6;
    if (dot) {
      if (y) { dot.setAttribute("cx", x); dot.setAttribute("cy", y); dot.style.opacity = 1; }
      else dot.style.opacity = 0;
    }
  }

  document.addEventListener("pointermove", (e) => {
    const el = e.target.closest && e.target.closest("[data-tip]");
    if (!el) { hideTip(); $$(".chart .xhair").forEach((x) => (x.style.opacity = 0)); $$(".chart .hdot").forEach((x) => (x.style.opacity = 0)); return; }
    showTip(el, e.clientX, e.clientY);
    if (el.classList.contains("hit")) crosshair(el, true);
  });
  document.addEventListener("focusin", (e) => {
    const el = e.target.closest && e.target.closest("[data-tip]");
    if (!el) return;
    const r = el.getBoundingClientRect();
    showTip(el, r.left + r.width / 2, r.top);
    if (el.classList.contains("hit")) crosshair(el, true);
  });
  document.addEventListener("focusout", (e) => {
    if (e.target.closest && e.target.closest("[data-tip]")) {
      hideTip();
      if (e.target.classList.contains("hit")) crosshair(e.target, false);
    }
  });
  window.addEventListener("scroll", hideTip, { passive: true });

  // ---------------------------------------------------------------- charts
  // On narrow screens charts scroll sideways; start them at the newest data.
  $$('.chart-scroll, .heat').forEach((el) => { el.scrollLeft = el.scrollWidth; });

  // ---------------------------------------------------------------- queue rows
  const rows = $$("#queue tr.ev, #cases tr.ev");
  let sel = -1;
  function select(i) {
    if (!rows.length) return;
    sel = Math.max(0, Math.min(rows.length - 1, i));
    rows.forEach((r, n) => r.classList.toggle("sel", n === sel));
    rows[sel].scrollIntoView({ block: "nearest" });
  }
  rows.forEach((r, n) => {
    r.addEventListener("click", (e) => {
      if (e.target.closest("a")) return;
      window.location = r.dataset.href;
    });
    r.addEventListener("mouseenter", () => { sel = n; rows.forEach((x, m) => x.classList.toggle("sel", m === n)); });
  });

  // ---------------------------------------------------------------- triage form
  const form = $("#triage-form");
  const reason = $("#reason");
  const pending = $("#pending");
  let pendingDisp = null;
  function decide(disp) {
    if (!form) return;
    const btn = form.querySelector(`button[data-disp="${disp}"]`);
    if (reason && !reason.value.trim()) {
      pendingDisp = disp;
      if (pending) {
        pending.textContent = disp === "malicious"
          ? "Escalating. Type your reason, then press Enter to submit."
          : "Closing as benign. Type your reason, then press Enter to submit.";
        pending.classList.add("on");
      }
      reason.focus();
      return;
    }
    btn && btn.click();
  }
  if (reason) {
    reason.addEventListener("keydown", (e) => {
      if (e.key !== "Enter") return;
      e.preventDefault(); // never let Enter silently pick the first button
      if (!reason.value.trim()) return;
      if (pendingDisp) decide(pendingDisp);
      else if (pending) {
        pending.textContent = "Pick a disposition: E to escalate or C to close (or click a button).";
        pending.classList.add("on");
        reason.blur();
      }
    });
  }

  // ---------------------------------------------------------------- keyboard
  const help = $("#help");
  $$("[data-help]").forEach((b) => b.addEventListener("click", () => help.classList.toggle("on")));
  help && help.addEventListener("click", (e) => { if (e.target === help) help.classList.remove("on"); });

  let gPrefix = false;
  const gMap = { p: "/", r: "/soc/", c: "/soc/cases", t: "/soc/turnover", a: "/soc/metrics", s: "/study/", b: "/study/today" };
  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "Escape") {
      help && help.classList.remove("on");
      document.body.classList.remove("nav-open");
      if (typing(document.activeElement)) document.activeElement.blur();
      return;
    }
    if (typing(e.target)) return;
    if (gPrefix) {
      gPrefix = false;
      if (gMap[e.key]) { window.location = gMap[e.key]; e.preventDefault(); }
      return;
    }
    switch (e.key) {
      case "/": e.preventDefault(); $("#global-search") && $("#global-search").focus(); break;
      case "?": help && help.classList.toggle("on"); break;
      case "g": gPrefix = true; setTimeout(() => (gPrefix = false), 1200); break;
      case "j": select(sel + 1); break;
      case "k": select(sel - 1); break;
      case "Enter": if (rows.length && sel >= 0) window.location = rows[sel].dataset.href; break;
      case "e": if (form) { e.preventDefault(); decide("malicious"); } break;
      case "c": if (form) { e.preventDefault(); decide("benign"); } break;
      case "n": { const nx = $("#next-alert"); if (nx) window.location = nx.href; break; }
    }
  });

  // ---------------------------------------------------------------- incident report
  // Live length counter per section, against the rubric's minimum.
  $$("textarea[data-minlen]").forEach((ta) => {
    const cc = $(`[data-cc="${ta.id}"]`);
    if (!cc) return;
    const min = parseInt(ta.dataset.minlen, 10) || 0;
    const update = () => {
      const n = ta.value.trim().length;
      cc.textContent = n ? `${n} / ${min} min` : `min ${min} chars`;
      cc.classList.toggle("ok", n >= min);
    };
    ta.addEventListener("input", update);
    update();
  });

  // ---------------------------------------------------------------- turnover
  // Suggested open items (open cases) append to the open-items box as plain text.
  const openItems = $("#open_items");
  function addItem(text) {
    if (!openItems || !text) return;
    const lines = openItems.value.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!lines.includes(text)) lines.push(text);
    openItems.value = lines.join("\n");
  }
  $$("[data-add-item]").forEach((b) => b.addEventListener("click", () => {
    addItem(b.getAttribute("data-add-item"));
    b.textContent = "Added";
    b.disabled = true;
  }));
  $$("[data-add-all]").forEach((b) => b.addEventListener("click", () => {
    $$("[data-add-item]").forEach((x) => { if (!x.disabled) x.click(); });
    if (openItems) openItems.focus();
  }));

  // ---------------------------------------------------------------- decoder
  const decIn = $("#dec-in"), decOut = $("#dec-out"), decMode = $("#dec-mode"), decGrab = $("#dec-grab");
  function b64bytes(s) {
    const clean = s.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(clean + "=".repeat((4 - (clean.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }
  function decode() {
    if (!decIn || !decOut) return;
    const s = decIn.value.trim();
    if (!s) { decOut.textContent = "Output appears here."; return; }
    try {
      let out;
      switch (decMode.value) {
        case "b64-utf16": out = new TextDecoder("utf-16le").decode(b64bytes(s)); break;
        case "b64": out = new TextDecoder("utf-8").decode(b64bytes(s)); break;
        case "url": out = decodeURIComponent(s.replace(/\+/g, " ")); break;
        case "hex": {
          const h = s.replace(/[^0-9a-f]/gi, "");
          out = new TextDecoder("utf-8").decode(Uint8Array.from(h.match(/.{1,2}/g) || [], (x) => parseInt(x, 16)));
          break;
        }
      }
      decOut.textContent = out; // textContent: decoded data is never treated as markup
    } catch (err) {
      decOut.textContent = "Could not decode: " + err.message;
    }
  }
  if (decIn) {
    decIn.addEventListener("input", decode);
    decMode.addEventListener("change", decode);
    decGrab.addEventListener("click", () => {
      const raw = ($("#raw-log") && $("#raw-log").value) || "";
      const enc = raw.match(/-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]{16,})/i);
      const any = raw.match(/[A-Za-z0-9+/]{24,}={0,2}/g);
      const pick = enc ? enc[1] : any ? any.sort((a, b) => b.length - a.length)[0] : "";
      if (!pick) { decOut.textContent = "No encoded-looking token in this event."; return; }
      decIn.value = pick;
      if (enc) decMode.value = "b64-utf16";
      decode();
    });
  }
})();
