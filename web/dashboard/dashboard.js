// HISN dashboard. Every value from the API (domains above all) is attacker-controlled
// text, so it is only ever inserted with textContent, never as HTML.
"use strict";

(() => {
  const TOKEN_KEY = "hisn-token";
  const SEEN_KEY = "hisn-last-seen-block";
  const LANG_KEY = "hisn-lang";
  const THEME_KEY = "hisn-theme";
  const REFRESH_MS = 15000;
  const TEXTS = window.HISN_TEXTS;

  const $ = (id) => document.getElementById(id);
  const numberFormat = new Intl.NumberFormat("en-US");

  // Browser storage can be missing or blocked (private windows); never let that break the page.
  const store = {
    get(area, key) {
      try { return window[area].getItem(key); } catch { return null; }
    },
    set(area, key, value) {
      try { window[area].setItem(key, value); } catch { /* ignore */ }
    },
    remove(area, key) {
      try { window[area].removeItem(key); } catch { /* ignore */ }
    },
  };

  let lang = store.get("localStorage", LANG_KEY) === "en" ? "en" : "ar";
  let theme = store.get("localStorage", THEME_KEY) === "light" ? "light" : "dark";
  let token = store.get("sessionStorage", TOKEN_KEY);
  let username = "";
  let timer = null;
  let dailyChart = null;
  let reasonChart = null;

  // ----- language -----

  function t(key, values = {}) {
    const text = (TEXTS[lang] && TEXTS[lang][key]) ?? TEXTS.ar[key] ?? key;
    return text.replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? ""));
  }

  const reasonText = (reason) => (TEXTS.ar[`reason_${reason}`] ? t(`reason_${reason}`) : reason);

  let timeFormat = null;

  function applyLanguage() {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
    for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of document.querySelectorAll("[data-i18n-placeholder]")) el.placeholder = t(el.dataset.i18nPlaceholder);
    for (const el of document.querySelectorAll("[data-i18n-title]")) {
      el.title = t(el.dataset.i18nTitle);
      el.setAttribute("aria-label", el.title);
    }
    for (const el of document.querySelectorAll("#lang [data-lang]")) el.classList.toggle("on", el.dataset.lang === lang);
    timeFormat = new Intl.DateTimeFormat(lang === "ar" ? "ar-SA-u-ca-gregory-nu-latn" : "en-GB", {
      dateStyle: "short",
      timeStyle: "short",
    });
    document.title = t("page_title");
  }

  // Dark (the default design) or light; the choice is kept in this browser.
  function applyTheme() {
    document.documentElement.dataset.theme = theme;
    $("theme").setAttribute("aria-pressed", String(theme === "light"));
  }

  function rebuildCharts() {
    // Charts keep their labels and colors until rebuilt.
    dailyChart?.destroy();
    reasonChart?.destroy();
    dailyChart = reasonChart = null;
    if (!$("dashboard").hidden) refresh().catch(() => {});
  }

  $("theme").addEventListener("click", () => {
    theme = theme === "dark" ? "light" : "dark";
    store.set("localStorage", THEME_KEY, theme);
    applyTheme();
    rebuildCharts();
  });

  $("lang").addEventListener("click", () => {
    lang = lang === "ar" ? "en" : "ar";
    store.set("localStorage", LANG_KEY, lang);
    applyLanguage();
    $("login-error").textContent = "";  // shown in the old language
    $("setup-error").textContent = "";
    rebuildCharts();
    if (!$("setup").hidden) showSetup();
  });

  // ----- API -----

  class AuthError extends Error {}

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { Authorization: `Bearer ${token}`, ...(options.headers || {}) },
      cache: "no-store",
    });
    if (response.status === 401) throw new AuthError("signed out");
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `HTTP ${response.status}`);
    }
    return response.json();
  }

  async function postJson(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const data = await response.json().catch(() => ({}));
    return { status: response.status, data };
  }

  // ----- tables -----

  function cell(text, className) {
    const td = document.createElement("td");
    td.textContent = text;
    if (className) td.className = className;
    return td;
  }

  function reasonCell(reason) {
    const td = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `badge ${TEXTS.ar[`reason_${reason}`] ? reason : ""}`;
    badge.textContent = reasonText(reason);
    td.append(badge);
    return td;
  }

  function smallButton(className, label, onClick) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `small ${className}`;
    button.textContent = label;
    button.addEventListener("click", onClick);
    return button;
  }

  async function changeAllowed(path, domain, question) {
    if (!window.confirm(question)) return;
    try {
      await api(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      await refresh();
    } catch (err) {
      window.alert(t("err_action", { msg: err.message }));
    }
  }

  // "Unblock" next to a blocked site, or a green badge when the admin already allowed it.
  function actionCell(domain, allowed) {
    const td = document.createElement("td");
    if (allowed.has(domain)) {
      const badge = document.createElement("span");
      badge.className = "badge owner";
      badge.textContent = t("allowed_badge");
      td.append(badge);
    } else {
      td.append(smallButton("unblock", t("unblock"), () =>
        changeAllowed("/api/allowed", domain, t("confirm_unblock", { domain }))));
    }
    return td;
  }

  function reblockCell(domain) {
    const td = document.createElement("td");
    td.append(smallButton("reblock", t("reblock"), () =>
      changeAllowed("/api/allowed/delete", domain, t("confirm_reblock", { domain }))));
    return td;
  }

  function fillTable(id, rows, makeCells, emptyKey) {
    const body = $(id);
    body.replaceChildren();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = cell(t(emptyKey), "empty");
      td.colSpan = body.closest("table").querySelectorAll("thead th").length;
      tr.append(td);
      body.append(tr);
      return;
    }
    for (const row of rows) {
      const tr = document.createElement("tr");
      tr.append(...makeCells(row));
      body.append(tr);
    }
  }

  const when = (ts) => timeFormat.format(new Date(ts * 1000));
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  // ----- charts -----

  function drawDaily(daily) {
    const data = {
      labels: daily.map((d) => d.day.slice(5)),
      datasets: [
        { label: t("series_allowed"), data: daily.map((d) => d.allowed), backgroundColor: css("--series-allowed"), borderRadius: 4 },
        { label: t("series_blocked"), data: daily.map((d) => d.blocked), backgroundColor: css("--series-blocked"), borderRadius: 4 },
      ],
    };
    if (dailyChart) {
      dailyChart.data = data;
      dailyChart.update();
      return;
    }
    dailyChart = new Chart($("daily-chart"), {
      type: "bar",
      data,
      options: {
        maintainAspectRatio: false,
        animation: false,
        scales: {
          x: { grid: { display: false }, ticks: { color: css("--muted") } },
          y: { beginAtZero: true, ticks: { precision: 0, color: css("--muted") }, grid: { color: css("--grid") } },
        },
        plugins: { legend: { rtl: lang === "ar", labels: { color: css("--text") } } },
      },
    });
  }

  function drawReasons(byReason) {
    const keys = Object.keys(byReason).filter((k) => byReason[k] > 0);
    $("reason-empty").hidden = keys.length > 0;
    $("reason-chart").hidden = keys.length === 0;
    const colors = { blacklist: "--reason-blacklist", lookalike: "--reason-lookalike", model: "--reason-model" };
    const data = {
      labels: keys.map(reasonText),
      datasets: [{
        data: keys.map((k) => byReason[k]),
        backgroundColor: keys.map((k) => css(colors[k] || "--reason-other")),
        borderColor: css("--card"),
        borderWidth: 2,
      }],
    };
    if (reasonChart) {
      reasonChart.data = data;
      reasonChart.update();
      return;
    }
    reasonChart = new Chart($("reason-chart"), {
      type: "doughnut",
      data,
      options: {
        maintainAspectRatio: false,
        animation: false,
        cutout: "60%",
        plugins: { legend: { position: "bottom", rtl: lang === "ar", labels: { color: css("--text") } } },
      },
    });
  }

  // ----- alert -----

  function showAlert(recent) {
    const lastSeen = Number(store.get("localStorage", SEEN_KEY) || 0);
    const fresh = recent.filter((e) => e.id > lastSeen);
    document.title = fresh.length ? `(${fresh.length}) ${t("page_title")}` : t("page_title");
    if (!fresh.length) {
      $("alert").hidden = true;
      return;
    }
    $("alert-title").textContent = t("alert_title", { count: fresh.length });
    const list = $("alert-list");
    list.replaceChildren();
    for (const e of fresh.slice(0, 5)) {
      const li = document.createElement("li");
      const sep = lang === "ar" ? "، " : ", ";
      li.textContent = `${e.domain}  (${[reasonText(e.reason), e.device, when(e.ts)].join(sep)})`;
      list.append(li);
    }
    $("alert-ok").onclick = () => {
      store.set("localStorage", SEEN_KEY, String(Math.max(...fresh.map((e) => e.id))));
      showAlert(recent);
    };
    $("alert").hidden = false;
  }

  // ----- data -----

  async function refresh() {
    const [stats, blocked, devices, recent, owner, me] = await Promise.all([
      api("/api/stats?days=14"),
      api("/api/blocked?limit=20"),
      api("/api/devices?limit=20"),
      api("/api/recent?limit=10"),
      api("/api/allowed"),
      api("/api/me"),
    ]);
    username = me.username;
    const allowed = new Set(owner.allowed.map((a) => a.domain));

    $("t-blocked").textContent = numberFormat.format(stats.totals.blocked);
    $("t-today").textContent = numberFormat.format(stats.today.blocked);
    $("t-allowed").textContent = numberFormat.format(stats.today.allowed);
    $("t-doh").textContent = numberFormat.format(stats.doh_blocked);
    $("t-devices").textContent = numberFormat.format(stats.devices);

    drawDaily(stats.daily);
    drawReasons(stats.by_reason);

    fillTable("recent-rows", recent, (e) => [
      cell(when(e.ts), "nowrap"), cell(e.domain, "domain"), reasonCell(e.reason), cell(e.device, "device"),
    ], "nothing_recent");
    fillTable("blocked-rows", blocked, (r) => [
      cell(r.domain, "domain"), cell(numberFormat.format(r.hits), "num"), reasonCell(r.reason), cell(when(r.last_seen), "nowrap"),
      actionCell(r.domain, allowed),
    ], "nothing_blocked");
    fillTable("allowed-rows", owner.allowed, (a) => [
      cell(a.domain, "domain"), a.was_reason ? reasonCell(a.was_reason) : cell("—"), cell(when(a.added_at), "nowrap"),
      reblockCell(a.domain),
    ], "nothing_allowed");
    fillTable("device-rows", devices, (d) => [
      cell(d.device, "device"), cell(numberFormat.format(d.blocked), d.blocked > 0 ? "num hot" : "num"),
      cell(numberFormat.format(d.requests), "num"), cell(when(d.last_seen), "nowrap"),
    ], "nothing_devices");

    showAlert(recent);
    $("updated").textContent = t("updated", {
      user: username,
      time: timeFormat.format(new Date()),
      days: stats.retention_days,
    });
  }

  // ----- screens -----

  function showOnly(id) {
    hidePasswords();
    for (const screen of ["login", "setup", "dashboard"]) $(screen).hidden = screen !== id;
    $("actions").hidden = id !== "dashboard";
    if (id !== "dashboard") {
      clearInterval(timer);
      $("updated").textContent = "";
    }
  }

  function showLogin(message) {
    showOnly("login");
    $("login-error").textContent = message || "";
    ($("username").value ? $("password") : $("username")).focus();
  }

  // The account is created once, from the HISN computer; afterwards this screen only explains.
  async function showSetup(message) {
    showOnly("setup");
    $("setup-error").textContent = message || "";
    let state = { account_exists: false, can_create: false };
    try {
      state = await (await fetch("/api/setup", { cache: "no-store" })).json();
    } catch { /* keep the defaults */ }
    const notice = state.account_exists
      ? t("setup_exists")
      : state.can_create ? "" : t("setup_not_local", { url: `http://127.0.0.1:${window.location.port || 80}/` });
    $("setup-notice").textContent = notice;
    $("setup-notice").hidden = !notice;
    for (const el of $("setup-form").elements) el.disabled = !state.can_create;
    if (state.can_create) $("new-username").focus();
  }

  function startSession(newToken) {
    token = newToken;
    store.set("sessionStorage", TOKEN_KEY, token);
    return start();
  }

  async function start() {
    try {
      await refresh();
    } catch (err) {
      if (err instanceof AuthError) {
        token = null;
        store.remove("sessionStorage", TOKEN_KEY);
        showLogin(t("err_signed_out"));
      } else {
        showLogin(t("err_connect", { msg: err.message }));
      }
      return;
    }
    showOnly("dashboard");
    clearInterval(timer);
    timer = setInterval(() => {
      refresh().catch((err) => {
        if (err instanceof AuthError) showLogin(t("err_signed_out"));
        else $("updated").textContent = t("err_update", { msg: err.message });
      });
    }, REFRESH_MS);
  }

  const LOGIN_ERRORS = { 401: "err_wrong_login", 429: "err_too_many", 409: "err_no_account" };
  const SETUP_ERRORS = {
    bad_username: "err_bad_username",
    bad_password: "err_bad_password",
    password_mismatch: "err_mismatch",
    account_exists: "setup_exists",
  };

  // The password is sent once and never kept; the page keeps only the session token, in this tab.
  $("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = $("username").value.trim();
    const password = $("password").value;
    $("password").value = "";
    $("login-button").disabled = true;
    try {
      const { status, data } = await postJson("/api/login", { username, password });
      if (status === 200) await startSession(data.token);
      else showLogin(LOGIN_ERRORS[status] ? t(LOGIN_ERRORS[status]) : t("err_connect", { msg: `HTTP ${status}` }));
    } catch (err) {
      showLogin(t("err_connect", { msg: err.message }));
    } finally {
      $("login-button").disabled = false;
    }
  });

  $("setup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = {
      username: $("new-username").value.trim(),
      password: $("new-password").value,
      confirm: $("confirm-password").value,
    };
    if (body.password !== body.confirm) {
      $("setup-error").textContent = t("err_mismatch");
      return;
    }
    $("setup-button").disabled = true;
    try {
      const { status, data } = await postJson("/api/setup", body);
      if (status === 200) {
        $("setup-form").reset();
        await startSession(data.token);
      } else if (SETUP_ERRORS[data.code]) {
        $("setup-error").textContent = t(SETUP_ERRORS[data.code]);
      } else {
        $("setup-error").textContent = t("err_connect", { msg: data.error || `HTTP ${status}` });
      }
    } catch (err) {
      $("setup-error").textContent = t("err_connect", { msg: err.message });
    } finally {
      $("setup-button").disabled = false;
    }
  });

  // The eye inside a password box shows or hides what was typed.
  for (const eye of document.querySelectorAll("button.eye")) {
    eye.addEventListener("click", () => {
      const input = $(eye.dataset.for);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      eye.setAttribute("aria-pressed", String(show));
      eye.dataset.i18nTitle = show ? "hide_password" : "show_password";
      eye.title = t(eye.dataset.i18nTitle);
      eye.setAttribute("aria-label", eye.title);
      input.focus();
    });
  }

  // Passwords are hidden again whenever a form is shown or sent.
  function hidePasswords() {
    for (const eye of document.querySelectorAll("button.eye")) {
      $(eye.dataset.for).type = "password";
      eye.setAttribute("aria-pressed", "false");
      eye.dataset.i18nTitle = "show_password";
      eye.title = t("show_password");
      eye.setAttribute("aria-label", eye.title);
    }
  }

  $("to-setup").addEventListener("click", () => showSetup());
  $("to-login").addEventListener("click", () => showLogin());

  $("logout").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" }).catch(() => {});
    token = null;
    store.remove("sessionStorage", TOKEN_KEY);
    showLogin();
  });

  $("delete-logs").addEventListener("click", async () => {
    if (!window.confirm(t("confirm_delete"))) return;
    try {
      await api("/api/logs/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirm: "delete" }),
      });
      store.remove("localStorage", SEEN_KEY);
      await refresh();
    } catch (err) {
      window.alert(t("err_action", { msg: err.message }));
    }
  });

  // ----- first screen -----

  if (typeof Chart !== "undefined") {
    Chart.defaults.font.family = '"HISN Sans", "Segoe UI", Tahoma, Arial, sans-serif';
  }
  applyTheme();
  applyLanguage();
  if (token) {
    start();
  } else {
    // Straight to "create account" on the very first start, otherwise to sign in.
    fetch("/api/setup", { cache: "no-store" })
      .then((r) => r.json())
      .then((state) => (state.account_exists ? showLogin() : showSetup()))
      .catch(() => showLogin());
  }
})();
