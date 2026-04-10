/* Claude Squad — Dashboard Frontend
   Vanilla JS, no frameworks, no build steps.
   Fetches from /api/accounts every 30 seconds and renders cards. */

(function () {
  "use strict";

  // ─── State ──────────────────────────────────────────

  var accounts = [];
  var sortMode = "utilization-desc";
  var refreshIntervalId = null;
  var REFRESH_INTERVAL_MS = 30000; // 30 seconds (reads cache, doesn't trigger API calls)
  var expandedCards = {}; // account_id -> true/false

  // ─── Init ───────────────────────────────────────────

  function init() {
    fetchAccounts();
    refreshIntervalId = setInterval(fetchAccounts, REFRESH_INTERVAL_MS);

    // Start countdown timer updates every second
    setInterval(updateTimers, 1000);
  }

  // ─── API calls ──────────────────────────────────────

  function fetchAccounts() {
    fetch("/api/accounts")
      .then(function (resp) {
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        return resp.json();
      })
      .then(function (data) {
        accounts = data.accounts || [];
        renderCards();
        updateStatusLine();
        hideError();
      })
      .catch(function (err) {
        showError("Failed to fetch accounts: " + err.message);
      });
  }

  function refreshAll() {
    var btn = document.getElementById("btn-refresh");
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Refreshing...';

    fetch("/api/refresh")
      .then(function (resp) {
        return resp.json();
      })
      .then(function (data) {
        // Wait a moment for cache to update, then fetch fresh data
        setTimeout(function () {
          fetchAccounts();
          btn.disabled = false;
          btn.textContent = "Refresh All";
        }, 2000);
      })
      .catch(function (err) {
        showError("Refresh failed: " + err.message);
        btn.disabled = false;
        btn.textContent = "Refresh All";
      });
  }

  // ─── Sorting ────────────────────────────────────────

  function onSortChange() {
    var sel = document.getElementById("sort-select");
    sortMode = sel.value;
    renderCards();
  }

  function sortAccounts(accts) {
    var sorted = accts.slice(); // copy
    switch (sortMode) {
      case "utilization-desc":
        sorted.sort(function (a, b) {
          return getMaxUtilization(b) - getMaxUtilization(a);
        });
        break;
      case "utilization-asc":
        sorted.sort(function (a, b) {
          return getMaxUtilization(a) - getMaxUtilization(b);
        });
        break;
      case "account":
        sorted.sort(function (a, b) {
          return a.id.localeCompare(b.id);
        });
        break;
      case "provider":
        sorted.sort(function (a, b) {
          var cmp = a.provider.localeCompare(b.provider);
          return cmp !== 0 ? cmp : a.id.localeCompare(b.id);
        });
        break;
    }
    return sorted;
  }

  // ─── Rendering ──────────────────────────────────────

  function renderCards() {
    var grid = document.getElementById("cards-grid");
    var noData = document.getElementById("no-data");

    if (accounts.length === 0) {
      grid.innerHTML = "";
      if (noData) noData.style.display = "block";
      var nd = document.createElement("div");
      nd.className = "no-data";
      nd.textContent =
        "No accounts discovered. Check ~/.claude/accounts/credentials/";
      grid.appendChild(nd);
      return;
    }

    var sorted = sortAccounts(accounts);
    grid.innerHTML = "";

    for (var i = 0; i < sorted.length; i++) {
      grid.appendChild(createCard(sorted[i]));
    }
  }

  function createCard(acct) {
    var card = document.createElement("div");
    var statusClass = getStatusColorClass(acct);
    card.className = "card status-" + statusClass;
    card.onclick = function () {
      toggleDetail(acct.id);
    };

    var usage = acct.usage || {};
    var isAnthropicUsage = usage.five_hour !== undefined;
    var is3pUsage = usage.rate_limits !== undefined;

    // Header
    var header = document.createElement("div");
    header.className = "card-header";

    var label = document.createElement("span");
    label.className = "card-label";
    label.textContent = acct.label;
    label.title = acct.label;

    var badges = document.createElement("div");
    badges.style.display = "flex";
    badges.style.gap = "6px";
    badges.style.alignItems = "center";

    var provider = document.createElement("span");
    provider.className = "card-provider";
    provider.textContent = acct.provider;

    var status = document.createElement("span");
    status.className = "card-status " + acct.status;
    status.textContent = acct.status;

    badges.appendChild(provider);
    badges.appendChild(status);
    header.appendChild(label);
    header.appendChild(badges);
    card.appendChild(header);

    // Usage display
    if (isAnthropicUsage) {
      card.appendChild(createAnthropicUsage(usage));
    } else if (is3pUsage) {
      card.appendChild(create3pUsage(usage));
    } else {
      var noUsage = document.createElement("div");
      noUsage.className = "no-data";
      noUsage.textContent = "No usage data yet";
      noUsage.style.padding = "12px 0";
      card.appendChild(noUsage);
    }

    // Detail section (hidden by default)
    var detail = document.createElement("div");
    detail.className =
      "card-detail" + (expandedCards[acct.id] ? " expanded" : "");
    detail.id = "detail-" + acct.id;

    if (isAnthropicUsage) {
      detail.appendChild(createAnthropicDetail(usage));
    }

    if (acct.token_prefix) {
      var tokenRow = createDetailRow("Token", acct.token_prefix);
      detail.appendChild(tokenRow);
    }

    if (acct.last_updated) {
      var updatedRow = createDetailRow(
        "Updated",
        formatTime(acct.last_updated),
      );
      detail.appendChild(updatedRow);
    }

    card.appendChild(detail);

    return card;
  }

  function createAnthropicUsage(usage) {
    var section = document.createElement("div");
    section.className = "usage-section";

    // 5-hour usage
    if (usage.five_hour) {
      var pct5 = Math.round((usage.five_hour.utilization || 0) * 100);
      section.appendChild(
        createUsageBar("5hr", pct5, usage.five_hour.resets_at),
      );
    }

    // 7-day usage
    if (usage.seven_day) {
      var pct7 = Math.round((usage.seven_day.utilization || 0) * 100);
      section.appendChild(
        createUsageBar("7day", pct7, usage.seven_day.resets_at),
      );
    }

    // Reset timer
    if (usage.five_hour && usage.five_hour.resets_at) {
      var timer = document.createElement("div");
      timer.className = "reset-timer";
      timer.innerHTML =
        '5hr resets in: <span class="timer-value" data-reset="' +
        usage.five_hour.resets_at +
        '">--</span>';
      section.appendChild(timer);
    }

    return section;
  }

  function create3pUsage(usage) {
    var section = document.createElement("div");
    section.className = "rate-limits";

    var rl = usage.rate_limits || {};
    var rows = [
      ["Requests", rl.requests_remaining, rl.requests_limit],
      ["Tokens", rl.tokens_remaining, rl.tokens_limit],
    ];

    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      if (r[1] !== undefined && r[2] !== undefined) {
        var row = document.createElement("div");
        row.className = "rl-row";

        var key = document.createElement("span");
        key.className = "rl-key";
        key.textContent = r[0];

        var val = document.createElement("span");
        val.className = "rl-value";
        val.textContent = r[1] + " / " + r[2];

        row.appendChild(key);
        row.appendChild(val);
        section.appendChild(row);
      }
    }

    if (section.children.length === 0) {
      var noRl = document.createElement("div");
      noRl.className = "no-data";
      noRl.textContent = "Headers only";
      noRl.style.padding = "8px 0";
      section.appendChild(noRl);
    }

    return section;
  }

  function createUsageBar(label, pct, resetsAt) {
    var container = document.createElement("div");

    var row = document.createElement("div");
    row.className = "usage-row";

    var lbl = document.createElement("span");
    lbl.className = "usage-label";
    lbl.textContent = label;

    var val = document.createElement("span");
    val.className = "usage-value";
    val.style.color = getBarColor(pct);
    val.textContent = pct + "%";

    row.appendChild(lbl);
    row.appendChild(val);
    container.appendChild(row);

    var bar = document.createElement("div");
    bar.className = "usage-bar";

    var fill = document.createElement("div");
    fill.className = "usage-bar-fill " + getBarColorClass(pct);
    fill.style.width = Math.min(pct, 100) + "%";

    bar.appendChild(fill);
    container.appendChild(bar);

    return container;
  }

  function createAnthropicDetail(usage) {
    var frag = document.createDocumentFragment();

    var windows = [
      "five_hour",
      "seven_day",
      "seven_day_opus",
      "seven_day_oauth_apps",
    ];
    var labels = {
      five_hour: "5-Hour",
      seven_day: "7-Day",
      seven_day_opus: "7-Day Opus",
      seven_day_oauth_apps: "7-Day OAuth Apps",
    };

    for (var i = 0; i < windows.length; i++) {
      var w = windows[i];
      if (usage[w]) {
        var pct = Math.round((usage[w].utilization || 0) * 100);
        frag.appendChild(
          createDetailRow(
            labels[w] || w,
            pct +
              "%" +
              (usage[w].resets_at
                ? " (resets " + formatResetTime(usage[w].resets_at) + ")"
                : ""),
          ),
        );
      }
    }

    return frag;
  }

  function createDetailRow(label, value) {
    var row = document.createElement("div");
    row.className = "detail-row";

    var lbl = document.createElement("span");
    lbl.className = "detail-label";
    lbl.textContent = label;

    var val = document.createElement("span");
    val.className = "detail-value";
    val.textContent = value;

    row.appendChild(lbl);
    row.appendChild(val);
    return row;
  }

  // ─── Interaction ────────────────────────────────────

  function toggleDetail(accountId) {
    expandedCards[accountId] = !expandedCards[accountId];
    var detail = document.getElementById("detail-" + accountId);
    if (detail) {
      detail.classList.toggle("expanded");
    }
  }

  // ─── Utilities ──────────────────────────────────────

  function getMaxUtilization(acct) {
    if (!acct.usage) return -1;
    var u = acct.usage;
    if (u.five_hour) {
      return u.five_hour.utilization || 0;
    }
    if (u.rate_limits && u.rate_limits.requests_limit) {
      var used =
        u.rate_limits.requests_limit - (u.rate_limits.requests_remaining || 0);
      return used / u.rate_limits.requests_limit;
    }
    return -1;
  }

  function getStatusColorClass(acct) {
    if (acct.status === "expired" || acct.status === "error") return "gray";
    if (!acct.usage) return "gray";

    var util = getMaxUtilization(acct);
    if (util < 0) return "gray";
    if (util >= 0.8) return "red";
    if (util >= 0.5) return "yellow";
    return "green";
  }

  function getBarColor(pct) {
    if (pct >= 80) return "var(--red)";
    if (pct >= 50) return "var(--yellow)";
    return "var(--green)";
  }

  function getBarColorClass(pct) {
    if (pct >= 80) return "red";
    if (pct >= 50) return "yellow";
    return "green";
  }

  function formatTime(epoch) {
    if (!epoch) return "--";
    var d = new Date(epoch * 1000);
    return d.toLocaleTimeString();
  }

  function formatResetTime(isoOrEpoch) {
    if (!isoOrEpoch) return "--";
    var d;
    if (typeof isoOrEpoch === "number") {
      d = new Date(isoOrEpoch * 1000);
    } else {
      d = new Date(isoOrEpoch);
    }
    return d.toLocaleTimeString();
  }

  function formatCountdown(isoOrEpoch) {
    if (!isoOrEpoch) return "--";
    var target;
    if (typeof isoOrEpoch === "number") {
      target = new Date(isoOrEpoch * 1000);
    } else {
      target = new Date(isoOrEpoch);
    }
    var now = new Date();
    var diff = target - now;
    if (diff <= 0) return "now";

    var hours = Math.floor(diff / 3600000);
    var minutes = Math.floor((diff % 3600000) / 60000);
    var seconds = Math.floor((diff % 60000) / 1000);

    if (hours > 0) return hours + "h " + minutes + "m";
    if (minutes > 0) return minutes + "m " + seconds + "s";
    return seconds + "s";
  }

  // ─── Live timers ────────────────────────────────────

  function updateTimers() {
    var timerElements = document.querySelectorAll("[data-reset]");
    for (var i = 0; i < timerElements.length; i++) {
      var el = timerElements[i];
      var resetAt = el.getAttribute("data-reset");
      el.textContent = formatCountdown(resetAt);
    }
  }

  // ─── Status line ────────────────────────────────────

  function updateStatusLine() {
    var line = document.getElementById("status-line");
    var activeCount = 0;
    var errorCount = 0;
    for (var i = 0; i < accounts.length; i++) {
      if (accounts[i].status === "active") activeCount++;
      if (accounts[i].status === "expired" || accounts[i].status === "error")
        errorCount++;
    }

    var parts = [accounts.length + " accounts"];
    if (activeCount > 0) parts.push(activeCount + " active");
    if (errorCount > 0) parts.push(errorCount + " issues");
    line.textContent = parts.join(" / ");

    // Footer timestamps
    var now = new Date();
    document.getElementById("footer-updated").textContent =
      "Last updated: " + now.toLocaleTimeString();
    document.getElementById("footer-next").textContent =
      "Next refresh: " +
      new Date(now.getTime() + REFRESH_INTERVAL_MS).toLocaleTimeString();
  }

  // ─── Error display ──────────────────────────────────

  function showError(msg) {
    var banner = document.getElementById("error-banner");
    banner.textContent = msg;
    banner.classList.add("visible");
  }

  function hideError() {
    var banner = document.getElementById("error-banner");
    banner.classList.remove("visible");
  }

  // ─── Expose globals for HTML onclick handlers ───────

  window.refreshAll = refreshAll;
  window.onSortChange = onSortChange;

  // ─── Start ──────────────────────────────────────────

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
