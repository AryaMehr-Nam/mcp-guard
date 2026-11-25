"use strict";

(function () {
  const MAX_FEED_ITEMS = 300;
  const VALID_TABS = new Set(["live-feed", "scanner", "pins", "policy"]);

  const state = {
    activeTab: "live-feed",
    actionFilter: "all",
    severityFilter: "all",
    searchQuery: "",
    paused: false,
    pausedBuffer: [],
    events: [],
    seenKeys: new Set(),
    counters: { total: 0, blocked: 0, redacted: 0, allowed: 0 },
    latestReport: null,
    scanDetectorFilter: "all",
    scanSeverityFilter: "all",
    scanSearchQuery: "",
    policy: null,
    policyDirty: false,
    selectedMode: "enforce",
    allowExec: false,
    eventSource: null,
    resetConfirmTimers: new Map(),
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function clearElement(el) {
    if (!el) return;
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function showToast(message, isError) {
    const toast = byId("global-toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.remove("is-hidden", "toast-error");
    if (isError) {
      toast.classList.add("toast-error");
    }
    window.clearTimeout(showToast._timer);
    showToast._timer = window.setTimeout(function () {
      toast.classList.add("is-hidden");
    }, 3600);
  }

  function toHex4(cp) {
    return cp.toString(16).toUpperCase().padStart(4, "0");
  }

  function isTagChar(cp) {
    return cp >= 0xe0000 && cp <= 0xe007f;
  }

  function isZeroWidthChar(cp) {
    return (
      (cp >= 0x200b && cp <= 0x200f) ||
      cp === 0xfeff ||
      (cp >= 0x2060 && cp <= 0x2064)
    );
  }

  function isBidiOverrideChar(cp) {
    return (
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069)
    );
  }

  /**
   * Render text into `container` using DOM text nodes only, revealing hidden
   * Unicode Tag, Zero-Width, and BiDi override codepoints as visible badges.
   */
  function renderSafeText(container, text) {
    const input = text === null || text === undefined ? "" : String(text);
    const chars = Array.from(input);
    let buffer = "";

    function flushBuffer() {
      if (buffer.length > 0) {
        container.appendChild(document.createTextNode(buffer));
        buffer = "";
      }
    }

    let i = 0;
    while (i < chars.length) {
      const ch = chars[i];
      const cp = ch.codePointAt(0);
      if (cp === undefined) {
        i += 1;
        continue;
      }

      if (isTagChar(cp)) {
        flushBuffer();
        const firstHex = cp.toString(16).toUpperCase();
        let decoded = "";
        while (i < chars.length) {
          const nextCp = chars[i].codePointAt(0);
          if (nextCp === undefined || !isTagChar(nextCp)) {
            break;
          }
          const ascii = nextCp - 0xe0000;
          if (ascii >= 0x20 && ascii <= 0x7e) {
            decoded += String.fromCharCode(ascii);
          } else if (ascii === 0x0a) {
            decoded += "\\n";
          } else if (ascii === 0x09) {
            decoded += "\\t";
          }
          i += 1;
        }
        const badge = document.createElement("span");
        badge.className = "unicode-badge unicode-tag";
        badge.textContent =
          "[U+" + firstHex + " TAG:" + (decoded || "<control>") + "]";
        container.appendChild(badge);
        continue;
      }

      if (isZeroWidthChar(cp)) {
        flushBuffer();
        const badge = document.createElement("span");
        badge.className = "unicode-badge";
        badge.textContent = "[ZW U+" + toHex4(cp) + "]";
        container.appendChild(badge);
        i += 1;
        continue;
      }

      if (isBidiOverrideChar(cp)) {
        flushBuffer();
        const badge = document.createElement("span");
        badge.className = "unicode-badge unicode-bidi";
        badge.textContent = "[BIDI U+" + toHex4(cp) + "]";
        container.appendChild(badge);
        i += 1;
        continue;
      }

      buffer += ch;
      i += 1;
    }

    flushBuffer();
  }

  async function apiFetch(url, options) {
    const opts = Object.assign({ credentials: "same-origin" }, options || {});
    if (opts.body !== undefined && typeof opts.body !== "string") {
      opts.body = JSON.stringify(opts.body);
    }
    if (opts.method && opts.method.toUpperCase() !== "GET") {
      opts.headers = Object.assign(
        { "Content-Type": "application/json" },
        opts.headers || {}
      );
    }
    const resp = await fetch(url, opts);
    const contentType = resp.headers.get("content-type") || "";
    let payload = null;
    if (contentType.indexOf("application/json") !== -1) {
      payload = await resp.json();
    } else {
      payload = await resp.text();
    }
    if (!resp.ok) {
      const errMsg =
        payload && typeof payload === "object" && (payload.detail || payload.error)
          ? String(payload.detail || payload.error)
          : "HTTP " + resp.status;
      const err = new Error(errMsg);
      err.status = resp.status;
      err.payload = payload;
      throw err;
    }
    return payload;
  }

  function makeBadge(label, className) {
    const span = document.createElement("span");
    span.className = className;
    span.textContent = label;
    return span;
  }

  function formatSeverityLabel(sev) {
    const s = String(sev || "info").toLowerCase();
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function formatActionLabel(action) {
    const map = {
      block: "Block",
      strip_tool: "Strip Tool",
      redact: "Redact",
      log: "Audit Log",
      allow: "Allow",
    };
    const key = String(action || "allow").toLowerCase();
    return map[key] || key;
  }

  function formatModeLabel(mode) {
    const key = String(mode || "enforce").toLowerCase();
    return key.charAt(0).toUpperCase() + key.slice(1);
  }

  function formatTimestamp(ts) {
    if (!ts) return "";
    const parsed = new Date(ts);
    if (Number.isNaN(parsed.getTime())) {
      return String(ts);
    }
    return parsed.toLocaleTimeString();
  }

  /* Navigation Tabs & URL Hash State */
  function readTabFromHash() {
    const raw = (window.location.hash || "").replace(/^#/, "").trim();
    return VALID_TABS.has(raw) ? raw : "live-feed";
  }

  function switchTab(tabName, skipHashUpdate) {
    const nextTab = VALID_TABS.has(tabName) ? tabName : "live-feed";
    state.activeTab = nextTab;

    document.querySelectorAll(".tab-btn").forEach(function (btn) {
      const isMatch = btn.dataset.tab === nextTab;
      btn.classList.toggle("active", isMatch);
      btn.setAttribute("aria-selected", isMatch ? "true" : "false");
      btn.setAttribute("tabindex", isMatch ? "0" : "-1");
    });

    document.querySelectorAll(".tab-panel").forEach(function (panel) {
      const isMatch = panel.id === "panel-" + nextTab;
      panel.classList.toggle("active", isMatch);
      panel.hidden = !isMatch;
    });

    if (!skipHashUpdate && window.location.hash !== "#" + nextTab) {
      window.history.replaceState(null, "", "#" + nextTab);
    }

    if (nextTab === "pins") {
      loadPins();
    } else if (nextTab === "policy") {
      loadPolicy();
    }
  }

  /* Header Status & Counters */
  function updateCountersUI() {
    byId("counter-total").textContent = String(state.counters.total);
    byId("counter-blocked").textContent = String(state.counters.blocked);
    byId("counter-redacted").textContent = String(state.counters.redacted);
    byId("counter-allowed").textContent = String(state.counters.allowed);

    const feedBadge = byId("feed-count-badge");
    if (feedBadge) {
      if (state.events.length > 0) {
        feedBadge.textContent = String(state.events.length);
        feedBadge.classList.remove("is-hidden");
      } else {
        feedBadge.classList.add("is-hidden");
      }
    }
  }

  function countEvent(ev) {
    const action = String(ev.action || "allow").toLowerCase();
    state.counters.total += 1;
    if (action === "block" || action === "strip_tool") {
      state.counters.blocked += 1;
    } else if (action === "redact") {
      state.counters.redacted += 1;
    } else {
      state.counters.allowed += 1;
    }
  }

  function applyStatus(status) {
    if (!status || typeof status !== "object") return;
    const isLiveProxy = Boolean(
      status.embedded ||
        status.runtime_mode === "proxy" ||
        status.proxy_attached ||
        status.live_proxy
    );
    const statusBadge = byId("status-mode-badge");
    statusBadge.textContent = isLiveProxy ? "Live Proxy" : "Standalone";
    statusBadge.className = isLiveProxy
      ? "pill pill-live-proxy"
      : "pill pill-neutral";

    const mode = String(status.mode || "enforce").toLowerCase();
    const modePill = byId("header-guard-mode");
    modePill.textContent = formatModeLabel(mode);
    modePill.className = "pill pill-mode-" + mode + " mode-jump-btn";

    byId("header-server-id").textContent = String(status.server_id || "default");

    state.allowExec = Boolean(status.allow_exec);
    const execPill = byId("exec-capability-pill");
    if (execPill) {
      execPill.textContent = state.allowExec
        ? "STDIO Enabled"
        : "Requires --allow-exec";
      execPill.className = state.allowExec
        ? "pill pill-live-proxy"
        : "pill pill-neutral";
    }
  }

  async function refreshStatus() {
    try {
      const status = await apiFetch("/api/status");
      applyStatus(status);
    } catch (err) {
      // Keep current header state on transient failure.
    }
  }

  /* Live Feed & SSE */
  function eventKey(ev) {
    if (ev.id) return String(ev.id);
    return [
      ev.timestamp || "",
      ev.direction || "",
      ev.method || "",
      ev.tool_name || "",
      ev.uri || "",
      ev.action || "",
      ev.summary || "",
      JSON.stringify(ev.findings || []),
    ].join("|");
  }

  function updatePauseButtonUI() {
    const btn = byId("btn-pause-feed");
    if (!btn) return;
    if (!state.paused) {
      btn.textContent = "Pause Stream";
      return;
    }
    const queued = state.pausedBuffer.length;
    btn.textContent =
      queued > 0 ? "Resume (" + queued + " queued)" : "Resume Stream";
  }

  function ingestEvent(ev, skipPauseCheck) {
    if (!ev || typeof ev !== "object") return false;
    const key = eventKey(ev);
    if (state.seenKeys.has(key)) return false;
    state.seenKeys.add(key);
    countEvent(ev);

    if (!skipPauseCheck && state.paused) {
      state.pausedBuffer.push(ev);
      if (state.pausedBuffer.length > MAX_FEED_ITEMS) {
        state.pausedBuffer.shift();
      }
      updateCountersUI();
      updatePauseButtonUI();
      return false;
    }

    state.events.unshift(ev);
    if (state.events.length > MAX_FEED_ITEMS) {
      state.events.length = MAX_FEED_ITEMS;
    }
    updateCountersUI();
    return true;
  }

  function eventMatchesFilter(ev) {
    const action = String(ev.action || "allow").toLowerCase();
    if (state.actionFilter === "blocked") {
      if (action !== "block" && action !== "strip_tool") return false;
    } else if (state.actionFilter !== "all" && action !== state.actionFilter) {
      return false;
    }

    if (state.severityFilter !== "all") {
      const targetSev = state.severityFilter;
      const evMax = String(ev.max_severity || "").toLowerCase();
      const hasMatch =
        evMax === targetSev ||
        (Array.isArray(ev.findings) &&
          ev.findings.some(function (f) {
            return String(f.severity || "").toLowerCase() === targetSev;
          }));
      if (!hasMatch) return false;
    }

    const q = state.searchQuery.trim().toLowerCase();
    if (!q) return true;
    const findingsText = Array.isArray(ev.findings)
      ? ev.findings
          .map(function (f) {
            return [f.rule_id, f.detector, f.title, f.target].join(" ");
          })
          .join(" ")
      : "";
    const haystack = [
      ev.method,
      ev.tool_name,
      ev.uri,
      ev.summary,
      ev.server_id,
      action,
      findingsText,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return haystack.indexOf(q) !== -1;
  }

  function setActionFilter(actionName) {
    state.actionFilter = actionName || "all";
    document.querySelectorAll(".filter-chip").forEach(function (c) {
      c.classList.toggle("active", c.dataset.actionFilter === state.actionFilter);
    });
    renderLiveFeed();
  }

  function renderEventCard(ev) {
    const card = document.createElement("article");
    const action = String(ev.action || "allow").toLowerCase();
    const maxSev = ev.max_severity ? String(ev.max_severity).toLowerCase() : "";
    let tierClass = "";
    if (maxSev === "critical") {
      tierClass = " event-item-critical";
    } else if (maxSev === "high") {
      tierClass = " event-item-high";
    }
    card.className = "event-item" + tierClass;

    const top = document.createElement("div");
    top.className = "event-top";

    const meta = document.createElement("div");
    meta.className = "event-meta";

    meta.appendChild(
      makeBadge(formatActionLabel(action), "action-badge action-" + action)
    );
    if (maxSev) {
      meta.appendChild(
        makeBadge(formatSeverityLabel(maxSev), "sev-badge sev-" + maxSev)
      );
    }
    if (ev.direction) {
      meta.appendChild(
        makeBadge(formatModeLabel(ev.direction), "pill pill-neutral")
      );
    }
    if (ev.method) {
      const methodBadge = document.createElement("code");
      methodBadge.className = "rule-badge mono-code";
      methodBadge.textContent = String(ev.method);
      meta.appendChild(methodBadge);
    }
    if (ev.tool_name) {
      const toolBadge = document.createElement("code");
      toolBadge.className = "rule-badge mono-code";
      renderSafeText(toolBadge, "tool:" + ev.tool_name);
      meta.appendChild(toolBadge);
    }
    if (ev.uri) {
      const uriBadge = document.createElement("code");
      uriBadge.className = "rule-badge mono-code";
      renderSafeText(uriBadge, "uri:" + ev.uri);
      meta.appendChild(uriBadge);
    }

    const timeEl = document.createElement("span");
    timeEl.className = "event-time mono-num";
    timeEl.textContent = formatTimestamp(ev.timestamp);
    if (ev.timestamp) {
      timeEl.title = String(ev.timestamp);
    }

    top.appendChild(meta);
    top.appendChild(timeEl);
    card.appendChild(top);

    const summary = document.createElement("p");
    summary.className = "event-summary";
    renderSafeText(
      summary,
      ev.summary || (ev.allowed ? "Message inspected and allowed" : "Security policy triggered")
    );
    card.appendChild(summary);

    if (Array.isArray(ev.findings) && ev.findings.length > 0) {
      const list = document.createElement("div");
      list.className = "event-findings";
      ev.findings.forEach(function (f) {
        const row = document.createElement("div");
        row.className = "event-finding-row";
        const sev = String(f.severity || "info").toLowerCase();
        row.appendChild(
          makeBadge(formatSeverityLabel(sev), "sev-badge sev-" + sev)
        );
        const ruleCode = document.createElement("code");
        ruleCode.className = "rule-badge mono-code";
        ruleCode.textContent = String(f.rule_id || "MCP-RULE");
        row.appendChild(ruleCode);

        const titleSpan = document.createElement("span");
        renderSafeText(titleSpan, f.title || "");
        row.appendChild(titleSpan);

        if (f.target) {
          const targetCode = document.createElement("code");
          targetCode.className = "mono-code muted";
          renderSafeText(targetCode, "(" + f.target + ")");
          row.appendChild(targetCode);
        }
        list.appendChild(row);
      });
      card.appendChild(list);
    }

    const details = document.createElement("details");
    details.className = "event-raw-details";
    const summaryEl = document.createElement("summary");
    summaryEl.textContent = "Inspect JSON payload";
    const pre = document.createElement("pre");
    pre.className = "code-block mono-code";
    renderSafeText(pre, JSON.stringify(ev, null, 2));
    details.appendChild(summaryEl);
    details.appendChild(pre);
    card.appendChild(details);

    return card;
  }

  function renderLiveFeed() {
    const container = byId("live-feed-list");
    clearElement(container);

    const hasFilters =
      state.actionFilter !== "all" ||
      state.severityFilter !== "all" ||
      state.searchQuery.trim() !== "";

    const resetBtn = byId("btn-clear-feed-filters");
    if (resetBtn) {
      resetBtn.classList.toggle("is-hidden", !hasFilters);
    }

    const filtered = state.events.filter(eventMatchesFilter);
    const statsEl = byId("feed-stats-line");
    if (statsEl) {
      statsEl.textContent = hasFilters
        ? filtered.length + " of " + state.events.length + " events"
        : state.events.length + " event" + (state.events.length === 1 ? "" : "s");
    }

    if (filtered.length === 0) {
      const empty = document.createElement("div");
      empty.className = "panel-box empty-state";

      const title = document.createElement("p");
      title.className = "empty-title";
      title.textContent =
        state.events.length === 0
          ? "Waiting for MCP proxy traffic or scan events"
          : "No events match the active filters";
      empty.appendChild(title);

      const desc = document.createElement("p");
      desc.className = "panel-desc";
      desc.textContent =
        state.events.length === 0
          ? "Attach a live proxy session with --ui-port or trigger the built-in 6-vector security demo to inspect events here."
          : "Clear search or severity filters to view buffered telemetry.";
      empty.appendChild(desc);

      const actions = document.createElement("div");
      actions.className = "empty-actions";

      if (state.events.length === 0) {
        const demoBtn = document.createElement("button");
        demoBtn.type = "button";
        demoBtn.className = "btn btn-primary";
        demoBtn.textContent = "Run 6-Vector Demo";
        demoBtn.addEventListener("click", function () {
          switchTab("scanner");
          runDemoScan();
        });
        actions.appendChild(demoBtn);

        const cliHint = document.createElement("code");
        cliHint.className = "empty-cli-hint mono-code";
        cliHint.textContent = "mcp-guard wrap --ui-port 8766 -- <server-cmd>";
        actions.appendChild(cliHint);
      } else {
        const clearBtn = document.createElement("button");
        clearBtn.type = "button";
        clearBtn.className = "btn btn-secondary";
        clearBtn.textContent = "Reset Filters";
        clearBtn.addEventListener("click", resetFeedFilters);
        actions.appendChild(clearBtn);
      }

      empty.appendChild(actions);
      container.appendChild(empty);
      return;
    }

    filtered.forEach(function (ev) {
      container.appendChild(renderEventCard(ev));
    });
  }

  function resetFeedFilters() {
    state.actionFilter = "all";
    state.severityFilter = "all";
    state.searchQuery = "";
    byId("feed-severity-filter").value = "all";
    byId("feed-search").value = "";
    setActionFilter("all");
  }

  function setSseStatus(statusName, label) {
    const pill = byId("sse-indicator");
    const text = byId("sse-status-text");
    pill.className = "sse-pill sse-" + statusName;
    text.textContent = label;
  }

  async function loadInitialHistory() {
    try {
      const data = await apiFetch("/api/history?limit=200");
      const items = Array.isArray(data)
        ? data
        : Array.isArray(data.events)
        ? data.events
        : [];
      items.forEach(function (ev) {
        ingestEvent(ev, true);
      });
      renderLiveFeed();
    } catch (err) {
      renderLiveFeed();
    }
  }

  function connectSse() {
    if (state.eventSource) {
      state.eventSource.close();
    }
    setSseStatus("connecting", "Connecting");
    const es = new EventSource("/api/events");
    state.eventSource = es;

    es.onopen = function () {
      setSseStatus("live", "Live");
    };

    es.onmessage = function (msg) {
      if (!msg.data) return;
      try {
        const parsed = JSON.parse(msg.data);
        if (ingestEvent(parsed, false)) {
          renderLiveFeed();
        }
      } catch (err) {
        // Ignore non-JSON keepalive comments.
      }
    };

    es.onerror = function () {
      setSseStatus("offline", "Reconnecting");
    };
  }

  /* Scanner & Demo */
  function renderScanSummary(report) {
    const grid = byId("scan-summary-cards");
    clearElement(grid);

    const counts = report.summary_counts || {};
    const total =
      counts.total !== undefined
        ? counts.total
        : Array.isArray(report.findings)
        ? report.findings.length
        : 0;
    const maxSev = report.max_severity
      ? formatSeverityLabel(report.max_severity)
      : "None";

    const critCount = Number(counts.critical || 0);
    const highCount = Number(counts.high || 0);
    const medLowCount = Number(counts.medium || 0) + Number(counts.low || 0);
    const promptsCount = Number(report.prompts_scanned || 0);
    const resourcesCount = Number(report.resources_scanned || 0);

    const cards = [
      {
        label: "Total Findings",
        value: String(total),
        tone: total > 0 ? "summary-value-danger" : "summary-value-ok",
      },
      {
        label: "Max Severity",
        value: maxSev,
        tone:
          maxSev === "Critical"
            ? "summary-value-danger"
            : maxSev === "High"
            ? "summary-value-warn"
            : "",
      },
      {
        label: "Tools Scanned",
        value: String(report.tools_scanned || 0),
        tone: "",
      },
      {
        label: "Prompts / Resources",
        value: promptsCount + " / " + resourcesCount,
        tone: "",
      },
      {
        label: "Critical / High",
        value: critCount + " / " + highCount,
        tone: critCount > 0 ? "summary-value-danger" : highCount > 0 ? "summary-value-warn" : "",
      },
      {
        label: "Medium / Low",
        value: String(medLowCount),
        tone: "",
      },
    ];

    cards.forEach(function (item) {
      const cell = document.createElement("div");
      cell.className = "summary-cell";
      const lbl = document.createElement("div");
      lbl.className = "summary-label";
      lbl.textContent = item.label;
      const val = document.createElement("div");
      val.className = "summary-value mono-num" + (item.tone ? " " + item.tone : "");
      val.textContent = item.value;
      cell.appendChild(lbl);
      cell.appendChild(val);
      grid.appendChild(cell);
    });
  }

  function renderDetectorStrip(findings) {
    const strip = byId("scan-detector-strip");
    if (!strip) return;
    clearElement(strip);

    const counts = new Map();
    findings.forEach(function (f) {
      const det = String(f.detector || "other");
      counts.set(det, (counts.get(det) || 0) + 1);
    });

    const allBtn = document.createElement("button");
    allBtn.type = "button";
    allBtn.className =
      "filter-chip" + (state.scanDetectorFilter === "all" ? " active" : "");
    allBtn.textContent = "All detectors (" + findings.length + ")";
    allBtn.addEventListener("click", function () {
      state.scanDetectorFilter = "all";
      renderScanFindingsTable();
    });
    strip.appendChild(allBtn);

    Array.from(counts.entries()).forEach(function (entry) {
      const det = entry[0];
      const count = entry[1];
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className =
        "filter-chip" + (state.scanDetectorFilter === det ? " active" : "");
      btn.textContent = det + " (" + count + ")";
      btn.addEventListener("click", function () {
        state.scanDetectorFilter = det;
        renderScanFindingsTable();
      });
      strip.appendChild(btn);
    });
  }

  function findingMatchesFilters(f) {
    if (
      state.scanDetectorFilter !== "all" &&
      String(f.detector || "other") !== state.scanDetectorFilter
    ) {
      return false;
    }
    const sev = String(f.severity || "info").toLowerCase();
    if (state.scanSeverityFilter !== "all" && sev !== state.scanSeverityFilter) {
      return false;
    }
    const q = state.scanSearchQuery.trim().toLowerCase();
    if (!q) return true;
    const hay = [
      f.rule_id,
      f.detector,
      f.target,
      f.title,
      f.description,
      f.evidence,
      f.remediation,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.indexOf(q) !== -1;
  }

  function renderScanFindingsTable() {
    const report = state.latestReport;
    if (!report) return;
    const allFindings = Array.isArray(report.findings) ? report.findings : [];
    renderDetectorStrip(allFindings);

    const tbody = byId("scan-findings-tbody");
    clearElement(tbody);

    const filtered = allFindings.filter(findingMatchesFilters);

    if (allFindings.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.className = "muted";
      td.textContent = "Zero security findings detected.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    if (filtered.length === 0) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 5;
      td.className = "muted";
      td.textContent = "No scan findings match the selected detector or search filter.";
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    filtered.forEach(function (f) {
      const tr = document.createElement("tr");

      const tdSev = document.createElement("td");
      const sev = String(f.severity || "info").toLowerCase();
      tdSev.appendChild(
        makeBadge(formatSeverityLabel(sev), "sev-badge sev-" + sev)
      );
      tr.appendChild(tdSev);

      const tdRule = document.createElement("td");
      const ruleCode = document.createElement("code");
      ruleCode.className = "rule-badge mono-code";
      ruleCode.textContent = String(f.rule_id || "");
      tdRule.appendChild(ruleCode);
      if (f.detector) {
        const det = document.createElement("div");
        det.className = "detector-sub";
        det.textContent = String(f.detector);
        tdRule.appendChild(det);
      }
      tr.appendChild(tdRule);

      const tdTarget = document.createElement("td");
      tdTarget.className = "mono-code";
      renderSafeText(tdTarget, f.target || "-");
      tr.appendChild(tdTarget);

      const tdDetails = document.createElement("td");
      const titleEl = document.createElement("div");
      titleEl.className = "finding-title";
      renderSafeText(titleEl, f.title || "");
      tdDetails.appendChild(titleEl);

      if (f.description) {
        const descEl = document.createElement("div");
        descEl.className = "finding-desc";
        renderSafeText(descEl, f.description);
        tdDetails.appendChild(descEl);
      }
      if (f.evidence) {
        const evBox = document.createElement("div");
        evBox.className = "evidence-box mono-code";
        renderSafeText(evBox, f.evidence);
        tdDetails.appendChild(evBox);
      }
      if (f.remediation) {
        const remEl = document.createElement("div");
        remEl.className = "finding-remediation";
        renderSafeText(remEl, "Remediation: " + f.remediation);
        tdDetails.appendChild(remEl);
      }
      tr.appendChild(tdDetails);

      const tdAction = document.createElement("td");
      const act = String(f.action_taken || "log").toLowerCase();
      tdAction.appendChild(
        makeBadge(formatActionLabel(act), "action-badge action-" + act)
      );
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    });
  }

  function renderScanReport(report) {
    if (!report || typeof report !== "object") return;
    state.latestReport = report;
    state.scanDetectorFilter = "all";
    state.scanSeverityFilter = "all";
    state.scanSearchQuery = "";
    byId("scan-filter-severity").value = "all";
    byId("scan-filter-search").value = "";

    byId("scan-empty-state").classList.add("is-hidden");
    byId("scan-report-area").classList.remove("is-hidden");

    const findingsCount = Array.isArray(report.findings) ? report.findings.length : 0;
    const scanBadge = byId("scan-findings-badge");
    if (scanBadge) {
      if (findingsCount > 0) {
        scanBadge.textContent = String(findingsCount);
        scanBadge.classList.remove("is-hidden");
      } else {
        scanBadge.classList.add("is-hidden");
      }
    }

    renderScanSummary(report);

    const meta = byId("scan-target-meta");
    clearElement(meta);
    const serverInfo = report.server_info || {};
    const infoName = [serverInfo.name, serverInfo.version].filter(Boolean).join(" ");
    renderSafeText(
      meta,
      "Target: " +
        (report.target || "") +
        " | Server ID: " +
        (report.server_id || "default") +
        (infoName ? " | Upstream: " + infoName : "")
    );

    const errBox = byId("scan-errors-box");
    clearElement(errBox);
    if (Array.isArray(report.errors) && report.errors.length > 0) {
      errBox.classList.remove("is-hidden");
      renderSafeText(errBox, "Scanner errors: " + report.errors.join("; "));
    } else {
      errBox.classList.add("is-hidden");
    }

    renderScanFindingsTable();
  }

  async function runDemoScan() {
    const btn = byId("btn-run-demo");
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    btn.textContent = "Running Demo…";
    try {
      const report = await apiFetch("/api/demo", { method: "POST", body: {} });
      renderScanReport(report);
      showToast("6-Vector demo scan completed", false);
      loadPins();
    } catch (err) {
      showToast("Demo failed: " + err.message, true);
    } finally {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.textContent = "Run 6-Vector Demo";
    }
  }

  async function handleHttpScan(ev) {
    ev.preventDefault();
    const url = byId("scan-http-url").value.trim();
    const probes = Number(byId("scan-http-probes").value) || 2;
    if (!url) return;

    const btn = byId("btn-scan-http");
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    btn.textContent = "Scanning…";
    try {
      const report = await apiFetch("/api/scan", {
        method: "POST",
        body: { kind: "http", url: url, rug_pull_probes: probes },
      });
      renderScanReport(report);
      showToast("HTTP scan completed", false);
      loadPins();
    } catch (err) {
      showToast("HTTP scan failed: " + err.message, true);
    } finally {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.textContent = "Scan HTTP URL";
    }
  }

  async function handleStdioScan(ev) {
    ev.preventDefault();
    const command = byId("scan-stdio-cmd").value.trim();
    const probes = Number(byId("scan-stdio-probes").value) || 2;
    const notice = byId("stdio-scan-notice");
    notice.classList.add("is-hidden");
    if (!command) {
      showToast("Enter a STDIO command to scan", true);
      return;
    }

    const btn = byId("btn-scan-stdio");
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    btn.textContent = "Scanning…";
    try {
      const report = await apiFetch("/api/scan", {
        method: "POST",
        body: { kind: "stdio", command: command, rug_pull_probes: probes },
      });
      renderScanReport(report);
      showToast("STDIO scan completed", false);
      loadPins();
    } catch (err) {
      if (err.status === 403) {
        notice.textContent =
          "STDIO subprocess execution is disabled (403 Forbidden). Start MCP-Guard UI with --allow-exec to enable local STDIO scanning, or use Run 6-Vector Demo / HTTP Scan.";
        notice.classList.remove("is-hidden");
      }
      showToast("STDIO scan blocked or failed: " + err.message, true);
    } finally {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.textContent = "Scan STDIO";
    }
  }

  async function downloadExport(format) {
    const extMap = { sarif: "sarif", markdown: "md", json: "json" };
    try {
      const resp = await fetch(
        "/api/scans/latest/export?format=" + encodeURIComponent(format),
        { credentials: "same-origin" }
      );
      if (!resp.ok) {
        throw new Error("HTTP " + resp.status);
      }
      const text = await resp.text();
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const blobUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = blobUrl;
      a.download = "mcp-guard-report." + (extMap[format] || "txt");
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    } catch (err) {
      showToast("Export failed: " + err.message, true);
    }
  }

  /* Schema Pins & Rug-Pull Diffs */
  function renderDiffLines(diffText) {
    const box = document.createElement("div");
    box.className = "diff-view";
    const lines = String(diffText || "").split("\n");
    lines.forEach(function (line) {
      const row = document.createElement("div");
      row.className = "diff-line";
      if (line.startsWith("+") && !line.startsWith("+++")) {
        row.classList.add("diff-line-add");
      } else if (line.startsWith("-") && !line.startsWith("---")) {
        row.classList.add("diff-line-del");
      } else if (line.startsWith("@@")) {
        row.classList.add("diff-line-hunk");
      }
      renderSafeText(row, line || " ");
      box.appendChild(row);
    });
    return box;
  }

  function renderToolSnapshotBox(label, toolObj) {
    const wrap = document.createElement("div");
    const lbl = document.createElement("div");
    lbl.className = "field-label";
    lbl.textContent = label;
    wrap.appendChild(lbl);

    const box = document.createElement("div");
    box.className = "evidence-box mono-code";
    const pretty = JSON.stringify(toolObj || {}, null, 2);
    renderSafeText(box, pretty);
    wrap.appendChild(box);
    return wrap;
  }

  function computeSimpleDiffText(pinnedTool, pendingTool) {
    const left = JSON.stringify(pinnedTool || {}, null, 2).split("\n");
    const right = JSON.stringify(pendingTool || {}, null, 2).split("\n");
    const out = ["--- pinned", "+++ pending"];
    const maxLen = Math.max(left.length, right.length);
    for (let i = 0; i < maxLen; i += 1) {
      const l = left[i];
      const r = right[i];
      if (l === r) {
        if (l !== undefined) out.push("  " + l);
      } else {
        if (l !== undefined) out.push("- " + l);
        if (r !== undefined) out.push("+ " + r);
      }
    }
    return out.join("\n");
  }

  async function copyPlainText(text, label, buttonEl) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        document.body.removeChild(area);
      }
      if (buttonEl) {
        const prev = buttonEl.textContent;
        buttonEl.textContent = "Copied";
        window.setTimeout(function () {
          buttonEl.textContent = prev;
        }, 1600);
      }
      showToast("Copied " + label + " to clipboard", false);
    } catch (err) {
      showToast("Copy failed: " + err.message, true);
    }
  }

  function armResetButton(buttonEl, defaultLabel, confirmLabel, onConfirm) {
    const key = buttonEl.dataset.resetKey || defaultLabel;
    if (buttonEl.dataset.armed === "true") {
      window.clearTimeout(state.resetConfirmTimers.get(key));
      state.resetConfirmTimers.delete(key);
      buttonEl.dataset.armed = "false";
      buttonEl.classList.remove("btn-danger-armed");
      buttonEl.textContent = defaultLabel;
      onConfirm();
      return;
    }

    buttonEl.dataset.armed = "true";
    buttonEl.classList.add("btn-danger-armed");
    buttonEl.textContent = confirmLabel;
    const timer = window.setTimeout(function () {
      buttonEl.dataset.armed = "false";
      buttonEl.classList.remove("btn-danger-armed");
      buttonEl.textContent = defaultLabel;
      state.resetConfirmTimers.delete(key);
    }, 4000);
    state.resetConfirmTimers.set(key, timer);
  }

  function renderPins(pinsPayload) {
    const container = byId("pins-container");
    clearElement(container);

    const servers =
      pinsPayload && typeof pinsPayload === "object"
        ? pinsPayload.servers || pinsPayload
        : {};
    const diffs =
      pinsPayload && typeof pinsPayload === "object" && pinsPayload.diffs
        ? pinsPayload.diffs
        : {};

    const serverIds = Object.keys(servers).filter(function (k) {
      return k !== "diffs" && k !== "version" && typeof servers[k] === "object";
    });

    let pendingCount = 0;
    let pinnedCount = 0;
    serverIds.forEach(function (sid) {
      const entry = servers[sid] || {};
      const tools = entry.tools || {};
      const pend = entry.pending || {};
      pinnedCount += Object.keys(tools).length;
      pendingCount += Object.keys(pend).length;
    });

    const badge = byId("pending-pins-badge");
    if (pendingCount > 0) {
      badge.textContent = String(pendingCount);
      badge.classList.remove("is-hidden");
    } else {
      badge.classList.add("is-hidden");
    }

    const summaryBar = byId("pins-summary-bar");
    if (summaryBar) {
      clearElement(summaryBar);
      if (serverIds.length > 0) {
        summaryBar.classList.remove("is-hidden");
        const items = [
          { label: "Servers", val: String(serverIds.length) },
          { label: "Pinned Tools", val: String(pinnedCount) },
          { label: "Pending / Mutations", val: String(pendingCount) },
        ];
        if (pinsPayload && pinsPayload.pin_file) {
          items.push({ label: "Pin Store", val: String(pinsPayload.pin_file), isPath: true });
        }
        items.forEach(function (it) {
          const stat = document.createElement("div");
          stat.className = "pins-summary-stat";
          const k = document.createElement("span");
          k.className = "meta-key";
          k.textContent = it.label + ":";
          const v = document.createElement("span");
          v.className = it.isPath ? "mono-code muted" : "mono-num";
          v.textContent = it.val;
          stat.appendChild(k);
          stat.appendChild(v);
          summaryBar.appendChild(stat);
        });
      } else {
        summaryBar.classList.add("is-hidden");
      }
    }

    if (serverIds.length === 0) {
      const empty = document.createElement("div");
      empty.className = "panel-box empty-state";
      const title = document.createElement("p");
      title.className = "empty-title";
      title.textContent = "No pinned or pending tool schemas recorded yet";
      empty.appendChild(title);

      const p = document.createElement("p");
      p.className = "panel-desc";
      p.textContent =
        "Run a scan or proxy session to compute SHA-256 tool schema fingerprints and detect mid-session mutations.";
      empty.appendChild(p);

      const actions = document.createElement("div");
      actions.className = "empty-actions";
      const goScan = document.createElement("button");
      goScan.type = "button";
      goScan.className = "btn btn-primary";
      goScan.textContent = "Open Scanner & Demo";
      goScan.addEventListener("click", function () {
        switchTab("scanner");
      });
      actions.appendChild(goScan);
      empty.appendChild(actions);

      container.appendChild(empty);
      return;
    }

    serverIds.forEach(function (sid) {
      const entry = servers[sid] || {};
      const tools = entry.tools || {};
      const pending = entry.pending || {};
      const serverDiffs =
        entry.diffs && typeof entry.diffs === "object"
          ? entry.diffs
          : diffs[sid] || {};

      const section = document.createElement("section");
      section.className = "pins-server-section";

      const header = document.createElement("div");
      header.className = "pins-server-head";

      const titleWrap = document.createElement("div");
      titleWrap.className = "pins-server-title";
      const title = document.createElement("h3");
      title.className = "mono-code";
      renderSafeText(title, sid);
      titleWrap.appendChild(title);

      const srvPinned = Object.keys(tools).length;
      const srvPending = Object.keys(pending).length;
      titleWrap.appendChild(
        makeBadge(srvPinned + " pinned", "pill pill-neutral")
      );
      if (srvPending > 0) {
        titleWrap.appendChild(
          makeBadge(srvPending + " pending", "sev-badge sev-high")
        );
      }
      header.appendChild(titleWrap);

      const actions = document.createElement("div");
      actions.className = "toolbar-actions";
      if (srvPending > 0) {
        const approveBtn = document.createElement("button");
        approveBtn.type = "button";
        approveBtn.className = "btn btn-primary btn-sm";
        approveBtn.textContent = "Approve Pending";
        approveBtn.addEventListener("click", function () {
          approvePins(sid, null);
        });
        actions.appendChild(approveBtn);
      }
      const resetBtn = document.createElement("button");
      resetBtn.type = "button";
      resetBtn.className = "btn btn-danger btn-sm";
      resetBtn.dataset.resetKey = "reset-srv-" + sid;
      resetBtn.textContent = "Reset Server";
      resetBtn.addEventListener("click", function () {
        armResetButton(resetBtn, "Reset Server", "Confirm Reset", function () {
          resetPins(sid);
        });
      });
      actions.appendChild(resetBtn);
      header.appendChild(actions);
      section.appendChild(header);

      const allNames = Array.from(
        new Set(Object.keys(pending).concat(Object.keys(tools)))
      ).sort(function (a, b) {
        function priority(name) {
          if (pending[name] && tools[name]) return 0; // Rug-Pull Mutation first
          if (pending[name]) return 1; // Pending Approval second
          return 2; // Approved Pinned last
        }
        const diff = priority(a) - priority(b);
        return diff !== 0 ? diff : a.localeCompare(b);
      });

      if (allNames.length === 0) {
        const none = document.createElement("p");
        none.className = "pin-row muted";
        none.textContent = "No tool entries recorded for this server.";
        section.appendChild(none);
      }

      allNames.forEach(function (toolName) {
        const pinnedRec = tools[toolName] || null;
        const pendingRec = pending[toolName] || null;

        const row = document.createElement("div");
        row.className =
          "pin-row" + (pendingRec ? " pin-row-pending" : "");

        const rowHead = document.createElement("div");
        rowHead.className = "pin-row-head";

        const left = document.createElement("div");
        left.className = "event-meta";
        const nameEl = document.createElement("strong");
        nameEl.className = "mono-code";
        renderSafeText(nameEl, toolName);
        left.appendChild(nameEl);

        if (pendingRec && pinnedRec) {
          left.appendChild(makeBadge("Rug-Pull Mutation", "sev-badge sev-critical"));
        } else if (pendingRec) {
          left.appendChild(makeBadge("Pending Approval", "sev-badge sev-high"));
        } else {
          left.appendChild(makeBadge("Pinned", "action-badge action-allow"));
        }

        rowHead.appendChild(left);

        if (pendingRec) {
          const approveToolBtn = document.createElement("button");
          approveToolBtn.type = "button";
          approveToolBtn.className = "btn btn-primary btn-sm";
          approveToolBtn.textContent = "Approve Tool";
          approveToolBtn.addEventListener("click", function () {
            approvePins(sid, toolName);
          });
          rowHead.appendChild(approveToolBtn);
        }

        row.appendChild(rowHead);

        const hashLine = document.createElement("div");
        hashLine.className = "pin-hash-line";
        if (pinnedRec && pinnedRec.hash) {
          const fullPinned = String(pinnedRec.hash);
          const h1Btn = document.createElement("button");
          h1Btn.type = "button";
          h1Btn.className = "hash-chip-btn";
          h1Btn.title = "Copy pinned SHA-256: " + fullPinned;
          h1Btn.textContent = "Pinned SHA-256: " + fullPinned.slice(0, 16) + "…";
          h1Btn.addEventListener("click", function () {
            copyPlainText(fullPinned, "pinned SHA-256", h1Btn);
          });
          hashLine.appendChild(h1Btn);
        }
        if (pendingRec && pendingRec.hash) {
          const fullPending = String(pendingRec.hash);
          const h2Btn = document.createElement("button");
          h2Btn.type = "button";
          h2Btn.className = "hash-chip-btn";
          h2Btn.title = "Copy pending SHA-256: " + fullPending;
          h2Btn.textContent = "Pending SHA-256: " + fullPending.slice(0, 16) + "…";
          h2Btn.addEventListener("click", function () {
            copyPlainText(fullPending, "pending SHA-256", h2Btn);
          });
          hashLine.appendChild(h2Btn);
        }
        row.appendChild(hashLine);

        const diffEntry = serverDiffs[toolName] || null;
        const diffText =
          diffEntry && typeof diffEntry.unified_diff === "string"
            ? diffEntry.unified_diff
            : typeof diffEntry === "string"
            ? diffEntry
            : pendingRec && typeof pendingRec.diff === "string"
            ? pendingRec.diff
            : pendingRec && pinnedRec
            ? computeSimpleDiffText(pinnedRec.tool, pendingRec.tool)
            : null;

        if (diffText) {
          const leftTool =
            (diffEntry && diffEntry.pinned_tool) ||
            (pinnedRec && pinnedRec.tool) ||
            null;
          const rightTool =
            (diffEntry && diffEntry.pending_tool) ||
            (pendingRec && pendingRec.tool) ||
            null;
          if (leftTool && rightTool) {
            const sideBySide = document.createElement("div");
            sideBySide.className = "diff-side-by-side";
            sideBySide.appendChild(renderToolSnapshotBox("Pinned Schema", leftTool));
            sideBySide.appendChild(renderToolSnapshotBox("Pending Schema (Mutation)", rightTool));
            row.appendChild(sideBySide);
          }
          row.appendChild(renderDiffLines(diffText));
        } else {
          const record = pendingRec || pinnedRec;
          if (record && record.tool) {
            row.appendChild(
              renderToolSnapshotBox(
                pendingRec ? "Pending Tool Schema" : "Pinned Tool Schema",
                record.tool
              )
            );
          }
        }

        section.appendChild(row);
      });

      container.appendChild(section);
    });
  }

  async function loadPins() {
    try {
      const data = await apiFetch("/api/pins");
      renderPins(data);
    } catch (err) {
      showToast("Failed to load pins: " + err.message, true);
    }
  }

  async function approvePins(serverId, toolName) {
    const body = {};
    if (serverId) body.server_id = serverId;
    if (toolName) body.tool_name = toolName;
    try {
      const res = await apiFetch("/api/pins/approve", {
        method: "POST",
        body: body,
      });
      const count = res && res.approved !== undefined ? res.approved : 0;
      showToast("Approved " + count + " tool pin(s)", false);
      await loadPins();
    } catch (err) {
      showToast("Approve failed: " + err.message, true);
    }
  }

  async function resetPins(serverId) {
    const body = serverId ? { server_id: serverId } : {};
    try {
      const res = await apiFetch("/api/pins/reset", {
        method: "POST",
        body: body,
      });
      const count = res && res.cleared !== undefined ? res.cleared : 0;
      showToast("Cleared " + count + " pin(s)", false);
      await loadPins();
    } catch (err) {
      showToast("Reset failed: " + err.message, true);
    }
  }

  /* Policy & Client Config */
  const POLICY_TOGGLES = [
    { section: "poisoning", field: "enabled", label: "Tool Poisoning Detector" },
    { section: "unicode", field: "enabled", label: "Unicode / Tag Guard" },
    { section: "pinning", field: "enabled", label: "Schema Pinning" },
    { section: "shadowing", field: "enabled", label: "Cross-Tool Shadowing" },
    { section: "runtime_guard", field: "enabled", label: "Runtime Argument Guard" },
    { section: "runtime_guard", field: "allow_private_urls", label: "Allow Private URLs (SSRF)" },
    { section: "response_guard", field: "enabled", label: "Response Guard" },
    { section: "response_guard", field: "detect_indirect_injection", label: "Detect Indirect IPI" },
    { section: "response_guard", field: "detect_secrets", label: "Detect & Redact Secrets" },
    { section: "rate_limit", field: "enabled", label: "Token-Bucket Rate Limit" },
    { section: "llm_judge", field: "enabled", label: "Semantic LLM Judge" },
  ];

  function setPolicyDirty(dirty) {
    state.policyDirty = Boolean(dirty);
    const pill = byId("policy-dirty-pill");
    const discardBtn = byId("btn-reset-policy");
    const tabBadge = byId("policy-dirty-badge");
    if (pill) pill.classList.toggle("is-hidden", !state.policyDirty);
    if (discardBtn) discardBtn.classList.toggle("is-hidden", !state.policyDirty);
    if (tabBadge) tabBadge.classList.toggle("is-hidden", !state.policyDirty);
  }

  function renderPolicyForm(data) {
    const policy =
      data && typeof data === "object" && data.policy ? data.policy : data;
    if (!policy || typeof policy !== "object") return;
    state.policy = policy;
    state.selectedMode = String(policy.mode || "enforce").toLowerCase();
    setPolicyDirty(false);

    document.querySelectorAll(".mode-option").forEach(function (btn) {
      const isActive = btn.dataset.policyMode === state.selectedMode;
      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-checked", isActive ? "true" : "false");
    });

    const pinningModeEl = byId("policy-pinning-mode");
    if (pinningModeEl && policy.pinning && policy.pinning.mode) {
      pinningModeEl.value = String(policy.pinning.mode);
    }

    const rpmEl = byId("policy-rate-rpm");
    if (rpmEl && policy.rate_limit && policy.rate_limit.requests_per_minute !== undefined) {
      rpmEl.value = String(policy.rate_limit.requests_per_minute);
    }
    const burstEl = byId("policy-rate-burst");
    if (burstEl && policy.rate_limit && policy.rate_limit.burst !== undefined) {
      burstEl.value = String(policy.rate_limit.burst);
    }
    const entropyEl = byId("policy-entropy-threshold");
    if (
      entropyEl &&
      policy.response_guard &&
      policy.response_guard.entropy_threshold !== undefined
    ) {
      entropyEl.value = String(policy.response_guard.entropy_threshold);
    }

    const togglesWrap = byId("policy-toggles");
    clearElement(togglesWrap);

    POLICY_TOGGLES.forEach(function (spec) {
      const label = document.createElement("label");
      label.className = "toggle-item";

      const span = document.createElement("span");
      span.textContent = spec.label;

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.dataset.section = spec.section;
      checkbox.dataset.field = spec.field;
      const sectionObj = policy[spec.section] || {};
      checkbox.checked = Boolean(sectionObj[spec.field]);
      checkbox.addEventListener("change", function () {
        setPolicyDirty(true);
      });

      label.appendChild(span);
      label.appendChild(checkbox);
      togglesWrap.appendChild(label);
    });

    const snippets =
      data && typeof data === "object" && data.snippets ? data.snippets : {};
    const claudeSnippet =
      snippets.claude_desktop ||
      data.claude_desktop_config ||
      JSON.stringify(
        {
          mcpServers: {
            "protected-server": {
              command: "mcp-guard",
              args: [
                "wrap",
                "--mode",
                state.selectedMode,
                "--",
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/path/to/workspace",
              ],
            },
          },
        },
        null,
        2
      );
    const cursorSnippet =
      snippets.cursor || data.cursor_config || claudeSnippet;

    byId("snippet-claude").textContent =
      typeof claudeSnippet === "string"
        ? claudeSnippet
        : JSON.stringify(claudeSnippet, null, 2);
    byId("snippet-cursor").textContent =
      typeof cursorSnippet === "string"
        ? cursorSnippet
        : JSON.stringify(cursorSnippet, null, 2);
    byId("snippet-yaml").textContent =
      data && data.yaml ? String(data.yaml) : "";
  }

  async function loadPolicy() {
    try {
      const data = await apiFetch("/api/policy");
      renderPolicyForm(data);
    } catch (err) {
      showToast("Failed to load policy: " + err.message, true);
    }
  }

  async function savePolicy() {
    const updated = Object.assign({}, state.policy || {});
    updated.mode = state.selectedMode;
    updated.pinning = Object.assign({}, updated.pinning || {}, {
      mode: byId("policy-pinning-mode").value,
    });

    const rpmVal = parseInt(byId("policy-rate-rpm").value, 10);
    const burstVal = parseInt(byId("policy-rate-burst").value, 10);
    const entropyVal = parseFloat(byId("policy-entropy-threshold").value);

    updated.rate_limit = Object.assign({}, updated.rate_limit || {}, {
      requests_per_minute: Number.isFinite(rpmVal) && rpmVal >= 1 ? rpmVal : 60,
      burst: Number.isFinite(burstVal) && burstVal >= 1 ? burstVal : 15,
    });
    updated.response_guard = Object.assign({}, updated.response_guard || {}, {
      entropy_threshold:
        Number.isFinite(entropyVal) && entropyVal >= 0 ? entropyVal : 3.5,
    });

    byId("policy-toggles")
      .querySelectorAll('input[type="checkbox"]')
      .forEach(function (cb) {
        const sec = cb.dataset.section;
        const fld = cb.dataset.field;
        updated[sec] = Object.assign({}, updated[sec] || {});
        updated[sec][fld] = cb.checked;
      });

    const btn = byId("btn-save-policy");
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    btn.textContent = "Saving…";
    try {
      const data = await apiFetch("/api/policy", {
        method: "POST",
        body: updated,
      });
      renderPolicyForm(data);
      refreshStatus();
      showToast("Runtime policy updated", false);
    } catch (err) {
      showToast("Failed to save policy: " + err.message, true);
    } finally {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.textContent = "Save Policy";
    }
  }

  function wireEvents() {
    const tabButtons = Array.from(document.querySelectorAll(".tab-btn"));
    tabButtons.forEach(function (btn, idx) {
      btn.addEventListener("click", function () {
        switchTab(btn.dataset.tab);
      });
      btn.addEventListener("keydown", function (ev) {
        let nextIdx = -1;
        if (ev.key === "ArrowRight") {
          nextIdx = (idx + 1) % tabButtons.length;
        } else if (ev.key === "ArrowLeft") {
          nextIdx = (idx - 1 + tabButtons.length) % tabButtons.length;
        } else if (ev.key === "Home") {
          nextIdx = 0;
        } else if (ev.key === "End") {
          nextIdx = tabButtons.length - 1;
        }
        if (nextIdx >= 0) {
          ev.preventDefault();
          const target = tabButtons[nextIdx];
          switchTab(target.dataset.tab);
          target.focus();
        }
      });
    });

    byId("header-guard-mode").addEventListener("click", function () {
      switchTab("policy");
    });

    document.querySelectorAll("[data-counter-filter]").forEach(function (cell) {
      cell.addEventListener("click", function () {
        switchTab("live-feed");
        setActionFilter(cell.dataset.counterFilter || "all");
      });
    });

    document.querySelectorAll(".filter-chip").forEach(function (chip) {
      chip.addEventListener("click", function () {
        setActionFilter(chip.dataset.actionFilter || "all");
      });
    });

    byId("feed-severity-filter").addEventListener("change", function (ev) {
      state.severityFilter = ev.target.value || "all";
      renderLiveFeed();
    });

    byId("feed-search").addEventListener("input", function (ev) {
      state.searchQuery = ev.target.value || "";
      renderLiveFeed();
    });

    byId("btn-clear-feed-filters").addEventListener("click", resetFeedFilters);

    byId("btn-pause-feed").addEventListener("click", function () {
      state.paused = !state.paused;
      if (!state.paused && state.pausedBuffer.length > 0) {
        state.pausedBuffer.forEach(function (queuedEv) {
          state.events.unshift(queuedEv);
        });
        state.pausedBuffer = [];
        if (state.events.length > MAX_FEED_ITEMS) {
          state.events.length = MAX_FEED_ITEMS;
        }
        updateCountersUI();
        renderLiveFeed();
      }
      updatePauseButtonUI();
    });

    byId("btn-clear-feed").addEventListener("click", function () {
      state.events = [];
      state.pausedBuffer = [];
      updateCountersUI();
      updatePauseButtonUI();
      renderLiveFeed();
    });

    byId("btn-run-demo").addEventListener("click", runDemoScan);
    byId("scan-http-form").addEventListener("submit", handleHttpScan);
    byId("scan-stdio-form").addEventListener("submit", handleStdioScan);

    byId("scan-filter-severity").addEventListener("change", function (ev) {
      state.scanSeverityFilter = ev.target.value || "all";
      renderScanFindingsTable();
    });
    byId("scan-filter-search").addEventListener("input", function (ev) {
      state.scanSearchQuery = ev.target.value || "";
      renderScanFindingsTable();
    });

    document.querySelectorAll("[data-export-format]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        downloadExport(btn.dataset.exportFormat);
      });
    });

    byId("btn-refresh-pins").addEventListener("click", loadPins);
    byId("btn-approve-all-pins").addEventListener("click", function () {
      approvePins(null, null);
    });
    const resetAllBtn = byId("btn-reset-all-pins");
    resetAllBtn.dataset.resetKey = "reset-all";
    resetAllBtn.addEventListener("click", function () {
      armResetButton(resetAllBtn, "Reset All", "Confirm Reset All", function () {
        resetPins(null);
      });
    });

    document.querySelectorAll(".mode-option").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.selectedMode = btn.dataset.policyMode || "enforce";
        document.querySelectorAll(".mode-option").forEach(function (other) {
          const match = other === btn;
          other.classList.toggle("active", match);
          other.setAttribute("aria-checked", match ? "true" : "false");
        });
        setPolicyDirty(true);
      });
    });

    byId("policy-pinning-mode").addEventListener("change", function () {
      setPolicyDirty(true);
    });
    byId("policy-rate-rpm").addEventListener("input", function () {
      setPolicyDirty(true);
    });
    byId("policy-rate-burst").addEventListener("input", function () {
      setPolicyDirty(true);
    });
    byId("policy-entropy-threshold").addEventListener("input", function () {
      setPolicyDirty(true);
    });

    byId("btn-reset-policy").addEventListener("click", loadPolicy);
    byId("btn-save-policy").addEventListener("click", savePolicy);

    byId("btn-copy-claude").addEventListener("click", function (ev) {
      copyPlainText(byId("snippet-claude").textContent || "", "Claude Desktop config", ev.currentTarget);
    });
    byId("btn-copy-cursor").addEventListener("click", function (ev) {
      copyPlainText(byId("snippet-cursor").textContent || "", "Cursor config", ev.currentTarget);
    });
    byId("btn-copy-yaml").addEventListener("click", function (ev) {
      copyPlainText(byId("snippet-yaml").textContent || "", "Policy YAML", ev.currentTarget);
    });

    window.addEventListener("hashchange", function () {
      switchTab(readTabFromHash(), true);
    });
  }

  async function init() {
    wireEvents();
    const initialTab = readTabFromHash();
    switchTab(initialTab, true);
    await Promise.all([refreshStatus(), loadInitialHistory(), loadPins()]);
    connectSse();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
