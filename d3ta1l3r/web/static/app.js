/* D3TA1L3R dashboard front-end.
 *
 * Vanilla JS, no build step, and every request uses a path relative to the
 * current origin — so the same code works when served locally, behind a reverse
 * proxy, or inside a sandbox preview host.
 */
(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);

  function setStatus(message, isError) {
    const node = $("#scan-status");
    if (!node) return;
    node.textContent = message || "";
    node.style.color = isError ? "var(--bad)" : "var(--muted)";
  }

  function formToPayload(form) {
    const data = new FormData(form);
    const payload = {};
    const list = (key) =>
      String(data.get(key) || "")
        .split(/[,\s]+/)
        .map((item) => item.trim())
        .filter(Boolean);

    for (const key of ["username", "email", "name", "domain", "location"]) {
      const value = String(data.get(key) || "").trim();
      if (value) payload[key] = value;
    }
    const sources = list("sources");
    if (sources.length) payload.sources = sources;
    const excluded = list("exclude_sources");
    if (excluded.length) payload.exclude_sources = excluded;
    const categories = list("categories");
    if (categories.length) payload.categories = categories;

    const maxSites = parseInt(data.get("max_sites"), 10);
    if (!Number.isNaN(maxSites)) payload.max_sites = maxSites;
    const concurrency = parseInt(data.get("concurrency"), 10);
    if (!Number.isNaN(concurrency)) payload.concurrency = concurrency;
    payload.min_confidence = data.get("min_confidence") || null;

    payload.demo = form.querySelector('[name="demo"]').checked;
    payload.respect_robots = form.querySelector('[name="respect_robots"]').checked;
    return payload;
  }

  async function startScan(event) {
    event.preventDefault();
    const form = event.target;
    const button = $("#scan-submit");
    const payload = formToPayload(form);

    if (!payload.username && !payload.email && !payload.name && !payload.domain) {
      setStatus("Enter at least one identifier to check.", true);
      return;
    }
    button.disabled = true;
    setStatus("Starting…");

    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail || "the dashboard rejected the request");
      }
      setStatus("Scanning…");
      window.location.href = body.page_url;
    } catch (error) {
      setStatus(String(error.message || error), true);
      button.disabled = false;
    }
  }

  /* Live progress page: SSE with a polling fallback. */
  function watchRun(runId) {
    const fill = $("#progress-fill");
    const status = $("#run-status");
    const counter = $("#run-counter");
    const message = $("#run-message");
    const log = $("#run-log");
    let finishedScan = null;
    let fallbackTimer = null;
    let stream = null;

    function append(line) {
      if (!log) return;
      log.textContent += line + "\n";
      log.scrollTop = log.scrollHeight;
      const lines = log.textContent.split("\n");
      if (lines.length > 120) log.textContent = lines.slice(-120).join("\n");
    }

    function handle(event) {
      if (event.percent !== undefined && fill) {
        fill.style.width = Math.max(2, event.percent) + "%";
      }
      if (event.completed !== undefined && counter) {
        counter.textContent = event.total ? event.completed + "/" + event.total + " sources" : "";
      }
      if (event.message && message) message.textContent = event.message;
      if (event.status && status) status.textContent = event.status;

      if (event.type === "source_finished" && event.status === "found") {
        append("✔ " + (event.source_name || event.source_id) + " — " + event.findings_count + " finding(s)");
      } else if (event.type === "run_error") {
        append("! " + event.error);
        if (message) message.textContent = event.error;
      } else if (event.type === "scan_completed") {
        finishedScan = event.scan_id;
        append("scan complete: " + event.findings + " finding(s) across " + event.sources + " sources");
      }
    }

    function stop() {
      if (stream) stream.close();
      if (fallbackTimer) clearInterval(fallbackTimer);
    }

    function poll() {
      fetch("/api/scans/" + encodeURIComponent(runId))
        .then((response) => response.json())
        .then((data) => {
          if (data.status) {
            if (status) status.textContent = data.status;
            if (message) message.textContent = data.status === "done" ? "Finished." : "Scanning…";
          }
          if (data.scan_ids && data.scan_ids.length) finishedScan = data.scan_ids.slice(-1)[0];
          if (data.status === "done" || data.status === "error") {
            stop();
            setTimeout(() => {
              window.location.href = finishedScan ? "/scans/" + finishedScan : "/";
            }, 900);
          }
        })
        .catch(() => {});
    }

    function beginPolling() {
      if (fallbackTimer) return;
      append("(stream unavailable — falling back to polling)");
      fallbackTimer = setInterval(poll, 2000);
      poll();
    }

    if (window.EventSource) {
      stream = new EventSource("/api/scans/" + encodeURIComponent(runId) + "/events");
      stream.onmessage = (message) => {
        let event;
        try {
          event = JSON.parse(message.data);
        } catch (error) {
          return;
        }
        handle(event);
        if (event.type === "run_finished") {
          stop();
          setTimeout(() => {
            window.location.href = finishedScan ? "/scans/" + finishedScan : "/";
          }, 700);
        }
      };
      stream.onerror = () => beginPolling();
    } else {
      beginPolling();
    }
  }

  function wireDeletes() {
    document.querySelectorAll("[data-delete]").forEach((button) => {
      button.addEventListener("click", async () => {
        const scanId = button.getAttribute("data-delete");
        if (!window.confirm("Delete this scan and its stored files?")) return;
        await fetch("/api/scans/" + encodeURIComponent(scanId), { method: "DELETE" });
        window.location.href = "/";
      });
    });
  }

  async function runCalibration() {
    const button = $("#calibrate-btn");
    const status = $("#calibrate-status");
    const log = $("#calibrate-log");
    if (!button) return;
    button.disabled = true;
    status.textContent = "probing bogus handles… (this makes real requests)";
    log.hidden = false;
    log.textContent = "";
    try {
      const response = await fetch("/api/calibrate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ absent_samples: 1 }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "calibration failed");
      const lines = ["site                          absent ok  false pos  ambiguous  verdict"];
      body.sites
        .slice()
        .sort((a, b) => b.counts.false_positive - a.counts.false_positive)
        .forEach((row) => {
          lines.push(
            row.id.padEnd(30) +
              String(row.counts.absent_confirmed).padStart(9) +
              String(row.counts.false_positive).padStart(11) +
              String(row.counts.ambiguous).padStart(11) +
              "  " +
              row.verdict
          );
        });
      log.textContent = lines.join("\n");
      status.textContent =
        body.false_positive_sites.length === 0
          ? "no false positives observed"
          : body.false_positive_sites.length + " site(s) produced false positives";
    } catch (error) {
      status.textContent = String(error.message || error);
    } finally {
      button.disabled = false;
    }
  }

  /* ---------------------------------------------------------------- breach watch
   * The watchlist is only present when the dashboard was started with a vault.
   * Nothing here ever echoes a secret back into the page: the API answers with
   * masked values and counts, and the password field is cleared as soon as it is
   * submitted.
   */

  function breachLine(check) {
    const label = check.label || check.masked_value;
    const where = check.label && check.label !== check.masked_value
      ? " (" + check.masked_value + ")"
      : "";
    return label + where + " — " + check.source_name + ": " + (check.detail || check.evidence);
  }

  function renderBreachResult(payload) {
    const node = $("#vault-check-result");
    if (!node) return;
    if (!payload) {
      node.innerHTML = "";
      return;
    }
    const report = payload.report || payload;
    const checks = report.checks || [];
    const unavailable = report.unavailable_sources || [];
    const pwned = checks.filter((c) => c.status === "pwned");
    const gaps = checks.filter((c) => c.status !== "pwned" && c.status !== "clean");
    const lines = [];
    if (report.headline) lines.push("<p><b>" + escapeHtml(report.headline) + "</b></p>");
    if (pwned.length) {
      lines.push('<p class="warn-text"><b>Found in breach data</b></p>');
      pwned.forEach((c) => lines.push("<p>" + escapeHtml(breachLine(c)) + "</p>"));
      lines.push(
        '<p class="fineprint">Change this password everywhere it was used, starting with ' +
          "your email account, and turn on two-factor authentication.</p>"
      );
    } else if (checks.length && !gaps.length) {
      lines.push('<p class="ok-text"><b>Not found</b> in the sources configured.</p>');
    }
    if (gaps.length) {
      lines.push('<p class="muted"><b>Not checked</b> (a gap, not a pass):</p>');
      gaps.forEach((c) => lines.push('<p class="muted">' + escapeHtml(breachLine(c)) + "</p>"));
    }
    if (!checks.length) {
      const names = unavailable.map((g) => g.source_name);
      lines.push(
        '<p class="muted">Nothing could check this entry' +
          (names.length ? " (" + escapeHtml(names.join(", ")) + " unavailable)" : "") +
          ". Configure a source and try again.</p>"
      );
    }
    node.innerHTML = lines.join("");
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[ch]));
  }

  async function addToWatchlist(event) {
    event.preventDefault();
    const form = event.target;
    const status = $("#vault-status");
    const data = new FormData(form);
    const kind = String(data.get("kind") || "email");
    const value = String(data.get("value") || "");
    const payload = {
      kind: kind,
      value: value,
      label: String(data.get("label") || ""),
      store_hash: Boolean(form.querySelector('[name="store_hash"]').checked),
      check_now: true,
    };
    if (!value) {
      status.textContent = "Enter a value first.";
      return;
    }
    status.textContent = "Checking…";
    try {
      const response = await fetch("/api/vault/entries", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "the dashboard rejected the entry");
      form.reset();
      status.textContent = body.created ? "Added." : "Already on the watchlist.";
      renderBreachResult(body.check);
    } catch (error) {
      status.textContent = String(error.message || error);
    }
  }

  async function runBreachCheck() {
    const button = $("#breach-run");
    const status = $("#breach-run-status");
    if (!button) return;
    button.disabled = true;
    status.textContent = "checking your watchlist…";
    try {
      const response = await fetch("/api/breach/check", { method: "POST" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.detail || "could not start the check");
      status.textContent = body.started ? "running…" : "already running";
      pollBreach();
    } catch (error) {
      status.textContent = String(error.message || error);
      button.disabled = false;
    }
  }

  async function pollBreach() {
    const status = $("#breach-run-status");
    const button = $("#breach-run");
    try {
      const response = await fetch("/api/breach");
      const body = await response.json();
      if (body.status === "running") {
        setTimeout(pollBreach, 1500);
        return;
      }
      if (status) {
        status.textContent = body.headline || "";
      }
      if (button) button.disabled = false;
      // A finished check changes the table's "last check" column.
      if (body.status === "done" || body.status === "error") {
        setTimeout(() => window.location.reload(), 900);
      }
    } catch (error) {
      if (button) button.disabled = false;
      if (status) status.textContent = String(error.message || error);
    }
  }

  function wireVault() {
    const form = $("#vault-form");
    if (form) form.addEventListener("submit", addToWatchlist);
    const run = $("#breach-run");
    if (run) run.addEventListener("click", runBreachCheck);
    document.querySelectorAll("[data-vault-delete]").forEach((button) => {
      button.addEventListener("click", async () => {
        const id = button.getAttribute("data-vault-delete");
        if (!window.confirm("Remove this identifier from the watchlist?")) return;
        await fetch("/api/vault/entries/" + encodeURIComponent(id), { method: "DELETE" });
        window.location.reload();
      });
    });
    const state = $("#breach-status");
    if (state && state.getAttribute("data-status") === "running") pollBreach();
  }

  async function loadAskSetup() {
    const box = $("#ask-setup");
    if (!box) return;
    try {
      const response = await fetch("/api/ask/setup");
      if (!response.ok) return;
      const setup = await response.json();
      if (setup.error) {
        box.textContent = setup.error;
        return;
      }
      const ready = (setup.backends || []).filter((b) => b.available).map((b) => b.name);
      const chosen = setup.selected
        ? setup.selected === "extractive"
          ? "no local model installed — answers come from the report itself"
          : "answering with " + setup.selected
        : "no backend available";
      const best = (setup.recommendations || [])[0];
      box.textContent =
        chosen +
        (ready.length ? " (ready: " + ready.join(", ") + ")" : "") +
        (best && setup.selected === "extractive"
          ? " · a " + best.name + " needs ~" + best.ram_mb + " MB of RAM and fits your " +
            setup.ram_budget_mb + " MB budget"
          : "");
    } catch (error) {
      /* a missing probe is not worth an error banner */
    }
  }

  function renderAnswer(payload) {
    const box = $("#ask-answer");
    box.hidden = false;
    box.textContent = "";
    const body = document.createElement("pre");
    body.className = "ask-text";
    body.textContent = payload.answer;
    box.appendChild(body);

    const meta = document.createElement("p");
    meta.className = "fineprint";
    const source = payload.session || {};
    const bits = [
      "answered by " + (source.model || payload.model || "?") +
        (source.is_model ? "" : " (retrieval, not generation)"),
      (payload.citations || []).length + " citation(s)",
      (source.context_items || 0) + " context line(s)",
      "raw values " + (source.values_included ? "included" : "masked"),
      "nothing written to disk",
    ];
    meta.textContent = bits.join(" · ");
    box.appendChild(meta);

    if (payload.citation_problem) {
      const warn = document.createElement("p");
      warn.className = "warn-text";
      warn.textContent = payload.citation_problem;
      box.appendChild(warn);
    }
  }

  async function askQuestion() {
    const input = $("#ask-question");
    const status = $("#ask-status");
    const question = (input.value || "").trim();
    if (!question) {
      status.textContent = "ask something first";
      return;
    }
    const button = $("#ask-submit");
    button.disabled = true;
    status.textContent = "thinking (a 1.5B model takes a few seconds on CPU)…";
    try {
      const response = await fetch("/api/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: question,
          include_values: !!$("#ask-include-values").checked,
        }),
      });
      if (!response.ok) {
        const detail = await response.json().catch(() => ({}));
        status.textContent = detail.detail || "the ask endpoint refused (" + response.status + ")";
        return;
      }
      const payload = await response.json();
      status.textContent = payload.elapsed_ms + " ms";
      renderAnswer(payload);
    } catch (error) {
      status.textContent = "the request failed: " + error;
    } finally {
      button.disabled = false;
    }
  }

  async function resetChat() {
    const box = $("#ask-answer");
    const status = $("#ask-status");
    await fetch("/api/ask/reset", { method: "POST" }).catch(() => {});
    box.hidden = true;
    box.textContent = "";
    status.textContent = "conversation forgotten";
  }

  function wireAsk() {
    const button = $("#ask-submit");
    if (!button) return;
    button.addEventListener("click", askQuestion);
    const reset = $("#ask-reset");
    if (reset) reset.addEventListener("click", resetChat);
    const input = $("#ask-question");
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        askQuestion();
      }
    });
    loadAskSetup();
  }

  function boot() {
    const form = $("#scan-form");
    if (form) form.addEventListener("submit", startScan);
    const calibrate = $("#calibrate-btn");
    if (calibrate) calibrate.addEventListener("click", runCalibration);
    wireDeletes();
    wireVault();
    wireAsk();
  }

  window.D3TA1L3R = {
    watchRun: watchRun,
    startScan: startScan,
    runCalibration: runCalibration,
    runBreachCheck: runBreachCheck,
    addToWatchlist: addToWatchlist,
    askQuestion: askQuestion,
    resetChat: resetChat,
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
