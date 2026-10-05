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

  function boot() {
    const form = $("#scan-form");
    if (form) form.addEventListener("submit", startScan);
    const calibrate = $("#calibrate-btn");
    if (calibrate) calibrate.addEventListener("click", runCalibration);
    wireDeletes();
  }

  window.D3TA1L3R = { watchRun: watchRun, startScan: startScan, runCalibration: runCalibration };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
