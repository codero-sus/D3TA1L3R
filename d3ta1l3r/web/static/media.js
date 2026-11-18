/* Media metadata panel.
 *
 * Every value rendered here comes from a file the user chose, which means it is
 * untrusted input. All of it goes through textContent / createElement — never
 * innerHTML — so a crafted tag value cannot execute as markup in the dashboard.
 */
(() => {
  "use strict";

  const fileInput = document.getElementById("media-file");
  const scrubInput = document.getElementById("media-scrub");
  const runButton = document.getElementById("media-run");
  const status = document.getElementById("media-status");
  const result = document.getElementById("media-result");
  const verdict = document.getElementById("media-verdict");
  const summary = document.getElementById("media-summary");
  const table = document.getElementById("media-exposure-table");
  const exposuresBody = document.getElementById("media-exposures");
  const actionsBox = document.getElementById("media-actions");
  const actionList = document.getElementById("media-action-list");
  const download = document.getElementById("media-download");
  const fieldsBox = document.getElementById("media-fields-box");
  const fieldsHost = document.getElementById("media-fields");
  const notesHost = document.getElementById("media-notes");

  if (!fileInput || !runButton) return;

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function bytesToBase64(bytes) {
    // String.fromCharCode(...bytes) blows the argument limit on big files, so
    // the conversion is chunked.
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function reset() {
    verdict.textContent = "Result";
    summary.textContent = "";
    exposuresBody.replaceChildren();
    actionList.replaceChildren();
    fieldsHost.replaceChildren();
    notesHost.replaceChildren();
    table.hidden = true;
    actionsBox.hidden = true;
    download.hidden = true;
    download.removeAttribute("href");
    result.hidden = true;
  }

  function renderReport(report) {
    result.hidden = false;
    verdict.textContent =
      `${report.name} — score ${report.score}/100`;
    const dimensions =
      report.width && report.height ? `${report.width} x ${report.height}` : "size unknown";
    summary.textContent =
      `${report.format_label} · ${report.size_bytes.toLocaleString()} bytes · ` +
      `${dimensions} · ${report.verdict}`;

    if (report.exposures.length) {
      table.hidden = false;
      for (const exposure of report.exposures) {
        const row = el("tr");
        const severityCell = el("td");
        const pill = el("span", exposure.severity.toUpperCase(), `sev sev-${exposure.severity}`);
        severityCell.append(pill);
        row.append(
          severityCell,
          el("td", exposure.label),
          el("td", exposure.value),
          el("td", exposure.reveals),
        );
        exposuresBody.append(row);
      }
      const actions = [...new Set(report.exposures.map((item) => item.action))];
      actionsBox.hidden = false;
      for (const action of actions) actionList.append(el("li", action));
    }

    if (report.fields.length) {
      fieldsBox.hidden = false;
      const groups = new Map();
      for (const field of report.fields) {
        if (!groups.has(field.group)) groups.set(field.group, []);
        groups.get(field.group).push(field);
      }
      for (const [group, items] of groups) {
        fieldsHost.append(el("h4", group));
        const list = el("ul");
        for (const item of items) {
          const li = el("li");
          li.append(el("b", item.label), document.createTextNode(` (${item.key}): ${item.value}`));
          list.append(li);
        }
        fieldsHost.append(list);
      }
    } else {
      fieldsBox.hidden = true;
    }

    for (const note of report.notes) {
      notesHost.append(el("p", note, "hint"));
    }
  }

  function renderScrub(scrub, report) {
    if (!scrub) return;
    if (!scrub.supported) {
      notesHost.append(el("p", `Cannot scrub this format: ${scrub.error}`, "hint"));
      return;
    }
    const blob = new Blob([Uint8Array.from(atob(scrub.data_base64), (c) => c.charCodeAt(0))]);
    const url = URL.createObjectURL(blob);
    const suffix = report.name.includes(".") ? report.name.slice(report.name.lastIndexOf(".")) : "";
    const stem = suffix ? report.name.slice(0, -suffix.length) : report.name;
    download.href = url;
    download.download = `${stem}.clean${suffix}`;
    download.hidden = false;
    download.textContent = `Download the cleaned file (residual score ${scrub.residual_score}/100)`;
    if (scrub.residual_score > 0) {
      notesHost.append(
        el("p", "Residual metadata remains — inspect the report before publishing.", "hint"),
      );
    }
  }

  async function run() {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      status.textContent = "choose a file first";
      return;
    }
    reset();
    status.textContent = `reading ${file.name} …`;
    runButton.disabled = true;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      status.textContent = "analysing …";
      const response = await fetch("/api/media", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: file.name,
          data_base64: bytesToBase64(bytes),
          scrub: scrubInput.checked,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || `HTTP ${response.status}`);
      }
      renderReport(payload.report);
      renderScrub(payload.scrub, payload.report);
      status.textContent = "";
    } catch (error) {
      status.textContent = `could not analyse: ${error.message}`;
    } finally {
      runButton.disabled = false;
    }
  }

  runButton.addEventListener("click", run);
  fileInput.addEventListener("change", reset);
})();
