(() => {
  "use strict";

  const STORAGE_KEY = "tracelens.web.vault.v1";
  const DNS_TYPES = [
    { name: "A", code: 1 },
    { name: "AAAA", code: 28 },
    { name: "CNAME", code: 5 },
    { name: "MX", code: 15 },
    { name: "NS", code: 2 },
    { name: "TXT", code: 16 },
    { name: "CAA", code: 257 },
    { name: "SOA", code: 6 }
  ];
  const TYPE_NAMES = Object.fromEntries(DNS_TYPES.map((item) => [item.code, item.name]));
  const RESOLVERS = [
    { name: "Cloudflare DNS-over-HTTPS", endpoint: "https://cloudflare-dns.com/dns-query" },
    { name: "Google Public DNS", endpoint: "https://dns.google/resolve" }
  ];
  const MAX_RUNS = 80;
  const MAX_NOTES = 500;

  const $ = (selector, root = document) => root.querySelector(selector);
  const state = {
    runs: [],
    notes: [],
    currentRunId: null,
    busy: false,
    toastTimer: null
  };

  function readVault() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.schema !== 1 || !Array.isArray(parsed.runs) || !Array.isArray(parsed.notes)) {
        throw new Error("Unsupported local vault format.");
      }
      state.runs = parsed.runs.slice(0, MAX_RUNS).filter((run) =>
        run && typeof run.id === "string" && typeof run.domain === "string" &&
        Array.isArray(run.records) && typeof run.queriedAt === "string" &&
        run.records.every((record) => record && typeof record.type === "string" &&
          typeof record.name === "string" && typeof record.value === "string")
      );
      state.notes = parsed.notes.slice(0, MAX_NOTES).filter((note) =>
        note && typeof note.id === "string" && typeof note.domain === "string" &&
        typeof note.text === "string" && typeof note.source === "string" &&
        typeof note.createdAt === "string" && ["unverified", "low", "medium", "high"].includes(note.confidence)
      );
    } catch (error) {
      state.runs = [];
      state.notes = [];
      showToast("The saved vault could not be read. Existing browser data was left untouched.");
      console.warn("TraceLens vault read error:", error);
    }
  }

  function persistVault() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        schema: 1,
        product: "TraceLens Web",
        savedAt: new Date().toISOString(),
        runs: state.runs.slice(0, MAX_RUNS),
        notes: state.notes.slice(0, MAX_NOTES)
      }));
      return true;
    } catch (error) {
      console.error("TraceLens vault write error:", error);
      showToast("Could not save locally. Browser storage may be full or disabled.");
      return false;
    }
  }

  function normalizeDomain(input) {
    const raw = String(input || "").trim();
    if (!raw) throw new Error("Enter a domain name first.");

    let hostname;
    try {
      if (/^https?:\/\//i.test(raw)) {
        const parsed = new URL(raw);
        if (parsed.username || parsed.password) throw new Error("Credentials are not accepted in a target URL.");
        hostname = parsed.hostname;
      } else {
        if (/[\s/@?#]/.test(raw)) throw new Error("Enter a domain name, not a path or search string.");
        const parsed = new URL("https://" + raw);
        if (parsed.port || parsed.username || parsed.password || parsed.pathname !== "/") {
          throw new Error("Enter only a domain name without a port or path.");
        }
        hostname = parsed.hostname;
      }
    } catch (error) {
      if (error instanceof Error && error.message && !/Invalid URL/i.test(error.message)) throw error;
      throw new Error("That does not look like a valid domain or HTTP(S) URL.");
    }

    hostname = hostname.toLowerCase().replace(/\.$/, "");
    if (!hostname || hostname.length > 253 || hostname.includes(":") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
      throw new Error("Enter a fully qualified domain name, not an IP address.");
    }
    const labels = hostname.split(".");
    if (labels.length < 2 || labels.some((label) =>
      !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    )) {
      throw new Error("Use a valid fully qualified domain, such as example.com.");
    }
    return hostname;
  }

  function setLookupStatus(message, kind = "") {
    const element = $("#lookupStatus");
    element.textContent = message;
    element.className = kind;
  }

  function showToast(message) {
    const toast = $("#toast");
    if (!toast) return;
    toast.textContent = message;
    toast.classList.add("show");
    if (state.toastTimer) window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => toast.classList.remove("show"), 3200);
  }

  function friendlyDnsStatus(status) {
    const labels = {
      0: "NOERROR",
      1: "FORMERR",
      2: "SERVFAIL",
      3: "NXDOMAIN",
      4: "NOTIMP",
      5: "REFUSED"
    };
    return labels[status] || ("RCODE " + status);
  }

  async function requestDns(resolver, domain, type) {
    const url = new URL(resolver.endpoint);
    url.searchParams.set("name", domain);
    url.searchParams.set("type", type.name);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 7000);
    try {
      const response = await fetch(url.toString(), {
        method: "GET",
        headers: { Accept: "application/dns-json" },
        cache: "no-store",
        signal: controller.signal
      });
      if (!response.ok) throw new Error(resolver.name + " returned HTTP " + response.status);
      const payload = await response.json();
      if (!Number.isInteger(payload.Status)) throw new Error("The DNS resolver returned an unreadable response.");
      return {
        resolver: resolver.name,
        status: payload.Status,
        answers: Array.isArray(payload.Answer) ? payload.Answer : []
      };
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function queryWithFallback(domain, type) {
    let lastError = "No DNS resolver responded.";
    for (const resolver of RESOLVERS) {
      try {
        const result = await requestDns(resolver, domain, type);
        if (result.status !== 0 && result.status !== 3) {
          lastError = resolver.name + " returned " + friendlyDnsStatus(result.status) + ".";
          continue;
        }
        return { ...result, requestedType: type.name, error: null };
      } catch (error) {
        lastError = error && error.name === "AbortError"
          ? resolver.name + " timed out."
          : (error && error.message ? error.message : "DNS request failed.");
      }
    }
    return { requestedType: type.name, resolver: "Unavailable", status: null, answers: [], error: lastError };
  }

  function normalizeAnswer(answer) {
    const type = TYPE_NAMES[answer.type] || ("TYPE" + String(answer.type || ""));
    return {
      type,
      name: String(answer.name || ""),
      value: String(answer.data || ""),
      ttl: Number.isFinite(Number(answer.TTL)) ? Number(answer.TTL) : null
    };
  }

  function uniqueRecords(records) {
    const seen = new Set();
    return records.filter((record) => {
      const key = [record.type, record.name, record.value].join("|");
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  async function performLookup(domain) {
    const results = await Promise.all(DNS_TYPES.map((type) => queryWithFallback(domain, type)));
    const failed = results.filter((result) => result.error);
    const resolverNames = [...new Set(results.filter((result) => !result.error).map((result) => result.resolver))];
    if (failed.length === DNS_TYPES.length) {
      throw new Error("Neither public DNS resolver could be reached. Check your connection and try again.");
    }

    const records = uniqueRecords(results.flatMap((result) =>
      result.answers.map(normalizeAnswer).filter((answer) => answer.value)
    ));
    const id = window.crypto && window.crypto.randomUUID
      ? window.crypto.randomUUID()
      : String(Date.now()) + "-" + Math.random().toString(36).slice(2, 10);
    const run = {
      id,
      domain,
      queriedAt: new Date().toISOString(),
      resolver: resolverNames.join(" + ") || "Public DNS-over-HTTPS",
      records,
      querySummary: results.map((result) => ({
        type: result.requestedType,
        status: result.status,
        resolver: result.resolver,
        error: result.error
      }))
    };
    state.runs.unshift(run);
    state.runs = state.runs.slice(0, MAX_RUNS);
    state.currentRunId = run.id;
    return { run, failed };
  }

  function currentRun() {
    return state.runs.find((run) => run.id === state.currentRunId) || null;
  }

  function currentDomain() {
    const run = currentRun();
    if (run) return run.domain;
    try { return normalizeDomain($("#domainInput").value); } catch (_) { return ""; }
  }

  function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "UNKNOWN TIME";
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", timeZoneName: "short"
    }).format(date);
  }

  function addCell(row, value, className) {
    const cell = document.createElement("td");
    cell.textContent = value;
    if (className) cell.className = className;
    row.appendChild(cell);
  }

  function renderRecordRows(run) {
    const body = $("#recordRows");
    body.replaceChildren();
    const records = run ? run.records : [];
    if (!records.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 4;
      cell.className = "empty-cell";
      cell.textContent = run
        ? "No answer records were returned in this snapshot."
        : "No observations yet. Inspect a domain to populate this view.";
      row.appendChild(cell);
      body.appendChild(row);
    } else {
      records.forEach((record) => {
        const row = document.createElement("tr");
        addCell(row, record.type);
        addCell(row, record.value);
        addCell(row, record.ttl === null ? "—" : String(record.ttl));
        addCell(row, record.name);
        body.appendChild(row);
      });
    }
    $("#recordCount").textContent = records.length + " RECORD" + (records.length === 1 ? "" : "S");
  }

  function getPreviousRun(run) {
    if (!run) return null;
    return state.runs
      .filter((item) => item.domain === run.domain && item.queriedAt < run.queriedAt)
      .sort((a, b) => b.queriedAt.localeCompare(a.queriedAt))[0] || null;
  }

  function recordKeys(run) {
    return new Set((run ? run.records : []).map((record) =>
      [record.type, record.name, record.value].join("|")
    ));
  }

  function renderDelta(run) {
    const previous = getPreviousRun(run);
    if (!run || !previous) {
      $("#addedCount").textContent = "—";
      $("#removedCount").textContent = "—";
      $("#deltaNote").textContent = "Run another lookup for this domain to compare snapshots.";
      return;
    }
    const currentKeys = recordKeys(run);
    const previousKeys = recordKeys(previous);
    let added = 0;
    let removed = 0;
    currentKeys.forEach((key) => { if (!previousKeys.has(key)) added += 1; });
    previousKeys.forEach((key) => { if (!currentKeys.has(key)) removed += 1; });
    $("#addedCount").textContent = String(added);
    $("#removedCount").textContent = String(removed);
    $("#deltaNote").textContent = "Compared with " + formatDate(previous.queriedAt) + ". Changes are differences in returned answers, not proof of an underlying configuration event.";
  }

  function renderMetrics(run) {
    const domain = run ? run.domain : currentDomain();
    const notes = domain ? state.notes.filter((note) => note.domain === domain).length : 0;
    const domainRuns = domain ? state.runs.filter((item) => item.domain === domain).length : 0;
    $("#currentTarget").textContent = domain ? domain.toUpperCase() : "NO TARGET LOADED";
    $("#graphTarget").textContent = domain ? domain.toUpperCase() : "NO TARGET LOADED";
    $("#evidenceTarget").textContent = domain ? domain.toUpperCase() : "NO TARGET LOADED";
    $("#metricRecords").textContent = run ? String(run.records.length) : "—";
    $("#metricTypes").textContent = run ? String(new Set(run.records.map((record) => record.type)).size) : "—";
    $("#metricRuns").textContent = String(domainRuns);
    $("#metricNotes").textContent = String(notes);
    $("#snapshotTime").textContent = run ? formatDate(run.queriedAt).toUpperCase() : "AWAITING LOOKUP";
  }

  function svgElement(name, attributes = {}) {
    const node = document.createElementNS("http://www.w3.org/2000/svg", name);
    Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, String(value)));
    return node;
  }

  function addSvgText(svg, x, y, text, className, anchor = "middle") {
    const node = svgElement("text", { x, y, "text-anchor": anchor, class: className });
    node.textContent = text;
    svg.appendChild(node);
  }

  function truncate(value, max) {
    const text = String(value);
    return text.length > max ? text.slice(0, max - 1) + "…" : text;
  }

  function renderGraph(run) {
    const svg = $("#relationshipGraph");
    svg.replaceChildren();
    if (!run) {
      addSvgText(svg, 450, 190, "INSPECT A DOMAIN TO BUILD THE MAP", "graph-group-label");
      $("#graphCaption").textContent = "No DNS snapshot is loaded.";
      return;
    }

    const records = run.records.slice(0, 12);
    if (!records.length) {
      addSvgText(svg, 450, 190, "NO DNS ANSWERS IN THIS SNAPSHOT", "graph-group-label");
      $("#graphCaption").textContent = "The selected lookup returned no answer records.";
      return;
    }

    const centerX = 450;
    const centerY = 190;
    records.forEach((record, index) => {
      const leftSide = index % 2 === 0;
      const column = Math.floor(index / 2);
      const x = leftSide ? 170 : 730;
      const y = 63 + column * 53;
      const line = svgElement("line", {
        x1: centerX + (leftSide ? -54 : 54),
        y1: centerY,
        x2: x,
        y2: y,
        class: "graph-edge"
      });
      svg.appendChild(line);
    });

    svg.appendChild(svgElement("circle", { cx: centerX, cy: centerY, r: 54, class: "graph-domain" }));
    addSvgText(svg, centerX, centerY - 3, truncate(run.domain, 22), "graph-root-label");
    addSvgText(svg, centerX, centerY + 15, "TARGET DOMAIN", "graph-sublabel");

    records.forEach((record, index) => {
      const leftSide = index % 2 === 0;
      const column = Math.floor(index / 2);
      const x = leftSide ? 170 : 730;
      const y = 63 + column * 53;
      svg.appendChild(svgElement("circle", { cx: x, cy: y, r: 5, class: "graph-record" }));
      const textX = leftSide ? x - 13 : x + 13;
      const anchor = leftSide ? "end" : "start";
      addSvgText(svg, textX, y - 8, record.type, "graph-sublabel", anchor);
      addSvgText(svg, textX, y + 11, truncate(record.value, 35), "graph-label", anchor);
    });

    addSvgText(svg, 170, 24, "OBSERVED ANSWERS", "graph-group-label");
    addSvgText(svg, 730, 24, "OBSERVED ANSWERS", "graph-group-label");
    $("#graphCaption").textContent = "Showing " + records.length + " returned records from " + formatDate(run.queriedAt) +
      (run.records.length > records.length ? ". " + (run.records.length - records.length) + " additional records are available in the observations table." : ".") +
      " Lines indicate DNS answer membership only.";
  }

  function renderNotes() {
    const list = $("#noteList");
    const domain = currentDomain();
    const notes = domain ? state.notes.filter((note) => note.domain === domain) : state.notes;
    list.replaceChildren();
    $("#noteTotal").textContent = notes.length + " NOTE" + (notes.length === 1 ? "" : "S");
    if (!notes.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = domain ? "No notes saved for this domain yet." : "Enter a domain and save a sourced note to begin.";
      list.appendChild(empty);
      return;
    }

    notes.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt)).forEach((note) => {
      const card = document.createElement("article");
      card.className = "note-item";
      const top = document.createElement("div");
      top.className = "note-item-top";
      const category = document.createElement("span");
      category.className = "note-category";
      category.textContent = note.category;
      const confidence = document.createElement("span");
      confidence.className = "confidence";
      confidence.textContent = note.confidence;
      top.append(category, confidence);
      const text = document.createElement("p");
      text.className = "note-body";
      text.textContent = note.text;
      let source;
      try {
        const safeSource = validateSourceUrl(note.source);
        source = document.createElement("a");
        source.href = safeSource;
        source.target = "_blank";
        source.rel = "noopener noreferrer";
        source.textContent = safeSource;
      } catch (_) {
        source = document.createElement("span");
        source.textContent = "Unsafe or invalid source URL (not linked)";
      }
      source.className = "note-source";
      const date = document.createElement("div");
      date.className = "note-date";
      date.textContent = note.domain + " · " + formatDate(note.createdAt);
      card.append(top, text, source, date);
      list.appendChild(card);
    });
  }

  function renderHistory() {
    const list = $("#historyList");
    list.replaceChildren();
    $("#historyTotal").textContent = state.runs.length + " SNAPSHOT" + (state.runs.length === 1 ? "" : "S");
    if (!state.runs.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";
      empty.textContent = "Your saved DNS snapshots will appear here after the first lookup.";
      list.appendChild(empty);
      return;
    }

    state.runs.slice().sort((a, b) => b.queriedAt.localeCompare(a.queriedAt)).forEach((run) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "history-item";
      button.dataset.runId = run.id;
      const description = document.createElement("span");
      const domain = document.createElement("span");
      domain.className = "history-domain";
      domain.textContent = run.domain;
      const date = document.createElement("span");
      date.className = "history-date";
      date.textContent = formatDate(run.queriedAt);
      description.append(domain, date);
      const count = document.createElement("span");
      count.className = "history-count";
      count.textContent = run.records.length + " RECORDS";
      const resolver = document.createElement("span");
      resolver.className = "history-resolver";
      resolver.textContent = run.resolver;
      button.append(description, count, resolver);
      button.addEventListener("click", () => {
        state.currentRunId = run.id;
        $("#domainInput").value = run.domain;
        $("#noteDomain").value = run.domain;
        renderAll();
        setView("overviewView");
        showToast("Loaded saved snapshot for " + run.domain + ".");
      });
      list.appendChild(button);
    });
  }

  function renderAll() {
    const run = currentRun();
    renderMetrics(run);
    renderRecordRows(run);
    renderDelta(run);
    renderGraph(run);
    renderNotes();
    renderHistory();
  }

  function setView(viewId) {
    document.querySelectorAll(".view").forEach((view) => {
      const active = view.id === viewId;
      view.hidden = !active;
      view.classList.toggle("active", active);
    });
    document.querySelectorAll("[data-view]").forEach((button) => {
      button.classList.toggle("active", button.dataset.view === viewId);
    });
  }

  function downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportVault() {
    const payload = {
      product: "TraceLens Web",
      schema: 1,
      exportedAt: new Date().toISOString(),
      storage: "browser-local",
      runs: state.runs,
      notes: state.notes
    };
    downloadFile("tracelens-evidence-vault.json", JSON.stringify(payload, null, 2), "application/json");
    showToast("Exported the local evidence vault as JSON.");
  }

  function exportReport() {
    const run = currentRun();
    if (!run) {
      showToast("Inspect a domain before exporting a report.");
      return;
    }
    const notes = state.notes.filter((note) => note.domain === run.domain);
    const lines = [
      "# TraceLens domain report: " + run.domain,
      "",
      "- Generated: " + new Date().toISOString(),
      "- Snapshot time: " + run.queriedAt,
      "- Resolver: " + run.resolver,
      "- Record count: " + run.records.length,
      "",
      "> Scope: Passive DNS answers and user-supplied notes. These are observations, not proof of ownership, affiliation, location, vulnerability, or security posture.",
      "",
      "## DNS observations",
      ""
    ];
    if (!run.records.length) lines.push("No answer records were returned in this snapshot.", "");
    run.records.forEach((record) => {
      lines.push(
        "- **" + record.type + "**: `" + record.value.replace(/\`/g, "'") + "`",
        "  - Name: " + record.name,
        "  - TTL: " + (record.ttl === null ? "unknown" : record.ttl),
        ""
      );
    });
    lines.push("## Sourced notes", "");
    if (!notes.length) lines.push("No manual notes saved for this domain.", "");
    notes.forEach((note) => {
      lines.push(
        "### " + note.category,
        "",
        note.text,
        "",
        "- Source: " + note.source,
        "- Confidence: " + note.confidence,
        "- Recorded: " + note.createdAt,
        ""
      );
    });
    lines.push("## Interpretation limits", "", "- DNS data varies by resolver and time.", "- Missing answers do not prove non-existence.", "- Notes are user-entered and are not independently verified.", "");
    downloadFile("tracelens-" + run.domain.replace(/[^a-z0-9.-]/g, "_") + "-report.md", lines.join("\n"), "text/markdown;charset=utf-8");
    showToast("Generated a Markdown report for " + run.domain + ".");
  }

  async function handleLookup(event) {
    event.preventDefault();
    if (state.busy) return;
    let domain;
    try {
      domain = normalizeDomain($("#domainInput").value);
    } catch (error) {
      setLookupStatus(error.message, "error");
      showToast(error.message);
      return;
    }

    state.busy = true;
    const button = $("#scanButton");
    button.disabled = true;
    button.textContent = "Collecting DNS…";
    setLookupStatus("Querying a fixed set of public DNS record types…");
    try {
      const { run, failed } = await performLookup(domain);
      const saved = persistVault();
      $("#domainInput").value = domain;
      $("#noteDomain").value = domain;
      renderAll();
      setView("overviewView");
      if (failed.length) {
        setLookupStatus(run.records.length + " records returned; " + failed.length + " query types could not be checked.", "success");
        showToast("Partial snapshot saved. Some DNS record queries failed.");
      } else {
        setLookupStatus(run.records.length + " records returned · resolver: " + run.resolver, "success");
        showToast(saved ? "Snapshot saved to this browser's local vault." : "Lookup completed, but local storage could not save the snapshot.");
      }
    } catch (error) {
      console.error("TraceLens lookup error:", error);
      setLookupStatus(error.message || "Lookup failed. Check the connection and try again.", "error");
      showToast(error.message || "Lookup failed.");
    } finally {
      state.busy = false;
      button.disabled = false;
      button.innerHTML = '<span class="scan-glyph">↗</span> Inspect domain';
    }
  }

  function validateSourceUrl(value) {
    let parsed;
    try { parsed = new URL(value); } catch (_) { throw new Error("Enter a complete source URL."); }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("Source links must use HTTP or HTTPS.");
    }
    if (!parsed.hostname) throw new Error("The source URL needs a hostname.");
    return parsed.toString();
  }

  function handleNote(event) {
    event.preventDefault();
    let domain;
    let source;
    try {
      domain = normalizeDomain($("#noteDomain").value);
      source = validateSourceUrl($("#noteSource").value.trim());
    } catch (error) {
      showToast(error.message);
      return;
    }

    const text = $("#noteText").value.trim();
    if (!text) {
      showToast("Write the observation before saving.");
      return;
    }
    const note = {
      id: window.crypto && window.crypto.randomUUID ? window.crypto.randomUUID() : String(Date.now()),
      domain,
      category: $("#noteCategory").value,
      text,
      source,
      confidence: $("#noteConfidence").value,
      createdAt: new Date().toISOString()
    };
    state.notes.unshift(note);
    state.notes = state.notes.slice(0, MAX_NOTES);
    const saved = persistVault();
    $("#domainInput").value = domain;
    state.currentRunId = state.runs.find((run) => run.domain === domain)?.id || null;
    $("#noteForm").reset();
    $("#noteDomain").value = domain;
    renderAll();
    showToast(saved ? "Sourced note saved locally." : "Note added to this session, but browser storage could not save it.");
  }

  function clearVault() {
    if (!state.runs.length && !state.notes.length) {
      showToast("The local vault is already empty.");
      return;
    }
    const confirmed = window.confirm("Clear all TraceLens snapshots and notes stored in this browser? This cannot be undone.");
    if (!confirmed) return;
    state.runs = [];
    state.notes = [];
    state.currentRunId = null;
    try { localStorage.removeItem(STORAGE_KEY); } catch (error) { console.error(error); }
    $("#domainInput").value = "";
    $("#noteDomain").value = "";
    renderAll();
    setLookupStatus("Local vault cleared.");
    showToast("All TraceLens browser-local evidence was cleared.");
  }

  function initialize() {
    readVault();
    $("#lookupForm").addEventListener("submit", handleLookup);
    $("#noteForm").addEventListener("submit", handleNote);
    $("#exportJson").addEventListener("click", exportVault);
    $("#exportReport").addEventListener("click", exportReport);
    $("#clearVault").addEventListener("click", clearVault);
    document.querySelectorAll("[data-view]").forEach((button) => {
      button.addEventListener("click", () => setView(button.dataset.view));
    });
    const latest = state.runs.slice().sort((a, b) => b.queriedAt.localeCompare(a.queriedAt))[0];
    if (latest) {
      state.currentRunId = latest.id;
      $("#domainInput").value = latest.domain;
      $("#noteDomain").value = latest.domain;
    }
    renderAll();
    setView("overviewView");
  }

  document.addEventListener("DOMContentLoaded", () => {
    const connect = document.getElementById("vxnConnect");
    const toggle = document.getElementById("vxnConnectToggle");
    if (connect && toggle) {
      toggle.addEventListener("click", () => {
        const opened = connect.classList.toggle("open");
        toggle.setAttribute("aria-expanded", String(opened));
      });
      document.addEventListener("click", (event) => {
        if (!connect.contains(event.target)) {
          connect.classList.remove("open");
          toggle.setAttribute("aria-expanded", "false");
        }
      });
    }
  });

  document.addEventListener("DOMContentLoaded", initialize);
})();
