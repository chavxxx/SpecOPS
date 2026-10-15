/**
 * WISPnet IP Reputation & Blacklist Intelligence Platform
 * Frontend Controller for Overview, Single Lookup, Bulk Scanner, Inventory, History, and Providers
 */

let currentIntelSubTab = "overview";
let activeScanPollInterval = null;

// Helper: Format UTC ISO timestamp to Asia/Manila (UTC+8) and UTC display
function formatManilaTime(isoStr) {
  if (!isoStr) return "—";
  try {
    const d = new Date(isoStr);
    const manilaStr = d.toLocaleString("en-PH", {
      timeZone: "Asia/Manila",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    });
    return `${manilaStr} PHT`;
  } catch (e) {
    return isoStr;
  }
}

function showIntelToast(msg, isError = false) {
  const toast = document.createElement("div");
  toast.className = `fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg text-white text-xs font-semibold shadow-xl flex items-center gap-2 animate-bounce ${
    isError ? "bg-rose-600 shadow-rose-900/40" : "bg-emerald-600 shadow-emerald-900/40"
  }`;
  toast.innerHTML = `<i data-lucide="${isError ? 'alert-circle' : 'check'}" class="w-4 h-4"></i> <span>${msg}</span>`;
  document.body.appendChild(toast);
  if (window.lucide) lucide.createIcons();
  setTimeout(() => toast.remove(), 3000);
}

// ---------------------------------------------------------------------------
// SUB-TAB NAVIGATION
// ---------------------------------------------------------------------------
function switchIntelSubTab(subTabId) {
  currentIntelSubTab = subTabId;
  document.querySelectorAll(".intel-subtab-btn").forEach(btn => {
    if (btn.getAttribute("data-subtab") === subTabId) {
      btn.className = "intel-subtab-btn px-3 py-1.5 rounded-lg text-xs font-bold transition-all bg-brand-600 text-white shadow-md shadow-brand-600/30";
    } else {
      btn.className = "intel-subtab-btn px-3 py-1.5 rounded-lg text-xs font-semibold transition-all bg-dark-800 text-slate-300 hover:bg-dark-750 hover:text-white border border-slate-700/60";
    }
  });

  document.querySelectorAll(".intel-subtab-view").forEach(view => {
    if (view.id === `intel-view-${subTabId}`) {
      view.classList.remove("hidden");
    } else {
      view.classList.add("hidden");
    }
  });

  if (window.lucide) lucide.createIcons();

  if (subTabId === "overview") {
    loadIPIntelOverview();
  } else if (subTabId === "inventory") {
    loadIPIntelInventory();
  } else if (subTabId === "providers") {
    loadIPIntelProviders();
  } else if (subTabId === "history") {
    loadIPIntelHistory();
  } else if (subTabId === "investigations") {
    loadIPIntelInvestigations();
  }
}

// ---------------------------------------------------------------------------
// 1. OVERVIEW DASHBOARD
// ---------------------------------------------------------------------------
async function loadIPIntelOverview(timeWindow = "24h") {
  const container = document.getElementById("intel-overview-kpis");
  if (!container) return;

  try {
    const res = await fetch(`/api/ip-intelligence/overview?time_window=${timeWindow}`, {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    document.getElementById("kpi-intel-monitored").innerText = data.total_monitored_ips || 0;
    document.getElementById("kpi-intel-listed").innerText = data.total_listed_ips || 0;
    document.getElementById("kpi-intel-abuse").innerText = data.total_recent_abuse_ips || 0;
    document.getElementById("kpi-intel-deteriorating").innerText = data.total_deteriorating_ips || 0;
    document.getElementById("kpi-intel-new-24h").innerText = `+${data.new_listings_24h || 0}`;
    document.getElementById("kpi-intel-resolved-24h").innerText = `-${data.resolved_listings_24h || 0}`;
    document.getElementById("kpi-intel-review").innerText = data.ips_requiring_review || 0;
    document.getElementById("kpi-intel-failed-checks").innerText = data.failed_provider_checks || 0;

    const lastScanEl = document.getElementById("intel-last-scan-time");
    if (lastScanEl) {
      lastScanEl.innerText = data.last_successful_scan_at ? formatManilaTime(data.last_successful_scan_at) : "No recent scan";
    }

    // Render provider health summary
    const provContainer = document.getElementById("intel-overview-providers-list");
    if (provContainer && data.provider_summary) {
      provContainer.innerHTML = data.provider_summary.map(p => `
        <div class="p-3 rounded-lg bg-dark-800/80 border border-slate-700/60 flex items-center justify-between">
          <div class="flex items-center gap-2">
            <span class="w-2.5 h-2.5 rounded-full ${p.enabled ? (p.last_error ? 'bg-amber-400 animate-pulse' : 'bg-emerald-400') : 'bg-slate-500'}"></span>
            <div>
              <div class="text-xs font-bold text-white">${p.provider_name}</div>
              <div class="text-[10px] text-slate-400 uppercase tracking-wider">${p.provider_type}</div>
            </div>
          </div>
          <div class="text-right">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${p.enabled ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-slate-700 text-slate-400'}">
              ${p.enabled ? (p.last_error ? 'Degraded' : 'Active') : 'Disabled'}
            </span>
            ${p.quota_remaining !== null && p.quota_remaining !== undefined ? `
              <div class="text-[10px] text-slate-400 mt-1">Quota: <strong class="text-slate-200">${p.quota_remaining}</strong> rem</div>
            ` : ''}
          </div>
        </div>
      `).join("");
    }
  } catch (e) {
    console.error("Failed to load IP Intel overview:", e);
  }
}

// ---------------------------------------------------------------------------
// 2. SINGLE IP LOOKUP
// ---------------------------------------------------------------------------
async function executeSingleLookup() {
  const ipInput = document.getElementById("input-intel-ip");
  const depthInput = document.getElementById("select-intel-depth");
  const portInput = document.getElementById("input-intel-port");
  const timeInput = document.getElementById("input-intel-timestamp");
  const resultCard = document.getElementById("intel-lookup-result");
  const btn = document.getElementById("btn-intel-check");

  if (!ipInput || !ipInput.value.trim()) {
    showIntelToast("Please enter a valid IPv4 or IPv6 address", true);
    return;
  }

  const ip = ipInput.value.trim();
  const depth = depthInput ? depthInput.value : "standard";
  const port = portInput && portInput.value ? parseInt(portInput.value) : null;
  const ts = timeInput && timeInput.value.trim() ? timeInput.value.trim() : null;

  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i> Checking...`;
  if (window.lucide) lucide.createIcons();

  try {
    const res = await fetch("/api/ip-intelligence/check", {
      method: "POST",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        ip_address: ip,
        depth: depth,
        event_port: port,
        event_timestamp: ts,
        include_historical_cgnat: true,
        include_suricata: true,
        include_akvorado: true
      })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderSingleLookupResult(data);
    resultCard.classList.remove("hidden");
    resultCard.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    showIntelToast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="search" class="w-4 h-4"></i> Check IP Reputation`;
    if (window.lucide) lucide.createIcons();
  }
}

function renderSingleLookupResult(data) {
  // 1. Overall Status & Score Header
  const statusBadge = document.getElementById("intel-res-status-badge");
  const scoreVal = document.getElementById("intel-res-score");
  const ipDisp = document.getElementById("intel-res-ip");
  const timeDisp = document.getElementById("intel-res-timestamp");
  const explanationDisp = document.getElementById("intel-res-explanation");

  if (ipDisp) ipDisp.innerText = data.ip_address;
  if (timeDisp) timeDisp.innerText = formatManilaTime(data.check_timestamp);
  if (explanationDisp) explanationDisp.innerText = data.explanation;
  if (scoreVal) scoreVal.innerText = `${data.overall_score}/100`;

  const statusColors = {
    CLEAN: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    LISTED: "bg-rose-500/20 text-rose-300 border-rose-500/30 animate-pulse",
    SUSPICIOUS: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    HIGH_RISK: "bg-red-600/30 text-red-300 border-red-500/40 animate-pulse",
    UNKNOWN: "bg-slate-700 text-slate-300 border-slate-600",
    INCOMPLETE: "bg-yellow-500/20 text-yellow-300 border-yellow-500/30"
  };

  if (statusBadge) {
    statusBadge.className = `px-3 py-1 rounded-full text-xs font-black uppercase tracking-wider border ${statusColors[data.overall_status] || statusColors.UNKNOWN}`;
    statusBadge.innerText = data.overall_status;
  }

  // 2. Score Factors Breakdown
  const factorsContainer = document.getElementById("intel-res-score-factors");
  if (factorsContainer) {
    if (data.score_factors && data.score_factors.length > 0) {
      factorsContainer.innerHTML = data.score_factors.map(f => `
        <div class="flex items-center justify-between text-xs p-2 rounded bg-dark-750 border border-slate-700/50">
          <div>
            <span class="font-bold text-slate-200">${f.factor}</span>
            <div class="text-[10px] text-slate-400">${f.evidence}</div>
          </div>
          <span class="font-mono font-bold text-rose-400">+${f.weight}</span>
        </div>
      `).join("");
    } else {
      factorsContainer.innerHTML = `<div class="text-xs text-slate-400 italic">No adverse risk factors identified.</div>`;
    }
  }

  // 3. Provider Results Table
  const tableBody = document.getElementById("intel-res-providers-tbody");
  if (tableBody) {
    tableBody.innerHTML = data.provider_results.map(r => `
      <tr class="border-b border-slate-800/80 hover:bg-dark-750/50 transition-colors">
        <td class="py-2.5 px-3">
          <div class="font-bold text-white text-xs">${r.provider_name}</div>
          <div class="text-[10px] text-slate-400 uppercase tracking-wider">${r.provider_type}</div>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
            r.is_listed ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
            (r.lookup_status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
            (r.lookup_status === 'unsupported' ? 'bg-slate-700 text-slate-400' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'))
          }">
            ${r.is_listed ? 'LISTED' : (r.lookup_status === 'completed' ? 'Clean' : r.lookup_status.toUpperCase())}
          </span>
        </td>
        <td class="py-2.5 px-3">
          <div class="text-xs text-slate-300">${r.source_classification || '—'}</div>
          <div class="text-[11px] text-slate-400 mt-0.5">${r.evidence_summary || ''}</div>
        </td>
        <td class="py-2.5 px-3 text-right text-xs font-mono text-slate-400">
          ${r.duration_ms}ms
        </td>
        <td class="py-2.5 px-3 text-right">
          ${r.documentation_url ? `
            <a href="${r.documentation_url}" target="_blank" rel="noopener noreferrer" class="text-brand-400 hover:text-brand-300 text-xs font-medium inline-flex items-center gap-1">
              Docs <i data-lucide="external-link" class="w-3 h-3"></i>
            </a>
          ` : '—'}
        </td>
      </tr>
    `).join("");
  }

  // 4. CGNAT Correlation Card
  const cgnatContainer = document.getElementById("intel-res-cgnat-brief");
  if (cgnatContainer) {
    if (data.cgnat_correlation && data.cgnat_correlation.is_cgnat_public_pool) {
      const c = data.cgnat_correlation;
      cgnatContainer.innerHTML = `
        <div class="p-4 rounded-xl ${c.exact_match ? 'bg-brand-950/40 border border-brand-500/30' : 'bg-dark-800 border border-slate-700/80'}">
          <div class="flex items-center justify-between mb-2">
            <span class="text-xs font-bold uppercase tracking-wider text-slate-400">CGNAT Correlation Analysis</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-black uppercase ${
              c.attribution_status === 'verified' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
              (c.attribution_status === 'high_confidence' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30')
            }">
              ${c.attribution_status}
            </span>
          </div>
          <div class="text-xs text-slate-200 mb-3">${c.explanation}</div>
          ${c.exact_match ? `
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3 rounded-lg bg-dark-900/60 border border-slate-700/60">
              <div>
                <span class="text-[10px] text-slate-400 uppercase font-semibold">Subscriber CGNAT IP</span>
                <div class="flex items-center gap-1 mt-0.5">
                  <span class="font-mono font-bold text-white text-xs">${c.subscriber_cgnat_ip}</span>
                  <button onclick="copyToClipboard('${c.subscriber_cgnat_ip}', 'Subscriber IP')" class="p-1 hover:text-white text-slate-400">
                    <i data-lucide="copy" class="w-3 h-3"></i>
                  </button>
                </div>
              </div>
              <div>
                <span class="text-[10px] text-slate-400 uppercase font-semibold">PPPoE Username</span>
                <div class="flex items-center gap-1 mt-0.5">
                  <span class="font-mono font-bold text-indigo-300 text-xs">${c.pppoe_username || 'Unrecorded'}</span>
                  ${c.pppoe_username ? `
                    <button onclick="copyToClipboard('${c.pppoe_username}', 'PPPoE Username')" class="p-1 hover:text-white text-slate-400">
                      <i data-lucide="copy" class="w-3 h-3"></i>
                    </button>
                  ` : ''}
                </div>
              </div>
              <div>
                <span class="text-[10px] text-slate-400 uppercase font-semibold">Port Block</span>
                <div class="font-mono font-bold text-white text-xs mt-0.5">${c.allocated_port_block}</div>
              </div>
            </div>
          ` : `
            <div class="text-[11px] text-amber-300/90 bg-amber-950/20 p-2.5 rounded border border-amber-500/20 flex items-start gap-2">
              <i data-lucide="info" class="w-4 h-4 text-amber-400 shrink-0 mt-0.5"></i>
              <span>This public IP is deterministically shared across <strong>${c.subscriber_candidates_count} subscribers</strong>. To pinpoint the exact customer without guessing, enter the source port from the abuse report in the search filters above.</span>
            </div>
          `}
        </div>
      `;
    } else {
      cgnatContainer.innerHTML = `
        <div class="p-3 rounded-lg bg-dark-800 border border-slate-800 text-xs text-slate-400">
          This IP is not part of the configured deterministic CGNAT public pool (Directly routed or external IP).
        </div>
      `;
    }
  }

  // 5. Related Suricata Security Alerts
  const suricataContainer = document.getElementById("intel-res-suricata-alerts");
  if (suricataContainer) {
    if (data.recent_suricata_alerts && data.recent_suricata_alerts.length > 0) {
      suricataContainer.innerHTML = `
        <div class="space-y-2">
          <div class="text-xs font-bold text-slate-300">
            Detected <strong>${data.suricata_alerts_count}</strong> Suricata intrusion events involving this IP:
          </div>
          ${data.recent_suricata_alerts.map(a => `
            <div class="p-2.5 rounded bg-dark-800 border border-slate-700/60 text-xs flex items-center justify-between">
              <div>
                <span class="font-bold text-white">${a.signature_name}</span>
                <div class="text-[10px] text-slate-400 font-mono mt-0.5">
                  ${a.source_ip}:${a.source_port} -> ${a.destination_ip}:${a.destination_port} (${a.protocol})
                </div>
              </div>
              <div class="text-right">
                <span class="px-2 py-0.5 rounded text-[10px] font-black uppercase ${
                  a.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                  (a.severity === 'high' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300')
                }">
                  ${a.severity}
                </span>
                <div class="text-[10px] text-slate-400 mt-1">${formatManilaTime(a.event_timestamp)}</div>
              </div>
            </div>
          `).join("")}
        </div>
      `;
    } else {
      suricataContainer.innerHTML = `<div class="text-xs text-slate-400 italic">No Suricata alerts logged involving this IP.</div>`;
    }
  }

  if (window.lucide) lucide.createIcons();
}

function exportCurrentLookupJSON() {
  const ip = document.getElementById("intel-res-ip")?.innerText;
  if (!ip) return;
  const data = {
    ip: ip,
    exported_at: new Date().toISOString(),
    status: document.getElementById("intel-res-status-badge")?.innerText,
    score: document.getElementById("intel-res-score")?.innerText,
    explanation: document.getElementById("intel-res-explanation")?.innerText
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `reputation_report_${ip}.json`;
  a.click();
}

// ---------------------------------------------------------------------------
// 3. BULK SCANNER
// ---------------------------------------------------------------------------
async function launchBulkScan() {
  const typeSelect = document.getElementById("select-bulk-type");
  const manualTextarea = document.getElementById("textarea-bulk-ips");
  const cidrInput = document.getElementById("input-bulk-cidr");
  const depthSelect = document.getElementById("select-bulk-depth");
  const confirmCheckbox = document.getElementById("checkbox-bulk-cidr-confirm");
  const btn = document.getElementById("btn-launch-bulk-scan");

  const scanType = typeSelect ? typeSelect.value : "bulk_manual";
  const depth = depthSelect ? depthSelect.value : "standard";

  let body = {
    scan_type: scanType,
    scan_depth: depth,
    concurrency_limit: 5,
    confirm_large_cidr: confirmCheckbox ? confirmCheckbox.checked : false
  };

  if (scanType === "bulk_cidr") {
    if (!cidrInput || !cidrInput.value.trim()) {
      showIntelToast("Please enter a CIDR range (e.g. 157.119.69.128/25)", true);
      return;
    }
    body.cidr_range = cidrInput.value.trim();
  } else if (scanType === "bulk_manual") {
    if (!manualTextarea || !manualTextarea.value.trim()) {
      showIntelToast("Please enter at least one IP address", true);
      return;
    }
    const lines = manualTextarea.value.split("\n").map(l => l.trim()).filter(l => l);
    body.ip_list = lines;
  }

  btn.disabled = true;
  try {
    const res = await fetch("/api/ip-intelligence/scans", {
      method: "POST",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    showIntelToast(`Bulk scan initiated for ${data.target_count} addresses!`);
    startMonitoringScanProgress(data.scan_id);
  } catch (e) {
    showIntelToast(e.message, true);
  } finally {
    btn.disabled = false;
  }
}

function startMonitoringScanProgress(scanId) {
  const progressBox = document.getElementById("bulk-scan-progress-box");
  if (progressBox) progressBox.classList.remove("hidden");

  if (activeScanPollInterval) clearInterval(activeScanPollInterval);

  activeScanPollInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/ip-intelligence/scans/${scanId}`, {
        headers: getAuthHeaders()
      });
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById("bulk-scan-status-text").innerText = `${data.status.toUpperCase()} (${data.progress_percent}%)`;
      document.getElementById("bulk-scan-progress-bar").style.width = `${data.progress_percent}%`;
      document.getElementById("bulk-scan-counts").innerText = `Completed: ${data.completed_count}/${data.target_count} | Listed: ${data.listed_count} | Failed: ${data.failed_count}`;

      if (data.status === "completed" || data.status === "cancelled" || data.status === "failed") {
        clearInterval(activeScanPollInterval);
        showIntelToast(`Scan completed: ${data.completed_count} checked, ${data.listed_count} listed.`);
        loadIPIntelOverview();
      }
    } catch (e) {
      console.error("Scan poll error:", e);
    }
  }, 1500);
}

// ---------------------------------------------------------------------------
// 4. PUBLIC IP INVENTORY
// ---------------------------------------------------------------------------
async function loadIPIntelInventory() {
  const tbody = document.getElementById("intel-inventory-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/ip-intelligence/inventory?limit=100", {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const items = await res.json();

    if (!items || items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-8 text-slate-400">No public IP addresses configured in inventory. Click 'Add IP / Range' to register.</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(it => `
      <tr class="border-b border-slate-800/80 hover:bg-dark-750/50 transition-colors">
        <td class="py-2.5 px-3">
          <div class="font-mono font-bold text-white text-xs flex items-center gap-1.5">
            ${it.ip_address}
            <button onclick="copyToClipboard('${it.ip_address}', 'IP')" class="p-1 hover:text-white text-slate-400">
              <i data-lucide="copy" class="w-3 h-3"></i>
            </button>
          </div>
          <div class="text-[10px] text-slate-400">${it.cidr_allocation || 'Direct Allocation'}</div>
        </td>
        <td class="py-2.5 px-3 text-xs text-slate-300 font-medium">
          ${it.purpose_role}
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
            it.monitoring_status === 'active' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
            (it.monitoring_status === 'reserved' ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' : 'bg-slate-700 text-slate-400')
          }">
            ${it.monitoring_status.toUpperCase()}
          </span>
        </td>
        <td class="py-2.5 px-3">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold ${
            it.current_reputation_status === 'CLEAN' ? 'bg-emerald-500/20 text-emerald-300' :
            (it.current_reputation_status === 'LISTED' || it.current_reputation_status === 'HIGH_RISK' ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-700 text-slate-300')
          }">
            ${it.current_reputation_status}
          </span>
        </td>
        <td class="py-2.5 px-3 text-xs font-mono">
          <span class="${it.active_listing_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}">
            ${it.active_listing_count}
          </span>
        </td>
        <td class="py-2.5 px-3 text-xs text-slate-400">
          ${it.last_checked_at ? formatManilaTime(it.last_checked_at) : 'Never'}
        </td>
        <td class="py-2.5 px-3 text-right">
          <button onclick="quickCheckIP('${it.ip_address}')" class="px-2 py-1 rounded bg-dark-700 hover:bg-dark-600 text-slate-200 text-xs font-semibold border border-slate-600 transition-all">
            Check Now
          </button>
        </td>
      </tr>
    `).join("");

    if (window.lucide) lucide.createIcons();
  } catch (e) {
    console.error("Inventory error:", e);
  }
}

function quickCheckIP(ip) {
  switchIntelSubTab("lookup");
  const ipInput = document.getElementById("input-intel-ip");
  if (ipInput) ipInput.value = ip;
  executeSingleLookup();
}

function openAddInventoryModal() {
  const ipEl = document.getElementById("modal-inv-ip");
  const cidrEl = document.getElementById("modal-inv-cidr");
  const notesEl = document.getElementById("modal-inv-notes");
  if (ipEl) ipEl.value = "";
  if (cidrEl) cidrEl.value = "";
  if (notesEl) notesEl.value = "";
  openModal("modal-intel-add-inventory");
}

async function addInventorySubmit() {
  const ipEl = document.getElementById("modal-inv-ip");
  const cidrEl = document.getElementById("modal-inv-cidr");
  const roleEl = document.getElementById("modal-inv-role");
  const notesEl = document.getElementById("modal-inv-notes");

  const ip = ipEl?.value.trim();
  const cidr = cidrEl?.value.trim();
  const role = roleEl?.value;
  const notes = notesEl?.value;

  if (!ip) {
    showIntelToast("IP Address or Range is required", true);
    if (ipEl) ipEl.focus();
    return;
  }

  try {
    const res = await fetch("/api/ip-intelligence/inventory", {
      method: "POST",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({
        ip_address: ip,
        cidr_allocation: cidr || null,
        purpose_role: role || "CGNAT Pool",
        notes: notes || null
      })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || "Failed to add IP to inventory");
    showIntelToast(data.message || `Added ${ip} to inventory!`, false);
    closeModal("modal-intel-add-inventory");
    if (ipEl) ipEl.value = "";
    if (cidrEl) cidrEl.value = "";
    if (notesEl) notesEl.value = "";
    loadIPIntelInventory();
  } catch (e) {
    showIntelToast(e.message, true);
  }
}

// ---------------------------------------------------------------------------
// 5. REPUTATION HISTORY
// ---------------------------------------------------------------------------
async function loadIPIntelHistory() {
  const tbody = document.getElementById("intel-history-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/ip-intelligence/ip/all/history", {
      headers: getAuthHeaders()
    });
    // Fallback if endpoint is for single IP
  } catch (e) {
    // Handled in single IP
  }
}

// ---------------------------------------------------------------------------
// 6. PROVIDER MANAGEMENT
// ---------------------------------------------------------------------------
async function loadIPIntelProviders() {
  const container = document.getElementById("intel-providers-container");
  if (!container) return;

  try {
    const res = await fetch("/api/ip-intelligence/providers", {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const provs = await res.json();

    container.innerHTML = provs.map(p => `
      <div class="p-5 rounded-xl bg-dark-800/90 border border-slate-700/80 shadow-lg flex flex-col justify-between">
        <div>
          <div class="flex items-center justify-between mb-3">
            <div class="flex items-center gap-2">
              <span class="w-3 h-3 rounded-full ${p.enabled ? 'bg-emerald-400' : 'bg-slate-500'}"></span>
              <h4 class="font-bold text-white text-sm">${p.provider_name}</h4>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
              p.provider_type === 'dnsbl' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
              (p.provider_type === 'abuse_api' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' : 'bg-purple-500/10 text-purple-400 border border-purple-500/20')
            }">
              ${p.provider_type}
            </span>
          </div>

          <p class="text-xs text-slate-300 mb-3">${p.terms_notice || 'Real-time reputation intelligence lookup.'}</p>

          <div class="space-y-1.5 text-xs text-slate-400 font-mono mb-4 bg-dark-850 p-3 rounded-lg border border-slate-800">
            <div>Auth: <span class="text-slate-200">${p.auth_method}</span></div>
            <div>Key: <span class="text-slate-200">${p.has_api_key ? p.api_key_masked : 'None / Not Required'}</span></div>
            <div>Timeout: <span class="text-slate-200">${p.timeout_seconds}s</span> | Rate Limit: <span class="text-slate-200">${p.rate_limit_rpm} rpm</span></div>
            ${p.dns_zone ? `<div>Zone: <span class="text-cyan-300">${p.dns_zone}</span></div>` : ''}
            ${p.last_error ? `<div class="text-rose-400 text-[11px] font-sans mt-1">⚠️ Error: ${p.last_error}</div>` : ''}
          </div>
        </div>

        <div class="flex items-center justify-between pt-3 border-t border-slate-700/60">
          <button onclick="testProviderConnectivity('${p.provider_id}')" class="px-3 py-1.5 rounded bg-dark-700 hover:bg-dark-600 text-slate-200 text-xs font-semibold border border-slate-600 transition-all flex items-center gap-1.5">
            <i data-lucide="activity" class="w-3.5 h-3.5 text-cyan-400"></i> Test
          </button>
          <button onclick="openProviderEditModal('${p.provider_id}')" class="px-3 py-1.5 rounded bg-brand-600 hover:bg-brand-500 text-white text-xs font-bold transition-all shadow-md shadow-brand-600/20">
            Configure
          </button>
        </div>
      </div>
    `).join("");

    if (window.lucide) lucide.createIcons();
  } catch (e) {
    console.error("Failed to load providers:", e);
  }
}

async function testProviderConnectivity(providerId) {
  showIntelToast(`Testing ${providerId}...`);
  try {
    const res = await fetch(`/api/ip-intelligence/providers/${providerId}/test`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    const data = await res.json();
    if (data.online) {
      showIntelToast(`[✓] ${providerId} is online! Latency: ${data.latency_ms || 0}ms`);
    } else {
      showIntelToast(`[!] ${providerId} status: ${data.status || 'Offline'} - ${data.message || ''}`, true);
    }
  } catch (e) {
    showIntelToast(`Test failed: ${e.message}`, true);
  }
}
