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

  let activeView = null;
  document.querySelectorAll(".intel-subtab-view").forEach(view => {
    if (view.id === `intel-view-${subTabId}`) {
      view.classList.remove("hidden");
      activeView = view;
    } else {
      view.classList.add("hidden");
    }
  });

  if (activeView && typeof renderIcons === "function") {
    renderIcons(activeView);
  }

  if (subTabId === "overview") {
    loadIPIntelOverview();
  } else if (subTabId === "inventory") {
    loadIPBlocksSummary();
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
    
    const disBadge = document.getElementById("kpi-intel-disabled-badge");
    if (disBadge) {
      if (data.total_disabled_ips && data.total_disabled_ips > 0) {
        disBadge.classList.remove("hidden");
        disBadge.textContent = `${data.total_disabled_ips} disabled`;
      } else {
        disBadge.classList.add("hidden");
      }
    }

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

  // 6. Online Gaming & Anti-Cheat Compatibility Assessment
  const gamingRes = data.provider_results ? data.provider_results.find(r => r.provider_id === "gaming_compat") : null;
  if (gamingRes && gamingRes.raw_reference) {
    renderGamingCompatibilityCard(gamingRes.raw_reference, data.ip_address);
  } else {
    fetch(`/api/ip-intelligence/ip/${encodeURIComponent(data.ip_address)}/gaming`, { headers: getAuthHeaders() })
      .then(r => r.ok ? r.json() : null)
      .then(summary => { if (summary) renderGamingCompatibilityCard(summary, data.ip_address); })
      .catch(() => {});
  }

  if (window.lucide) lucide.createIcons();
}

function renderGamingCompatibilityCard(gaming, ip) {
  const card = document.getElementById("intel-res-gaming-card");
  const gradeContainer = document.getElementById("intel-res-gaming-grade-container");
  const body = document.getElementById("intel-res-gaming-body");
  if (!card || !body) return;

  if (!gaming) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");

  const gradeColors = {
    "A+": "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
    "A": "bg-teal-500/20 text-teal-300 border-teal-500/40",
    "B": "bg-blue-500/20 text-blue-300 border-blue-500/40",
    "C": "bg-amber-500/20 text-amber-300 border-amber-500/40",
    "F": "bg-rose-600/30 text-rose-300 border-rose-500/40 animate-pulse"
  };

  if (gradeContainer) {
    gradeContainer.innerHTML = `
      <div class="flex items-center gap-2">
        <span class="text-xs text-slate-400 font-semibold">GAMING GRADE:</span>
        <span class="px-3 py-1 rounded-full text-xs font-black tracking-wider border ${gradeColors[gaming.overall_grade] || 'bg-slate-700 text-white'}">
          GRADE ${gaming.overall_grade} • ${gaming.overall_status}
        </span>
      </div>
    `;
  }

  const riskColor = gaming.anti_cheat_risk === 'LOW' ? 'text-emerald-400' : (gaming.anti_cheat_risk === 'MODERATE' ? 'text-amber-400' : 'text-rose-400');
  const natColor = (gaming.nat_suitability && (gaming.nat_suitability.includes('Full-Cone') || gaming.nat_suitability.includes('Open'))) ? 'text-emerald-400' : 'text-amber-400';

  const gamesHtml = (gaming.games || []).map(g => {
    const statusBadge = g.status === 'EXCELLENT' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
      (g.status === 'COMPATIBLE' ? 'bg-teal-500/10 text-teal-400 border border-teal-500/20' :
      (g.status === 'RESTRICTED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'));

    return `
      <div class="p-3.5 rounded-xl bg-dark-900 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between">
        <div>
          <div class="flex items-start justify-between gap-2 mb-1.5">
            <div>
              <h5 class="text-xs font-bold text-white leading-tight">${g.game_name}</h5>
              <span class="text-[10px] text-slate-400">${g.category}</span>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${statusBadge}">
              ${g.status}
            </span>
          </div>
          <div class="text-[11px] text-slate-300 my-2 leading-relaxed">${g.notes}</div>
        </div>
        <div class="pt-2 border-t border-slate-800/80 space-y-1 text-[10px] font-mono text-slate-400">
          <div class="flex items-center justify-between">
            <span>Ping / RTT:</span>
            <span class="font-bold text-slate-200">${g.latency_ms > 0 ? g.latency_ms + 'ms' : 'Timeout'}</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Anti-Cheat:</span>
            <span class="text-slate-300">${g.anti_cheat_engine}</span>
          </div>
          <div class="flex items-center justify-between">
            <span>Ports:</span>
            <span class="text-cyan-300">${g.port_requirements}</span>
          </div>
        </div>
      </div>
    `;
  }).join("");

  body.innerHTML = `
    <!-- Summary Metrics -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-xl bg-dark-900/60 border border-slate-700/60">
      <div>
        <span class="text-[10px] text-slate-400 uppercase font-semibold">Anti-Cheat Fraud Risk</span>
        <div class="text-xs font-bold ${riskColor} mt-0.5">${gaming.anti_cheat_risk} RISK</div>
      </div>
      <div>
        <span class="text-[10px] text-slate-400 uppercase font-semibold">NAT Gaming Suitability</span>
        <div class="text-xs font-bold ${natColor} mt-0.5">${gaming.nat_suitability}</div>
      </div>
      <div>
        <span class="text-[10px] text-slate-400 uppercase font-semibold">IP Classification</span>
        <div class="text-xs font-bold text-slate-200 mt-0.5">${gaming.isp_classification}</div>
      </div>
    </div>

    <!-- Games Matrix -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      ${gamesHtml}
    </div>

    <!-- Recommendations -->
    ${(gaming.recommendations && gaming.recommendations.length > 0) ? `
      <div class="p-3.5 rounded-xl bg-dark-900/80 border border-slate-800 text-xs text-slate-300 space-y-1.5">
        <div class="font-bold text-white flex items-center gap-1.5">
          <i data-lucide="check-circle-2" class="w-4 h-4 text-emerald-400"></i> WISP Engineering Recommendations
        </div>
        <ul class="list-disc list-inside space-y-1 text-slate-400 pl-1">
          ${gaming.recommendations.map(r => `<li>${r}</li>`).join("")}
        </ul>
      </div>
    ` : ''}
  `;

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
// 4. PUBLIC IP INVENTORY STATE & CONTROLS
// ---------------------------------------------------------------------------
let currentInvPage = 1;
let currentInvLimit = 50;
let currentInvSearch = "";
let currentInvRole = "";
let currentInvStatus = "";
let currentInvBlock = "";
let currentInvMonitoring = "";
let currentInvSort = "recent";
let currentInvTotal = 0;
let invSearchDebounceTimer = null;

function escapeId(str) {
  return String(str || '').replace(/[^a-zA-Z0-9_-]/g, '_');
}

function debounceInventorySearch() {
  const input = document.getElementById("intel-inv-search");
  const clearBtn = document.getElementById("intel-inv-search-clear");
  const val = input ? input.value.trim() : "";
  if (clearBtn) {
    if (val.length > 0) clearBtn.classList.remove("hidden");
    else clearBtn.classList.add("hidden");
  }
  clearTimeout(invSearchDebounceTimer);
  invSearchDebounceTimer = setTimeout(() => {
    currentInvSearch = val;
    currentInvPage = 1;
    loadIPIntelInventory();
  }, 250);
}

function clearInventorySearch() {
  const input = document.getElementById("intel-inv-search");
  const clearBtn = document.getElementById("intel-inv-search-clear");
  if (input) input.value = "";
  if (clearBtn) clearBtn.classList.add("hidden");
  currentInvSearch = "";
  currentInvPage = 1;
  loadIPIntelInventory();
}

function applyInventoryFilter() {
  const roleEl = document.getElementById("intel-inv-role-filter");
  const statusEl = document.getElementById("intel-inv-status-filter");
  const blockEl = document.getElementById("intel-inv-block-filter");
  const monEl = document.getElementById("intel-inv-monitoring-filter");
  const sortEl = document.getElementById("intel-inv-sort");

  currentInvRole = roleEl ? roleEl.value : "";
  currentInvStatus = statusEl ? statusEl.value : "";
  currentInvBlock = blockEl ? blockEl.value : "";
  currentInvMonitoring = monEl ? monEl.value : "";
  currentInvSort = sortEl ? sortEl.value : "recent";
  currentInvPage = 1;
  loadIPIntelInventory();
}

function changeInventoryLimit() {
  const limitEl = document.getElementById("intel-inv-limit");
  currentInvLimit = limitEl ? parseInt(limitEl.value, 10) || 50 : 50;
  currentInvPage = 1;
  loadIPIntelInventory();
}

function prevInventoryPage() {
  if (currentInvPage > 1) {
    currentInvPage--;
    loadIPIntelInventory();
  }
}

function nextInventoryPage() {
  const maxPage = Math.max(1, Math.ceil(currentInvTotal / currentInvLimit));
  if (currentInvPage < maxPage) {
    currentInvPage++;
    loadIPIntelInventory();
  }
}

// ---------------------------------------------------------------------------
// IP BLOCKS ALLOCATION DECK & MONITORING CONTROLS
// ---------------------------------------------------------------------------
async function loadIPBlocksSummary() {
  const container = document.getElementById("intel-blocks-container");
  const countBadge = document.getElementById("intel-blocks-count-badge");
  const blockSelect = document.getElementById("intel-inv-block-filter");
  if (!container) return;

  try {
    const res = await fetch("/api/ip-intelligence/blocks", {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blocks = await res.json();

    if (countBadge) {
      countBadge.textContent = `${blocks.length} Block${blocks.length === 1 ? '' : 's'}`;
    }

    // Populate dropdown options
    if (blockSelect) {
      const prevVal = blockSelect.value;
      blockSelect.innerHTML = `<option value="">All IP Blocks (${blocks.length})</option>` +
        blocks.map(b => `<option value="${escapeHtml(b.cidr_allocation)}">${escapeHtml(b.cidr_allocation)} (${b.total_ips} IPs - ${b.status.toUpperCase()})</option>`).join("");
      blockSelect.value = prevVal;
    }

    if (!blocks || blocks.length === 0) {
      container.innerHTML = `<div class="col-span-full py-4 text-center text-xs text-slate-400">No allocated IP blocks found in inventory.</div>`;
      return;
    }

    container.innerHTML = blocks.map(b => {
      const isDis = b.status === "disabled";
      const isMixed = b.status === "mixed";
      const statusPill = isDis
        ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span> DISABLED</span>`
        : (isMixed
          ? `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> PARTIAL</span>`
          : `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> MONITORED</span>`);

      const toggleBtn = isDis
        ? `<button id="btn-block-toggle-${escapeId(b.cidr_allocation)}" onclick="toggleIPBlockMonitoring('${escapeHtml(b.cidr_allocation)}', 'active')" class="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-sm transition-all flex items-center gap-1"><i data-lucide="play" class="w-3 h-3"></i> Enable</button>`
        : `<button id="btn-block-toggle-${escapeId(b.cidr_allocation)}" onclick="toggleIPBlockMonitoring('${escapeHtml(b.cidr_allocation)}', 'disabled')" class="px-2.5 py-1 rounded bg-dark-800 hover:bg-rose-950/50 text-slate-300 hover:text-rose-300 border border-slate-700 hover:border-rose-500/40 text-xs font-semibold transition-all flex items-center gap-1"><i data-lucide="pause" class="w-3 h-3 text-rose-400"></i> Disable</button>`;

      return `
        <div class="p-3.5 rounded-xl border transition-all ${isDis ? 'bg-dark-900/60 border-slate-800/80 opacity-75 hover:opacity-100' : 'bg-dark-850 border-slate-700/80 hover:border-slate-600'} flex flex-col justify-between gap-3">
          <div>
            <div class="flex items-start justify-between gap-2 mb-2">
              <div>
                <div class="font-mono font-bold text-xs text-white flex items-center gap-1.5">
                  <i data-lucide="network" class="w-3.5 h-3.5 ${isDis ? 'text-slate-500' : 'text-cyan-400'}"></i>
                  ${escapeHtml(b.cidr_allocation)}
                </div>
                <div class="text-[10px] text-slate-400 mt-0.5">${escapeHtml(b.purpose_role || 'CGNAT Pool')}</div>
              </div>
              ${statusPill}
            </div>

            <div class="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-300 bg-dark-900/80 p-2 rounded-lg border border-slate-800">
              <div>
                <span class="text-slate-500 text-[10px] uppercase">Pool Size:</span>
                <div class="font-bold text-white">${b.total_ips} IPs</div>
              </div>
              <div>
                <span class="text-slate-500 text-[10px] uppercase">Active:</span>
                <div class="font-bold ${isDis ? 'text-slate-400' : 'text-emerald-400'}">${b.active_ips} Active</div>
              </div>
              <div>
                <span class="text-slate-500 text-[10px] uppercase">Clean:</span>
                <span class="font-semibold text-emerald-400">${b.clean_count}</span>
              </div>
              <div>
                <span class="text-slate-500 text-[10px] uppercase">Listed:</span>
                <span class="font-semibold ${b.listed_count > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}">${b.listed_count}</span>
              </div>
            </div>
          </div>

          <div class="flex items-center justify-between pt-2 border-t border-slate-800/80">
            <div class="flex items-center gap-1.5">
              ${toggleBtn}
              <button onclick="filterInventoryByBlock('${escapeHtml(b.cidr_allocation)}')" class="px-2.5 py-1 rounded bg-dark-800 hover:bg-dark-750 text-slate-300 text-xs font-medium border border-slate-700 transition-all flex items-center gap-1" title="Filter table by this block">
                <i data-lucide="filter" class="w-3 h-3 text-cyan-400"></i> View
              </button>
            </div>
            <button onclick="deleteIPBlock('${escapeHtml(b.cidr_allocation)}')" class="p-1.5 rounded hover:bg-rose-950/40 text-slate-500 hover:text-rose-400 transition-all" title="Delete entire block">
              <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>
      `;
    }).join("");

    renderIcons(container);
  } catch (e) {
    console.error("Failed to load IP blocks:", e);
    container.innerHTML = `<div class="col-span-full text-xs text-rose-400 italic py-2">Failed to load IP blocks: ${escapeHtml(e.message)}</div>`;
  }
}

async function toggleIPBlockMonitoring(cidr, newStatus) {
  const btn = document.getElementById(`btn-block-toggle-${escapeId(cidr)}`);
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="loader-2" class="w-3 h-3 animate-spin"></i> Updating...`;
    renderIcons(btn);
  }

  try {
    const res = await fetch("/api/ip-intelligence/blocks/toggle-status", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders()
      },
      body: JSON.stringify({
        cidr_allocation: cidr,
        monitoring_status: newStatus
      })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to update block status");

    const isDis = newStatus === "disabled";
    showIntelToast(data.message || `IP block '${cidr}' ${isDis ? 'disabled (loading & scans accelerated)' : 'enabled'}!`, false);

    await loadIPBlocksSummary();
    await loadIPIntelInventory();
    loadIPIntelOverview();
  } catch (e) {
    showIntelToast(`Error: ${e.message}`, true);
    if (btn) btn.disabled = false;
  }
}

async function toggleIPMonitoring(ip, newStatus) {
  try {
    const res = await fetch(`/api/ip-intelligence/inventory/${encodeURIComponent(ip)}/status`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders()
      },
      body: JSON.stringify({ monitoring_status: newStatus })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to update IP status");

    const isDis = newStatus === "disabled";
    showIntelToast(`IP ${ip} ${isDis ? 'disabled (skipped from scans)' : 'enabled for active monitoring'}!`, false);
    await loadIPIntelInventory();
    await loadIPBlocksSummary();
    loadIPIntelOverview();
  } catch (e) {
    showIntelToast(`Error: ${e.message}`, true);
  }
}

function filterInventoryByBlock(cidr) {
  const blockSelect = document.getElementById("intel-inv-block-filter");
  if (blockSelect) blockSelect.value = cidr;
  currentInvBlock = cidr;
  currentInvPage = 1;
  loadIPIntelInventory();
  showIntelToast(`Filtered inventory by block ${cidr}`);
}

async function deleteIPBlock(cidr) {
  if (!confirm(`Are you sure you want to remove the ENTIRE IP block '${cidr}' and all its addresses from inventory?`)) return;
  try {
    const res = await fetch(`/api/ip-intelligence/blocks?cidr_allocation=${encodeURIComponent(cidr)}`, {
      method: "DELETE",
      headers: getAuthHeaders()
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Failed to delete IP block");

    showIntelToast(data.message || `Deleted block '${cidr}'!`, false);
    currentInvBlock = "";
    currentInvPage = 1;
    await loadIPBlocksSummary();
    await loadIPIntelInventory();
    loadIPIntelOverview();
  } catch (e) {
    showIntelToast(`Delete failed: ${e.message}`, true);
  }
}

async function loadIPIntelInventory() {
  const tbody = document.getElementById("intel-inventory-tbody");
  if (!tbody) return;

  const countInfo = document.getElementById("intel-inv-count-info");
  const totalBadge = document.getElementById("intel-inv-total-badge");
  const pageIndicator = document.getElementById("intel-inv-page-indicator");
  const prevBtn = document.getElementById("intel-inv-prev-btn");
  const nextBtn = document.getElementById("intel-inv-next-btn");

  const offset = (currentInvPage - 1) * currentInvLimit;
  const params = new URLSearchParams({
    limit: String(currentInvLimit),
    offset: String(offset),
    sort_by: currentInvSort || "recent"
  });
  if (currentInvSearch) params.append("search", currentInvSearch);
  if (currentInvRole) params.append("purpose_role", currentInvRole);
  if (currentInvStatus) params.append("reputation_status", currentInvStatus);
  if (currentInvBlock) params.append("cidr_allocation", currentInvBlock);
  if (currentInvMonitoring) params.append("monitoring_status", currentInvMonitoring);

  try {
    const res = await fetch(`/api/ip-intelligence/inventory?${params.toString()}`, {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const totalHeader = res.headers.get("X-Total-Count");
    const items = await res.json();
    currentInvTotal = totalHeader ? parseInt(totalHeader, 10) : items.length;

    // Update Badges & Pagination UI
    if (totalBadge) totalBadge.textContent = `${currentInvTotal.toLocaleString()} IPs`;

    const maxPage = Math.max(1, Math.ceil(currentInvTotal / currentInvLimit));
    if (pageIndicator) pageIndicator.textContent = `Page ${currentInvPage} of ${maxPage}`;
    if (prevBtn) prevBtn.disabled = currentInvPage <= 1;
    if (nextBtn) nextBtn.disabled = currentInvPage >= maxPage;

    if (countInfo) {
      if (currentInvTotal === 0) {
        countInfo.textContent = (currentInvSearch || currentInvRole || currentInvStatus || currentInvBlock || currentInvMonitoring)
          ? "No matching IP addresses found"
          : "No IP addresses in inventory";
      } else {
        const start = offset + 1;
        const end = Math.min(offset + items.length, currentInvTotal);
        countInfo.textContent = `Showing ${start}–${end} of ${currentInvTotal.toLocaleString()} IPs${(currentInvSearch || currentInvRole || currentInvStatus || currentInvBlock || currentInvMonitoring) ? ' (Filtered)' : ''}`;
      }
    }

    if (!items || items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-10 text-slate-400">
        <div class="flex flex-col items-center justify-center gap-2">
          <i data-lucide="search-x" class="w-8 h-8 text-slate-500"></i>
          <span>No IP addresses found matching the current criteria.</span>
          ${(currentInvSearch || currentInvRole || currentInvStatus || currentInvBlock || currentInvMonitoring) ? '<button onclick="clearInventorySearch(); document.getElementById(\'intel-inv-role-filter\').value=\'\'; document.getElementById(\'intel-inv-status-filter\').value=\'\'; document.getElementById(\'intel-inv-block-filter\').value=\'\'; document.getElementById(\'intel-inv-monitoring-filter\').value=\'\'; applyInventoryFilter();" class="text-xs text-brand-400 hover:underline mt-1">Clear all filters</button>' : ''}
        </div>
      </td></tr>`;
      if (window.lucide) lucide.createIcons();
      return;
    }

    tbody.innerHTML = items.map(it => {
      const isDis = it.monitoring_status === 'disabled';
      const statusBadge = isDis
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">DISABLED</span>`
        : (it.monitoring_status === 'active'
          ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">ACTIVE</span>`
          : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/20">${escapeHtml(it.monitoring_status.toUpperCase())}</span>`);

      const toggleIpBtn = isDis
        ? `<button onclick="toggleIPMonitoring('${it.ip_address}', 'active')" class="p-1 rounded bg-slate-800 hover:bg-emerald-950/40 text-slate-400 hover:text-emerald-400 transition-all border border-slate-700 hover:border-emerald-500/30" title="Enable Monitoring (Active)"><i data-lucide="play" class="w-3.5 h-3.5 text-emerald-400"></i></button>`
        : `<button onclick="toggleIPMonitoring('${it.ip_address}', 'disabled')" class="p-1 rounded hover:bg-rose-950/40 text-slate-400 hover:text-amber-400 transition-all border border-transparent hover:border-amber-500/30" title="Disable Monitoring (Faster)"><i data-lucide="pause" class="w-3.5 h-3.5 text-amber-400"></i></button>`;

      return `
        <tr class="border-b border-slate-800/80 hover:bg-dark-750/50 transition-colors ${isDis ? 'opacity-60 hover:opacity-100' : ''}">
          <td class="py-2.5 px-3">
            <div class="font-mono font-bold text-white text-xs flex items-center gap-1.5">
              ${it.ip_address}
              <button onclick="copyToClipboard('${it.ip_address}', 'IP')" class="p-1 hover:text-white text-slate-400" title="Copy IP">
                <i data-lucide="copy" class="w-3 h-3"></i>
              </button>
            </div>
            <div class="text-[10px] text-slate-400">${escapeHtml(it.cidr_allocation || 'Direct Allocation')}</div>
          </td>
          <td class="py-2.5 px-3 text-xs text-slate-300 font-medium">
            ${escapeHtml(it.purpose_role)}
          </td>
          <td class="py-2.5 px-3">
            ${statusBadge}
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
            <div class="flex items-center justify-end gap-1.5">
              ${toggleIpBtn}
              <button onclick="quickCheckIP('${it.ip_address}')" class="px-2 py-1 rounded bg-dark-700 hover:bg-dark-600 text-slate-200 text-xs font-semibold border border-slate-600 transition-all flex items-center gap-1" title="Quick check">
                <i data-lucide="shield-check" class="w-3 h-3 text-cyan-400"></i> Check
              </button>
              <button onclick="openRemediationModal('${it.ip_address}')" class="px-2 py-1 rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 text-xs font-semibold border border-amber-500/30 transition-all flex items-center gap-1" title="Clean & Delist IP Agent">
                <i data-lucide="sparkles" class="w-3 h-3 text-amber-400"></i> Clean
              </button>
              <button onclick="deleteInventoryIP('${it.ip_address}')" class="p-1 rounded hover:bg-rose-950/40 text-slate-400 hover:text-rose-400 transition-all border border-transparent hover:border-rose-500/30" title="Delete IP">
                <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join("");

    renderIcons(tbody);
  } catch (e) {
    console.error("Inventory error:", e);
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-rose-400">Failed to load inventory: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function deleteInventoryIP(ip) {
  if (!confirm(`Are you sure you want to remove ${ip} from the monitored inventory?`)) return;
  try {
    const res = await fetch(`/api/ip-intelligence/inventory/${encodeURIComponent(ip)}`, {
      method: "DELETE",
      headers: getAuthHeaders()
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || "Failed to remove IP");
    showIntelToast(data.message || `Removed ${ip} from inventory!`, false);
    loadIPIntelInventory();
  } catch (e) {
    showIntelToast(e.message, true);
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
  const monEl = document.getElementById("modal-inv-monitoring");
  const notesEl = document.getElementById("modal-inv-notes");

  const ip = ipEl?.value.trim();
  const cidr = cidrEl?.value.trim();
  const role = roleEl?.value;
  const monitoring = monEl?.value || "active";
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
        monitoring_status: monitoring,
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

    // Switch sort order to "recent" so the newly inserted/updated IPs appear at row 1 immediately!
    currentInvSort = "recent";
    const sortEl = document.getElementById("intel-inv-sort");
    if (sortEl) sortEl.value = "recent";
    currentInvPage = 1;
    clearInventorySearch();
    await loadIPBlocksSummary();
    await loadIPIntelInventory();
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
let _allProvidersCache = [];

async function loadIPIntelProviders() {
  const container = document.getElementById("intel-providers-container");
  if (!container) return;

  // Stale-while-revalidate client cache for instant subtab rendering
  if (typeof getCachedData === "function") {
    const cached = getCachedData("intel-providers", 45000);
    if (cached && Array.isArray(cached) && cached.length) {
      _allProvidersCache = cached;
      renderProvidersGrid(cached, container);
    }
  }

  if (!container.children.length) {
    container.innerHTML = `
      <div class="col-span-full py-12 flex flex-col items-center justify-center text-slate-400">
        <div class="w-8 h-8 border-2 border-brand-500/20 border-t-brand-500 rounded-full animate-spin mb-3"></div>
        <span class="text-xs">Loading threat intelligence providers...</span>
      </div>
    `;
  }

  try {
    const res = await fetch("/api/ip-intelligence/providers", {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const provs = await res.json();
    _allProvidersCache = provs;
    if (typeof setCachedData === "function") {
      setCachedData("intel-providers", provs);
    }
    renderProvidersGrid(provs, container);
  } catch (e) {
    console.error("Failed to load providers:", e);
    if (!_allProvidersCache || !_allProvidersCache.length) {
      container.innerHTML = `<div class="col-span-full p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">Failed to load providers: ${e.message}</div>`;
    }
  }
}

function renderProvidersGrid(provs, container) {
  container.innerHTML = provs.map(p => `
    <div class="p-5 rounded-xl bg-dark-800/90 border border-slate-700/80 shadow-lg flex flex-col justify-between hover:border-slate-600 transition-all">
      <div>
        <div class="flex items-center justify-between mb-3">
          <div class="flex items-center gap-2">
            <span class="w-3 h-3 rounded-full ${p.enabled ? 'bg-emerald-400 ring-2 ring-emerald-400/20' : 'bg-slate-500'}"></span>
            <h4 class="font-bold text-white text-sm">${p.provider_name}</h4>
          </div>
          <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
            p.provider_type === 'dnsbl' ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
            (p.provider_type === 'abuse_api' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
            (p.provider_type === 'gaming_intel' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-purple-500/10 text-purple-400 border border-purple-500/20'))
          }">
            ${p.provider_type === 'gaming_intel' ? 'GAMING & ANTI-CHEAT' : p.provider_type}
          </span>
        </div>

        <p class="text-xs text-slate-300 mb-3">${p.terms_notice || 'Real-time reputation intelligence lookup.'}</p>

        <div class="space-y-1.5 text-xs text-slate-400 font-mono mb-4 bg-dark-850 p-3 rounded-lg border border-slate-800">
          <div>Auth: <span class="text-slate-200">${p.auth_method}</span></div>
          <div>Key: <span class="${p.has_api_key ? 'text-emerald-300' : 'text-slate-400'}">${p.has_api_key ? p.api_key_masked : 'None / Not Required'}</span></div>
          <div>Timeout: <span class="text-slate-200">${p.timeout_seconds}s</span> | Rate: <span class="text-slate-200">${p.rate_limit_rpm} rpm</span></div>
          ${p.dns_zone ? `<div>Zone: <span class="text-cyan-300">${p.dns_zone}</span></div>` : ''}
          ${p.last_error ? `<div class="text-rose-400 text-[11px] font-sans mt-1">⚠️ Error: ${p.last_error}</div>` : ''}
        </div>
      </div>

      <div>
        <div class="flex items-center justify-between pt-3 border-t border-slate-700/60">
          <button id="btn-test-prov-${p.provider_id}" onclick="testProviderConnectivity('${p.provider_id}')" class="px-3.5 py-1.5 rounded-lg bg-dark-700 hover:bg-dark-600 text-slate-200 text-xs font-semibold border border-slate-600 transition-all flex items-center gap-1.5 active:scale-95">
            <i data-lucide="activity" class="w-3.5 h-3.5 text-cyan-400"></i> Test
          </button>
          <button onclick="openProviderEditModal('${p.provider_id}')" class="px-3.5 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-xs font-bold transition-all shadow-md shadow-brand-600/20 active:scale-95 flex items-center gap-1.5">
            <i data-lucide="settings" class="w-3.5 h-3.5"></i> Configure
          </button>
        </div>
        <div id="prov-test-badge-${p.provider_id}" class="hidden mt-2 p-2 rounded-lg text-[11px] font-mono border"></div>
      </div>
    </div>
  `).join("");

  if (typeof renderIcons === "function") {
    renderIcons(container);
  }
}

async function testProviderConnectivity(providerId) {
  const btn = document.getElementById(`btn-test-prov-${providerId}`);
  const badge = document.getElementById(`prov-test-badge-${providerId}`);
  
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin text-cyan-400"></i> Testing...`;
    if (typeof renderIcons === "function") renderIcons(btn);
  }
  if (badge) {
    badge.className = "mt-2 p-2 rounded-lg text-[11px] font-mono border bg-dark-900 border-slate-700 text-slate-400 flex items-center gap-2";
    badge.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin text-cyan-400"></i> Querying provider health probe...`;
    badge.classList.remove("hidden");
    if (typeof renderIcons === "function") renderIcons(badge);
  }

  showIntelToast(`Testing connectivity for ${providerId}...`);

  try {
    const res = await fetch(`/api/ip-intelligence/providers/${providerId}/test`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    const data = await res.json();
    
    if (res.ok && data.online) {
      const latencyStr = data.latency_ms !== undefined ? `${data.latency_ms}ms` : 'OK';
      const msg = `Online (${latencyStr}) • ${data.status || 'Healthy'}`;
      if (badge) {
        badge.className = "mt-2 p-2 rounded-lg text-[11px] font-mono border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 flex items-center justify-between";
        badge.innerHTML = `<span>✓ ${msg}</span><span class="text-[10px] text-emerald-400 font-bold">${latencyStr}</span>`;
      }
      showIntelToast(`[✓] ${providerId}: ${msg}`);
    } else {
      const errMsg = data.message || data.detail || data.status || 'Offline';
      const isConfigIssue = data.status === 'awaiting_credentials' || (typeof errMsg === 'string' && (errMsg.includes('API key') || errMsg.includes('credentials')));
      if (badge) {
        badge.className = `mt-2 p-2 rounded-lg text-[11px] font-mono border ${isConfigIssue ? 'bg-amber-500/10 border-amber-500/30 text-amber-300' : 'bg-rose-500/10 border-rose-500/30 text-rose-300'} flex items-center justify-between`;
        badge.innerHTML = `<span>${isConfigIssue ? '⚠️' : '✖'} ${errMsg}</span><button onclick="openProviderEditModal('${providerId}')" class="text-[10px] underline hover:text-white font-bold ml-2">Configure</button>`;
      }
      showIntelToast(`[!] ${providerId}: ${errMsg}`, true);
    }
  } catch (e) {
    if (badge) {
      badge.className = "mt-2 p-2 rounded-lg text-[11px] font-mono border bg-rose-500/10 border-rose-500/30 text-rose-300";
      badge.innerHTML = `<span>✖ Network error: ${e.message}</span>`;
    }
    showIntelToast(`Test failed: ${e.message}`, true);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="activity" class="w-3.5 h-3.5 text-cyan-400"></i> Test`;
      if (typeof renderIcons === "function") renderIcons(btn);
    }
    if (badge && typeof renderIcons === "function") renderIcons(badge);
  }
}

async function openProviderEditModal(providerId) {
  let p = _allProvidersCache.find(x => x.provider_id === providerId);
  if (!p) {
    try {
      const res = await fetch("/api/ip-intelligence/providers", { headers: getAuthHeaders() });
      if (res.ok) {
        _allProvidersCache = await res.json();
        p = _allProvidersCache.find(x => x.provider_id === providerId);
      }
    } catch (e) {}
  }
  if (!p) {
    showIntelToast(`Provider '${providerId}' not found`, true);
    return;
  }

  const modal = document.getElementById("modal-provider-config");
  if (!modal) return;

  document.getElementById("modal-prov-id").value = p.provider_id;
  document.getElementById("modal-prov-title").textContent = `Configure ${p.provider_name}`;
  
  const typeBadge = document.getElementById("modal-prov-type-badge");
  if (typeBadge) {
    typeBadge.textContent = p.provider_type === 'gaming_intel' ? 'GAMING & ANTI-CHEAT' : p.provider_type.toUpperCase();
  }

  document.getElementById("modal-prov-subtitle").textContent = p.terms_notice || p.documentation_url || "Reputation intelligence provider configuration.";
  document.getElementById("modal-prov-enabled").checked = Boolean(p.enabled);

  // Key handling
  const keyInput = document.getElementById("modal-prov-key");
  const keyStatus = document.getElementById("modal-prov-key-status");
  keyInput.value = "";
  keyInput.type = "password";
  
  if (p.auth_method === "none" && !p.has_api_key && p.provider_type === "dnsbl") {
    keyStatus.textContent = "Not Required (DNSBL Mode)";
    keyInput.placeholder = "Optional Data Query Service (DQS) key if subscribed...";
  } else if (p.has_api_key) {
    keyStatus.textContent = `Configured: ${p.api_key_masked}`;
    keyInput.placeholder = "Enter new key to overwrite, or leave blank to keep current...";
  } else {
    keyStatus.textContent = "Not Configured";
    keyInput.placeholder = "Enter API key / secret token...";
  }

  // Zone vs Endpoint visibility
  const zoneContainer = document.getElementById("modal-prov-zone-container");
  const endpointContainer = document.getElementById("modal-prov-endpoint-container");
  const zoneInput = document.getElementById("modal-prov-zone");
  const endpointInput = document.getElementById("modal-prov-endpoint");

  zoneInput.value = p.dns_zone || "";
  endpointInput.value = p.api_endpoint || "";

  if (p.dns_zone || p.provider_type === "dnsbl") {
    zoneContainer.classList.remove("hidden");
  } else {
    zoneContainer.classList.add("hidden");
  }

  if (p.api_endpoint || p.provider_type !== "dnsbl") {
    endpointContainer.classList.remove("hidden");
  } else {
    endpointContainer.classList.add("hidden");
  }

  document.getElementById("modal-prov-timeout").value = p.timeout_seconds || 5.0;
  document.getElementById("modal-prov-ratelimit").value = p.rate_limit_rpm || 60;
  document.getElementById("modal-prov-maxconcurrent").value = p.max_concurrent || 5;
  document.getElementById("modal-prov-pos-ttl").value = p.cache_duration_positive_sec || 1800;
  document.getElementById("modal-prov-neg-ttl").value = p.cache_duration_negative_sec || 7200;

  // Reset test result inside modal
  const testRes = document.getElementById("modal-prov-test-result");
  if (testRes) {
    testRes.classList.add("hidden");
    testRes.innerHTML = "";
  }

  modal.classList.remove("hidden");
  modal.classList.add("flex");
  if (typeof renderIcons === "function") renderIcons(modal);
}

function toggleProvKeyVisibility() {
  const input = document.getElementById("modal-prov-key");
  const eye = document.getElementById("modal-prov-key-eye");
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    if (eye) eye.setAttribute("data-lucide", "eye-off");
  } else {
    input.type = "password";
    if (eye) eye.setAttribute("data-lucide", "eye");
  }
  if (typeof renderIcons === "function") renderIcons(input.parentElement);
}

async function saveProviderConfig(e) {
  if (e && e.preventDefault) e.preventDefault();
  const providerId = document.getElementById("modal-prov-id").value;
  if (!providerId) return;

  const saveBtn = document.getElementById("btn-save-prov-modal");
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i> Saving...`;
    if (typeof renderIcons === "function") renderIcons(saveBtn);
  }

  const payload = {
    enabled: document.getElementById("modal-prov-enabled").checked,
    timeout_seconds: parseFloat(document.getElementById("modal-prov-timeout").value) || 5.0,
    rate_limit_rpm: parseInt(document.getElementById("modal-prov-ratelimit").value, 10) || 60,
    max_concurrent: parseInt(document.getElementById("modal-prov-maxconcurrent").value, 10) || 5,
    cache_duration_positive_sec: parseInt(document.getElementById("modal-prov-pos-ttl").value, 10) || 1800,
    cache_duration_negative_sec: parseInt(document.getElementById("modal-prov-neg-ttl").value, 10) || 7200
  };

  const keyVal = document.getElementById("modal-prov-key").value.trim();
  if (keyVal) {
    payload.api_key = keyVal;
  }

  const zoneVal = document.getElementById("modal-prov-zone").value.trim();
  if (zoneVal) {
    payload.dns_zone = zoneVal;
  }

  const endpointVal = document.getElementById("modal-prov-endpoint").value.trim();
  if (endpointVal) {
    payload.api_endpoint = endpointVal;
  }

  try {
    const res = await fetch(`/api/ip-intelligence/providers/${providerId}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeaders()
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    showIntelToast(`Provider '${providerId}' updated successfully!`);
    closeModal("modal-provider-config");
    if (window._clientDataCache) window._clientDataCache.delete("intel-providers");
    await loadIPIntelProviders();
  } catch (err) {
    showIntelToast(`Save failed: ${err.message}`, true);
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.innerHTML = `<i data-lucide="save" class="w-3.5 h-3.5"></i> Save Settings`;
      if (typeof renderIcons === "function") renderIcons(saveBtn);
    }
  }
}

async function testModalProviderConnectivity() {
  const providerId = document.getElementById("modal-prov-id").value;
  if (!providerId) return;

  const btn = document.getElementById("btn-modal-test-prov");
  const resultBox = document.getElementById("modal-prov-test-result");
  if (!btn || !resultBox) return;

  btn.disabled = true;
  btn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin text-cyan-400"></i> Testing...`;
  resultBox.classList.remove("hidden");
  resultBox.className = "p-3 rounded-xl text-xs font-mono border bg-dark-900 border-slate-700 text-slate-300 flex items-center gap-2";
  resultBox.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin text-cyan-400"></i> Sending health probe to ${providerId}...`;
  if (typeof renderIcons === "function") {
    renderIcons(resultBox);
    renderIcons(btn);
  }

  try {
    const res = await fetch(`/api/ip-intelligence/providers/${providerId}/test`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    const data = await res.json();
    if (res.ok && data.online) {
      const latStr = data.latency_ms !== undefined ? `${data.latency_ms}ms` : 'OK';
      resultBox.className = "p-3 rounded-xl text-xs font-mono border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 flex items-center justify-between";
      resultBox.innerHTML = `<span>✓ Connectivity verified! (${data.status || 'healthy'})</span><span class="font-bold">${latStr}</span>`;
    } else {
      const msg = data.message || data.detail || data.status || 'Offline';
      resultBox.className = "p-3 rounded-xl text-xs font-mono border bg-rose-500/10 border-rose-500/30 text-rose-300 flex items-center justify-between";
      resultBox.innerHTML = `<span>✖ Health check alert: ${msg}</span><span class="font-bold">${data.latency_ms !== undefined ? data.latency_ms + 'ms' : 'Error'}</span>`;
    }
  } catch (e) {
    resultBox.className = "p-3 rounded-xl text-xs font-mono border bg-rose-500/10 border-rose-500/30 text-rose-300";
    resultBox.innerHTML = `<span>✖ Request failed: ${e.message}</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="activity" class="w-3.5 h-3.5 text-cyan-400"></i> Test Connection`;
    if (typeof renderIcons === "function") {
      renderIcons(btn);
      renderIcons(resultBox);
    }
  }
}

// ---------------------------------------------------------------------------
// 6. AUTONOMOUS IP REMEDIATION & DELISTING AGENT
// ---------------------------------------------------------------------------
let currentRemediationJob = null;

async function openRemediationModal(ipAddress) {
  const ip = (ipAddress || "").trim();
  if (!ip) {
    showIntelToast("Please specify an IP address to clean", true);
    return;
  }

  const modal = document.getElementById("modal-intel-remediation");
  if (!modal) return;

  const targetIpEl = document.getElementById("remediation-target-ip");
  const statusBadge = document.getElementById("remediation-status-badge");
  const loading = document.getElementById("remediation-loading");
  const content = document.getElementById("remediation-content");

  if (targetIpEl) targetIpEl.textContent = ip;
  if (statusBadge) {
    statusBadge.textContent = "DIAGNOSING";
    statusBadge.className = "px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/30";
  }

  if (loading) loading.classList.remove("hidden");
  if (content) {
    content.classList.add("hidden");
    content.innerHTML = "";
  }

  openModal("modal-intel-remediation");

  try {
    const res = await fetch("/api/ip-intelligence/remediation/jobs", {
      method: "POST",
      headers: { ...getAuthHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ ip_address: ip, auto_apply_mitigation: false })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const job = await res.json();
    currentRemediationJob = job;
    renderRemediationDetails(job);
  } catch (e) {
    console.error("Remediation Agent error:", e);
    if (loading) loading.classList.add("hidden");
    if (content) {
      content.classList.remove("hidden");
      content.innerHTML = `
        <div class="p-6 rounded-xl bg-rose-950/30 border border-rose-500/40 text-center space-y-3">
          <i data-lucide="alert-triangle" class="w-8 h-8 text-rose-400 mx-auto"></i>
          <div class="text-sm font-bold text-white">Diagnostic Initiation Failed</div>
          <div class="text-xs text-rose-300 font-mono">${e.message}</div>
          <button onclick="openRemediationModal('${ip}')" class="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold mt-2">Retry Diagnostics</button>
        </div>
      `;
      if (window.lucide) lucide.createIcons();
    }
  }
}

function renderRemediationDetails(job) {
  const loading = document.getElementById("remediation-loading");
  const content = document.getElementById("remediation-content");
  const statusBadge = document.getElementById("remediation-status-badge");

  if (loading) loading.classList.add("hidden");
  if (!content) return;
  content.classList.remove("hidden");

  const statusColors = {
    evaluating: "bg-amber-500/20 text-amber-300 border border-amber-500/40",
    sanitizing: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
    delisting: "bg-indigo-500/20 text-indigo-300 border border-indigo-500/40",
    monitoring: "bg-blue-500/20 text-blue-300 border border-blue-500/40",
    completed: "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40",
    failed: "bg-rose-500/20 text-rose-300 border border-rose-500/40"
  };

  if (statusBadge) {
    statusBadge.textContent = (job.status || "UNKNOWN").toUpperCase();
    statusBadge.className = `px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider ${statusColors[job.status] || 'bg-slate-700 text-slate-300'}`;
  }

  const rca = job.root_cause_analysis || {};
  const sub = job.attributed_subscriber;
  const sanitizationScript = (job.sanitization_commands || []).join("\n");

  const blockingActions = (job.delisting_actions || []).filter(a => a.is_blocking);
  const otherActions = (job.delisting_actions || []).filter(a => !a.is_blocking);
  const totalBlocking = blockingActions.length;

  content.innerHTML = `
    <!-- 1. DETECTED BLOCKING AUTHORITIES (ACTION REQUIRED) -->
    <div class="p-5 rounded-2xl bg-dark-800/90 border border-slate-700/80 space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-slate-700/60">
        <div class="flex items-center gap-2">
          <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i>
          <h4 class="text-xs font-black uppercase tracking-wider text-white">External Authorities Blocking This IP</h4>
        </div>
        <span class="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase ${
          totalBlocking > 0 ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
        }">
          ${totalBlocking > 0 ? `${totalBlocking} ACTIVE BLOCKLISTS` : 'NO ACTIVE BLOCKS'}
        </span>
      </div>

      ${totalBlocking > 0 ? `
        <div class="space-y-3">
          <div class="text-xs text-rose-300/90 leading-relaxed">
            The following external authorities are currently blacklisting or restricting traffic from <strong>${job.ip_address}</strong>. Click the direct delisting portal for each authority below and submit the pre-formatted ISP appeal letter:
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            ${blockingActions.map(action => {
              const letter = action.appeal_letter || "";
              return `
                <div class="p-4 rounded-xl bg-rose-950/20 border border-rose-500/30 flex flex-col justify-between space-y-3.5">
                  <div class="space-y-1.5">
                    <div class="flex items-center justify-between gap-2">
                      <span class="font-bold text-white text-xs flex items-center gap-1.5">
                        <i data-lucide="alert-octagon" class="w-3.5 h-3.5 text-rose-400"></i>
                        ${action.provider_name}
                      </span>
                      <span class="px-2 py-0.5 rounded text-[9px] font-black uppercase bg-rose-500/25 text-rose-300 border border-rose-500/30">
                        LISTED
                      </span>
                    </div>
                    <div class="text-[10px] uppercase font-semibold text-rose-300/80">${action.category || 'Reputation Authority'}</div>
                    <p class="text-[11px] text-slate-300 leading-snug">${action.description || action.impact || ''}</p>
                    
                    ${action.removal_sla ? `
                      <div class="text-[10px] text-amber-300 font-medium flex items-center gap-1 mt-1">
                        <i data-lucide="clock" class="w-3 h-3 text-amber-400"></i> Expected SLA: ${action.removal_sla}
                      </div>
                    ` : ''}

                    ${(action.requirements && action.requirements.length > 0) ? `
                      <div class="mt-2 text-[10px] text-slate-400 space-y-0.5">
                        <span class="font-bold text-slate-300">Authority Removal Criteria:</span>
                        <ul class="list-disc pl-4 space-y-0.5 text-slate-400">
                          ${action.requirements.map(r => `<li>${r}</li>`).join("")}
                        </ul>
                      </div>
                    ` : ''}
                  </div>

                  <div class="flex items-center justify-between gap-2 pt-2.5 border-t border-rose-500/20">
                    <button onclick="copyAppealLetter(\`${letter.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`, '${action.provider_name.replace(/'/g, "\\'")}')" class="px-3 py-1.5 rounded-lg bg-dark-750 hover:bg-dark-700 text-slate-200 text-xs font-semibold border border-slate-650 flex items-center gap-1.5 transition-all shadow-sm" title="Copy formal removal petition">
                      <i data-lucide="file-text" class="w-3.5 h-3.5 text-amber-400"></i> Copy Appeal Letter
                    </button>
                    ${action.external_url ? `
                      <a href="${action.external_url}" target="_blank" rel="noopener noreferrer" class="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-brand-600 to-indigo-600 hover:from-brand-500 hover:to-indigo-500 text-white text-xs font-bold flex items-center gap-1.5 shadow-md shadow-brand-600/30 transition-all">
                        <span>Delist on ${action.organization || 'Portal'}</span>
                        <i data-lucide="external-link" class="w-3.5 h-3.5"></i>
                      </a>
                    ` : ''}
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      ` : `
        <div class="p-4 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-emerald-300 flex items-center gap-3">
          <i data-lucide="check-circle-2" class="w-5 h-5 text-emerald-400 shrink-0"></i>
          <div>
            <div class="text-xs font-bold text-white">No Active External Blocklists Detected</div>
            <div class="text-xs text-emerald-300/90 mt-0.5">All monitored RBLs, spam filters, and reputation authorities report that ${job.ip_address} is clean.</div>
          </div>
        </div>
      `}
    </div>

    <!-- 2. ONLINE GAMING & ANTI-CHEAT APPEAL CENTER (CODM / VANGUARD / MLBB) -->
    <div class="p-5 rounded-2xl bg-dark-800/90 border border-slate-700/80 space-y-3.5">
      <div class="flex items-center justify-between pb-2 border-b border-slate-700/60">
        <div class="flex items-center gap-2">
          <i data-lucide="gamepad-2" class="w-4 h-4 text-emerald-400"></i>
          <h4 class="text-xs font-black uppercase tracking-wider text-white">Online Gaming & Anti-Cheat Appeal Center</h4>
        </div>
        <span class="text-[11px] text-slate-400 font-medium">CODM Garena, Activision, Riot Vanguard, MLBB</span>
      </div>
      <p class="text-xs text-slate-400 leading-relaxed">
        Online game publishers (Activision Demonware, Garena Anti-Hack, Riot Vanguard) automatically flag residential IPs that lack compliant Reverse DNS or have incorrect country metadata.
      </p>

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
        <div class="p-3.5 rounded-xl bg-dark-850 border border-slate-700/60 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-bold text-slate-400 uppercase">Recommended DNS PTR Record (Reverse DNS)</span>
            <button onclick="copyToClipboard('${job.rdns_recommendation || ''}', 'Reverse DNS Record')" class="p-1 hover:text-white text-slate-400">
              <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            </button>
          </div>
          <pre class="p-2 rounded bg-dark-900 border border-slate-800 font-mono text-[10px] text-indigo-300 overflow-x-auto">${job.rdns_recommendation || '—'}</pre>
        </div>

        <div class="p-3.5 rounded-xl bg-dark-850 border border-slate-700/60 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-bold text-slate-400 uppercase">RFC 8805 Geofeed CSV Line</span>
            <button onclick="copyToClipboard('${job.geofeed_entry || ''}', 'Geofeed Entry')" class="p-1 hover:text-white text-slate-400">
              <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            </button>
          </div>
          <pre class="p-2 rounded bg-dark-900 border border-slate-800 font-mono text-[10px] text-cyan-300 overflow-x-auto">${job.geofeed_entry || '—'}</pre>
        </div>
      </div>
    </div>

    <!-- 3. COMPREHENSIVE GLOBAL AUTHORITY DIRECTORY & DELISTING PORTALS -->
    <div class="p-5 rounded-2xl bg-dark-800/90 border border-slate-700/80 space-y-3">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <i data-lucide="book-open" class="w-4 h-4 text-indigo-400"></i>
          <h4 class="text-xs font-black uppercase tracking-wider text-white">Global Authority Delisting Directory & Appeal Forms</h4>
        </div>
        <span class="text-xs text-slate-400">${otherActions.length} Clean Authorities Available</span>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
        ${otherActions.map(action => {
          const letter = action.appeal_letter || "";
          return `
            <div class="p-3.5 rounded-xl bg-dark-850 border border-slate-700/50 flex flex-col justify-between space-y-2.5">
              <div>
                <div class="flex items-center justify-between gap-1.5">
                  <span class="font-bold text-white text-xs truncate" title="${action.provider_name}">${action.provider_name}</span>
                  <span class="px-1.5 py-0.5 rounded text-[8px] font-black uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Clean</span>
                </div>
                <div class="text-[10px] text-slate-400 mt-0.5">${action.category}</div>
                <div class="text-[10px] text-slate-500 mt-1">SLA: ${action.removal_sla || 'Standard'}</div>
              </div>

              <div class="flex items-center justify-between gap-1.5 pt-2 border-t border-slate-750">
                <button onclick="copyAppealLetter(\`${letter.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`, '${action.provider_name.replace(/'/g, "\\'")}')" class="px-2 py-1 rounded bg-dark-750 hover:bg-dark-700 text-slate-300 text-[10px] font-semibold border border-slate-650 flex items-center gap-1 transition-all" title="Copy formal removal petition">
                  <i data-lucide="file-text" class="w-3 h-3 text-amber-400"></i> Letter
                </button>
                ${action.external_url ? `
                  <a href="${action.external_url}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded bg-dark-700 hover:bg-dark-600 text-slate-200 text-[10px] font-bold border border-slate-600 flex items-center gap-1 transition-all">
                    <span>Portal</span>
                    <i data-lucide="external-link" class="w-2.5 h-2.5"></i>
                  </a>
                ` : ''}
              </div>
            </div>
          `;
        }).join("")}
      </div>
    </div>

    <!-- 4. AUTONOMOUS CLEAN VERIFICATION -->
    <div class="p-5 rounded-2xl bg-dark-800/90 border border-slate-700/80 space-y-4">
      <div class="flex items-center justify-between">
        <div>
          <h4 class="text-xs font-black uppercase tracking-wider text-white flex items-center gap-2">
            <i data-lucide="check-circle" class="w-4 h-4 text-emerald-400"></i> Authority Delisting Verification
          </h4>
          <p class="text-xs text-slate-400 mt-0.5">Re-scans all external blocklists and DNSBL authorities to verify that your IP has been officially removed.</p>
        </div>
        <button id="btn-remediation-verify" onclick="verifyRemediationClean('${job.job_id}')" class="px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-lg shadow-emerald-600/30 flex items-center gap-2 transition-all">
          <i data-lucide="shield-check" class="w-4 h-4"></i> Verify Delisting from Authorities Now
        </button>
      </div>

      <div id="remediation-verify-result" class="hidden"></div>
    </div>

    <!-- 5. AGENT AUDIT LOGS -->
    <div class="p-4 rounded-xl bg-dark-850 border border-slate-800 space-y-2">
      <div class="text-[10px] font-bold uppercase tracking-wider text-slate-400">Agent Action History</div>
      <div class="space-y-1 max-h-32 overflow-y-auto">
        ${(job.logs || []).map(l => `
          <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 py-0.5">
            <span>${l.message}</span>
            <span class="text-slate-500 text-[10px]">${formatManilaTime(l.timestamp)}</span>
          </div>
        `).join("")}
      </div>
    </div>
  `;

  renderIcons(content);
}

async function verifyRemediationClean(jobId) {
  const btn = document.getElementById("btn-remediation-verify");
  const resultDiv = document.getElementById("remediation-verify-result");
  if (!btn || !resultDiv) return;

  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<div class="w-3.5 h-3.5 border-2 border-white/20 border-t-white rounded-full animate-spin"></div> Verifying...`;

  try {
    const res = await fetch(`/api/ip-intelligence/remediation/jobs/${encodeURIComponent(jobId)}/verify-clean`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    const data = await res.json();
    resultDiv.classList.remove("hidden");

    const isClean = Boolean(data.verified_clean || data.is_clean);
    if (isClean) {
      resultDiv.innerHTML = `
        <div class="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 flex items-start gap-3">
          <i data-lucide="shield-check" class="w-5 h-5 text-emerald-400 shrink-0 mt-0.5"></i>
          <div>
            <div class="text-xs font-bold text-white">IP Officially Verified Clean!</div>
            <div class="text-xs text-emerald-300 mt-0.5">${data.message || 'All providers report zero active listings.'}</div>
          </div>
        </div>
      `;
      const statusBadge = document.getElementById("remediation-status-badge");
      if (statusBadge) {
        statusBadge.textContent = "COMPLETED";
        statusBadge.className = "px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
      }
      showIntelToast("IP successfully verified clean!");
      if (typeof loadIPIntelInventory === "function") loadIPIntelInventory();
    } else {
      const remainingCount = data.active_listings_remaining !== undefined ? data.active_listings_remaining : (data.remaining_listings ? data.remaining_listings.length : 0);
      resultDiv.innerHTML = `
        <div class="p-4 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-300 flex items-start gap-3">
          <i data-lucide="alert-triangle" class="w-5 h-5 text-amber-400 shrink-0 mt-0.5"></i>
          <div>
            <div class="text-xs font-bold text-white">Active Listings Still Detected (${remainingCount})</div>
            <div class="text-xs text-amber-300/90 mt-0.5">${data.message}</div>
          </div>
        </div>
      `;
    }
    if (window.lucide) lucide.createIcons();
  } catch (e) {
    resultDiv.classList.remove("hidden");
    resultDiv.innerHTML = `
      <div class="p-3 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs">
        Verification error: ${e.message}
      </div>
    `;
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
    renderIcons();
  }
}

function copyJustificationText(text, providerName) {
  copyToClipboard(text, `${providerName} Justification`);
}

function copyAppealLetter(text, authName) {
  copyToClipboard(text, `${authName} Appeal Letter`);
  showIntelToast(`Copied official appeal letter for ${authName}!`);
}
