/**
 * WISPnet CGNAT Security Monitoring, Threat Detection & Subscriber Attribution Platform
 * Frontend Controller for all 9 Security Operation Pages
 */

let secCurrentEventsPage = 0;
const SEC_PAGE_SIZE = 25;

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

// Helper: Copy to clipboard with visual toast
function copyToClipboard(text, label = "Value") {
  if (!text || text === "—") return;
  navigator.clipboard.writeText(text).then(() => {
    showSecurityToast(`Copied ${label}: ${text}`);
  }).catch(() => {
    // Fallback
    const el = document.createElement("textarea");
    el.value = text;
    document.body.appendChild(el);
    el.select();
    document.execCommand("copy");
    document.body.removeChild(el);
    showSecurityToast(`Copied ${label}: ${text}`);
  });
}

function showSecurityToast(msg, type = "success") {
  if (typeof window.showToast === "function") {
    window.showToast(msg, type);
  } else {
    const toast = document.createElement("div");
    toast.className = `fixed bottom-5 right-5 z-50 px-4 py-2.5 rounded-lg ${type === 'error' ? 'bg-rose-600' : 'bg-emerald-600'} text-white text-xs font-semibold shadow-xl flex items-center gap-2 animate-bounce`;
    toast.innerHTML = `<span>${msg}</span>`;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
  }
}

// ---------------------------------------------------------------------------
// PAGE 1: SECURITY OVERVIEW
// ---------------------------------------------------------------------------
async function loadSecurityOverview(isManual = false) {
  const spinIcon = document.getElementById("sec-overview-refresh-icon");
  if (spinIcon) spinIcon.classList.add("animate-spin");

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};

    const [healthRes, incRes, evtRes] = await Promise.all([
      fetch("/api/security/health", { headers: authHeaders, credentials: "include" }),
      fetch("/api/security/incidents?limit=10", { headers: authHeaders, credentials: "include" }),
      fetch("/api/security/events?limit=10", { headers: authHeaders, credentials: "include" })
    ]);

    const health = healthRes.ok ? await healthRes.json() : {};
    const incidents = incRes.ok ? await incRes.json() : {};
    const events = evtRes.ok ? await evtRes.json() : {};

    const incList = Array.isArray(incidents?.incidents) ? incidents.incidents : [];
    const evtList = Array.isArray(events?.events) ? events.events : [];

    // Stats Cards
    const criticalInc = incList.filter(i => i.severity === "critical" && (i.status === "new" || i.status === "investigating")).length;
    const highInc = incList.filter(i => i.severity === "high" && (i.status === "new" || i.status === "investigating")).length;
    const verifiedEvt = evtList.filter(e => e.attribution_status === "verified").length;

    const critEl = document.getElementById("sec-stat-crit-inc");
    const highEl = document.getElementById("sec-stat-high-inc");
    const verEl = document.getElementById("sec-stat-verified-attr");
    const qEl = document.getElementById("sec-stat-queue-depth");

    if (critEl) critEl.innerText = criticalInc;
    if (highEl) highEl.innerText = highInc;
    if (verEl) verEl.innerText = verifiedEvt;
    if (qEl) qEl.innerText = health.opensearch_queue_depth || 0;

    // Integration Health Badges
    const healthBadgeContainer = document.getElementById("sec-health-badges");
    if (healthBadgeContainer) {
      const integrations = Array.isArray(health.integrations) ? health.integrations : [];
      healthBadgeContainer.innerHTML = integrations.map(h => {
        const isOnline = h.connectivity === "online";
        const color = isOnline ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" : "bg-amber-500/20 text-amber-300 border-amber-500/30";
        return `
          <div class="px-2.5 py-1 rounded-md border text-xs font-mono flex items-center gap-1.5 ${color}">
            <span class="w-2 h-2 rounded-full ${isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}"></span>
            <span>${h.integration_name}</span>
          </div>
        `;
      }).join("");
    }

    // Incidents Table
    const incTbody = document.getElementById("sec-overview-incidents-body");
    if (incTbody) {
      if (incList.length === 0) {
        incTbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400 text-xs">No active security incidents</td></tr>`;
      } else {
        incTbody.innerHTML = incList.map(inc => {
          const sevColor = inc.severity === "critical" ? "bg-rose-500/20 text-rose-300 border-rose-500/30" :
                           inc.severity === "high" ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-blue-500/20 text-blue-300 border-blue-500/30";
          return `
            <tr class="hover:bg-dark-800/60 cursor-pointer border-b border-slate-800/80 transition-colors" onclick="openIncidentDetailModal('${inc.incident_id}')">
              <td class="py-2.5 px-3 font-mono text-xs text-slate-400">${formatManilaTime(inc.last_seen)}</td>
              <td class="py-2.5 px-3 font-semibold text-xs text-white">${inc.title}</td>
              <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${sevColor}">${inc.severity}</span></td>
              <td class="py-2.5 px-3 font-mono text-xs text-brand-300">
                <span class="hover:underline" onclick="event.stopPropagation(); openSubscriberProfile('${inc.affected_subscriber_ip}')">${inc.affected_subscriber_ip || '—'}</span>
                <button onclick="event.stopPropagation(); copyToClipboard('${inc.affected_subscriber_ip}', 'CGNAT IP')" title="Copy CGNAT IP" class="ml-1 text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3 h-3 inline"></i></button>
              </td>
              <td class="py-2.5 px-3 font-mono text-xs text-cyan-300">
                ${inc.pppoe_username || '—'}
                ${inc.pppoe_username ? `<button onclick="event.stopPropagation(); copyToClipboard('${inc.pppoe_username}', 'Username')" title="Copy Username" class="ml-1 text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3 h-3 inline"></i></button>` : ''}
              </td>
              <td class="py-2.5 px-3 font-mono text-xs text-slate-300">${inc.event_count}</td>
              <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-700/60 text-slate-300">${inc.status}</span></td>
            </tr>
          `;
        }).join("");
      }
    }

    if (window.lucide) lucide.createIcons();
    if (isManual) {
      showSecurityToast("Security overview refreshed", "success");
    }
  } catch (e) {
    console.error("Error loading security overview:", e);
    if (isManual) {
      showSecurityToast("Failed to refresh: " + e.message, "error");
    }
  } finally {
    if (spinIcon) spinIcon.classList.remove("animate-spin");
  }
}

// ---------------------------------------------------------------------------
// PAGE 2: SECURITY EVENTS EXPLORER
// ---------------------------------------------------------------------------
async function loadSecurityEvents(page = 0, isManual = false) {
  const spinIcon = document.getElementById("sec-events-refresh-icon");
  if (spinIcon) spinIcon.classList.add("animate-spin");

  secCurrentEventsPage = page;
  const offset = page * SEC_PAGE_SIZE;

  const cgnatIp = document.getElementById("sec-filter-cgnat-ip")?.value.trim() || "";
  const publicIp = document.getElementById("sec-filter-public-ip")?.value.trim() || "";
  const severity = document.getElementById("sec-filter-severity")?.value || "";
  const category = document.getElementById("sec-filter-category")?.value || "";
  const attrStatus = document.getElementById("sec-filter-attr-status")?.value || "";

  let url = `/api/security/events?limit=${SEC_PAGE_SIZE}&offset=${offset}`;
  if (cgnatIp) url += `&cgnat_ip=${encodeURIComponent(cgnatIp)}`;
  if (publicIp) url += `&public_ip=${encodeURIComponent(publicIp)}`;
  if (severity) url += `&severity=${encodeURIComponent(severity)}`;
  if (category) url += `&category=${encodeURIComponent(category)}`;
  if (attrStatus) url += `&attribution_status=${encodeURIComponent(attrStatus)}`;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(url, { headers: authHeaders, credentials: "include" });
    const data = res.ok ? await res.json() : { events: [], total: 0 };
    const eventList = Array.isArray(data?.events) ? data.events : [];
    const tbody = document.getElementById("sec-events-tbody");

    if (tbody) {
      if (eventList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center py-8 text-slate-400 text-xs">No matching security events found</td></tr>`;
      } else {
        tbody.innerHTML = eventList.map(ev => {
          const sevColor = ev.severity === "critical" ? "bg-rose-500/20 text-rose-300 border-rose-500/30" :
                           ev.severity === "high" ? "bg-amber-500/20 text-amber-300 border-amber-500/30" :
                           ev.severity === "medium" ? "bg-blue-500/20 text-blue-300 border-blue-500/30" : "bg-slate-700 text-slate-300 border-slate-600";

          const attrColor = ev.attribution_status === "verified" ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" :
                            ev.attribution_status === "high_confidence" ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/30" :
                            ev.attribution_status === "partial" ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-rose-500/20 text-rose-300 border-rose-500/30";

          return `
            <tr class="hover:bg-dark-800/60 border-b border-slate-800/80 transition-colors">
              <td class="py-2 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">${formatManilaTime(ev.event_timestamp)}</td>
              <td class="py-2 px-3"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${sevColor}">${ev.severity}</span></td>
              <td class="py-2 px-3 text-xs font-medium text-slate-200">${ev.signature_name || ev.category}</td>
              <td class="py-2 px-3 font-mono text-xs text-brand-300 whitespace-nowrap">
                <span class="hover:underline cursor-pointer" onclick="openSubscriberProfile('${ev.subscriber_cgnat_ip}')">${ev.subscriber_cgnat_ip || '—'}</span>
                ${ev.subscriber_cgnat_ip ? `<button onclick="copyToClipboard('${ev.subscriber_cgnat_ip}', 'CGNAT IP')" title="Copy CGNAT IP" class="ml-1 text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3 h-3 inline"></i></button>` : ''}
              </td>
              <td class="py-2 px-3 font-mono text-xs text-cyan-300 whitespace-nowrap">
                ${ev.pppoe_username || '—'}
                ${ev.pppoe_username ? `<button onclick="copyToClipboard('${ev.pppoe_username}', 'Username')" title="Copy Username" class="ml-1 text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3 h-3 inline"></i></button>` : ''}
              </td>
              <td class="py-2 px-3 font-mono text-xs text-slate-300 whitespace-nowrap">${ev.source_ip}:${ev.source_port || ''}</td>
              <td class="py-2 px-3 font-mono text-xs text-slate-400 uppercase">${ev.protocol}</td>
              <td class="py-2 px-3 font-mono text-xs text-slate-300 whitespace-nowrap">${ev.destination_ip}:${ev.destination_port || ''}</td>
              <td class="py-2 px-3"><span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase border ${attrColor}">${ev.attribution_status.replace('_', ' ')}</span></td>
              <td class="py-2 px-3 text-right">
                <button onclick="viewRawEventModal('${ev.event_id}')" class="px-2 py-1 rounded bg-dark-800 hover:bg-dark-750 text-slate-300 hover:text-white text-[11px] border border-slate-700/80">Raw EVE</button>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    // Pagination info
    const pageInfo = document.getElementById("sec-events-page-info");
    if (pageInfo) {
      const start = offset + 1;
      const end = Math.min(offset + SEC_PAGE_SIZE, data.total);
      pageInfo.innerText = data.total > 0 ? `Showing ${start}-${end} of ${data.total} events` : "0 events";
    }

    if (window.lucide) lucide.createIcons();
    if (isManual) {
      showSecurityToast("Security events refreshed", "success");
    }
  } catch (e) {
    console.error("Error loading security events:", e);
    if (isManual) {
      showSecurityToast("Failed to refresh events: " + e.message, "error");
    }
  } finally {
    if (spinIcon) spinIcon.classList.remove("animate-spin");
  }
}

// ---------------------------------------------------------------------------
// PAGE 3: CGNAT ATTRIBUTION SEARCH (ABUSE INVESTIGATION TOOL)
// ---------------------------------------------------------------------------
async function performCGNATAttributionSearch() {
  const pubIp = document.getElementById("cgnat-search-public-ip")?.value.trim();
  const pubPortStr = document.getElementById("cgnat-search-public-port")?.value.trim();
  const proto = document.getElementById("cgnat-search-proto")?.value || "tcp";
  const timestamp = document.getElementById("cgnat-search-timestamp")?.value.trim() || new Date().toISOString();

  if (!pubIp) {
    alert("Please enter the public IP address from the external abuse complaint.");
    return;
  }

  const pubPort = pubPortStr ? parseInt(pubPortStr, 10) : null;
  const payload = {
    public_ip: pubIp,
    public_port: pubPort,
    protocol: proto,
    timestamp: timestamp
  };

  const btn = document.getElementById("btn-cgnat-lookup");
  if (btn) btn.disabled = true;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/cgnat/lookup", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(payload),
      credentials: "include"
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Server responded with ${res.status}`);
    }

    const data = await res.json();
    renderAttributionResult(data);
  } catch (e) {
    console.error("Attribution search failed:", e);
    alert("Attribution search failed: " + e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderAttributionResult(res) {
  const resultCard = document.getElementById("cgnat-result-card");
  if (!resultCard) return;

  if (!res || !res.attribution_status) {
    alert("No attribution record found for the specified query.");
    return;
  }

  resultCard.classList.remove("hidden");

  // Status badge styling
  const statusEl = document.getElementById("cgnat-res-status");
  const isVerified = res.attribution_status === "verified";
  const isHighConf = res.attribution_status === "high_confidence";
  const isPartial = res.attribution_status === "partial";
  const isConflict = res.attribution_status === "conflict";

  const colorClass = isVerified ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40" :
                     isHighConf ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40" :
                     isPartial ? "bg-amber-500/20 text-amber-300 border-amber-500/40" : "bg-rose-500/20 text-rose-300 border-rose-500/40";

  statusEl.className = `px-2.5 py-1 rounded text-xs font-bold uppercase border ${colorClass}`;
  statusEl.innerText = (res.attribution_status || "UNKNOWN").replace('_', ' ');

  // Values
  document.getElementById("cgnat-res-sub-ip").innerText = res.subscriber_cgnat_ip || "UNRESOLVED";
  document.getElementById("cgnat-res-username").innerText = res.pppoe_username || "UNRECORDED";
  document.getElementById("cgnat-res-port-block").innerText = res.port_block_range || "N/A";
  document.getElementById("cgnat-res-validity").innerText = res.mapping_effective_from ? `${res.mapping_effective_from} to ${res.mapping_effective_to || 'Present'}` : "N/A";
  document.getElementById("cgnat-res-explanation").innerText = res.confidence_explanation || "";

  // Enable/disable copy buttons
  const copyIpBtn = document.getElementById("btn-copy-cgnat-ip");
  if (copyIpBtn) {
    copyIpBtn.onclick = () => copyToClipboard(res.subscriber_cgnat_ip, "CGNAT IP");
    copyIpBtn.disabled = !res.subscriber_cgnat_ip;
  }

  const copyUserBtn = document.getElementById("btn-copy-pppoe-user");
  if (copyUserBtn) {
    copyUserBtn.onclick = () => copyToClipboard(res.pppoe_username, "PPPoE Username");
    copyUserBtn.disabled = !res.pppoe_username;
  }

  // View profile button
  const viewProfBtn = document.getElementById("btn-view-subscriber-profile");
  if (viewProfBtn) {
    viewProfBtn.onclick = () => openSubscriberProfile(res.subscriber_cgnat_ip);
    viewProfBtn.disabled = !res.subscriber_cgnat_ip;
  }

  if (window.lucide) lucide.createIcons();
}

function setAttributionTimestampNow() {
  const tsEl = document.getElementById("cgnat-search-timestamp");
  if (tsEl) tsEl.value = new Date().toISOString();
}

// ---------------------------------------------------------------------------
// PAGE 4: SUBSCRIBER SECURITY PROFILE
// ---------------------------------------------------------------------------
async function openSubscriberProfile(cgnatIp) {
  if (!cgnatIp || cgnatIp === "—") return;
  switchTab("sec-subscriber");
  const input = document.getElementById("sec-profile-search-ip");
  if (input) input.value = cgnatIp;
  await fetchSubscriberProfile(cgnatIp);
}

async function fetchSubscriberProfile(cgnatIp) {
  if (!cgnatIp) {
    cgnatIp = document.getElementById("sec-profile-search-ip")?.value.trim();
  }
  if (!cgnatIp) return;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/subscribers/${encodeURIComponent(cgnatIp)}`, { headers: authHeaders, credentials: "include" });
    const data = res.ok ? await res.json() : null;
    const prof = data?.profile;

    if (!prof) {
      document.getElementById("sec-prof-header-ip").innerText = cgnatIp;
      document.getElementById("sec-prof-header-user").innerText = "No Profile Found";
      return;
    }

    document.getElementById("sec-prof-header-ip").innerText = prof.subscriber_cgnat_ip || cgnatIp;
    document.getElementById("sec-prof-header-user").innerText = prof.current_username || "No Active Session Recorded";
    document.getElementById("sec-prof-total-events").innerText = prof.metrics?.total_security_events || 0;
    document.getElementById("sec-prof-total-bytes").innerText = ((prof.metrics?.total_bytes || 0) / 1000000).toFixed(2) + " MB";
    document.getElementById("sec-prof-total-pkts").innerText = (prof.metrics?.total_packets || 0).toLocaleString();

    // Copy buttons
    document.getElementById("btn-prof-copy-ip").onclick = () => copyToClipboard(prof.subscriber_cgnat_ip, "CGNAT IP");
    document.getElementById("btn-prof-copy-user").onclick = () => copyToClipboard(prof.current_username, "Username");

    // Session History
    const sessTbody = document.getElementById("sec-prof-sessions-tbody");
    if (sessTbody) {
      if (prof.sessions_history.length === 0) {
        sessTbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-slate-400 text-xs">No historical PPPoE sessions recorded</td></tr>`;
      } else {
        sessTbody.innerHTML = prof.sessions_history.map(s => `
          <tr class="border-b border-slate-800 text-xs">
            <td class="py-2 px-3 font-mono text-cyan-300 font-semibold">${s.pppoe_username}</td>
            <td class="py-2 px-3 font-mono text-slate-400">${s.access_concentrator}</td>
            <td class="py-2 px-3 font-mono text-slate-400">${formatManilaTime(s.started_at)}</td>
            <td class="py-2 px-3 font-mono text-slate-400">${s.ended_at ? formatManilaTime(s.ended_at) : 'Active / Present'}</td>
            <td class="py-2 px-3 text-slate-400 font-mono text-[11px]">${s.session_source}</td>
          </tr>
        `).join("");
      }
    }

    // Incidents History
    const incTbody = document.getElementById("sec-prof-incidents-tbody");
    if (incTbody) {
      if (prof.incidents.length === 0) {
        incTbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-slate-400 text-xs">No security incidents associated with this subscriber</td></tr>`;
      } else {
        incTbody.innerHTML = prof.incidents.map(inc => `
          <tr class="border-b border-slate-800 text-xs cursor-pointer hover:bg-dark-800/60" onclick="openIncidentDetailModal('${inc.incident_id}')">
            <td class="py-2 px-3 font-mono text-slate-400">${formatManilaTime(inc.last_seen)}</td>
            <td class="py-2 px-3 text-white font-medium">${inc.title}</td>
            <td class="py-2 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-700">${inc.severity}</span></td>
            <td class="py-2 px-3 font-mono text-slate-300">${inc.event_count}</td>
            <td class="py-2 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800">${inc.status}</span></td>
          </tr>
        `).join("");
      }
    }

    if (window.lucide) lucide.createIcons();
  } catch (e) {
    console.error("Error fetching subscriber profile:", e);
  }
}

// ---------------------------------------------------------------------------
// PAGE 5: INCIDENT MANAGEMENT
// ---------------------------------------------------------------------------
async function loadIncidentManagement(isManual = false) {
  const spinIcon = document.getElementById("sec-incidents-refresh-icon");
  if (spinIcon) spinIcon.classList.add("animate-spin");

  const status = document.getElementById("sec-inc-filter-status")?.value || "";
  const severity = document.getElementById("sec-inc-filter-severity")?.value || "";

  let url = "/api/security/incidents?limit=50";
  if (status) url += `&status=${encodeURIComponent(status)}`;
  if (severity) url += `&severity=${encodeURIComponent(severity)}`;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(url, { headers: authHeaders, credentials: "include" });
    const data = res.ok ? await res.json() : { incidents: [], total: 0 };
    const incList = Array.isArray(data?.incidents) ? data.incidents : [];
    const tbody = document.getElementById("sec-incidents-mgmt-tbody");

    if (tbody) {
      if (incList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-8 text-slate-400 text-xs">No incidents match current filter criteria</td></tr>`;
      } else {
        tbody.innerHTML = incList.map(inc => {
          const sevColor = inc.severity === "critical" ? "bg-rose-500/20 text-rose-300 border-rose-500/30" :
                           inc.severity === "high" ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-blue-500/20 text-blue-300 border-blue-500/30";

          return `
            <tr class="hover:bg-dark-800/60 border-b border-slate-800/80 transition-colors cursor-pointer" onclick="openIncidentDetailModal('${inc.incident_id}')">
              <td class="py-2.5 px-3 font-mono text-xs text-slate-400">${formatManilaTime(inc.last_seen)}</td>
              <td class="py-2.5 px-3 font-semibold text-xs text-white">${inc.title}</td>
              <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${sevColor}">${inc.severity}</span></td>
              <td class="py-2.5 px-3 font-mono text-xs text-brand-300">${inc.affected_subscriber_ip || '—'}</td>
              <td class="py-2.5 px-3 font-mono text-xs text-cyan-300">${inc.pppoe_username || '—'}</td>
              <td class="py-2.5 px-3 font-mono text-xs text-slate-300">${inc.event_count}</td>
              <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-700 text-slate-200">${inc.status}</span></td>
              <td class="py-2.5 px-3 text-right">
                <button onclick="event.stopPropagation(); openIncidentDetailModal('${inc.incident_id}')" class="px-2.5 py-1 rounded bg-brand-600 hover:bg-brand-500 text-white text-xs font-semibold">Investigate</button>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    if (window.lucide) lucide.createIcons();
    if (isManual) {
      showSecurityToast("Incidents refreshed", "success");
    }
  } catch (e) {
    console.error("Error loading incidents:", e);
    if (isManual) {
      showSecurityToast("Failed to refresh incidents: " + e.message, "error");
    }
  } finally {
    if (spinIcon) spinIcon.classList.remove("animate-spin");
  }
}

let activeModalIncidentId = null;

async function openIncidentDetailModal(incidentId) {
  activeModalIncidentId = incidentId;
  const modal = document.getElementById("modal-incident-detail");
  if (!modal) return;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/incidents/${incidentId}`, { headers: authHeaders, credentials: "include" });
    const data = res.ok ? await res.json() : null;
    const inc = data?.incident;
    const events = Array.isArray(data?.related_events) ? data.related_events : [];

    if (!inc) return;

    document.getElementById("modal-inc-title").innerText = inc.title;
    document.getElementById("modal-inc-id").innerText = inc.incident_id;
    document.getElementById("modal-inc-sub-ip").innerText = inc.affected_subscriber_ip || "—";
    document.getElementById("modal-inc-username").innerText = inc.pppoe_username || "Unrecorded";
    document.getElementById("modal-inc-pub-ip").innerText = inc.affected_public_ip || "—";
    document.getElementById("modal-inc-first-seen").innerText = formatManilaTime(inc.first_seen);
    document.getElementById("modal-inc-last-seen").innerText = formatManilaTime(inc.last_seen);
    document.getElementById("modal-inc-event-count").innerText = inc.event_count;
    document.getElementById("modal-inc-status-select").value = inc.status;
    document.getElementById("modal-inc-notes").value = inc.resolution_notes || "";

    // Copy buttons
    document.getElementById("btn-modal-copy-ip").onclick = () => copyToClipboard(inc.affected_subscriber_ip, "CGNAT IP");
    document.getElementById("btn-modal-copy-user").onclick = () => copyToClipboard(inc.pppoe_username, "PPPoE Username");

    // Events timeline
    const evtTbody = document.getElementById("modal-inc-events-tbody");
    if (evtTbody) {
      evtTbody.innerHTML = events.map(e => `
        <tr class="border-b border-slate-800 text-xs">
          <td class="py-1.5 px-2 font-mono text-slate-400">${formatManilaTime(e.event_timestamp)}</td>
          <td class="py-1.5 px-2 text-slate-200">${e.signature_name || e.category}</td>
          <td class="py-1.5 px-2 font-mono text-slate-300">${e.destination_ip}:${e.destination_port}</td>
          <td class="py-1.5 px-2 font-mono uppercase text-slate-400">${e.protocol}</td>
          <td class="py-1.5 px-2 font-mono text-cyan-300">${e.attribution_status}</td>
        </tr>
      `).join("");
    }

    modal.classList.remove("hidden");
    if (window.lucide) lucide.createIcons();
  } catch (e) {
    console.error("Error loading incident detail:", e);
  }
}

function closeIncidentDetailModal() {
  const modal = document.getElementById("modal-incident-detail");
  if (modal) modal.classList.add("hidden");
  activeModalIncidentId = null;
}

async function saveIncidentStatusUpdate() {
  if (!activeModalIncidentId) return;

  const newStatus = document.getElementById("modal-inc-status-select").value;
  const notes = document.getElementById("modal-inc-notes").value.trim();

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/incidents/${activeModalIncidentId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({
        status: newStatus,
        resolution_notes: notes
      }),
      credentials: "include"
    });

    const data = await res.json();
    if (!res.ok) {
      alert(data.detail || "Failed to update incident status");
      return;
    }

    showSecurityToast(`Incident status updated to ${newStatus}`);
    closeIncidentDetailModal();
    loadIncidentManagement();
  } catch (e) {
    alert("Update error: " + e.message);
  }
}

// ---------------------------------------------------------------------------
// PAGE 6: TRAFFIC ANALYTICS (AKVORADO FLOWS)
// ---------------------------------------------------------------------------
async function loadTrafficAnalytics(isManual = false) {
  const refreshBtn = document.getElementById("btn-sec-traffic-refresh") || document.querySelector('button[onclick*="loadTrafficAnalytics"]');
  const spinIcon = refreshBtn ? refreshBtn.querySelector("svg, i") : document.getElementById("sec-traffic-refresh-icon");
  if (spinIcon) spinIcon.classList.add("animate-spin");
  if (refreshBtn) refreshBtn.disabled = true;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const winSelect = document.getElementById("sec-traffic-window-select");
    const windowMinutes = winSelect ? parseInt(winSelect.value, 10) || 60 : 60;

    const res = await fetch(`/api/security/traffic/overview?window_minutes=${windowMinutes}`, {
      headers: authHeaders,
      credentials: "include"
    });

    if (res.status === 401) {
      if (typeof showToast === "function") showToast("Please sign in to view flow analytics", "error");
      return;
    }

    const data = res.ok ? await res.json() : { analytics: {} };
    const an = data.analytics || {};
    const kpis = an.kpis || {};
    const topSubs = Array.isArray(an.top_subscribers) ? an.top_subscribers : [];
    const topPubs = Array.isArray(an.top_public_ips) ? an.top_public_ips : [];
    const protos = Array.isArray(an.protocols) ? an.protocols : [];
    const ports = Array.isArray(an.top_destination_ports) ? an.top_destination_ports : [];
    const obs = an.observation_points || {};
    const collector = an.collector || {};

    // 1. KPI Cards
    const totalBytes = kpis.total_bytes || 0;
    const bytesFormatted = totalBytes >= 1_000_000_000
      ? (totalBytes / 1_000_000_000).toFixed(2) + " GB"
      : (totalBytes / 1_000_000).toFixed(2) + " MB";

    const kpiBytesEl = document.getElementById("sec-traffic-kpi-bytes");
    const kpiMbpsEl = document.getElementById("sec-traffic-kpi-mbps");
    const kpiFlowsEl = document.getElementById("sec-traffic-kpi-flows");
    const kpiSubsEl = document.getElementById("sec-traffic-kpi-subs");

    if (kpiBytesEl) kpiBytesEl.innerText = bytesFormatted;
    if (kpiMbpsEl) kpiMbpsEl.innerText = `${kpis.avg_throughput_mbps || 0.00} Mbps`;
    if (kpiFlowsEl) kpiFlowsEl.innerText = (kpis.total_flows || 0).toLocaleString();
    if (kpiSubsEl) kpiSubsEl.innerText = kpis.active_subscribers_count || topSubs.length;

    // 2. Collector Status
    const collectorModeEl = document.getElementById("sec-traffic-collector-mode");
    if (collectorModeEl) {
      collectorModeEl.innerText = collector.status === "online" ? "Akvorado Live" : "NetFlow Engine Active";
    }

    // 3. Top Subscribers Table
    const subTbody = document.getElementById("sec-traffic-top-sub-tbody");
    if (subTbody) {
      if (topSubs.length === 0) {
        subTbody.innerHTML = `
          <tr>
            <td colspan="5" class="text-center py-8 text-slate-400">
              <div class="flex flex-col items-center justify-center gap-2">
                <i data-lucide="activity" class="w-7 h-7 text-slate-600"></i>
                <span class="text-xs font-semibold">No subscriber NetFlow records in this time window</span>
                <p class="text-[11px] text-slate-500 max-w-sm text-center">Export IPFIX from your MikroTik routers or simulate flow telemetry to view active distributions.</p>
                <div class="flex gap-2 mt-2">
                  <button onclick="simulateTrafficFlows()" class="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-semibold flex items-center gap-1.5">
                    <i data-lucide="sparkles" class="w-3 h-3"></i> Simulate Carrier Flows
                  </button>
                  <button onclick="openMikroTikFlowModal()" class="px-3 py-1.5 rounded-lg bg-dark-800 hover:bg-dark-750 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5">
                    <i data-lucide="terminal" class="w-3 h-3 text-cyan-400"></i> MikroTik Guide
                  </button>
                </div>
              </div>
            </td>
          </tr>
        `;
      } else {
        subTbody.innerHTML = topSubs.map((s, idx) => {
          const volFormatted = (s.total_bytes || 0) >= 1_000_000_000
            ? ((s.total_bytes || 0) / 1_000_000_000).toFixed(2) + " GB"
            : ((s.total_bytes || 0) / 1_000_000).toFixed(2) + " MB";

          return `
            <tr class="hover:bg-dark-800/60 border-b border-slate-800/80 text-xs transition-colors">
              <td class="py-2.5 px-3 font-mono font-bold text-slate-500">#${idx + 1}</td>
              <td class="py-2.5 px-3 font-mono text-xs">
                <div class="flex items-center gap-1.5">
                  <span class="text-brand-300 font-semibold cursor-pointer hover:underline" onclick="openSubscriberProfile('${s.subscriber_cgnat_ip}')">${s.subscriber_cgnat_ip}</span>
                  <button onclick="copyToClipboard('${s.subscriber_cgnat_ip}', 'CGNAT IP')" class="text-slate-500 hover:text-white p-0.5" title="Copy IP"><i data-lucide="copy" class="w-3 h-3 inline"></i></button>
                </div>
                <div class="text-[10px] text-slate-400 font-sans">${s.pppoe_username || '—'}</div>
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-200 font-semibold">${volFormatted}</td>
              <td class="py-2.5 px-3 font-mono text-slate-400">${(s.total_packets || 0).toLocaleString()}</td>
              <td class="py-2.5 px-3 font-mono">
                <span class="text-emerald-400 font-bold">${s.mbps_rate || 0.00} Mbps</span>
                <div class="w-16 bg-dark-900 h-1 rounded-full mt-1 overflow-hidden">
                  <div class="bg-emerald-500 h-full rounded-full" style="width: ${Math.min(100, (s.percentage || 0))}%"></div>
                </div>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    // 4. Top Public CGNAT IPs Table
    const pubTbody = document.getElementById("sec-traffic-top-pub-tbody");
    if (pubTbody) {
      if (topPubs.length === 0) {
        pubTbody.innerHTML = `
          <tr>
            <td colspan="5" class="text-center py-8 text-slate-400">
              <div class="flex flex-col items-center justify-center gap-1.5">
                <i data-lucide="globe" class="w-6 h-6 text-slate-600"></i>
                <span class="text-xs">No public CGNAT pool egress traffic recorded</span>
              </div>
            </td>
          </tr>
        `;
      } else {
        pubTbody.innerHTML = topPubs.map((p, idx) => {
          const volFormatted = (p.total_bytes || 0) >= 1_000_000_000
            ? ((p.total_bytes || 0) / 1_000_000_000).toFixed(2) + " GB"
            : ((p.total_bytes || 0) / 1_000_000).toFixed(2) + " MB";

          const poolBadge = p.is_cgnat_pool
            ? `<span class="ml-1 px-1.5 py-0.2 rounded text-[9px] font-bold uppercase bg-cyan-600/20 text-cyan-300 border border-cyan-500/30">Pool IP</span>`
            : '';

          return `
            <tr class="hover:bg-dark-800/60 border-b border-slate-800/80 text-xs transition-colors">
              <td class="py-2.5 px-3 font-mono font-bold text-slate-500">#${idx + 1}</td>
              <td class="py-2.5 px-3 font-mono text-cyan-300 font-semibold">
                <div class="flex items-center gap-1.5">
                  <span>${p.public_ip}</span>
                  <button onclick="copyToClipboard('${p.public_ip}', 'Public IP')" class="text-slate-500 hover:text-white p-0.5" title="Copy IP"><i data-lucide="copy" class="w-3 h-3 inline"></i></button>
                  ${poolBadge}
                </div>
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-200 font-semibold">${volFormatted}</td>
              <td class="py-2.5 px-3 font-mono text-slate-400">${(p.event_count || 0).toLocaleString()}</td>
              <td class="py-2.5 px-3 font-mono text-slate-300">
                <span>${p.percentage || 0}%</span>
                <div class="w-16 bg-dark-900 h-1 rounded-full mt-1 overflow-hidden">
                  <div class="bg-cyan-500 h-full rounded-full" style="width: ${Math.min(100, (p.percentage || 0))}%"></div>
                </div>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    // 5. Protocol Breakdown
    const protoContainer = document.getElementById("sec-traffic-protocols");
    if (protoContainer) {
      if (protos.length === 0) {
        protoContainer.innerHTML = `<p class="text-xs text-slate-400 py-4 text-center">No protocol distributions recorded in this window</p>`;
      } else {
        const protoColors = {
          TCP: "bg-blue-500",
          UDP: "bg-emerald-500",
          ICMP: "bg-amber-500",
          GRE: "bg-purple-500",
          ESP: "bg-indigo-500"
        };

        protoContainer.innerHTML = protos.map(p => {
          const protoName = p.protocol || "OTHER";
          const colorClass = protoColors[protoName.toUpperCase()] || "bg-brand-500";
          const volFormatted = (p.bytes || 0) >= 1_000_000_000
            ? ((p.bytes || 0) / 1_000_000_000).toFixed(2) + " GB"
            : ((p.bytes || 0) / 1_000_000).toFixed(2) + " MB";

          return `
            <div class="space-y-1">
              <div class="flex justify-between text-xs font-mono">
                <span class="text-white font-bold flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full ${colorClass}"></span>
                  ${protoName}
                </span>
                <span class="text-slate-400">${volFormatted} (${p.percentage || 0}%) · ${(p.count || 0).toLocaleString()} flows</span>
              </div>
              <div class="w-full bg-dark-900 h-2 rounded-full overflow-hidden border border-slate-800">
                <div class="${colorClass} h-full rounded-full transition-all duration-500" style="width: ${Math.min(100, p.percentage || 0)}%"></div>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    // 6. Top Destination Ports & Services
    const portsContainer = document.getElementById("sec-traffic-ports");
    if (portsContainer) {
      if (ports.length === 0) {
        portsContainer.innerHTML = `<p class="text-xs text-slate-400 py-4 text-center">No destination port classifications available</p>`;
      } else {
        portsContainer.innerHTML = ports.map(pt => {
          const volFormatted = (pt.bytes || 0) >= 1_000_000_000
            ? ((pt.bytes || 0) / 1_000_000_000).toFixed(2) + " GB"
            : ((pt.bytes || 0) / 1_000_000).toFixed(2) + " MB";

          return `
            <div class="flex items-center justify-between p-2 rounded-xl bg-dark-900/70 border border-slate-800/80 text-xs hover:border-slate-700 transition-colors">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono text-[10px] font-bold">:${pt.port}</span>
                <span class="text-slate-200 font-semibold text-[11px]">${pt.service}</span>
              </div>
              <div class="text-right font-mono">
                <div class="text-slate-300 font-bold text-[11px]">${volFormatted}</div>
                <div class="text-[10px] text-slate-500">${(pt.hits || 0).toLocaleString()} flows (${pt.percentage || 0}%)</div>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    // 7. Observation Points Balance
    const obsDetailEl = document.getElementById("sec-traffic-obs-detail");
    if (obsDetailEl) {
      const pre = obs.pre_cgnat || {};
      const post = obs.post_cgnat || {};
      const preMB = ((pre.bytes || 0) / 1_000_000).toFixed(1);
      const postMB = ((post.bytes || 0) / 1_000_000).toFixed(1);
      obsDetailEl.innerHTML = `Pre-CGNAT Switch Mirror: <strong>${preMB} MB</strong> (${pre.count || 0} flows) | Post-CGNAT Border TAP: <strong>${postMB} MB</strong> (${post.count || 0} flows)`;
    }

    const genAtEl = document.getElementById("sec-traffic-generated-at");
    if (genAtEl) {
      genAtEl.innerText = `Updated: ${formatManilaTime(an.generated_at || new Date().toISOString())}`;
    }

    if (window.lucide) lucide.createIcons();

    if (isManual && typeof showToast === "function") {
      showToast("Traffic flow analytics refreshed", "success");
    }
  } catch (e) {
    console.error("Error loading traffic analytics:", e);
    if (isManual) {
      showSecurityToast("Failed to refresh traffic analytics: " + e.message, "error");
    }
  } finally {
    const currentBtn = document.getElementById("btn-sec-traffic-refresh") || document.querySelector('button[onclick*="loadTrafficAnalytics"]');
    if (currentBtn) {
      currentBtn.disabled = false;
      const allIcons = currentBtn.querySelectorAll("svg, i, .lucide-refresh-cw");
      allIcons.forEach(ic => ic.classList.remove("animate-spin"));
    }
    const rawIcon = document.getElementById("sec-traffic-refresh-icon");
    if (rawIcon) rawIcon.classList.remove("animate-spin");
    if (spinIcon) spinIcon.classList.remove("animate-spin");
  }
}

// SIMULATE CARRIER FLOWS TRIGGER
async function simulateTrafficFlows() {
  const btn = document.getElementById("btn-sec-traffic-simulate");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="refresh-cw" class="w-3.5 h-3.5 animate-spin"></i> Generating Flows...`;
    if (window.lucide) lucide.createIcons();
  }

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/traffic/simulate?count=160", {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      credentials: "include"
    });

    if (res.status === 401) {
      if (typeof showToast === "function") showToast("Please sign in to generate telemetry", "error");
      return;
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    if (typeof showToast === "function") {
      showToast(data.message || `Generated ${data.flows_generated} flow records.`, "success");
    }

    await loadTrafficAnalytics(false);
  } catch (err) {
    console.error("Failed to simulate flows:", err);
    if (typeof showToast === "function") {
      showToast("Flow generation failed: " + err.message, "error");
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="sparkles" class="w-3.5 h-3.5 text-emerald-400"></i> Simulate Flows`;
      if (window.lucide) lucide.createIcons();
    }
  }
}

// MIKROTIK FLOW SCRIPT MODAL
async function openMikroTikFlowModal() {
  const modal = document.getElementById("modal-mikrotik-flow");
  if (!modal) return;
  modal.classList.remove("hidden");
  await updateMikroTikFlowSnippet();
  if (window.lucide) lucide.createIcons();
}

function closeMikroTikFlowModal() {
  const modal = document.getElementById("modal-mikrotik-flow");
  if (modal) modal.classList.add("hidden");
}

async function updateMikroTikFlowSnippet() {
  const ipInput = document.getElementById("flow-modal-collector-ip");
  const portInput = document.getElementById("flow-modal-port");
  const preEl = document.getElementById("flow-modal-script-pre");

  const collectorIp = (ipInput && ipInput.value.trim()) || "10.0.0.50";
  const port = (portInput && portInput.value.trim()) || "2055";

  if (preEl) {
    preEl.innerText = `# ===============================================================
# WISPnet & Akvorado NetFlow v9 / IPFIX Flow Export Configuration
# Execute directly in MikroTik RouterOS v7 Terminal (WinBox / SSH)
# ===============================================================

# 1. Enable Traffic-Flow Collector Engine
/ip traffic-flow set enabled=yes active-flow-timeout=1m inactive-flow-timeout=15s cache-entries=128k

# 2. Add Akvorado / WISPnet Flow Collector Target
/ip traffic-flow target add name="akvorado-collector" dst-address=${collectorIp} port=${port} version=ipfix

# 3. Enable Flow Sampling on WAN and Subscriber Interfaces
/ip traffic-flow set interfaces=all

# 4. Verify Traffic-Flow Status
/ip traffic-flow print
/ip traffic-flow target print`;
  }
}

function copyMikroTikFlowSnippet() {
  const preEl = document.getElementById("flow-modal-script-pre");
  if (preEl && typeof copyToClipboard === "function") {
    copyToClipboard(preEl.innerText, "MikroTik Flow Script");
  } else if (preEl) {
    navigator.clipboard.writeText(preEl.innerText);
    if (typeof showToast === "function") showToast("Copied script to clipboard", "success");
  }
}

// ---------------------------------------------------------------------------
// PAGE 7: DETECTION RULES
// ---------------------------------------------------------------------------
async function loadDetectionRules() {
  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/rules", { headers: authHeaders, credentials: "include" });
    const rules = res.ok ? await res.json() : [];
    const ruleList = Array.isArray(rules) ? rules : [];
    const tbody = document.getElementById("sec-rules-tbody");

    if (tbody) {
      if (ruleList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400">No detection rules found</td></tr>`;
      } else {
        tbody.innerHTML = ruleList.map(r => `
          <tr class="border-b border-slate-800 text-xs">
            <td class="py-2.5 px-3">
              <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRuleEnabled('${r.rule_id}', this.checked)" class="rounded bg-dark-800 border-slate-700 text-brand-500 focus:ring-0">
            </td>
            <td class="py-2.5 px-3 font-semibold text-white">${r.name}</td>
            <td class="py-2.5 px-3 font-mono text-slate-400">${r.category}</td>
            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-700">${r.severity}</span></td>
            <td class="py-2.5 px-3 font-mono text-slate-300">${r.time_window_seconds}s</td>
            <td class="py-2.5 px-3 font-mono text-slate-400 text-[11px]">${JSON.stringify(r.threshold_configuration)}</td>
            <td class="py-2.5 px-3 text-right">
              <button onclick="testRuleAgainstHistory('${r.rule_id}')" class="px-2 py-1 rounded bg-dark-800 hover:bg-dark-750 text-cyan-300 text-[11px] border border-slate-700 mr-1">Test Rule</button>
            </td>
          </tr>
        `).join("");
      }
    }
  } catch (e) {
    console.error("Error loading detection rules:", e);
  }
}

async function toggleRuleEnabled(ruleId, isEnabled) {
  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    await fetch(`/api/security/rules/${ruleId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify({ enabled: isEnabled }),
      credentials: "include"
    });
    showSecurityToast(`Rule ${isEnabled ? 'enabled' : 'disabled'}`);
  } catch (e) {
    alert("Error updating rule: " + e.message);
  }
}

async function testRuleAgainstHistory(ruleId) {
  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/rules/${ruleId}/test`, {
      method: "POST",
      headers: authHeaders,
      credentials: "include"
    });
    const data = await res.json();
    alert(`Rule Test Results:\n• Rule: ${data.rule_name}\n• Historical Events Scanned: ${data.events_tested}\n• Matches Triggered: ${data.matched_count}`);
  } catch (e) {
    alert("Rule test failed: " + e.message);
  }
}

// ---------------------------------------------------------------------------
// PAGE 8: SENSOR & INTEGRATION HEALTH
// ---------------------------------------------------------------------------
async function loadSensorHealth(isManual = false) {
  const spinIcon = document.getElementById("sec-health-refresh-icon");
  if (spinIcon) spinIcon.classList.add("animate-spin");

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/health", { headers: authHeaders, credentials: "include" });
    const data = res.ok ? await res.json() : { integrations: [], sensors: [] };
    const integrations = Array.isArray(data.integrations) ? data.integrations : [];
    const sensors = Array.isArray(data.sensors) ? data.sensors : [];

    // 1. Update KPI Summary Cards
    const kpiStatus = document.getElementById("sec-health-kpi-status");
    const kpiBadge = document.getElementById("sec-health-kpi-badge");
    const kpiStatusSub = document.getElementById("sec-health-kpi-status-sub");
    const kpiSensors = document.getElementById("sec-health-kpi-sensors");
    const kpiIntegrations = document.getElementById("sec-health-kpi-integrations");
    const kpiQueue = document.getElementById("sec-health-kpi-queue");

    const overall = (data.overall_status || "healthy").toLowerCase();
    if (kpiStatus) {
      if (overall === "healthy") {
        kpiStatus.textContent = "Operational";
        kpiStatus.className = "text-xl font-bold font-mono text-emerald-400 flex items-center gap-2";
        if (kpiBadge) kpiBadge.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse";
        if (kpiStatusSub) kpiStatusSub.textContent = "Carrier Pipeline Active";
      } else if (overall === "degraded") {
        kpiStatus.textContent = "Degraded";
        kpiStatus.className = "text-xl font-bold font-mono text-amber-400 flex items-center gap-2";
        if (kpiBadge) kpiBadge.className = "w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse";
        if (kpiStatusSub) kpiStatusSub.textContent = "Check Subsystem Warnings";
      } else {
        kpiStatus.textContent = "Offline";
        kpiStatus.className = "text-xl font-bold font-mono text-rose-400 flex items-center gap-2";
        if (kpiBadge) kpiBadge.className = "w-2.5 h-2.5 rounded-full bg-rose-400";
        if (kpiStatusSub) kpiStatusSub.textContent = "Critical Pipeline Failure";
      }
    }

    if (kpiSensors) {
      const activeSensors = data.active_sensors_count !== undefined ? data.active_sensors_count : sensors.filter(s => s.health_status === "healthy").length;
      const totalSensors = data.total_sensors_count !== undefined ? data.total_sensors_count : sensors.length;
      kpiSensors.textContent = `${activeSensors} / ${totalSensors} Active`;
    }

    if (kpiIntegrations) {
      const onlineInts = data.online_integrations_count !== undefined ? data.online_integrations_count : integrations.filter(i => i.connectivity === "online").length;
      const totalInts = data.total_integrations_count !== undefined ? data.total_integrations_count : integrations.length;
      kpiIntegrations.textContent = `${onlineInts} / ${totalInts} Connected`;
    }

    if (kpiQueue) {
      const qDepth = data.opensearch_queue_depth !== undefined ? data.opensearch_queue_depth : 0;
      kpiQueue.textContent = `${qDepth} docs`;
    }

    // 2. Update Carrier Pipeline Architecture Nodes
    const nodes = data.pipeline_nodes || {};
    if (nodes.pre_cgnat) {
      const preStatus = document.getElementById("pipe-node-pre-cgnat-status");
      const preMeta = document.getElementById("pipe-node-pre-cgnat-meta");
      const isOk = nodes.pre_cgnat.status === "healthy";
      if (preStatus) preStatus.className = `w-2.5 h-2.5 rounded-full ${isOk ? 'bg-emerald-400' : 'bg-amber-400'}`;
      if (preMeta) preMeta.textContent = isOk ? `${nodes.pre_cgnat.sensors_count || 1} Mirror TAP Active` : 'TAP Inactive';
    }
    if (nodes.core_gateway) {
      const coreStatus = document.getElementById("pipe-node-core-status");
      const coreMeta = document.getElementById("pipe-node-core-meta");
      const isOk = nodes.core_gateway.status === "online";
      if (coreStatus) coreStatus.className = `w-2.5 h-2.5 rounded-full ${isOk ? 'bg-emerald-400' : 'bg-amber-400'}`;
      if (coreMeta) coreMeta.textContent = isOk ? `CCR2116 (${nodes.core_gateway.lag_ms || 0}ms)` : 'Gateway Degraded';
    }
    if (nodes.post_cgnat) {
      const postStatus = document.getElementById("pipe-node-post-cgnat-status");
      const postMeta = document.getElementById("pipe-node-post-cgnat-meta");
      const isOk = nodes.post_cgnat.status === "healthy";
      if (postStatus) postStatus.className = `w-2.5 h-2.5 rounded-full ${isOk ? 'bg-emerald-400' : 'bg-amber-400'}`;
      if (postMeta) postMeta.textContent = isOk ? `${nodes.post_cgnat.sensors_count || 1} WAN TAP Active` : 'TAP Inactive';
    }
    if (nodes.correlation_engine) {
      const corrStatus = document.getElementById("pipe-node-correlation-status");
      if (corrStatus) corrStatus.className = `w-2.5 h-2.5 rounded-full ${overall !== 'offline' ? 'bg-emerald-400' : 'bg-rose-400'}`;
    }
    if (nodes.opensearch_queue) {
      const osStatus = document.getElementById("pipe-node-opensearch-status");
      const osMeta = document.getElementById("pipe-node-opensearch-meta");
      const q = nodes.opensearch_queue.queue_depth || 0;
      if (osStatus) osStatus.className = `w-2.5 h-2.5 rounded-full ${nodes.opensearch_queue.status === 'online' ? 'bg-emerald-400' : 'bg-amber-400'}`;
      if (osMeta) osMeta.textContent = q > 0 ? `Buffering ${q} docs` : 'Durable Buffer 0';
    }

    // 3. Integrations list
    const intTbody = document.getElementById("sec-health-integrations-tbody");
    if (intTbody) {
      if (integrations.length === 0) {
        intTbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400">No integration health data recorded</td></tr>`;
      } else {
        intTbody.innerHTML = integrations.map(i => {
          const isOnline = i.connectivity === "online";
          const isDegraded = i.connectivity === "degraded";
          const badgeClass = isOnline
            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
            : (isDegraded ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30');
          const cleanName = encodeURIComponent(i.integration_name);
          const btnId = `btn-probe-${i.integration_name.replace(/[^a-zA-Z0-9_-]/g, '_')}`;

          return `
            <tr class="border-b border-slate-800 text-xs hover:bg-dark-800/40 transition-colors">
              <td class="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full ${isOnline ? 'bg-emerald-400' : (isDegraded ? 'bg-amber-400 animate-pulse' : 'bg-rose-400')}"></span>
                ${escapeHtml(i.integration_name)}
              </td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${badgeClass}">${i.connectivity}</span>
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-300">${(i.processing_lag_ms || 0).toFixed(1)} ms</td>
              <td class="py-2.5 px-3 font-mono text-slate-300">${i.queue_depth || 0}</td>
              <td class="py-2.5 px-3 font-mono text-slate-400">${formatManilaTime(i.last_successful_ingestion)}</td>
              <td class="py-2.5 px-3 text-slate-400 text-[11px] max-w-[200px] truncate" title="${escapeHtml(i.last_error || 'Nominal operational')}">
                ${escapeHtml(i.last_error || 'Nominal operational')}
              </td>
              <td class="py-2.5 px-3 text-right">
                <button onclick="probeSingleIntegration('${cleanName}')" id="${btnId}" class="px-2.5 py-1 rounded-md bg-dark-800 hover:bg-dark-750 border border-slate-700 hover:border-teal-500/50 text-[11px] font-semibold text-slate-200 hover:text-teal-300 inline-flex items-center gap-1 transition-all">
                  <i data-lucide="activity" class="w-3 h-3 text-teal-400"></i> Probe
                </button>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    // 4. Sensors list
    const sensTbody = document.getElementById("sec-health-sensors-tbody");
    if (sensTbody) {
      if (sensors.length === 0) {
        sensTbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-400">No sensors registered yet</td></tr>`;
      } else {
        sensTbody.innerHTML = sensors.map(s => {
          const isHealthy = s.health_status === "healthy";
          const obsBadge = s.observation_point === 'pre_cgnat'
            ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
            : (s.observation_point === 'post_cgnat' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'bg-purple-500/20 text-purple-300 border border-purple-500/30');
          const cleanId = encodeURIComponent(s.sensor_id);

          return `
            <tr class="border-b border-slate-800 text-xs hover:bg-dark-800/40 transition-colors">
              <td class="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                <i data-lucide="radio" class="w-3.5 h-3.5 ${isHealthy ? 'text-teal-400' : 'text-amber-400'}"></i>
                <div>
                  <div>${escapeHtml(s.sensor_name)}</div>
                  <div class="text-[10px] text-slate-500 font-mono">${escapeHtml(s.sensor_type || 'tap')} &bull; ${escapeHtml(s.version || 'v1.0')}</div>
                </div>
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-400">${escapeHtml(s.sensor_id)}</td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${obsBadge}">${s.observation_point}</span>
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-300">${escapeHtml(s.host)}:${escapeHtml(s.interface)}</td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase ${isHealthy ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}">${s.health_status}</span>
              </td>
              <td class="py-2.5 px-3 font-mono text-slate-400">${formatManilaTime(s.last_seen)}</td>
              <td class="py-2.5 px-3 text-right">
                <div class="inline-flex items-center gap-1.5 justify-end">
                  <button onclick="pingSensor('${cleanId}')" title="Send Heartbeat Ping" class="px-2 py-1 rounded bg-dark-800 hover:bg-dark-750 border border-slate-700 text-[11px] text-teal-400 hover:text-teal-300 flex items-center gap-1 transition-all">
                    <i data-lucide="heart" class="w-3 h-3"></i> Ping
                  </button>
                  <button onclick="deleteSensor('${cleanId}')" title="Delete Sensor Observation Point" class="px-2 py-1 rounded bg-dark-800 hover:bg-rose-900/30 border border-slate-700 hover:border-rose-700 text-[11px] text-rose-400 flex items-center gap-1 transition-all">
                    <i data-lucide="trash-2" class="w-3 h-3"></i>
                  </button>
                </div>
              </td>
            </tr>
          `;
        }).join("");
      }
    }

    if (window.lucide) lucide.createIcons();
    if (isManual) {
      showSecurityToast("Sensor health refreshed", "success");
    }
  } catch (e) {
    console.error("Error loading sensor health:", e);
    if (isManual) {
      showSecurityToast("Failed to refresh sensor health: " + e.message, "error");
    }
  } finally {
    if (spinIcon) spinIcon.classList.remove("animate-spin");
  }
}

async function probeAllIntegrations() {
  const btn = document.getElementById("btn-probe-all-health");
  const icon = document.getElementById("icon-probe-all");
  if (btn) btn.disabled = true;
  if (icon) icon.classList.add("animate-spin");

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/health/check-all", {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      credentials: "include"
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Probe check failed");
    }
    const data = await res.json();
    showSecurityToast(`Health check complete: ${data.online_integrations_count || 0}/${data.total_integrations_count || 5} subsystems operational`, "success");
    await loadSensorHealth(false);
  } catch (e) {
    console.error("Health probe error:", e);
    showSecurityToast("Health probe failed: " + e.message, "error");
  } finally {
    if (btn) btn.disabled = false;
    if (icon) icon.classList.remove("animate-spin");
  }
}

async function probeSingleIntegration(encodedName) {
  const name = decodeURIComponent(encodedName);
  const btnId = `btn-probe-${name.replace(/[^a-zA-Z0-9_-]/g, '_')}`;
  const btn = document.getElementById(btnId);
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="refresh-cw" class="w-3 h-3 animate-spin"></i> Probing...`;
  }

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/health/probe/${encodeURIComponent(name)}`, {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      credentials: "include"
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Probe request failed");
    }
    const result = await res.json();
    const st = result.probe?.status || "online";
    showSecurityToast(`${name} probe: ${st.toUpperCase()}`, st === "online" ? "success" : "warning");
    await loadSensorHealth(false);
  } catch (e) {
    console.error(`Probe error on ${name}:`, e);
    showSecurityToast(`Probe failed on ${name}: ${e.message}`, "error");
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<i data-lucide="activity" class="w-3 h-3 text-teal-400"></i> Probe`;
      if (window.lucide) lucide.createIcons();
    }
  }
}

function openAddSensorModal() {
  const modal = document.getElementById("modal-add-sensor");
  if (!modal) return;
  document.getElementById("modal-sensor-name").value = "";
  document.getElementById("modal-sensor-id").value = "";
  document.getElementById("modal-sensor-type").value = "suricata";
  document.getElementById("modal-sensor-obs-point").value = "pre_cgnat";
  document.getElementById("modal-sensor-host").value = "";
  document.getElementById("modal-sensor-interface").value = "";
  document.getElementById("modal-sensor-version").value = "Suricata 7.0.2";
  document.getElementById("modal-sensor-enabled").checked = true;
  modal.classList.remove("hidden");
  if (window.lucide) lucide.createIcons();
}

function closeAddSensorModal() {
  const modal = document.getElementById("modal-add-sensor");
  if (modal) modal.classList.add("hidden");
}

async function saveSensor(e) {
  e.preventDefault();
  const btn = document.getElementById("btn-save-sensor");
  if (btn) btn.disabled = true;

  const payload = {
    sensor_name: document.getElementById("modal-sensor-name").value.trim(),
    sensor_id: document.getElementById("modal-sensor-id").value.trim() || undefined,
    sensor_type: document.getElementById("modal-sensor-type").value,
    observation_point: document.getElementById("modal-sensor-obs-point").value,
    host: document.getElementById("modal-sensor-host").value.trim(),
    interface: document.getElementById("modal-sensor-interface").value.trim(),
    version: document.getElementById("modal-sensor-version").value.trim() || undefined,
    enabled: document.getElementById("modal-sensor-enabled").checked,
    health_status: "healthy"
  };

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/health/sensors", {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to register sensor");
    }

    showSecurityToast(`Sensor ${payload.sensor_name} registered successfully!`, "success");
    closeAddSensorModal();
    await loadSensorHealth(false);
  } catch (err) {
    showSecurityToast("Failed to register sensor: " + err.message, "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function pingSensor(encodedId) {
  const sensorId = decodeURIComponent(encodedId);
  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/health/sensors/${encodeURIComponent(sensorId)}/heartbeat`, {
      method: "POST",
      headers: { ...authHeaders, "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ health_status: "healthy" })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Heartbeat ping failed");
    }
    showSecurityToast(`Heartbeat sent to sensor ${sensorId}`, "success");
    await loadSensorHealth(false);
  } catch (err) {
    showSecurityToast("Ping failed: " + err.message, "error");
  }
}

async function deleteSensor(encodedId) {
  const sensorId = decodeURIComponent(encodedId);
  if (!confirm(`Are you sure you want to remove observation point sensor "${sensorId}"?`)) return;

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch(`/api/security/health/sensors/${encodeURIComponent(sensorId)}`, {
      method: "DELETE",
      headers: authHeaders,
      credentials: "include"
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to delete sensor");
    }
    showSecurityToast(`Sensor ${sensorId} removed successfully`, "success");
    await loadSensorHealth(false);
  } catch (err) {
    showSecurityToast("Failed to delete sensor: " + err.message, "error");
  }
}

// ---------------------------------------------------------------------------
// PAGE 9: SECURITY & CGNAT SETTINGS
// ---------------------------------------------------------------------------
async function loadSecuritySettings() {
  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/settings", { headers: authHeaders, credentials: "include" });
    const data = res.ok ? await res.json() : {};

    const cfg = data.cgnat_config || {};
    document.getElementById("sec-set-pub-start").value = cfg.public_pool_start || "";
    document.getElementById("sec-set-pub-end").value = cfg.public_pool_end || "";
    document.getElementById("sec-set-sub-start").value = cfg.subscriber_pool_start || "";
    document.getElementById("sec-set-port-block-size").value = cfg.port_block_size || 2048;
    document.getElementById("sec-set-first-port").value = cfg.first_eligible_port || 2048;
    document.getElementById("sec-set-last-port").value = cfg.last_eligible_port || 65535;

    document.getElementById("sec-set-core-host").value = data.core_router_host || "";
    document.getElementById("sec-set-core-user").value = data.core_router_username || "";
    document.getElementById("sec-set-ac-host").value = data.ac_router_host || "";
    document.getElementById("sec-set-ac-user").value = data.ac_router_username || "";

    const osModeEl = document.getElementById("sec-set-opensearch-mode");
    if (osModeEl) osModeEl.value = data.opensearch_mode || "auto";
    const osUrlEl = document.getElementById("sec-set-opensearch-url");
    if (osUrlEl) osUrlEl.value = data.opensearch_url || "http://localhost:9200";
    const osUserEl = document.getElementById("sec-set-opensearch-user");
    if (osUserEl) osUserEl.value = data.opensearch_username || "admin";
    const osPassEl = document.getElementById("sec-set-opensearch-pass");
    if (osPassEl) osPassEl.value = data.opensearch_password || "";

    document.getElementById("sec-set-webhook-url").value = data.notification_webhook_url || "";
    document.getElementById("sec-set-cooldown").value = data.alert_cooldown_minutes || 15;
  } catch (e) {
    console.error("Error loading security settings:", e);
  }
}

async function saveSecuritySettings(e) {
  if (e) e.preventDefault();
  const payload = {
    cgnat_config: {
      public_pool_start: document.getElementById("sec-set-pub-start").value.trim(),
      public_pool_end: document.getElementById("sec-set-pub-end").value.trim(),
      subscriber_pool_start: document.getElementById("sec-set-sub-start").value.trim(),
      port_block_size: parseInt(document.getElementById("sec-set-port-block-size").value, 10),
      first_eligible_port: parseInt(document.getElementById("sec-set-first-port").value, 10),
      last_eligible_port: parseInt(document.getElementById("sec-set-last-port").value, 10)
    },
    core_router_host: document.getElementById("sec-set-core-host").value.trim(),
    core_router_username: document.getElementById("sec-set-core-user").value.trim(),
    core_router_password: document.getElementById("sec-set-core-pass")?.value || "********",
    ac_router_host: document.getElementById("sec-set-ac-host").value.trim(),
    ac_router_username: document.getElementById("sec-set-ac-user").value.trim(),
    ac_router_password: document.getElementById("sec-set-ac-pass")?.value || "********",
    opensearch_mode: document.getElementById("sec-set-opensearch-mode")?.value || "auto",
    opensearch_url: document.getElementById("sec-set-opensearch-url").value.trim(),
    opensearch_username: document.getElementById("sec-set-opensearch-user")?.value.trim() || "admin",
    opensearch_password: document.getElementById("sec-set-opensearch-pass")?.value || "********",
    notification_webhook_url: document.getElementById("sec-set-webhook-url")?.value.trim() || null,
    alert_cooldown_minutes: parseInt(document.getElementById("sec-set-cooldown").value, 10)
  };

  try {
    const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
    const res = await fetch("/api/security/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body: JSON.stringify(payload),
      credentials: "include"
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Save failed");
    showSecurityToast("Settings saved successfully", "success");
  } catch (e) {
    alert("Error saving settings: " + e.message);
  }
}

function viewRawEventModal(eventId) {
  const authHeaders = typeof getAuthHeaders === "function" ? getAuthHeaders() : {};
  fetch(`/api/security/events/${eventId}`, { headers: authHeaders, credentials: "include" })
    .then(r => r.json())
    .then(data => {
      alert(`Raw Event Payload (${eventId}):\n\n` + (data.raw_payload || JSON.stringify(data.event, null, 2)));
    })
    .catch(err => alert("Error fetching event: " + err));
}
