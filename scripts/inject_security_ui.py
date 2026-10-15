"""
Injects WISPnet Security Platform HTML sections and modal into app/static/index.html
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
INDEX_HTML = BASE_DIR / "app" / "static" / "index.html"

security_html = """
    <!-- ========================================================= -->
    <!-- TAB: SECURITY OVERVIEW -->
    <!-- ========================================================= -->
    <section id="tab-sec-overview" class="tab-content hidden space-y-6">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 class="text-xl font-bold text-white flex items-center gap-2">
            <i data-lucide="shield-alert" class="w-6 h-6 text-rose-500"></i>
            WISPnet ISP Security Overview & Threat Intelligence
          </h2>
          <p class="text-xs text-slate-400 mt-1">Real-time threat monitoring, deterministic CGNAT attribution & subscriber correlation</p>
        </div>
        <div class="flex items-center gap-2">
          <button onclick="loadSecurityOverview()" class="px-3 py-1.5 rounded-lg bg-dark-800 hover:bg-dark-750 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-all">
            <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i> Refresh
          </button>
        </div>
      </div>

      <!-- Top KPI Cards -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div class="p-5 rounded-2xl bg-dark-850 border border-rose-500/30 bg-gradient-to-br from-rose-950/20 to-dark-850">
          <div class="flex items-center justify-between text-xs text-rose-400 font-semibold mb-2">
            <span>Critical Incidents</span>
            <i data-lucide="flame" class="w-4 h-4 text-rose-500"></i>
          </div>
          <div class="text-2xl font-black text-white font-mono" id="sec-stat-crit-inc">0</div>
          <p class="text-[11px] text-slate-400 mt-1">Active severe attacks & floods</p>
        </div>

        <div class="p-5 rounded-2xl bg-dark-850 border border-amber-500/30 bg-gradient-to-br from-amber-950/20 to-dark-850">
          <div class="flex items-center justify-between text-xs text-amber-400 font-semibold mb-2">
            <span>High Severity Alerts</span>
            <i data-lucide="alert-triangle" class="w-4 h-4 text-amber-500"></i>
          </div>
          <div class="text-2xl font-black text-white font-mono" id="sec-stat-high-inc">0</div>
          <p class="text-[11px] text-slate-400 mt-1">Scanning, brute-force & C2</p>
        </div>

        <div class="p-5 rounded-2xl bg-dark-850 border border-emerald-500/30 bg-gradient-to-br from-emerald-950/20 to-dark-850">
          <div class="flex items-center justify-between text-xs text-emerald-400 font-semibold mb-2">
            <span>Verified Attributions</span>
            <i data-lucide="check-circle-2" class="w-4 h-4 text-emerald-500"></i>
          </div>
          <div class="text-2xl font-black text-white font-mono" id="sec-stat-verified-attr">0</div>
          <p class="text-[11px] text-slate-400 mt-1">Authoritative CGNAT + Session matches</p>
        </div>

        <div class="p-5 rounded-2xl bg-dark-850 border border-indigo-500/30 bg-gradient-to-br from-indigo-950/20 to-dark-850">
          <div class="flex items-center justify-between text-xs text-indigo-400 font-semibold mb-2">
            <span>OpenSearch Buffer Queue</span>
            <i data-lucide="database" class="w-4 h-4 text-indigo-400"></i>
          </div>
          <div class="text-2xl font-black text-white font-mono" id="sec-stat-queue-depth">0</div>
          <p class="text-[11px] text-slate-400 mt-1">Local durable queue depth</p>
        </div>
      </div>

      <!-- Integration Health Badges Row -->
      <div class="p-4 rounded-xl bg-dark-850 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div class="text-xs font-semibold text-slate-400 flex items-center gap-2">
          <i data-lucide="server" class="w-4 h-4 text-cyan-400"></i> Active Integrations & Collectors:
        </div>
        <div id="sec-health-badges" class="flex flex-wrap gap-2"></div>
      </div>

      <!-- Recent Incidents Table -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i data-lucide="alert-octagon" class="w-4 h-4 text-rose-400"></i> Recent Correlated Security Incidents
          </h3>
          <button onclick="switchTab('sec-incidents')" class="text-xs text-brand-400 hover:underline">View All Incidents &rarr;</button>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Last Seen (PHT)</th>
                <th class="py-2.5 px-3">Incident Title</th>
                <th class="py-2.5 px-3">Severity</th>
                <th class="py-2.5 px-3">Subscriber CGNAT IP</th>
                <th class="py-2.5 px-3">PPPoE User</th>
                <th class="py-2.5 px-3">Events</th>
                <th class="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody id="sec-overview-incidents-body" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="7" class="text-center py-6 text-slate-500">Loading incidents...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: SECURITY EVENTS EXPLORER -->
    <!-- ========================================================= -->
    <section id="tab-sec-events" class="tab-content hidden space-y-6">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 class="text-xl font-bold text-white flex items-center gap-2">
            <i data-lucide="activity" class="w-6 h-6 text-amber-500"></i>
            Security Events Explorer & Suricata Telemetry
          </h2>
          <p class="text-xs text-slate-400 mt-1">Search, inspect and filter normalized Suricata IDS alerts with real-time CGNAT attribution</p>
        </div>
        <div class="flex items-center gap-2">
          <a href="/api/security/events/export/csv" target="_blank" class="px-3 py-1.5 rounded-lg bg-dark-800 hover:bg-dark-750 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-all">
            <i data-lucide="download" class="w-3.5 h-3.5"></i> Export CSV
          </a>
        </div>
      </div>

      <!-- Filter Controls Bar -->
      <div class="p-4 rounded-2xl bg-dark-850 border border-slate-800 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3">
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 mb-1">Subscriber CGNAT IP</label>
          <input type="text" id="sec-filter-cgnat-ip" placeholder="e.g. 100.91.0.2" class="w-full px-3 py-1.5 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono focus:border-brand-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 mb-1">Public IP</label>
          <input type="text" id="sec-filter-public-ip" placeholder="e.g. 157.119.69.129" class="w-full px-3 py-1.5 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono focus:border-brand-500 focus:outline-none">
        </div>
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 mb-1">Severity</label>
          <select id="sec-filter-severity" class="w-full px-3 py-1.5 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white focus:border-brand-500 focus:outline-none">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 mb-1">Category</label>
          <select id="sec-filter-category" class="w-full px-3 py-1.5 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white focus:border-brand-500 focus:outline-none">
            <option value="">All Categories</option>
            <option value="port_scanning">Port Scanning</option>
            <option value="outbound_ddos">Outbound DDoS</option>
            <option value="brute_force">Brute Force</option>
            <option value="botnet_c2">Botnet / C2</option>
            <option value="dns_anomaly">DNS Anomaly</option>
            <option value="inbound_ddos">Inbound DDoS</option>
          </select>
        </div>
        <div>
          <label class="block text-[11px] font-semibold text-slate-400 mb-1">Attribution Status</label>
          <select id="sec-filter-attr-status" class="w-full px-3 py-1.5 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white focus:border-brand-500 focus:outline-none">
            <option value="">All Statuses</option>
            <option value="verified">Verified</option>
            <option value="high_confidence">High Confidence</option>
            <option value="partial">Partial</option>
            <option value="unresolved">Unresolved</option>
            <option value="conflict">Conflict</option>
          </select>
        </div>
        <div class="flex items-end gap-2">
          <button onclick="loadSecurityEvents(0)" class="flex-1 py-1.5 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-xs font-semibold shadow-md transition-all">Filter</button>
          <button onclick="document.querySelectorAll('#tab-sec-events input').forEach(i=>i.value=''); document.querySelectorAll('#tab-sec-events select').forEach(s=>s.value=''); loadSecurityEvents(0);" class="px-2.5 py-1.5 rounded-lg bg-dark-800 hover:bg-dark-700 border border-slate-700 text-slate-300 text-xs">Reset</button>
        </div>
      </div>

      <!-- Events Table -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Timestamp (PHT)</th>
                <th class="py-2.5 px-3">Severity</th>
                <th class="py-2.5 px-3">Signature / Alert</th>
                <th class="py-2.5 px-3">Subscriber CGNAT IP</th>
                <th class="py-2.5 px-3">PPPoE User</th>
                <th class="py-2.5 px-3">Public Source</th>
                <th class="py-2.5 px-3">Proto</th>
                <th class="py-2.5 px-3">Destination</th>
                <th class="py-2.5 px-3">Attribution</th>
                <th class="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody id="sec-events-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="10" class="text-center py-8 text-slate-500">Loading events...</td></tr>
            </tbody>
          </table>
        </div>
        <!-- Pagination footer -->
        <div class="p-3 border-t border-slate-800 bg-dark-900 flex items-center justify-between text-xs text-slate-400">
          <span id="sec-events-page-info">Showing 0-0 of 0 events</span>
          <div class="flex items-center gap-2">
            <button onclick="if(secCurrentEventsPage>0) loadSecurityEvents(secCurrentEventsPage-1)" class="px-2.5 py-1 rounded bg-dark-800 hover:bg-dark-700 border border-slate-700 text-slate-200 text-xs">Previous</button>
            <button onclick="loadSecurityEvents(secCurrentEventsPage+1)" class="px-2.5 py-1 rounded bg-dark-800 hover:bg-dark-700 border border-slate-700 text-slate-200 text-xs">Next</button>
          </div>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: CGNAT ATTRIBUTION SEARCH (ABUSE INVESTIGATION) -->
    <!-- ========================================================= -->
    <section id="tab-sec-attribution" class="tab-content hidden space-y-6">
      <div class="pb-4 border-b border-slate-800">
        <h2 class="text-xl font-bold text-white flex items-center gap-2">
          <i data-lucide="search" class="w-6 h-6 text-cyan-400"></i>
          CGNAT Deterministic Port-Block Attribution & Abuse Investigation
        </h2>
        <p class="text-xs text-slate-400 mt-1">Authoritatively correlate translated public IP and port block to subscriber CGNAT IP and PPPoE session without guessing</p>
      </div>

      <!-- Investigation Form -->
      <div class="p-6 rounded-2xl bg-dark-850 border border-slate-800 space-y-4">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Reported Public IPv4 Address *</label>
            <input type="text" id="cgnat-search-public-ip" placeholder="e.g. 157.119.69.129" value="157.119.69.129" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono focus:border-cyan-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Translated Source Port *</label>
            <input type="number" id="cgnat-search-public-port" placeholder="e.g. 2500" value="2500" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono focus:border-cyan-500 focus:outline-none">
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 mb-1">Protocol</label>
            <select id="cgnat-search-proto" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white focus:border-cyan-500 focus:outline-none">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="all">ALL</option>
            </select>
          </div>
          <div>
            <div class="flex items-center justify-between mb-1">
              <label class="text-xs font-semibold text-slate-300">Incident Timestamp (UTC) *</label>
              <button onclick="setAttributionTimestampNow()" class="text-[10px] text-cyan-400 hover:underline">Now</button>
            </div>
            <input type="text" id="cgnat-search-timestamp" placeholder="YYYY-MM-DDTHH:MM:SSZ" value="2026-10-15T12:00:00Z" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono focus:border-cyan-500 focus:outline-none">
          </div>
        </div>

        <div class="flex justify-end gap-3 pt-2">
          <button id="btn-cgnat-lookup" onclick="performCGNATAttributionSearch()" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-brand-600 hover:from-cyan-500 hover:to-brand-500 text-white text-xs font-bold shadow-lg shadow-cyan-600/30 flex items-center gap-2">
            <i data-lucide="shield-check" class="w-4 h-4"></i> Run Authoritative Attribution Lookup
          </button>
        </div>
      </div>

      <!-- Result Card (Populated dynamically) -->
      <div id="cgnat-result-card" class="hidden p-6 rounded-2xl bg-dark-850 border border-cyan-500/40 bg-gradient-to-br from-cyan-950/20 via-dark-850 to-dark-850 space-y-6 shadow-2xl">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div class="flex items-center gap-2">
            <i data-lucide="check-circle" class="w-5 h-5 text-emerald-400"></i>
            <h3 class="text-base font-bold text-white">Attribution Investigation Result</h3>
          </div>
          <span id="cgnat-res-status" class="px-2.5 py-1 rounded text-xs font-bold uppercase border"></span>
        </div>

        <!-- Prominent Identity Result Display -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div class="p-4 rounded-xl bg-dark-900 border border-slate-800">
            <div class="text-[11px] font-semibold text-slate-400 uppercase mb-1">Subscriber CGNAT IP</div>
            <div class="text-xl font-bold font-mono text-brand-300 flex items-center justify-between">
              <span id="cgnat-res-sub-ip">—</span>
              <button id="btn-copy-cgnat-ip" class="px-2 py-1 rounded bg-dark-800 hover:bg-dark-700 border border-slate-700 text-xs text-slate-200 flex items-center gap-1">
                <i data-lucide="copy" class="w-3.5 h-3.5"></i> Copy
              </button>
            </div>
            <p class="text-[10px] text-slate-500 mt-1">Original pre-NAT subscriber IP</p>
          </div>

          <div class="p-4 rounded-xl bg-dark-900 border border-slate-800">
            <div class="text-[11px] font-semibold text-slate-400 uppercase mb-1">PPPoE Username</div>
            <div class="text-xl font-bold font-mono text-cyan-300 flex items-center justify-between">
              <span id="cgnat-res-username">—</span>
              <button id="btn-copy-pppoe-user" class="px-2 py-1 rounded bg-dark-800 hover:bg-dark-700 border border-slate-700 text-xs text-slate-200 flex items-center gap-1">
                <i data-lucide="copy" class="w-3.5 h-3.5"></i> Copy
              </button>
            </div>
            <p class="text-[10px] text-slate-500 mt-1">Active session at incident timestamp</p>
          </div>

          <div class="p-4 rounded-xl bg-dark-900 border border-slate-800">
            <div class="text-[11px] font-semibold text-slate-400 uppercase mb-1">Allocated Port Block</div>
            <div class="text-xl font-bold font-mono text-white" id="cgnat-res-port-block">—</div>
            <p class="text-[10px] text-slate-500 mt-1">Fixed 2,048-port range</p>
          </div>

          <div class="p-4 rounded-xl bg-dark-900 border border-slate-800">
            <div class="text-[11px] font-semibold text-slate-400 uppercase mb-1">Mapping Validity Interval</div>
            <div class="text-xs font-bold font-mono text-slate-300 truncate" id="cgnat-res-validity">—</div>
            <p class="text-[10px] text-slate-500 mt-1">Historical allocation bounds</p>
          </div>
        </div>

        <!-- Explanation -->
        <div class="p-4 rounded-xl bg-dark-900/60 border border-slate-800">
          <div class="text-xs font-semibold text-slate-300 mb-1">Confidence & Attribution Method:</div>
          <p id="cgnat-res-explanation" class="text-xs font-mono text-slate-400 leading-relaxed"></p>
        </div>

        <!-- External Manual Billing Lookup Workflow Box -->
        <div class="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3">
          <i data-lucide="info" class="w-5 h-5 text-amber-400 shrink-0 mt-0.5"></i>
          <div class="text-xs text-amber-200 space-y-1">
            <span class="font-bold">Independent Security Monitoring & Billing System Isolation Notice:</span>
            <p class="text-slate-300">
              This application operates strictly independently and does NOT query, connect to, or modify customer billing systems.
              To identify subscriber account balance, address, or service contract, copy the <strong class="text-white">Subscriber CGNAT IP</strong> or <strong class="text-white">PPPoE Username</strong> above and manually paste into the external ISP billing portal.
            </p>
          </div>
        </div>

        <div class="flex justify-end gap-3 pt-2">
          <button id="btn-view-subscriber-profile" class="px-4 py-2 rounded-lg bg-dark-800 hover:bg-dark-700 border border-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <i data-lucide="user" class="w-4 h-4"></i> View Subscriber Security Profile
          </button>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: SUBSCRIBER SECURITY PROFILE -->
    <!-- ========================================================= -->
    <section id="tab-sec-subscriber" class="tab-content hidden space-y-6">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 class="text-xl font-bold text-white flex items-center gap-2">
            <i data-lucide="user-check" class="w-6 h-6 text-indigo-400"></i>
            Subscriber Security Profile (Network-Derived)
          </h2>
          <p class="text-xs text-slate-400 mt-1">Comprehensive historical session timeline, port block history, and incident telemetry</p>
        </div>
        <div class="flex items-center gap-2">
          <input type="text" id="sec-profile-search-ip" placeholder="Enter CGNAT IP (100.91.x.x)" value="100.91.0.2" class="px-3 py-1.5 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono focus:border-indigo-500 focus:outline-none">
          <button onclick="fetchSubscriberProfile()" class="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold">Search</button>
        </div>
      </div>

      <!-- Profile Summary Cards -->
      <div class="p-5 rounded-2xl bg-dark-850 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div class="flex items-center gap-4">
          <div class="w-12 h-12 rounded-xl bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center">
            <i data-lucide="user" class="w-6 h-6 text-indigo-400"></i>
          </div>
          <div>
            <div class="text-lg font-bold text-white font-mono flex items-center gap-2">
              <span id="sec-prof-header-ip">100.91.0.2</span>
              <button id="btn-prof-copy-ip" class="text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3.5 h-3.5"></i></button>
            </div>
            <div class="text-xs text-cyan-300 font-mono flex items-center gap-1">
              Username: <span id="sec-prof-header-user">—</span>
              <button id="btn-prof-copy-user" class="text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3.5 h-3.5"></i></button>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-6 text-right font-mono text-xs">
          <div>
            <div class="text-slate-400 text-[10px] uppercase">Security Events</div>
            <div class="text-base font-bold text-white" id="sec-prof-total-events">0</div>
          </div>
          <div>
            <div class="text-slate-400 text-[10px] uppercase">Total Volume</div>
            <div class="text-base font-bold text-white" id="sec-prof-total-bytes">0 MB</div>
          </div>
          <div>
            <div class="text-slate-400 text-[10px] uppercase">Total Packets</div>
            <div class="text-base font-bold text-white" id="sec-prof-total-pkts">0</div>
          </div>
        </div>
      </div>

      <!-- Sessions History Table -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="p-4 border-b border-slate-800">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i data-lucide="clock" class="w-4 h-4 text-cyan-400"></i> Historical PPPoE Sessions
          </h3>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Username</th>
                <th class="py-2.5 px-3">Access Concentrator</th>
                <th class="py-2.5 px-3">Session Start</th>
                <th class="py-2.5 px-3">Session End</th>
                <th class="py-2.5 px-3">Source</th>
              </tr>
            </thead>
            <tbody id="sec-prof-sessions-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="5" class="text-center py-4 text-slate-500">Loading sessions...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Security Incidents History -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="p-4 border-b border-slate-800">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i> Associated Security Incidents
          </h3>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Last Seen (PHT)</th>
                <th class="py-2.5 px-3">Incident Title</th>
                <th class="py-2.5 px-3">Severity</th>
                <th class="py-2.5 px-3">Event Count</th>
                <th class="py-2.5 px-3">Status</th>
              </tr>
            </thead>
            <tbody id="sec-prof-incidents-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="5" class="text-center py-4 text-slate-500">Loading incidents...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: INCIDENT MANAGEMENT -->
    <!-- ========================================================= -->
    <section id="tab-sec-incidents" class="tab-content hidden space-y-6">
      <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 class="text-xl font-bold text-white flex items-center gap-2">
            <i data-lucide="alert-triangle" class="w-6 h-6 text-rose-500"></i>
            Security Incident Management & Investigation
          </h2>
          <p class="text-xs text-slate-400 mt-1">Track ongoing attacks, assign operators, audit status transitions, and enforce resolution notes</p>
        </div>
        <div class="flex items-center gap-2">
          <select id="sec-inc-filter-severity" onchange="loadIncidentManagement()" class="px-3 py-1.5 rounded-lg bg-dark-800 border border-slate-700 text-xs text-white focus:outline-none">
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
          <select id="sec-inc-filter-status" onchange="loadIncidentManagement()" class="px-3 py-1.5 rounded-lg bg-dark-800 border border-slate-700 text-xs text-white focus:outline-none">
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="confirmed_suspicious">Confirmed Suspicious</option>
            <option value="resolved">Resolved</option>
            <option value="benign">Benign / False Positive</option>
          </select>
        </div>
      </div>

      <!-- Incidents Table -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Last Seen (PHT)</th>
                <th class="py-2.5 px-3">Title</th>
                <th class="py-2.5 px-3">Severity</th>
                <th class="py-2.5 px-3">Subscriber CGNAT IP</th>
                <th class="py-2.5 px-3">PPPoE User</th>
                <th class="py-2.5 px-3">Events</th>
                <th class="py-2.5 px-3">Status</th>
                <th class="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="sec-incidents-mgmt-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="8" class="text-center py-8 text-slate-500">Loading incidents...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: TRAFFIC ANALYTICS (AKVORADO FLOWS) -->
    <!-- ========================================================= -->
    <section id="tab-sec-traffic" class="tab-content hidden space-y-6">
      <div class="pb-4 border-b border-slate-800">
        <h2 class="text-xl font-bold text-white flex items-center gap-2">
          <i data-lucide="bar-chart-3" class="w-6 h-6 text-emerald-400"></i>
          Akvorado Flow Analytics & Traffic Distributions
        </h2>
        <p class="text-xs text-slate-400 mt-1">Top talkers before and after CGNAT, protocol breakdowns, and network traffic anomalies</p>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Top Subscribers Pre-NAT -->
        <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
          <div class="p-4 border-b border-slate-800">
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              <i data-lucide="users" class="w-4 h-4 text-brand-400"></i> Top Subscriber CGNAT IPs (Pre-NAT Bandwidth)
            </h3>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left">
              <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                <tr>
                  <th class="py-2.5 px-3">Rank</th>
                  <th class="py-2.5 px-3">CGNAT IP</th>
                  <th class="py-2.5 px-3">Volume</th>
                  <th class="py-2.5 px-3">Packets</th>
                  <th class="py-2.5 px-3">Rate</th>
                </tr>
              </thead>
              <tbody id="sec-traffic-top-sub-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
                <tr><td colspan="5" class="text-center py-6 text-slate-500">Loading flow data...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Top Public IPs Post-NAT -->
        <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
          <div class="p-4 border-b border-slate-800">
            <h3 class="text-sm font-bold text-white flex items-center gap-2">
              <i data-lucide="globe" class="w-4 h-4 text-cyan-400"></i> Top Public CGNAT IPs (Post-NAT Volume)
            </h3>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left">
              <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
                <tr>
                  <th class="py-2.5 px-3">Rank</th>
                  <th class="py-2.5 px-3">Public IP</th>
                  <th class="py-2.5 px-3">Volume</th>
                  <th class="py-2.5 px-3">Events</th>
                </tr>
              </thead>
              <tbody id="sec-traffic-top-pub-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
                <tr><td colspan="4" class="text-center py-6 text-slate-500">Loading public IP flows...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Protocol Distribution Card -->
      <div class="p-5 rounded-2xl bg-dark-850 border border-slate-800 space-y-4">
        <h3 class="text-sm font-bold text-white flex items-center gap-2">
          <i data-lucide="pie-chart" class="w-4 h-4 text-purple-400"></i> Protocol Distribution Breakdown
        </h3>
        <div id="sec-traffic-protocols" class="space-y-3">
          <p class="text-xs text-slate-500">Loading protocol stats...</p>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: DETECTION RULES -->
    <!-- ========================================================= -->
    <section id="tab-sec-rules" class="tab-content hidden space-y-6">
      <div class="pb-4 border-b border-slate-800">
        <h2 class="text-xl font-bold text-white flex items-center gap-2">
          <i data-lucide="sliders" class="w-6 h-6 text-purple-400"></i>
          Detection Rules Engine & Threshold Configuration
        </h2>
        <p class="text-xs text-slate-400 mt-1">Configure active attack thresholds, observation time windows, exclusions, and test against historical traffic</p>
      </div>

      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Active</th>
                <th class="py-2.5 px-3">Rule Name</th>
                <th class="py-2.5 px-3">Category</th>
                <th class="py-2.5 px-3">Severity</th>
                <th class="py-2.5 px-3">Window</th>
                <th class="py-2.5 px-3">Thresholds</th>
                <th class="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="sec-rules-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="7" class="text-center py-6 text-slate-500">Loading detection rules...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: SENSOR & INTEGRATION HEALTH -->
    <!-- ========================================================= -->
    <section id="tab-sec-health" class="tab-content hidden space-y-6">
      <div class="pb-4 border-b border-slate-800">
        <h2 class="text-xl font-bold text-white flex items-center gap-2">
          <i data-lucide="heart-pulse" class="w-6 h-6 text-teal-400"></i>
          Sensor Observation Points & Pipeline Health
        </h2>
        <p class="text-xs text-slate-400 mt-1">Live status of RouterOS CCR2116 routers, Suricata IDS, Akvorado, OpenSearch durable queue, and interfaces</p>
      </div>

      <!-- Integrations Table -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="p-4 border-b border-slate-800">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i data-lucide="layers" class="w-4 h-4 text-cyan-400"></i> Core Subsystems & Integrations
          </h3>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Integration</th>
                <th class="py-2.5 px-3">Connectivity</th>
                <th class="py-2.5 px-3">Processing Lag</th>
                <th class="py-2.5 px-3">Queue Depth</th>
                <th class="py-2.5 px-3">Last Ingestion (PHT)</th>
                <th class="py-2.5 px-3">Last Error</th>
              </tr>
            </thead>
            <tbody id="sec-health-integrations-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="6" class="text-center py-6 text-slate-500">Loading integration health...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Sensors Table -->
      <div class="rounded-2xl bg-dark-850 border border-slate-800 overflow-hidden shadow-xl">
        <div class="p-4 border-b border-slate-800">
          <h3 class="text-sm font-bold text-white flex items-center gap-2">
            <i data-lucide="radio" class="w-4 h-4 text-teal-400"></i> Observation Point Sensors & TAPs
          </h3>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead class="bg-dark-900 border-b border-slate-800 text-[11px] font-semibold text-slate-400 uppercase">
              <tr>
                <th class="py-2.5 px-3">Sensor Name</th>
                <th class="py-2.5 px-3">Sensor ID</th>
                <th class="py-2.5 px-3">Observation Point</th>
                <th class="py-2.5 px-3">Host:Interface</th>
                <th class="py-2.5 px-3">Status</th>
                <th class="py-2.5 px-3">Last Heartbeat (PHT)</th>
              </tr>
            </thead>
            <tbody id="sec-health-sensors-tbody" class="divide-y divide-slate-800/60 font-mono text-xs">
              <tr><td colspan="6" class="text-center py-6 text-slate-500">Loading sensors...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ========================================================= -->
    <!-- TAB: SECURITY SETTINGS -->
    <!-- ========================================================= -->
    <section id="tab-sec-settings" class="tab-content hidden space-y-6">
      <div class="pb-4 border-b border-slate-800">
        <h2 class="text-xl font-bold text-white flex items-center gap-2">
          <i data-lucide="settings-2" class="w-6 h-6 text-slate-400"></i>
          Security Platform & CGNAT Pool Configuration
        </h2>
        <p class="text-xs text-slate-400 mt-1">Configure public and subscriber pools, port block alignment, router credentials, and OpenSearch</p>
      </div>

      <form onsubmit="saveSecuritySettings(event)" class="space-y-6">
        <!-- CGNAT Parameters Card -->
        <div class="p-6 rounded-2xl bg-dark-850 border border-slate-800 space-y-4">
          <h3 class="text-sm font-bold text-cyan-400 flex items-center gap-2 uppercase tracking-wide">
            <i data-lucide="network" class="w-4 h-4"></i> Deterministic CGNAT Pool & Port-Block Architecture
          </h3>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Public IPv4 Pool Start</label>
              <input type="text" id="sec-set-pub-start" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Public IPv4 Pool End</label>
              <input type="text" id="sec-set-pub-end" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Subscriber CGNAT Pool Start</label>
              <input type="text" id="sec-set-sub-start" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Port Block Size (Ports / Sub)</label>
              <input type="number" id="sec-set-port-block-size" value="2048" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">First Eligible Port</label>
              <input type="number" id="sec-set-first-port" value="2048" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Last Eligible Port</label>
              <input type="number" id="sec-set-last-port" value="65535" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
          </div>
        </div>

        <!-- Router Credentials Card -->
        <div class="p-6 rounded-2xl bg-dark-850 border border-slate-800 space-y-4">
          <h3 class="text-sm font-bold text-cyan-400 flex items-center gap-2 uppercase tracking-wide">
            <i data-lucide="router" class="w-4 h-4"></i> MikroTik CCR2116 Router Integration (Read-Only)
          </h3>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Core Router Host (CCR2116)</label>
              <input type="text" id="sec-set-core-host" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Core Router Username</label>
              <input type="text" id="sec-set-core-user" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Core Router Password</label>
              <input type="password" id="sec-set-core-pass" placeholder="********" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">PPPoE AC Host (CCR2116)</label>
              <input type="text" id="sec-set-ac-host" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">PPPoE AC Username</label>
              <input type="text" id="sec-set-ac-user" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">PPPoE AC Password</label>
              <input type="password" id="sec-set-ac-pass" placeholder="********" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
          </div>
        </div>

        <!-- OpenSearch & Alerting Card -->
        <div class="p-6 rounded-2xl bg-dark-850 border border-slate-800 space-y-4">
          <h3 class="text-sm font-bold text-cyan-400 flex items-center gap-2 uppercase tracking-wide">
            <i data-lucide="bell" class="w-4 h-4"></i> OpenSearch Storage & Alerting Integrations
          </h3>
          <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">OpenSearch Cluster URL</label>
              <input type="text" id="sec-set-opensearch-url" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Notification Webhook URL</label>
              <input type="text" id="sec-set-webhook-url" placeholder="https://hooks.slack.com/services/..." class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 mb-1">Alert Cooldown (Minutes)</label>
              <input type="number" id="sec-set-cooldown" value="15" class="w-full px-3 py-2 rounded-lg bg-dark-900 border border-slate-700 text-xs text-white font-mono">
            </div>
          </div>
        </div>

        <div class="flex justify-end gap-3">
          <button type="submit" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-brand-600 to-indigo-600 hover:from-brand-500 hover:to-indigo-500 text-white text-xs font-bold shadow-lg shadow-brand-600/30">
            Save Security Settings
          </button>
        </div>
      </form>
    </section>
"""

modal_html = """
  <!-- ========================================================= -->
  <!-- MODAL: INCIDENT DETAIL & STATUS TRANSITION -->
  <!-- ========================================================= -->
  <div id="modal-incident-detail" class="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm hidden items-center justify-center p-4 overflow-y-auto">
    <div class="bg-dark-850 border border-slate-700 rounded-2xl max-w-4xl w-full p-6 shadow-2xl space-y-4 my-8">
      <div class="flex items-center justify-between pb-3 border-b border-slate-800">
        <div>
          <h3 id="modal-inc-title" class="text-base font-bold text-white flex items-center gap-2">Security Incident Details</h3>
          <p id="modal-inc-id" class="text-[11px] font-mono text-slate-400"></p>
        </div>
        <button onclick="closeIncidentDetailModal()" class="text-slate-400 hover:text-white">
          <i data-lucide="x" class="w-5 h-5"></i>
        </button>
      </div>

      <!-- Quick Metrics -->
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div class="p-3 rounded-xl bg-dark-900 border border-slate-800">
          <div class="text-[10px] uppercase text-slate-500 font-semibold">Subscriber CGNAT IP</div>
          <div class="text-sm font-bold font-mono text-brand-300 flex items-center justify-between">
            <span id="modal-inc-sub-ip">—</span>
            <button id="btn-modal-copy-ip" class="text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3.5 h-3.5"></i></button>
          </div>
        </div>
        <div class="p-3 rounded-xl bg-dark-900 border border-slate-800">
          <div class="text-[10px] uppercase text-slate-500 font-semibold">PPPoE Username</div>
          <div class="text-sm font-bold font-mono text-cyan-300 flex items-center justify-between">
            <span id="modal-inc-username">—</span>
            <button id="btn-modal-copy-user" class="text-slate-500 hover:text-white p-0.5"><i data-lucide="copy" class="w-3.5 h-3.5"></i></button>
          </div>
        </div>
        <div class="p-3 rounded-xl bg-dark-900 border border-slate-800">
          <div class="text-[10px] uppercase text-slate-500 font-semibold">Affected Public IP</div>
          <div class="text-sm font-bold font-mono text-slate-200" id="modal-inc-pub-ip">—</div>
        </div>
        <div class="p-3 rounded-xl bg-dark-900 border border-slate-800">
          <div class="text-[10px] uppercase text-slate-500 font-semibold">Correlated Events</div>
          <div class="text-sm font-bold font-mono text-white" id="modal-inc-event-count">1</div>
        </div>
      </div>

      <!-- Related Events Table -->
      <div class="space-y-2">
        <div class="text-xs font-semibold text-slate-300">Correlated Event Timeline:</div>
        <div class="max-h-48 overflow-y-auto border border-slate-800 rounded-xl bg-dark-900">
          <table class="w-full text-left">
            <thead class="bg-dark-950 text-[10px] text-slate-400 uppercase font-semibold sticky top-0">
              <tr>
                <th class="py-1.5 px-2">Time (PHT)</th>
                <th class="py-1.5 px-2">Signature</th>
                <th class="py-1.5 px-2">Destination</th>
                <th class="py-1.5 px-2">Proto</th>
                <th class="py-1.5 px-2">Attribution</th>
              </tr>
            </thead>
            <tbody id="modal-inc-events-tbody" class="divide-y divide-slate-800/60 font-mono text-xs"></tbody>
          </table>
        </div>
      </div>

      <!-- Status Transition Form -->
      <div class="p-4 rounded-xl bg-dark-900 border border-slate-800 space-y-3">
        <div class="text-xs font-bold text-white flex items-center gap-1.5">
          <i data-lucide="edit-3" class="w-4 h-4 text-brand-400"></i> Operator Status Transition & Resolution Notes
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Incident Status</label>
            <select id="modal-inc-status-select" class="w-full px-3 py-1.5 rounded-lg bg-dark-850 border border-slate-700 text-xs text-white focus:outline-none">
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="confirmed_suspicious">Confirmed Suspicious</option>
              <option value="resolved">Resolved</option>
              <option value="benign">Benign / False Positive</option>
              <option value="escalated">Escalated</option>
            </select>
          </div>
          <div>
            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Resolution Reason / Investigation Notes *</label>
            <input type="text" id="modal-inc-notes" placeholder="Required when resolving high/critical incidents..." class="w-full px-3 py-1.5 rounded-lg bg-dark-850 border border-slate-700 text-xs text-white focus:outline-none">
          </div>
        </div>
      </div>

      <div class="flex justify-end gap-3 pt-2 border-t border-slate-800">
        <button onclick="closeIncidentDetailModal()" class="px-4 py-2 rounded-xl bg-dark-800 hover:bg-dark-700 border border-slate-700 text-slate-200 text-xs font-semibold">Cancel</button>
        <button onclick="saveIncidentStatusUpdate()" class="px-5 py-2 rounded-xl bg-brand-600 hover:bg-brand-500 text-white text-xs font-bold shadow-md shadow-brand-600/30">Save Update</button>
      </div>
    </div>
  </div>
"""

with open(INDEX_HTML, "r") as f:
    content = f.read()

# Insert security sections right before </main>
if "<!-- TAB: SECURITY OVERVIEW -->" not in content:
    content = content.replace("</main>", security_html + "\n  </main>")

# Insert incident modal right before toast container
if "modal-incident-detail" not in content:
    content = content.replace('<div id="toast-container"', modal_html + '\n  <div id="toast-container"')

# Insert security.js script tag
if "security.js" not in content:
    content = content.replace('<script src="/static/js/app.js?v=1.1.3"></script>', '<script src="/static/js/app.js?v=1.1.3"></script>\n  <script src="/static/js/security.js?v=2.0.0"></script>')

with open(INDEX_HTML, "w") as f:
    f.write(content)

print("Successfully injected WISPnet Security UI components into app/static/index.html")
