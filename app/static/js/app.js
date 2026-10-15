/**
 * WISPnet Unified Security Operations Platform - Core Application Logic
 * Manages Authentication, RBAC, Modal UI, Toast Notifications, and Tab Navigation.
 */

// Global Application State
let currentTab = 'sec-overview';
let currentUser = null;

// ============================================================================
// AUTHENTICATION & SESSION MANAGEMENT HELPERS
// ============================================================================

/**
 * Returns HTTP authorization headers for secure API requests.
 * Uses Bearer token stored in localStorage/sessionStorage.
 */
function getAuthHeaders() {
  const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
  if (token) {
    return { 'Authorization': `Bearer ${token}` };
  }
  return {};
}

/**
 * Format timestamps in Asia/Manila (PHT) timezone.
 */
function formatManilaTime(isoStr) {
  if (!isoStr || isoStr === "—" || isoStr === "null" || isoStr === "None") return "—";
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return new Intl.DateTimeFormat("en-PH", {
      timeZone: "Asia/Manila",
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false
    }).format(d) + " PHT";
  } catch (e) {
    return isoStr;
  }
}

/**
 * Format timestamps matching local browser timezone.
 */
function formatLocalTime(val, includeDate = false) {
  if (!val || val === 'Never' || val === 'never' || val === 'None' || val === 'null') {
    return 'Never';
  }
  let dateObj = null;
  if (typeof val === 'number') {
    dateObj = new Date(val < 1e11 ? val * 1000 : val);
  } else if (typeof val === 'string') {
    const trimmed = val.trim();
    if (/^\d+(\.\d+)?$/.test(trimmed)) {
      const num = parseFloat(trimmed);
      dateObj = new Date(num < 1e11 ? num * 1000 : num);
    } else {
      dateObj = new Date(trimmed);
    }
  }
  if (!dateObj || isNaN(dateObj.getTime())) return val;

  if (includeDate) {
    return dateObj.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    });
  }
  return dateObj.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
}

/**
 * Clipboard copy utility with non-blocking fallback and visual feedback.
 */
function copyToClipboard(text, label = "Value") {
  if (!text || text === "—" || text === "None") return;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showToast(`Copied ${label}: ${text}`, "success");
    }).catch(() => {
      fallbackCopyText(text, label);
    });
  } else {
    fallbackCopyText(text, label);
  }
}

function fallbackCopyText(text, label) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand('copy');
    showToast(`Copied ${label}: ${text}`, "success");
  } catch (err) {
    console.error('Fallback copy failed', err);
  }
  document.body.removeChild(textArea);
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  let bg = 'bg-dark-800 border-slate-700 text-white';
  if (type === 'success') bg = 'bg-emerald-950/90 border-emerald-500/50 text-emerald-200';
  if (type === 'warning') bg = 'bg-amber-950/90 border-amber-500/50 text-amber-200';
  if (type === 'error') bg = 'bg-rose-950/90 border-rose-500/50 text-rose-200';

  toast.className = `p-3 rounded-xl border shadow-xl flex items-center gap-2.5 text-xs font-semibold max-w-sm transform transition-all duration-300 translate-y-2 opacity-0 ${bg}`;
  toast.innerHTML = `
    <span class="flex-1">${escapeHtml(message)}</span>
    <button onclick="this.parentElement.remove()" class="opacity-70 hover:opacity-100">&times;</button>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.remove('translate-y-2', 'opacity-0');
  }, 10);

  setTimeout(() => {
    toast.classList.add('translate-y-2', 'opacity-0');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Aliases for security & intelligence modules
function showSecurityToast(msg) {
  showToast(msg, 'info');
}

function showIntelToast(msg, isError = false) {
  showToast(msg, isError ? 'error' : 'info');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Modal helper
function closeModal(modalId) {
  const m = document.getElementById(modalId);
  if (m) {
    m.classList.add('hidden');
    m.classList.remove('flex');
  }
}

// ============================================================================
// TAB NAVIGATION
// ============================================================================
function switchTab(tabId) {
  currentTab = tabId;

  // 1. Update navigation buttons
  document.querySelectorAll('#nav-tabs .tab-btn').forEach(btn => {
    if (btn.getAttribute('data-tab') === tabId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // 2. Hide all tab sections, show the target
  document.querySelectorAll('main > section.tab-content').forEach(sec => {
    if (sec.id === `tab-${tabId}`) {
      sec.classList.remove('hidden');
      sec.classList.add('block', 'space-y-6');
    } else {
      sec.classList.add('hidden');
      sec.classList.remove('block', 'space-y-6');
    }
  });

  // 3. Dispatch data load depending on tab
  switch (tabId) {
    case 'sec-overview':
      if (typeof loadSecurityOverview === 'function') loadSecurityOverview();
      break;
    case 'sec-events':
      if (typeof loadSecurityEvents === 'function') loadSecurityEvents(0);
      break;
    case 'sec-attribution':
      const tsEl = document.getElementById("cgnat-search-timestamp");
      if (tsEl && !tsEl.value && typeof setAttributionTimestampNow === 'function') {
        setAttributionTimestampNow();
      }
      break;
    case 'sec-subscriber':
      const subIpInput = document.getElementById("sub-profile-search-ip");
      if (subIpInput && subIpInput.value.trim() && typeof fetchSubscriberProfile === 'function') {
        fetchSubscriberProfile(subIpInput.value.trim());
      }
      break;
    case 'sec-incidents':
      if (typeof loadIncidentManagement === 'function') loadIncidentManagement();
      break;
    case 'sec-traffic':
      if (typeof loadTrafficAnalytics === 'function') loadTrafficAnalytics();
      break;
    case 'sec-rules':
      if (typeof loadDetectionRules === 'function') loadDetectionRules();
      break;
    case 'sec-health':
      if (typeof loadSensorHealth === 'function') loadSensorHealth();
      break;
    case 'sec-settings':
      if (typeof loadSecuritySettings === 'function') loadSecuritySettings();
      break;
    case 'sec-routers':
      loadRouters();
      break;
    case 'ip-intel':
      if (typeof loadIPIntelOverview === 'function') loadIPIntelOverview();
      break;
    case 'users':
      loadUsers();
      break;
  }

  if (window.lucide) {
    lucide.createIcons();
  }
}

// ============================================================================
// AUTHENTICATION & USER MANAGEMENT CONTROLLER
// ============================================================================
async function checkAuthStatus() {
  try {
    const res = await fetch('/api/auth/me', {
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    const data = await res.json();

    if (data.authenticated && data.user) {
      currentUser = data.user;
      updateAuthUI(currentUser);
      switchTab(currentTab);
    } else {
      currentUser = null;
      updateAuthUI(null);
      openLoginModal(true);
    }
  } catch (err) {
    console.error('Failed to check auth:', err);
    currentUser = null;
    updateAuthUI(null);
    openLoginModal(true);
  }
}

function handleAuthPillClick() {
  if (!currentUser) {
    openLoginModal(false);
  } else {
    switchTab('users');
  }
}

function updateAuthUI(user) {
  const userEl = document.getElementById('auth-username');
  const roleEl = document.getElementById('auth-role-badge');
  const banner = document.getElementById('readonly-warning-banner');
  const logoutBtn = document.getElementById('auth-logout-btn');
  const authIcon = document.getElementById('auth-icon');

  if (!user) {
    if (userEl) userEl.innerText = 'Sign In';
    if (roleEl) {
      roleEl.innerText = 'GUEST';
      roleEl.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-700 text-slate-400 border border-slate-600 uppercase';
    }
    if (logoutBtn) logoutBtn.classList.add('hidden');
    if (authIcon) {
      authIcon.setAttribute('data-lucide', 'lock');
      if (window.lucide) lucide.createIcons();
    }
    if (banner) banner.classList.add('hidden');
    return;
  }

  if (logoutBtn) logoutBtn.classList.remove('hidden');
  if (authIcon) {
    authIcon.setAttribute('data-lucide', 'shield-check');
    if (window.lucide) lucide.createIcons();
  }

  if (userEl) userEl.innerText = user.username;
  if (roleEl) {
    roleEl.innerText = user.role.toUpperCase();
    if (user.role === 'admin') {
      roleEl.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold bg-brand-500/20 text-brand-300 border border-brand-500/30 uppercase';
    } else {
      roleEl.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 uppercase';
    }
  }

  if (banner) {
    if (user.role === 'read-only') {
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }
  }
}

function fillAdminCredentials() {
  const u = document.getElementById('login-username');
  const p = document.getElementById('login-password');
  if (u) u.value = 'synchavxxx';
  if (p) p.value = 'passworD1369';
}

function openLoginModal(mandatory = false) {
  const modal = document.getElementById('modal-login');
  if (!modal) return;
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  const closeBtn = document.getElementById('btn-close-login');
  if (closeBtn) {
    closeBtn.classList.remove('hidden');
  }

  setTimeout(() => document.getElementById('login-username')?.focus(), 50);
}

function closeLoginModal() {
  const modal = document.getElementById('modal-login');
  if (!modal) return;
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const u = document.getElementById('login-username').value.trim();
  const p = document.getElementById('login-password').value;

  if (!u || !p) {
    showToast('Username and password are required', 'warning');
    return;
  }

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p }),
      credentials: 'include'
    });

    if (!res.ok) {
      const err = await res.json();
      showToast(err.detail || 'Login failed', 'error');
      return;
    }

    const data = await res.json();
    currentUser = data.user;
    if (data.token) {
      localStorage.setItem('auth_token', data.token);
    }
    updateAuthUI(currentUser);
    closeLoginModal();
    showToast(data.message || 'Login successful', 'success');

    switchTab(currentTab);
  } catch (err) {
    showToast('Login request failed: ' + err, 'error');
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include'
    });
  } catch (err) {
    console.error('Logout error:', err);
  } finally {
    localStorage.removeItem('auth_token');
    sessionStorage.removeItem('auth_token');
    currentUser = null;
    updateAuthUI(null);
    showToast('Logged out successfully.', 'info');
    openLoginModal(true);
  }
}

// ============================================================================
// USER MANAGEMENT CRUD
// ============================================================================
async function loadUsers(manual = false) {
  const spinIcon = document.getElementById('users-refresh-icon');
  if (spinIcon) spinIcon.classList.add('animate-spin');

  const tbody = document.getElementById('users-table-body');
  if (!tbody) {
    if (spinIcon) spinIcon.classList.remove('animate-spin');
    return;
  }

  try {
    const res = await fetch('/api/users', {
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    if (res.status === 403) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-8 text-amber-400 font-sans">
            <i data-lucide="lock" class="w-6 h-6 mx-auto mb-2 text-amber-400"></i>
            User Management is restricted to Administrators.
          </td>
        </tr>
      `;
      if (window.lucide) lucide.createIcons();
      return;
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const users = await res.json();
    const countBadge = document.getElementById('badge-users-count');
    if (countBadge) countBadge.innerText = users.length;

    if (users.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-8 text-slate-500 font-sans">No users configured.</td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = users.map(u => {
      const roleBadge = u.role === 'admin'
        ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-brand-500/20 text-brand-300 border border-brand-500/30">ADMIN</span>'
        : '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">READ-ONLY</span>';

      const statusBadge = u.enabled
        ? '<span class="inline-flex items-center gap-1 text-emerald-400"><span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> Active</span>'
        : '<span class="inline-flex items-center gap-1 text-slate-500"><span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span> Disabled</span>';

      return `
        <tr class="hover:bg-dark-800/50 transition-colors">
          <td class="py-3 px-4 font-bold text-white">${escapeHtml(u.username)}</td>
          <td class="py-3 px-4 text-slate-300 font-sans">${escapeHtml(u.full_name || '—')}</td>
          <td class="py-3 px-4">${roleBadge}</td>
          <td class="py-3 px-4 font-sans">${statusBadge}</td>
          <td class="py-3 px-4 text-slate-400 text-[11px]">${formatManilaTime(u.created_at)}</td>
          <td class="py-3 px-4 text-right space-x-2">
            <button onclick="openEditUserModal('${u.id}')" class="px-2.5 py-1 rounded-lg bg-dark-800 hover:bg-dark-750 border border-slate-700 text-slate-200 text-xs font-semibold">
              Edit
            </button>
            <button onclick="deleteUser('${u.id}', '${encodeURIComponent(u.username)}')" class="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs font-semibold">
              Delete
            </button>
          </td>
        </tr>
      `;
    }).join('');

    if (window.lucide) lucide.createIcons();
    if (manual) {
      showToast('User accounts refreshed', 'success');
    }
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-8 text-rose-400 font-sans">
          Failed to load users: ${err.message}
        </td>
      </tr>
    `;
    if (manual) {
      showToast('Failed to refresh users: ' + err.message, 'error');
    }
  } finally {
    if (spinIcon) spinIcon.classList.remove('animate-spin');
  }
}

function openAddUserModal() {
  document.getElementById('user-form-id').value = '';
  document.getElementById('modal-user-title').innerHTML = '<i data-lucide="user-plus" class="w-5 h-5 text-brand-400"></i> Add User Account';

  const uInput = document.getElementById('user-form-username');
  uInput.value = '';
  uInput.disabled = false;

  document.getElementById('user-form-fullname').value = '';
  document.getElementById('user-form-role').value = 'read-only';

  const pInput = document.getElementById('user-form-password');
  pInput.value = '';
  pInput.required = true;
  document.getElementById('user-form-pwd-hint').classList.add('hidden');

  document.getElementById('user-form-enabled-row').classList.add('hidden');

  const modal = document.getElementById('modal-user');
  modal.classList.remove('hidden');
  modal.classList.add('flex');
  if (window.lucide) lucide.createIcons();
  setTimeout(() => uInput.focus(), 50);
}

async function openEditUserModal(userId) {
  try {
    const res = await fetch(`/api/users/${userId}`, {
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    if (!res.ok) throw new Error('User not found');
    const u = await res.json();

    document.getElementById('user-form-id').value = u.id;
    document.getElementById('modal-user-title').innerHTML = `<i data-lucide="user-cog" class="w-5 h-5 text-brand-400"></i> Edit User: ${escapeHtml(u.username)}`;

    const uInput = document.getElementById('user-form-username');
    uInput.value = u.username;
    uInput.disabled = true;

    document.getElementById('user-form-fullname').value = u.full_name || '';
    document.getElementById('user-form-role').value = u.role || 'read-only';

    const pInput = document.getElementById('user-form-password');
    pInput.value = '';
    pInput.required = false;
    document.getElementById('user-form-pwd-hint').classList.remove('hidden');

    const enabledRow = document.getElementById('user-form-enabled-row');
    enabledRow.classList.remove('hidden');
    document.getElementById('user-form-enabled').checked = u.enabled;

    const modal = document.getElementById('modal-user');
    modal.classList.remove('hidden');
    modal.classList.add('flex');
    if (window.lucide) lucide.createIcons();
  } catch (err) {
    showToast('Failed to load user details: ' + err, 'error');
  }
}

function closeUserModal() {
  const modal = document.getElementById('modal-user');
  if (!modal) return;
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}

async function handleSaveUser(e) {
  e.preventDefault();
  const userId = document.getElementById('user-form-id').value;
  const username = document.getElementById('user-form-username').value.trim();
  const fullName = document.getElementById('user-form-fullname').value.trim();
  const role = document.getElementById('user-form-role').value;
  const password = document.getElementById('user-form-password').value;
  const enabled = document.getElementById('user-form-enabled').checked;

  try {
    if (!userId) {
      if (!password || password.length < 4) {
        showToast('Password must be at least 4 characters', 'warning');
        return;
      }
      const res = await fetch('/api/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        credentials: 'include',
        body: JSON.stringify({
          username: username,
          password: password,
          role: role,
          full_name: fullName
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Creation failed');
      showToast(data.message || 'User created successfully', 'success');
    } else {
      const payload = {
        full_name: fullName,
        role: role,
        enabled: enabled
      };
      if (password && password.length >= 4) {
        payload.password = password;
      }
      const res = await fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Update failed');
      showToast(data.message || 'User updated successfully', 'success');
    }

    closeUserModal();
    loadUsers();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteUser(userId, usernameEncoded) {
  const username = decodeURIComponent(usernameEncoded || '');
  if (!confirm(`Are you sure you want to delete user '${username}'?`)) return;

  try {
    const res = await fetch(`/api/users/${userId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      credentials: 'include'
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Delete failed');
    showToast(data.message || 'User deleted', 'success');
    loadUsers();
  } catch (err) {
    showToast('Delete failed: ' + err.message, 'error');
  }
}

// ============================================================================
// MIKROTIK ROUTER FLEET & ONBOARDING CONTROLLER
// ============================================================================
let routerRoleFilter = 'all';
let cachedRouters = [];

let isSyncingFleet = false;
async function syncEverything() {
  if (isSyncingFleet) return;
  isSyncingFleet = true;

  const iconIds = [
    'global-sync-icon',
    'routers-sync-icon',
    'sec-overview-sync-icon',
    'routers-refresh-icon',
    'sec-overview-refresh-icon',
    'sec-health-refresh-icon'
  ];
  const icons = iconIds.map(id => document.getElementById(id)).filter(Boolean);
  icons.forEach(ic => ic.classList.add('animate-spin'));

  try {
    const authHeaders = typeof getAuthHeaders === 'function' ? getAuthHeaders() : {};
    const candidateEndpoints = [
      '/api/routers/sync-all',
      '/api/routers/sync',
      '/routers/sync-all',
      '/routers/sync',
      '/api/fleet/sync',
      '/api/sync'
    ];

    let res = null;
    let authFailed = false;

    for (const ep of candidateEndpoints) {
      try {
        const response = await fetch(ep, {
          method: 'POST',
          headers: {
            ...authHeaders,
            'Content-Type': 'application/json'
          },
          credentials: 'include'
        });

        if (response.status === 401) {
          authFailed = true;
          break;
        }

        if (response.ok) {
          res = response;
          break;
        }

        // Keep last response if not 404/405
        if (response.status !== 404 && response.status !== 405) {
          res = response;
          break;
        }
        res = response;
      } catch (networkErr) {
        // try next endpoint
      }
    }

    if (authFailed) {
      showToast('Authentication required to sync fleet. Please sign in.', 'error');
      if (typeof openLoginModal === 'function') openLoginModal();
      return;
    }

    if (!res || !res.ok) {
      const err = res ? await res.json().catch(() => ({})) : {};
      throw new Error(err.detail || (res ? `HTTP ${res.status}` : 'Server connection failed'));
    }

    const data = await res.json();
    if (data.total_routers === 0) {
      showToast('Router fleet is clean (0 routers). Click "+ Onboard Router" to connect your hardware.', 'info');
    } else {
      showToast(`Fleet sync complete: ${data.online_routers}/${data.total_routers} online (${data.sessions_harvested} sessions harvested)`, 'success');
    }

    // Refresh active components
    if (typeof loadRouters === 'function') await loadRouters(false);
    if (typeof loadSecurityOverview === 'function') await loadSecurityOverview(false);
    if (typeof loadSensorHealth === 'function') await loadSensorHealth(false);
    if (typeof loadIncidentManagement === 'function' && currentTab === 'sec-incidents') loadIncidentManagement(false);
    if (typeof loadSecurityEvents === 'function' && currentTab === 'sec-events') loadSecurityEvents(secCurrentEventsPage || 0, false);
    if (typeof loadIPIntelOverview === 'function' && currentTab === 'ip-intel') loadIPIntelOverview();
    if (typeof loadTrafficAnalytics === 'function' && currentTab === 'sec-traffic') loadTrafficAnalytics();
    if (typeof loadDetectionRules === 'function' && currentTab === 'sec-rules') loadDetectionRules();
  } catch (err) {
    console.error('Fleet sync failed:', err);
    showToast(`Fleet sync failed: ${err.message}`, 'error');
  } finally {
    icons.forEach(ic => ic.classList.remove('animate-spin'));
    isSyncingFleet = false;
    if (window.lucide) lucide.createIcons();
  }
}

async function loadRouters(manual = false) {
  const spinIcon = document.getElementById('routers-refresh-icon');
  if (spinIcon) spinIcon.classList.add('animate-spin');

  const tbody = document.getElementById('routers-table-body');
  if (!tbody) {
    if (spinIcon) spinIcon.classList.remove('animate-spin');
    return;
  }

  try {
    const url = routerRoleFilter && routerRoleFilter !== 'all'
      ? `/api/routers?role=${encodeURIComponent(routerRoleFilter)}`
      : '/api/routers';

    const res = await fetch(url, {
      headers: getAuthHeaders(),
      credentials: 'include'
    });

    if (res.status === 401) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-slate-500">Authentication required. Please sign in.</td></tr>`;
      return;
    }

    if (!res.ok) {
      throw new Error(`Failed to load routers (${res.status})`);
    }

    const routers = await res.json();
    cachedRouters = routers;

    // Update fleet metrics
    const totalEl = document.getElementById('stat-routers-total');
    const coreEl = document.getElementById('stat-routers-core');
    const acEl = document.getElementById('stat-routers-ac');
    const onlineEl = document.getElementById('stat-routers-online');
    const badgeEl = document.getElementById('badge-routers-count');

    if (totalEl) totalEl.innerText = routers.length;
    if (coreEl) coreEl.innerText = routers.filter(r => r.role === 'core').length;
    if (acEl) acEl.innerText = routers.filter(r => r.role === 'ac').length;
    if (onlineEl) onlineEl.innerText = routers.filter(r => r.status === 'online').length;
    if (badgeEl) badgeEl.innerText = routers.length;

    renderRoutersTable(routers);
    if (manual) {
      showToast('Router fleet refreshed', 'success');
    }
  } catch (err) {
    console.error('Error loading routers:', err);
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-6 text-rose-400">Failed to load routers: ${err.message}</td></tr>`;
    if (manual) {
      showToast('Failed to refresh routers: ' + err.message, 'error');
    }
  } finally {
    if (spinIcon) spinIcon.classList.remove('animate-spin');
    if (window.lucide) lucide.createIcons();
  }
}

function renderRoutersTable(routers) {
  const tbody = document.getElementById('routers-table-body');
  if (!tbody) return;

  if (!routers || routers.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center py-10 text-slate-400 font-sans">
          <div class="flex flex-col items-center justify-center gap-2">
            <i data-lucide="router" class="w-8 h-8 text-slate-600"></i>
            <span class="text-sm font-medium">No routers found matching this filter</span>
            <button onclick="openOnboardRouterModal()" class="mt-2 px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 text-xs font-semibold border border-cyan-500/30">
              + Onboard First Router
            </button>
          </div>
        </td>
      </tr>
    `;
    if (window.lucide) lucide.createIcons();
    return;
  }

  const roleStyles = {
    core: { label: 'CORE GATEWAY', badge: 'bg-purple-500/20 text-purple-300 border-purple-500/40' },
    ac: { label: 'PPPoE AC', badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40' },
    border: { label: 'BORDER EDGE', badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
    distribution: { label: 'DISTRIBUTION', badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
    cpe: { label: 'CPE / EDGE', badge: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40' },
    other: { label: 'OTHER', badge: 'bg-slate-500/20 text-slate-300 border-slate-500/40' }
  };

  tbody.innerHTML = routers.map(r => {
    const roleConfig = roleStyles[r.role] || { label: r.role.toUpperCase(), badge: 'bg-slate-500/20 text-slate-300 border-slate-500/40' };

    // Status styling
    let statusHtml = '';
    if (r.status === 'online') {
      statusHtml = `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>ONLINE</span>`;
    } else if (r.status === 'offline') {
      statusHtml = `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30"><span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span>OFFLINE</span>`;
    } else if (r.status === 'error') {
      statusHtml = `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30"><span class="w-1.5 h-1.5 rounded-full bg-rose-500"></span>ERROR</span>`;
    } else {
      statusHtml = `<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30"><span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span>UNTESTED</span>`;
    }

    // Protocol styling
    let protoHtml = '';
    if (r.use_rest) {
      protoHtml = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">REST (v7)</span>`;
    } else if (r.use_ssl) {
      protoHtml = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">API-SSL</span>`;
    } else {
      protoHtml = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">API</span>`;
    }

    // Hardware & ROS
    const modelText = r.model || 'MikroTik RouterOS';
    const rosText = r.ros_version ? `v${r.ros_version.replace(/^v/, '')}` : 'v7.x';

    // CPU & Uptime
    let cpuHtml = '—';
    if (r.cpu_load !== null && r.cpu_load !== undefined) {
      const loadColor = r.cpu_load > 80 ? 'text-rose-400' : (r.cpu_load > 60 ? 'text-amber-400' : 'text-emerald-400');
      cpuHtml = `<span class="font-bold ${loadColor}">${r.cpu_load}% CPU</span>`;
    }
    const uptimeText = r.uptime ? `<span class="text-slate-400 text-[11px] block">${r.uptime}</span>` : '';

    return `
      <tr class="hover:bg-dark-800/50 transition-colors">
        <td class="py-3 px-4">
          <div class="font-sans font-bold text-white text-sm">${escapeHtml(r.name)}</div>
          <div class="flex items-center gap-2 mt-0.5 font-mono text-xs text-cyan-300">
            <span>${escapeHtml(r.host)}</span>
            <span class="text-slate-500">#${escapeHtml(r.id)}</span>
          </div>
          ${r.notes ? `<div class="text-[11px] text-slate-400 font-sans mt-0.5">${escapeHtml(r.notes)}</div>` : ''}
        </td>
        <td class="py-3 px-4">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${roleConfig.badge}">
            ${roleConfig.label}
          </span>
        </td>
        <td class="py-3 px-4">
          <div class="flex items-center gap-1.5 font-mono">
            ${protoHtml}
            <span class="text-slate-400">:${r.port}</span>
          </div>
        </td>
        <td class="py-3 px-4">
          ${statusHtml}
          ${r.last_seen ? `<div class="text-[10px] text-slate-500 mt-1 font-sans">${formatLocalTime(r.last_seen)}</div>` : ''}
        </td>
        <td class="py-3 px-4">
          <div class="font-sans text-xs text-slate-200 font-semibold">${escapeHtml(modelText)}</div>
          <div class="text-[11px] font-mono text-slate-400">${escapeHtml(rosText)}</div>
        </td>
        <td class="py-3 px-4 font-mono text-xs">
          ${cpuHtml}
          ${uptimeText}
        </td>
        <td class="py-3 px-4 text-right">
          <div class="flex items-center justify-end gap-1.5">
            <button onclick="testRouterConnection('${escapeHtml(r.id)}')" title="Test Live Connection & Telemetry" class="p-1.5 rounded-lg bg-dark-800 hover:bg-dark-700 text-cyan-400 hover:text-cyan-300 border border-slate-700 active:scale-95 transition-all">
              <i data-lucide="zap" class="w-3.5 h-3.5"></i>
            </button>
            <button onclick="harvestRouterSessions('${escapeHtml(r.id)}')" title="Harvest Active Subscriber Sessions" class="p-1.5 rounded-lg bg-dark-800 hover:bg-dark-700 text-indigo-400 hover:text-indigo-300 border border-slate-700 active:scale-95 transition-all">
              <i data-lucide="database" class="w-3.5 h-3.5"></i>
            </button>
            <button onclick="openEditRouterModal('${escapeHtml(r.id)}')" title="Edit Router Configuration" class="p-1.5 rounded-lg bg-dark-800 hover:bg-dark-700 text-amber-400 hover:text-amber-300 border border-slate-700 active:scale-95 transition-all">
              <i data-lucide="edit-2" class="w-3.5 h-3.5"></i>
            </button>
            <button onclick="deleteRouter('${escapeHtml(r.id)}', '${encodeURIComponent(r.name)}')" title="Delete Router" class="p-1.5 rounded-lg bg-dark-800 hover:bg-dark-700 text-rose-400 hover:text-rose-300 border border-slate-700 active:scale-95 transition-all">
              <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  if (window.lucide) {
    lucide.createIcons();
  }
}

function filterRoutersByRole(role) {
  routerRoleFilter = role;
  document.querySelectorAll('.router-role-filter').forEach(btn => {
    if (btn.dataset.role === role) {
      btn.classList.add('bg-dark-750', 'text-white');
      btn.classList.remove('bg-dark-850', 'text-slate-300');
    } else {
      btn.classList.remove('bg-dark-750', 'text-white');
      btn.classList.add('bg-dark-850', 'text-slate-300');
    }
  });
  loadRouters();
}

function openOnboardRouterModal() {
  document.getElementById('modal-router-title').innerHTML = `<i data-lucide="router" class="w-5 h-5 text-cyan-400"></i> Onboard MikroTik Router`;
  document.getElementById('modal-router-id').value = '';
  document.getElementById('modal-router-name').value = '';
  document.getElementById('modal-router-role').value = 'core';
  document.getElementById('modal-router-host').value = '';
  document.getElementById('modal-router-port').value = '8728';
  document.getElementById('modal-router-user').value = 'security_ro';
  document.getElementById('modal-router-pass').value = '';
  document.getElementById('modal-router-pass').required = true;
  document.getElementById('label-router-password').innerText = 'Password *';
  document.getElementById('modal-router-ssl').checked = false;
  document.getElementById('modal-router-rest').checked = false;
  document.getElementById('modal-router-enabled').checked = true;
  document.getElementById('modal-router-notes').value = '';

  const resBox = document.getElementById('modal-router-test-result');
  if (resBox) {
    resBox.classList.add('hidden');
    resBox.innerHTML = '';
  }

  document.getElementById('modal-router-onboard').classList.remove('hidden');
  if (window.lucide) lucide.createIcons();
}

function openEditRouterModal(routerId) {
  const router = cachedRouters.find(r => r.id === routerId);
  if (!router) {
    showToast('Router not found in cache', 'error');
    return;
  }

  document.getElementById('modal-router-title').innerHTML = `<i data-lucide="edit-3" class="w-5 h-5 text-amber-400"></i> Edit Router: ${escapeHtml(router.name)}`;
  document.getElementById('modal-router-id').value = router.id;
  document.getElementById('modal-router-name').value = router.name;
  document.getElementById('modal-router-role').value = router.role;
  document.getElementById('modal-router-host').value = router.host;
  document.getElementById('modal-router-port').value = router.port;
  document.getElementById('modal-router-user').value = router.username;
  document.getElementById('modal-router-pass').value = '';
  document.getElementById('modal-router-pass').required = false;
  document.getElementById('label-router-password').innerText = 'Password (Leave blank to keep current)';
  document.getElementById('modal-router-ssl').checked = Boolean(router.use_ssl);
  document.getElementById('modal-router-rest').checked = Boolean(router.use_rest);
  document.getElementById('modal-router-enabled').checked = Boolean(router.enabled);
  document.getElementById('modal-router-notes').value = router.notes || '';

  const resBox = document.getElementById('modal-router-test-result');
  if (resBox) {
    resBox.classList.add('hidden');
    resBox.innerHTML = '';
  }

  document.getElementById('modal-router-onboard').classList.remove('hidden');
  if (window.lucide) lucide.createIcons();
}

function closeRouterModal() {
  document.getElementById('modal-router-onboard').classList.add('hidden');
}

function handleRouterProtocolChange() {
  const isRest = document.getElementById('modal-router-rest').checked;
  const isSsl = document.getElementById('modal-router-ssl').checked;
  const portInput = document.getElementById('modal-router-port');

  if (isRest) {
    if (portInput.value === '8728' || portInput.value === '8729') portInput.value = '443';
  } else if (isSsl) {
    if (portInput.value === '8728' || portInput.value === '443') portInput.value = '8729';
  } else {
    if (portInput.value === '8729' || portInput.value === '443') portInput.value = '8728';
  }
}

async function handleSaveRouter(e) {
  e.preventDefault();
  const routerId = document.getElementById('modal-router-id').value;
  const name = document.getElementById('modal-router-name').value.trim();
  const role = document.getElementById('modal-router-role').value;
  const host = document.getElementById('modal-router-host').value.trim();
  const port = parseInt(document.getElementById('modal-router-port').value, 10);
  const username = document.getElementById('modal-router-user').value.trim();
  const password = document.getElementById('modal-router-pass').value;
  const use_ssl = document.getElementById('modal-router-ssl').checked;
  const use_rest = document.getElementById('modal-router-rest').checked;
  const enabled = document.getElementById('modal-router-enabled').checked;
  const notes = document.getElementById('modal-router-notes').value.trim();

  const saveBtn = document.getElementById('btn-save-router');
  if (saveBtn) saveBtn.disabled = true;

  try {
    if (!routerId) {
      // Create new router
      const payload = {
        name, role, host, port, username, password,
        use_ssl, use_rest, enabled, notes
      };

      const res = await fetch('/api/routers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to onboard router');

      showToast(`Router '${name}' onboarded successfully!`, 'success');
    } else {
      // Update existing router
      const payload = {
        name, role, host, port, username,
        use_ssl, use_rest, enabled, notes
      };
      if (password) {
        payload.password = password;
      }

      const res = await fetch(`/api/routers/${routerId}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        credentials: 'include',
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to update router');

      showToast(`Router '${name}' updated successfully!`, 'success');
    }

    closeRouterModal();
    loadRouters();
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    if (saveBtn) saveBtn.disabled = false;
  }
}

async function testModalRouterConnection() {
  const routerId = document.getElementById('modal-router-id')?.value;
  const resBox = document.getElementById('modal-router-test-result');
  const btn = document.getElementById('btn-test-modal-router');

  const host = document.getElementById('modal-router-host')?.value.trim();
  const port = parseInt(document.getElementById('modal-router-port')?.value || '8728', 10);
  const username = document.getElementById('modal-router-user')?.value.trim() || 'security_ro';
  const password = document.getElementById('modal-router-pass')?.value || '';
  const use_ssl = document.getElementById('modal-router-ssl')?.checked || false;
  const use_rest = document.getElementById('modal-router-rest')?.checked || false;

  if (!routerId && !host) {
    showToast('Please enter an IP address or hostname to test.', 'warning');
    return;
  }

  if (btn) btn.disabled = true;
  if (resBox) {
    resBox.classList.remove('hidden');
    resBox.className = 'p-3 rounded-xl text-xs font-mono bg-dark-900 border border-slate-700 text-slate-300';
    resBox.innerHTML = '<span class="animate-pulse">Connecting to router API and retrieving live /system/resource...</span>';
  }

  try {
    let url = `/api/routers/${routerId}/test`;
    let options = {
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include'
    };

    if (!routerId) {
      url = '/api/routers/test-connection';
      options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...getAuthHeaders()
        },
        credentials: 'include',
        body: JSON.stringify({ host, port, username, password, use_ssl, use_rest })
      };
    }

    const res = await fetch(url, options);
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Connection test failed');

    const isOnline = Boolean(data.online);
    const model = data.model || data.board_name || 'MikroTik Router';
    const rosVersion = data.ros_version || data.routeros_version || 'RouterOS v7';
    const cpuLoad = data.cpu_load !== null && data.cpu_load !== undefined ? data.cpu_load + '%' : 'N/A';
    const uptime = data.uptime || 'N/A';
    const latency = data.latency_ms ? data.latency_ms.toFixed(1) + 'ms' : (data.response_time_ms ? data.response_time_ms.toFixed(1) + 'ms' : '< 1ms');
    const pppoeCount = data.pppoe_count || data.active_pppoe_count || 0;
    const errorMsg = data.error || data.error_message || 'Connection failed';

    if (isOnline) {
      resBox.className = 'p-3 rounded-xl text-xs font-mono bg-emerald-950/40 border border-emerald-500/40 text-emerald-300';
      resBox.innerHTML = `
        <div class="font-bold flex items-center gap-1.5"><i data-lucide="check-circle" class="w-4 h-4 text-emerald-400"></i> CONNECTION SUCCESSFUL</div>
        <div class="mt-1">Model: <strong class="text-white">${escapeHtml(model)}</strong></div>
        <div>RouterOS Version: <strong class="text-white">${escapeHtml(rosVersion)}</strong></div>
        <div>CPU Load: <strong class="text-white">${cpuLoad}</strong> | Uptime: <strong class="text-white">${escapeHtml(uptime)}</strong></div>
        <div>Active PPPoE Sessions: <strong class="text-white">${pppoeCount}</strong></div>
        <div>Latency: <strong class="text-white">${latency}</strong></div>
      `;
      showToast('Router connection verified successfully!', 'success');
    } else {
      resBox.className = 'p-3 rounded-xl text-xs font-mono bg-rose-950/40 border border-rose-500/40 text-rose-300';
      resBox.innerHTML = `
        <div class="font-bold">✗ CONNECTION FAILED</div>
        <div class="mt-1">Error: ${escapeHtml(errorMsg)}</div>
      `;
      showToast(`Router connection failed: ${errorMsg}`, 'error');
    }
    if (window.lucide) lucide.createIcons();
    if (routerId) loadRouters();
  } catch (err) {
    if (resBox) {
      resBox.className = 'p-3 rounded-xl text-xs font-mono bg-rose-950/40 border border-rose-500/40 text-rose-300';
      resBox.innerHTML = `<div>Error: ${escapeHtml(err.message)}</div>`;
    }
    showToast(err.message, 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function testRouterConnection(routerId) {
  try {
    showToast('Testing router connectivity...', 'info');
    const res = await fetch(`/api/routers/${routerId}/test`, {
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include'
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Test failed');

    if (data.online) {
      showToast(`Router Online! ROS ${data.ros_version || 'v7'}, CPU: ${data.cpu_load || 0}%`, 'success');
    } else {
      showToast(`Router Offline: ${data.error || 'Connection failed'}`, 'error');
    }
    loadRouters();
  } catch (err) {
    showToast('Connection test error: ' + err.message, 'error');
  }
}

async function harvestRouterSessions(routerId) {
  try {
    showToast('Harvesting active subscriber sessions...', 'info');
    const res = await fetch(`/api/routers/${routerId}/harvest`, {
      method: 'POST',
      headers: getAuthHeaders(),
      credentials: 'include'
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Harvest failed');

    showToast(`Harvest complete: ${data.harvested_sessions} active sessions synchronized!`, 'success');
    loadRouters();
  } catch (err) {
    showToast('Harvest error: ' + err.message, 'error');
  }
}

async function deleteRouter(routerId, routerNameEncoded) {
  const routerName = decodeURIComponent(routerNameEncoded || '');
  if (!confirm(`Are you sure you want to delete router '${routerName}' from the fleet?`)) return;

  try {
    const res = await fetch(`/api/routers/${routerId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
      credentials: 'include'
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Delete failed');

    showToast(`Router '${routerName}' removed from fleet.`, 'success');
    loadRouters();
  } catch (err) {
    showToast('Delete error: ' + err.message, 'error');
  }
}

// ============================================================================
// SYSTEM UPDATES CONTROLLER (GITHUB chavxxx/SpecOPS)
// ============================================================================
let updateCheckInProgress = false;

async function checkSystemUpdate(manual = false) {
  if (updateCheckInProgress) return;
  updateCheckInProgress = true;

  const spinner = document.getElementById('update-spinner');
  if (spinner) spinner.classList.add('animate-spin');

  const pillBadge = document.getElementById('system-update-badge');
  const pillVersion = document.getElementById('system-version-text');

  try {
    const res = await fetch('/api/system/update/check', {
      headers: getAuthHeaders(),
      credentials: 'include'
    });

    if (!res.ok) {
      if (pillBadge) {
        pillBadge.innerText = 'OFFLINE';
        pillBadge.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700';
      }
      return;
    }

    const data = await res.json();

    // Update Header Pill
    if (pillVersion && data.current_version) {
      pillVersion.innerText = data.current_version;
    }

    if (pillBadge) {
      if (data.has_update) {
        pillBadge.innerText = 'UPDATE AVAILABLE';
        pillBadge.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse';
      } else {
        pillBadge.innerText = 'UP TO DATE';
        pillBadge.className = 'px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
      }
    }

    // Update Modal Content
    renderUpdateModal(data);

    if (manual) {
      if (data.has_update) {
        showToast('New update available from GitHub (chavxxx/SpecOPS)!', 'info');
      } else {
        showToast('System is up to date with chavxxx/SpecOPS (main)!', 'success');
      }
    }
  } catch (err) {
    console.error('System update check error:', err);
    if (manual) showToast('Failed to check updates: ' + err.message, 'error');
  } finally {
    updateCheckInProgress = false;
    if (spinner) spinner.classList.remove('animate-spin');
  }
}

function renderUpdateModal(data) {
  const statusIcon = document.getElementById('update-status-icon');
  const statusHeader = document.getElementById('update-status-header');
  const statusBadge = document.getElementById('update-status-badge');
  const localVer = document.getElementById('update-local-version');
  const localCommit = document.getElementById('update-local-commit');
  const remoteBranch = document.getElementById('update-remote-branch');
  const remoteCommit = document.getElementById('update-remote-commit');
  const commitDetails = document.getElementById('update-commit-details');
  const commitMsg = document.getElementById('update-commit-message');
  const commitMeta = document.getElementById('update-commit-meta');
  const alertBox = document.getElementById('update-alert-box');
  const applyBtn = document.getElementById('btn-apply-update');

  if (localVer) localVer.innerText = data.current_version || 'v1.2.0';
  if (localCommit) localCommit.innerText = data.current_commit || 'unknown';
  if (remoteBranch) remoteBranch.innerText = data.repo ? `${data.repo} (main)` : 'chavxxx/SpecOPS (main)';
  if (remoteCommit) remoteCommit.innerText = data.remote_commit || '—';

  if (data.has_update) {
    if (statusIcon) statusIcon.className = 'w-3 h-3 rounded-full bg-amber-400 animate-pulse';
    if (statusHeader) statusHeader.innerText = 'New Update Available on origin/main';
    if (statusBadge) {
      statusBadge.innerText = 'UPDATE READY';
      statusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40';
    }

    if (commitDetails && data.remote_commit_message) {
      commitDetails.classList.remove('hidden');
      if (commitMsg) commitMsg.innerText = data.remote_commit_message;
      if (commitMeta) {
        commitMeta.innerText = `Authored by ${data.remote_commit_author || 'chavxxx'} · ${formatLocalTime(data.remote_commit_date, true)}`;
      }
    }

    if (alertBox) {
      alertBox.className = 'p-3 rounded-lg bg-amber-950/40 border border-amber-500/40 text-xs text-amber-200';
      alertBox.innerHTML = `<strong>Update Available:</strong> Origin repository has newer commits. Applying update will pull from <code>main</code>, migrate local databases, and refresh services.`;
    }

    if (applyBtn) {
      applyBtn.classList.remove('hidden');
      applyBtn.disabled = false;
    }
  } else {
    if (statusIcon) statusIcon.className = 'w-3 h-3 rounded-full bg-emerald-400';
    if (statusHeader) statusHeader.innerText = 'SpecOPS is Fully Up to Date';
    if (statusBadge) {
      statusBadge.innerText = 'SYNCED';
      statusBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';
    }

    if (commitDetails) commitDetails.classList.add('hidden');

    if (alertBox) {
      alertBox.className = 'p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-xs text-emerald-300';
      alertBox.innerHTML = `Your SpecOPS deployment is running the latest commit matching <code>origin/main</code> on <strong>chavxxx/SpecOPS</strong>.`;
    }

    if (applyBtn) {
      applyBtn.classList.add('hidden');
      applyBtn.disabled = true;
    }
  }
}

function openUpdateModal() {
  document.getElementById('modal-system-update').classList.remove('hidden');
  checkSystemUpdate(false);
  if (window.lucide) lucide.createIcons();
}

function closeUpdateModal() {
  document.getElementById('modal-system-update').classList.add('hidden');
}

async function applySystemUpdate() {
  if (!confirm('Are you sure you want to apply system updates from GitHub repository chavxxx/SpecOPS? This will fast-forward your local checkout.')) {
    return;
  }

  const applyBtn = document.getElementById('btn-apply-update');
  const alertBox = document.getElementById('update-alert-box');

  if (applyBtn) {
    applyBtn.disabled = true;
    applyBtn.innerHTML = '<i data-lucide="refresh-cw" class="w-3.5 h-3.5 animate-spin"></i> Updating Platform...';
  }

  if (alertBox) {
    alertBox.className = 'p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/40 text-xs text-cyan-200 animate-pulse';
    alertBox.innerText = 'Fetching commits from origin/main, resetting working tree, and refreshing python packages...';
  }

  try {
    const res = await fetch('/api/system/update/apply', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...getAuthHeaders()
      },
      credentials: 'include',
      body: JSON.stringify({ branch: 'main' })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Update execution failed');

    showToast('Platform updated successfully! Reloading in 3 seconds...', 'success');

    if (alertBox) {
      alertBox.className = 'p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-xs text-emerald-200';
      alertBox.innerHTML = `<strong>Update Succeeded:</strong> ${escapeHtml(data.message || 'Updated to latest commit')}. Reloading page...`;
    }

    setTimeout(() => {
      window.location.reload();
    }, 3000);
  } catch (err) {
    showToast('Update failed: ' + err.message, 'error');
    if (alertBox) {
      alertBox.className = 'p-3 rounded-lg bg-rose-950/40 border border-rose-500/40 text-xs text-rose-200';
      alertBox.innerText = 'Update failed: ' + err.message;
    }
    if (applyBtn) {
      applyBtn.disabled = false;
      applyBtn.innerHTML = '<i data-lucide="download" class="w-3.5 h-3.5"></i> Retry Update';
    }
  }
}

// ============================================================================
// APPLICATION BOOTSTRAP
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  checkAuthStatus();
  checkSystemUpdate(false);
});
