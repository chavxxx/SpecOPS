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

function openLoginModal(mandatory = false) {
  const modal = document.getElementById('modal-login');
  if (!modal) return;
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  const closeBtn = document.getElementById('btn-close-login');
  if (closeBtn) {
    if (!currentUser) closeBtn.classList.add('hidden');
    else closeBtn.classList.remove('hidden');
  }

  setTimeout(() => document.getElementById('login-username')?.focus(), 50);
}

function closeLoginModal() {
  if (!currentUser) {
    showToast('Please sign in to access WISPnet SecOps Console', 'warning');
    return;
  }
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
async function loadUsers() {
  const tbody = document.getElementById('users-table-body');
  if (!tbody) return;

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
            <button onclick="openEditUserModal('${u.id}')" class="px-2.5 py-1 rounded-lg bg-dark-800 hover:bg-dark-700 border border-slate-700 text-slate-200 text-xs font-semibold">
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
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-8 text-rose-400 font-sans">
          Failed to load users: ${err.message}
        </td>
      </tr>
    `;
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
// APPLICATION BOOTSTRAP
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) {
    lucide.createIcons();
  }
  checkAuthStatus();
});
