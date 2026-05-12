// Live-logs tab controller — the first Vaultify frontend module
// extracted from the monolithic app.js. Phase 4 pattern:
//
//   attachLogsController(App)
//
// installs state + methods onto the singleton App object so existing
// inline onclick handlers (e.g. onclick="App.toggleLogsPause()") keep
// working. Future modules follow the same shape; nothing is rewired at
// the top level.
//
// All DOM access is scoped to #logsOutput / #logsLiveDot / etc. so
// the module is safe to attach even if those nodes are not in the
// current page.

import { byId, toggleClass } from '../shared/dom.js';

const LEVEL_RANK = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
const FILTER_TO_RANK = { debug: 0, info: 1, warn: 2, error: 3 };
const LEVEL_CLASSES = { DEBUG: 'lg-debug', INFO: 'lg-info', WARN: 'lg-warn', ERROR: 'lg-error' };

const MAX_BUFFER = 1500;
const INITIAL_TAIL_LIMIT = 200;
const RECONNECT_DELAY_MS = 2000;

export function attachLogsController(App) {
  const state = {
    logs: [],
    paused: false,
    levelFilter: 'info',
    categoryFilter: 'all',
    ws: null,
    initialised: false,
  };

  Object.assign(App, {
    async loadLogs() {
      if (!state.initialised) {
        state.initialised = true;
        try {
          const recs = await (await fetch(`/api/logs/tail?limit=${INITIAL_TAIL_LIMIT}`)).json();
          if (Array.isArray(recs)) state.logs = recs;
        } catch (_) {}
      }
      renderLogs(App, state);
      connectLogsWs(App, state);
    },

    toggleLogsPause() {
      state.paused = !state.paused;
      const btn = byId('btnLogsPause');
      if (btn) btn.textContent = state.paused ? 'Resume' : 'Pause';
    },

    setLogsLevel(level) {
      if (!Object.prototype.hasOwnProperty.call(FILTER_TO_RANK, level)) return;
      state.levelFilter = level;
      document.querySelectorAll('.logs-level-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.level === level);
      });
      renderLogs(App, state);
    },

    /**
     * Filter records by an inferred category. Categories come from the
     * record itself: explicit `category` attr (audit), or msg/attr
     * heuristics (http.* → http, op.* → op, vault_auth → vault_auth, etc).
     */
    setLogsCategory(cat) {
      const allowed = ['all', 'http', 'op', 'vault_auth', 'vee', 'audit', 'scan'];
      if (!allowed.includes(cat)) cat = 'all';
      state.categoryFilter = cat;
      const sel = byId('logsCategorySelect');
      if (sel && sel.value !== cat) sel.value = cat;
      renderLogs(App, state);
    },

    clearLogs() {
      state.logs = [];
      renderLogs(App, state);
    },

    copyLogs() {
      const text = filteredLogs(state).map(formatLogRow).join('\n');
      if (!text) {
        App.showToast('No logs to copy.', 'warning');
        return;
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(
          () => App.showToast('Copied logs to clipboard', 'success'),
          () => App.showToast('Copy failed', 'error'),
        );
      } else {
        App.showToast('Clipboard not available', 'error');
      }
    },
  });
}

function connectLogsWs(App, state) {
  if (state.ws && state.ws.readyState <= 1) return;
  try {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/api/logs/ws`);
    ws.onopen = () => {
      toggleClass(byId('logsLiveDot'), 'active', true);
      toggleClass(byId('activityLiveDot'), 'active', true);
    };
    ws.onmessage = (e) => {
      try {
        const rec = JSON.parse(e.data);
        if (state.paused) return;
        state.logs.push(rec);
        if (state.logs.length > MAX_BUFFER) {
          state.logs.splice(0, state.logs.length - MAX_BUFFER);
        }
        renderLogs(App, state);
      } catch (_) {}
    };
    ws.onclose = () => {
      state.ws = null;
      toggleClass(byId('logsLiveDot'), 'active', false);
      toggleClass(byId('activityLiveDot'), 'active', false);
      // Page was renamed `logs` -> `activity` when Audit was merged.
      // Keep the legacy `logs` literal so a downgrade still reconnects.
      if (App.currentPage === 'activity' || App.currentPage === 'logs') {
        setTimeout(() => connectLogsWs(App, state), RECONNECT_DELAY_MS);
      }
    };
    ws.onerror = () => {};
    state.ws = ws;
  } catch (_) {}
}

/**
 * Heuristic category resolver. Records carry a `category` attribute when
 * the server explicitly tagged them (audit events), otherwise we infer
 * from the slog message prefix used by middleware and helpers:
 *   http.start / http.finish     -> http
 *   op.start / op.finish / op.error -> op
 *   vault_auth                   -> vault_auth (broadcast also has type=vault_auth)
 *   vee.* / chat.*               -> vee
 *   scan.* / audit.scan_*        -> scan
 *   audit.*                      -> audit
 */
function categoryOf(r) {
  if (r && r.attrs && typeof r.attrs.category === 'string' && r.attrs.category) return r.attrs.category;
  if (r && r.attrs && r.attrs.subsystem === 'vault') return 'op';
  if (r && r.attrs && r.attrs.subsystem === 'vee') return 'vee';
  const msg = (r && r.msg) || '';
  if (msg.startsWith('http.')) return 'http';
  if (msg.startsWith('op.')) return 'op';
  if (msg.startsWith('chat.') || msg.startsWith('vee.') || msg === 'fp_finder.error') return 'vee';
  if (msg.startsWith('scan.') || msg.startsWith('audit.scan_') || msg.startsWith('audit.remediation')) return 'scan';
  if (msg.startsWith('audit.')) return 'audit';
  if (msg.includes('vault_auth') || msg === 'signin.begin' || msg === 'signin.success' || msg === 'signin.timeout') return 'vault_auth';
  return 'other';
}

function filteredLogs(state) {
  const min = FILTER_TO_RANK[state.levelFilter] ?? 1;
  const wantCat = state.categoryFilter || 'all';
  return state.logs.filter(r => {
    if ((LEVEL_RANK[r.level] ?? 1) < min) return false;
    if (wantCat !== 'all' && categoryOf(r) !== wantCat) return false;
    return true;
  });
}

function formatLogRow(r) {
  const time = (r.time || '').replace('T', ' ').replace(/\..*Z$/, 'Z');
  const attrs = r.attrs && Object.keys(r.attrs).length
    ? ' ' + Object.entries(r.attrs)
        .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
        .join(' ')
    : '';
  return `${time} ${(r.level || 'INFO').padEnd(5)} ${r.msg || ''}${attrs}`;
}

function renderLogs(App, state) {
  const el = byId('logsOutput');
  const badge = byId('logsCountBadge');
  if (!el) return;
  const rows = filteredLogs(state);
  if (badge) badge.textContent = rows.length;
  if (rows.length === 0) {
    el.textContent = 'No log records match the current level filter.';
    return;
  }
  const frag = document.createDocumentFragment();
  rows.forEach(r => {
    const span = document.createElement('span');
    span.className = LEVEL_CLASSES[r.level] || 'lg-info';
    span.textContent = formatLogRow(r) + '\n';
    frag.appendChild(span);
  });
  el.textContent = '';
  el.appendChild(frag);
  el.scrollTop = el.scrollHeight;
}
