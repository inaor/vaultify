// Posture controller — fetches /api/posture and renders the rolling
// 30-day fingerprint view.
//
// State lives on the App object under `posture` so the rest of the
// app can poke it (e.g. invalidate after Apply). The DOM is rendered
// from data without innerHTML+string concat for the row list to keep
// XSS risk near zero.
import { byId } from '/assets/shared/dom.js';

const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };

export function attachPostureController(App) {
  App.posture = {
    summary: null,
    findings: [],
    filterStatus: 'all',     // all | present | deleted
    filterSeverity: 'all',   // all | high | medium | low
    search: '',
    loading: false,
    error: '',
  };

  /**
   * Fetch /api/posture and render.
   */
  App.loadPosture = async function loadPosture(opts) {
    const force = !!(opts && opts.force);
    if (this.posture.loading && !force) return;
    this.posture.loading = true;
    this.posture.error = '';
    renderPosture(this);

    try {
      const resp = await fetch('/api/posture', { headers: { 'Accept': 'application/json' } });

      if (resp.status === 402) {
        const body = await resp.json().catch(() => ({}));
        this.posture.loading = false;
        this.posture.error = (body && body.message) ? String(body.message) : 'This feature is not available.';
        renderPosture(this);
        this.showToast(this.posture.error, 'warning');
        return;
      }

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const data = await resp.json();
      this.posture.summary = data.summary || { window_days: 30 };
      this.posture.findings = Array.isArray(data.findings) ? data.findings : [];
      this.posture.loading = false;
      renderPosture(this);
    } catch (err) {
      this.posture.loading = false;
      this.posture.error = String(err && err.message ? err.message : err);
      renderPosture(this);
    }
  };

  App.setPostureStatusFilter = function (val) {
    this.posture.filterStatus = val || 'all';
    renderPosture(this);
  };
  App.setPostureSeverityFilter = function (val) {
    this.posture.filterSeverity = val || 'all';
    renderPosture(this);
  };
  App.setPostureSearch = function (val) {
    this.posture.search = (val || '').toLowerCase();
    renderPosture(this);
  };
  App.refreshPosture = function () {
    this.loadPosture({ force: true });
  };

  // Reload whenever the user navigates to the Posture tab so the data
  // is current — no need to remember to call loadPosture from button
  // handlers.
  const prev = App.navigate ? App.navigate.bind(App) : null;
  App.navigate = function (page) {
    if (prev) prev(page);
    if (page === 'posture') this.loadPosture();
  };
}

function renderPosture(App) {
  renderSummary(App);
  renderTable(App);
}

function renderSummary(App) {
  const root = byId('postureSummary');
  if (!root) return;
  const s = App.posture.summary;
  if (App.posture.loading && !s) {
    root.innerHTML = '<div class="post-empty">Loading 30-day posture…</div>';
    return;
  }
  if (App.posture.error) {
    root.innerHTML = `<div class="post-empty post-empty-err">Could not load posture: ${escapeHTML(App.posture.error)}</div>`;
    return;
  }
  if (!s) {
    root.innerHTML = '<div class="post-empty">No posture data yet. Run a scan to populate.</div>';
    return;
  }
  // The "Active right now" card is the hero of the page: present rows
  // whose last validation was confirmed live by the provider. That's
  // the number Vaultify exists to drive to zero.
  root.innerHTML = `
    <div class="post-cards">
      <div class="post-card post-card--active">
        <div class="post-card-label">Active right now</div>
        <div class="post-card-value">${s.active_present ?? 0}</div>
        <div class="post-card-foot">live keys, present on disk</div>
      </div>
      <div class="post-card post-card--total">
        <div class="post-card-label">Tracked findings</div>
        <div class="post-card-value">${s.total ?? 0}</div>
        <div class="post-card-foot">across last ${s.window_days ?? 30} days · ${s.scans_in_window ?? 0} scan${s.scans_in_window === 1 ? '' : 's'}</div>
      </div>
      <div class="post-card post-card--present">
        <div class="post-card-label">Present</div>
        <div class="post-card-value">${s.present ?? 0}</div>
        <div class="post-card-foot">still on disk</div>
      </div>
      <div class="post-card post-card--deleted">
        <div class="post-card-label">Removed</div>
        <div class="post-card-value">${s.deleted ?? 0}</div>
        <div class="post-card-foot">since last seen</div>
      </div>
      <div class="post-card post-card--sev">
        <div class="post-card-label">Present by severity</div>
        <div class="post-sev-row">
          <span class="post-sev-pill post-sev-high">High ${s.high_present ?? 0}</span>
          <span class="post-sev-pill post-sev-med">Medium ${s.medium_present ?? 0}</span>
          <span class="post-sev-pill post-sev-low">Low ${s.low_present ?? 0}</span>
        </div>
      </div>
    </div>
  `;
}

function renderTable(App) {
  const tbody = byId('postureTbody');
  const countEl = byId('postureFilteredCount');
  if (!tbody) return;

  const rows = filteredRows(App);
  if (countEl) countEl.textContent = String(rows.length);

  if (App.posture.loading && rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="post-empty">Loading…</td></tr>`;
    return;
  }
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="post-empty">No findings match the current filters.</td></tr>`;
    return;
  }

  // Build via DOM rather than innerHTML to avoid any chance of HTML
  // injection from finding text. The redacted preview is server-side
  // sanitised but defence-in-depth here is cheap.
  const frag = document.createDocumentFragment();
  for (const f of rows) {
    const tr = document.createElement('tr');
    tr.className = `post-row post-row--${f.status}`;

    appendCell(tr, severityPill(f.severity));
    appendCell(tr, statusPill(f));
    appendCell(tr, textCell(f.pattern_id));

    const path = document.createElement('td');
    path.className = 'post-path';
    const pathSpan = document.createElement('div');
    pathSpan.className = 'post-path-rel';
    pathSpan.textContent = f.relative_path;
    pathSpan.title = `${f.root}\n${f.relative_path}:${f.line_number}`;
    path.appendChild(pathSpan);
    const pathRoot = document.createElement('div');
    pathRoot.className = 'post-path-root';
    pathRoot.textContent = f.root;
    path.appendChild(pathRoot);
    tr.appendChild(path);

    const preview = document.createElement('td');
    preview.className = 'post-preview';
    const code = document.createElement('code');
    code.textContent = f.redacted_preview || '—';
    preview.appendChild(code);
    tr.appendChild(preview);

    appendCell(tr, timelineCell(f), 'post-timeline');

    frag.appendChild(tr);
  }
  tbody.replaceChildren(frag);
}

function filteredRows(App) {
  const { findings, filterStatus, filterSeverity, search } = App.posture;
  return findings.filter(f => {
    if (filterStatus !== 'all' && f.status !== filterStatus) return false;
    if (filterSeverity !== 'all' && f.severity !== filterSeverity) return false;
    if (search) {
      const hay = `${f.pattern_id} ${f.relative_path} ${f.root}`.toLowerCase();
      if (!hay.includes(search)) return false;
    }
    return true;
  }).sort((a, b) => {
    // Present before deleted, then by severity, then most recent first.
    if (a.status !== b.status) return a.status === 'present' ? -1 : 1;
    const ar = SEVERITY_RANK[a.severity] ?? 9;
    const br = SEVERITY_RANK[b.severity] ?? 9;
    if (ar !== br) return ar - br;
    return (b.last_seen || '').localeCompare(a.last_seen || '');
  });
}

function severityPill(sev) {
  const span = document.createElement('span');
  span.className = `post-pill post-pill--sev post-pill--sev-${sev || 'unknown'}`;
  span.textContent = (sev || 'unknown').toUpperCase();
  return span;
}

function statusPill(f) {
  const span = document.createElement('span');
  span.className = `post-pill post-pill--status post-pill--status-${f.status}`;
  if (f.status === 'present') {
    span.textContent = 'Present';
  } else {
    const days = relativeDaysAgo(f.deleted_at);
    span.textContent = days ? `Removed ${days}` : 'Removed';
    if (f.deleted_at) span.title = `Last seen: ${f.last_seen}\nRemoved: ${f.deleted_at}`;
  }
  return span;
}

function textCell(text) {
  const span = document.createElement('span');
  span.textContent = text || '—';
  return span;
}

function timelineCell(f) {
  const wrap = document.createElement('div');
  wrap.className = 'post-timeline-wrap';

  const last = document.createElement('div');
  last.textContent = `Last seen ${relativeDaysAgo(f.last_seen) || '—'}`;
  last.title = f.last_seen || '';
  wrap.appendChild(last);

  const first = document.createElement('div');
  first.className = 'post-timeline-first';
  first.textContent = `First ${relativeDaysAgo(f.first_seen) || '—'}`;
  first.title = f.first_seen || '';
  wrap.appendChild(first);

  return wrap;
}

function appendCell(tr, content, className) {
  const td = document.createElement('td');
  if (className) td.className = className;
  if (content instanceof Node) {
    td.appendChild(content);
  } else {
    td.textContent = String(content);
  }
  tr.appendChild(td);
}

function relativeDaysAgo(iso) {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const days = Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24));
  if (days <= 0) return 'today';
  if (days === 1) return '1 day ago';
  return `${days} days ago`;
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}
