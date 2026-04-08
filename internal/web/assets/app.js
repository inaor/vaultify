const App = {
  ws: null,
  state: { status: 'idle', dirs_visited: 0, candidates_queued: 0, files_scanned: 0, hits_total: 0, progress_denominator: 1, file_cap: 100000, pattern_totals: [], findings: [] },
  decisions: {},
  currentPage: 'dashboard',
  vaultList: [],
  sessionId: null,

  init() {
    this.connectWebSocket();
    this.setupNavigation();
    this.navigate(window.location.hash.slice(1) || 'dashboard');
    this.loadVaults();
    this.loadSessions();
    this.loadVeeProviders();
  },

  connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    this.ws = new WebSocket(`${proto}://${location.host}/api/scan/ws`);
    this.ws.onmessage = (e) => { try { this.handleMessage(JSON.parse(e.data)); } catch (err) { console.warn('WS error', err); } };
    this.ws.onclose = () => { setTimeout(() => this.connectWebSocket(), 3000); };
  },

  handleMessage(msg) {
    switch (msg.type) {
      case 'scan_progress':
        this.state.status = 'running';
        this.state.files_scanned = msg.progress || 0;
        this.state.progress_denominator = msg.total || 1;
        break;
      case 'scan_finding':
        if (msg.finding) {
          this.state.findings.push(msg.finding);
          this.state.hits_total = this.state.findings.length;
          this.updatePatternTotals();
        }
        break;
      case 'scan_complete':
        this.state.status = 'complete';
        this.sessionId = msg.sessionId;
        this.loadSessions();
        break;
    }
    this.updateDashboard();
    this.updateNav();
    this.updateButtons();
  },

  updatePatternTotals() {
    const map = {};
    this.state.findings.forEach(f => { if (!map[f.pattern_id]) map[f.pattern_id] = 0; map[f.pattern_id]++; });
    this.state.pattern_totals = Object.keys(map).map(id => ({ id, n: map[id] })).sort((a, b) => b.n - a.n);
  },

  updateButtons() {
    const running = this.state.status === 'running';
    const hasFindings = this.state.findings && this.state.findings.length > 0;
    const el = id => document.getElementById(id);
    if (el('btnStartScan')) el('btnStartScan').style.display = running ? 'none' : '';
    if (el('btnStopScan')) el('btnStopScan').style.display = running ? '' : 'none';
    const summBtn = el('veeSummaryBtn');
    if (summBtn) {
      summBtn.disabled = !hasFindings;
      summBtn.style.opacity = hasFindings ? '' : '.35';
      summBtn.style.cursor = hasFindings ? '' : 'not-allowed';
    }
  },

  setupNavigation() {
    document.querySelectorAll('.sidebar nav a').forEach(a => {
      a.addEventListener('click', (e) => { e.preventDefault(); this.navigate(a.dataset.page); });
    });
  },

  navigate(page) {
    this.currentPage = page || 'dashboard';
    window.location.hash = this.currentPage;
    document.querySelectorAll('.sidebar nav a').forEach(a => { a.classList.toggle('active', a.dataset.page === this.currentPage); });
    document.querySelectorAll('.page').forEach(p => { p.classList.toggle('active', p.id === `page-${this.currentPage}`); });
    if (this.currentPage === 'reports') this.loadSessions();
    if (this.currentPage === 'review') this.renderReview();
  },

  updateNav() {
    const badge = document.getElementById('navFindingsBadge');
    if (badge) badge.textContent = this.state.hits_total || 0;
    const pill = document.getElementById('navStatusPill');
    if (!pill) return;
    const s = this.state.status || 'idle';
    const colors = { running: 'var(--accent)', complete: 'var(--ok)', error: 'var(--err)', idle: 'var(--muted)', stopped: 'var(--warn)' };
    const c = colors[s] || 'var(--muted)';
    pill.style.color = c; pill.style.borderColor = c;
    pill.querySelector('.status-text').textContent = s === 'running' ? 'Scanning' : s === 'complete' ? 'Complete' : s === 'idle' ? 'Ready' : s;
    pill.querySelector('.spinner').style.display = s === 'running' ? '' : 'none';
  },

  esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; },
  sevColor(pid) { if (/aws|stripe|openai|anthropic|private_key/.test(pid)) return '#f87171'; if (/gh_|github|gitlab|slack/.test(pid)) return '#fb923c'; if (/jwt|telegram|twilio/.test(pid)) return '#fbbf24'; return '#38bdf8'; },
  riskColor(r) { return r < 20 ? '#4ade80' : r < 50 ? '#fbbf24' : r < 75 ? '#fb923c' : '#f87171'; },
  riskLabel(r) { return r < 20 ? 'Low' : r < 50 ? 'Moderate' : r < 75 ? 'High' : 'Critical'; },
  dashOffset(pct) { return Math.round(251.2 - (251.2 * pct / 100)); },

  async startScan() {
    this.state = { status: 'running', dirs_visited: 0, candidates_queued: 0, files_scanned: 0, hits_total: 0, progress_denominator: 1, file_cap: 100000, pattern_totals: [], findings: [] };
    this.decisions = {};
    this._patternEls = {};
    const patEl = document.getElementById('patterns');
    if (patEl) patEl.innerHTML = '<div class="empty-msg">Scanning...</div>';
    this.updateDashboard(); this.updateButtons(); this.updateNav();
    try { const r = await (await fetch('/api/scan/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"roots":[]}' })).json(); this.sessionId = r.sessionId; } catch (err) { console.error('Start scan failed', err); }
  },

  async stopScan() {
    try { await fetch('/api/scan/stop', { method: 'POST' }); } catch (err) {}
    this.state.status = 'stopped';
    this.updateDashboard(); this.updateButtons(); this.updateNav();
  },

  updateDashboard() {
    if (this.currentPage !== 'dashboard') return;
    const s = this.state;
    const files = s.files_scanned || 0;
    const denom = Math.max(s.progress_denominator || 1, 1);
    const pct = Math.min(100, Math.round(100 * files / denom));
    const hits = s.hits_total || 0;
    const risk = hits ? Math.min(100, Math.round(hits * 3.5 + 2)) : 0;
    const rc = this.riskColor(risk);
    const sc = s.status === 'complete' ? '#4ade80' : s.status === 'error' ? '#f87171' : '#38bdf8';
    const el = id => document.getElementById(id);
    const set = (id, v) => { const e = el(id); if (e) e.textContent = v; };
    const setS = (id, p, v) => { const e = el(id); if (e) e.style[p] = v; };
    set('mFiles', files); set('mHits', hits); setS('mHits', 'color', hits > 0 ? rc : '');
    set('mPatterns', (s.pattern_totals || []).length);
    const pr = el('progRing'); if (pr) { pr.style.strokeDashoffset = this.dashOffset(pct); pr.style.stroke = sc; }
    set('progVal', pct + '%'); setS('progVal', 'color', sc); set('gFiles', files + ' / ' + denom); set('gCand', s.candidates_queued || 0); set('gCap', s.file_cap || 100000);
    const rr = el('riskRing'); if (rr) { rr.style.strokeDashoffset = this.dashOffset(risk); rr.style.stroke = rc; }
    set('riskVal', risk); setS('riskVal', 'color', rc); set('gRiskLabel', this.riskLabel(risk)); setS('gRiskLabel', 'color', rc); set('gHits', hits);
    const uniq = new Set(s.findings.map(f => f.match_sha256)).size;
    set('gUnique', uniq);
    set('gUnique2', uniq);
    this.renderPatterns(s.pattern_totals);
  },

  _patternEls: {},

  renderPatterns(pt) {
    const el = document.getElementById('patterns');
    if (!el) return;
    if (!pt || !pt.length) {
      if (!Object.keys(this._patternEls).length) el.innerHTML = '<div class="empty-msg">Start a scan to see results.</div>';
      return;
    }
    let max = 1; pt.forEach(r => { if (r.n > max) max = r.n; });
    const b = document.getElementById('patBadge'); if (b) b.textContent = pt.length + ' types';

    pt.forEach(r => {
      const w = Math.max(2, Math.round(100 * r.n / max));
      const c = this.sevColor(r.id);
      if (this._patternEls[r.id]) {
        const pe = this._patternEls[r.id];
        pe.fill.style.width = w + '%';
        pe.fill.style.background = c;
        pe.count.textContent = r.n;
      } else {
        const row = document.createElement('div');
        row.className = 'pat-row';
        row.innerHTML = `<span class="pat-label">${this.esc(r.id)}</span><div class="pat-bar-track"><div class="pat-bar-fill" style="width:${w}%;background:${c}"></div></div><span class="pat-count">${r.n}</span>`;
        el.querySelector('.empty-msg')?.remove();
        el.appendChild(row);
        this._patternEls[r.id] = {
          fill: row.querySelector('.pat-bar-fill'),
          count: row.querySelector('.pat-count')
        };
      }
    });
  },

  opSignedIn: false,

  async loadVaults() {
    try {
      const resp = await fetch('/api/vaults');
      this.vaultList = await resp.json();
      this.renderVaultStatus();
    } catch (err) {}
  },

  renderVaultStatus() {
    const el = document.getElementById('vaultStatus');
    if (!el) return;
    el.innerHTML = this.vaultList.map(v => {
      const check = v.installed ? '<span style="color:var(--ok)">✓</span>' : '<span style="color:var(--err)">✗</span>';
      let extra = '';
      if (!v.installed) {
        extra = ` <span style="font-size:.72rem;color:var(--muted);font-family:monospace">${this.esc(v.install_cmd || '')}</span>`;
      } else if (v.cli === 'op') {
        if (this.opSignedIn) {
          extra = ' <span style="font-size:.72rem;color:var(--ok);font-weight:600">vault open</span>';
        } else {
          extra = ' <button class="tb-btn" onclick="event.stopPropagation();App.openVault()" style="font-size:.72rem;padding:3px 10px;margin-left:8px;border-color:var(--ok);color:var(--ok)">Open Vault</button><span id="signInMsg" style="font-size:.72rem;color:var(--muted);margin-left:6px"></span>';
        }
      }
      return `<div class="vault-row">${check} <strong style="font-size:.84rem">${this.esc(v.name)}</strong>${extra}</div>`;
    }).join('');
    const authEl = document.getElementById('vaultAuth');
    if (authEl) authEl.innerHTML = '';
  },

  async openVault() {
    const msg = document.getElementById('signInMsg');
    if (msg) msg.textContent = 'Opening vault...';
    try {
      const r = await (await fetch('/api/vaults/signin', { method: 'POST' })).json();
      this.opSignedIn = r.signed_in;
      this.renderVaultStatus();
      if (r.signed_in) {
        this.loadVeeProviders(true);
      } else {
        const m = document.getElementById('signInMsg');
        if (m) m.innerHTML = '<span style="color:var(--warn)">Unlock 1Password app first.</span>';
      }
    } catch (e) {
      if (msg) msg.textContent = 'Request failed.';
    }
  },

  async loadSessions() {
    try {
      const sessions = await (await fetch('/api/sessions')).json();
      const el = document.getElementById('reportsContent');
      if (!el) return;
      const reportsBadge = document.querySelector('[data-page="reports"] .badge');
      if (reportsBadge) reportsBadge.textContent = (sessions || []).length;
      if (!sessions || !sessions.length) { el.innerHTML = '<div class="empty-msg">No scan sessions found.</div>'; return; }
      const thStyle = 'text-align:left;padding:10px 12px;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border)';
      let html = `<table style="width:100%;border-collapse:collapse;font-size:.88rem"><thead><tr><th style="${thStyle}">Date</th><th style="${thStyle}">Status</th><th style="${thStyle};text-align:center">Findings</th><th style="${thStyle};text-align:center">Remediation</th><th style="${thStyle};text-align:right"></th></tr></thead><tbody>`;
      sessions.forEach(s => {
        let dt = s.scanned_at || '';
        try { const d = new Date(dt); if (!isNaN(d.getTime())) dt = d.toLocaleString(); } catch(e) {}
        const fc = s.findings_count || 0;
        const rem = s.remediated || 0;
        const pct = fc > 0 ? Math.round(100 * rem / fc) : 0;
        const pctColor = pct === 0 ? 'var(--muted)' : pct < 50 ? 'var(--err)' : pct < 100 ? 'var(--warn)' : 'var(--ok)';
        const stColor = s.status === 'complete' ? 'var(--ok)' : s.status === 'running' ? 'var(--accent)' : 'var(--muted)';
        html += `<tr style="border-bottom:1px solid var(--border);transition:background .15s" onmouseover="this.style.background='rgba(56,189,248,.03)'" onmouseout="this.style.background=''">`;
        html += `<td style="padding:12px">${this.esc(dt)}</td>`;
        html += `<td style="padding:12px;color:${stColor};font-weight:600;font-size:.78rem;text-transform:uppercase">${this.esc(s.status||'complete')}</td>`;
        html += `<td style="padding:12px;text-align:center;font-weight:700;font-size:1.05rem;color:${fc>0?'var(--warn)':'var(--muted)'}">${fc}</td>`;
        html += `<td style="padding:12px;text-align:center">`;
        if (fc > 0) {
          html += `<div style="display:flex;align-items:center;gap:8px;justify-content:center">`;
          html += `<span style="font-weight:700;color:${pctColor}">${rem}/${fc}</span>`;
          html += `<div style="width:60px;height:6px;background:var(--border);border-radius:99px;overflow:hidden"><div style="height:100%;width:${pct}%;background:${pctColor};border-radius:99px;transition:width .4s"></div></div>`;
          html += `<span style="font-size:.78rem;font-weight:600;color:${pctColor}">${pct}%</span>`;
          html += `</div>`;
        } else {
          html += `<span style="color:var(--muted)">—</span>`;
        }
        html += `</td>`;
        html += `<td style="padding:12px;text-align:right">${fc > 0 ? `<button class="tb-btn" onclick="App.loadSessionFindings('${this.esc(s.id)}')" style="font-size:.78rem;padding:5px 12px">Review</button>` : ''}</td>`;
        html += `</tr>`;
      });
      el.innerHTML = html + '</tbody></table>';
    } catch (err) {}
  },

  async loadSessionFindings(sessionId) {
    try {
      const resp = await fetch(`/api/sessions/${sessionId}`);
      const session = await resp.json();
      if (session && session.findings) {
        this.state.findings = session.findings;
        this.state.hits_total = session.findings.length;
        this.state.status = 'complete';
        this.sessionId = sessionId;
        this.updatePatternTotals();
        this.decisions = {};
        this.navigate('review');
      }
    } catch (err) { console.warn('Load session failed', err); }
  },

  // --- REVIEW & DECIDE ---

  getGroups() {
    const map = {};
    (this.state.findings || []).forEach(f => {
      const h = f.match_sha256 || 'unknown';
      if (!map[h]) map[h] = { pattern_id: f.pattern_id, severity: f.severity, description: f.description, redacted_preview: f.redacted_preview, hash: h, locs: [] };
      map[h].locs.push(f);
    });
    return Object.values(map);
  },

  decisionCounts() {
    const c = { vault: 0, remove: 0, dismiss: 0, pending: 0 };
    this.getGroups().forEach(g => { const d = this.decisions[g.hash]; c[d ? d.action : 'pending']++; });
    return c;
  },

  setDecision(hash, action) {
    const group = this.getGroups().find(g => g.hash === hash);
    if (!group) return;
    this.decisions[hash] = { action, pattern_id: group.pattern_id, locations: group.locs.map(f => ({ full_path: f.full_path, relative_path: f.relative_path, line_number: f.line_number, match_sha256: f.match_sha256 })) };
    this.renderReview();
  },

  reviewPage: 0,
  REVIEW_PAGE_SIZE: 20,

  renderReview() {
    const el = document.getElementById('reviewContent');
    const statsEl = document.getElementById('reviewStats');
    if (!el) return;
    const groups = this.getGroups();
    const filter = (document.getElementById('reviewSearch') || {}).value || '';
    const q = filter.trim().toLowerCase();
    const filtered = q ? groups.filter(g => [g.pattern_id, g.redacted_preview, g.hash, ...g.locs.map(l => l.relative_path || l.full_path)].join(' ').toLowerCase().includes(q)) : groups;

    const cnt = this.decisionCounts();
    if (statsEl) {
      statsEl.innerHTML = `<span><strong>${groups.length}</strong> secrets</span><span style="color:var(--ok)">Vaultify <strong>${cnt.vault}</strong></span><span style="color:var(--err)">Remove <strong>${cnt.remove}</strong></span><span>Dismissed <strong>${cnt.dismiss}</strong></span><span>Pending <strong>${cnt.pending}</strong></span>`;
    }

    if (!filtered.length) { el.innerHTML = '<div class="empty-msg">' + (groups.length ? 'No matches for filter.' : 'No findings yet. Run a scan first.') + '</div>'; return; }

    const totalPages = Math.max(1, Math.ceil(filtered.length / this.REVIEW_PAGE_SIZE));
    if (this.reviewPage >= totalPages) this.reviewPage = totalPages - 1;
    if (this.reviewPage < 0) this.reviewPage = 0;
    const start = this.reviewPage * this.REVIEW_PAGE_SIZE;
    const pageItems = filtered.slice(start, start + this.REVIEW_PAGE_SIZE);

    const pillColors = { vault: 'background:rgba(74,222,128,.12);color:var(--ok)', remove: 'background:rgba(248,113,113,.1);color:var(--err)', dismiss: 'background:rgba(107,125,149,.12);color:var(--muted)', pending: 'background:rgba(107,125,149,.15);color:var(--muted)' };
    const pillLabels = { vault: 'Vaultify', remove: 'Remove From Code', dismiss: 'Dismissed', pending: 'Pending' };
    const lockSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>';
    const trashSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>';
    const xSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>';

    let html = '<table style="width:100%;border-collapse:collapse;font-size:.88rem"><thead><tr><th style="width:30px;padding:10px 8px;border-bottom:1px solid var(--border)"></th><th style="text-align:left;padding:10px 8px;color:var(--muted);font-size:.72rem;text-transform:uppercase;border-bottom:1px solid var(--border)">Pattern</th><th style="text-align:left;padding:10px 8px;color:var(--muted);font-size:.72rem;text-transform:uppercase;border-bottom:1px solid var(--border)">Preview</th><th style="text-align:center;padding:10px 8px;color:var(--muted);font-size:.72rem;text-transform:uppercase;border-bottom:1px solid var(--border)">Files</th><th style="text-align:center;padding:10px 8px;color:var(--muted);font-size:.72rem;text-transform:uppercase;border-bottom:1px solid var(--border)">Decision</th><th style="width:110px;padding:10px 8px;border-bottom:1px solid var(--border)"></th></tr></thead><tbody>';

    pageItems.forEach(g => {
      const dec = this.decisions[g.hash];
      const st = dec ? dec.action : 'pending';
      const sc = this.sevColor(g.pattern_id);
      const btnStyle = (act, icon) => `style="width:30px;height:28px;display:flex;align-items:center;justify-content:center;border:1px solid ${st===act?({vault:'var(--ok)',remove:'var(--err)',dismiss:'var(--muted)'}[act]):'var(--border)'};background:${st===act?({vault:'rgba(74,222,128,.15)',remove:'rgba(248,113,113,.1)',dismiss:'var(--bg2)'}[act]):'var(--panel)'};color:${({vault:'var(--ok)',remove:'var(--err)',dismiss:'var(--muted)'})[act]};border-radius:6px;cursor:pointer;padding:0" title="${({vault:'Vaultify',remove:'Remove from code',dismiss:'Dismiss'})[act]}"`;

      html += `<tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'table-row':'none'">`;
      html += `<td style="padding:8px"><span style="width:9px;height:9px;border-radius:50%;background:${sc};display:inline-block"></span></td>`;
      html += `<td style="padding:8px;font-family:monospace;font-size:12px;color:var(--accent)">${this.esc(g.pattern_id)}</td>`;
      html += `<td style="padding:8px;font-family:monospace;font-size:12px;color:var(--warn);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this.esc(g.redacted_preview)}</td>`;
      html += `<td style="padding:8px;text-align:center"><span style="background:var(--border);padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600">${g.locs.length}</span></td>`;
      html += `<td style="padding:8px;text-align:center"><span style="display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;${pillColors[st]}">${pillLabels[st]}</span></td>`;
      html += `<td style="padding:8px"><div style="display:flex;gap:4px" onclick="event.stopPropagation()">`;
      html += `<button onclick="App.setDecision('${g.hash}','vault')" ${btnStyle('vault')}>${lockSvg}</button>`;
      html += `<button onclick="App.setDecision('${g.hash}','remove')" ${btnStyle('remove')}>${trashSvg}</button>`;
      html += `<button onclick="App.setDecision('${g.hash}','dismiss')" ${btnStyle('dismiss')}>${xSvg}</button>`;
      html += `</div></td></tr>`;

      html += '<tr style="display:none;background:var(--bg2)"><td colspan="6" style="padding:10px 16px 14px 32px">';
      g.locs.forEach((f, fi) => {
        const hasSnippet = f.line_snippet && f.line_snippet.trim();
        html += `<div style="display:flex;align-items:baseline;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:12px">`;
        html += `<span style="color:var(--text);font-weight:600;flex-shrink:0">L${f.line_number}</span>`;
        html += `<span style="color:var(--muted);font-family:monospace;word-break:break-all;flex:1">${this.esc(f.relative_path || f.full_path)}</span>`;
        if (hasSnippet) html += `<span onclick="event.stopPropagation();var s=document.getElementById('snip-${g.hash}-${fi}');s.style.display=s.style.display==='none'?'block':'none'" style="font-size:10px;color:var(--accent);cursor:pointer;padding:2px 8px;background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.2);border-radius:4px;flex-shrink:0">snippet</span>`;
        html += `</div>`;
        if (hasSnippet) html += `<div id="snip-${g.hash}-${fi}" style="display:none;margin:6px 0 8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;color:#a8b9cc;white-space:pre-wrap;word-break:break-all;max-height:150px;overflow:auto;line-height:1.5">${this.esc(f.line_snippet)}</div>`;
      });
      html += '</td></tr>';
    });
    html += '</tbody></table>';

    if (totalPages > 1) {
      html += `<div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-top:16px;font-size:13px">`;
      html += `<button onclick="App.reviewPage--;App.renderReview()" ${this.reviewPage===0?'disabled':''} style="background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 14px;cursor:pointer;font:inherit;${this.reviewPage===0?'opacity:.35;cursor:not-allowed':''}">Prev</button>`;
      html += `<span style="color:var(--muted)">Page ${this.reviewPage+1} of ${totalPages} (${filtered.length} secrets)</span>`;
      html += `<button onclick="App.reviewPage++;App.renderReview()" ${this.reviewPage>=totalPages-1?'disabled':''} style="background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 14px;cursor:pointer;font:inherit;${this.reviewPage>=totalPages-1?'opacity:.35;cursor:not-allowed':''}">Next</button>`;
      html += `</div>`;
    }
    el.innerHTML = html;
  },

  // --- APPLY MODAL ---

  async showApplyModal() {
    const c = this.decisionCounts();
    if (c.vault + c.remove + c.dismiss === 0) { alert('No decisions made yet. Use the buttons in the Review table first.'); return; }

    const overlay = document.getElementById('applyOverlay');
    overlay.style.display = 'flex';

    let authOk = false;
    if (c.vault > 0) {
      try {
        const r = await (await fetch('/api/vaults/auth-status')).json();
        authOk = r.onepassword_signed_in;
      } catch (e) {}
    }

    let vaultHtml = '';
    if (c.vault > 0) {
      const op = this.vaultList.find(v => v.cli === 'op');
      if (!op || !op.installed) {
        vaultHtml = `<div style="background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.3);border-radius:8px;padding:10px 14px;color:var(--err);font-size:.85rem;margin-top:12px">1Password CLI not installed. Install: <code>winget install -e --id AgileBits.1Password.CLI</code></div>`;
      } else if (!authOk) {
        vaultHtml = `<div style="background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.3);border-radius:8px;padding:10px 14px;color:var(--warn);font-size:.85rem;margin-top:12px">Vault not open. Click "Open Vault" in the Scan tab first, then try again.</div>`;
      } else {
        let opts = '<option value="__new__">+ Create new vault</option>';
        try {
          const vaults = await (await fetch('/api/vaults/list-1p')).json();
          if (vaults && vaults.length) {
            vaults.forEach(v => { opts += `<option value="${this.esc(v.name)}">${this.esc(v.name)} (${v.items} items)</option>`; });
          }
        } catch (e) {}
        vaultHtml = `<div style="margin-top:12px"><label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Vault for ${c.vault} secret(s)</label><select id="vaultSelect" style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit" onchange="document.getElementById('newVaultName').style.display=this.value==='__new__'?'block':'none'">${opts}</select><input id="newVaultName" placeholder="Vault name (e.g. Vaultify)" style="display:none;width:100%;margin-top:8px;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit" value="Vaultify"></div>`;
      }
    }

    const body = document.getElementById('applyModalBody');
    body.innerHTML = `
      <div style="font-size:.85rem;margin-bottom:16px">
        <div style="display:flex;gap:20px;flex-wrap:wrap">
          <div><span style="color:var(--ok);font-weight:700;font-size:1.3rem">${c.vault}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Vault It</div></div>
          <div><span style="color:var(--err);font-weight:700;font-size:1.3rem">${c.remove}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Remove</div></div>
          <div><span style="color:var(--muted);font-weight:700;font-size:1.3rem">${c.dismiss}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Dismiss</div></div>
          <div><span style="font-weight:700;font-size:1.3rem">${c.vault + c.remove + c.dismiss}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Total</div></div>
        </div>
      </div>
      ${vaultHtml}
    `;

    const confirmBtn = document.getElementById('btnConfirmApply');
    confirmBtn.disabled = (c.vault > 0 && !authOk && this.vaultList.find(v => v.cli === 'op')?.installed);
  },

  hideApplyModal() {
    document.getElementById('applyOverlay').style.display = 'none';
  },

  async confirmApply() {
    const body = document.getElementById('applyModalBody');
    const footer = document.getElementById('applyModalFooter');
    footer.style.display = 'none';

    let vaultName = 'Vaultify';
    const sel = document.getElementById('vaultSelect');
    if (sel) {
      if (sel.value === '__new__') {
        const input = document.getElementById('newVaultName');
        vaultName = input ? input.value.trim() || 'Vaultify' : 'Vaultify';
        body.innerHTML = '<div style="text-align:center;padding:20px"><div style="width:24px;height:24px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin:0 auto 12px"></div>Creating vault...</div>';
        try {
          await fetch('/api/vaults/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: vaultName }) });
        } catch (e) {}
      } else {
        vaultName = sel.value;
      }
    }

    body.innerHTML = '<div style="text-align:center;padding:20px"><div style="width:24px;height:24px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin:0 auto 12px"></div>Applying decisions...</div>';

    const items = Object.entries(this.decisions).map(([hash, d]) => ({
      match_sha256: hash,
      action: d.action,
      pattern_id: d.pattern_id,
      locations: d.locations || []
    }));

    try {
      const resp = await fetch('/api/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: this.sessionId, vault_name: vaultName, items })
      });
      const result = await resp.json();
      this.showApplyResults(result);
    } catch (err) {
      body.innerHTML = `<div style="color:var(--err);padding:20px">Apply failed: ${this.esc(err.message)}</div>`;
      footer.style.display = 'flex';
    }
  },

  showApplyResults(result) {
    const body = document.getElementById('applyModalBody');
    const footer = document.getElementById('applyModalFooter');
    const results = result.results || [];
    let vaulted = 0, removed = 0, dismissed = 0, errors = 0;
    results.forEach(r => {
      if (!r.ok) errors++;
      else if (r.action === 'vault') vaulted++;
      else if (r.action === 'remove') removed++;
      else dismissed++;
    });

    let html = '<div style="font-size:.85rem">';
    if (dismissed > 0) html += `<div style="padding:4px 0;color:var(--muted)">✓ ${dismissed} dismissed</div>`;
    if (removed > 0) html += `<div style="padding:4px 0;color:var(--ok)">✓ ${removed} file(s) redacted <span style="color:var(--muted)">(REDACTED_BY_VAULTIFY)</span></div>`;
    if (vaulted > 0) html += `<div style="padding:4px 0;color:var(--ok)">✓ ${vaulted} ingested to vault</div>`;
    if (errors > 0) {
      html += `<div style="padding:4px 0;color:var(--warn)">⚠ ${errors} item(s) had errors</div>`;
      results.filter(r => !r.ok).forEach(r => {
        html += `<div style="padding:2px 0 2px 16px;font-size:.78rem;color:var(--muted)">${this.esc(r.error)}</div>`;
      });
    }
    html += '</div>';

    body.innerHTML = html;
    footer.innerHTML = '<button class="btn-primary" onclick="App.hideApplyModal()">Done</button>';
    footer.style.display = 'flex';
  },

  // --- VEE AI AGENT ---
  veeOpen: false,
  veeProvider: '',
  veeProviders: [],

  toggleVee() {},

  async loadVeeProviders(checkVault) {
    try {
      const url = checkVault ? '/api/vee/providers?check=1' : '/api/vee/providers';
      this.veeProviders = await (await fetch(url)).json();
      this.renderVeeProviders();
    } catch (e) { console.warn('Vee providers failed', e); }
  },

  renderVeeProviders() {
    const el = document.getElementById('veeProviders');
    if (!el) return;
    const logos = {
      openai: `<svg width="24" height="24" viewBox="0 0 320 320" fill="currentColor"><path d="M297.06 130.97c7.26-21.79 4.76-45.66-6.85-65.48-17.46-30.4-52.56-46.04-86.84-38.68C186.64 7.04 163.42-3.02 140.2.62c-34.87 5.43-61.94 34.34-67.05 69.44C49.82 75.87 30.1 93.12 22.3 116.7c-11.73 35.35 1.27 74.07 31.63 95.32-7.26 21.79-4.76 45.66 6.85 65.48 17.46 30.4 52.56 46.04 86.84 38.68 16.73 19.77 39.95 29.83 63.17 26.19 34.87-5.43 61.94-34.34 67.05-69.44 23.33-5.81 43.05-23.06 50.85-46.64 11.73-35.35-1.27-74.07-31.63-95.32zM160.06 296.3c-15.61.02-30.85-5.13-43.23-14.58l2.16-1.23 71.7-41.41c3.68-2.09 5.94-5.98 5.92-10.19V138.36l30.31 17.5c.33.17.57.48.63.84v83.77c-.08 30.66-24.88 55.5-55.5 55.83h.01z"/></svg>`,
      anthropic: `<svg width="24" height="24" viewBox="0 0 256 176" fill="#D97757"><path d="M147.49 0l60.11 176h-41.2l-60.1-176h41.19zM66.98 0H25.8L86 176h41.19L66.98 0z"/></svg>`,
      gemini: `<svg width="24" height="24" viewBox="0 0 28 28"><defs><linearGradient id="gg" x1="0" y1="0" x2="28" y2="28" gradientUnits="userSpaceOnUse"><stop stop-color="#4285F4"/><stop offset=".5" stop-color="#9B72CB"/><stop offset="1" stop-color="#D96570"/></linearGradient></defs><path d="M14 28C14 21.4 8.8 14 0 14c8.8 0 14-7.4 14-14 0 8.8 5.2 14 14 14-8.8 0-14 7.4-14 14z" fill="url(#gg)"/></svg>`,
      ollama: `<span style="font-size:1.3rem">🦙</span>`
    };
    el.innerHTML = this.veeProviders.map(p => {
      const active = this.veeProvider === p.id;
      const avail = p.available || !p.needs_key;
      return `<div class="vee-prov-card ${active ? 'active' : ''} ${avail ? 'available' : ''}" onclick="App.selectVeeProvider('${p.id}')" title="${p.name} (${p.model})">${logos[p.id] || '?'}<span style="font-size:.6rem;margin-top:2px">${p.name}</span></div>`;
    }).join('');
    const label = document.getElementById('veeProvLabel');
    if (label) {
      const active = this.veeProviders.find(p => p.id === this.veeProvider);
      label.textContent = active ? `Using ${active.name} ${active.model}` : 'Select a provider to start';
    }
  },

  async selectVeeProvider(id) {
    const p = this.veeProviders.find(x => x.id === id);
    if (!p) return;
    if (p.needs_key && !p.has_key) {
      await this.loadVeeProviders(true);
      const updated = this.veeProviders.find(x => x.id === id);
      if (updated && updated.has_key) { p.has_key = true; p.available = true; }
    }
    if (p.needs_key && !p.has_key) {
      const area = document.getElementById('veeKeyArea');
      area.innerHTML = `<div class="vee-key-input"><input type="password" id="veeKeyInput" placeholder="${p.name} API key"><button class="vee-send" onclick="App.storeVeeKey('${id}')" style="padding:6px 12px;font-size:.78rem">Store in Vault</button></div>`;
      this.addVeeMsg('vee', `To use ${p.name}, paste your API key above. It'll be stored securely in your Vaultify vault — dogfooding our own product!`);
      return;
    }
    if (p.needs_key && p.has_key) {
      this.veeProvider = id;
      document.getElementById('veeKeyArea').innerHTML = '';
      this.renderVeeProviders();
      this.addVeeMsg('vee', `Using ${p.name} (${p.model}). Key loaded from your Vaultify vault. How can I help?`);
      return;
    }
    if (!p.available) {
      this.addVeeMsg('vee', `Ollama isn't running. Start it with \`ollama serve\` and try again.`);
      return;
    }
    this.veeProvider = id;
    document.getElementById('veeKeyArea').innerHTML = '';
    this.renderVeeProviders();
    this.addVeeMsg('vee', `Switched to ${p.name} (${p.model}). How can I help with your scan findings?`);
  },

  async storeVeeKey(provider) {
    const input = document.getElementById('veeKeyInput');
    if (!input || !input.value.trim()) return;
    try {
      const r = await (await fetch('/api/vee/key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, key: input.value.trim() })
      })).json();
      if (r.stored) {
        document.getElementById('veeKeyArea').innerHTML = '';
        this.veeProvider = provider;
        const p = this.veeProviders.find(x => x.id === provider);
        if (p) p.has_key = true;
        this.renderVeeProviders();
        this.addVeeMsg('vee', `Key stored in vault. Using ${p ? p.name : provider} now. How can I help?`);
      }
    } catch (e) {
      this.addVeeMsg('vee', 'Failed to store key. Make sure your vault is open first (click "Open Vault" in the Scan tab).');
    }
  },

  addVeeMsg(role, text) {
    const chat = document.getElementById('veeChat');
    const div = document.createElement('div');
    div.className = `vee-msg ${role}`;
    if (role === 'vee') {
      div.innerHTML = `<div class="msg-name">Vee</div>${this.formatVeeText(text)}`;
    } else {
      div.textContent = text;
    }
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
    return div;
  },

  formatVeeText(text) {
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/^- (.+)/gm, '<li>$1</li>')
      .replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>')
      .replace(/\n/g, '<br>');
  },

  async veeSend() {
    const input = document.getElementById('veeInput');
    const msg = input.value.trim();
    if (!msg) return;
    if (!this.veeProvider) { this.addVeeMsg('vee', 'Please select an AI provider first.'); return; }
    input.value = '';
    this.addVeeMsg('user', msg);
    const thinking = this.addVeeMsg('vee', '<div class="msg-name">Vee</div><span style="color:var(--muted)">Thinking...</span>');

    try {
      const resp = await fetch('/api/vee/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: this.sessionId || '', message: msg, provider: this.veeProvider })
      });
      const text = await resp.text();
      thinking.innerHTML = `<div class="msg-name">Vee</div>${this.formatVeeText(text)}`;
      document.getElementById('veeChat').scrollTop = document.getElementById('veeChat').scrollHeight;
    } catch (e) {
      thinking.innerHTML = `<div class="msg-name">Vee</div><span style="color:var(--err)">Sorry, something went wrong. ${this.esc(e.message)}</span>`;
    }
  },

  async veeSummary() {
    if (!this.state.findings || !this.state.findings.length) { this.addVeeMsg('vee', 'No scan data yet. Run a scan first, then I can create a summary.'); if (!this.veeOpen) this.toggleVee(); return; }
    if (!this.veeProvider) { this.addVeeMsg('vee', 'Please select an AI provider first.'); if (!this.veeOpen) this.toggleVee(); return; }
    if (!this.veeOpen) this.toggleVee();
    this.addVeeMsg('user', 'Create a remediation summary for governance reporting.');
    const thinking = this.addVeeMsg('vee', '<div class="msg-name">Vee</div><span style="color:var(--muted)">Generating summary...</span>');

    try {
      const resp = await fetch('/api/vee/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: this.sessionId || '',
          message: 'Generate a concise executive remediation summary suitable for governance reporting. Include: total secrets found, breakdown by severity and type, top 5 most critical findings with recommended actions (Vaultify/Remove/Dismiss), overall risk assessment, and recommended next steps. Format with headers and bullet points.',
          provider: this.veeProvider
        })
      });
      const text = await resp.text();
      thinking.innerHTML = `<div class="msg-name">Vee</div>${this.formatVeeText(text)}`;
      document.getElementById('veeChat').scrollTop = document.getElementById('veeChat').scrollHeight;
    } catch (e) {
      thinking.innerHTML = `<div class="msg-name">Vee</div><span style="color:var(--err)">Summary generation failed.</span>`;
    }
  }
};

document.addEventListener('DOMContentLoaded', () => App.init());
