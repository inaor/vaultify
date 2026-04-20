const App = {
  ws: null,
  state: { status: 'idle', dirs_visited: 0, candidates_queued: 0, files_scanned: 0, hits_total: 0, progress_denominator: 1, file_cap: 100000, pattern_totals: [], findings: [] },
  decisions: {},
  reviewSubTab: 'active',
  reviewSort: { col: 'severity', dir: -1 },
  sessionsSort: { col: 'date', dir: -1 },
  auditSort: { col: 'time', dir: -1 },
  catalogueSort: { col: 'id', dir: 1 },
  _fpFinderStaged: null,
  currentPage: 'dashboard',
  vaultList: [],
  sessionId: null,

  init() {
    this._loadSelectedVaultProvider();
    this._setupOpSessionSync();
    this.connectWebSocket();
    this.setupNavigation();
    this.navigate(window.location.hash.slice(1) || 'dashboard');
    this.loadVaults();
    this.loadCatalogue();
    this.loadSessions();
    this.loadVeeProviders();
    this.updateFooters();
  },

  /** Re-check op session when user returns from 1Password / unlock flow (CLI auth is external to this UI). */
  _vaultAuthPollTimer: null,
  _opUnlockFastTimer: null,
  _refreshVaultAuthDebounceTimer: null,
  /** After first auth-status fetch, so we do not toast on every page load when already connected. */
  _vaultAuthHydrated: false,
  /** Serializes auth-status fetches so overlapping responses cannot apply out of order (false "signed out"). */
  _refreshVaultAuthChain: Promise.resolve(),

  _lastVisibilityAuthBump: 0,
  _visAuthBumpTimer: null,

  _setupOpSessionSync() {
    const bump = () => {
      clearTimeout(this._visAuthBumpTimer);
      this._visAuthBumpTimer = setTimeout(() => {
        if (!this.opSignedIn) {
          this.refreshVaultAuthUI(true);
          return;
        }
        const now = Date.now();
        if (now - (this._lastVisibilityAuthBump || 0) < 45000) return;
        this._lastVisibilityAuthBump = now;
        this.refreshVaultAuthUIDebounced();
      }, 300);
    };
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') bump();
    });
    window.addEventListener('focus', bump);
    window.addEventListener('pageshow', (e) => { if (e.persisted) bump(); });
  },

  _clearOpUnlockFastPoll() {
    if (this._opUnlockFastTimer) {
      clearInterval(this._opUnlockFastTimer);
      this._opUnlockFastTimer = null;
    }
  },

  /** After Open Vault, poll auth frequently until unlocked (desktop + CLI handoff can lag). */
  _startOpUnlockFastPoll() {
    this._clearOpUnlockFastPoll();
    let ticks = 0;
    const maxTicks = 40;
    this._opUnlockFastTimer = setInterval(() => {
      ticks++;
      if (ticks > maxTicks || this.opSignedIn) {
        this._clearOpUnlockFastPoll();
        return;
      }
      this.refreshVaultAuthUI(true);
    }, 2500);
  },

  refreshVaultAuthUIDebounced() {
    clearTimeout(this._refreshVaultAuthDebounceTimer);
    this._refreshVaultAuthDebounceTimer = setTimeout(() => { this.refreshVaultAuthUI(false); }, 120);
  },

  /** Ask at most once per browser profile so we do not spam the permission dialog. */
  _requestVaultNotificationsIfNeeded() {
    try {
      if (typeof Notification === 'undefined') return;
      if (Notification.permission !== 'default') return;
      try {
        if (localStorage.getItem('vf-notify-perm-asked') === '1') return;
        localStorage.setItem('vf-notify-perm-asked', '1');
      } catch (e) {}
      Notification.requestPermission().catch(() => {});
    } catch (e) {}
  },

  /**
   * 1Password stays available to the CLI while the app is unlocked and CLI integration is on — not a short window.
   * We notify when we *detect* that state so you know Vaultify can use the vault (esp. after switching back from 1Password).
   */
  _notifyOpSessionConnected() {
    this.showToast('1Password connected — Apply and Vee can use your vault.', 'success');
    try {
      if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
      if (document.visibilityState === 'visible') return;
      new Notification('Vaultify', {
        body: '1Password is connected. You can apply decisions or use Vee with the vault.',
        icon: '/assets/vee-avatar.png',
        tag: 'vaultify-op-connected',
        renotify: true
      });
    } catch (e) {}
  },

  _clearVaultAuthPoll() {
    if (this._vaultAuthPollTimer) {
      clearInterval(this._vaultAuthPollTimer);
      this._vaultAuthPollTimer = null;
    }
  },

  /** While op is installed but not signed in, poll auth-status so unlock in 1Password updates tiles without a refresh. */
  _syncVaultAuthPoll() {
    const op = (this.vaultList || []).find(v => v.cli === 'op');
    const shouldPoll = !!(op && op.installed && !this.opSignedIn);
    if (!shouldPoll) {
      this._clearVaultAuthPoll();
      return;
    }
    if (this._vaultAuthPollTimer) return;
    this._vaultAuthPollTimer = setInterval(() => {
      if (document.visibilityState !== 'visible') return;
      this.refreshVaultAuthUI(true);
    }, 8000);
  },

  connectWebSocket() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    this.ws = new WebSocket(`${proto}://${location.host}/api/scan/ws`);
    this.ws.onmessage = (e) => { try { this.handleMessage(JSON.parse(e.data)); } catch (err) { console.warn('WS error', err); } };
    this.ws.onopen = () => { this.syncScanState(); };
    this.ws.onclose = () => { setTimeout(() => this.connectWebSocket(), 3000); };
  },

  async syncScanState() {
    try {
      const s = await (await fetch('/api/scan/state')).json();
      if (!s.running && this.state.status === 'running') {
        this.state.status = 'complete';
        this.state.current_path = '';
        this.updateDashboard(); this.updateButtons(); this.updateNav();
      }
    } catch (e) {}
  },

  handleMessage(msg) {
    switch (msg.type) {
      case 'scan_progress':
        this.state.status = 'running';
        this.state.files_scanned = msg.progress || 0;
        this.state.progress_denominator = msg.total || 1;
        if (msg.current_path) this.state.current_path = msg.current_path;
        if (msg.progress > 0 && msg.progress === msg.total) {
          clearTimeout(this._scanCompleteTimeout);
          this._scanCompleteTimeout = setTimeout(() => {
            if (this.state.status === 'running' && this.state.files_scanned === this.state.progress_denominator) {
              this.state.status = 'complete';
              this.state.current_path = '';
              this.updateDashboard(); this.updateButtons(); this.updateNav();
            }
          }, 3000);
        }
        break;
      case 'scan_finding':
        if (msg.finding) {
          this.state.findings.push(msg.finding);
          this.state.hits_total = this.state.findings.length;
          this.updatePatternTotals();
          this.addFeedItem(msg.finding);
        }
        break;
      case 'scan_complete':
        this.state.status = 'complete';
        this.state.current_path = '';
        if (msg.scan_type) this.state.scan_type = msg.scan_type;
        this.sessionId = msg.sessionId;
        this.restoreDecisions();
        if (Object.keys(this.decisions).length === 0) this.autoSuggestDecisions();
        this.loadSessions();
        this.showToast('Scan complete \u2014 ' + (this.state.findings.length) + ' findings across ' + ((this.state.pattern_totals || []).length) + ' patterns', 'success');
        if (!App.tour.active && (this.state.findings || []).length > 0) {
          this.navigate('review');
        }
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
    if (el('scanBtnGroup')) el('scanBtnGroup').style.display = running ? 'none' : '';
    if (el('btnStopScan')) el('btnStopScan').style.display = running ? '' : 'none';
    const summBtn = el('veeSummaryBtn');
    if (summBtn) {
      summBtn.disabled = !hasFindings;
      summBtn.style.opacity = hasFindings ? '' : '.35';
      summBtn.style.cursor = hasFindings ? '' : 'not-allowed';
    }
    this.updateHeroStatus();
  },

  _scanStartTime: null,
  _elapsedTimer: null,
  _lastFilesCount: 0,
  _lastFilesTime: 0,

  updateHeroStatus() {
    const pill = document.getElementById('heroStatusPill');
    const textEl = document.getElementById('heroStatusText');
    const elapsedEl = document.getElementById('heroElapsed');
    const throughputEl = document.getElementById('heroThroughput');
    if (!pill) return;
    const s = this.state.status || 'idle';
    pill.className = 'status-pill ' + (s === 'running' ? 'running' : s === 'complete' ? 'complete' : s === 'stopped' ? 'stopped' : '');
    const st = this.state.scan_type;
    const typeLabel = st === 'specific_folder' ? 'Folder Scan' : 'Machine Scan';
    if (s === 'running') {
      textEl.textContent = typeLabel + '...';
    } else if (s === 'complete') {
      textEl.textContent = typeLabel + ' Complete';
    } else if (s === 'stopped') {
      textEl.textContent = typeLabel + ' Stopped';
    } else {
      textEl.textContent = 'Ready';
    }

    if (s === 'running') {
      elapsedEl.style.display = '';
      throughputEl.style.display = '';
      if (!this._scanStartTime) {
        this._scanStartTime = Date.now();
        this._lastFilesCount = 0;
        this._lastFilesTime = Date.now();
        clearInterval(this._elapsedTimer);
        this._elapsedTimer = setInterval(() => {
          const sec = Math.floor((Date.now() - this._scanStartTime) / 1000);
          elapsedEl.textContent = Math.floor(sec / 60) + ':' + String(sec % 60).padStart(2, '0');
        }, 1000);
      }
      const now = Date.now();
      const dt = (now - this._lastFilesTime) / 1000;
      if (dt > 0.5) {
        const df = (this.state.files_scanned || 0) - this._lastFilesCount;
        const fps = Math.round(df / dt);
        if (fps > 0) throughputEl.textContent = '~' + fps + ' files/s';
        this._lastFilesCount = this.state.files_scanned || 0;
        this._lastFilesTime = now;
      }
    } else {
      if (this._elapsedTimer) { clearInterval(this._elapsedTimer); this._elapsedTimer = null; }
      if (s === 'complete' || s === 'stopped') {
        elapsedEl.style.display = '';
        throughputEl.style.display = 'none';
      } else {
        elapsedEl.style.display = 'none';
        throughputEl.style.display = 'none';
      }
      this._scanStartTime = null;
    }

    const vizCards = document.querySelectorAll('.viz-card');
    vizCards.forEach(c => c.classList.toggle('scanning', s === 'running'));
  },

  animateValue(el, to) {
    if (!el) return;
    const from = parseInt(el.textContent) || 0;
    if (from === to) return;
    const duration = 400;
    const start = performance.now();
    const step = (now) => {
      const t = Math.min((now - start) / duration, 1);
      const ease = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
      el.textContent = Math.round(from + (to - from) * ease);
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  },

  showToast(message, type) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = 'toast-msg ' + (type || 'info');
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  },

  setupNavigation() {
    document.querySelectorAll('.sidebar nav a[data-page]').forEach(a => {
      a.addEventListener('click', (e) => { e.preventDefault(); this.navigate(a.dataset.page); });
    });
  },

  navigate(page) {
    this.currentPage = page || 'dashboard';
    window.location.hash = this.currentPage;
    document.querySelectorAll('.sidebar nav a[data-page]').forEach(a => { a.classList.toggle('active', a.dataset.page === this.currentPage); });
    document.querySelectorAll('.page').forEach(p => { p.classList.toggle('active', p.id === `page-${this.currentPage}`); });
    if (this.currentPage === 'reports') this.loadSessions();
    if (this.currentPage === 'review') this.renderReview();
    if (this.currentPage === 'dashboard') this.refreshVaultAuthUI(false);
    if (this.currentPage === 'audit') this.loadAuditLog();
    if (this.currentPage === 'catalogue') this.loadCatalogue();
    if (this.currentPage === 'docs') this.loadDocs();
    if (this.currentPage === 'version') this.loadVersion();
  },

  updateNav() {
    const badge = document.getElementById('navFindingsBadge');
    if (badge) badge.textContent = (this.state.findings && this.state.findings.length) ? this.activeFindingsCount() : (this.state.hits_total || 0);
    const pill = document.getElementById('navStatusPill');
    if (!pill) return;
    const s = this.state.status || 'idle';
    const colors = { running: 'var(--accent)', complete: 'var(--ok)', error: 'var(--err)', idle: 'var(--muted)', stopped: 'var(--warn)' };
    const c = colors[s] || 'var(--muted)';
    pill.style.color = c; pill.style.borderColor = c;
    const navLabel = s === 'running' ? 'Scanning' : s === 'complete' ? 'Complete' : s === 'idle' ? 'Ready' : s;
    pill.querySelector('.status-text').textContent = navLabel;
    pill.querySelector('.spinner').style.display = s === 'running' ? '' : 'none';
  },

  esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; },

  /** After esc(), wrap in-file redaction markers for Review / explorer snippets. */
  wrapVaultifyRedactionInEscapedHtml(escaped) {
    if (!escaped) return '';
    return escaped.replace(/REDACTED_BY_VAULTIFY/gi, '<span class="vf-snippet-redact">$&</span>');
  },

  snippetHighlightRedaction(raw) {
    return this.wrapVaultifyRedactionInEscapedHtml(this.esc(raw));
  },
  sevColors: { critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#38bdf8', info: '#4ade80' },
  sevColor(pid) { if (pid === 'op_secret_ref') return '#4ade80'; if (/aws|stripe|openai|anthropic|private_key|hashicorp|age_secret|dynatrace/.test(pid)) return '#f87171'; if (/gh_|github|gitlab|slack|bitbucket|docker|npm|pypi|figma|hubspot/.test(pid)) return '#fb923c'; if (/jwt|telegram|twilio|mailgun/.test(pid)) return '#fbbf24'; return '#38bdf8'; },
  sevColorBySev(sev) { return this.sevColors[sev] || '#38bdf8'; },

  isJunkyardAction(act) {
    return act === 'graveyard' || act === 'dismiss';
  },

  activeFindingsCount() {
    return this.getGroups().filter(g => {
      if (g.pattern_id === 'op_secret_ref') return false;
      const d = this.decisions[g.hash];
      if (d && d.good_practice) return false;
      return !this.isJunkyardAction(d && d.action);
    }).length;
  },

  severityRank(sev) {
    const o = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return o[String(sev || '').toLowerCase()] ?? 9;
  },

  /** Split a path into directory and file name (handles Windows and POSIX). */
  _splitPath(path) {
    if (!path) return { dir: '', base: '' };
    const norm = String(path).replace(/\\/g, '/');
    const i = norm.lastIndexOf('/');
    if (i < 0) return { dir: '', base: norm };
    return { dir: norm.slice(0, i), base: norm.slice(i + 1) };
  },

  /** First location when sorted by path (stable “primary” for folder/file columns). */
  _primaryLoc(g) {
    const locs = [...(g.locs || [])].sort((a, b) => {
      const pa = (a.relative_path || a.full_path || '');
      const pb = (b.relative_path || b.full_path || '');
      return pa.localeCompare(pb);
    });
    return locs[0];
  },

  _primaryPath(g) {
    const f = this._primaryLoc(g);
    return (f && (f.relative_path || f.full_path)) || '';
  },

  _groupFolder(g) {
    return this._splitPath(this._primaryPath(g)).dir;
  },

  _groupFileLabel(g) {
    const { base } = this._splitPath(this._primaryPath(g));
    const n = (g.locs && g.locs.length) || 0;
    if (!this._primaryPath(g)) return '\u2014';
    if (n > 1) return base + ` (+${n - 1})`;
    return base;
  },

  sortGroups(list, col, dir) {
    const arr = [...list];
    const mul = dir < 0 ? -1 : 1;
    arr.sort((a, b) => {
      let cmp = 0;
      switch (col) {
        case 'pattern':
          cmp = (a.pattern_id || '').localeCompare(b.pattern_id || '');
          break;
        case 'preview':
          cmp = (a.redacted_preview || '').localeCompare(b.redacted_preview || '');
          break;
        case 'folder':
          cmp = this._groupFolder(a).localeCompare(this._groupFolder(b));
          break;
        case 'file': {
          const fa = this._splitPath(this._primaryPath(a)).base;
          const fb = this._splitPath(this._primaryPath(b)).base;
          cmp = fa.localeCompare(fb);
          break;
        }
        case 'severity':
          cmp = this.severityRank(a.severity) - this.severityRank(b.severity);
          break;
        case 'entropy': {
          const ae = a.locs.reduce((s, f) => s + (f.entropy || 0), 0) / (a.locs.length || 1);
          const be = b.locs.reduce((s, f) => s + (f.entropy || 0), 0) / (b.locs.length || 1);
          cmp = ae - be;
          break;
        }
        case 'files':
          cmp = a.locs.length - b.locs.length;
          break;
        case 'decision': {
          const ord = { pending: 0, vault: 1, remove: 2, graveyard: 3, dismiss: 3, good_practice: 4 };
          const ad = this.decisions[a.hash];
          const bd = this.decisions[b.hash];
          const ak = ad?.good_practice ? 'good_practice' : (ad ? ad.action : 'pending');
          const bk = bd?.good_practice ? 'good_practice' : (bd ? bd.action : 'pending');
          cmp = (ord[ak] ?? 9) - (ord[bk] ?? 9);
          break;
        }
        default:
          cmp = (a.pattern_id || '').localeCompare(b.pattern_id || '');
      }
      if (cmp !== 0) return mul * cmp;
      return (a.hash || '').localeCompare(b.hash || '');
    });
    return arr;
  },

  async syncExclusionAdd(hash, patternId, source) {
    try {
      await fetch('/api/exclusions/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entries: [{ match_sha256: hash, pattern_id: patternId || '', source: source || 'graveyard' }] }) });
    } catch (e) {}
  },

  async syncExclusionRemove(hash) {
    try {
      await fetch('/api/exclusions/remove', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ match_sha256: hash }) });
    } catch (e) {}
  },
  riskColor(r) { return r < 20 ? '#4ade80' : r < 50 ? '#fbbf24' : r < 75 ? '#fb923c' : '#f87171'; },
  riskLabel(r) { return r < 20 ? 'Low' : r < 50 ? 'Moderate' : r < 75 ? 'High' : 'Critical'; },
  dashOffset(pct) { return Math.round(251.2 - (251.2 * pct / 100)); },

  async startScan(roots) {
    this.hideFolderPicker();
    const scanType = roots && roots.length ? 'specific_folder' : 'entire_machine';
    this.state = { status: 'running', dirs_visited: 0, candidates_queued: 0, files_scanned: 0, hits_total: 0, progress_denominator: 1, file_cap: 100000, pattern_totals: [], findings: [], scan_type: scanType, current_path: '' };
    this.decisions = {};
    this._patternEls = {};
    const patEl = document.getElementById('patterns');
    if (patEl) patEl.innerHTML = '<div class="empty-msg">Scanning...</div>';
    const treeEl = document.getElementById('findingsTree');
    if (treeEl) treeEl.innerHTML = '<div class="empty-msg" style="padding:16px;font-size:.78rem">Waiting for findings...</div>';
    const graphEl = document.getElementById('patternGraph');
    if (graphEl) graphEl.innerHTML = '<div class="empty-msg">Scanning...</div>';
    this.updateDashboard(); this.updateButtons(); this.updateNav();
    const body = roots && roots.length ? JSON.stringify({ roots }) : '{"roots":[]}';
    try {
      let resp = await fetch('/api/scan/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      if (resp.status === 409) {
        await fetch('/api/scan/stop', { method: 'POST' });
        await new Promise(r => setTimeout(r, 500));
        resp = await fetch('/api/scan/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      }
      const r = await resp.json();
      if (r.sessionId) this.sessionId = r.sessionId;
      if (r.error) { this.state.status = 'idle'; this.updateButtons(); this.updateNav(); this.showToast('Scan failed: ' + r.error, 'error'); }
    } catch (err) {
      console.error('Start scan failed', err);
      this.state.status = 'idle'; this.updateButtons(); this.updateNav();
    }
  },

  toggleScanMenu() {
    const menu = document.getElementById('scanMenu');
    menu.classList.toggle('open');
    if (menu.classList.contains('open')) {
      setTimeout(() => { document.addEventListener('click', this._closeScanMenu); }, 0);
    }
  },

  _closeScanMenu(e) {
    const menu = document.getElementById('scanMenu');
    const btn = document.getElementById('btnScanDrop');
    if (menu && !menu.contains(e.target) && btn && !btn.contains(e.target)) {
      menu.classList.remove('open');
      document.removeEventListener('click', App._closeScanMenu);
    }
  },

  hideScanMenu() {
    const menu = document.getElementById('scanMenu');
    if (menu) menu.classList.remove('open');
    document.removeEventListener('click', this._closeScanMenu);
  },

  async showFolderPicker() {
    const picker = document.getElementById('folderPicker');
    picker.style.display = '';
    const input = document.getElementById('folderPath');
    input.value = '';
    input.focus();
    try {
      const resp = await (await fetch('/api/browse')).json();
      input.value = resp.current || '';
      this._renderQuickPicks(resp.quick || []);
      this._renderBrowser(resp);
    } catch (e) { console.warn('Browse failed', e); }
  },

  hideFolderPicker() {
    const picker = document.getElementById('folderPicker');
    if (picker) picker.style.display = 'none';
  },

  _renderQuickPicks(picks) {
    const area = document.getElementById('folderQuickPicks');
    const list = document.getElementById('folderQuickList');
    if (!picks || !picks.length) { area.style.display = 'none'; return; }
    area.style.display = '';
    const folderSvg = '<svg viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>';
    list.innerHTML = picks.map(p => {
      const safePath = this.esc(p.path).replace(/\\/g, '\\\\');
      return `<span class="folder-quick-chip" onclick="App.pickFolder('${safePath}')" title="${this.esc(p.path)}">${folderSvg} ${this.esc(p.name)}</span>`;
    }).join('');
  },

  _renderBrowser(resp) {
    const pathEl = document.getElementById('folderBrowserPath');
    const listEl = document.getElementById('folderBrowserList');
    pathEl.textContent = resp.current || '';
    const folderSvg = '<svg viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>';
    let html = '';
    if (resp.parent) {
      const safeParent = this.esc(resp.parent).replace(/\\/g, '\\\\');
      html += `<div class="folder-dir-item" onclick="App.browseDir('${safeParent}')"><svg viewBox="0 0 24 24"><path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"/></svg> <span style="color:var(--accent)">..</span></div>`;
    }
    if (resp.dirs && resp.dirs.length) {
      resp.dirs.forEach(d => {
        const safeDPath = this.esc(d.path).replace(/\\/g, '\\\\');
        html += `<div class="folder-dir-item" onclick="App.browseDir('${safeDPath}')">${folderSvg} ${this.esc(d.name)}<span class="folder-select-btn" onclick="event.stopPropagation();App.pickFolder('${safeDPath}')">Select</span></div>`;
      });
    } else {
      html = '<div style="padding:12px;font-size:.82rem;color:var(--muted);text-align:center">No subdirectories</div>';
    }
    listEl.innerHTML = html;
  },

  async browseDir(path) {
    try {
      const resp = await (await fetch('/api/browse?path=' + encodeURIComponent(path))).json();
      document.getElementById('folderPath').value = resp.current || path;
      this._renderBrowser(resp);
    } catch (e) { console.warn('Browse failed', e); }
  },

  pickFolder(path) {
    document.getElementById('folderPath').value = path;
  },

  startFolderScan() {
    const path = (document.getElementById('folderPath').value || '').trim();
    if (!path) { alert('Enter a folder path first.'); return; }
    this.startScan([path]);
  },

  async stopScan() {
    try { await fetch('/api/scan/stop', { method: 'POST' }); } catch (err) {}
    this.state.status = 'stopped';
    this.updateDashboard(); this.updateButtons(); this.updateNav();
    if (!this.tour.active && this.state.findings.length > 0) this.navigate('review');
  },

  updateDashboard() {
    if (this.currentPage !== 'dashboard') return;
    const s = this.state;
    const files = s.files_scanned || 0;
    const denom = Math.max(s.progress_denominator || 1, 1);
    const pct = Math.min(100, Math.round(100 * files / denom));
    const hits = s.hits_total || 0;
    const sc = s.status === 'complete' ? '#4ade80' : s.status === 'error' ? '#f87171' : '#22d3ee';
    const el = id => document.getElementById(id);

    this.animateValue(el('mFiles'), files);
    this.animateValue(el('mHits'), hits);
    if (el('mHits')) el('mHits').style.color = hits > 0 ? this.riskColor(Math.min(100, hits * 3.5 + 2)) : '';
    const uniq = new Set(s.findings.map(f => f.match_sha256)).size;
    this.animateValue(el('gUnique'), uniq);
    this.animateValue(el('mPatterns'), (s.pattern_totals || []).length);

    const pr = el('progRing'); if (pr) { pr.style.strokeDashoffset = this.dashOffset(pct); pr.style.stroke = sc; }
    if (el('progVal')) { el('progVal').textContent = pct + '%'; el('progVal').style.color = sc; }
    if (el('gFiles')) el('gFiles').textContent = files + ' / ' + denom;
    if (el('gCap')) el('gCap').textContent = s.file_cap || 100000;

    const pathRow = el('currentPathRow');
    const pathEl = el('currentPath');
    if (pathRow && pathEl) {
      if (s.status === 'running' && s.current_path) {
        pathRow.style.display = '';
        const cp = s.current_path;
        pathEl.textContent = cp.length > 50 ? '...' + cp.slice(-47) : cp;
        pathEl.title = cp;
      } else {
        pathRow.style.display = 'none';
      }
    }

    this.renderSeverityDonut();
    this.renderPatterns(s.pattern_totals);

    if (this._treeNeedsRebuild) {
      this._treeNeedsRebuild = false;
      clearTimeout(this._treeTimer);
      this._treeTimer = setTimeout(() => this.renderFindingsTree(), 500);
    }
    if (s.status === 'complete' || s.status === 'stopped') {
      this.renderFindingsTree();
    }
  },

  renderSeverityDonut() {
    const findings = this.state.findings || [];
    const uniq = new Set(findings.map(f => f.match_sha256)).size;
    const el = document.getElementById('donutVal');
    if (el) this.animateValue(el, uniq);

    const sevMap = {};
    const seen = {};
    findings.forEach(f => {
      if (seen[f.match_sha256]) return;
      seen[f.match_sha256] = true;
      const sev = f.severity || 'medium';
      sevMap[sev] = (sevMap[sev] || 0) + 1;
    });

    const sevOrder = [
      { key: 'critical', color: '#f87171', label: 'Critical' },
      { key: 'high', color: '#fb923c', label: 'High' },
      { key: 'medium', color: '#fbbf24', label: 'Medium' },
      { key: 'low', color: '#38bdf8', label: 'Low' },
      { key: 'info', color: '#4ade80', label: 'Vault ref (op://)' }
    ];

    const svg = document.getElementById('sevDonut');
    if (!svg) return;
    const total = uniq || 1;
    const circumference = 2 * Math.PI * 40;
    let offset = 0;

    svg.innerHTML = '<circle cx="50" cy="50" r="40" fill="none" stroke="rgba(30,42,58,.6)" stroke-width="5"/>';
    sevOrder.forEach(s => {
      const count = sevMap[s.key] || 0;
      if (count === 0) return;
      const segLen = (count / total) * circumference;
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', '50');
      circle.setAttribute('cy', '50');
      circle.setAttribute('r', '40');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', s.color);
      circle.setAttribute('stroke-width', '5.5');
      circle.setAttribute('stroke-linecap', 'round');
      circle.style.strokeDasharray = `${segLen} ${circumference - segLen}`;
      circle.style.strokeDashoffset = `${-offset}`;
      circle.style.transform = 'rotate(-90deg)';
      circle.style.transformOrigin = '50% 50%';
      circle.style.transition = 'stroke-dasharray .6s ease, stroke-dashoffset .6s ease';
      svg.appendChild(circle);
      offset += segLen;
    });

    const legend = document.getElementById('sevLegend');
    if (legend) {
      if (uniq === 0) {
        legend.innerHTML = '<div class="empty-msg" style="padding:8px 0;font-size:.78rem">No findings yet</div>';
      } else {
        legend.innerHTML = sevOrder.filter(s => sevMap[s.key]).map(s =>
          `<div style="display:flex;align-items:center;gap:8px"><span style="width:8px;height:8px;border-radius:50%;background:${s.color};flex-shrink:0"></span><span style="flex:1">${s.label}</span><span style="font-weight:700;font-variant-numeric:tabular-nums">${sevMap[s.key]}</span></div>`
        ).join('');
      }
    }
  },

  expandPatternGraph() {
    const modal = document.getElementById('graphModal');
    modal.style.display = 'flex';
    const container = document.getElementById('patternGraphModal');
    if (!this.state.pattern_totals || !this.state.pattern_totals.length) this.updatePatternTotals();
    const pt = this.state.pattern_totals || [];
    const badge = document.getElementById('patBadgeModal');
    if (badge) badge.textContent = pt.length + ' types';
    if (this._graphAnim) cancelAnimationFrame(this._graphAnim);
    requestAnimationFrame(() => { this._startForceGraph(container, pt, true, { maxPatternTypes: this.GRAPH_MAX_MODAL }); });
  },

  closeGraphModal() {
    if (this._graphAnim) { cancelAnimationFrame(this._graphAnim); this._graphAnim = null; }
    document.getElementById('graphModal').style.display = 'none';
    const legend = document.getElementById('graphNodeLegend');
    if (legend) legend.style.display = 'none';
    const mh = document.getElementById('graphModalHint');
    if (mh) { mh.style.display = 'none'; mh.textContent = ''; }
    const pt = this.state.pattern_totals || [];
    if (pt.length) {
      const container = document.getElementById('patternGraph');
      if (container) this._startForceGraph(container, pt, false, { maxPatternTypes: this.GRAPH_MAX_INLINE });
    }
  },

  _graphAnim: null,
  _graphNodes: null,
  _graphOtherPatternIds: null,

  /** Keeps the force graph responsive: top-N volume patterns + one "Other" aggregate; caps satellite dots per pattern. */
  GRAPH_MAX_INLINE: 28,
  GRAPH_MAX_MODAL: 40,

  bucketPatternTotalsForGraph(pt, maxTypes) {
    if (!pt || !pt.length) return { rows: [], groupedTypeCount: 0, otherIds: [] };
    if (pt.length <= maxTypes) return { rows: pt.slice(), groupedTypeCount: 0, otherIds: [] };
    const top = pt.slice(0, maxTypes);
    const rest = pt.slice(maxTypes);
    const otherIds = rest.map(p => p.id);
    const sumN = rest.reduce((s, p) => s + p.n, 0);
    top.push({ id: '__vf_other__', n: sumN, __groupedCount: rest.length });
    return { rows: top, groupedTypeCount: rest.length, otherIds };
  },

  _maxSatellitesForGraph(patternNodeCount, row) {
    if (row.id === '__vf_other__') return Math.min(8, Math.max(2, Math.ceil(Math.log2(1 + row.n))));
    if (patternNodeCount > 36) return Math.min(2, row.n);
    if (patternNodeCount > 24) return Math.min(4, row.n);
    if (patternNodeCount > 16) return Math.min(8, row.n);
    return Math.min(12, row.n);
  },

  _updateGraphHints(totalTypes, groupedTypeCount, maxTypesShown, interactive) {
    const hintInline = document.getElementById('patGraphHint');
    const hintModal = document.getElementById('graphModalHint');
    const msg = groupedTypeCount > 0
      ? `Volume-ranked: showing top ${maxTypesShown} pattern types plus one grouped node (${groupedTypeCount} more types). Full list is in Review.`
      : '';
    if (hintInline) {
      if (groupedTypeCount > 0 && !interactive) {
        hintInline.style.display = '';
        hintInline.textContent = msg;
      } else {
        hintInline.style.display = 'none';
        hintInline.textContent = '';
      }
    }
    if (hintModal) {
      if (groupedTypeCount > 0 && interactive) {
        hintModal.style.display = '';
        hintModal.textContent = msg;
      } else {
        hintModal.style.display = 'none';
        hintModal.textContent = '';
      }
    }
  },

  _startForceGraph(container, pt, interactive, opts) {
    const maxTypes = (opts && opts.maxPatternTypes) != null ? opts.maxPatternTypes : this.GRAPH_MAX_INLINE;
    if (!container || !pt || !pt.length) {
      container.innerHTML = '<div class="empty-msg">No patterns to display.</div>';
      this._graphOtherPatternIds = null;
      const hintInline = document.getElementById('patGraphHint');
      if (hintInline) { hintInline.style.display = 'none'; hintInline.textContent = ''; }
      return;
    }
    const { rows, groupedTypeCount, otherIds } = this.bucketPatternTotalsForGraph(pt, maxTypes);
    this._graphOtherPatternIds = otherIds && otherIds.length ? otherIds : null;
    this._updateGraphHints(pt.length, groupedTypeCount, maxTypes, interactive);
    const dpr = window.devicePixelRatio || 1;
    const w = container.clientWidth || 600;
    const h = container.clientHeight || 300;
    container.innerHTML = '';
    const canvas = document.createElement('canvas');
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    container.appendChild(canvas);
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);

    let zoom = 1, panX = 0, panY = 0;
    if (interactive) {
      canvas.addEventListener('wheel', (e) => {
        e.preventDefault();
        const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1;
        zoom = Math.max(0.3, Math.min(5, zoom * zoomFactor));
      }, { passive: false });

      let dragging = false, lastX = 0, lastY = 0;
      canvas.addEventListener('mousedown', (e) => { dragging = true; lastX = e.clientX; lastY = e.clientY; });
      canvas.addEventListener('mousemove', (e) => {
        if (!dragging) return;
        panX += (e.clientX - lastX) / zoom;
        panY += (e.clientY - lastY) / zoom;
        lastX = e.clientX; lastY = e.clientY;
      });
      canvas.addEventListener('mouseup', () => { dragging = false; });
      canvas.addEventListener('mouseleave', () => { dragging = false; });

      canvas.addEventListener('click', (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = (e.clientX - rect.left) / zoom - panX;
        const my = (e.clientY - rect.top) / zoom - panY;
        let clicked = null;
        nodes.forEach(n => {
          if (n.type !== 'pattern') return;
          const dx = n.x - mx, dy = n.y - my;
          if (Math.sqrt(dx*dx + dy*dy) < n.r + 5) clicked = n;
        });
        if (clicked) App._showNodeLegend(clicked.id);
      });
      canvas.style.cursor = 'grab';
    }

    const display = rows;
    const maxN = Math.max(...display.map(p => p.n), 1);
    const nodes = [];
    const links = [];
    const pn = display.length;

    display.forEach((p, i) => {
      const angle = (2 * Math.PI * i / display.length);
      const r = Math.max(10, Math.min(28, 10 + (p.n / maxN) * 18));
      let patFindings;
      if (p.id === '__vf_other__' && otherIds && otherIds.length) {
        const allow = new Set(otherIds);
        patFindings = (App.state.findings || []).filter(f => allow.has(f.pattern_id));
      } else {
        patFindings = (App.state.findings || []).filter(f => f.pattern_id === p.id);
      }
      const avgEnt = patFindings.length ? patFindings.reduce((s,f) => s + (f.entropy || 0), 0) / patFindings.length : 0;
      const isCtx = patFindings.some(f => f.detection_layer === 'context');
      nodes.push({ id: p.id, n: p.n, r, x: w/2 + Math.cos(angle) * 100 + (Math.random()-0.5)*40, y: h/2 + Math.sin(angle) * 100 + (Math.random()-0.5)*40, vx: 0, vy: 0, type: 'pattern', avgEnt, isCtx, groupedCount: p.__groupedCount || 0 });
      const satN = this._maxSatellitesForGraph(pn, p);
      for (let j = 0; j < satN; j++) {
        const fid = p.id + '_f' + j;
        nodes.push({ id: fid, n: 0, r: 3, x: w/2 + (Math.random()-0.5)*200, y: h/2 + (Math.random()-0.5)*200, vx: 0, vy: 0, type: 'finding', parent: p.id });
        links.push({ source: p.id, target: fid });
      }
    });

    const nodeMap = {};
    nodes.forEach(n => { nodeMap[n.id] = n; });

    const simulate = () => {
      const heavy = nodes.length > 100;
      const repulsion = heavy ? 520 : 800;
      const attraction = heavy ? 0.0065 : 0.005;
      const centering = 0.01;
      const damping = heavy ? 0.88 : 0.85;

      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        a.vx += (w/2 - a.x) * centering;
        a.vy += (h/2 - a.y) * centering;
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j];
          let dx = b.x - a.x, dy = b.y - a.y;
          let dist = Math.sqrt(dx*dx + dy*dy) || 1;
          const force = repulsion / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          a.vx -= fx; a.vy -= fy;
          b.vx += fx; b.vy += fy;
        }
      }

      links.forEach(l => {
        const s = nodeMap[l.source], t = nodeMap[l.target];
        if (!s || !t) return;
        let dx = t.x - s.x, dy = t.y - s.y;
        let dist = Math.sqrt(dx*dx + dy*dy) || 1;
        const targetDist = s.r + 20;
        const force = (dist - targetDist) * attraction;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        s.vx += fx; s.vy += fy;
        t.vx -= fx; t.vy -= fy;
      });

      nodes.forEach(n => {
        n.vx *= damping; n.vy *= damping;
        n.x += n.vx; n.y += n.vy;
        n.x = Math.max(n.r + 5, Math.min(w - n.r - 5, n.x));
        n.y = Math.max(n.r + 5, Math.min(h - n.r - 5, n.y));
      });
    };

    const render = () => {
      simulate();
      ctx.clearRect(0, 0, w, h);
      ctx.save();
      if (interactive) { ctx.translate(panX * zoom, panY * zoom); ctx.scale(zoom, zoom); }

      links.forEach(l => {
        const s = nodeMap[l.source], t = nodeMap[l.target];
        if (!s || !t) return;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = 'rgba(167,139,250,.12)';
        ctx.lineWidth = 0.5;
        ctx.stroke();
      });

      nodes.forEach(n => {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        if (n.type === 'pattern') {
          const nodeColor = n.isCtx ? 'rgba(244,114,182,.2)' : 'rgba(167,139,250,.2)';
          const strokeColor = n.isCtx ? '#f472b6' : '#a78bfa';
          const glowIntensity = Math.max(6, Math.min(20, (n.avgEnt || 0) * 4));
          ctx.fillStyle = nodeColor;
          ctx.fill();
          ctx.strokeStyle = strokeColor;
          ctx.lineWidth = 1.5;
          ctx.stroke();
          ctx.shadowColor = n.isCtx ? 'rgba(244,114,182,.3)' : 'rgba(167,139,250,.3)';
          ctx.shadowBlur = glowIntensity;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(167,139,250,.4)';
          ctx.lineWidth = 1;
          ctx.stroke();
          ctx.shadowBlur = 0;

          ctx.fillStyle = '#f472b6';
          ctx.font = 'bold 11px system-ui';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(n.n, n.x, n.y);

          ctx.fillStyle = n.isCtx ? '#f472b6' : '#a78bfa';
          ctx.font = '600 8px monospace';
          let subLabel = n.id === '__vf_other__' && n.groupedCount
            ? ('Other (+' + n.groupedCount + ')')
            : (n.id.length > 14 ? n.id.slice(0, 12) + '..' : n.id);
          if (subLabel.length > 18) subLabel = subLabel.slice(0, 16) + '..';
          ctx.fillText(subLabel, n.x, n.y + n.r + 11);
      } else {
          ctx.fillStyle = 'rgba(244,114,182,.5)';
          ctx.fill();
          ctx.shadowColor = 'rgba(244,114,182,.3)';
          ctx.shadowBlur = 6;
          ctx.beginPath();
          ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
          ctx.fillStyle = 'rgba(244,114,182,.4)';
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      ctx.restore();
      this._graphAnim = requestAnimationFrame(render);
    };

    render();
  },

  _showNodeLegend(patternId) {
    const legend = document.getElementById('graphNodeLegend');
    const title = document.getElementById('legendTitle');
    const content = document.getElementById('legendContent');
    if (!legend || !content) return;
    legend.style.display = '';

    let findings;
    if (patternId === '__vf_other__' && this._graphOtherPatternIds && this._graphOtherPatternIds.length) {
      const allow = new Set(this._graphOtherPatternIds);
      findings = (this.state.findings || []).filter(f => allow.has(f.pattern_id));
      title.textContent = 'Other pattern types (grouped)';
    } else {
      findings = (this.state.findings || []).filter(f => f.pattern_id === patternId);
      title.textContent = patternId;
    }

    if (!findings.length) { content.innerHTML = '<div style="color:var(--c-slate);font-size:.82rem">No findings for this pattern.</div>'; return; }

    const seen = {};
    let html = '';
    findings.forEach(f => {
      const key = f.match_sha256;
      if (seen[key]) return;
      seen[key] = true;
      const path = f.relative_path || f.full_path || '';
      const shortPath = path.length > 35 ? '...' + path.slice(-32) : path;
      const sc = this.sevColorBySev(f.severity);
      html += `<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:.78rem">`;
      html += `<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px"><span style="width:6px;height:6px;border-radius:50%;background:${sc};flex-shrink:0"></span><span style="color:var(--c-rose);font-family:monospace;font-weight:600">${this.esc(f.redacted_preview)}</span></div>`;
      html += `<div style="color:var(--c-slate);font-family:monospace;font-size:.72rem;word-break:break-all">${this.esc(shortPath)}</div>`;
      html += `<div style="color:var(--c-slate);font-size:.68rem;margin-top:2px">Line ${f.line_number} &middot; ${this.esc(f.severity)}</div>`;
      if (f.line_snippet) {
        html += `<div style="margin-top:4px;padding:6px 8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;font-family:monospace;font-size:.68rem;color:var(--c-slate);white-space:pre-wrap;word-break:break-all;max-height:60px;overflow:auto">${this.snippetHighlightRedaction(f.line_snippet)}</div>`;
      }
      html += `</div>`;
    });
    content.innerHTML = html;
  },

  addFeedItem(f) {
    this._treeNeedsRebuild = true;
  },

  _treeNeedsRebuild: false,
  _treeTimer: null,

  renderFindingsTree() {
    const el = document.getElementById('findingsTree');
    if (!el) return;
    const findings = this.state.findings || [];
    if (!findings.length) { el.innerHTML = '<div class="empty-msg">Start a scan to see findings.</div>'; return; }

    const tree = {};
    findings.forEach(f => {
      const fp = (f.relative_path || f.full_path || 'unknown').replace(/\\/g, '/');
      const parts = fp.split('/');
      const fileName = parts.pop();
      let node = tree;
      parts.forEach(p => {
        if (!node[p]) node[p] = { _children: {}, _files: {} };
        node = node[p]._children;
      });
      if (!node['__files']) node['__files'] = {};
      if (!node['__files'][fileName]) node['__files'][fileName] = [];
      node['__files'][fileName].push(f);
    });

    let html = '';
    const renderNode = (obj, depth) => {
      const folders = Object.keys(obj).filter(k => k !== '__files').sort();
      const files = obj['__files'] || {};

      folders.forEach(name => {
        const sub = obj[name];
        const count = this._countFindings(sub);
        const id = 'tf-' + Math.random().toString(36).slice(2, 8);
        html += `<div class="tree-folder" onclick="var c=document.getElementById('${id}');var i=this.querySelector('.tree-folder-icon');if(c){c.style.display=c.style.display==='none'?'':'none';i.classList.toggle('open')}" style="padding-left:${depth*12+4}px">`;
        html += `<span class="tree-folder-icon">\u25B6</span>`;
        html += `<span class="tree-folder-name">${this.esc(name)}</span>`;
        if (count > 0) html += `<span class="tree-folder-badge">${count}</span>`;
        html += `</div>`;
        html += `<div class="tree-children" id="${id}" style="display:none">`;
        renderNode(sub._children || sub, depth + 1);
        html += `</div>`;
      });

      Object.keys(files).sort().forEach(fileName => {
        const fileFindings = files[fileName];
        const isEnv = /^\.env|^credentials$|^config$|^secrets$|^\.npmrc$|^\.pypirc$|^\.netrc$/i.test(fileName);
        const hasCtx = fileFindings.some(f => f.detection_layer === 'context');
        const fileIcon = isEnv ? '\u{1F512}' : '\u{1F4C4}';
        const fileBg = isEnv ? ';background:rgba(244,114,182,.04);border-radius:6px' : '';
        html += `<div class="tree-file" style="padding-left:${depth*12+4}px${fileBg}"><span class="tree-file-icon">${fileIcon}</span><span style="font-family:monospace;font-size:.78rem${isEnv ? ';color:var(--c-rose);font-weight:600' : ''}">${this.esc(fileName)}</span><span class="tree-folder-badge">${fileFindings.length}</span></div>`;
        if (isEnv && hasCtx && fileFindings.length >= 3) {
          html += `<div style="padding-left:${depth*12+24}px;font-size:.72rem;color:var(--c-rose);margin:2px 0 4px;opacity:.8">High-density credential file \u2014 review all entries</div>`;
        }
        fileFindings.forEach(f => {
          const sc = this.sevColor(f.pattern_id);
          const entVal = f.entropy ? f.entropy.toFixed(1) : '';
          const entOp = f.entropy >= 4.0 ? '1' : f.entropy >= 3.0 ? '.7' : '.5';
          const ctxBadge = f.detection_layer === 'context' ? '<span style="font-size:8px;padding:1px 4px;border-radius:3px;background:rgba(167,139,250,.15);color:var(--c-violet);font-weight:700;margin-left:4px">CTX</span>' : '';
          html += `<div class="tree-finding" style="padding-left:${depth*12+20}px"><span class="tree-finding-dot" style="background:${sc}"></span><span class="tree-finding-pattern">${this.esc(f.pattern_id)}${ctxBadge}</span><span class="tree-finding-preview">${this.esc(f.redacted_preview)}</span>${entVal ? `<span style="font-family:monospace;font-size:.68rem;color:var(--c-cyan);opacity:${entOp};margin-left:auto">${entVal}</span>` : ''}<span class="tree-finding-line">L${f.line_number}</span></div>`;
        });
      });
    };

    renderNode(tree, 0);
    el.innerHTML = html;
  },

  _countFindings(node) {
    let count = 0;
    if (node.__files) Object.values(node.__files).forEach(arr => { count += arr.length; });
    if (node._children) Object.values(node._children).forEach(child => { count += this._countFindings(child); });
    const keys = Object.keys(node).filter(k => k !== '__files' && k !== '_children');
    keys.forEach(k => { if (node[k] && typeof node[k] === 'object') count += this._countFindings(node[k]); });
    return count;
  },

  _inlineGraphTimer: null,

  renderPatterns(pt) {
    const container = document.getElementById('patternGraph');
    if (!container) return;
    const b = document.getElementById('patBadge');
    if (b) b.textContent = (pt || []).length + ' types';
    if (!pt || !pt.length) {
      if (!container.querySelector('canvas')) {
        const running = this.state.status === 'running';
        container.innerHTML = running
          ? '<div class="empty-msg">Scanning\u2026</div>'
          : '<div class="empty-msg">Start a scan to see patterns.</div>';
      }
      return;
    }
    clearTimeout(this._inlineGraphTimer);
    this._inlineGraphTimer = setTimeout(() => {
      if (this._graphAnim && document.getElementById('graphModal')?.style.display === 'flex') return;
      if (this._graphAnim) { cancelAnimationFrame(this._graphAnim); this._graphAnim = null; }
      this._startForceGraph(container, pt);
    }, 800);
  },

  opSignedIn: false,
  /** Primary vault tile highlight (purple border). Default 1Password — first in the grid and the default selection until the user picks another provider. */
  selectedVaultProvider: 'op',

  _loadSelectedVaultProvider() {
    try {
      const s = localStorage.getItem('vf-vault-provider');
      if (s && /^(op|aws|vault|doppler)$/.test(s)) this.selectedVaultProvider = s;
      else this.selectedVaultProvider = 'op';
    } catch (e) {
      this.selectedVaultProvider = 'op';
    }
  },

  selectVaultProvider(cli) {
    if (!/^(op|aws|vault|doppler)$/.test(cli)) return;
    this.selectedVaultProvider = cli;
    try { localStorage.setItem('vf-vault-provider', cli); } catch (e) {}
    this.renderVaultStatus();
  },

  renderVaultSkeleton() {
    const grid = document.getElementById('sidebarVaultGrid');
    if (!grid) return;
    const tile = `<div class="sidebar-vault-tile sidebar-vault-tile--skeleton"><span class="sidebar-vault-skel-logo sidebar-vault-skel-shimmer"></span><span class="sidebar-vault-skel-line sidebar-vault-skel-line--lg sidebar-vault-skel-shimmer"></span><span class="sidebar-vault-skel-line sidebar-vault-skel-line--sm sidebar-vault-skel-shimmer"></span><span class="sidebar-vault-skel-line sidebar-vault-skel-line--status sidebar-vault-skel-shimmer"></span></div>`;
    grid.setAttribute('aria-busy', 'true');
    grid.setAttribute('aria-label', 'Loading vault providers');
    grid.innerHTML = tile.repeat(4);
  },

  /**
   * Loads vault provider list and auth status.
   * @param {boolean} [forceAuthCheck] If true, runs a fresh op session check (can prompt 1Password). Use false on startup; true when the user is about to use vault features (Apply, Vee key ops).
   */
  async loadVaults(forceAuthCheck) {
    this.renderVaultSkeleton();
    try {
      const resp = await fetch('/api/vaults');
      this.vaultList = await resp.json();
    } catch (err) {}
    await this.refreshVaultAuthUI(forceAuthCheck === true);
  },

  /** Keeps 1Password session in sync with /api/vaults/auth-status (Apply, Vee, FP Finder). Pass forceRefresh to run op (server bypasses short TTL). */
  refreshVaultAuthUI(forceRefresh) {
    const force = !!forceRefresh;
    this._refreshVaultAuthChain = this._refreshVaultAuthChain
      .then(() => this._refreshVaultAuthUIRun(force))
      .catch(() => {});
    return this._refreshVaultAuthChain;
  },

  async _refreshVaultAuthUIRun(forceRefresh) {
    const wasSignedIn = this.opSignedIn;
    const hadPriorAuthCheck = this._vaultAuthHydrated;
    try {
      const q = forceRefresh ? '?refresh=1' : '';
      const r = await (await fetch('/api/vaults/auth-status' + q)).json();
      this.opSignedIn = !!r.onepassword_signed_in;
    } catch (e) {}
    this._vaultAuthHydrated = true;
    if (hadPriorAuthCheck && !wasSignedIn && this.opSignedIn) {
      this._notifyOpSessionConnected();
    }
    if (!wasSignedIn && this.opSignedIn) {
      this._clearOpUnlockFastPoll();
      try {
        // First app load: shallow provider list only (no op key reads) — avoids 1Password / CLI prompts.
        // After at least one auth poll, deep-check keys when the user becomes signed in (e.g. after unlock).
        await this.loadVeeProviders(hadPriorAuthCheck);
      } catch (e) {}
    }
    this.renderVaultStatus();
  },

  updateVaultReadinessSection() {
    const section = document.getElementById('sidebarVaultSection');
    if (!section) return;
    const op = (this.vaultList || []).find(v => v.cli === 'op');
    const opInstalled = !!(op && op.installed);
    const needAttention = !opInstalled || !this.opSignedIn;
    section.classList.toggle('sidebar-vault-block--needs-attention', needAttention);
  },

  /** Returns true when 1Password CLI is on PATH and authenticated (same bar as Apply / Vee vault ops). */
  async ensureOpSessionForVaultFeatures() {
    const haveProviders = Array.isArray(this.vaultList) && this.vaultList.length > 0;
    const opRow = (this.vaultList || []).find(v => v.cli === 'op');
    // Avoid re-running the full vault grid skeleton on every Vee send / summary — only refresh auth.
    if (haveProviders && opRow && opRow.installed) {
      await this.refreshVaultAuthUI(true);
    } else {
      await this.loadVaults(true);
    }
    const op = this.vaultList.find(v => v.cli === 'op');
    if (!op || !op.installed) {
      this.showToast('Install the 1Password CLI — use the 1Password tile in the sidebar (official install link).', 'error');
      return false;
    }
    if (!this.opSignedIn) {
      this.showToast('Connect 1Password: open the 1Password tile in the sidebar, then Open Vault.', 'error');
      return false;
    }
    return true;
  },

  vaultLogos: {
    op: '/assets/vault-logo-1password.png',
    aws: '/assets/vault-logo-aws-ssm.png',
    vault: '/assets/vault-logo-hashicorp.png',
    doppler: '/assets/vault-logo-doppler.png'
  },

  vaultProviderLogo(v) {
    const src = this.vaultLogos[v.cli];
    if (!src) {
      return `<div class="vault-card-icon" style="background:var(--bg2)" title="${this.esc(v.name)}">\u{1F5DD}</div>`;
    }
    return `<div class="vault-card-icon vault-card-logo-wrap" title="${this.esc(v.name)}"><img src="${src}" alt="${this.esc(v.name)}" class="vault-card-logo-img" width="36" height="36" loading="lazy"></div>`;
  },

  sidebarVaultTileLogo(v) {
    const src = this.vaultLogos[v.cli];
    if (!src) {
      return `<div class="sidebar-vault-tile-logo-wrap" title="${this.esc(v.name)}">\u{1F5DD}</div>`;
    }
    return `<div class="sidebar-vault-tile-logo-wrap" title="${this.esc(v.name)}"><img src="${src}" alt="" loading="lazy"></div>`;
  },

  onSidebarVaultTileClick(e) {
    if (e.target.closest('button, a')) return;
    const cli = e.currentTarget && e.currentTarget.dataset && e.currentTarget.dataset.cli;
    if (cli) this.selectVaultProvider(cli);
  },

  vaultOfficialInstallLink(v) {
    const u = v.docs_url;
    if (!u) return '';
    return `<a href="${this.esc(u)}" target="_blank" rel="noopener noreferrer" class="vault-vendor-link" onclick="event.stopPropagation()">Official install page \u2197</a>`;
  },

  renderVaultStatus() {
    const grid = document.getElementById('sidebarVaultGrid');
    if (!grid) return;
    grid.removeAttribute('aria-busy');
    grid.removeAttribute('aria-label');
    const order = ['op', 'aws', 'vault', 'doppler'];
    const byCli = Object.fromEntries((this.vaultList || []).map(v => [v.cli, v]));
    const list = order.map(cli => byCli[cli]).filter(Boolean);
    if (!list.length) {
      grid.innerHTML = '<div class="empty-msg" style="font-size:.7rem;padding:6px 4px">No vault providers</div>';
      this.updateVaultReadinessSection();
      this._clearVaultAuthPoll();
      return;
    }
    grid.innerHTML = list.map(v => this._renderSidebarVaultTile(v)).join('');
    this.updateVaultReadinessSection();
    this._syncVaultAuthPoll();
  },

  _renderSidebarVaultTile(v) {
    const active = this.selectedVaultProvider === v.cli ? ' sidebar-vault-tile--active' : '';
    let statusHtml = '';
    let actionsHtml = '';

    if (v.cli === 'op') {
      if (!v.installed) {
        statusHtml = '<span style="color:var(--err)">CLI missing</span>';
        actionsHtml = `${this.vaultOfficialInstallLink(v)}
            <button class="btn-primary" id="btnInstallOp" onclick="event.stopPropagation();App.installOp()" style="font-size:.58rem;padding:4px 8px;width:100%">Install</button>
            <span id="installOpMsg" style="font-size:.55rem;color:var(--muted);display:block;margin-top:4px"></span>`;
      } else if (this.opSignedIn) {
        statusHtml = '<span style="color:var(--ok)">\u2713 Connected</span>';
      } else {
        statusHtml = '<span style="color:var(--warn)">Locked</span>';
        actionsHtml = `<button class="tb-btn" onclick="event.stopPropagation();App.openVault()" style="font-size:.58rem;padding:4px 8px;border-color:var(--ok);color:var(--ok);width:100%">Open Vault</button>
            <span id="signInMsg" style="font-size:.55rem;color:var(--muted);display:block;margin-top:4px">Unlock 1Password</span>`;
      }
    } else if (v.installed) {
      statusHtml = '<span style="color:var(--ok)">On PATH</span>';
    } else {
      statusHtml = '<span style="color:var(--muted)">Not installed</span>';
      actionsHtml = `${this.vaultOfficialInstallLink(v)}<div style="font-size:.55rem;color:var(--muted);margin-top:2px"><code style="color:var(--accent)">${this.esc(v.cli)}</code></div>`;
    }

    const actionsBlock = actionsHtml ? `<div class="sidebar-vault-tile-actions">${actionsHtml}</div>` : '';
    return `<div class="sidebar-vault-tile${active}" data-cli="${this.esc(v.cli)}" onclick="App.onSidebarVaultTileClick(event)" role="button" tabindex="0">
        ${this.sidebarVaultTileLogo(v)}
        <div class="sidebar-vault-tile-name">${this.esc(v.name)}</div>
        <div class="sidebar-vault-tile-cli">${this.esc(v.cli)}</div>
        <div class="sidebar-vault-tile-status">${statusHtml}</div>
        ${actionsBlock}
      </div>`;
  },

  async installOp() {
    const btn = document.getElementById('btnInstallOp');
    const msg = document.getElementById('installOpMsg');
    if (btn) { btn.disabled = true; btn.innerHTML = '<div class="vf-spinner" style="width:12px;height:12px;display:inline-block;vertical-align:middle;margin-right:6px"></div>Installing...'; }
    if (msg) msg.textContent = 'This may take a minute...';
    try {
      const r = await (await fetch('/api/vaults/install-op', { method: 'POST' })).json();
      if (r.installed) {
        await this.loadVaults();
      } else {
        if (msg) msg.innerHTML = '<span style="color:var(--warn)">Install may need admin privileges. Run the command manually in an elevated terminal.</span>';
        if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
      }
    } catch (e) {
      if (msg) msg.innerHTML = '<span style="color:var(--err)">Install failed. Try running the command manually.</span>';
      if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
    }
  },

  async openVault() {
    this._requestVaultNotificationsIfNeeded();
    const msg = document.getElementById('signInMsg');
    if (msg) msg.innerHTML = '<span style="color:var(--muted)">Opening 1Password and connecting the CLI\u2026 (unlock if prompted; can take up to ~1 minute)</span>';
    try {
      const r = await (await fetch('/api/vaults/signin', { method: 'POST' })).json();
      this.opSignedIn = r.signed_in;
      this.renderVaultStatus();
      if (r.signed_in) {
        this._clearOpUnlockFastPoll();
        this._notifyOpSessionConnected();
        this.loadVeeProviders(true);
      } else {
        this._startOpUnlockFastPoll();
        const m = document.getElementById('signInMsg');
        if (m) m.innerHTML = `<span style="color:var(--warn)">${this.esc(r.hint || 'Unlock 1Password first.')}</span> <button class="tb-btn" onclick="App.openVault()" style="font-size:.68rem;padding:2px 8px;margin-left:4px">Retry</button>`;
      }
    } catch (e) {
      this._startOpUnlockFastPoll();
      const detail = (e && (e.message || String(e))) ? this.esc(String(e.message || e)) : '';
      const hint = detail ? ` ${detail}` : '';
      if (msg) msg.innerHTML = `<span style="color:var(--warn)">Connection failed.${hint}</span> <span style="color:var(--muted);font-size:.55rem">Is Vaultify running? Start <code>vaultify.exe</code> or open it from the repo, then Retry.</span> <button class="tb-btn" onclick="App.openVault()" style="font-size:.68rem;padding:2px 8px;margin-left:4px">Retry</button>`;
    }
  },

  reportsTab: 'active',

  showReportsTab(tab) {
    this.reportsTab = tab;
    const activeBtn = document.getElementById('btnReportsActive');
    const archiveBtn = document.getElementById('btnReportsArchive');
    if (activeBtn) { activeBtn.style.borderColor = tab === 'active' ? 'var(--accent)' : ''; activeBtn.style.color = tab === 'active' ? 'var(--accent)' : ''; }
    if (archiveBtn) { archiveBtn.style.borderColor = tab === 'archive' ? 'var(--accent)' : ''; archiveBtn.style.color = tab === 'archive' ? 'var(--accent)' : ''; }
    this.loadSessions();
  },

  toggleSessionsSort(c) {
    if (this.sessionsSort.col === c) this.sessionsSort.dir *= -1;
    else {
      this.sessionsSort.col = c;
      this.sessionsSort.dir = c === 'date' ? -1 : 1;
    }
    this.loadSessions();
  },

  _sessionsThMark(c) {
    if (this.sessionsSort.col !== c) return '';
    return this.sessionsSort.dir < 0 ? ' \u2193' : ' \u2191';
  },

  async loadSessions() {
    try {
      const el = document.getElementById('reportsContent');
      if (el && !el.querySelector('table')) el.innerHTML = '<div style="text-align:center;padding:24px"><div class="vf-spinner" style="margin:0 auto 12px"></div><span style="color:var(--muted);font-size:.85rem">Loading scan history...</span></div>';
      const isArchive = this.reportsTab === 'archive';
      const url = isArchive ? '/api/sessions/archived' : '/api/sessions';
      const sessionsRaw = await (await fetch(url)).json();
      if (!el) return;
      const reportsBadge = document.querySelector('[data-page="reports"] .badge');
      if (reportsBadge && !isArchive) reportsBadge.textContent = (sessionsRaw || []).length;
      if (!sessionsRaw || !sessionsRaw.length) { el.innerHTML = `<div class="empty-msg">${isArchive ? 'No archived sessions.' : 'No scan sessions found.'}</div>`; return; }
      const sessions = [...sessionsRaw];
      const dir = this.sessionsSort.dir;
      const sc = this.sessionsSort.col;
      sessions.sort((a, b) => {
        let cmp = 0;
        if (sc === 'session') cmp = (a.id || '').localeCompare(b.id || '');
        else if (sc === 'date') cmp = new Date(a.scanned_at || 0) - new Date(b.scanned_at || 0);
        else if (sc === 'status') cmp = (a.status || '').localeCompare(b.status || '');
        else if (sc === 'findings') cmp = (a.original_findings_count || a.findings_count || 0) - (b.original_findings_count || b.findings_count || 0);
        else if (sc === 'remediation') {
          const af = a.original_findings_count || a.findings_count || 0;
          const bf = b.original_findings_count || b.findings_count || 0;
          const ap = af > 0 ? (a.remediated || 0) / af : 0;
          const bp = bf > 0 ? (b.remediated || 0) / bf : 0;
          cmp = ap - bp;
        }
        if (cmp !== 0) return dir * cmp;
        return (a.id || '').localeCompare(b.id || '');
      });
      const thStyle = 'text-align:left;padding:10px 12px;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);cursor:pointer;user-select:none';
      const thC = `${thStyle};text-align:center`;
      let html = `<table class="vf-sortable" style="width:100%;border-collapse:collapse;font-size:.88rem"><thead><tr><th style="${thStyle}" onclick="App.toggleSessionsSort('session')">Session${this._sessionsThMark('session')}</th><th style="${thStyle}" onclick="App.toggleSessionsSort('date')">Date${this._sessionsThMark('date')}</th><th style="${thStyle}" onclick="App.toggleSessionsSort('status')">Status${this._sessionsThMark('status')}</th><th style="${thC}" onclick="App.toggleSessionsSort('findings')">Findings${this._sessionsThMark('findings')}</th><th style="${thC}" onclick="App.toggleSessionsSort('remediation')">Remediation${this._sessionsThMark('remediation')}</th><th style="${thStyle};text-align:right"></th></tr></thead><tbody>`;
      sessions.forEach(s => {
        let dt = s.scanned_at || '';
        try { const d = new Date(dt); if (!isNaN(d.getTime())) dt = d.toLocaleString(); } catch(e) {}
        const fc = s.original_findings_count || s.findings_count || 0;
        const rem = s.remediated || 0;
        const pct = fc > 0 ? Math.round(100 * rem / fc) : 0;
        const pctColor = pct === 0 ? 'var(--muted)' : pct < 50 ? 'var(--err)' : pct < 100 ? 'var(--warn)' : 'var(--ok)';
        const stColor = s.status === 'complete' ? 'var(--ok)' : s.status === 'remediated' ? 'var(--accent)' : s.status === 'running' ? 'var(--accent)' : 'var(--muted)';
        const sid = (s.id || '').slice(0, 8);
        html += `<tr style="border-bottom:1px solid var(--border);transition:background .15s" onmouseover="this.style.background='rgba(56,189,248,.03)'" onmouseout="this.style.background=''">`;
        html += `<td style="padding:12px;font-family:monospace;font-size:.78rem;color:var(--accent)">${this.esc(sid)}</td>`;
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
          html += `<span style="color:var(--muted)">\u2014</span>`;
        }
        html += `</td>`;
        html += `<td style="padding:12px;text-align:right">`;
        html += `<div style="display:flex;gap:8px;justify-content:flex-end">`;
        if (isArchive) {
          html += `<button class="tb-btn" onclick="App.unarchiveSession('${this.esc(s.id)}')" style="font-size:.72rem;padding:4px 10px;border-color:var(--ok);color:var(--ok)" title="Restore">Restore</button>`;
        } else {
          if (fc > 0) html += `<button class="tb-btn" onclick="App.loadSessionFindings('${this.esc(s.id)}')" style="font-size:.78rem;padding:5px 12px">Review</button>`;
          html += `<button class="tb-btn" onclick="App.archiveSession('${this.esc(s.id)}')" style="font-size:.72rem;padding:4px 10px" title="Archive">Archive</button>`;
          html += `<button class="tb-btn" onclick="event.stopPropagation();App.showProModal()" style="font-size:.68rem;padding:3px 8px;opacity:.6" title="Share Report">Share \u{1F451}</button>`;
        }
        html += `</div>`;
        html += `</td></tr>`;
      });
      el.innerHTML = html + '</tbody></table>';
    } catch (err) {}
  },

  async archiveSession(id) {
    try { await fetch(`/api/sessions/${id}/archive`, { method: 'POST' }); } catch (e) {}
    this.loadSessions();
  },

  async unarchiveSession(id) {
    try { await fetch(`/api/sessions/${id}/unarchive`, { method: 'POST' }); } catch (e) {}
    this.loadSessions();
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
        this.restoreDecisions();
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
    const c = { vault: 0, remove: 0, graveyard: 0, pending: 0, good_practice: 0 };
    this.getGroups().forEach(g => {
      const d = this.decisions[g.hash];
      if (!d) { c.pending++; return; }
      if (d.good_practice) { c.good_practice++; return; }
      const a = d.action === 'dismiss' ? 'graveyard' : d.action;
      if (a === 'vault') c.vault++;
      else if (a === 'remove') c.remove++;
      else if (a === 'graveyard') c.graveyard++;
      else c.pending++;
    });
    return c;
  },

  setDecision(hash, action, opts) {
    const group = this.getGroups().find(g => g.hash === hash);
    if (!group) return;
    const prev = this.decisions[hash]?.action;
    if (this.isJunkyardAction(prev) && !this.isJunkyardAction(action)) {
      this.syncExclusionRemove(hash);
    }
    const locs = group.locs.map(f => ({ full_path: f.full_path, relative_path: f.relative_path, line_number: f.line_number, match_sha256: f.match_sha256 }));
    const row = { action, pattern_id: group.pattern_id, locations: locs };
    if (opts && opts.good_practice) row.good_practice = true;
    this.decisions[hash] = row;
    if (this.isJunkyardAction(action) && !(opts && opts.good_practice)) {
      this.syncExclusionAdd(hash, group.pattern_id, opts && opts.source);
    }
    this.persistDecisions();
    this.renderReview();
    this.updateNav();
  },

  persistDecisions() {
    if (!this.sessionId) return;
    try {
      localStorage.setItem('vf-decisions-' + this.sessionId, JSON.stringify(this.decisions));
    } catch (e) {}
    this.saveDecisionsToServer();
  },

  _decisionSaveTimer: null,
  saveDecisionsToServer() {
    if (!this.sessionId) return;
    clearTimeout(this._decisionSaveTimer);
    this._decisionSaveTimer = setTimeout(() => {
      const items = Object.entries(this.decisions).map(([hash, d]) => ({
        match_sha256: hash, action: d.action, pattern_id: d.pattern_id,
        locations: d.locations || []
      }));
      fetch('/api/decisions/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId: this.sessionId, decisions: items })
      }).catch(() => {});
    }, 1000);
  },

  restoreDecisions() {
    if (!this.sessionId) return;
    try {
      const saved = localStorage.getItem('vf-decisions-' + this.sessionId);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === 'object') {
          this.decisions = parsed;
          Object.keys(this.decisions).forEach(h => {
            const d = this.decisions[h];
            if (d && d.action === 'dismiss' && !d.good_practice) d.action = 'graveyard';
          });
        }
      }
    } catch (e) {}
  },

  bulkDecision(severity, action) {
    const groups = this.getGroups();
    groups.forEach(g => {
      if (g.severity === severity) {
        this.setDecision(g.hash, action);
      }
    });
  },

  clearAllDecisions() {
    this.decisions = {};
    this.persistDecisions();
    const banner = document.getElementById('autoSuggestBanner');
    if (banner) banner.style.display = 'none';
    this.renderReview();
  },

  goodPracticePatterns: {
    aws_temp_access_key_id: 'Temporary credential — rotates automatically via STS/AssumeRole. Nice work!',
    jwt: 'Short-lived token — typically expires within hours. Good practice.',
    op_secret_ref: 'This value is a 1Password inject reference (op://). The secret lives in your vault — not in the repo. Exactly what we want after Vaultify.',
  },

  isGoodPractice(patternId) {
    return !!this.goodPracticePatterns[patternId];
  },

  noisePaths: ['.nuget', '.npm', '.cargo', '.m2', '.gradle', 'site-packages', 'node_modules', 'AppData'],

  isNoisePath(path) {
    if (!path) return false;
    const lower = path.toLowerCase().replace(/\\/g, '/');
    return this.noisePaths.some(frag => lower.includes('/' + frag + '/') || lower.includes('\\' + frag + '\\'));
  },

  autoSuggestDecisions() {
    const groups = this.getGroups();
    let vaultCount = 0, dismissCount = 0, pendingCount = 0, goodCount = 0;
    groups.forEach(g => {
      if (this.decisions[g.hash]) return;
      const locs = g.locs.map(f => ({ full_path: f.full_path, relative_path: f.relative_path, line_number: f.line_number, match_sha256: f.match_sha256 }));
      const allNoise = g.locs.every(f => this.isNoisePath(f.full_path || f.relative_path));
      const avgConf = g.locs.reduce((s,f) => s + (f.confidence || 0), 0) / g.locs.length;
      const dl = g.locs[0]?.detection_layer || 'value';
      if (this.isGoodPractice(g.pattern_id)) {
        this.decisions[g.hash] = { action: 'graveyard', pattern_id: g.pattern_id, locations: locs, good_practice: true };
        goodCount++;
      } else if (allNoise) {
        this.decisions[g.hash] = { action: 'graveyard', pattern_id: g.pattern_id, locations: locs };
        dismissCount++;
        this.syncExclusionAdd(g.hash, g.pattern_id, 'auto_suggest');
      } else if (dl === 'context' && avgConf < 0.6) {
        pendingCount++;
      } else if (avgConf >= 0.8 || g.severity === 'critical') {
        this.decisions[g.hash] = { action: 'vault', pattern_id: g.pattern_id, locations: locs };
        vaultCount++;
      } else if (g.severity === 'high' && dl !== 'context') {
        this.decisions[g.hash] = { action: 'vault', pattern_id: g.pattern_id, locations: locs };
        vaultCount++;
      } else if (g.severity === 'low') {
        this.decisions[g.hash] = { action: 'graveyard', pattern_id: g.pattern_id, locations: locs };
        dismissCount++;
        this.syncExclusionAdd(g.hash, g.pattern_id, 'auto_suggest');
      } else {
        pendingCount++;
      }
    });
    this.persistDecisions();
    const banner = document.getElementById('autoSuggestBanner');
    if (banner && (vaultCount + dismissCount + goodCount) > 0) {
      banner.style.display = '';
      let parts = [];
      if (vaultCount > 0) parts.push(`<strong style="color:var(--c-success)">${vaultCount} to Vaultify</strong>`);
      if (dismissCount > 0) parts.push(`<strong style="color:var(--c-slate)">${dismissCount} to Junkyard</strong>`);
      if (goodCount > 0) parts.push(`<strong style="color:var(--c-success)">${goodCount} Good Practice \u{1F44D}</strong>`);
      if (pendingCount > 0) parts.push(`<strong style="color:var(--c-slate)">${pendingCount} pending</strong> your review`);
      banner.innerHTML = `<div style="background:rgba(56,189,248,.06);border:1px solid rgba(56,189,248,.2);border-radius:10px;padding:12px 18px;font-size:.84rem;display:flex;align-items:center;gap:14px;margin-bottom:14px;animation:slideUp .3s ease">
        <span style="flex-shrink:0;width:40px;height:40px;border-radius:50%;border:1px solid rgba(56,189,248,.35);overflow:hidden;box-shadow:0 0 0 1px rgba(0,0,0,.2) inset;display:block">
          <img src="/assets/vee-avatar.png" alt="" width="40" height="40" style="width:40px;height:40px;min-width:40px;object-fit:cover;display:block;vertical-align:top">
        </span>
        <span style="flex:1;min-width:0">Vee auto-suggested: ${parts.join(', ')}. You can override any decision.</span>
        <button type="button" onclick="App.clearAllDecisions()" style="flex-shrink:0;margin-left:auto;background:none;border:none;color:var(--muted);font:inherit;font-size:.75rem;cursor:pointer;text-decoration:underline;white-space:nowrap">Undo All</button>
      </div>`;
    }
  },

  reviewPage: 0,
  REVIEW_PAGE_SIZE: 20,

  toggleReviewSort(col) {
    if (this.reviewSort.col === col) this.reviewSort.dir *= -1;
    else {
      this.reviewSort.col = col;
      this.reviewSort.dir = col === 'severity' ? -1 : 1;
    }
    this.reviewPage = 0;
    this.renderReview();
  },

  _reviewThMark(c) {
    if (this.reviewSort.col !== c) return '';
    return this.reviewSort.dir < 0 ? ' \u2193' : ' \u2191';
  },

  renderReview() {
    const el = document.getElementById('reviewContent');
    const statsEl = document.getElementById('reviewStats');
    if (!el) return;
    const allGroups = this.getGroups();
    const bulkEl = document.getElementById('bulkActions');
    if (bulkEl) bulkEl.style.display = allGroups.length > 0 ? 'flex' : 'none';

    const isRowActiveTab = (g) => {
      const d = this.decisions[g.hash];
      if (!d) return true;
      if (d.good_practice) return true;
      const a = d.action === 'dismiss' ? 'graveyard' : d.action;
      return a !== 'graveyard';
    };
    const isRowJunkyardTab = (g) => {
      const d = this.decisions[g.hash];
      if (!d || d.good_practice) return false;
      const a = d.action === 'dismiss' ? 'graveyard' : d.action;
      return a === 'graveyard';
    };

    const activeCount = allGroups.filter(isRowActiveTab).length;
    const jyCount = allGroups.filter(isRowJunkyardTab).length;

    let groups = this.reviewSubTab === 'junkyard'
      ? allGroups.filter(isRowJunkyardTab)
      : allGroups.filter(isRowActiveTab);

    const filter = (document.getElementById('reviewSearch') || {}).value || '';
    const q = filter.trim().toLowerCase();
    const filtered = q ? groups.filter(g => {
      const folder = this._groupFolder(g);
      const fileLabel = this._groupFileLabel(g).replace(/\u2014/g, '');
      return [g.pattern_id, g.redacted_preview, g.severity, g.hash, folder, fileLabel, ...g.locs.map(l => l.relative_path || l.full_path)].join(' ').toLowerCase().includes(q);
    }) : groups;

    const cnt = this.decisionCounts();
    if (statsEl) {
      let gpCount = 0;
      allGroups.forEach(g => { if (this.decisions[g.hash]?.good_practice) gpCount++; });
      const nOpRef = allGroups.filter(g => g.pattern_id === 'op_secret_ref').length;
      const nSecret = allGroups.length - nOpRef;
      let statsHtml = `<span><strong>${nSecret}</strong> secret${nSecret === 1 ? '' : 's'}</span>`;
      if (nOpRef > 0) statsHtml += `<span style="color:var(--c-success)"><strong>${nOpRef}</strong> op:// (good)</span>`;
      statsHtml += `<span style="color:var(--c-success)">Vaultify <strong>${cnt.vault}</strong></span><span style="color:var(--c-rose)">Remove <strong>${cnt.remove}</strong></span><span style="color:var(--c-slate)">Junkyard <strong>${cnt.graveyard}</strong></span>`;
      if (gpCount > 0) statsHtml += `<span style="color:var(--c-success)">\u{1F44D} Good Practice <strong>${gpCount}</strong></span>`;
      statsHtml += `<span style="color:var(--c-slate)">Pending <strong>${cnt.pending}</strong></span>`;
      statsEl.innerHTML = statsHtml;
    }

    if (!allGroups.length) { el.innerHTML = '<div class="empty-msg">No findings yet. Run a scan first.</div>'; return; }

    const sorted = this.sortGroups(filtered, this.reviewSort.col, this.reviewSort.dir);
    const tabBar = `<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
<button type="button" class="tb-btn" onclick="App.reviewSubTab='active';App.reviewPage=0;App.renderReview()" style="${this.reviewSubTab === 'active' ? 'border-color:var(--accent);color:var(--accent)' : ''}">Active <span class="badge">${activeCount}</span></button>
<button type="button" class="tb-btn" onclick="App.reviewSubTab='junkyard';App.reviewPage=0;App.renderReview()" style="${this.reviewSubTab === 'junkyard' ? 'border-color:var(--accent);color:var(--accent)' : ''}">\u{1F5D1}\u{FE0F} Junkyard <span class="badge">${jyCount}</span></button>
<span style="font-size:.72rem;color:var(--c-slate);margin-left:8px">Junkyard entries are excluded on the next scan (match hash).</span>
</div>`;

    if (!sorted.length) {
      el.innerHTML = tabBar + '<div class="empty-msg">' + (q ? 'No matches for filter.' : (this.reviewSubTab === 'junkyard' ? 'Nothing in the junkyard yet. Mark false positives with the wastebasket button.' : 'No rows in this view.')) + '</div>';
      return;
    }

    const totalPages = Math.max(1, Math.ceil(sorted.length / this.REVIEW_PAGE_SIZE));
    if (this.reviewPage >= totalPages) this.reviewPage = totalPages - 1;
    if (this.reviewPage < 0) this.reviewPage = 0;
    const start = this.reviewPage * this.REVIEW_PAGE_SIZE;
    const pageItems = sorted.slice(start, start + this.REVIEW_PAGE_SIZE);

    const pillColors = { vault: 'background:rgba(74,222,128,.12);color:var(--c-success)', remove: 'background:rgba(244,114,182,.1);color:var(--c-rose)', graveyard: 'background:rgba(148,163,184,.12);color:var(--c-slate)', pending: 'background:rgba(148,163,184,.15);color:var(--c-slate)', good_practice: 'background:rgba(74,222,128,.15);color:var(--c-success)' };
    const pillLabels = { vault: 'Vaultify', remove: 'Remove From Code', graveyard: 'Junkyard', pending: 'Pending', good_practice: '\u{1F44D} Good Practice' };
    const lockSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>';
    const trashSvg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>';
    const junkGlyph = '<span style="font-size:13px;line-height:1" aria-hidden="true">\u{1F5D1}\u{FE0F}</span>';

    const thS = 'text-align:left;padding:10px 8px;color:var(--c-slate);font-size:.72rem;text-transform:uppercase;border-bottom:1px solid var(--border);cursor:pointer;user-select:none';
    const thC = `${thS};text-align:center`;
    let html = tabBar + `<div class="vf-review-table-wrap" style="overflow-x:auto;width:100%;margin-bottom:4px;-webkit-overflow-scrolling:touch"><table class="vf-sortable" style="width:100%;min-width:1020px;border-collapse:collapse;font-size:.88rem"><thead><tr><th style="width:30px;padding:10px 8px;border-bottom:1px solid var(--border)"></th><th style="${thS}" onclick="App.toggleReviewSort('pattern')">Pattern${this._reviewThMark('pattern')}</th><th style="${thS}" onclick="App.toggleReviewSort('preview')">Preview${this._reviewThMark('preview')}</th><th style="${thS};min-width:140px" onclick="App.toggleReviewSort('folder')">Folder${this._reviewThMark('folder')}</th><th style="${thS};min-width:120px" onclick="App.toggleReviewSort('file')">File${this._reviewThMark('file')}</th><th style="${thC}" onclick="App.toggleReviewSort('severity')">Severity${this._reviewThMark('severity')}</th><th style="${thC}" onclick="App.toggleReviewSort('entropy')">Entropy${this._reviewThMark('entropy')}</th><th style="${thC}" onclick="App.toggleReviewSort('files')">Files${this._reviewThMark('files')}</th><th style="${thC}" onclick="App.toggleReviewSort('decision')">Decision${this._reviewThMark('decision')}</th><th style="width:120px;padding:10px 8px;border-bottom:1px solid var(--border)"></th></tr></thead><tbody>`;

    pageItems.forEach(g => {
      const dec = this.decisions[g.hash];
      const isGP = dec && dec.good_practice;
      let raw = dec ? dec.action : 'pending';
      if (raw === 'dismiss') raw = 'graveyard';
      const st = isGP ? 'good_practice' : raw;
      const sc = this.sevColor(g.pattern_id);
      const sevKey = (g.severity || 'low').toLowerCase();
      const sevCol = this.sevColorBySev(sevKey);
      const btnStyle = (act) => {
        const map = { vault: 'var(--c-success)', remove: 'var(--c-rose)', graveyard: 'var(--c-slate)' };
        const bg = { vault: 'rgba(74,222,128,.15)', remove: 'rgba(244,114,182,.1)', graveyard: 'var(--bg2)' };
        const cur = st === 'graveyard' ? 'graveyard' : st;
        const on = cur === act;
        return `style="width:30px;height:28px;display:flex;align-items:center;justify-content:center;border:1px solid ${on ? map[act] : 'var(--border)'};background:${on ? bg[act] : 'var(--panel)'};color:${map[act]};border-radius:6px;cursor:pointer;padding:0" title="${({ vault: 'Vaultify', remove: 'Remove from code', graveyard: 'Move to Junkyard (exclude on next scan)' })[act]}"`;
      };

      html += `<tr style="border-bottom:1px solid var(--border);cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'table-row':'none'">`;
      const dl = g.locs[0]?.detection_layer || '';
      const isCtx = dl === 'context';
      const isBoth = dl === 'both';
      const avgEnt = g.locs.reduce((s, f) => s + (f.entropy || 0), 0) / g.locs.length;
      const entOpacity = avgEnt >= 4.0 ? '1' : avgEnt >= 3.0 ? '.7' : '.5';
      const folderStr = this._groupFolder(g);
      const fileStr = this._groupFileLabel(g);
      const pathTitle = this.esc(this._primaryPath(g));
      html += `<td style="padding:8px"><span style="width:9px;height:9px;border-radius:50%;background:${sc};display:inline-block"></span></td>`;
      html += `<td style="padding:8px;font-family:monospace;font-size:12px;color:var(--accent)">${this.esc(g.pattern_id)}${isCtx ? '<span style="margin-left:6px;font-size:9px;padding:1px 5px;border-radius:3px;background:rgba(167,139,250,.15);color:var(--c-violet);font-weight:700;vertical-align:middle">CTX</span>' : ''}${isBoth ? '<span style="margin-left:6px;font-size:9px;color:var(--c-success);vertical-align:middle">\u2713</span>' : ''}</td>`;
      html += `<td style="padding:8px;font-family:monospace;font-size:12px;color:var(--c-rose);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this.esc(g.redacted_preview)}</td>`;
      html += `<td style="padding:8px;font-family:monospace;font-size:11px;color:var(--muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${pathTitle}">${folderStr ? this.esc(folderStr) : '\u2014'}</td>`;
      html += `<td style="padding:8px;font-family:monospace;font-size:11px;color:var(--text);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${pathTitle}">${fileStr === '\u2014' ? '\u2014' : this.esc(fileStr)}</td>`;
      html += `<td style="padding:8px;text-align:center"><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;background:${sevCol}22;color:${sevCol}">${this.esc(g.severity || '')}</span></td>`;
      html += `<td style="padding:8px;text-align:center;font-family:monospace;font-size:12px;font-weight:700;color:var(--c-cyan);opacity:${entOpacity}">${avgEnt > 0 ? avgEnt.toFixed(1) : '\u2014'}</td>`;
      html += `<td style="padding:8px;text-align:center"><span style="background:var(--border);padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600">${g.locs.length}</span></td>`;
      html += `<td style="padding:8px;text-align:center"><span style="display:inline-block;padding:2px 10px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;${pillColors[st]}">${pillLabels[st]}</span></td>`;
      html += `<td style="padding:8px"><div style="display:flex;gap:4px" onclick="event.stopPropagation()">`;
      html += `<button onclick="App.setDecision('${g.hash}','vault')" ${btnStyle('vault')}>${lockSvg}</button>`;
      html += `<button onclick="App.setDecision('${g.hash}','remove')" ${btnStyle('remove')}>${trashSvg}</button>`;
      html += `<button onclick="App.setDecision('${g.hash}','graveyard')" ${btnStyle('graveyard')}>${junkGlyph}</button>`;
      html += `</div></td></tr>`;

      html += '<tr style="display:none;background:var(--bg2)"><td colspan="10" style="padding:10px 16px 14px 32px">';
      if (isGP) {
        const gpMsg = App.goodPracticePatterns[g.pattern_id] || 'This credential follows security best practices.';
        html += `<div style="background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.2);border-radius:8px;padding:10px 14px;margin-bottom:10px;font-size:.82rem;display:flex;align-items:center;gap:10px"><span style="font-size:1.2rem">\u{1F44D}</span><span style="color:var(--ok)">${App.esc(gpMsg)}</span></div>`;
      }
      g.locs.forEach((f, fi) => {
        const hasSnippet = f.line_snippet && f.line_snippet.trim();
        html += `<div style="display:flex;align-items:baseline;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);font-size:12px">`;
        html += `<span style="color:var(--text);font-weight:600;flex-shrink:0">L${f.line_number}</span>`;
        html += `<span style="color:var(--muted);font-family:monospace;word-break:break-all;flex:1">${this.esc(f.relative_path || f.full_path)}</span>`;
        if (hasSnippet) html += `<span onclick="event.stopPropagation();var s=document.getElementById('snip-${g.hash}-${fi}');s.style.display=s.style.display==='none'?'block':'none'" style="font-size:10px;color:var(--accent);cursor:pointer;padding:2px 8px;background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.2);border-radius:4px;flex-shrink:0">snippet</span>`;
        html += `</div>`;
        if (hasSnippet) {
          let snipText = this.esc(f.line_snippet);
          if (f.redacted_preview) {
            const parts = f.redacted_preview.split('...');
            if (parts.length === 2 && parts[0].length >= 3) {
              const prefix = this.esc(parts[0]);
              const re = new RegExp(prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[A-Za-z0-9+/=\\-_]{4,}', 'g');
              snipText = snipText.replace(re, '<span style="background:rgba(248,113,113,.15);color:var(--err);padding:1px 4px;border-radius:3px;font-weight:600">CENSORED_BY_VAULTIFY</span>');
            }
          }
          snipText = this.wrapVaultifyRedactionInEscapedHtml(snipText);
          html += `<div id="snip-${g.hash}-${fi}" style="display:none;margin:6px 0 8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-family:monospace;font-size:12px;color:#a8b9cc;white-space:pre-wrap;word-break:break-all;max-height:150px;overflow:auto;line-height:1.5">${snipText}</div>`;
        }
      });
      html += '</td></tr>';
    });
    html += '</tbody></table></div>';

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

  patternApiUrls: {
    aws_access_key_id: 'https://aws.amazon.com', aws_temp_access_key_id: 'https://aws.amazon.com',
    gh_pat_classic: 'https://github.com', gh_pat_fine: 'https://github.com', github_oauth: 'https://github.com', github_app: 'https://github.com',
    gitlab_pat: 'https://gitlab.com', bitbucket_app_password: 'https://bitbucket.org',
    slack_bot: 'https://api.slack.com', slack_user: 'https://api.slack.com', slack_app: 'https://api.slack.com', slack_webhook: 'https://api.slack.com',
    teams_webhook: 'https://teams.microsoft.com', discord_bot: 'https://discord.com',
    stripe_secret: 'https://api.stripe.com',
    anthropic_api: 'https://api.anthropic.com',
    openai_project: 'https://api.openai.com', openai_legacy: 'https://api.openai.com',
    google_api_key: 'https://cloud.google.com',
    npm_token: 'https://registry.npmjs.org', pypi_token: 'https://pypi.org', nuget_api: 'https://nuget.org',
    atlassian_api_token: 'https://api.atlassian.com',
    shopify_token: 'https://admin.shopify.com',
    sendgrid: 'https://api.sendgrid.com',
    twilio: 'https://api.twilio.com', twilio_auth: 'https://api.twilio.com',
    telegram_bot: 'https://api.telegram.org',
    dropbox_token: 'https://api.dropboxapi.com',
    figma_pat: 'https://api.figma.com',
    hubspot_private_app: 'https://api.hubapi.com',
    contentful_pat: 'https://api.contentful.com',
    postman_api: 'https://api.getpostman.com',
    supabase_key: 'https://supabase.com',
    airtable_pat: 'https://api.airtable.com',
    planetscale_token: 'https://api.planetscale.com',
    databricks: 'https://accounts.cloud.databricks.com',
    pulumi: 'https://api.pulumi.com',
    notion: 'https://api.notion.com',
    linear: 'https://api.linear.app',
    mailgun: 'https://api.mailgun.net',
    hashicorp_vault_token: 'https://www.vaultproject.io',
    hashicorp_tf_token: 'https://app.terraform.io',
    doppler_token: 'https://api.doppler.com',
    docker_pat: 'https://hub.docker.com',
    grafana_service: 'https://grafana.com', grafana_cloud: 'https://grafana.com',
    dynatrace_token: 'https://www.dynatrace.com',
    newrelic_user_api: 'https://api.newrelic.com', newrelic_insert: 'https://api.newrelic.com',
    artifactory_token: 'https://jfrog.com',
  },

  patternSuggestedNames: {
    aws_access_key_id: 'AWS Access Key', aws_temp_access_key_id: 'AWS Temp Access Key',
    gh_pat_classic: 'GitHub PAT', gh_pat_fine: 'GitHub Fine-Grained PAT', github_oauth: 'GitHub OAuth Token', github_app: 'GitHub App Token',
    gitlab_pat: 'GitLab PAT', bitbucket_app_password: 'Bitbucket App Password',
    slack_bot: 'Slack Bot Token', slack_user: 'Slack User Token', slack_app: 'Slack App Token', slack_webhook: 'Slack Webhook',
    teams_webhook: 'Teams Webhook', discord_bot: 'Discord Bot Token',
    stripe_secret: 'Stripe Secret Key',
    anthropic_api: 'Anthropic API Key',
    openai_project: 'OpenAI API Key', openai_legacy: 'OpenAI API Key',
    google_api_key: 'Google API Key',
    npm_token: 'npm Token', pypi_token: 'PyPI API Token', nuget_api: 'NuGet API Key',
    atlassian_api_token: 'Atlassian API Token',
    shopify_token: 'Shopify Token',
    sendgrid: 'SendGrid API Key',
    twilio: 'Twilio Account SID', twilio_auth: 'Twilio API Key',
    telegram_bot: 'Telegram Bot Token',
    dropbox_token: 'Dropbox Access Token',
    figma_pat: 'Figma PAT',
    hubspot_private_app: 'HubSpot Private App Token',
    contentful_pat: 'Contentful PAT',
    postman_api: 'Postman API Key',
    supabase_key: 'Supabase Service Key',
    airtable_pat: 'Airtable PAT',
    planetscale_token: 'PlanetScale Token',
    databricks: 'Databricks PAT',
    pulumi: 'Pulumi Token',
    notion: 'Notion Secret',
    linear: 'Linear API Key',
    mailgun: 'Mailgun API Key',
    hashicorp_vault_token: 'HashiCorp Vault Token',
    hashicorp_tf_token: 'Terraform Cloud Token',
    doppler_token: 'Doppler Token',
    docker_pat: 'Docker Hub PAT',
    grafana_service: 'Grafana Service Token', grafana_cloud: 'Grafana Cloud Key',
    dynatrace_token: 'Dynatrace API Token',
    newrelic_user_api: 'New Relic API Key', newrelic_insert: 'New Relic Insert Key',
    artifactory_token: 'JFrog Artifactory Token',
    age_secret_key: 'age Secret Key',
  },

  async showApplyModal() {
    const c = this.decisionCounts();
    if (c.vault + c.remove === 0) { alert('No Vaultify or Remove decisions yet. Junkyard items apply on the next scan automatically.'); return; }

    const overlay = document.getElementById('applyOverlay');
    overlay.style.display = 'flex';
    const body = document.getElementById('applyModalBody');
    const footer = document.getElementById('applyModalFooter');
    body.innerHTML = '<div style="text-align:center;padding:30px"><div class="vf-spinner" style="margin:0 auto 12px"></div><span style="color:var(--muted);font-size:.85rem">Loading vault status...</span></div>';
    footer.innerHTML = '<button class="tb-btn" onclick="App.hideApplyModal()">Cancel</button><button class="btn-primary" id="btnConfirmApply" onclick="App.confirmApply()" disabled>Confirm &amp; Apply</button>';
    footer.style.display = 'flex';

    let authOk = false;
    if (c.vault > 0) {
      try {
        const r = await (await fetch('/api/vaults/auth-status?refresh=1')).json();
        authOk = !!r.onepassword_signed_in;
      } catch (e) {}
      this.opSignedIn = authOk;
      this.renderVaultStatus();
    }

    let vaultHtml = '';
    if (c.vault > 0) {
      const op = this.vaultList.find(v => v.cli === 'op');
      if (!op || !op.installed) {
        vaultHtml = `<div style="background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.3);border-radius:8px;padding:10px 14px;color:var(--err);font-size:.85rem;margin-top:12px">1Password CLI not installed. Install: <code>winget install -e --id AgileBits.1Password.CLI</code></div>`;
      } else if (!authOk) {
        vaultHtml = `<div style="background:rgba(251,191,36,.08);border:1px solid rgba(251,191,36,.3);border-radius:8px;padding:10px 14px;color:var(--warn);font-size:.85rem;margin-top:12px">Vault not open. In the sidebar, click the <strong>1Password</strong> tile, then <strong>Open Vault</strong>, and try again.</div>`;
      } else {
        let opts = '<option value="__new__">+ Create new vault</option>';
        try {
          const vaults = await (await fetch('/api/vaults/list-1p')).json();
          if (vaults && vaults.length) {
            const vfFirst = vaults.filter(v => /vaultify/i.test(v.name));
            const rest = vaults.filter(v => !/vaultify/i.test(v.name));
            [...vfFirst, ...rest].forEach(v => { opts += `<option value="${this.esc(v.name)}" ${/vaultify/i.test(v.name)?'selected':''}>${this.esc(v.name)} (${v.items} items)</option>`; });
          }
        } catch (e) {}
        vaultHtml = `<div style="margin-top:12px"><label style="font-size:12px;color:var(--muted);display:block;margin-bottom:4px">Vault for ${c.vault} secret(s)</label><select id="vaultSelect" style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit" onchange="document.getElementById('newVaultName').style.display=this.value==='__new__'?'block':'none'">${opts}</select><input id="newVaultName" placeholder="Vault name (e.g. Vaultify)" style="display:none;width:100%;margin-top:8px;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit" value="Vaultify"></div>`;

        const vaultItems = this.getGroups().filter(g => this.decisions[g.hash]?.action === 'vault');
        if (vaultItems.length > 0) {
          vaultHtml += `<div style="margin-top:16px;border-top:1px solid var(--border);padding-top:12px"><label style="font-size:12px;color:var(--muted);display:block;margin-bottom:8px">Name items to Vaultify</label>`;
          vaultItems.forEach(g => {
            const pid = g.pattern_id;
            const suggestedName = this.patternSuggestedNames[pid] || g.description || pid;
            const apiUrl = this.patternApiUrls[pid] || '';
            vaultHtml += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:.84rem">`;
            vaultHtml += `<span style="width:10px;height:10px;border-radius:50%;background:var(--ok);flex-shrink:0"></span>`;
            vaultHtml += `<input data-vault-name="${this.esc(g.hash)}" value="${this.esc(suggestedName)}" style="flex:1;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 10px;font:inherit;font-size:.84rem" placeholder="Item name">`;
            vaultHtml += `<input data-vault-url="${this.esc(g.hash)}" value="${this.esc(apiUrl)}" style="width:200px;background:var(--bg2);border:1px solid var(--border);color:var(--muted);border-radius:6px;padding:6px 10px;font:inherit;font-size:.78rem" placeholder="API URL (for vault logo)" title="API URL — helps vault associate a logo">`;
            vaultHtml += `</div>`;
          });
          vaultHtml += `</div>`;
        }
      }
    }

    let providerBanner = '';
    if (c.vault > 0 && this.selectedVaultProvider !== 'op') {
      const pv = (this.vaultList || []).find(x => x.cli === this.selectedVaultProvider);
      const pname = pv ? pv.name : this.selectedVaultProvider;
      providerBanner = `<div style="background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.25);border-radius:8px;padding:10px 14px;color:var(--accent);font-size:.82rem;margin-bottom:12px">You have <strong>${this.esc(pname)}</strong> selected in the sidebar. Apply still uses <strong>1Password</strong> until other vault backends are available.</div>`;
    }

    body.innerHTML = `
      <div style="font-size:.85rem;margin-bottom:16px">
        <div style="display:flex;gap:20px;flex-wrap:wrap">
          <div><span style="color:var(--ok);font-weight:700;font-size:1.3rem">${c.vault}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Vaultify</div></div>
          <div><span style="color:var(--err);font-weight:700;font-size:1.3rem">${c.remove}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Remove</div></div>
          <div><span style="color:var(--muted);font-weight:700;font-size:1.3rem">${c.graveyard}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">Junkyard</div></div>
          <div><span style="font-weight:700;font-size:1.3rem">${c.vault + c.remove + c.graveyard}</span><div style="color:var(--muted);font-size:.72rem;text-transform:uppercase">With action</div></div>
        </div>
      </div>
      ${providerBanner}
      ${vaultHtml}
    `;

    const confirmBtn = document.getElementById('btnConfirmApply');
    const op = this.vaultList.find(v => v.cli === 'op');
    const opReady = !!(op && op.installed && authOk);
    confirmBtn.disabled = (c.vault > 0) && !opReady;
    this.updateVaultReadinessSection();
  },

  _applyCompleted: false,
  _lastApplyResults: null,

  hideApplyModal() {
    document.getElementById('applyOverlay').style.display = 'none';
    if (this._applyCompleted) {
      this._applyCompleted = false;
      const results = this._lastApplyResults || [];
      this._lastApplyResults = null;
      const successVaultRemove = new Set();
      results.forEach(r => {
        if (!r.ok) return;
        if (r.action === 'vault' || r.action === 'remove') successVaultRemove.add(r.match_sha256);
      });
      this.state.findings = (this.state.findings || []).filter(f => !successVaultRemove.has(f.match_sha256));
      this.state.hits_total = this.state.findings.length;
      results.forEach(r => {
        if (!r.ok || !r.match_sha256) return;
        if (r.action === 'vault' || r.action === 'remove') delete this.decisions[r.match_sha256];
      });
      if (this.sessionId) {
        try { localStorage.setItem('vf-decisions-' + this.sessionId, JSON.stringify(this.decisions)); } catch (e) {}
      }
      this.saveDecisionsToServer();
      this.updateNav();
      this.renderReview();
      this.loadSessions();
      this.navigate('review');
    }
  },

  async confirmApply() {
    const body = document.getElementById('applyModalBody');
    const footer = document.getElementById('applyModalFooter');
    footer.style.display = 'none';

    const nameInputs = {};
    const urlInputs = {};
    document.querySelectorAll('[data-vault-name]').forEach(el => { nameInputs[el.getAttribute('data-vault-name')] = el.value.trim(); });
    document.querySelectorAll('[data-vault-url]').forEach(el => { urlInputs[el.getAttribute('data-vault-url')] = el.value.trim(); });

    let vaultName = 'Vaultify';
    const sel = document.getElementById('vaultSelect');
    if (sel) {
      if (sel.value === '__new__') {
        const input = document.getElementById('newVaultName');
        vaultName = input ? input.value.trim() || 'Vaultify' : 'Vaultify';
        body.innerHTML = '<div style="text-align:center;padding:20px"><div class="vf-spinner" style="margin:0 auto 12px"></div>Creating vault...</div>';
        try {
          await fetch('/api/vaults/create', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: vaultName }) });
        } catch (e) {}
      } else {
        vaultName = sel.value;
      }
    }

    body.innerHTML = '<div style="text-align:center;padding:20px"><div class="vf-spinner" style="margin:0 auto 12px"></div>Applying decisions...</div>';

    const items = Object.entries(this.decisions).map(([hash, d]) => ({
      match_sha256: hash,
      action: d.action,
      pattern_id: d.pattern_id,
      locations: d.locations || [],
      item_name: nameInputs[hash] || '',
      api_url: urlInputs[hash] || ''
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

  async runVeeFpFinder() {
    const overlay = document.getElementById('fpFinderOverlay');
    const body = document.getElementById('fpFinderBody');
    const approveBtn = document.getElementById('fpFinderApprove');
    if (!overlay || !body) return;

    overlay.style.display = 'flex';
    if (approveBtn) approveBtn.style.display = 'none';
    body.innerHTML = `<div style="text-align:center;padding:28px 16px">
      <div class="vf-spinner" style="margin:0 auto 16px;width:32px;height:32px"></div>
      <div style="color:var(--text);font-size:.9rem;font-weight:600;margin-bottom:6px">Preparing FP Finder</div>
      <div style="color:var(--muted);font-size:.82rem;line-height:1.45">Checking Vee provider and vault, then analysing findings\u2026<br>This can take a little while.</div>
    </div>`;

    try {
      await this.loadVeeProviders(true);
      const p = this.veeProviders.find(x => x.id === this.veeProvider);
      if (!p || !p.has_key) {
        overlay.style.display = 'none';
        this.showToast('Select an AI provider and store its key in the Vee panel (1Password).', 'error');
        return;
      }
      if (!(await this.ensureOpSessionForVaultFeatures())) {
        overlay.style.display = 'none';
        return;
      }

      body.innerHTML = `<div style="text-align:center;padding:24px 16px">
        <div class="vf-spinner" style="margin:0 auto 14px;width:32px;height:32px"></div>
        <div style="color:var(--text);font-size:.88rem;font-weight:600;margin-bottom:4px">Vee is analysing likely false positives</div>
        <div style="color:var(--muted);font-size:.8rem">Calling the model\u2026</div>
      </div>`;

      const resp = await fetch('/api/vee/fp-finder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: this.sessionId, provider: this.veeProvider })
      });
      if (!resp.ok) {
        const errTxt = await resp.text();
        throw new Error(errTxt || resp.statusText);
      }
      const data = await resp.json();
      this._fpFinderStaged = data.likely_false_positive_hashes || [];
      const reason = data.reasoning || '';
      body.innerHTML = `<div style="line-height:1.6;color:var(--text);font-size:.88rem;margin-bottom:12px">${this.esc(reason)}</div><div style="font-size:.82rem;color:var(--muted)">Staged <strong style="color:var(--c-violet)">${this._fpFinderStaged.length}</strong> finding(s). Approve to move them to the Junkyard and register scan exclusions.</div>`;
      if (approveBtn) approveBtn.style.display = this._fpFinderStaged.length ? '' : 'none';
    } catch (e) {
      body.innerHTML = `<div style="color:var(--err);font-size:.86rem">${this.esc(e.message || String(e))}</div>`;
      if (approveBtn) approveBtn.style.display = 'none';
    }
  },

  approveVeeFpFinder() {
    const hashes = this._fpFinderStaged || [];
    hashes.forEach(h => {
      const g = this.getGroups().find(x => x.hash === h);
      if (g) this.setDecision(h, 'graveyard', { source: 'vee_fp_finder' });
    });
    this._fpFinderStaged = null;
    const overlay = document.getElementById('fpFinderOverlay');
    if (overlay) overlay.style.display = 'none';
    this.reviewSubTab = 'junkyard';
    this.renderReview();
    this.showToast(`Moved ${hashes.length} to Junkyard`, 'success');
  },

  hideFpFinderModal() {
    const overlay = document.getElementById('fpFinderOverlay');
    if (overlay) overlay.style.display = 'none';
    this._fpFinderStaged = null;
  },

  showApplyResults(result) {
    this._applyCompleted = true;
    this._lastApplyResults = result.results || [];
    const body = document.getElementById('applyModalBody');
    const footer = document.getElementById('applyModalFooter');
    const results = result.results || [];
    let vaulted = 0, removed = 0, dismissed = 0, errors = 0;
    results.forEach(r => {
      if (!r.ok) errors++;
      else if (r.action === 'vault') vaulted++;
      else if (r.action === 'remove') removed++;
      else if (r.action === 'graveyard' || r.action === 'dismiss') dismissed++;
    });

    let html = '<div style="font-size:.85rem">';
    if (dismissed > 0) html += `<div style="padding:4px 0;color:var(--muted)">✓ ${dismissed} junkyard / logged</div>`;
    if (removed > 0) html += `<div style="padding:4px 0;color:var(--ok)">✓ ${removed} file(s) redacted <span style="color:var(--muted)">(REDACTED_BY_VAULTIFY)</span></div>`;
    if (vaulted > 0) html += `<div style="padding:4px 0;color:var(--ok)">✓ ${vaulted} vaulted — source updated with <span style="color:var(--muted);word-break:break-all">op://…</span> references</div>`;
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

  updateFooters() {
    const d = new Date();
    const dateStr = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    document.querySelectorAll('.vaultify-footer').forEach(f => {
      f.innerHTML = `Vaultify v0.1.7 &copy; ${d.getFullYear()} All Rights Reserved &mdash; Endpoint Credential Remediation &mdash; ${dateStr}`;
    });
  },

  showProModal() {
    const m = document.getElementById('proModal');
    if (m) m.style.display = 'flex';
  },

  hideProModal() {
    const m = document.getElementById('proModal');
    if (m) m.style.display = 'none';
  },

  showEnterpriseModal() {
    const m = document.getElementById('enterpriseModal');
    if (m) m.style.display = 'flex';
  },

  hideEnterpriseModal() {
    const m = document.getElementById('enterpriseModal');
    if (m) m.style.display = 'none';
  },

  toggleAuditSort(c) {
    if (this.auditSort.col === c) this.auditSort.dir *= -1;
    else {
      this.auditSort.col = c;
      this.auditSort.dir = c === 'time' ? -1 : 1;
    }
    this.loadAuditLog();
  },

  _auditThMark(c) {
    if (this.auditSort.col !== c) return '';
    return this.auditSort.dir < 0 ? ' \u2193' : ' \u2191';
  },

  async loadAuditLog() {
    try {
      const el = document.getElementById('auditContent');
      if (el && !el.querySelector('table')) el.innerHTML = '<div style="text-align:center;padding:24px"><div class="vf-spinner" style="margin:0 auto 12px"></div><span style="color:var(--muted);font-size:.85rem">Loading audit log...</span></div>';
      const logRaw = await (await fetch('/api/audit')).json();
      if (!el) return;
      if (!logRaw || !logRaw.length) { el.innerHTML = '<div class="empty-msg">No actions recorded yet. Start a scan to generate audit entries.</div>'; return; }
      const log = [...logRaw];
      const dir = this.auditSort.dir;
      const ac = this.auditSort.col;
      log.sort((a, b) => {
        let cmp = 0;
        if (ac === 'time') cmp = new Date(a.timestamp || 0) - new Date(b.timestamp || 0);
        else if (ac === 'level') cmp = (a.level || '').localeCompare(b.level || '');
        else if (ac === 'action') cmp = (a.action || '').localeCompare(b.action || '');
        else if (ac === 'session') cmp = (a.session_id || '').localeCompare(b.session_id || '');
        else if (ac === 'detail') cmp = (a.detail || '').localeCompare(b.detail || '');
        if (cmp !== 0) return dir * cmp;
        return new Date(a.timestamp || 0) - new Date(b.timestamp || 0);
      });
      const thStyle = 'text-align:left;padding:10px 12px;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);cursor:pointer;user-select:none';
      const levelColors = { audit: 'var(--accent)', info: 'var(--ok)', warn: 'var(--warn)', error: 'var(--err)', debug: 'var(--muted)' };
      let html = `<table class="vf-sortable" style="width:100%;border-collapse:collapse;font-size:.85rem"><thead><tr><th style="${thStyle}" onclick="App.toggleAuditSort('time')">Time${this._auditThMark('time')}</th><th style="${thStyle}" onclick="App.toggleAuditSort('level')">Level${this._auditThMark('level')}</th><th style="${thStyle}" onclick="App.toggleAuditSort('action')">Action${this._auditThMark('action')}</th><th style="${thStyle}" onclick="App.toggleAuditSort('session')">Session${this._auditThMark('session')}</th><th style="${thStyle}" onclick="App.toggleAuditSort('detail')">Detail${this._auditThMark('detail')}</th></tr></thead><tbody>`;
      log.forEach(e => {
        let dt = e.timestamp || '';
        try { dt = new Date(dt).toLocaleString(); } catch(x) {}
        const lvl = e.level || 'info';
        const sid = (e.session_id || '').slice(0, 8);
        const lc = levelColors[lvl] || 'var(--muted)';
        html += `<tr style="border-bottom:1px solid var(--border)">`;
        html += `<td style="padding:10px 12px;white-space:nowrap;color:var(--muted);font-size:.82rem">${this.esc(dt)}</td>`;
        html += `<td style="padding:10px 12px"><span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;background:${lc}22;color:${lc}">${this.esc(lvl)}</span></td>`;
        html += `<td style="padding:10px 12px;font-weight:600;font-size:.82rem">${this.esc(e.action)}</td>`;
        html += `<td style="padding:10px 12px;font-family:monospace;font-size:.78rem;color:var(--accent)">${this.esc(sid)}</td>`;
        html += `<td style="padding:10px 12px;font-family:monospace;font-size:.78rem;color:var(--muted);word-break:break-all">${this.esc(e.detail)}</td>`;
        html += `</tr>`;
      });
      el.innerHTML = html + '</tbody></table>';
    } catch (e) {}
  },

  catalogueData: null,
  cataloguePage: 0,
  CATALOGUE_PAGE_SIZE: 15,
  currentVersion: '0.1.7',

  async loadCatalogue() {
    if (this.catalogueData) { this.renderCatalogue(); return; }
    try {
      this.catalogueData = await (await fetch('/api/patterns')).json();
      this.renderCatalogue();
    } catch (e) { console.warn('Load catalogue failed', e); }
  },

  toggleCatalogueSort(c) {
    if (this.catalogueSort.col === c) this.catalogueSort.dir *= -1;
    else {
      this.catalogueSort.col = c;
      this.catalogueSort.dir = c === 'severity' ? -1 : 1;
    }
    this.cataloguePage = 0;
    this.renderCatalogue();
  },

  renderCatalogue() {
    const el = document.getElementById('catalogueContent');
    if (!el || !this.catalogueData) return;
    const q = (document.getElementById('catalogueSearch') || {}).value || '';
    const query = q.trim().toLowerCase();
    const all = this.catalogueData;
    const filtered = query ? all.filter(p => [p.id, p.description, p.severity, p.added_in || ''].join(' ').toLowerCase().includes(query)) : all;
    const dir = this.catalogueSort.dir;
    const ccol = this.catalogueSort.col;
    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (ccol === 'id') cmp = (a.id || '').localeCompare(b.id || '');
      else if (ccol === 'description') cmp = (a.description || '').localeCompare(b.description || '');
      else if (ccol === 'severity') cmp = this.severityRank(a.severity) - this.severityRank(b.severity);
      else if (ccol === 'since') cmp = (a.added_in || '').localeCompare(b.added_in || '');
      if (cmp !== 0) return dir * cmp;
      return (a.id || '').localeCompare(b.id || '');
    });

    const badge = document.getElementById('catalogueBadge');
    if (badge) badge.textContent = all.length + ' patterns';
    const navBadge = document.getElementById('navCatBadge');
    if (navBadge) navBadge.textContent = all.length;

    if (!sorted.length) { el.innerHTML = '<div class="empty-msg">No patterns match your search.</div>'; return; }

    const totalPages = Math.max(1, Math.ceil(sorted.length / this.CATALOGUE_PAGE_SIZE));
    if (this.cataloguePage >= totalPages) this.cataloguePage = totalPages - 1;
    if (this.cataloguePage < 0) this.cataloguePage = 0;
    const start = this.cataloguePage * this.CATALOGUE_PAGE_SIZE;
    const pageItems = sorted.slice(start, start + this.CATALOGUE_PAGE_SIZE);

    const sevColors = { critical: 'var(--err)', high: 'var(--orange)', medium: 'var(--warn)', low: 'var(--muted)' };
    const thStyle = 'text-align:left;padding:10px 12px;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--border);cursor:pointer;user-select:none';
    const thC = `${thStyle};text-align:center`;
    const m = c => (this.catalogueSort.col === c ? (this.catalogueSort.dir < 0 ? ' \u2193' : ' \u2191') : '');

    let html = `<table class="vf-sortable" style="width:100%;border-collapse:collapse;font-size:.88rem"><thead><tr>`;
    html += `<th style="${thStyle}" onclick="App.toggleCatalogueSort('id')">Pattern ID${m('id')}</th>`;
    html += `<th style="${thStyle}" onclick="App.toggleCatalogueSort('description')">Description${m('description')}</th>`;
    html += `<th style="${thC}" onclick="App.toggleCatalogueSort('severity')">Severity${m('severity')}</th>`;
    html += `<th style="${thC}" onclick="App.toggleCatalogueSort('since')">Since${m('since')}</th>`;
    html += `</tr></thead><tbody>`;

    pageItems.forEach(p => {
      const sc = sevColors[p.severity] || 'var(--muted)';
      const isNew = p.added_in === this.currentVersion;
      html += `<tr style="border-bottom:1px solid var(--border);transition:background .15s" onmouseover="this.style.background='rgba(56,189,248,.03)'" onmouseout="this.style.background=''">`;
      html += `<td style="padding:10px 12px;font-family:monospace;font-size:.82rem;color:var(--accent)">${this.esc(p.id)}${isNew ? '<span class="cat-new">NEW</span>' : ''}</td>`;
      html += `<td style="padding:10px 12px">${this.esc(p.description)}</td>`;
      html += `<td style="padding:10px 12px;text-align:center"><span style="display:inline-block;padding:2px 10px;border-radius:4px;font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;background:${sc}18;color:${sc}">${this.esc(p.severity)}</span></td>`;
      html += `<td style="padding:10px 12px;text-align:center;font-family:monospace;font-size:.78rem;color:var(--muted)">v${this.esc(p.added_in || '0.1.0')}</td>`;
      html += `</tr>`;
    });
    html += '</tbody></table>';

    if (totalPages > 1) {
      html += `<div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-top:16px;font-size:13px">`;
      html += `<button onclick="App.cataloguePage--;App.renderCatalogue()" ${this.cataloguePage===0?'disabled':''} style="background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 14px;cursor:pointer;font:inherit;${this.cataloguePage===0?'opacity:.35;cursor:not-allowed':''}">Prev</button>`;
      html += `<span style="color:var(--muted)">Page ${this.cataloguePage+1} of ${totalPages} (${sorted.length} patterns)</span>`;
      html += `<button onclick="App.cataloguePage++;App.renderCatalogue()" ${this.cataloguePage>=totalPages-1?'disabled':''} style="background:var(--panel);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 14px;cursor:pointer;font:inherit;${this.cataloguePage>=totalPages-1?'opacity:.35;cursor:not-allowed':''}">Next</button>`;
      html += `</div>`;
    }
    el.innerHTML = html;
  },

  loadDocs() {
    const extEl = document.getElementById('docsExtensions');
    const fnEl = document.getElementById('docsFilenames');
    const exts = ['.env','.ps1','.json','.yml','.yaml','.js','.mjs','.ts','.tsx','.jsx','.py','.rb','.go','.java','.properties','.toml','.config','.cfg','.ini','.conf','.tf','.tfvars','.sh','.bash','.zsh','.xml','.cs','.php','.sql','.rs','.vue','.local','.development','.kt','.scala','.swift','.gradle','.sbt','.r','.lua','.pl','.pm','.pem','.key','.crt','.dockerfile','.helmfile'];
    const fns = ['.npmrc','.pypirc','.netrc','.gitconfig','credentials','config','secrets','Dockerfile','Makefile','Vagrantfile','.bashrc','.zshrc','.profile','.bash_profile'];
    if (extEl) extEl.innerHTML = exts.map(e => `<span style="font-family:monospace;font-size:.75rem;padding:3px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--c-cyan)">${this.esc(e)}</span>`).join('');
    if (fnEl) fnEl.innerHTML = fns.map(f => `<span style="font-family:monospace;font-size:.75rem;padding:3px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;color:var(--c-violet)">${this.esc(f)}</span>`).join('');
  },

  releaseNotes: [
    {
      version: '0.1.7',
      date: 'April 2026',
      current: true,
      changes: [
        { type: 'new', text: 'Context Detection Layer — identifies secrets by variable name (api_key, password, secret_access, db_url) in assignment patterns' },
        { type: 'new', text: 'Sequenced detection pipeline: Pre-validate → Layer 2 Context → Layer 1 Value Patterns → Post-validate with confidence scoring' },
        { type: 'new', text: 'Shannon entropy computed and displayed for all findings — cyan numbers in Review table and Findings Explorer' },
        { type: 'new', text: 'CTX badge on context-detected findings, checkmark when both layers agree' },
        { type: 'new', text: '.env and credential file highlighting in Findings Explorer with high-density warnings' },
        { type: 'new', text: 'Confidence-based auto-suggest — context-only findings stay pending for human review' },
        { type: 'new', text: 'Pattern Graph node glow scales with average entropy; context nodes in rose' },
        { type: 'new', text: 'Docs page — Detection Pipeline, Entropy Scoring, Security Model, Supported Vaults, File Coverage' },
        { type: 'new', text: 'Vee Enterprise tier with diamond badges, suited Vee avatar, and Contact Sales modal' },
        { type: 'new', text: 'Application log file at %TEMP%/vaultify-scans/.logs/vaultify-app.log' },
        { type: 'perf', text: 'Force-directed Canvas graph replacing SVG — 60fps physics simulation' },
        { type: 'fix', text: 'Scan stuck at 100% — auto-complete after 3s and WebSocket reconnect sync' },
        { type: 'fix', text: 'Scan conflict recovery — auto-stops stale scans on retry' },
        { type: 'new', text: 'Choose a Vault: four provider tiles in the sidebar (2×2), selectable sync focus; 1Password default; subtle glow when op CLI or session missing' },
        { type: 'new', text: 'Scan complete → Review (skipped during Walkthrough); unified op session check for Apply, Vee chat/summary, FP Finder' },
        { type: 'fix', text: 'Apply Decisions confirm disabled when op CLI missing but Vaultify decisions exist' },
      ]
    },
    {
      version: '0.1.6',
      date: 'April 2026',
      changes: [
        { type: 'perf', text: 'Prefix-based fast-skip scanning — 10-50x faster scan performance' },
        { type: 'new', text: 'Pattern Node Graph visualization replacing flat bar charts' },
        { type: 'new', text: 'Findings Tree Explorer with collapsible folder structure' },
        { type: 'new', text: 'Unified color system — consistent semantic colors across all pages' },
        { type: 'new', text: 'Expandable full-screen Pattern Graph modal' },
        { type: 'fix', text: 'Restored snippet button with redacted secret values in previews' },
        { type: 'fix', text: 'Browser extension directories excluded from scanning (Brave, Chrome, Firefox, Edge, Yandex, Opera, Vivaldi)' },
        { type: 'fix', text: 'Auto-suggest no longer falsely dismisses secrets in cache directories' },
        { type: 'fix', text: 'NuGet and Artifactory false positive reduction with higher entropy thresholds' },
        { type: 'fix', text: 'OpenAI legacy pattern entropy threshold raised to reduce minified JS matches' },
      ]
    },
    {
      version: '0.1.5',
      date: 'April 2026',
      changes: [
        { type: 'new', text: 'Scan dashboard redesign — hero status bar, animated counters, severity donut chart' },
        { type: 'new', text: 'Choose a Vault: vendor logos, official install links, then PATH detection + 1Password package install' },
        { type: 'new', text: 'Pro tier teaser — Unified Dashboard, Compliance, Settings with crown badges' },
        { type: 'new', text: 'Pro modal with Vee in crown pose' },
        { type: 'new', text: 'Toast notifications on scan complete' },
        { type: 'new', text: 'Elapsed time and files/s throughput during scan' },
        { type: 'new', text: 'Current file path shown in scan progress' },
        { type: 'new', text: 'Scan type indicator — Machine Scan vs Folder Scan in status pill' },
        { type: 'new', text: '20+ additional file types and extensionless files now scanned' },
        { type: 'fix', text: 'Folder picker backslash path bug on Windows' },
        { type: 'fix', text: 'Report buttons layout spacing' },
      ]
    },
    {
      version: '0.1.4',
      date: 'April 2026',
      changes: [
        { type: 'security', text: 'Eliminated plaintext.json — zero secrets written to disk, ever' },
        { type: 'security', text: 'Line snippets redacted in session storage and API responses' },
        { type: 'security', text: 'WebSocket broadcasts stripped of secret values' },
        { type: 'security', text: '.bak backup files removed — no pre-redaction copies' },
        { type: 'security', text: 'File permissions tightened to owner-only (0o700/0o600)' },
        { type: 'security', text: 'Gemini API key moved from URL query string to header' },
        { type: 'security', text: 'WebSocket origin validation — localhost only' },
        { type: 'security', text: 'Error responses sanitized — no internal paths or CLI output leaked' },
        { type: 'new', text: '24 new detection patterns — Dropbox, Figma, HubSpot, Discord, Docker, PyPI, and more (54 total)' },
        { type: 'new', text: 'Secret Catalogue page with searchable, paginated pattern library' },
        { type: 'new', text: 'Good Practice recognition for temporary/rotating credentials' },
        { type: 'new', text: 'Bulk decision buttons — Vaultify All Critical, Vaultify All High, Dismiss All Low' },
        { type: 'new', text: 'Auto-suggest decisions on scan complete with undo banner' },
        { type: 'new', text: 'Session archiving — Active/Archive tabs in Reports' },
        { type: 'new', text: '1Password CLI one-click install button in Choose a Vault' },
        { type: 'new', text: 'Interactive walkthrough tour with live demo scan and Vee as guide' },
        { type: 'new', text: 'Scan folder picker with directory browser and quick picks' },
        { type: 'new', text: 'Vee loading spinner when connecting AI provider' },
        { type: 'new', text: 'Remediation summary renders under Review table instead of chat' },
        { type: 'new', text: 'Vee falls back to most recent session when no active scan' },
        { type: 'fix', text: 'Duplicate Vee label in chat messages' },
        { type: 'fix', text: 'Empty parens in provider activation message' },
        { type: 'new', text: 'MIT License, .gitignore cleanup, GitHub Actions CI for cross-platform releases' },
      ]
    }
  ],

  async loadVersion() {
    try {
      const v = await (await fetch('/api/version')).json();
      const el = document.getElementById('versionContent');
      if (!el) return;
      el.innerHTML = `<div style="font-size:.9rem;display:grid;grid-template-columns:140px 1fr;gap:8px 16px;padding:8px 0">
        <span style="color:var(--c-slate)">Version</span><span style="font-weight:700;color:var(--c-cyan)">${this.esc(v.version)}</span>
        <span style="color:var(--c-slate)">Build</span><span>${this.esc(v.build)}</span>
        <span style="color:var(--c-slate)">OS</span><span>${this.esc(v.os)}</span>
        <span style="color:var(--c-slate)">Architecture</span><span>${this.esc(v.arch)}</span>
        <span style="color:var(--c-slate)">Domain</span><span><a href="https://vaultify.live" target="_blank" style="color:var(--c-indigo)">vaultify.live</a></span>
      </div>`;

      const notesEl = document.getElementById('releaseNotes');
      if (!notesEl) return;
      const typeColors = { 'new': 'var(--c-cyan)', 'fix': 'var(--c-success)', 'security': 'var(--c-violet)', 'perf': 'var(--c-rose)' };
      const typeLabels = { 'new': 'NEW', 'fix': 'FIX', 'security': 'SEC', 'perf': 'PERF' };

      notesEl.innerHTML = this.releaseNotes.map(r => {
        const isCurrent = r.current;
        let html = `<div class="card" style="margin-bottom:16px${isCurrent ? ';border-color:rgba(34,211,238,.25)' : ''}">`;
        html += `<div class="card-title" style="justify-content:space-between"><span>v${this.esc(r.version)} ${isCurrent ? '<span class="badge" style="background:rgba(34,211,238,.12);color:var(--c-cyan)">Current</span>' : ''}</span><span style="font-size:.78rem;font-weight:400;color:var(--c-slate)">${this.esc(r.date)}</span></div>`;
        html += '<div style="display:flex;flex-direction:column;gap:6px">';
        r.changes.forEach(c => {
          const tc = typeColors[c.type] || 'var(--c-slate)';
          const tl = typeLabels[c.type] || c.type.toUpperCase();
          html += `<div style="display:flex;align-items:flex-start;gap:10px;font-size:.84rem;line-height:1.5">`;
          html += `<span style="flex-shrink:0;font-size:.62rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em;padding:2px 8px;border-radius:4px;background:${tc}18;color:${tc};margin-top:2px">${tl}</span>`;
          html += `<span>${this.esc(c.text)}</span>`;
          html += `</div>`;
        });
        html += '</div></div>';
        return html;
      }).join('');
    } catch (e) {}
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
    this.updateVeeChatState();
    const logos = {
      openai: `<img src="/assets/vee-logo-gpt.svg" alt="" class="vee-prov-logo-img" width="26" height="26" loading="lazy">`,
      anthropic: `<img src="/assets/vee-logo-claude.svg" alt="" class="vee-prov-logo-img" width="26" height="26" loading="lazy">`,
      gemini: `<svg width="24" height="24" viewBox="0 0 28 28"><defs><linearGradient id="gg" x1="0" y1="0" x2="28" y2="28" gradientUnits="userSpaceOnUse"><stop stop-color="#4285F4"/><stop offset=".5" stop-color="#9B72CB"/><stop offset="1" stop-color="#D96570"/></linearGradient></defs><path d="M14 28C14 21.4 8.8 14 0 14c8.8 0 14-7.4 14-14 0 8.8 5.2 14 14 14-8.8 0-14 7.4-14 14z" fill="url(#gg)"/></svg>`,
      ollama: `<span style="font-size:1.3rem">🦙</span>`
    };
    el.innerHTML = this.veeProviders.map(p => {
      const active = this.veeProvider === p.id;
      return `<div class="vee-prov-card ${active ? 'active' : ''} ${p.available ? 'available' : ''}" onclick="App.selectVeeProvider('${p.id}')" title="${p.name} (${p.model})">${logos[p.id] || '?'}<span style="font-size:.6rem;margin-top:2px">${p.name}</span></div>`;
    }).join('');
    const label = document.getElementById('veeProvLabel');
    if (label) {
      const active = this.veeProviders.find(p => p.id === this.veeProvider);
      label.textContent = active ? `Using ${active.name}${active.model ? ' · ' + active.model : ''}` : 'Select a provider to start';
    }
  },

  async selectVeeProvider(id) {
    const p = this.veeProviders.find(x => x.id === id);
    if (!p) return;
    const provLabel = document.getElementById('veeProvLabel');
    const cards = document.querySelectorAll('.vee-prov-card');
    if (p.needs_key && !p.has_key) {
      if (!(await this.ensureOpSessionForVaultFeatures())) {
        if (provLabel) provLabel.textContent = 'Select a provider to start';
        return;
      }
      provLabel.innerHTML = '<div class="vf-spinner" style="width:14px;height:14px;display:inline-block;vertical-align:middle;margin-right:6px"></div> Connecting...';
      cards.forEach(c => { c.style.pointerEvents = 'none'; c.style.opacity = '.4'; });
      try {
      await this.loadVeeProviders(true);
      const updated = this.veeProviders.find(x => x.id === id);
      if (updated && updated.has_key) { p.has_key = true; p.available = true; p.model = updated.model; }
      } finally {
        cards.forEach(c => { c.style.pointerEvents = ''; c.style.opacity = ''; });
      }
    }
    if (p.needs_key && !p.has_key) {
      const area = document.getElementById('veeKeyArea');
      area.innerHTML = `<div style="padding:8px 20px"><input type="password" id="veeKeyInput" placeholder="${p.name} API key" style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit;font-size:.82rem;margin-bottom:6px"><button class="vee-send" onclick="App.validateVeeKey('${id}')" style="width:100%;padding:8px;font-size:.82rem">Validate Key</button></div>`;
      this.addVeeMsg('vee', `Paste your ${p.name} API key above. I'll check which models are available, then you choose one.`);
      return;
    }
    if (p.needs_key && p.has_key) {
      if (this.veeProvider === id) return;
      this.veeProvider = id;
      document.getElementById('veeKeyArea').innerHTML = '';
      this.renderVeeProviders();
      this.addVeeMsg('vee', `<strong>${this.esc(p.name)}</strong>${p.model ? ' \u00b7 ' + this.esc(p.model) : ''} connected. Key loaded from your Vaultify vault. How can I help?`);
      return;
    }
    if (!p.available) {
      this.addVeeMsg('vee', `Ollama isn't running. Start it with \`ollama serve\` and try again.`);
      return;
    }
    this.veeProvider = id;
    document.getElementById('veeKeyArea').innerHTML = '';
    this.renderVeeProviders();
    this.addVeeMsg('vee', `<strong>${this.esc(p.name)}</strong>${p.model ? ' \u00b7 ' + this.esc(p.model) : ''} connected. How can I help with your scan findings?`);
  },

  async validateVeeKey(provider) {
    const input = document.getElementById('veeKeyInput');
    if (!input || !input.value.trim()) return;
    const key = input.value.trim();
    const area = document.getElementById('veeKeyArea');
    area.innerHTML = '<div style="padding:12px 20px;color:var(--muted);font-size:.82rem">Validating key and fetching models...</div>';

    try {
      const r = await (await fetch('/api/vee/models', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, key })
      })).json();

      if (!r.valid || !r.models || !r.models.length) {
        area.innerHTML = `<div style="padding:8px 20px"><div style="color:var(--err);font-size:.82rem;margin-bottom:8px">Invalid key or no models available.</div><input type="password" id="veeKeyInput" value="${this.esc(key)}" style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit;font-size:.82rem;margin-bottom:6px"><button class="vee-send" onclick="App.validateVeeKey('${provider}')" style="width:100%;padding:8px;font-size:.82rem">Try Again</button></div>`;
        return;
      }

      this._pendingVeeKey = key;
      let opts = r.models.map(m => `<option value="${this.esc(m)}">${this.esc(m)}</option>`).join('');
      area.innerHTML = `<div style="padding:8px 20px"><div style="color:var(--ok);font-size:.82rem;margin-bottom:8px">✓ Key valid — ${r.models.length} model(s) available</div><select id="veeModelSelect" style="width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:8px 10px;font:inherit;font-size:.82rem;margin-bottom:6px">${opts}</select><button class="vee-send" onclick="App.storeVeeKey('${provider}')" style="width:100%;padding:8px;font-size:.82rem">Store Key &amp; Model in Vault</button></div>`;
    } catch (e) {
      area.innerHTML = `<div style="padding:8px 20px;color:var(--err);font-size:.82rem">Validation failed. Check your connection.</div>`;
    }
  },

  async storeVeeKey(provider) {
    if (!(await this.ensureOpSessionForVaultFeatures())) return;
    const modelSelect = document.getElementById('veeModelSelect');
    const model = modelSelect ? modelSelect.value : '';
    const key = this._pendingVeeKey || '';
    if (!key) return;

    try {
      const r = await (await fetch('/api/vee/key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, key, model })
      })).json();
      if (r.stored) {
        document.getElementById('veeKeyArea').innerHTML = '';
        this._pendingVeeKey = '';
        this.veeProvider = provider;
        await this.loadVeeProviders(true);
        const p = this.veeProviders.find(x => x.id === provider);
        this.addVeeMsg('vee', `Key and model stored in vault. Using ${p ? p.name : provider} (${r.model || model}). How can I help?`);
      }
    } catch (e) {
      this.addVeeMsg('vee', 'Failed to store key. Make sure your vault is open first.');
    }
  },

  addVeeMsg(role, text) {
    const chat = document.getElementById('veeChat');
    const div = document.createElement('div');
    div.className = `vee-msg ${role}`;
    if (role === 'vee') {
      div.innerHTML = `<div class="msg-name">Vee</div><div class="msg-body">${this.formatVeeText(text)}</div>`;
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

  updateVeeChatState() {
    const input = document.getElementById('veeInput');
    const sendBtn = document.getElementById('veeSendBtn');
    const disabled = !this.veeProvider;
    if (input) { input.disabled = disabled; input.placeholder = disabled ? 'Select an AI provider above to start chatting' : 'Ask Vee about your findings...'; }
    if (sendBtn) sendBtn.disabled = disabled;
  },

  async veeSend() {
    const input = document.getElementById('veeInput');
    const msg = input.value.trim();
    if (!msg) return;
    if (!this.veeProvider) return;
    if (!(await this.ensureOpSessionForVaultFeatures())) return;
    input.value = '';
    this.addVeeMsg('user', msg);
    const thinking = this.addVeeMsg('vee', 'Thinking...');
    thinking.querySelector('.msg-body').innerHTML = '<span style="color:var(--muted)"><div class="vf-spinner" style="width:12px;height:12px;display:inline-block;vertical-align:middle;margin-right:6px"></div>Thinking...</span>';

    try {
      const resp = await fetch('/api/vee/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: this.sessionId || '',
          message: msg,
          provider: this.veeProvider,
          context: {
            current_page: this.currentPage,
            decisions: this.decisionCounts(),
            total_findings: (this.state.findings || []).length,
            scan_status: this.state.status
          }
        })
      });
      const text = await resp.text();
      thinking.querySelector('.msg-body').innerHTML = this.formatVeeText(text);
      document.getElementById('veeChat').scrollTop = document.getElementById('veeChat').scrollHeight;
    } catch (e) {
      thinking.querySelector('.msg-body').innerHTML = `<span style="color:var(--err)">Sorry, something went wrong. ${this.esc(e.message)}</span>`;
    }
  },

  async veeSummary() {
    if (!this.state.findings || !this.state.findings.length) { this.addVeeMsg('vee', 'No scan data yet. Run a scan or load a session from Reports first.'); return; }
    if (!this.veeProvider) return;
    if (!(await this.ensureOpSessionForVaultFeatures())) return;

    this.addVeeMsg('vee', 'Generating your remediation summary...');

    const sumEl = document.getElementById('remediationSummary');
    sumEl.innerHTML = '<div class="card" style="margin-top:22px"><div class="card-title">Remediation Summary</div><div style="text-align:center;padding:30px"><div class="vf-spinner" style="margin:0 auto 12px"></div><span style="color:var(--muted);font-size:.85rem">Generating summary with Vee...</span></div></div>';
    this.navigate('review');

    try {
      const resp = await fetch('/api/vee/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: this.sessionId || '',
          message: 'Generate a concise executive remediation summary suitable for governance reporting. Include: total secrets found, breakdown by severity and type, top 5 most critical findings with recommended actions (Vaultify/Remove/Dismiss), overall risk assessment, highlight any likely false positives and explain why, and recommended next steps. Format with headers and bullet points.',
          provider: this.veeProvider
        })
      });
      const text = await resp.text();
      sumEl.innerHTML = `<div class="card" style="margin-top:22px"><div class="card-title">Remediation Summary <span class="badge">by Vee</span></div><div style="font-size:.88rem;line-height:1.7">${this.formatVeeText(text)}</div></div>`;
      this.addVeeMsg('vee', 'Summary generated \u2014 see it below the Review table.');
    } catch (e) {
      sumEl.innerHTML = `<div class="card" style="margin-top:22px"><div class="card-title">Remediation Summary</div><div style="color:var(--err);padding:16px">Summary generation failed. ${this.esc(e.message)}</div></div>`;
    }
  },

  // =====================================================================
  // INTERACTIVE WALKTHROUGH TOUR
  // =====================================================================

  DEMO_FINDINGS: [
    { pattern_id: 'aws_access_key_id', severity: 'critical', description: 'AWS Access Key ID', root: 'C:\\Users\\demo', relative_path: 'projects\\backend\\.env', full_path: 'C:\\Users\\demo\\projects\\backend\\.env', line_number: 3, match_sha256: 'demo_sha_001', redacted_preview: 'AKIA5R...XMPL', line_snippet: 'AWS_ACCESS_KEY_ID=AKIA5REXAMPLE1234', value: 'AKIA5REXAMPLE1234' },
    { pattern_id: 'aws_access_key_id', severity: 'critical', description: 'AWS Access Key ID', root: 'C:\\Users\\demo', relative_path: 'scripts\\deploy.ps1', full_path: 'C:\\Users\\demo\\scripts\\deploy.ps1', line_number: 17, match_sha256: 'demo_sha_002', redacted_preview: 'AKIA9Q...DEMO', line_snippet: '$accessKey = "AKIA9QDEMOKEY5678"', value: 'AKIA9QDEMOKEY5678' },
    { pattern_id: 'gh_pat_classic', severity: 'high', description: 'GitHub Personal Access Token (Classic)', root: 'C:\\Users\\demo', relative_path: 'dev\\automation\\github-sync.js', full_path: 'C:\\Users\\demo\\dev\\automation\\github-sync.js', line_number: 8, match_sha256: 'demo_sha_003', redacted_preview: 'ghp_Xk...9mRt', line_snippet: 'const token = "ghp_XkDemoToken9mRt"', value: 'ghp_XkDemoToken9mRt1234567890abcdef' },
    { pattern_id: 'gh_pat_fine', severity: 'high', description: 'GitHub Fine-Grained PAT', root: 'C:\\Users\\demo', relative_path: 'dev\\ci\\.github-token', full_path: 'C:\\Users\\demo\\dev\\ci\\.github-token', line_number: 1, match_sha256: 'demo_sha_004', redacted_preview: 'github_pat_11A...F4kE', line_snippet: 'github_pat_11ADEMOTOKEN_F4kE', value: 'github_pat_11ADEMOTOKEN_F4kE' },
    { pattern_id: 'slack_bot', severity: 'high', description: 'Slack Bot Token', root: 'C:\\Users\\demo', relative_path: 'projects\\chatbot\\config.json', full_path: 'C:\\Users\\demo\\projects\\chatbot\\config.json', line_number: 12, match_sha256: 'demo_sha_005', redacted_preview: 'xoxb-1...dEmO', line_snippet: '"token": "xoxb-1234-5678-dEmOsLaCk"', value: 'xoxb-1234-5678-dEmOsLaCk' },
    { pattern_id: 'openai_project', severity: 'high', description: 'OpenAI Project API Key', root: 'C:\\Users\\demo', relative_path: 'dev\\ai-tools\\.env.local', full_path: 'C:\\Users\\demo\\dev\\ai-tools\\.env.local', line_number: 2, match_sha256: 'demo_sha_006', redacted_preview: 'sk-proj-Dm...oKEy', line_snippet: 'OPENAI_API_KEY=sk-proj-DmExAmPlEoKEy', value: 'sk-proj-DmExAmPlEoKEy' },
    { pattern_id: 'stripe_secret', severity: 'critical', description: 'Stripe Secret Key', root: 'C:\\Users\\demo', relative_path: 'projects\\store\\server.js', full_path: 'C:\\Users\\demo\\projects\\store\\server.js', line_number: 5, match_sha256: 'demo_sha_007', redacted_preview: 'sk_live_51...dEmO', line_snippet: 'const stripe = require("stripe")("sk_live_51DeMoStRiPeKeY")', value: 'sk_live_51DeMoStRiPeKeY' },
    { pattern_id: 'anthropic_api', severity: 'high', description: 'Anthropic API Key', root: 'C:\\Users\\demo', relative_path: 'dev\\ai-tools\\claude-config.yml', full_path: 'C:\\Users\\demo\\dev\\ai-tools\\claude-config.yml', line_number: 4, match_sha256: 'demo_sha_008', redacted_preview: 'sk-ant-...xMpL', line_snippet: 'api_key: sk-ant-dEmOkEyExMpL', value: 'sk-ant-dEmOkEyExMpL' },
    { pattern_id: 'telegram_bot', severity: 'medium', description: 'Telegram Bot Token', root: 'C:\\Users\\demo', relative_path: 'scripts\\notify-bot.py', full_path: 'C:\\Users\\demo\\scripts\\notify-bot.py', line_number: 11, match_sha256: 'demo_sha_009', redacted_preview: '71234...DeMo', line_snippet: 'BOT_TOKEN = "7123456789:AAFdEmOtOkEn"', value: '7123456789:AAFdEmOtOkEn' },
    { pattern_id: 'sendgrid', severity: 'medium', description: 'SendGrid API Key', root: 'C:\\Users\\demo', relative_path: 'projects\\mailer\\.env', full_path: 'C:\\Users\\demo\\projects\\mailer\\.env', line_number: 7, match_sha256: 'demo_sha_010', redacted_preview: 'SG.dEm...oKeY', line_snippet: 'SENDGRID_API_KEY=SG.dEmOsEnDgRiDkEy.oKeY', value: 'SG.dEmOsEnDgRiDkEy.oKeY' },
    { pattern_id: 'google_api_key', severity: 'medium', description: 'Google API Key', root: 'C:\\Users\\demo', relative_path: 'dev\\maps-app\\config.ts', full_path: 'C:\\Users\\demo\\dev\\maps-app\\config.ts', line_number: 9, match_sha256: 'demo_sha_011', redacted_preview: 'AIzaSy...dEmO', line_snippet: 'export const MAPS_KEY = "AIzaSyDeMoGoOgLeKeY"', value: 'AIzaSyDeMoGoOgLeKeY' },
    { pattern_id: 'npm_token', severity: 'medium', description: 'npm Access Token', root: 'C:\\Users\\demo', relative_path: '.npmrc', full_path: 'C:\\Users\\demo\\.npmrc', line_number: 1, match_sha256: 'demo_sha_012', redacted_preview: 'npm_Dm...eXmP', line_snippet: '//registry.npmjs.org/:_authToken=npm_DmExMpLeToKeN', value: 'npm_DmExMpLeToKeN' },
  ],

  async simulateDemoScan() {
    await this._fallbackDemoScan();
  },

  async _fallbackDemoScan() {
    this.state = { status: 'running', dirs_visited: 0, candidates_queued: 0, files_scanned: 0, hits_total: 0, progress_denominator: 100, file_cap: 100000, pattern_totals: [], findings: [] };
    this.decisions = {};
    this._patternEls = {};
    const patEl = document.getElementById('patterns');
    if (patEl) patEl.innerHTML = '<div class="empty-msg">Scanning...</div>';
    this.updateDashboard(); this.updateButtons(); this.updateNav();
    const findings = this.DEMO_FINDINGS;
    const total = findings.length;
    let i = 0;
    return new Promise(resolve => {
      const interval = setInterval(() => {
        if (i >= total) {
          clearInterval(interval);
          this.state.status = 'complete';
          this.state.files_scanned = 100;
          this.state.progress_denominator = 100;
          this.updateDashboard(); this.updateButtons(); this.updateNav();
          resolve();
          return;
        }
        this.state.findings.push(findings[i]);
        this.state.hits_total = this.state.findings.length;
        this.state.files_scanned = Math.round((i + 1) / total * 100);
        this.updatePatternTotals();
        this.updateDashboard(); this.updateNav();
        i++;
      }, 400);
      this._demoScanInterval = interval;
    });
  },

  tour: {
    active: false,
    step: 0,
    _typeTimer: null,
    _typeResolve: null,
    _demoScanPromise: null,

    steps: [
      {
        target: '#scanBtnGroup',
        page: 'dashboard',
        position: 'right',
        title: 'The Scanner',
        text: "I'm Vee, your Secrets Agent. This is where it all starts — one click to scan your entire machine or pick a specific folder. Everything runs locally, nothing leaves your endpoint. Ever."
      },
      {
        target: '#scanBtnGroup',
        page: 'dashboard',
        position: 'right',
        title: 'Live Scanning',
        text: "Watch! I'm scanning now — you can see the files/second throughput and which folder I'm inspecting in real time. Our prefix-skip engine makes this blazingly fast.",
        beforeStep: async () => { App.tour._demoScanPromise = App.simulateDemoScan(); }
      },
      {
        target: null,
        page: 'dashboard',
        position: 'bottom',
        targetSelector: '.metrics',
        title: 'At a Glance',
        text: "Four metric cards, each with its own colour. Cyan for files scanned, rose for findings that need attention, violet for unique secrets, and green for pattern types detected. Colours mean the same thing everywhere in Vaultify.",
        beforeStep: async () => { if (App.tour._demoScanPromise) await App.tour._demoScanPromise; }
      },
      {
        target: null,
        page: 'dashboard',
        position: 'right',
        targetSelector: '.viz-row .viz-card:nth-child(2)',
        title: 'Entropy Scoring',
        text: "On the Review page, cyan numbers in the table are Shannon entropy — a measure of randomness. Real secrets score high (4.0+), code identifiers lower (below 3.0). I use a two-layer pipeline: variable names like api_key and password, then value patterns like AKIA or ghp_. When both layers agree, confidence is highest. Science, not guesswork."
      },
      {
        target: null,
        page: 'dashboard',
        position: 'right',
        targetSelector: '.viz-row .viz-card:nth-child(2)',
        title: 'Severity Breakdown',
        text: "This donut shows the severity split — red for critical, orange for high, amber for medium. These colours are reserved for severity only, so your brain always knows what's urgent."
      },
      {
        target: '#patternGraph',
        page: 'dashboard',
        position: 'top',
        targetParent: true,
        title: 'Pattern Graph',
        text: "This is the fun one! Each violet node is a pattern type, and the rose dots around it are individual findings. Bigger node means more findings. Hit Expand to see the full graph."
      },
      {
        target: '#findingsTree',
        page: 'dashboard',
        position: 'top',
        targetParent: true,
        title: 'Findings Explorer',
        text: "A file explorer for your secrets. Folders, files, and every finding with its pattern, preview, and line number. Collapse what you don't need, expand what matters."
      },
      {
        target: null,
        page: 'dashboard',
        position: 'right',
        targetSelector: '.pro-nav-item',
        title: 'Vee Pro',
        text: "See the golden crowns? That's Vee Pro — expanded pattern graph with zoom and inspect, CSV exports, shared reports, custom patterns, scheduled scans. Power tools for power users. If you want to come and meet me there, just click when you're ready. I'd love that!",
        avatar: '/assets/vee-pro.png',
        pro: true,
        beforeStep: async () => {
          document.querySelectorAll('.pro-nav-item').forEach(el => { el.classList.add('pro-blink'); });
        },
        afterStep: async () => {
          document.querySelectorAll('.pro-nav-item').forEach(el => { el.classList.remove('pro-blink'); });
        }
      },
      {
        target: null,
        page: 'dashboard',
        position: 'right',
        targetSelector: '.ent-nav-item',
        title: 'Vee Enterprise',
        text: "And the diamonds? That's me in a suit. Enterprise grade — Unified Fleet Dashboard, Compliance Evidence Collection, Policy Settings, centralised reporting. Built for organisations of 50 to 5,000. When you're ready for the big leagues, I'll be waiting.",
        avatar: '/assets/vee-enterprise.png',
        pro: true,
        beforeStep: async () => {
          document.querySelectorAll('.ent-nav-item').forEach(el => { el.classList.add('pro-blink'); });
        },
        afterStep: async () => {
          document.querySelectorAll('.ent-nav-item').forEach(el => { el.classList.remove('pro-blink'); });
        }
      },
      {
        target: null,
        page: 'dashboard',
        position: 'right',
        targetSelector: '.sidebar-bottom-dock .sidebar-nav-secondary',
        title: 'Walkthrough',
        text: "This is the same control you used to start me — it stays at the bottom of the sidebar so you can replay the tour anytime. Right below it is where you pick your vault provider.",
        beforeStep: async () => { document.querySelector('.sidebar-bottom-dock')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); await new Promise(r => setTimeout(r, 280)); }
      },
      {
        target: '#sidebarVaultSection',
        page: 'dashboard',
        position: 'right',
        title: 'Choose a Vault',
        text: "Choose a Vault sits under Walkthrough: four provider tiles in a two-by-two grid. Click a tile to set your sync focus for the app — 1Password is the default. Tiles show a quick shimmer while vault status loads. For 1Password, use the install link if needed, unlock the desktop app, enable CLI integration, then Open Vault on this tile. When you return to Vaultify, I recheck the session so the UI stays honest. Apply and Vee still use 1Password for vault operations until other backends arrive.",
        beforeStep: async () => { document.getElementById('sidebarVaultSection')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); await new Promise(r => setTimeout(r, 350)); }
      },
      {
        target: '#veePanel',
        page: 'dashboard',
        position: 'left',
        title: "Secrets Agent HQ",
        text: "This is my home! I'm Vee, your Secrets Agent. Connect an AI provider and I'll analyse your findings, flag false positives, and generate remediation summaries. API keys belong in 1Password — store them via Choose a Vault and the op session, same as Apply. Practice what we preach, yeah?"
      },
      {
        target: '#reviewContent',
        page: 'review',
        position: 'top',
        title: 'Review & Decide',
        text: "Notice the Entropy column — cyan numbers showing how random each secret is. CTX badges mean I found it by variable name, not just the value. When both layers agree you'll see a checkmark. High confidence gets auto-Vaultified, context-only stays pending for your review. Let me show you..."
      },
      {
        target: null,
        page: 'review',
        position: 'right',
        targetSelector: '#reviewContent table tbody tr:first-child',
        title: 'Expand a Finding',
        text: "I just expanded a row. Every file where this secret appears, the line number, and a code snippet — all redacted. We never show the real value, not even to you in the UI.",
        beforeStep: async () => {
          const firstRow = document.querySelector('#reviewContent table tbody tr:first-child');
          if (firstRow) firstRow.click();
          await new Promise(r => setTimeout(r, 300));
        }
      },
      {
        target: null,
        page: 'review',
        position: 'top',
        targetSelector: '#reviewContent table tbody tr:first-child td:last-child',
        title: 'Three Choices',
        text: "Lock icon for Vaultify — straight into 1Password. Trash to remove from code. Wastebasket for Junkyard (false positives excluded on the next scan). Watch me mark a few...",
        beforeStep: async () => {
          const firstRow = document.querySelector('#reviewContent table tbody tr:first-child');
          if (firstRow && firstRow.nextElementSibling && firstRow.nextElementSibling.style.display !== 'none') firstRow.click();
          await new Promise(r => setTimeout(r, 200));
        }
      },
      {
        target: '#reviewStats',
        page: 'review',
        position: 'bottom',
        title: 'Decisions Made!',
        text: "See the stats? 4 to Vaultify, 4 to remove, 2 to Junkyard. In a real workflow, you'd review each one. Some might be Good Practice — rotating credentials you don't need to Vaultify.",
        beforeStep: async () => {
          const groups = App.getGroups();
          const actions = ['vault','vault','vault','vault','remove','remove','remove','remove','graveyard','graveyard'];
          const toMark = groups.slice(0, Math.min(actions.length, groups.length));
          for (let i = 0; i < toMark.length; i++) {
            App.decisions[toMark[i].hash] = {
              action: actions[i],
              pattern_id: toMark[i].pattern_id,
              locations: toMark[i].locs.map(f => ({ full_path: f.full_path, relative_path: f.relative_path, line_number: f.line_number, match_sha256: f.match_sha256 }))
            };
            await new Promise(r => setTimeout(r, 150));
            App.renderReview();
          }
        }
      },
      {
        target: '#btnApply',
        page: 'review',
        position: 'bottom',
        title: 'Apply & Remediate',
        text: "Hit Apply Decisions — pick the 1Password vault, name your items, confirm. Stay signed in via the 1Password tile in Choose a Vault first. One confirmation: secrets move into 1Password, risky code gets redacted, dismissals are logged. Full audit trail."
      },
      {
        target: null,
        page: 'reports',
        position: 'top',
        targetSelector: '#reportsContent',
        title: 'Reports & Governance',
        text: "Every scan is tracked here. Remediation progress bars, archive for old sessions. This is your evidence trail for audits and due diligence."
      },
      {
        target: '#catalogueContent',
        page: 'catalogue',
        position: 'top',
        title: 'Secret Catalogue',
        text: "54 detection patterns and growing. AWS, GitHub, Slack, Stripe, 1Password, Dropbox, Figma, HubSpot — and 40 more. Search, filter, and patterns tagged NEW were added in this version.",
        beforeStep: async () => { await App.loadCatalogue(); }
      },
      {
        target: '#releaseNotes',
        page: 'version',
        position: 'top',
        title: 'Release Notes',
        text: "Every version, every change, right here. Security fixes, performance improvements, new patterns — full transparency. We ship fast and we ship often."
      }
    ],

    start() {
      this.active = true;
      this.step = 0;
      document.getElementById('tourWelcome').style.display = '';
    },

    beginSteps() {
      this.active = true;
      document.getElementById('tourWelcome').style.display = 'none';
      document.getElementById('tourBackdrop').style.display = '';
      document.getElementById('tourBubble').style.display = '';
      this.goToStep(0);
    },

    async goToStep(n) {
      this._clearTypewriter();
      if (n < 0 || n >= this.steps.length) { this.finish(); return; }
      this.step = n;
      const s = this.steps[n];

      if (this.step > 0 || n > 0) {
        const prev = this.steps[n > 0 ? n - 1 : 0];
        if (prev && prev.afterStep) await prev.afterStep();
      }

      if (s.page) App.navigate(s.page);
      await new Promise(r => setTimeout(r, 100));

      if (s.beforeStep) await s.beforeStep();
      await new Promise(r => setTimeout(r, 50));

      const targetEl = this._resolveTarget(s);
      this._positionSpotlight(targetEl);
      this._positionBubble(targetEl, s.position || 'right');

      document.getElementById('tourBubbleTitle').textContent = s.title || '';
      document.getElementById('tourCounter').textContent = `${n + 1} of ${this.steps.length}`;
      document.getElementById('tourBack').style.display = n === 0 ? 'none' : '';
      document.querySelector('.tour-bubble-avatar').src = s.avatar || '/assets/vee-avatar.png';
      const bubble = document.getElementById('tourBubble');
      bubble.classList.toggle('tour-bubble-pro', !!s.pro);

      const nextBtn = document.getElementById('tourNext');
      nextBtn.textContent = n === this.steps.length - 1 ? 'Finish' : 'Next';

      await this._typewrite(s.text);
    },

    _resolveTarget(s) {
      let el = null;
      if (s.target) el = document.querySelector(s.target);
      if (!el && s.targetSelector) el = document.querySelector(s.targetSelector);
      if (el && s.targetParent) el = el.closest('.card') || el.parentElement;
      return el;
    },

    _positionSpotlight(el) {
      const spot = document.getElementById('tourSpotlight');
      const fill = document.querySelector('.tour-backdrop-fill');
      if (!el) {
        spot.style.display = 'none';
        fill.style.background = 'rgba(0,0,0,.7)';
        return;
      }
      spot.style.display = '';
      fill.style.background = 'transparent';
      const r = el.getBoundingClientRect();
      const pad = 10;
      spot.style.top = (r.top - pad) + 'px';
      spot.style.left = (r.left - pad) + 'px';
      spot.style.width = (r.width + pad * 2) + 'px';
      spot.style.height = (r.height + pad * 2) + 'px';
    },

    _positionBubble(el, position) {
      const bubble = document.getElementById('tourBubble');
      bubble.style.display = '';
      if (!el) {
        bubble.style.top = '50%';
        bubble.style.left = '50%';
        bubble.style.transform = 'translate(-50%, -50%)';
        return;
      }
      bubble.style.transform = '';
      const r = el.getBoundingClientRect();
      const bw = 380;
      const bh = 220;
      const margin = 20;
      const maxTop = window.innerHeight - bh - 20;
      const clampTop = (v) => Math.max(20, Math.min(v, maxTop));
      switch (position) {
        case 'right':
          bubble.style.top = clampTop(r.top) + 'px';
          bubble.style.left = Math.min(r.right + margin, window.innerWidth - bw - 20) + 'px';
          break;
        case 'left':
          bubble.style.top = clampTop(r.top) + 'px';
          bubble.style.left = Math.max(20, r.left - bw - margin) + 'px';
          break;
        case 'bottom':
          bubble.style.top = clampTop(r.bottom + margin) + 'px';
          bubble.style.left = Math.max(20, Math.min(r.left, window.innerWidth - bw - 20)) + 'px';
          break;
        case 'top':
          bubble.style.top = clampTop(r.top - 200) + 'px';
          bubble.style.left = Math.max(20, Math.min(r.left, window.innerWidth - bw - 20)) + 'px';
          break;
      }
    },

    async _typewrite(text) {
      const el = document.getElementById('tourBubbleText');
      el.innerHTML = '<span class="tour-cursor"></span>';
      let i = 0;
      return new Promise(resolve => {
        this._typeResolve = resolve;
        const clickSkip = () => {
          if (i < text.length) {
            i = text.length;
            el.innerHTML = App.esc(text);
            el.removeEventListener('click', clickSkip);
            resolve();
            this._typeResolve = null;
          }
        };
        el.addEventListener('click', clickSkip);
        this._typeTimer = setInterval(() => {
          if (i >= text.length) {
            clearInterval(this._typeTimer);
            this._typeTimer = null;
            el.innerHTML = App.esc(text);
            el.removeEventListener('click', clickSkip);
            resolve();
            this._typeResolve = null;
            return;
          }
          i++;
          el.innerHTML = App.esc(text.slice(0, i)) + '<span class="tour-cursor"></span>';
        }, 30);
      });
    },

    _clearTypewriter() {
      if (this._typeTimer) { clearInterval(this._typeTimer); this._typeTimer = null; }
      if (this._typeResolve) { this._typeResolve(); this._typeResolve = null; }
    },

    next() {
      if (this.step >= this.steps.length - 1) { this.finish(); return; }
      this.goToStep(this.step + 1);
    },

    prev() {
      if (this.step > 0) this.goToStep(this.step - 1);
    },

    finish() {
      this._clearTypewriter();
      document.getElementById('tourBackdrop').style.display = 'none';
      document.getElementById('tourBubble').style.display = 'none';
      if (App._demoScanInterval) { clearInterval(App._demoScanInterval); App._demoScanInterval = null; }

      const overlay = document.getElementById('tourWelcome');
      overlay.style.display = '';
      overlay.innerHTML = `<div class="tour-finish-card">
        <img src="/assets/vee-avatar.png" class="tour-welcome-avatar" alt="Vee">
        <div class="tour-welcome-title">You're All Set!</div>
        <div class="tour-welcome-text">That's the tour! You're ready to secure your endpoint. Start a real scan whenever you're ready — I'll be right here if you need me.</div>
        <button class="btn-primary tour-welcome-start" onclick="App.tour.destroy()">Let's Go!</button>
      </div>`;
    },

    destroy() {
      this._clearTypewriter();
      this.active = false;
      this.step = 0;
      if (App._demoScanInterval) { clearInterval(App._demoScanInterval); App._demoScanInterval = null; }
      document.getElementById('tourWelcome').style.display = 'none';
      document.getElementById('tourBackdrop').style.display = 'none';
      document.getElementById('tourBubble').style.display = 'none';

      // Restore welcome modal HTML for next tour
      document.getElementById('tourWelcome').innerHTML = `<div class="tour-welcome-card">
        <img src="/assets/vee-avatar.png" class="tour-welcome-avatar" alt="Vee">
        <div class="tour-welcome-title">Welcome to Vaultify!</div>
        <div class="tour-welcome-text">Hello! I'm Vee, your tour guide. Let me walk you through how Vaultify finds, reviews, and remediates your plaintext secrets — all locally on your machine.</div>
        <button class="btn-primary tour-welcome-start" onclick="App.tour.beginSteps()">Start Tour</button>
        <button class="tour-welcome-skip" onclick="App.tour.destroy()">Maybe Later</button>
      </div>`;

      // Reset demo state
      App.state = { status: 'idle', dirs_visited: 0, candidates_queued: 0, files_scanned: 0, hits_total: 0, progress_denominator: 1, file_cap: 100000, pattern_totals: [], findings: [] };
      App.decisions = {};
      App._patternEls = {};
      App.updateDashboard(); App.updateButtons(); App.updateNav();
      App.navigate('dashboard');
    }
  }
};

document.addEventListener('DOMContentLoaded', () => App.init());
