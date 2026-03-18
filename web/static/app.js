/* AgentShield Web Scanner — Frontend Logic */
(function () {
  'use strict';

  // ── DOM references ───────────────────────────────────────────────
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const scanBtn = $('#scan-btn');
  const clearBtn = $('#clear-btn');
  const fileInput = $('#file-input');
  const contentEl = $('#skill-content');
  const nameEl = $('#skill-name');
  const frameworkEl = $('#framework');
  const resultsEl = $('#results');
  const errorBox = $('#error-box');
  const errorMsg = $('#error-message');
  const findingsList = $('#findings-list');
  const noFindings = $('#no-findings');
  const downloadJson = $('#download-json');
  const downloadSarif = $('#download-sarif');

  let lastResult = null;
  let lastContent = '';

  // ── Tab Navigation ───────────────────────────────────────────────
  $$('.nav-link').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const tab = link.dataset.tab;
      $$('.nav-link').forEach((l) => l.classList.remove('active'));
      link.classList.add('active');
      $$('.tab-content').forEach((t) => {
        t.hidden = t.id !== 'tab-' + tab;
      });
      if (tab === 'rules') loadRules();
    });
  });

  // ── Scan ─────────────────────────────────────────────────────────
  scanBtn.addEventListener('click', runScan);

  contentEl.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runScan();
    }
  });

  async function runScan() {
    const content = contentEl.value.trim();
    if (!content) {
      showError('Please paste skill content to scan.');
      return;
    }

    hideError();
    resultsEl.hidden = true;
    scanBtn.disabled = true;
    scanBtn.querySelector('.btn-text').hidden = true;
    scanBtn.querySelector('.btn-loading').hidden = false;

    const body = { content };
    if (nameEl.value.trim()) body.name = nameEl.value.trim();
    if (frameworkEl.value) body.framework = frameworkEl.value;

    try {
      const res = await fetch('/api/v1/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      lastResult = await res.json();
      lastContent = content;
      renderResults(lastResult);
    } catch (err) {
      showError(err.message);
    } finally {
      scanBtn.disabled = false;
      scanBtn.querySelector('.btn-text').hidden = false;
      scanBtn.querySelector('.btn-loading').hidden = true;
    }
  }

  // ── Render Results ───────────────────────────────────────────────
  function renderResults(data) {
    resultsEl.hidden = false;

    // Score circle
    const circle = $('#score-circle');
    const scoreVal = $('#score-value');
    scoreVal.textContent = data.score;

    const level = data.risk_level || 'Clean';
    circle.className = 'score-circle ' + level.toLowerCase();

    // Risk badge
    const badge = $('#risk-badge');
    badge.textContent = level;
    badge.className = 'risk-badge ' + level;

    // Skill name
    $('#skill-name-display').textContent = data.skill_name || '';
    $('#scan-time').textContent = data.scan_duration_ms != null
      ? `Scanned in ${data.scan_duration_ms}ms`
      : '';

    // Breakdown
    const bd = data.breakdown || {};
    setBreakdown('critical', bd.critical_count);
    setBreakdown('high', bd.high_count);
    setBreakdown('medium', bd.medium_count);
    setBreakdown('low', bd.low_count);
    setBreakdown('info', bd.info_count);

    // Findings
    findingsList.innerHTML = '';
    const findings = data.findings || [];

    if (findings.length === 0) {
      noFindings.hidden = false;
      findingsList.hidden = true;
    } else {
      noFindings.hidden = true;
      findingsList.hidden = false;

      // Sort: Critical > High > Medium > Low > Info
      const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
      findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));

      findings.forEach((f) => {
        const card = document.createElement('div');
        card.className = 'finding-card ' + (f.severity || '');
        card.innerHTML = `
          <div class="finding-header">
            <span class="finding-rule">${esc(f.rule_id)}</span>
            <span class="finding-title">${esc(f.title)}</span>
            <span class="severity-tag ${f.severity || ''}">${esc(f.severity)}</span>
          </div>
          <div class="finding-desc">${esc(f.description)}</div>
          ${f.evidence ? `<div class="finding-evidence">${esc(f.evidence)}</div>` : ''}
          ${f.line ? `<div class="finding-line">Line ${f.line}</div>` : ''}
          ${f.remediation ? `<div class="finding-remediation">${esc(f.remediation)}</div>` : ''}
        `;
        findingsList.appendChild(card);
      });
    }

    resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function setBreakdown(level, count) {
    const el = $(`#bc-${level}`);
    if (el) el.querySelector('.breakdown-count').textContent = count || 0;
  }

  // ── Downloads ────────────────────────────────────────────────────
  downloadJson.addEventListener('click', () => {
    if (!lastResult) return;
    downloadFile('agentshield-report.json', JSON.stringify(lastResult, null, 2), 'application/json');
  });

  downloadSarif.addEventListener('click', async () => {
    if (!lastContent) return;

    const body = { content: lastContent, format: 'sarif' };
    if (nameEl.value.trim()) body.name = nameEl.value.trim();
    if (frameworkEl.value) body.framework = frameworkEl.value;

    try {
      const res = await fetch('/api/v1/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const text = await res.text();
      downloadFile('agentshield-report.sarif', text, 'application/sarif+json');
    } catch (err) {
      showError('Failed to generate SARIF: ' + err.message);
    }
  });

  function downloadFile(name, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ── Clear ────────────────────────────────────────────────────────
  clearBtn.addEventListener('click', () => {
    contentEl.value = '';
    nameEl.value = '';
    frameworkEl.value = '';
    resultsEl.hidden = true;
    hideError();
    lastResult = null;
    lastContent = '';
    contentEl.focus();
  });

  // ── File Upload ──────────────────────────────────────────────────
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      contentEl.value = reader.result;
      // Auto-set name from filename
      if (!nameEl.value) {
        nameEl.value = file.name.replace(/\.[^.]+$/, '');
      }
      // Auto-detect framework from extension
      if (!frameworkEl.value) {
        if (file.name.endsWith('.py')) frameworkEl.value = 'langchain';
        else if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) frameworkEl.value = 'dify';
        else if (file.name.endsWith('.md')) frameworkEl.value = 'openclaw';
      }
    };
    reader.readAsText(file);
    fileInput.value = '';
  });

  // ── Rules Tab ────────────────────────────────────────────────────
  let rulesLoaded = false;

  async function loadRules() {
    if (rulesLoaded) return;

    const list = $('#rules-list');
    try {
      const res = await fetch('/api/v1/rules');
      const rules = await res.json();
      rulesLoaded = true;

      list.innerHTML = '';
      rules.forEach((r) => {
        const card = document.createElement('div');
        card.className = 'rule-card';

        const severityClass = r.severity || '';
        card.innerHTML = `
          <div>
            <div class="rule-id">${esc(r.id)}</div>
            <div class="rule-category">${esc(r.category)}</div>
          </div>
          <div class="rule-severity severity-tag ${severityClass}">${esc(r.severity)}</div>
          <div class="rule-desc">${esc(r.description)}</div>
        `;
        list.appendChild(card);
      });
    } catch (err) {
      list.innerHTML = `<p class="error-box">Failed to load rules: ${esc(err.message)}</p>`;
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────
  function showError(msg) {
    errorBox.hidden = false;
    errorMsg.textContent = msg;
  }

  function hideError() {
    errorBox.hidden = true;
  }

  function esc(str) {
    if (!str) return '';
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
  }

  // ── Keyboard shortcut hint ───────────────────────────────────────
  contentEl.title = 'Ctrl+Enter to scan';
})();
