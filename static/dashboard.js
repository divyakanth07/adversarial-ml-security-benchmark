/**
 * dashboard.js — Adversarial ML Toolkit frontend logic (v2)
 *
 * Responsibilities:
 *  • Fetch benchmark results from /api/results on load
 *  • Render five Plotly charts:
 *      1. 3×5 heatmap    — evasion rates (RdYlGn_r, red=high risk)
 *      2. Grouped bar    — original vs post-attack accuracy per model
 *      3. Line chart     — confidence delta across attack types
 *      4. Sweep line     — evasion rate vs epsilon
 *      5. Defense bar    — before/after adversarial training
 *      6. History trend  — evasion rate across benchmark runs
 *  • POST to /api/run-benchmark with selected model/attack/epsilon
 *  • Threat scenario presets via GET /api/profiles
 *  • Domain-realistic feature constraints via GET /api/constraints
 *  • Epsilon sweep via POST /api/epsilon-sweep
 *  • Adversarial training defense via POST /api/defend
 *  • Run history via GET /api/history
 *  • GET /api/generate-report → redirect to /report
 */

'use strict';

// --------------------------------------------------------------------------
// Constants  (5 attacks now)
// --------------------------------------------------------------------------
const MODELS  = ['malware', 'ids', 'phishing'];
const ATTACKS = ['fgsm', 'hopskipjump', 'zoo', 'cw', 'deepfool'];
const ATTACK_LABELS = {
  fgsm:        'FGSM',
  hopskipjump: 'HopSkipJump',
  zoo:         'ZooAttack',
  cw:          'C&W L2',
  deepfool:    'DeepFool',
};
const MODEL_LABELS = { malware: 'Malware', ids: 'IDS', phishing: 'Phishing' };

const PLOTLY_LAYOUT_BASE = {
  paper_bgcolor: 'rgba(0,0,0,0)',
  plot_bgcolor:  'rgba(0,0,0,0)',
  font: { color: '#94a3b8', size: 11, family: 'Segoe UI, sans-serif' },
  margin: { t: 20, b: 50, l: 60, r: 20 },
};

// Active scenario profile key ('custom' by default)
let _activeProfile = 'custom';

// --------------------------------------------------------------------------
// DOM helpers
// --------------------------------------------------------------------------
const $ = id => document.getElementById(id);

// --------------------------------------------------------------------------
// Progress polling state
// --------------------------------------------------------------------------
let _progressPoller = null;

function formatDuration(s) {
  if (s === null || s === undefined || s < 0) return '…';
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = (s % 60).toString().padStart(2, '0');
  if (m < 60) return `${m}m ${rem}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

function _startProgressPolling() {
  _stopProgressPolling();
  _progressPoller = setInterval(async () => {
    try {
      const res = await fetch('/api/progress');
      const p   = await res.json();
      const done  = p.done  ?? 0;
      const total = p.total ?? 1;

      const nowSec     = Date.now() / 1000;
      const elapsedSec = p.started_at ? (nowSec - p.started_at) : (p.elapsed_s || 0);
      const etaSec = (done > 0 && elapsedSec > 0)
        ? (elapsedSec / done) * (total - done)
        : null;

      const elapsedStr = `Elapsed ${formatDuration(elapsedSec)}`;
      const etaStr     = etaSec != null ? `ETA ~${formatDuration(etaSec)}` : 'Calculating…';
      const label      = p.current_label || '';

      showStatus(
        `⏱ [${done}/${total}]  ${label}  ·  ${elapsedStr}  ·  ${etaStr}`,
        'loading'
      );

      if (p.status === 'done' || p.status === 'idle') {
        _stopProgressPolling();
      }
    } catch (_) { /* silently ignore poll errors */ }
  }, 2000);
}

function _stopProgressPolling() {
  if (_progressPoller) { clearInterval(_progressPoller); _progressPoller = null; }
}

function showStatus(msg, type = '') {
  const bar = $('statusBar');
  bar.innerHTML = (type === 'loading'
    ? `<span class="spinner"></span>${msg}`
    : msg);
  bar.style.display = 'block';
  bar.className = type;
  if (type !== 'loading') {
    setTimeout(() => { bar.style.display = 'none'; }, 6000);
  }
}
function hideStatus() { $('statusBar').style.display = 'none'; }

// --------------------------------------------------------------------------
// Data extraction helpers
// --------------------------------------------------------------------------
function getMetric(results, model, attack, key) {
  const entry = results?.[model]?.[attack];
  if (!entry || entry.error) return null;
  const v = entry[key];
  return (typeof v === 'number') ? v : null;
}

function riskLabel(er) {
  if (er === null) return { text: 'N/A', cls: '' };
  if (er > 0.50)   return { text: '🔴 CRITICAL', cls: 'risk-critical' };
  if (er > 0.20)   return { text: '🟡 HIGH',     cls: 'risk-high' };
  return               { text: '🟢 MODERATE',  cls: 'risk-moderate' };
}

function fmt(v, pct = false) {
  if (v === null || v === undefined) return '—';
  return pct ? (v * 100).toFixed(1) + '%' : v.toFixed(4);
}

function fmtInt(v) {
  if (v === null || v === undefined) return '—';
  return Number(v).toLocaleString();
}

// --------------------------------------------------------------------------
// Summary cards  (now iterates over all 5 attacks)
// --------------------------------------------------------------------------
function updateCards(results) {
  if (!results || !Object.keys(results).length) {
    ['cardModels','cardAttacks','cardMaxEvasion','cardRiskPair'].forEach(id => { $(id).textContent = '—'; });
    return;
  }

  let modelsEvaluated = 0, attacksRun = new Set();
  let maxEvasion = -Infinity, maxPair = '—';

  for (const m of MODELS) {
    if (!results[m]) continue;
    let hasAny = false;
    for (const a of ATTACKS) {
      const er = getMetric(results, m, a, 'evasion_rate');
      if (er !== null) {
        hasAny = true;
        attacksRun.add(a);
        if (er > maxEvasion) { maxEvasion = er; maxPair = `${MODEL_LABELS[m]} + ${ATTACK_LABELS[a]}`; }
      }
    }
    if (hasAny) modelsEvaluated++;
  }

  $('cardModels').textContent  = modelsEvaluated || '—';
  $('cardAttacks').textContent = attacksRun.size || '—';

  if (maxEvasion === -Infinity) {
    $('cardMaxEvasion').textContent = '—';
    $('cardMaxEvasion').className = 'value neutral';
    $('cardRiskPair').textContent = '—';
  } else {
    $('cardMaxEvasion').textContent = (maxEvasion * 100).toFixed(1) + '%';
    $('cardMaxEvasion').className = 'value ' + (maxEvasion > .5 ? 'critical' : maxEvasion > .2 ? 'high' : 'moderate');
    $('cardRiskPair').textContent = maxPair;
  }
}

// --------------------------------------------------------------------------
// Results table  (10 columns: added Est. Queries)
// --------------------------------------------------------------------------
function renderTable(results) {
  const tbody = $('resultsBody');
  const rows = [];

  for (const m of MODELS) {
    for (const a of ATTACKS) {
      const entry = results?.[m]?.[a];
      if (!entry || typeof entry !== 'object') continue;
      if (entry.error) {
        rows.push(`<tr><td>${MODEL_LABELS[m] || m}</td><td>${ATTACK_LABELS[a] || a}</td>
          <td colspan="8" style="color:var(--danger)">${entry.error}</td></tr>`);
        continue;
      }
      const er = entry.evasion_rate;
      const risk = riskLabel(typeof er === 'number' ? er : null);
      rows.push(`<tr>
        <td>${MODEL_LABELS[m] || m}</td>
        <td>${ATTACK_LABELS[a] || a}</td>
        <td>${fmt(entry.original_accuracy)}</td>
        <td>${fmt(entry.post_attack_accuracy)}</td>
        <td>${fmt(er, true)}</td>
        <td>${fmt(entry.confidence_delta)}</td>
        <td>${entry.epsilon != null ? entry.epsilon : '—'}</td>
        <td>${entry.n_samples ?? '—'}</td>
        <td>${fmtInt(entry.n_queries)}</td>
        <td class="${risk.cls}">${risk.text}</td>
      </tr>`);
    }
  }

  tbody.innerHTML = rows.length
    ? rows.join('')
    : '<tr><td colspan="10" style="color:var(--muted);text-align:center;padding:20px">No results yet — run a benchmark above.</td></tr>';
}

// --------------------------------------------------------------------------
// Heatmap — 3×5 evasion rates (models × attacks)
// --------------------------------------------------------------------------
function renderHeatmap(results) {
  const attacksWithData = ATTACKS.filter(a =>
    MODELS.some(m => getMetric(results, m, a, 'evasion_rate') !== null)
  );
  const cols = attacksWithData.length > 0 ? attacksWithData : ATTACKS;

  const z = MODELS.map(m =>
    cols.map(a => {
      const v = getMetric(results, m, a, 'evasion_rate');
      return v !== null ? +(v * 100).toFixed(2) : null;
    })
  );

  const xLabels = cols.map(a => ATTACK_LABELS[a] || a);
  const yLabels = MODELS.map(m => MODEL_LABELS[m]);
  const hasData = z.some(row => row.some(v => v !== null));

  const emptyZ = MODELS.map(() => cols.map(() => 0));

  Plotly.newPlot('heatmapDiv', [{
    type: 'heatmap',
    x: xLabels,
    y: yLabels,
    z: hasData ? z : emptyZ,
    colorscale: 'RdYlGn',
    reversescale: true,
    zmin: 0,
    zmax: 100,
    colorbar: {
      title: { text: 'Evasion %', side: 'right' },
      tickfont: { color: '#94a3b8' },
      titlefont: { color: '#94a3b8' },
    },
    text: hasData ? z.map(row => row.map(v => v !== null ? v.toFixed(1) + '%' : 'N/A')) : null,
    texttemplate: hasData ? '%{text}' : '',
    hovertemplate: 'Model: %{y}<br>Attack: %{x}<br>Evasion: %{z:.1f}%<extra></extra>',
  }], {
    ...PLOTLY_LAYOUT_BASE,
    xaxis: { color: '#94a3b8' },
    yaxis: { color: '#94a3b8' },
  }, { responsive: true, displayModeBar: false });
}

// --------------------------------------------------------------------------
// Grouped bar chart — original vs post-attack accuracy  (all 5 attacks)
// --------------------------------------------------------------------------
function renderBarChart(results) {
  const modelLabels = MODELS.map(m => MODEL_LABELS[m]);
  const traces = [];

  const origAcc = MODELS.map(m => {
    for (const a of ATTACKS) {
      const v = getMetric(results, m, a, 'original_accuracy');
      if (v !== null) return +(v * 100).toFixed(2);
    }
    return null;
  });

  traces.push({
    type: 'bar',
    name: 'Original Accuracy',
    x: modelLabels,
    y: origAcc,
    marker: { color: '#38bdf8' },
    hovertemplate: '%{x}<br>Original: %{y:.1f}%<extra></extra>',
  });

  for (const a of ATTACKS) {
    const postAcc = MODELS.map(m => {
      const v = getMetric(results, m, a, 'post_attack_accuracy');
      return v !== null ? +(v * 100).toFixed(2) : null;
    });
    if (postAcc.some(v => v !== null)) {
      traces.push({
        type: 'bar',
        name: `Post-${ATTACK_LABELS[a]}`,
        x: modelLabels,
        y: postAcc,
        hovertemplate: `%{x}<br>Post-${ATTACK_LABELS[a]}: %{y:.1f}%<extra></extra>`,
      });
    }
  }

  Plotly.newPlot('barChartDiv', traces, {
    ...PLOTLY_LAYOUT_BASE,
    barmode: 'group',
    legend: { orientation: 'h', y: -0.25, font: { color: '#94a3b8' } },
    yaxis: { title: 'Accuracy (%)', color: '#94a3b8', range: [0, 100], gridcolor: '#1e293b' },
    xaxis: { color: '#94a3b8' },
  }, { responsive: true, displayModeBar: false });
}

// --------------------------------------------------------------------------
// Line chart — confidence delta  (all 5 attacks)
// --------------------------------------------------------------------------
function renderLineChart(results) {
  const modelLabels = MODELS.map(m => MODEL_LABELS[m]);
  const traces = ATTACKS
    .filter(a => MODELS.some(m => getMetric(results, m, a, 'confidence_delta') !== null))
    .map(a => ({
      type: 'scatter',
      mode: 'lines+markers',
      name: ATTACK_LABELS[a],
      x: modelLabels,
      y: MODELS.map(m => {
        const v = getMetric(results, m, a, 'confidence_delta');
        return v !== null ? +v.toFixed(4) : null;
      }),
      marker: { size: 8 },
      hovertemplate: `%{x}<br>${ATTACK_LABELS[a]} Δ: %{y:.4f}<extra></extra>`,
    }));

  if (!traces.length) {
    traces.push({ type: 'scatter', mode: 'lines+markers', name: 'No data', x: modelLabels, y: [null, null, null] });
  }

  Plotly.newPlot('lineChartDiv', traces, {
    ...PLOTLY_LAYOUT_BASE,
    legend: { font: { color: '#94a3b8' } },
    yaxis: { title: 'Confidence Δ', color: '#94a3b8', gridcolor: '#1e293b' },
    xaxis: { color: '#94a3b8' },
  }, { responsive: true, displayModeBar: false });
}

// --------------------------------------------------------------------------
// Main render pipeline
// --------------------------------------------------------------------------
function renderAll(results) {
  updateCards(results);
  renderTable(results);
  renderHeatmap(results);
  renderBarChart(results);
  renderLineChart(results);
}

// --------------------------------------------------------------------------
// Scenario / Profile loader
// --------------------------------------------------------------------------
async function loadProfiles() {
  try {
    const res  = await fetch('/api/profiles');
    const data = await res.json();
    const profiles = data.profiles || {};
    const bar = document.querySelector('.scenario-bar');

    // Remove previously injected API buttons (keep the Custom button)
    bar.querySelectorAll('.scenario-btn[data-api]').forEach(b => b.remove());

    for (const [key, prof] of Object.entries(profiles)) {
      if (key === 'custom') continue; // already in HTML
      const btn = document.createElement('button');
      btn.className = 'scenario-btn';
      btn.dataset.profile = key;
      btn.dataset.api = '1';
      btn.textContent = prof.label || key;
      btn.title = prof.description || '';
      btn.addEventListener('click', () => _applyProfile(key, prof));
      bar.appendChild(btn);
    }

    // Wire the built-in Custom button
    const customBtn = bar.querySelector('[data-profile="custom"]');
    if (customBtn) {
      customBtn.addEventListener('click', () => _applyProfile('custom', { description: 'Manual configuration — choose model, attack, and ε yourself.' }));
    }
  } catch (_) { /* profiles are optional */ }
}

function _applyProfile(key, prof) {
  _activeProfile = key;

  // Update active button styling
  document.querySelectorAll('.scenario-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.profile === key);
  });

  // Update description
  $('scenarioDesc').textContent = prof.description || '';

  // Auto-fill controls if profile specifies them
  if (prof.model  && $('modelSel'))   $('modelSel').value   = prof.model;
  if (prof.attack && $('attackSel'))  $('attackSel').value  = prof.attack;
  if (prof.epsilon != null && $('epsilonInp')) $('epsilonInp').value = prof.epsilon;
}

// --------------------------------------------------------------------------
// Constraint info band
// --------------------------------------------------------------------------
async function handleConstraintToggle() {
  const chk  = $('constraintChk');
  const band = $('constraintInfo');
  const lbl  = $('constraintToggle');

  if (!chk.checked) {
    band.classList.remove('visible');
    lbl && lbl.classList.remove('active');
    return;
  }

  lbl && lbl.classList.add('active');

  const model = $('modelSel').value;
  if (!model || model === 'all') {
    band.innerHTML = '<strong>⛓ Constraints active</strong> — select a specific model to see feature details.';
    band.classList.add('visible');
    return;
  }

  try {
    const res  = await fetch(`/api/constraints?model=${encodeURIComponent(model)}`);
    const data = await res.json();
    if (data.error) { band.textContent = data.error; band.classList.add('visible'); return; }

    band.innerHTML = `
      <strong>⛓ Realistic Constraints ON</strong> — ${model} model&nbsp;
      <span style="color:var(--success)">(${data.n_mutable} mutable features, ${data.pct_mutable}%)</span>
      &nbsp;·&nbsp;
      <span style="color:var(--danger)">${data.n_immutable} immutable</span><br>
      <span style="font-size:.72rem">
        ✅ <strong>Can perturb:</strong> ${data.mutable_desc || '—'}&nbsp;&nbsp;
        ⛔ <strong>Fixed:</strong> ${data.immutable_desc || '—'}<br>
        <em>${data.rationale || ''}</em>
      </span>`;
    band.classList.add('visible');
  } catch (err) {
    band.textContent = 'Could not load constraint info.';
    band.classList.add('visible');
  }
}

// --------------------------------------------------------------------------
// Epsilon Sweep
// --------------------------------------------------------------------------
async function runSweep() {
  const model  = $('sweepModelSel').value;
  const attack = $('sweepAttackSel').value;
  const epsRaw = $('sweepEpsInp').value;
  const epsList = epsRaw.split(',').map(s => parseFloat(s.trim())).filter(v => !isNaN(v) && v > 0);

  if (!epsList.length) { showStatus('Enter at least one valid ε value.', 'error'); return; }

  const btn = $('sweepBtn');
  btn.disabled = true;
  showStatus('Running epsilon sweep… (this may take a few minutes)', 'loading');

  try {
    const res  = await fetch('/api/epsilon-sweep', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, attack, eps_values: epsList }),
    });
    const data = await res.json();
    hideStatus();

    if (data.error) { showStatus('Sweep failed: ' + data.error, 'error'); return; }

    _renderSweepChart(data.sweep || {}, attack);
    showStatus('✓ Epsilon sweep complete.', 'success');
  } catch (err) {
    hideStatus();
    showStatus('Sweep request failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

function _renderSweepChart(sweep, attack) {
  // sweep shape: { model_name: [ {epsilon, evasion_rate, post_attack_accuracy}, ... ] }
  const traces = [];
  const colors = { malware: '#f87171', ids: '#38bdf8', phishing: '#a78bfa' };

  for (const [modelKey, pts] of Object.entries(sweep)) {
    if (!Array.isArray(pts) || !pts.length) continue;
    const sorted = [...pts].sort((a, b) => a.epsilon - b.epsilon);
    traces.push({
      type: 'scatter',
      mode: 'lines+markers',
      name: MODEL_LABELS[modelKey] || modelKey,
      x: sorted.map(p => p.epsilon),
      y: sorted.map(p => (p.evasion_rate ?? 0) * 100),
      marker: { size: 8, color: colors[modelKey] || '#94a3b8' },
      line: { color: colors[modelKey] || '#94a3b8' },
      hovertemplate: `ε=%{x:.3f}<br>Evasion: %{y:.1f}%<extra>${MODEL_LABELS[modelKey] || modelKey}</extra>`,
    });
  }

  if (!traces.length) {
    $('sweepChartDiv').innerHTML = '<p style="color:var(--muted);padding:20px">No sweep data returned.</p>';
    return;
  }

  Plotly.newPlot('sweepChartDiv', traces, {
    ...PLOTLY_LAYOUT_BASE,
    legend: { font: { color: '#94a3b8' } },
    xaxis: { title: 'Epsilon (ε)', color: '#94a3b8', gridcolor: '#1e293b' },
    yaxis: { title: 'Evasion Rate (%)', color: '#94a3b8', gridcolor: '#1e293b', range: [0, 100] },
    title: { text: `${ATTACK_LABELS[attack] || attack} — Evasion Rate vs ε`, font: { color: '#94a3b8', size: 13 } },
  }, { responsive: true, displayModeBar: false });
}

// --------------------------------------------------------------------------
// Adversarial Training Defense
// --------------------------------------------------------------------------
async function applyDefense() {
  const model  = $('defModelSel').value;
  const attack = $('defAttackSel').value;
  const eps    = parseFloat($('defEpsInp').value) || 0.05;
  const ratio  = parseFloat($('defRatioInp').value) || 0.3;

  const btn = $('defendBtn');
  btn.disabled = true;
  $('defenseComparison').style.display = 'none';
  showStatus('Applying adversarial training defense… (this may take several minutes)', 'loading');

  try {
    const res  = await fetch('/api/defend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, attack, eps, augment_ratio: ratio }),
    });
    const data = await res.json();
    hideStatus();

    if (data.error) { showStatus('Defense failed: ' + data.error, 'error'); return; }

    _renderDefenseComparison(data, model, attack);
    showStatus('✓ Adversarial training complete.', 'success');
  } catch (err) {
    hideStatus();
    showStatus('Defense request failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

function _renderDefenseComparison(data, model, attack) {
  const before = data.before || {};
  const after  = data.after  || {};
  const imp    = data.improvement || {};

  const bER  = before.evasion_rate   ?? null;
  const aER  = after.evasion_rate    ?? null;
  const bAcc = before.post_attack_accuracy ?? null;
  const aAcc = after.post_attack_accuracy  ?? null;
  const erDelta  = imp.evasion_rate ?? (aER  !== null && bER  !== null ? aER  - bER  : null);
  const accDelta = imp.post_attack_accuracy ?? (aAcc !== null && bAcc !== null ? aAcc - bAcc : null);

  const pct = v => v !== null ? (v * 100).toFixed(1) + '%' : '—';
  const dlt = (v, invert = false) => {
    if (v === null) return '';
    const good = invert ? v < 0 : v > 0;
    const sign = v > 0 ? '+' : '';
    return `<span class="${good ? 'cmp-delta' : 'cmp-bad'}">${sign}${(v * 100).toFixed(1)}%</span>`;
  };

  const grid = $('defenseComparison');
  grid.innerHTML = `
    <div class="cmp-card">
      <div class="cmp-label">Evasion Rate</div>
      <span class="cmp-before">${pct(bER)}</span>
      <span class="cmp-arrow">→</span>
      <span class="cmp-after">${pct(aER)}</span>
      <div>${dlt(erDelta, true)} change after adversarial training</div>
    </div>
    <div class="cmp-card">
      <div class="cmp-label">Post-Attack Accuracy</div>
      <span class="cmp-before" style="color:var(--warn)">${pct(bAcc)}</span>
      <span class="cmp-arrow">→</span>
      <span class="cmp-after">${pct(aAcc)}</span>
      <div>${dlt(accDelta)} change after adversarial training</div>
    </div>
    <div class="cmp-card">
      <div class="cmp-label">Original Accuracy (clean)</div>
      <span style="font-size:1.3rem;font-weight:700;color:var(--accent)">${pct(before.original_accuracy ?? null)}</span>
      <div style="font-size:.72rem;margin-top:4px;color:var(--muted)">
        ${MODEL_LABELS[model] || model} + ${ATTACK_LABELS[attack] || attack}<br>
        Augment ratio: ${($('defRatioInp').value * 100).toFixed(0)}% of training set
      </div>
    </div>`;
  grid.style.display = 'grid';

  // Defense bar chart
  const barTraces = [
    { name: 'Before', values: [bER, bAcc], color: '#f87171' },
    { name: 'After',  values: [aER, aAcc], color: '#4ade80' },
  ].map(t => ({
    type: 'bar',
    name: t.name,
    x: ['Evasion Rate', 'Post-Attack Accuracy'],
    y: t.values.map(v => v !== null ? +(v * 100).toFixed(2) : null),
    marker: { color: t.color },
    hovertemplate: `%{x}<br>${t.name}: %{y:.1f}%<extra></extra>`,
  }));

  Plotly.newPlot('defenseChartDiv', barTraces, {
    ...PLOTLY_LAYOUT_BASE,
    barmode: 'group',
    legend: { font: { color: '#94a3b8' } },
    yaxis: { title: 'Rate / Accuracy (%)', color: '#94a3b8', gridcolor: '#1e293b', range: [0, 100] },
    xaxis: { color: '#94a3b8' },
    title: { text: `Defense Results — ${MODEL_LABELS[model] || model}`, font: { color: '#94a3b8', size: 13 } },
  }, { responsive: true, displayModeBar: false });
}

// --------------------------------------------------------------------------
// Run History
// --------------------------------------------------------------------------
async function loadHistory() {
  try {
    const res  = await fetch('/api/history');
    const data = await res.json();
    const hist = data.history || [];
    _renderHistory(hist);
  } catch (_) {
    $('historySummary').innerHTML = '<span class="h-pill">No history yet</span>';
  }
}

function _renderHistory(hist) {
  const summaryEl = $('historySummary');
  const chartEl   = $('historyChartDiv');

  if (!hist.length) {
    summaryEl.innerHTML = '<span class="h-pill">No runs recorded yet</span>';
    chartEl.innerHTML   = '<p style="color:var(--muted);padding:20px;font-size:.82rem">Run benchmarks to see history here.</p>';
    return;
  }

  // Summary pills — last 5 runs condensed
  const recent = hist.slice(-5).reverse();
  summaryEl.innerHTML = recent.map(r => {
    const er = r.evasion_rate != null ? (r.evasion_rate * 100).toFixed(1) + '%' : '—';
    const riskColor = r.evasion_rate > 0.5 ? 'var(--danger)' : r.evasion_rate > 0.2 ? 'var(--warn)' : 'var(--success)';
    const ts = r.timestamp ? new Date(r.timestamp).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '?';
    return `<span class="h-pill" title="${ts}">
      ${MODEL_LABELS[r.model] || r.model} / ${ATTACK_LABELS[r.attack] || r.attack}
      &nbsp;<span style="color:${riskColor};font-weight:700">${er}</span>
    </span>`;
  }).join('');

  // Group by model+attack for trend lines
  const seriesMap = {};
  for (const r of hist) {
    const key = `${r.model}/${r.attack}`;
    if (!seriesMap[key]) seriesMap[key] = { xs: [], ys: [], model: r.model, attack: r.attack };
    const ts = r.timestamp ? new Date(r.timestamp) : null;
    seriesMap[key].xs.push(ts ? ts.toISOString() : seriesMap[key].xs.length.toString());
    seriesMap[key].ys.push(r.evasion_rate != null ? +(r.evasion_rate * 100).toFixed(2) : null);
  }

  const traces = Object.entries(seriesMap).map(([key, s]) => ({
    type: 'scatter',
    mode: 'lines+markers',
    name: `${MODEL_LABELS[s.model] || s.model} / ${ATTACK_LABELS[s.attack] || s.attack}`,
    x: s.xs,
    y: s.ys,
    marker: { size: 7 },
    hovertemplate: `Run: %{x}<br>Evasion: %{y:.1f}%<extra></extra>`,
  }));

  Plotly.newPlot('historyChartDiv', traces, {
    ...PLOTLY_LAYOUT_BASE,
    legend: { font: { color: '#94a3b8' }, orientation: 'h', y: -0.3 },
    xaxis: { color: '#94a3b8', type: 'category', title: 'Run', tickangle: -30 },
    yaxis: { title: 'Evasion Rate (%)', color: '#94a3b8', gridcolor: '#1e293b', range: [0, 100] },
  }, { responsive: true, displayModeBar: false });
}

// --------------------------------------------------------------------------
// API calls — main benchmark
// --------------------------------------------------------------------------
async function fetchResults() {
  showStatus('Loading benchmark results …', 'loading');
  try {
    const res = await fetch('/api/results');
    const data = await res.json();
    if (data.error) { showStatus('⚠ ' + data.error, 'error'); return; }
    hideStatus();
    renderAll(data.results || {});
  } catch (err) {
    showStatus('Failed to fetch results: ' + err.message, 'error');
  }
}

async function runBenchmark() {
  const model          = $('modelSel').value;
  const attack         = $('attackSel').value;
  const epsilon        = parseFloat($('epsilonInp').value) || 0.05;
  const use_constraints = $('constraintChk').checked;

  $('runBtn').disabled = true;
  showStatus('⏱ [0/?]  Initialising benchmark…', 'loading');
  _startProgressPolling();

  try {
    const res = await fetch('/api/run-benchmark', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, attack, epsilon, use_constraints, profile: _activeProfile,
                             session_id: _currentSessionId }),
    });
    const data = await res.json();
    _stopProgressPolling();

    if (data.error) {
      showStatus('✗ Benchmark failed: ' + data.error, 'error');
    } else {
      const sid = data.session_id || null;
      _currentSessionId = sid;
      _updateSessionBar(sid);
      // Update URL so the current run is shareable immediately
      if (sid) {
        const url = new URL(window.location.href);
        url.searchParams.set('session', sid);
        window.history.replaceState({}, '', url.toString());
      }
      showStatus('✓ Benchmark completed. Session: ' + (sid || '—'), 'success');
      renderAll(data.results || {});
      // Refresh history in background
      loadHistory();
    }
  } catch (err) {
    _stopProgressPolling();
    showStatus('✗ Request failed: ' + err.message, 'error');
  } finally {
    $('runBtn').disabled = false;
  }
}

async function generateReport() {
  $('reportBtn').disabled = true;
  $('reportOutput').innerHTML = '<span class="spinner"></span> Generating report…';
  showStatus('Generating AI threat analysis…', 'loading');
  try {
    const res  = await fetch('/api/generate-report');
    const data = await res.json();
    if (data.error) {
      hideStatus();
      $('reportOutput').textContent = 'Error: ' + data.error;
      $('reportBtn').disabled = false;
    } else {
      // Redirect to the dedicated report page
      window.location.href = '/report';
    }
  } catch (err) {
    hideStatus();
    $('reportOutput').textContent = 'Request failed: ' + err.message;
    $('reportBtn').disabled = false;
  }
}

// --------------------------------------------------------------------------
// Event listeners
// --------------------------------------------------------------------------
$('runBtn').addEventListener('click', runBenchmark);
$('refreshBtn').addEventListener('click', fetchResults);
$('reportBtn').addEventListener('click', generateReport);
$('sweepBtn').addEventListener('click', runSweep);
$('defendBtn').addEventListener('click', applyDefense);
$('constraintChk').addEventListener('change', handleConstraintToggle);
$('vtUrlBtn').addEventListener('click', vtScanUrl);
$('vtHashBtn').addEventListener('click', vtLookupHash);
$('hfClassifyBtn').addEventListener('click', hfClassify);
$('hfEvasionBtn').addEventListener('click', hfEvasion);

// Also re-fetch constraint info if model changes while constraint checkbox is active
$('modelSel').addEventListener('change', () => {
  if ($('constraintChk').checked) handleConstraintToggle();
});

// --------------------------------------------------------------------------
// Real-World Targets — tab switcher
// --------------------------------------------------------------------------
document.querySelectorAll('.rw-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const key = tab.dataset.rwtab;
    document.querySelectorAll('.rw-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.rw-tab-panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    const panel = document.getElementById(`rwPanel-${key}`);
    if (panel) panel.classList.add('active');
  });
});

// --------------------------------------------------------------------------
// VirusTotal
// --------------------------------------------------------------------------
function _vtRiskClass(risk) {
  return risk === 'CRITICAL' ? 'critical' : risk === 'HIGH' ? 'high' : 'low';
}

function _renderVTResult(data, label) {
  const el = $('vtResult');
  if (data.error) {
    el.innerHTML = `<div style="color:var(--danger);font-size:.85rem">⚠ ${data.error}</div>`;
    return;
  }
  const rc  = _vtRiskClass(data.risk);
  const col = rc === 'critical' ? 'var(--danger)' : rc === 'high' ? 'var(--warn)' : 'var(--success)';

  const enginesHtml = (data.flagging_engines || []).map(e => `
    <div class="vt-engine-chip ${e.category === 'suspicious' ? 'suspicious' : ''}">
      <strong>${e.engine}</strong> — ${e.result}
    </div>`).join('');

  el.innerHTML = `
    <div class="vt-result-bar">
      <div>
        <div class="vt-gauge ${rc}">${data.detection_ratio}</div>
        <div class="vt-gauge-label">engines detected it</div>
      </div>
      <div style="flex:1">
        <div style="font-weight:700;color:${col};font-size:1rem">${data.risk} RISK</div>
        <div style="font-size:.78rem;color:var(--muted);margin-top:3px">${label}</div>
        ${data.file_name ? `<div style="font-size:.75rem;color:var(--muted);margin-top:2px">File: ${data.file_name} &nbsp;·&nbsp; ${data.file_type || ''} &nbsp;·&nbsp; ${data.file_size ? (data.file_size/1024).toFixed(1)+'KB' : ''}</div>` : ''}
        ${data.cached ? '<div style="font-size:.72rem;color:var(--muted);margin-top:2px">⚡ Served from VirusTotal cache</div>' : ''}
      </div>
      <div style="text-align:right">
        <div style="font-size:.72rem;color:var(--muted)">Undetected</div>
        <div style="font-size:1.4rem;font-weight:700;color:var(--success)">${data.undetected}</div>
      </div>
    </div>
    ${enginesHtml ? `
      <div style="font-size:.75rem;color:var(--muted);margin-bottom:8px">
        Flagging engines (${data.flagging_engines.length}):
      </div>
      <div class="vt-engines-grid">${enginesHtml}</div>` : `
      <div style="color:var(--success);font-size:.85rem;padding:10px 0">
        ✅ No engines flagged this ${data.url ? 'URL' : 'file'}.
      </div>`}`;
}

async function vtScanUrl() {
  const url = $('vtUrlInp').value.trim();
  if (!url) { showStatus('Enter a URL to scan.', 'error'); return; }
  $('vtUrlBtn').disabled = true;
  $('vtResult').innerHTML = '<span class="spinner"></span> Submitting to VirusTotal… (may take up to 60s on first scan)';
  showStatus('Scanning URL on VirusTotal…', 'loading');
  try {
    const res  = await fetch('/api/virustotal-scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    hideStatus();
    _renderVTResult(data, url);
  } catch (err) {
    hideStatus();
    $('vtResult').innerHTML = `<div style="color:var(--danger)">Request failed: ${err.message}</div>`;
  } finally { $('vtUrlBtn').disabled = false; }
}

async function vtLookupHash() {
  const hash = $('vtHashInp').value.trim();
  if (!hash) { showStatus('Enter a SHA-256 hash.', 'error'); return; }
  $('vtHashBtn').disabled = true;
  $('vtResult').innerHTML = '<span class="spinner"></span> Looking up hash on VirusTotal…';
  showStatus('Looking up file hash…', 'loading');
  try {
    const res  = await fetch('/api/virustotal-scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash }),
    });
    const data = await res.json();
    hideStatus();
    _renderVTResult(data, hash.substring(0, 16) + '…');
  } catch (err) {
    hideStatus();
    $('vtResult').innerHTML = `<div style="color:var(--danger)">Request failed: ${err.message}</div>`;
  } finally { $('vtHashBtn').disabled = false; }
}

// --------------------------------------------------------------------------
// HuggingFace models
// --------------------------------------------------------------------------
async function loadHFModels() {
  try {
    const res  = await fetch('/api/hf-models');
    const data = await res.json();
    const sel  = $('hfModelSel');
    sel.innerHTML = (data.models || []).map(m =>
      `<option value="${m.key}">${m.label}</option>`
    ).join('');

    // Populate sample URL quick-links
    const linksEl = $('hfSampleLinks');
    const phishing = (data.sample_urls || {}).phishing || [];
    linksEl.innerHTML = phishing.slice(0, 3).map(u => {
      const short = u.length > 45 ? u.substring(0, 45) + '…' : u;
      return `<button onclick="$('hfUrlInp').value='${u.replace(/'/g, "\\'")}';"
        style="background:var(--surface2);border:1px solid var(--border);border-radius:5px;
               color:var(--muted);font-size:.7rem;padding:2px 8px;cursor:pointer"
        title="${u}">${short}</button>`;
    }).join('');
  } catch (_) { /* optional feature */ }
}

function _renderHFClassify(data) {
  const el = $('hfResult');
  if (data.error) { el.innerHTML = `<div style="color:var(--danger);font-size:.85rem">⚠ ${data.error}</div>`; return; }
  const cls   = data.is_malicious ? 'malicious' : 'benign';
  const emoji = data.is_malicious ? '🔴' : '🟢';
  const pct   = data.score != null ? (data.score * 100).toFixed(1) + '%' : '—';
  el.innerHTML = `
    <div class="hf-result-pill ${cls}">
      ${emoji} ${data.label?.toUpperCase()} &nbsp;·&nbsp; confidence ${pct}
    </div>
    <div style="font-size:.75rem;color:var(--muted)">
      Model: ${data.model_label || data.model_key} &nbsp;·&nbsp;
      URL: <code style="color:var(--text)">${data.url}</code>
    </div>`;
}

function _renderHFEvasion(data) {
  const el = $('hfResult');
  if (data.error) { el.innerHTML = `<div style="color:var(--danger);font-size:.85rem">⚠ ${data.error}</div>`; return; }

  const pct   = ((data.evasion_rate || 0) * 100).toFixed(0);
  const col   = data.evasion_rate > 0.5 ? 'var(--danger)' : data.evasion_rate > 0.2 ? 'var(--warn)' : 'var(--success)';
  const rows  = (data.results || []).map(r => {
    if (r.error) return `<tr><td>${r.mutation_label}</td><td colspan="4" style="color:var(--danger)">${r.error}</td></tr>`;
    const evCls  = r.evaded ? 'evaded-yes' : 'evaded-no';
    const evText = r.evaded ? '✓ EVADED' : '✗ Detected';
    const short  = (r.mutated_url || '').length > 60 ? r.mutated_url.substring(0, 60) + '…' : r.mutated_url;
    return `<tr>
      <td>${r.mutation_label}</td>
      <td style="font-family:monospace;font-size:.72rem;color:var(--muted)" title="${r.mutated_url}">${short}</td>
      <td>${r.label?.toUpperCase() || '—'}</td>
      <td>${r.score != null ? (r.score * 100).toFixed(1) + '%' : '—'}</td>
      <td class="${evCls}">${evText}</td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div style="margin-bottom:14px;display:flex;align-items:center;gap:16px">
      <div>
        <div style="font-size:2rem;font-weight:800;color:${col}">${pct}%</div>
        <div style="font-size:.72rem;color:var(--muted)">Evasion rate</div>
      </div>
      <div>
        <div style="font-size:.88rem;color:var(--text)">
          <strong>${data.n_evaded} / ${data.n_total}</strong> mutation techniques evaded
          <strong>${data.model_label || data.model_key}</strong>
        </div>
        <div style="font-size:.75rem;color:var(--muted);margin-top:4px">
          Original URL: <code style="color:var(--text)">${data.original_url}</code>
        </div>
      </div>
    </div>
    <table class="evasion-table">
      <thead><tr>
        <th>Technique</th><th>Mutated URL</th><th>Label</th><th>Confidence</th><th>Result</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

async function hfClassify() {
  const model_key = $('hfModelSel').value;
  const url       = $('hfUrlInp').value.trim();
  if (!url) { showStatus('Enter a URL to classify.', 'error'); return; }
  $('hfClassifyBtn').disabled = true;
  $('hfResult').innerHTML = '<span class="spinner"></span> Classifying…';
  showStatus('Calling HuggingFace model…', 'loading');
  try {
    const res  = await fetch('/api/hf-classify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_key, url }),
    });
    const data = await res.json();
    hideStatus();
    _renderHFClassify(data);
  } catch (err) {
    hideStatus();
    $('hfResult').innerHTML = `<div style="color:var(--danger)">Request failed: ${err.message}</div>`;
  } finally { $('hfClassifyBtn').disabled = false; }
}

async function hfEvasion() {
  const model_key = $('hfModelSel').value;
  const url       = $('hfUrlInp').value.trim();
  if (!url) { showStatus('Enter a URL for the evasion demo.', 'error'); return; }
  $('hfEvasionBtn').disabled = true;
  $('hfResult').innerHTML = '<span class="spinner"></span> Running 7 mutation techniques against HuggingFace model… (may take ~30s)';
  showStatus('Running URL evasion demo…', 'loading');
  try {
    const res  = await fetch('/api/hf-evasion', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model_key, url }),
    });
    const data = await res.json();
    hideStatus();
    _renderHFEvasion(data);
    showStatus(`✓ Evasion demo complete — ${(data.evasion_rate * 100).toFixed(0)}% evasion rate.`, 'success');
  } catch (err) {
    hideStatus();
    $('hfResult').innerHTML = `<div style="color:var(--danger)">Request failed: ${err.message}</div>`;
  } finally { $('hfEvasionBtn').disabled = false; }
}

// --------------------------------------------------------------------------
// Session management
// --------------------------------------------------------------------------

let _currentSessionId = null;   // session loaded into the UI (or null = latest run)

/** Read ?session=<id> from URL; load it if present. */
async function initSession() {
  const params = new URLSearchParams(window.location.search);
  const sid    = params.get('session');
  if (sid) {
    await loadSession(sid);
  }
  // Always refresh the session list in the background
  _refreshSessionList();
}

/** Fetch and render a specific session's results. */
async function loadSession(sid) {
  showStatus('Loading session ' + sid + '…', 'loading');
  try {
    const res  = await fetch(`/api/sessions/${sid}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showStatus('Session not found: ' + (err.error || sid), 'error');
      return;
    }
    const data = await res.json();

    // Always wipe charts first so previous session data doesn't bleed through
    renderAll({});

    _currentSessionId = sid;
    _updateSessionBar(sid);

    // Update URL without page reload
    const url = new URL(window.location.href);
    url.searchParams.set('session', sid);
    window.history.replaceState({}, '', url.toString());

    const results = data.results || {};
    const hasResults = Object.keys(results).length > 0;
    if (hasResults) {
      _applySessionResults(results, data);
      hideStatus();
      showStatus('✓ Session ' + sid + ' loaded — ' + (data.created_at || ''), 'success');
    } else {
      hideStatus();
      showStatus('✓ Session ' + sid + ' opened (no results yet — run a benchmark to populate it).', 'success');
    }
  } catch (err) {
    showStatus('Failed to load session: ' + err.message, 'error');
  }
}

/** Apply session results data to all charts and table (same as fetchResults). */
function _applySessionResults(results, meta) {
  renderAll(results);
}

/** Update the session bar display. */
function _updateSessionBar(sid) {
  const el = $('sessionCodeDisplay');
  if (sid) {
    el.textContent = sid;
    el.className   = 'session-code';
    // Share button visible as soon as a session ID exists
    $('shareSessionBtn').style.display = '';
  } else {
    el.textContent = 'no active session';
    el.className   = 'session-code none';
    $('shareSessionBtn').style.display = 'none';
  }
}

/** Click-to-copy the session code itself (not the full URL). */
function copySessionCode() {
  if (!_currentSessionId) return;
  navigator.clipboard.writeText(_currentSessionId).catch(() => {});
}

/** Create a new empty session immediately, clear the UI, update the URL. */
async function startNewSession() {
  showStatus('Creating new session…', 'loading');
  try {
    const res  = await fetch('/api/sessions/new', { method: 'POST' });
    const data = await res.json();
    const sid  = data.session_id;

    _currentSessionId = sid;
    _updateSessionBar(sid);

    // Push new session ID into the URL right away — shareable before benchmark runs
    const u = new URL(window.location.href);
    u.searchParams.set('session', sid);
    window.history.replaceState({}, '', u.toString());

    // Wipe all charts and the table so the UI is visibly fresh
    renderAll({});

    hideStatus();
    showStatus(`✓ New session ${sid} ready — run a benchmark to populate it.`, 'success');
  } catch (err) {
    showStatus('Failed to create session: ' + err.message, 'error');
  }
}

/** Load the most recent saved session. */
async function loadLastSession() {
  showStatus('Finding last session…', 'loading');
  try {
    const res  = await fetch('/api/sessions');
    const data = await res.json();
    const list = data.sessions || [];
    if (!list.length) {
      showStatus('No saved sessions found — run a benchmark first.', 'error');
      return;
    }
    await loadSession(list[0].session_id);
  } catch (err) {
    showStatus('Failed to fetch sessions: ' + err.message, 'error');
  }
}

/** Copy a shareable URL for the current session to the clipboard. */
function shareSession() {
  if (!_currentSessionId) return;
  const url = new URL(window.location.href);
  url.searchParams.set('session', _currentSessionId);
  const shareUrl = url.toString();
  navigator.clipboard.writeText(shareUrl).then(() => {
    showStatus('✓ Link copied: ' + shareUrl, 'success');
  }).catch(() => {
    // Fallback: show the URL in the status bar
    showStatus('Share URL: ' + shareUrl, 'success');
  });
}

/** Open the session picker modal and refresh its list. */
function openSessionModal() {
  $('sessionModal').classList.add('open');
  $('sessionCodeInp').value = '';
  _refreshSessionList();
}

/** Close the session picker modal. */
function closeSessionModal() {
  $('sessionModal').classList.remove('open');
}

/** Navigate to a session by ID (entered in the modal). */
async function openSessionById(sid) {
  sid = (sid || '').trim().toLowerCase();
  if (sid.length !== 8 || !/^[0-9a-f]{8}$/.test(sid)) {
    showStatus('Session ID must be exactly 8 hex characters (e.g. a3f2b1c9).', 'error');
    return;
  }
  closeSessionModal();
  await loadSession(sid);
}

/** Populate the recent-sessions list inside the modal. */
async function _refreshSessionList() {
  const listEl = $('sessionList');
  if (!listEl) return;
  try {
    const res  = await fetch('/api/sessions');
    const data = await res.json();
    const list = (data.sessions || []).slice(0, 15);   // show max 15

    if (!list.length) {
      listEl.innerHTML = '<div style="color:var(--muted);font-size:.78rem;padding:8px">No saved sessions yet — run a benchmark to create one.</div>';
      return;
    }

    listEl.innerHTML = list.map(s => {
      const er    = s.max_evasion != null ? (s.max_evasion * 100).toFixed(1) + '%' : '—';
      const erCol = s.max_evasion > 0.5 ? 'var(--danger)' : s.max_evasion > 0.2 ? 'var(--warn)' : 'var(--success)';
      const model  = s.params?.model  || '?';
      const attack = s.params?.attack || '?';
      const ts     = (s.created_at || '').replace(' UTC', '');
      return `<div class="session-item" onclick="closeSessionModal();loadSession('${s.session_id}')">
        <span class="session-item-code">${s.session_id}</span>
        <span class="session-item-meta">${ts} · ${model}/${attack}</span>
        <span class="session-item-er" style="color:${erCol}">${er}</span>
      </div>`;
    }).join('');
  } catch (_) {
    listEl.innerHTML = '<div style="color:var(--danger);font-size:.78rem;padding:8px">Could not load sessions.</div>';
  }
}

// --------------------------------------------------------------------------
// Initialise on load
// --------------------------------------------------------------------------

// Render empty placeholder charts so the page looks complete immediately
renderHeatmap({});
renderBarChart({});
renderLineChart({});

// Fetch live results and supporting data
fetchResults();
loadProfiles();
loadHistory();
loadHFModels();
initSession();
