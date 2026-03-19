// app.js — Main application logic for Policy Intelligence web demo.
//
// Handles: UI rendering, tab switching, WASM compilation,
// Z3 solving via z3-solver-bridge, and result interpretation.

import { initZ3, solveSmtLib2 } from './z3-solver-bridge.mjs';
import {
  escapeHtml, highlightOutput, applyKeywordHighlights,
  highlightSMT, highlightRego, highlightCedar, highlightJsonLine,
} from './highlighting.js';

// ── WASM module references (set during init) ────────────
let wasm = null;  // the regorus WASM module

// ── File cache ──────────────────────────────────────────
const fileCache = new Map();

async function fetchText(url) {
  if (fileCache.has(url)) return fileCache.get(url);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch ${url}: ${resp.status}`);
  const text = await resp.text();
  fileCache.set(url, text);
  return text;
}

// ═══════════════════════════════════════════════════════════
//  INITIALIZATION
// ═══════════════════════════════════════════════════════════
export async function initApp() {
  const DEMOS = window.DEMOS;
  const OVERVIEW_CARDS = window.OVERVIEW_CARDS;
  const TAG_CLASSES = window.TAG_CLASSES;
  const LANG_BADGE = window.LANG_BADGE;
  const statusEl = document.getElementById('initStatus');

  // Build UI immediately (before WASM loads)
  buildUI(DEMOS, OVERVIEW_CARDS, TAG_CLASSES, LANG_BADGE);

  // Load WASM modules
  try {
    statusEl.textContent = 'Loading regorus WASM module…';
    const regorusModule = await import('./regorusjs.js');
    await regorusModule.default();
    wasm = regorusModule;

    statusEl.textContent = 'Loading Z3 WASM solver (~32 MB, first load may take a moment)…';
    await initZ3();

    statusEl.textContent = '✓ Ready — regorus + Z3 loaded';
    statusEl.classList.add('ready');
    setTimeout(() => { statusEl.style.display = 'none'; }, 2000);
  } catch (err) {
    statusEl.textContent = `✗ Failed to initialize: ${err.message}`;
    statusEl.classList.add('error');
    console.error('Init error:', err);
  }
}

// ═══════════════════════════════════════════════════════════
//  UI BUILDING
// ═══════════════════════════════════════════════════════════
function buildUI(DEMOS, OVERVIEW_CARDS, TAG_CLASSES, LANG_BADGE) {
  const tabBar = document.getElementById('tabBar');
  const tabPanels = document.getElementById('tabPanels');

  DEMOS.forEach((demo, di) => {
    const btn = document.createElement('button');
    btn.className = 'tab-btn' + (di === 0 ? ' active' : '');
    btn.dataset.tab = demo.id;
    if (demo.playground) {
      btn.innerHTML = `<span class="tab-num">🔬</span>Playground`;
    } else if (demo.intro) {
      btn.innerHTML = `<span class="tab-num">📐</span>How It Works`;
    } else if (di > 0) {
      const langCls = LANG_BADGE[demo.lang] || '';
      btn.innerHTML = `<span class="tab-num">${di}</span>${langCls ? `<span class="lang-badge ${langCls}">${demo.lang}</span>` : ''}${demo.title}`;
    } else {
      btn.textContent = demo.title;
    }
    btn.addEventListener('click', () => switchTab(demo.id));
    tabBar.appendChild(btn);

    const panel = document.createElement('div');
    panel.className = 'tab-panel' + (di === 0 ? ' active' : '');
    panel.id = `panel-${demo.id}`;
    panel.innerHTML = demo.overview
      ? buildOverview(demo, OVERVIEW_CARDS, TAG_CLASSES)
      : demo.intro
      ? buildIntroPanel()
      : demo.playground
      ? buildPlayground()
      : buildActPanel(demo, di, LANG_BADGE);
    tabPanels.appendChild(panel);
  });

  // Overview card click handler
  document.addEventListener('click', e => {
    const card = e.target.closest('.overview-card');
    if (card && card.dataset.goto) switchTab(card.dataset.goto);
  });

  // Expose global handlers for onclick attributes
  window.runStep = runStep;
  window.runAll = runAll;
  window.copyOutput = copyOutput;
  window.toggleOutput = toggleOutput;
  window.toggleSmt = toggleSmt;
  window.togglePolicyViewer = togglePolicyViewer;
  window.switchPolicyView = switchPolicyView;
  window.pgRun = pgRun;
  window.pgToggleSmt = pgToggleSmt;
  window.pgTogglePanel = pgTogglePanel;
  window.pgClearEditor = pgClearEditor;
  window.runSmtPreset = runSmtPreset;
  window.switchSmtPreset = switchSmtPreset;

}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tabId}`));
  if (tabId === 'playground') ensurePlaygroundInit();
  if (tabId === 'intro') ensureIntroInit();
}

// ── SMT Presets for the interactive intro ───────────────
const SMT_PRESETS = [
  {
    id: 'impossible',
    label: 'Impossible?',
    desc: 'Can x be greater than 5 AND less than 3? Z3 proves: no.',
    smt: `; Can a number be greater than 5 AND less than 3?
(declare-const x Int)
(assert (> x 5))
(assert (< x 3))
(check-sat)`,
  },
  {
    id: 'find-value',
    label: 'Find a value',
    desc: 'Find an age eligible for a senior discount.',
    smt: `; Find an age eligible for a "senior discount"
(declare-const age Int)
(assert (>= age 65))
(assert (<= age 120))
(check-sat)
(get-value (age))`,
  },
  {
    id: 'strings',
    label: 'Strings',
    desc: 'Find a role that starts with "a" but isn\'t "admin".',
    smt: `; Find a role starting with "a" that isn't "admin"
(declare-const role String)
(assert (not (= role "admin")))
(assert (str.prefixof "a" role))
(assert (> (str.len role) 2))
(check-sat)
(get-value (role))`,
  },
  {
    id: 'https',
    label: 'HTTPS compliance',
    desc: 'Can a storage account be compliant without HTTPS? Z3 proves: impossible.',
    smt: `; Can a storage account be compliant without HTTPS?
(declare-const https_enabled Bool)
(declare-const compliant Bool)

; Policy: compliant requires HTTPS
(assert (= compliant https_enabled))

; Question: compliant but no HTTPS?
(assert compliant)
(assert (not https_enabled))
(check-sat)`,
  },
  {
    id: 'region',
    label: 'Region violation',
    desc: 'What resource gets denied by a region-restriction policy?',
    smt: `; Azure policy: deny VMs outside allowed regions
(declare-const region String)

; Region must not be in the allowed list
(assert (not (= region "eastus")))
(assert (not (= region "westus2")))

; But it must be a plausible region string (non-empty)
(assert (> (str.len region) 0))
(check-sat)
(get-value (region))`,
  },
  {
    id: 'allof-anyof',
    label: 'allOf vs anyOf',
    desc: 'A policy requires two tags (allOf) but is mistakenly written with anyOf \u2014 Z3 finds a resource that slips through.',
    smt: `; Two required tags for compliance
(declare-const has_env Bool)
(declare-const has_owner Bool)

; Intent: resource must have BOTH env AND owner tags
; Bug: policy was written with anyOf (OR) instead of allOf (AND)
(declare-const passes_policy Bool)
(assert (= passes_policy (or has_env has_owner)))  ; ← should be 'and'

; Resource passes the policy check
(assert passes_policy)

; But is missing at least one required tag
(assert (not (and has_env has_owner)))

(check-sat)
(get-value (has_env has_owner))`,
  },
];

// ── Overview ────────────────────────────────────────────
function buildOverview(demo, OVERVIEW_CARDS, TAG_CLASSES) {
  let html = `<div class="act-header">
    <h2>Z3 Symbolic Policy Analysis</h2>
    <div class="subtitle">
      Given any policy — <strong style="color:var(--cyan)">Rego</strong>, <strong style="color:var(--green)">Cedar</strong>, or <strong style="color:var(--accent)">Azure Policy</strong> —
      Z3 automatically synthesizes concrete inputs for any desired outcome.
      No fuzzing, no sampling, no manual test writing. Click a card to explore.
    </div>
  </div>
  <div class="overview-grid">`;
  for (const c of OVERVIEW_CARDS) {
    const tags = c.tags.map(t => `<span class="tag ${TAG_CLASSES[t] || ''}">${t}</span>`).join('');
    html += `<div class="overview-card" data-goto="${c.tabId}">
      <div class="card-num">${c.num}</div>
      <h3>${c.title}</h3>
      <p>${c.desc}</p>
      <div class="tags">${tags}</div>
    </div>`;
  }
  return html + '</div>';
}

function buildIntroPanel() {
  return `<div class="act-header">
    <h2>Symbolic Policy Analysis</h2>
    <div class="subtitle">How SMT solving and Z3 power policy analysis.</div>
  </div>

  <div class="intro-section">

    <div class="intro-block">
      <h3 class="intro-heading">What is SMT?</h3>
      <p>
        You give a solver a set of constraints —
        <em>"x is an integer greater than 5"</em>,
        <em>"y is a string starting with CC-"</em> —
        and ask: <strong>is there any combination of values that satisfies all of them?</strong>
        If yes, it hands you one (<span class="hl-sat">sat</span>).
        If no such values exist, it proves that mathematically (<span class="hl-unsat">unsat</span>).
        This is SMT: Satisfiability Modulo Theories.
      </p>
    </div>

    <div class="intro-block">
      <h3 class="intro-heading">Z3</h3>
      <p>
        <a href="https://github.com/Z3Prover/z3" target="_blank" rel="noopener">Z3</a>
        is the SMT solver built by Microsoft Research.
        It's used across the industry — in compilers, security tools, program verifiers.
        Here, it's running directly in your browser via WebAssembly.
      </p>
    </div>

    <div class="intro-tryit">
      <h3 class="intro-heading">Try it</h3>
      <p class="intro-tryit-desc">
        This is raw SMT-LIB2 — the constraint language Z3 speaks.
        Pick a preset, read the comments, hit <strong>Solve</strong>.
      </p>
      <div class="smt-preset-tabs">
        ${SMT_PRESETS.map((p, i) => `<button class="smt-preset-btn${i === 0 ? ' active' : ''}" data-preset="${i}" onclick="switchSmtPreset(${i})">${p.label}</button>`).join('')}
      </div>
      <p class="smt-preset-desc" id="smt-preset-desc">${SMT_PRESETS[0].desc}</p>
      <div class="smt-tryit-split">
        <div class="smt-tryit-editor">
          <pre class="smt-tryit-highlight" id="smt-tryit-highlight"></pre>
          <textarea id="smt-tryit-input" class="smt-tryit-textarea" spellcheck="false"></textarea>
        </div>
        <div class="smt-tryit-result" id="smt-tryit-result">
          <div class="smt-tryit-placeholder">Hit <strong>Solve</strong> to run Z3</div>
        </div>
      </div>
      <div class="smt-tryit-actions">
        <button class="btn btn-run" onclick="runSmtPreset()">▶ Solve with Z3</button>
        <span class="status-text" id="smt-tryit-status"></span>
      </div>
    </div>

    <div class="intro-block">
      <h3 class="intro-heading">What we do with it</h3>
      <p>
        Normally you run a policy on one input and get one answer.
        We do something different: we run the policy on <strong>symbolic</strong> inputs —
        placeholders that stand for every possible value at once.
        The output isn't a yes/no — it's a formula. Z3 solves that formula.
      </p>
      <div class="sym-compare">
        <div class="sym-panel">
          <div class="sym-panel-label">Concrete evaluation</div>
          <pre class="sym-code"><span class="sym-dim">input.role</span> = <span class="sym-val">"admin"</span>
<span class="sym-dim">input.suspended</span> = <span class="sym-val">false</span>
        ↓
<span class="sym-dim">allow</span> = <span class="sym-val">true</span>  <span class="sym-note">← one answer for one input</span></pre>
        </div>
        <div class="sym-vs">vs</div>
        <div class="sym-panel sym-panel-hl">
          <div class="sym-panel-label">Symbolic evaluation</div>
          <pre class="sym-code"><span class="sym-dim">input.role</span> = <span class="sym-sym">R</span>  <span class="sym-note">← any string</span>
<span class="sym-dim">input.suspended</span> = <span class="sym-sym">S</span>  <span class="sym-note">← any bool</span>
        ↓
<span class="sym-dim">allow = true</span>  <strong>when</strong>  <span class="sym-sym">R</span> = "admin" ∧ ¬<span class="sym-sym">S</span>
        ↓
<span class="sym-dim">Z3 finds:</span>  <span class="sym-val">R = "admin", S = false</span></pre>
        </div>
      </div>
      <div class="pipeline-diagram">
        <div class="pipeline-step">Policy<span class="pipeline-sub">Rego / Cedar</span></div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step pipeline-step-hl">Symbolic<br>Interpreter<span class="pipeline-sub">regorus</span></div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">SMT<br>Formula<span class="pipeline-sub">constraints</span></div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step pipeline-step-hl">Z3<br>Solver<span class="pipeline-sub">satisfiability</span></div>
        <div class="pipeline-arrow">→</div>
        <div class="pipeline-step">Result<span class="pipeline-sub">input / proof</span></div>
      </div>

      <p class="intro-operations">
        This lets us answer questions that testing alone cannot:
        <strong>analyze</strong> — find an input that produces a specific outcome;
        <strong>diff</strong> — find where two policy versions disagree;
        <strong>subsumes</strong> — prove one policy is at least as permissive as another;
        <strong>gen-tests</strong> — generate test cases covering every code path.
      </p>
    </div>
  </div>`;
}

let introInitDone = false;
function ensureIntroInit() {
  if (introInitDone) return;
  introInitDone = true;
  initSmtTryit();
}

function initSmtTryit() {
  const ta = document.getElementById('smt-tryit-input');
  if (!ta) return;
  ta.value = SMT_PRESETS[0].smt;
  syncSmtHighlight();
  ta.addEventListener('input', syncSmtHighlight);
  ta.addEventListener('scroll', () => {
    document.getElementById('smt-tryit-highlight').scrollTop = ta.scrollTop;
    document.getElementById('smt-tryit-highlight').scrollLeft = ta.scrollLeft;
  });
}

function syncSmtHighlight() {
  const ta = document.getElementById('smt-tryit-input');
  const pre = document.getElementById('smt-tryit-highlight');
  if (!ta || !pre) return;
  pre.innerHTML = highlightSMT(ta.value);
}

function switchSmtPreset(idx) {
  const p = SMT_PRESETS[idx];
  if (!p) return;
  document.querySelectorAll('.smt-preset-btn').forEach((b, i) => b.classList.toggle('active', i === idx));
  document.getElementById('smt-preset-desc').textContent = p.desc;
  document.getElementById('smt-tryit-input').value = p.smt;
  syncSmtHighlight();
  // Clear previous result
  const result = document.getElementById('smt-tryit-result');
  result.innerHTML = '<div class="smt-tryit-placeholder">Hit <strong>Solve</strong> to run Z3</div>';
  document.getElementById('smt-tryit-status').textContent = '';
}

function formatSmtValue(v) {
  if (v === 'Undefined') return 'undefined';
  if (typeof v === 'string') return v;
  if (v.Bool !== undefined) return String(v.Bool);
  if (v.Int !== undefined) return String(v.Int);
  if (v.String !== undefined) return `"${v.String}"`;
  if (v.Float !== undefined) return String(v.Float);
  if (v.Array) return JSON.stringify(v.Array);
  return JSON.stringify(v);
}

async function runSmtPreset() {
  const ta = document.getElementById('smt-tryit-input');
  const resultDiv = document.getElementById('smt-tryit-result');
  const statusEl = document.getElementById('smt-tryit-status');
  if (!ta) return;

  const smtText = ta.value.trim();
  if (!smtText) { statusEl.textContent = '✗ Empty formula'; statusEl.className = 'status-text error'; return; }

  statusEl.textContent = 'Solving…';
  statusEl.className = 'status-text';
  resultDiv.innerHTML = '<div class="smt-tryit-placeholder"><span class="spinner"></span> Solving…</div>';

  try {
    const t0 = performance.now();
    const resultJson = await solveSmtLib2(smtText, 0);
    const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
    const result = JSON.parse(resultJson);

    let html = '';
    if (result.status === 'Sat') {
      html += `<div class="smt-result-status smt-sat">sat</div>`;
      html += `<div class="smt-result-explain">A solution exists!</div>`;
      if (result.values && result.values.length > 0) {
        // Extract variable names from (get-value (...)) in the input
        const varNames = [];
        const gvMatch = smtText.match(/\(get-value\s*\(([^)]+)\)\)/);
        if (gvMatch) gvMatch[1].trim().split(/\s+/).forEach(n => varNames.push(n));
        html += `<div class="smt-result-model">`;
        result.values.forEach((v, i) => {
          const name = varNames[i] || `value_${i}`;
          const display = formatSmtValue(v);
          html += `<div class="smt-model-row"><span class="smt-model-var">${escapeHtml(name)}</span> <span class="smt-model-eq">=</span> <span class="smt-model-val">${escapeHtml(display)}</span></div>`;
        });
        html += `</div>`;
      }
    } else if (result.status === 'Unsat') {
      html += `<div class="smt-result-status smt-unsat">unsat</div>`;
      html += `<div class="smt-result-explain">No solution exists — impossible!</div>`;
    } else {
      html += `<div class="smt-result-status smt-unknown">unknown</div>`;
      html += `<div class="smt-result-explain">${escapeHtml(result.reason_unknown || 'Solver could not determine')}</div>`;
    }
    html += `<div class="smt-result-time">${elapsed}s</div>`;
    resultDiv.innerHTML = html;
    statusEl.textContent = `✓ ${result.status} (${elapsed}s)`;
    statusEl.className = 'status-text success';
  } catch (err) {
    resultDiv.innerHTML = `<div class="smt-result-status smt-unknown">error</div><div class="smt-result-explain">${escapeHtml(err.message)}</div>`;
    statusEl.textContent = `✗ ${err.message}`;
    statusEl.className = 'status-text error';
  }
}

// ── Demo Panel ──────────────────────────────────────────
function buildActPanel(demo, actNum, LANG_BADGE) {
  const langLabel = demo.lang ? ` <span class="lang-badge ${LANG_BADGE[demo.lang] || ''}" style="font-size:0.65rem;vertical-align:2px">${demo.lang}</span>` : '';
  let html = `<div class="act-header">
    <h2>${demo.title}${langLabel}</h2>
    <div class="subtitle">${demo.subtitle}</div>
  </div>`;

  if (demo.policyFiles && demo.policyFiles.length > 0) {
    html += buildPolicyViewer(demo);
  }

  html += `<div class="run-all-bar">
    <button class="btn btn-run btn-run-all" data-act="${demo.id}" onclick="runAll('${demo.id}')">▶ Run All Steps</button>
    <span class="progress-text" id="progress-${demo.id}"></span>
  </div>`;

  demo.steps.forEach((step, si) => {
    const stepId = `${demo.id}-${si}`;
    const cmdStr = formatCmd(step.args);
    html += `<div class="demo-card" id="card-${stepId}">
      <div class="demo-card-header">
        <span class="step-badge">${si + 1}</span>
        <span class="desc">${step.label}</span>
      </div>
      <div class="demo-cmd"><span class="cmd-label">CLI equivalent</span><code><span class="prompt">$ </span>${escapeHtml(cmdStr)}</code></div>
      <div class="demo-actions">
        <button class="btn btn-run" id="btn-${stepId}" onclick="runStep('${demo.id}', ${si})">▶ Run</button>
        <button class="btn btn-smt" id="btn-smt-${stepId}" onclick="toggleSmt('${stepId}')">Show SMT</button>
        <span class="status-text" id="status-${stepId}"></span>
      </div>
      <div class="demo-output" id="output-${stepId}">
        <div class="output-toolbar">
          <span class="label">Output</span>
          <button class="btn-sm" onclick="copyOutput('${stepId}')">Copy</button>
          <button class="btn-sm" onclick="toggleOutput('${stepId}')">Collapse</button>
        </div>
        <div class="output-body"><pre id="pre-${stepId}"></pre></div>
      </div>
      <div class="smt-viewer" id="smt-${stepId}" style="display:none">
        <div class="output-toolbar">
          <span class="label" style="color:var(--magenta)">SMT-LIB Encoding</span>
          <button class="btn-sm" onclick="copyOutput('smt-${stepId}')">Copy</button>
          <button class="btn-sm" onclick="toggleSmt('${stepId}')">Hide</button>
        </div>
        <div class="output-body" style="max-height:400px"><pre id="pre-smt-${stepId}"></pre></div>
      </div>
      ${step.postFetch ? buildPostFetchAreas(stepId, step.postFetch) : ''}
      ${step.insight ? `<div class="insight" id="insight-${stepId}" style="display:none">➤ ${escapeHtml(step.insight)}</div>` : ''}
    </div>`;
  });

  return html;
}

function buildPostFetchAreas(stepId, types) {
  let html = '';
  for (const t of types) {
    const label = t === 'smt' ? 'SMT-LIB Encoding' : 'Z3 Model';
    const id = `${stepId}-${t}`;
    html += `<div class="demo-output" id="output-${id}" style="display:none">
      <div class="output-toolbar">
        <span class="label" style="color:var(--magenta)">${label}</span>
        <button class="btn-sm" onclick="copyOutput('${id}')">Copy</button>
        <button class="btn-sm" onclick="toggleOutput('${id}')">Collapse</button>
      </div>
      <div class="output-body" style="max-height:400px"><pre id="pre-${id}"></pre></div>
    </div>`;
  }
  return html;
}

function formatCmd(args) {
  let parts = ['regorus'];
  let line = 'regorus';
  for (const a of args) {
    const token = a.includes(' ') || a.includes('"') ? `'${a}'` : a;
    if (line.length + token.length > 78 && !a.startsWith('-')) {
      parts.push(' \\\n    ' + token);
      line = '    ' + token;
    } else if (a.startsWith('--') && line.length + token.length > 58) {
      parts.push(' \\\n    ' + token);
      line = '    ' + token;
    } else {
      parts.push(' ' + token);
      line += ' ' + token;
    }
  }
  return parts.join('');
}

// ═══════════════════════════════════════════════════════════
//  POLICY VIEWER
// ═══════════════════════════════════════════════════════════
function buildPolicyViewer(demo) {
  const vid = `pv-${demo.id}`;
  const files = demo.policyFiles;
  const hasSideBySide = demo.sideBySide;
  const fileCount = files.length;
  const langKey = files[0]?.lang || 'rego';
  const pvLabelCls = `pv-label-${langKey === 'cedar' ? 'cedar' : langKey === 'json' ? 'json' : langKey === 'rego' ? 'rego' : 'azure'}`;
  const fileText = fileCount === 1 ? files[0].name : `${fileCount} files`;

  let html = `<div class="policy-viewer">
    <button class="pv-toggle" onclick="togglePolicyViewer('${vid}')">
      <span class="pv-icon">▶</span>
      <span class="pv-label ${pvLabelCls}">Policy</span>
      <span>${escapeHtml(fileText)}</span>
    </button>
    <div class="pv-content" id="${vid}">`;

  if (hasSideBySide && demo.sideBySidePairs) {
    html += '<div class="pv-file-tabs">';
    files.forEach((f, i) => {
      html += `<button class="pv-file-tab${i === 0 ? ' active' : ''}" data-viewer="${vid}" data-fi="${i}" data-view="single" onclick="switchPolicyView('${vid}', 'single', ${i})">${escapeHtml(f.name)}</button>`;
    });
    demo.sideBySidePairs.forEach((pair, pi) => {
      html += `<button class="pv-file-tab" data-viewer="${vid}" data-fi="pair${pi}" data-view="pair" onclick="switchPolicyView('${vid}', 'pair', ${pi})">⇔ ${escapeHtml(pair.leftLabel)} vs ${escapeHtml(pair.rightLabel)}</button>`;
    });
    html += '</div>';
    files.forEach((f, i) => {
      html += `<div class="pv-file-panel${i === 0 ? ' active' : ''}" id="${vid}-fp-${i}" data-view="single"><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-${i}">Loading…</div><table class="pv-code-table" id="${vid}-code-${i}" style="display:none"></table></div></div>`;
    });
    demo.sideBySidePairs.forEach((pair, pi) => {
      html += `<div class="pv-file-panel" id="${vid}-fp-pair${pi}" data-view="pair"><div class="pv-side-by-side"><div class="pv-side-col"><div class="pv-side-col-header left-col">${escapeHtml(pair.leftLabel)}</div><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-pair${pi}-left">Loading…</div><table class="pv-code-table" id="${vid}-code-pair${pi}-left" style="display:none"></table></div></div><div class="pv-side-col"><div class="pv-side-col-header right-col">${escapeHtml(pair.rightLabel)}</div><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-pair${pi}-right">Loading…</div><table class="pv-code-table" id="${vid}-code-pair${pi}-right" style="display:none"></table></div></div></div></div>`;
    });
  } else if (hasSideBySide && files.length === 2) {
    const ll = demo.sideBySideLabels || [files[0].name, files[1].name];
    html += '<div class="pv-file-tabs">';
    files.forEach((f, i) => {
      html += `<button class="pv-file-tab" data-viewer="${vid}" data-fi="${i}" data-view="single" onclick="switchPolicyView('${vid}', 'single', ${i})">${escapeHtml(f.name)}</button>`;
    });
    html += `<button class="pv-file-tab active" data-viewer="${vid}" data-fi="sbs" data-view="sbs" onclick="switchPolicyView('${vid}', 'sbs', 0)">⇔ Side by Side</button>`;
    html += '</div>';
    files.forEach((f, i) => {
      html += `<div class="pv-file-panel" id="${vid}-fp-${i}" data-view="single"><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-${i}">Loading…</div><table class="pv-code-table" id="${vid}-code-${i}" style="display:none"></table></div></div>`;
    });
    html += `<div class="pv-file-panel active" id="${vid}-fp-sbs" data-view="sbs"><div class="pv-side-by-side"><div class="pv-side-col"><div class="pv-side-col-header left-col">${escapeHtml(ll[0])}</div><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-sbs-left">Loading…</div><table class="pv-code-table" id="${vid}-code-sbs-left" style="display:none"></table></div></div><div class="pv-side-col"><div class="pv-side-col-header right-col">${escapeHtml(ll[1])}</div><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-sbs-right">Loading…</div><table class="pv-code-table" id="${vid}-code-sbs-right" style="display:none"></table></div></div></div></div>`;
  } else {
    if (fileCount > 1) {
      html += '<div class="pv-file-tabs">';
      files.forEach((f, i) => {
        html += `<button class="pv-file-tab${i === 0 ? ' active' : ''}" data-viewer="${vid}" data-fi="${i}" data-view="single" onclick="switchPolicyView('${vid}', 'single', ${i})">${escapeHtml(f.name)}</button>`;
      });
      html += '</div>';
    }
    files.forEach((f, i) => {
      html += `<div class="pv-file-panel${i === 0 ? ' active' : ''}" id="${vid}-fp-${i}" data-view="single"><div class="pv-code-wrap"><div class="pv-loading" id="${vid}-loading-${i}">Loading…</div><table class="pv-code-table" id="${vid}-code-${i}" style="display:none"></table></div></div>`;
    });
  }

  html += '</div></div>';
  return html;
}

function togglePolicyViewer(vid) {
  const content = document.getElementById(vid);
  const toggle = content.parentElement.querySelector('.pv-toggle');
  const isOpen = content.classList.toggle('open');
  toggle.classList.toggle('open', isOpen);

  if (isOpen && !content.dataset.loaded) {
    content.dataset.loaded = '1';
    const DEMOS = window.DEMOS;
    const demo = DEMOS.find(d => `pv-${d.id}` === vid);
    if (!demo) return;
    demo.policyFiles.forEach((f, i) => loadPolicyFile(vid, `${i}`, f.file, f.lang));
    if (demo.sideBySide && demo.sideBySidePairs) {
      demo.sideBySidePairs.forEach((pair, pi) => {
        loadPolicyFile(vid, `pair${pi}-left`, demo.policyFiles[pair.leftIdx].file, demo.policyFiles[pair.leftIdx].lang);
        loadPolicyFile(vid, `pair${pi}-right`, demo.policyFiles[pair.rightIdx].file, demo.policyFiles[pair.rightIdx].lang);
      });
    } else if (demo.sideBySide && demo.policyFiles.length === 2) {
      loadPolicyFile(vid, 'sbs-left', demo.policyFiles[0].file, demo.policyFiles[0].lang);
      loadPolicyFile(vid, 'sbs-right', demo.policyFiles[1].file, demo.policyFiles[1].lang);
    }
  }
}

function switchPolicyView(vid, view, idx) {
  const content = document.getElementById(vid);
  content.querySelectorAll('.pv-file-tab').forEach(t => t.classList.remove('active'));
  content.querySelectorAll('.pv-file-panel').forEach(p => p.classList.remove('active'));

  if (view === 'single') {
    const tab = content.querySelector(`.pv-file-tab[data-fi="${idx}"][data-view="single"]`);
    const panel = document.getElementById(`${vid}-fp-${idx}`);
    if (tab) tab.classList.add('active');
    if (panel) panel.classList.add('active');
  } else if (view === 'sbs') {
    const tab = content.querySelector('.pv-file-tab[data-fi="sbs"]');
    const panel = document.getElementById(`${vid}-fp-sbs`);
    if (tab) tab.classList.add('active');
    if (panel) panel.classList.add('active');
  } else if (view === 'pair') {
    const tab = content.querySelector(`.pv-file-tab[data-fi="pair${idx}"]`);
    const panel = document.getElementById(`${vid}-fp-pair${idx}`);
    if (tab) tab.classList.add('active');
    if (panel) panel.classList.add('active');
  }
}

async function loadPolicyFile(vid, suffix, filename, lang) {
  const loading = document.getElementById(`${vid}-loading-${suffix}`);
  const table = document.getElementById(`${vid}-code-${suffix}`);
  if (!loading || !table) return;

  try {
    const content = await fetchText(`policies/${filename}`);
    const lines = content.split('\n');
    const highlighter = lang === 'cedar' ? highlightCedar : lang === 'rego' ? highlightRego : highlightJsonLine;
    let tbody = '';
    lines.forEach((line, i) => {
      tbody += `<tr><td class="pv-line-num">${i + 1}</td><td class="pv-line-code">${highlighter(line)}</td></tr>`;
    });
    table.innerHTML = `<tbody>${tbody}</tbody>`;
    loading.style.display = 'none';
    table.style.display = 'table';
  } catch (err) {
    loading.textContent = `Error: ${err.message}`;
    loading.style.color = 'var(--danger)';
  }
}

// ═══════════════════════════════════════════════════════════
//  COMPILATION HELPERS
// ═══════════════════════════════════════════════════════════

/**
 * Compile a program from a compile spec.
 * Returns a wasm Program object.
 */
async function compileProgram(spec, entryPoint) {
  if (spec.type === 'rego') {
    const modules = [];
    for (const filePath of spec.files) {
      const content = await fetchText(filePath);
      const id = filePath.split('/').pop();
      modules.push({ id, content });
    }
    return wasm.Program.compileFromModules(
      '{}',
      JSON.stringify(modules),
      JSON.stringify([entryPoint]),
    );
  } else if (spec.type === 'cedar') {
    const policies = [];
    for (const filePath of spec.policies) {
      const content = await fetchText(filePath);
      const id = filePath.split('/').pop();
      policies.push({ id, content });
    }
    const program = wasm.Program.compileCedarPolicies(JSON.stringify(policies));
    // If there are entities, store them for later use in the config
    if (spec.entities) {
      program._entitiesFile = spec.entities;
    }
    return program;
  } else if (spec.type === 'azure') {
    const defnContent = await fetchText(spec.definition);
    let aliasMap = null;
    if (spec.aliases) {
      aliasMap = await fetchText(spec.aliases);
    }
    return wasm.Program.compileAzurePolicyDefinition(defnContent, aliasMap);
  }
  throw new Error(`Unknown compile type: ${spec.type}`);
}

/**
 * Build the config JSON for analysis, loading referenced files.
 * For Cedar programs with entities, injects them as concrete_input.
 */
async function buildConfigJson(config, program) {
  const cfg = {};
  if (config.max_loop_depth != null) cfg.max_loop_depth = config.max_loop_depth;
  if (config.timeout_ms != null) cfg.timeout_ms = config.timeout_ms;

  if (config.example_input) {
    const content = await fetchText(config.example_input);
    cfg.example_input = JSON.parse(content);
  }
  if (config.input_schema) {
    const content = await fetchText(config.input_schema);
    cfg.input_schema = JSON.parse(content);
  }
  if (config.concrete_input) {
    cfg.concrete_input = {};
    for (const [key, filePath] of Object.entries(config.concrete_input)) {
      const content = await fetchText(filePath);
      cfg.concrete_input[key] = JSON.parse(content);
    }
  }
  // Cedar entities → concrete_input so the translator treats them as concrete.
  if (program && program._entitiesFile) {
    if (!cfg.concrete_input) cfg.concrete_input = {};
    const content = await fetchText(program._entitiesFile);
    cfg.concrete_input.entities = JSON.parse(content);
  }
  if (config.fetch_input_path) {
    cfg.fetch_input_path = config.fetch_input_path;
  }
  if (config.cover_lines) {
    cfg.cover_lines = config.cover_lines;
  }
  if (config.avoid_lines) {
    cfg.avoid_lines = config.avoid_lines;
  }
  return JSON.stringify(cfg);
}

/**
 * Build data JSON for a program.
 */
async function buildDataJson(program) {
  return '{}';
}

// ═══════════════════════════════════════════════════════════
//  STEP EXECUTION
// ═══════════════════════════════════════════════════════════
async function runStep(actId, stepIdx) {
  const DEMOS = window.DEMOS;
  const demo = DEMOS.find(d => d.id === actId);
  const step = demo.steps[stepIdx];
  const stepId = `${actId}-${stepIdx}`;
  const btn = document.getElementById(`btn-${stepId}`);
  const status = document.getElementById(`status-${stepId}`);
  const outputDiv = document.getElementById(`output-${stepId}`);
  const pre = document.getElementById(`pre-${stepId}`);
  const insightEl = document.getElementById(`insight-${stepId}`);

  btn.disabled = true;
  btn.classList.add('running');
  btn.innerHTML = '<span class="spinner"></span> Running…';
  status.textContent = '';
  status.className = 'status-text';
  outputDiv.classList.remove('visible');
  if (insightEl) insightEl.style.display = 'none';

  // Hide post-fetch areas
  if (step.postFetch) {
    for (const t of step.postFetch) {
      const pf = document.getElementById(`output-${stepId}-${t}`);
      if (pf) pf.style.display = 'none';
    }
  }

  const t0 = performance.now();

  try {
    if (!wasm) throw new Error('WASM not loaded yet. Please wait for initialization.');

    let output;
    let smtText = null;
    let modelText = null;

    if (step.op === 'analyze' || step.op === 'smt-dump') {
      output = await executeAnalyze(step);
      smtText = output._smtText || null;
      if (step.op === 'smt-dump') {
        modelText = output._modelText;
      }
    } else if (step.op === 'diff') {
      output = await executeDiff(step);
      smtText = output._smtText || null;
    } else if (step.op === 'subsumes') {
      output = await executeSubsumes(step);
      smtText = output._smtText || null;
    } else if (step.op === 'gen-tests') {
      output = await executeGenTests(step);
      smtText = output._smtText || null;
    } else {
      throw new Error(`Unknown operation: ${step.op}`);
    }

    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);
    const outputText = typeof output === 'string' ? output : (output._displayText || JSON.stringify(output, null, 2));

    pre.innerHTML = applyKeywordHighlights(highlightOutput(outputText), step.highlights);
    outputDiv.classList.add('visible');

    status.textContent = `✓ Done in ${elapsed}s`;
    status.className = 'status-text success';
    if (insightEl) insightEl.style.display = 'block';

    // Always populate the per-step SMT viewer (hidden until toggled)
    if (smtText) {
      const smtDiv = document.getElementById(`smt-${stepId}`);
      const smtPre = document.getElementById(`pre-smt-${stepId}`);
      if (smtDiv && smtPre) {
        smtPre.innerHTML = highlightSMT(smtText);
        // Keep hidden — user can toggle via the Show SMT button
      }
    }

    // Show SMT / model for smt-dump
    if (step.postFetch && smtText != null) {
      showPostFetch(stepId, 'smt', smtText);
      if (modelText) showPostFetch(stepId, 'model', modelText);
    }
  } catch (err) {
    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);
    const errMsg = err instanceof Error ? err.message : String(err);
    const errStack = err instanceof Error ? (err.stack || '') : '';
    pre.innerHTML = escapeHtml(`Error: ${errMsg}\n\n${errStack}`);
    outputDiv.classList.add('visible');
    status.textContent = `✗ Error (${elapsed}s)`;
    status.className = 'status-text error';
    console.error('Step error:', err);
  }

  btn.disabled = false;
  btn.classList.remove('running');
  btn.innerHTML = '▶ Run';
}

function showPostFetch(stepId, type, content) {
  const id = `${stepId}-${type}`;
  const outputDiv = document.getElementById(`output-${id}`);
  const pre = document.getElementById(`pre-${id}`);
  if (outputDiv && pre) {
    pre.innerHTML = highlightSMT(content);
    outputDiv.style.display = 'block';
    outputDiv.classList.add('visible');
  }
}

// ── Analyze ─────────────────────────────────────────────
async function executeAnalyze(step) {
  const program = await compileProgram(step.compile, step.entryPoint);
  const dataJson = await buildDataJson(program);
  const configJson = await buildConfigJson(step.config, program);

  const hasLines = step.config && (step.config.cover_lines || step.config.avoid_lines);
  let goal;
  if (step.desiredOutput && hasLines) {
    goal = 'output-and-cover';
  } else if (step.desiredOutput) {
    goal = 'expected';
  } else {
    goal = step.goal || 'non-default';
  }
  const problem = wasm.prepareForGoal(
    program, dataJson, step.entryPoint, goal,
    step.desiredOutput || undefined, configJson,
  );

  const smtText = problem.smtLib2();
  const warnings = problem.warnings();
  const numExtractions = countExtractions(smtText);

  const solutionJson = await solveSmtLib2(smtText, numExtractions);
  const resultJson = problem.interpretSolution(solutionJson);
  const result = JSON.parse(resultJson);

  // Format output similar to CLI
  const outputText = formatAnalysisResult(result, warnings);

  if (step.op === 'smt-dump') {
    return {
      _displayText: outputText,
      _smtText: smtText,
      _modelText: result.model_string || '(no model)',
    };
  }

  return { _displayText: outputText, _smtText: smtText };
}

// ── Diff ────────────────────────────────────────────────
async function executeDiff(step) {
  const program1 = await compileProgram(step.compile1, step.entryPoint);
  const program2 = await compileProgram(step.compile2, step.entryPoint);
  const dataJson = await buildDataJson(program1);
  const configJson = await buildConfigJson(step.config, program1);

  const desiredOutput = step.desiredOutput || null;
  const problem = wasm.preparePolicyDiff(
    program1, program2, dataJson, step.entryPoint, desiredOutput, configJson
  );

  const smtText = problem.smtLib2();
  const warnings = problem.warnings();
  const numExtractions = countExtractions(smtText);

  const solutionJson = await solveSmtLib2(smtText, numExtractions);
  const resultJson = problem.interpretSolution(solutionJson);
  const result = JSON.parse(resultJson);

  return { _displayText: formatDiffResult(result, warnings), _smtText: smtText };
}

// ── Subsumes ────────────────────────────────────────────
async function executeSubsumes(step) {
  const oldProgram = await compileProgram(step.compileOld, step.entryPoint);
  const newProgram = await compileProgram(step.compileNew, step.entryPoint);
  const dataJson = await buildDataJson(oldProgram);
  const configJson = await buildConfigJson(step.config, oldProgram);

  const problem = wasm.preparePolicySubsumes(
    oldProgram, newProgram, dataJson, step.entryPoint,
    step.desiredOutput, configJson
  );

  const smtText = problem.smtLib2();
  const warnings = problem.warnings();
  const numExtractions = countExtractions(smtText);

  const solutionJson = await solveSmtLib2(smtText, numExtractions);
  const resultJson = problem.interpretSolution(solutionJson);
  const result = JSON.parse(resultJson);

  return { _displayText: formatSubsumesResult(result, warnings), _smtText: smtText };
}

// ── Gen-Tests ───────────────────────────────────────────
async function executeGenTests(step) {
  const program = await compileProgram(step.compile, step.entryPoint);
  const dataJson = await buildDataJson(program);
  const configJson = await buildConfigJson(step.config, program);
  const desiredOutput = step.desiredOutput || null;
  const maxTests = step.maxTests || 10;
  const conditionCoverage = step.conditionCoverage || false;

  // Fetch policy source text for annotated output.
  const sourceCache = {};
  if (step.compile.type === 'rego' && step.compile.files) {
    for (const filePath of step.compile.files) {
      const content = await fetchText(filePath);
      const id = filePath.split('/').pop();
      sourceCache[id] = content.split('\n');
    }
  }

  const suite = wasm.prepareTestSuite(
    program, dataJson, desiredOutput, step.entryPoint, configJson, maxTests, conditionCoverage
  );

  const testCases = [];
  const smtTexts = [];
  let iteration = 0;
  while (true) {
    const problem = suite.nextProblem();
    if (!problem) break;
    iteration++;

    const smtText = problem.smtLib2();
    smtTexts.push(smtText);
    const numExtractions = countExtractions(smtText);
    const solutionJson = await solveSmtLib2(smtText, numExtractions);
    const tcJson = suite.recordSolution(solutionJson);
    const tc = JSON.parse(tcJson);
    if (tc.satisfiable) {
      testCases.push(tc);
    }
  }

  const resultJson = suite.getResult();
  const result = JSON.parse(resultJson);
  // Collect all SMT texts from iterations
  const allSmt = smtTexts.join('\n\n;; --- next problem ---\n\n');
  return { _displayText: formatGenTestsResult(result, testCases, sourceCache), _smtText: allSmt || null };
}

// ═══════════════════════════════════════════════════════════
//  RESULT FORMATTING
// ═══════════════════════════════════════════════════════════

function formatAnalysisResult(result, _warnings) {
  const parts = [];

  if (result.satisfiable === true) {
    parts.push('Result: SATISFIABLE');
    if (result.input) {
      parts.push('');
      parts.push('Synthesized input:');
      try {
        const parsed = JSON.parse(result.input);
        parts.push(JSON.stringify(parsed, null, 2));
      } catch {
        parts.push(result.input);
      }
    }
  } else if (result.satisfiable === false) {
    parts.push('Result: UNSATISFIABLE');
    parts.push('No input exists that produces the desired output.');
  } else {
    parts.push('Result: UNKNOWN');
    parts.push('The solver could not determine satisfiability.');
  }

  return parts.join('\n');
}

function formatDiffResult(result, _warnings) {
  const parts = [];

  if (result.satisfiable === true) {
    parts.push('Result: NOT EQUIVALENT');
    parts.push('The two policies disagree on the following input:');
    if (result.input) {
      parts.push('');
      try {
        const parsed = JSON.parse(result.input);
        parts.push(JSON.stringify(parsed, null, 2));
      } catch {
        parts.push(result.input);
      }
    }
  } else if (result.satisfiable === false) {
    parts.push('Result: EQUIVALENT');
    parts.push('The two policies produce the same output for all inputs.');
  } else {
    parts.push('Result: UNKNOWN');
    parts.push('The solver could not determine equivalence.');
  }

  return parts.join('\n');
}

function formatGenTestsResult(result, _testCases, sourceCache) {
  sourceCache = sourceCache || {};
  const parts = [];
  const pct = result.coverable_lines > 0
    ? ((result.covered_lines / result.coverable_lines) * 100).toFixed(0)
    : 0;
  parts.push(`# Coverage: ${result.covered_lines}/${result.coverable_lines} lines (${pct}%)`);

  if (result.condition_goals > 0) {
    const condPct = ((result.condition_goals_covered / result.condition_goals) * 100).toFixed(0);
    parts.push(`# Conditions: ${result.condition_goals_covered}/${result.condition_goals} goals (${condPct}%)`);
  }
  parts.push(`# Tests: ${result.test_cases.length}`);
  parts.push('');

  // Collect all files referenced and all condition lines across all tests.
  const allFiles = Object.keys(sourceCache).sort();
  const allConditionLines = new Set();
  for (const tc of result.test_cases) {
    if (tc.condition_coverage) {
      for (const [loc] of tc.condition_coverage) {
        const idx = loc.lastIndexOf(':');
        if (idx > 0) allConditionLines.add(loc);
      }
    }
  }

  for (let i = 0; i < result.test_cases.length; i++) {
    const tc = result.test_cases[i];

    // Build lookup sets for this test case.
    const coveredSet = new Set();
    if (tc.covered_lines) {
      for (const [f, l] of tc.covered_lines) coveredSet.add(`${f}:${l}`);
    }
    const condMap = new Map();
    if (tc.condition_coverage) {
      for (const [loc, val] of tc.condition_coverage) condMap.set(loc, val);
    }

    // Determine test label like the Rust CLI.
    const falseConds = (tc.condition_coverage || []).filter(([, val]) => !val);
    let testLabel;
    if (falseConds.length === 0) {
      testLabel = 'line coverage';
    } else {
      testLabel = falseConds.map(([loc, , expr]) => {
        const exprText = expr ? ` \`${expr}\`` : '';
        return `${loc}${exprText} = false`;
      }).join(', ');
    }

    parts.push(`== Test ${i + 1} (${testLabel}) ==`);
    parts.push(`Input:`);
    try {
      const parsed = JSON.parse(tc.input);
      parts.push(JSON.stringify(parsed, null, 2));
    } catch {
      parts.push(tc.input);
    }
    parts.push('');

    // Print annotated source listing if we have source text.
    if (allFiles.length > 0) {
      for (const file of allFiles) {
        const lines = sourceCache[file];
        if (!lines) continue;
        for (let li = 0; li < lines.length; li++) {
          const lineNo = li + 1;
          const key = `${file}:${lineNo}`;
          let marker;
          if (condMap.has(key)) {
            marker = condMap.get(key) ? 'true ' : 'false';
          } else if (allConditionLines.has(key) && coveredSet.has(key)) {
            // Condition line that was covered (assertion passed) → condition was true.
            marker = 'true ';
          } else {
            marker = '     ';
          }
          const lineNumStr = String(lineNo).padStart(4);
          parts.push(`${marker} ${lineNumStr} | ${lines[li]}`);
        }
      }
    } else {
      // Fallback: no source text available, just show line refs.
      if (tc.covered_lines && tc.covered_lines.length > 0) {
        const lineRefs = tc.covered_lines.map(([f, l]) => `${f}:${l}`).join(', ');
        parts.push(`Covers ${tc.covered_lines.length} line(s): ${lineRefs}`);
      }
      if (tc.condition_coverage && tc.condition_coverage.length > 0) {
        const condParts = tc.condition_coverage.map(([loc, val, expr]) => {
          const exprText = expr ? ` \`${expr}\`` : '';
          return `${loc}${exprText} = ${val ? 'true' : 'false'}`;
        });
        parts.push(`Conditions: ${condParts.join(', ')}`);
      }
    }
    parts.push('');
  }

  return parts.join('\n');
}

function formatSubsumesResult(result, _warnings) {
  const parts = [];

  // For subsumption: SAT means counterexample found (doesn't subsume)
  // UNSAT means subsumption holds
  if (result.satisfiable === true) {
    parts.push('Result: DOES NOT SUBSUME');
    parts.push('Counterexample found — an input where old policy fires but new policy does not:');
    if (result.input) {
      parts.push('');
      try {
        const parsed = JSON.parse(result.input);
        parts.push(JSON.stringify(parsed, null, 2));
      } catch {
        parts.push(result.input);
      }
    }
  } else if (result.satisfiable === false) {
    parts.push('Result: SUBSUMES');
    parts.push('Proved: for all inputs, if the old policy produces the desired output, the new policy does too.');
  } else {
    parts.push('Result: UNKNOWN');
    parts.push('The solver could not determine subsumption.');
  }

  return parts.join('\n');
}

// ═══════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════

/**
 * Count the number of (get-value ...) extractions in SMT text.
 * Each variable in the get-value list counts as one extraction.
 */
function countExtractions(smtText) {
  const match = smtText.match(/\(get-value\s*\(([^)]*)\)\)/);
  if (!match) return 0;
  const vars = match[1].trim().split(/\s+/).filter(s => s.length > 0);
  return vars.length;
}

async function runAll(actId) {
  const DEMOS = window.DEMOS;
  const demo = DEMOS.find(d => d.id === actId);
  const allBtn = document.querySelector(`.btn-run-all[data-act="${actId}"]`);
  const progress = document.getElementById(`progress-${actId}`);

  allBtn.disabled = true;
  allBtn.innerHTML = '<span class="spinner"></span> Running…';

  for (let i = 0; i < demo.steps.length; i++) {
    progress.textContent = `Step ${i + 1} of ${demo.steps.length}…`;
    await runStep(actId, i);
  }

  progress.textContent = `All ${demo.steps.length} steps complete ✓`;
  allBtn.disabled = false;
  allBtn.innerHTML = '▶ Run All Steps';
}

function copyOutput(stepId) {
  const pre = document.getElementById(`pre-${stepId}`);
  navigator.clipboard.writeText(pre.textContent).then(() => {
    const container = pre.closest('.demo-output') || pre.closest('.smt-viewer') || pre.closest('.postfetch-area');
    const btn = container.querySelector('.btn-sm');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1200);
  });
}

function toggleOutput(stepId) {
  const outputDiv = document.getElementById(`output-${stepId}`);
  outputDiv.classList.toggle('visible');
}

function toggleSmt(stepId) {
  const smtDiv = document.getElementById(`smt-${stepId}`);
  if (!smtDiv) return;
  const visible = smtDiv.style.display !== 'none';
  smtDiv.style.display = visible ? 'none' : 'block';
  smtDiv.classList.toggle('visible', !visible);
  const btn = document.getElementById(`btn-smt-${stepId}`);
  if (btn) btn.textContent = visible ? 'Show SMT' : 'Hide SMT';
}

// ═══════════════════════════════════════════════════════════
//  PLAYGROUND
// ═══════════════════════════════════════════════════════════

const PG_SAMPLES = {
  rego: {
    policy1: `package access_control

default allow := false

# Managers can access anything at any time
allow if {
    input.user.role == "manager"
}

# Regular employees: business hours only
allow if {
    input.user.role == "employee"
    input.request.hour >= 9
    input.request.hour < 17
}

# Interns: non-sensitive resources, business hours only
allow if {
    input.user.role == "intern"
    input.resource.sensitivity != "high"
    input.request.hour >= 9
    input.request.hour < 17
}`,
    policy2: `package access_control

default allow := false

# Bug fix: suspended users are always denied
allow if {
    not input.user.suspended
    input.user.role == "manager"
}

allow if {
    not input.user.suspended
    input.user.role == "employee"
    input.request.hour >= 9
    input.request.hour < 17
}

allow if {
    not input.user.suspended
    input.user.role == "intern"
    input.resource.sensitivity != "high"
    input.request.hour >= 9
    input.request.hour < 17
}`,
    entrypoint: 'data.access_control.allow',
    schema: JSON.stringify({
      type: "object",
      properties: {
        user: {
          type: "object",
          properties: {
            role: { type: "string", enum: ["manager", "employee", "intern"] },
            suspended: { type: "boolean" }
          }
        },
        resource: {
          type: "object",
          properties: {
            sensitivity: { type: "string", enum: ["high", "low", "public"] }
          }
        },
        request: {
          type: "object",
          properties: {
            hour: { type: "integer", minimum: 0, maximum: 23 }
          }
        }
      }
    }, null, 2),
  },
  cedar: {
    policy1: `// Doctors can view patient records during business hours
permit(
  principal in Role::"doctor",
  action == Action::"view",
  resource in ResourceType::"patient_record"
) when {
  context.hour >= 8 && context.hour < 18 &&
  context.device_trusted == true
};

// Nurses can view non-VIP records during business hours
permit(
  principal in Role::"nurse",
  action == Action::"view",
  resource in ResourceType::"patient_record"
) when {
  context.hour >= 8 && context.hour < 18 &&
  resource.vip == false
};

// Nobody can delete patient records
forbid(
  principal,
  action == Action::"delete",
  resource in ResourceType::"patient_record"
);`,
    policy2: '',
    entrypoint: 'cedar.authorize',
    entities: JSON.stringify([
      { uid: { type: "Role", id: "doctor" }, parents: [{ type: "Role", id: "staff" }], attrs: {} },
      { uid: { type: "Role", id: "nurse" }, parents: [{ type: "Role", id: "staff" }], attrs: {} },
      { uid: { type: "Role", id: "staff" }, parents: [], attrs: {} },
      { uid: { type: "ResourceType", id: "patient_record" }, parents: [], attrs: {} },
    ], null, 2),
    schema: '',
  },
  azure: {
    policy1: JSON.stringify({
      properties: {
        displayName: "Require HTTPS for Storage Accounts",
        policyType: "Custom",
        mode: "All",
        parameters: {},
        policyRule: {
          if: {
            allOf: [
              { field: "type", equals: "Microsoft.Storage/storageAccounts" },
              {
                anyOf: [
                  { field: "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", notEquals: "true" },
                  { field: "Microsoft.Storage/storageAccounts/minimumTlsVersion", notEquals: "TLS1_2" }
                ]
              }
            ]
          },
          then: { effect: "deny" }
        }
      }
    }, null, 2),
    policy2: '',
    entrypoint: 'main',
    schema: JSON.stringify({
      type: "object",
      properties: {
        type: { type: "string" },
        properties: {
          type: "object",
          properties: {
            supportsHttpsTrafficOnly: { type: "string", enum: ["true", "false"] },
            minimumTlsVersion: { type: "string", enum: ["TLS1_0", "TLS1_1", "TLS1_2"] }
          }
        }
      }
    }, null, 2),
  },
};

function buildPlayground() {
  return `<div class="act-header">
    <h2>🔬 Playground</h2>
    <div class="subtitle">Paste your own policy and analyze it with Z3. Supports Rego, Cedar, and Azure Policy.</div>
  </div>

  <!-- Compact toolbar: language + entrypoint + target -->
  <div class="pg-toolbar">
    <div class="pg-lang-radio" id="pg-lang">
      <label class="pg-radio active"><input type="radio" name="pg-lang" value="rego" checked> Rego</label>
      <label class="pg-radio"><input type="radio" name="pg-lang" value="cedar"> Cedar</label>
      <label class="pg-radio"><input type="radio" name="pg-lang" value="azure"> Azure Policy</label>
    </div>
    <div class="pg-toolbar-sep"></div>
    <label class="pg-toolbar-label">Entry</label>
    <input id="pg-entrypoint" class="pg-toolbar-input pg-toolbar-ep" type="text" value="data.policy.allow" placeholder="data.package.rule" spellcheck="false">
    <label class="pg-toolbar-label">→</label>
    <div class="pg-target-row">
      <label class="pg-radio active"><input type="radio" name="pg-target" value="false" checked> false</label>
      <label class="pg-radio"><input type="radio" name="pg-target" value="true"> true</label>
      <label class="pg-radio"><input type="radio" name="pg-target" value="custom"> custom:</label>
      <input id="pg-target-custom" class="pg-toolbar-input pg-toolbar-custom" type="text" placeholder='"deny"' spellcheck="false" disabled>
    </div>
    <div class="pg-toolbar-sep"></div>
    <label class="pg-toolbar-label">Loops</label>
    <input id="pg-max-loops" class="pg-toolbar-input pg-toolbar-loops" type="number" value="3" min="1" max="5">
  </div>

  <!-- Side-by-side: left = editors, right = result -->
  <div class="pg-split">

    <!-- LEFT PANE: editors + config + actions -->
    <div class="pg-left">
      <div class="pg-section">
        <div class="pg-section-header">
          Policy 1
          <button class="btn-sm pg-clear-btn" onclick="pgClearEditor('pg-policy1')">Clear</button>
        </div>
        <div class="pg-editor-wrap">
          <pre class="pg-highlight" id="pg-hl-policy1" aria-hidden="true"></pre>
          <textarea id="pg-policy1" class="pg-editor pg-editor-overlay" spellcheck="false" placeholder="Paste your policy here…"></textarea>
        </div>
      </div>

      <div class="pg-section">
        <button class="pg-collapse-toggle" id="pg-p2-toggle" onclick="pgTogglePanel('pg-p2-panel', 'pg-p2-toggle')">
          ▸ Policy 2 <span class="pg-hint">(for Diff / Subsumes)</span>
        </button>
        <div id="pg-p2-panel" class="pg-collapsible">
          <div class="pg-editor-wrap">
            <pre class="pg-highlight" id="pg-hl-policy2" aria-hidden="true"></pre>
            <textarea id="pg-policy2" class="pg-editor pg-editor-overlay" spellcheck="false" placeholder="Paste second policy…"></textarea>
          </div>
        </div>
      </div>

      <div class="pg-section">
        <button class="pg-collapse-toggle" id="pg-extra-toggle" onclick="pgTogglePanel('pg-extra-panel', 'pg-extra-toggle')">
          ▸ Schema &amp; Input <span class="pg-hint">(optional)</span>
        </button>
        <div id="pg-extra-panel" class="pg-collapsible">
          <div class="pg-config-grid">
            <div class="pg-field pg-field-wide">
              <label for="pg-schema">Input Schema (JSON)</label>
              <div class="pg-editor-wrap pg-editor-wrap-sm">
                <pre class="pg-highlight" id="pg-hl-schema" aria-hidden="true"></pre>
                <textarea id="pg-schema" class="pg-editor pg-editor-sm pg-editor-overlay" spellcheck="false" placeholder='{"type":"object","properties":{...}}'></textarea>
              </div>
            </div>

            <div class="pg-field pg-field-wide" id="pg-entities-field" style="display:none">
              <label for="pg-entities">Entities (Cedar JSON)</label>
              <div class="pg-editor-wrap pg-editor-wrap-sm">
                <pre class="pg-highlight" id="pg-hl-entities" aria-hidden="true"></pre>
                <textarea id="pg-entities" class="pg-editor pg-editor-sm pg-editor-overlay" spellcheck="false" placeholder='[{"uid":{...},...}]'></textarea>
              </div>
            </div>
            <div class="pg-field pg-field-wide" id="pg-aliases-field" style="display:none">
              <label for="pg-aliases">Azure Policy Aliases (JSON)</label>
              <div class="pg-editor-wrap pg-editor-wrap-sm">
                <pre class="pg-highlight" id="pg-hl-aliases" aria-hidden="true"></pre>
                <textarea id="pg-aliases" class="pg-editor pg-editor-sm pg-editor-overlay" spellcheck="false" placeholder='{"Microsoft.Storage/...":...}'></textarea>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="pg-action-bar">
        <button class="btn btn-run pg-btn" id="pg-btn-analyze" onclick="pgRun('analyze')">▶ Analyze</button>
        <button class="btn btn-run pg-btn" id="pg-btn-diff" onclick="pgRun('diff')">▶ Diff</button>
        <button class="btn btn-run pg-btn" id="pg-btn-subsumes" onclick="pgRun('subsumes')">▶ Subsumes</button>
        <button class="btn btn-run pg-btn" id="pg-btn-gentests" onclick="pgRun('gen-tests')">▶ Gen Tests</button>
        <span class="status-text" id="pg-status"></span>
      </div>
    </div>

    <!-- RIGHT PANE: result + SMT -->
    <div class="pg-right">
      <div class="pg-section-header">Result</div>
      <div class="pg-result-area">
        <div class="demo-output pg-result-output" id="output-pg-result">
          <div class="output-toolbar">
            <span class="label">Output</span>
            <button class="btn-sm" onclick="copyOutput('pg-result')">Copy</button>
          </div>
          <div class="output-body"><pre id="pre-pg-result" class="pg-result-pre"></pre></div>
        </div>
        <div class="pg-result-placeholder" id="pg-result-placeholder">
          <div class="pg-placeholder-icon">⚡</div>
          <div>Click <strong>Analyze</strong> to synthesize an input,<br>
          <strong>Diff</strong> to compare two policies, or<br>
          <strong>Gen Tests</strong> for coverage.</div>
        </div>
      </div>
      <div class="pg-smt-bar">
        <button class="btn btn-smt" id="pg-btn-smt" onclick="pgToggleSmt()">Show SMT</button>
      </div>
      <div class="smt-viewer" id="smt-pg" style="display:none">
        <div class="output-toolbar">
          <span class="label" style="color:var(--magenta)">SMT-LIB Encoding</span>
          <button class="btn-sm" onclick="copyOutput('smt-pg-content')">Copy</button>
          <button class="btn-sm" onclick="pgToggleSmt()">Hide</button>
        </div>
        <div class="output-body" style="max-height:400px"><pre id="pre-smt-pg-content"></pre></div>
      </div>
    </div>

  </div>`;
}

// ── Playground initialization (called once panel is built) ──

// Map textarea ids → highlight pre ids
const PG_HL_MAP = {
  'pg-policy1':      { hl: 'pg-hl-policy1',      langFn: 'policy' },
  'pg-policy2':      { hl: 'pg-hl-policy2',      langFn: 'policy' },
  'pg-schema':       { hl: 'pg-hl-schema',       langFn: 'json' },
  'pg-entities':     { hl: 'pg-hl-entities',      langFn: 'json' },
  'pg-aliases':      { hl: 'pg-hl-aliases',       langFn: 'json' },
};

function pgGetHighlighter(langFnKey) {
  if (langFnKey === 'json') return highlightJsonLine;
  const lang = document.querySelector('input[name="pg-lang"]:checked')?.value || 'rego';
  if (lang === 'cedar') return highlightCedar;
  if (lang === 'azure') return highlightJsonLine;
  return highlightRego;
}

function pgSyncHighlight(textareaId) {
  const ta = document.getElementById(textareaId);
  const info = PG_HL_MAP[textareaId];
  if (!ta || !info) return;
  const pre = document.getElementById(info.hl);
  if (!pre) return;
  const fn = pgGetHighlighter(info.langFn);
  const text = ta.value;
  if (!text) {
    pre.innerHTML = '';
    return;
  }
  const lines = text.split('\n');
  // Highlight each line; add trailing newline so pre height matches textarea
  pre.innerHTML = lines.map(l => fn(l)).join('\n') + '\n';
}

function pgSyncScroll(textareaId) {
  const ta = document.getElementById(textareaId);
  const info = PG_HL_MAP[textareaId];
  if (!ta || !info) return;
  const pre = document.getElementById(info.hl);
  if (!pre) return;
  pre.scrollTop = ta.scrollTop;
  pre.scrollLeft = ta.scrollLeft;
}

function pgSyncAllHighlights() {
  for (const id of Object.keys(PG_HL_MAP)) {
    pgSyncHighlight(id);
  }
}

function pgClearEditor(textareaId) {
  const ta = document.getElementById(textareaId);
  if (ta) ta.value = '';
  pgSyncHighlight(textareaId);
}

function initPlaygroundListeners() {
  // Language radio → show/hide Cedar entities / Azure aliases fields
  const langRadios = document.querySelectorAll('input[name="pg-lang"]');
  langRadios.forEach(r => r.addEventListener('change', () => {
    const lang = document.querySelector('input[name="pg-lang"]:checked').value;
    document.getElementById('pg-entities-field').style.display = lang === 'cedar' ? '' : 'none';
    document.getElementById('pg-aliases-field').style.display = lang === 'azure' ? '' : 'none';
    // Update entrypoint hint
    const ep = document.getElementById('pg-entrypoint');
    if (lang === 'cedar') ep.placeholder = 'cedar.authorize';
    else if (lang === 'azure') ep.placeholder = 'main';
    else ep.placeholder = 'data.package.rule';
    // Style active radio
    document.querySelectorAll('#pg-lang .pg-radio').forEach(l => l.classList.toggle('active', l.querySelector('input').checked));
    // Load sample for the selected language
    pgLoadSample(lang);
  }));

  // Target output radio → enable/disable custom field
  const targetRadios = document.querySelectorAll('input[name="pg-target"]');
  targetRadios.forEach(r => r.addEventListener('change', () => {
    const val = document.querySelector('input[name="pg-target"]:checked').value;
    document.getElementById('pg-target-custom').disabled = val !== 'custom';
    document.querySelectorAll('.pg-target-row .pg-radio').forEach(l => l.classList.toggle('active', l.querySelector('input').checked));
  }));

  // Auto-detect package name from policy text to pre-fill entrypoint
  const p1 = document.getElementById('pg-policy1');
  let debounce = null;
  p1.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const text = p1.value;
      const m = text.match(/^\s*package\s+([\w.]+)/m);
      if (m) {
        const ep = document.getElementById('pg-entrypoint');
        if (ep.dataset.autoFilled) {
          ep.value = `data.${m[1]}.allow`;
        }
      }
    }, 400);
  });

  // Load the Rego sample on first init
  pgLoadSample('rego');

  // Wire up highlighting sync on all editor textareas
  for (const id of Object.keys(PG_HL_MAP)) {
    const ta = document.getElementById(id);
    if (!ta) continue;
    ta.addEventListener('input', () => pgSyncHighlight(id));
    ta.addEventListener('scroll', () => pgSyncScroll(id));
  }

  // Initial highlight sync
  pgSyncAllHighlights();
}

function pgLoadSample(lang) {
  const sample = PG_SAMPLES[lang];
  if (!sample) return;
  document.getElementById('pg-policy1').value = sample.policy1;
  document.getElementById('pg-policy2').value = sample.policy2 || '';
  const ep = document.getElementById('pg-entrypoint');
  ep.value = sample.entrypoint;
  ep.dataset.autoFilled = '1';

  // Optional inputs
  document.getElementById('pg-schema').value = sample.schema || '';
  document.getElementById('pg-entities').value = sample.entities || '';
  document.getElementById('pg-aliases').value = sample.aliases || '';

  // Set target output to false for rego, 1 for cedar, "deny" for azure
  if (lang === 'cedar') {
    // Select "true" radio (maps to 1 internally)
    document.querySelector('input[name="pg-target"][value="true"]').checked = true;
  } else if (lang === 'azure') {
    document.querySelector('input[name="pg-target"][value="custom"]').checked = true;
    const customField = document.getElementById('pg-target-custom');
    customField.disabled = false;
    customField.value = '"deny"';
  } else {
    document.querySelector('input[name="pg-target"][value="false"]').checked = true;
    document.getElementById('pg-target-custom').disabled = true;
  }
  // Update radio active styles
  document.querySelectorAll('.pg-target-row .pg-radio').forEach(l => l.classList.toggle('active', l.querySelector('input').checked));

  // Show/hide optional panels if sample has content
  const extraPanel = document.getElementById('pg-extra-panel');
  const extraToggle = document.getElementById('pg-extra-toggle');
  if (sample.schema || sample.entities) {
    extraPanel.classList.add('open');
    extraToggle.classList.add('open');
    extraToggle.textContent = '▾ Optional inputs';
  }

  // Clear previous results
  document.getElementById('output-pg-result').classList.remove('visible');
  const smtDiv = document.getElementById('smt-pg');
  if (smtDiv) smtDiv.style.display = 'none';

  // Re-sync all highlighting for the new language/content
  pgSyncAllHighlights();
}

let playgroundInitialized = false;

function ensurePlaygroundInit() {
  if (playgroundInitialized) return;
  if (!document.getElementById('pg-policy1')) return;
  playgroundInitialized = true;
  initPlaygroundListeners();
}

// ── Playground execution ────────────────────────────────
async function pgRun(op) {
  ensurePlaygroundInit();
  const status = document.getElementById('pg-status');
  const resultDiv = document.getElementById('output-pg-result');
  const resultPre = document.getElementById('pre-pg-result');

  // Gather inputs
  const lang = document.querySelector('input[name="pg-lang"]:checked').value;
  const policy1 = document.getElementById('pg-policy1').value.trim();
  const policy2 = document.getElementById('pg-policy2').value.trim();
  const entryPoint = document.getElementById('pg-entrypoint').value.trim();
  const maxLoops = parseInt(document.getElementById('pg-max-loops').value) || 3;

  const targetRadio = document.querySelector('input[name="pg-target"]:checked').value;
  let desiredOutput;
  if (targetRadio === 'custom') {
    desiredOutput = document.getElementById('pg-target-custom').value.trim() || null;
  } else {
    desiredOutput = targetRadio;
  }

  // For cedar with output 1/0
  if (lang === 'cedar' && (desiredOutput === 'true' || desiredOutput === null)) {
    desiredOutput = '1';
  } else if (lang === 'cedar' && desiredOutput === 'false') {
    desiredOutput = '0';
  }
  // Azure policy output is typically "deny" or "audit"
  if (lang === 'azure' && desiredOutput === 'false') {
    desiredOutput = '"deny"';
  } else if (lang === 'azure' && desiredOutput === 'true') {
    desiredOutput = '"audit"';
  }

  const schemaText = document.getElementById('pg-schema').value.trim();
  const entitiesText = document.getElementById('pg-entities').value.trim();
  const aliasesText = document.getElementById('pg-aliases').value.trim();

  // Validation
  if (!policy1) { status.textContent = '✗ Policy 1 is empty'; status.className = 'status-text error'; return; }
  if (!entryPoint) { status.textContent = '✗ Entrypoint is empty'; status.className = 'status-text error'; return; }
  if ((op === 'diff' || op === 'subsumes') && !policy2) {
    status.textContent = `✗ Policy 2 is required for ${op}`;
    status.className = 'status-text error';
    return;
  }
  if (!wasm) { status.textContent = '✗ WASM not loaded yet'; status.className = 'status-text error'; return; }

  // Disable buttons, show running state
  const allBtns = document.querySelectorAll('.pg-btn');
  allBtns.forEach(b => { b.disabled = true; });
  const activeBtn = document.getElementById(`pg-btn-${op === 'gen-tests' ? 'gentests' : op}`);
  activeBtn.classList.add('running');
  activeBtn.innerHTML = '<span class="spinner"></span> Running…';
  status.textContent = '';
  status.className = 'status-text';
  resultDiv.classList.remove('visible');

  const t0 = performance.now();

  try {
    // Build compile spec
    const compileSpec = pgBuildCompileSpec(lang, policy1, aliasesText);
    const config = pgBuildConfig(maxLoops, schemaText);

    let output;
    if (op === 'analyze') {
      const program = await pgCompile(compileSpec, entryPoint, entitiesText);
      const configJson = await pgBuildConfigJson(config, program);
      const hasLines = false;
      const goal = desiredOutput ? 'expected' : 'non-default';
      const problem = wasm.prepareForGoal(program, '{}', entryPoint, goal, desiredOutput || undefined, configJson);
      const smtText = problem.smtLib2();
      const warnings = problem.warnings();
      const numExtractions = countExtractions(smtText);
      const solutionJson = await solveSmtLib2(smtText, numExtractions);
      const resultJson = problem.interpretSolution(solutionJson);
      const result = JSON.parse(resultJson);
      output = { _displayText: formatAnalysisResult(result, warnings), _smtText: smtText };

    } else if (op === 'diff') {
      const compileSpec2 = pgBuildCompileSpec(lang, policy2, aliasesText);
      const program1 = await pgCompile(compileSpec, entryPoint, entitiesText);
      const program2 = await pgCompile(compileSpec2, entryPoint, entitiesText);
      const configJson = await pgBuildConfigJson(config, program1);
      const problem = wasm.preparePolicyDiff(program1, program2, '{}', entryPoint, desiredOutput || null, configJson);
      const smtText = problem.smtLib2();
      const warnings = problem.warnings();
      const numExtractions = countExtractions(smtText);
      const solutionJson = await solveSmtLib2(smtText, numExtractions);
      const resultJson = problem.interpretSolution(solutionJson);
      const result = JSON.parse(resultJson);
      output = { _displayText: formatDiffResult(result, warnings), _smtText: smtText };

    } else if (op === 'subsumes') {
      const compileSpec2 = pgBuildCompileSpec(lang, policy2, aliasesText);
      const oldProgram = await pgCompile(compileSpec, entryPoint, entitiesText);
      const newProgram = await pgCompile(compileSpec2, entryPoint, entitiesText);
      const configJson = await pgBuildConfigJson(config, oldProgram);
      const problem = wasm.preparePolicySubsumes(oldProgram, newProgram, '{}', entryPoint, desiredOutput || undefined, configJson);
      const smtText = problem.smtLib2();
      const warnings = problem.warnings();
      const numExtractions = countExtractions(smtText);
      const solutionJson = await solveSmtLib2(smtText, numExtractions);
      const resultJson = problem.interpretSolution(solutionJson);
      const result = JSON.parse(resultJson);
      output = { _displayText: formatSubsumesResult(result, warnings), _smtText: smtText };

    } else if (op === 'gen-tests') {
      const program = await pgCompile(compileSpec, entryPoint, entitiesText);
      const configJson = await pgBuildConfigJson(config, program);
      const suite = wasm.prepareTestSuite(program, '{}', desiredOutput || null, entryPoint, configJson, 10, false);
      const testCases = [];
      const smtTexts = [];
      while (true) {
        const problem = suite.nextProblem();
        if (!problem) break;
        const smtText = problem.smtLib2();
        smtTexts.push(smtText);
        const numExtractions = countExtractions(smtText);
        const solutionJson = await solveSmtLib2(smtText, numExtractions);
        const tcJson = suite.recordSolution(solutionJson);
        const tc = JSON.parse(tcJson);
        if (tc.satisfiable) testCases.push(tc);
      }
      const resultJson = suite.getResult();
      const result = JSON.parse(resultJson);
      const allSmt = smtTexts.join('\n\n;; --- next problem ---\n\n');
      output = { _displayText: formatGenTestsResult(result, testCases, {}), _smtText: allSmt || null };
    }

    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);
    const outputText = output._displayText || JSON.stringify(output, null, 2);
    resultPre.innerHTML = highlightOutput(outputText);
    resultDiv.classList.add('visible');
    const ph = document.getElementById('pg-result-placeholder');
    if (ph) ph.style.display = 'none';
    status.textContent = `✓ Done in ${elapsed}s`;
    status.className = 'status-text success';

    // Populate SMT viewer
    if (output._smtText) {
      document.getElementById('pre-smt-pg-content').innerHTML = highlightSMT(output._smtText);
    }

  } catch (err) {
    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);
    resultPre.innerHTML = escapeHtml(`Error: ${err.message}\n\n${err.stack || ''}`);
    resultDiv.classList.add('visible');
    const ph2 = document.getElementById('pg-result-placeholder');
    if (ph2) ph2.style.display = 'none';
    status.textContent = `✗ Error (${elapsed}s)`;
    status.className = 'status-text error';
    console.error('Playground error:', err);
  }

  // Re-enable buttons
  allBtns.forEach(b => { b.disabled = false; });
  const labels = { analyze: '▶ Analyze', diff: '▶ Diff', subsumes: '▶ Subsumes', 'gen-tests': '▶ Gen Tests' };
  activeBtn.classList.remove('running');
  activeBtn.innerHTML = labels[op];
}

function pgBuildCompileSpec(lang, policyText, aliasesText) {
  if (lang === 'rego') {
    return { type: 'rego', text: policyText };
  } else if (lang === 'cedar') {
    return { type: 'cedar', text: policyText };
  } else if (lang === 'azure') {
    return { type: 'azure', text: policyText, aliasesText };
  }
  throw new Error(`Unknown language: ${lang}`);
}

async function pgCompile(spec, entryPoint, entitiesText) {
  if (spec.type === 'rego') {
    const modules = [{ id: 'playground.rego', content: spec.text }];
    return wasm.Program.compileFromModules('{}', JSON.stringify(modules), JSON.stringify([entryPoint]));
  } else if (spec.type === 'cedar') {
    const policies = [{ id: 'playground.cedar', content: spec.text }];
    const program = wasm.Program.compileCedarPolicies(JSON.stringify(policies));
    if (entitiesText) {
      program._entitiesFile = null;
      program._entitiesJson = entitiesText;
    }
    return program;
  } else if (spec.type === 'azure') {
    return wasm.Program.compileAzurePolicyDefinition(spec.text, spec.aliasesText || null);
  }
  throw new Error(`Unknown compile type: ${spec.type}`);
}

function pgBuildConfig(maxLoops, schemaText) {
  return { maxLoops, schemaText };
}

async function pgBuildConfigJson(config, program) {
  const cfg = {};
  if (config.maxLoops) cfg.max_loop_depth = config.maxLoops;
  if (config.schemaText) {
    cfg.input_schema = JSON.parse(config.schemaText);
  }
  if (program && program._entitiesJson) {
    cfg.concrete_input = { entities: JSON.parse(program._entitiesJson) };
  } else if (program && program._entitiesFile) {
    const content = await fetchText(program._entitiesFile);
    cfg.concrete_input = { entities: JSON.parse(content) };
  }
  return JSON.stringify(cfg);
}

function pgToggleSmt() {
  const smtDiv = document.getElementById('smt-pg');
  if (!smtDiv) return;
  const visible = smtDiv.style.display !== 'none';
  smtDiv.style.display = visible ? 'none' : 'block';
  smtDiv.classList.toggle('visible', !visible);
  const btn = document.getElementById('pg-btn-smt');
  if (btn) btn.textContent = visible ? 'Show SMT' : 'Hide SMT';
}

function pgTogglePanel(panelId, toggleId) {
  const panel = document.getElementById(panelId);
  const toggle = document.getElementById(toggleId);
  const isOpen = panel.classList.toggle('open');
  toggle.classList.toggle('open', isOpen);
  // Flip the arrow character at the start
  const text = toggle.textContent;
  toggle.innerHTML = toggle.innerHTML.replace(/^[▸▾]/, isOpen ? '▾' : '▸');
}
