// app.js — Main application logic for Policy Intelligence web demo.
//
// Handles: UI rendering, tab switching, WASM compilation,
// Z3 solving via z3-solver-bridge, and result interpretation.

import { initZ3, solveSmtLib2 } from './z3-solver-bridge.mjs';
import {
  escapeHtml, highlightOutput, applyKeywordHighlights,
  highlightSMT, highlightRego, highlightCedar, highlightJsonLine,
  highlightRegoFull, highlightJsonFull,
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
    if (demo.copilot) {
      btn.innerHTML = `<span class="tab-num">🤖</span>Copilot`;
    } else if (demo.playground) {
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
      : demo.copilot
      ? buildCopilotPanel()
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
  window.cpSend = cpSend;
  window.cpValidate = cpValidate;
  window.cpCompare = cpCompare;
  window.cpExplain = cpExplain;
  window.cpUseSuggestion = cpUseSuggestion;
  window.cpNewSession = cpNewSession;
  window.cpLangChanged = cpLangChanged;
  window.cpResourceChanged = cpResourceChanged;
  window.cpSwitchVariant = cpSwitchVariant;
  window.cpModeChanged = cpModeChanged;
  window.syncCpSchemaHighlight = syncCpSchemaHighlight;

}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tabId}`));
  if (tabId === 'playground') ensurePlaygroundInit();
  if (tabId === 'intro') ensureIntroInit();
  if (tabId === 'copilot') ensureCopilotInit();
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
    id: 'region',
    label: 'Region violation',
    desc: 'Region must be one of the allowed values — Z3 finds one that slips through.',
    smt: `; Azure policy: resources must be in an allowed region
(declare-const region String)

; Allowed regions
(declare-const in_allowed Bool)
(assert (= in_allowed
  (or (= region "eastus")
      (= region "westus2"))))

; Resource is NOT in the allowed set
(assert (not in_allowed))

; Uncomment below to constrain Z3 to real Azure regions:
; (assert (or (= region "eastus") (= region "eastus2") (= region "westus") (= region "westus2") (= region "centralus") (= region "westeurope") (= region "northeurope") (= region "southeastasia")))

(check-sat)
(get-value (region))`,
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
      <div class="pipe-wrap">
        <div class="pipe-line">
          <div class="pipe-langs">
            <div class="pipe-lang-row"><span class="pipe-box pipe-lang">Rego</span><span class="pipe-arr">→</span><span class="pipe-box">Compiler</span></div>
            <div class="pipe-lang-row"><span class="pipe-box pipe-lang">Cedar</span><span class="pipe-arr">→</span><span class="pipe-box">Compiler</span></div>
            <div class="pipe-lang-row"><span class="pipe-box pipe-lang">Azure Policy</span><span class="pipe-arr">→</span><span class="pipe-box">Compiler</span></div>
          </div>
          <svg class="pipe-lines" viewBox="0 0 32 72" preserveAspectRatio="none">
            <line x1="0" y1="11" x2="32" y2="36" stroke="var(--text-dim)" stroke-width="1.2"/>
            <line x1="0" y1="36" x2="32" y2="36" stroke="var(--text-dim)" stroke-width="1.2"/>
            <line x1="0" y1="61" x2="32" y2="36" stroke="var(--text-dim)" stroke-width="1.2"/>
          </svg>
          <span class="pipe-box pipe-box-hl">RVM<span class="pipe-sub">bytecode</span></span>
          <span class="pipe-arr">+</span>
          <span class="pipe-box">Schema<span class="pipe-sub">data model</span></span>
          <span class="pipe-arr">→</span>
          <span class="pipe-box pipe-box-hl">Symbolic Interpreter<span class="pipe-sub">regorus</span></span>
          <span class="pipe-arr">→</span>
          <span class="pipe-box">SMT Formula<span class="pipe-sub">constraints</span></span>
          <span class="pipe-arr">→</span>
          <span class="pipe-box pipe-box-hl">Z3 Solver<span class="pipe-sub">satisfiability</span></span>
          <span class="pipe-arr">→</span>
          <span class="pipe-box">Result<span class="pipe-sub">input / proof</span></span>
        </div>
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

// ═══════════════════════════════════════════════════════════
//  COPILOT — LLM + Policy Intelligence
// ═══════════════════════════════════════════════════════════

const CP_LLM_BASE = 'http://localhost:8000';

const CP_SUGGESTIONS = [
  "Only managers and employees can access. Employees restricted to business hours (9-17). Suspended users always denied.",
  "Kubernetes admission: deny privileged containers and deny unencrypted volumes on public hosts.",
  "Storage accounts must use HTTPS. Deny any storage account where supportsHttpsTrafficOnly is false.",
  "Allow if user's clearance level >= resource's required level, unless account is locked.",
  "Azure: SQL servers must have minimum TLS 1.2and public network access disabled.",
  "Azure: Key Vaults must enable soft delete, purge protection, and RBAC authorization.",
];

const CP_QUERY_SUGGESTIONS = [
  "Can a storage account with public network access be created?",
  "What inputs trigger the deny effect?",
  "Is there any way to bypass the TLS 1.2 requirement?",
  "Can a resource with HTTP (no HTTPS) pass this policy?",
];

// Azure resource type registry — pre-built schemas
const CP_AZURE_RESOURCES = {
  'Microsoft.Storage/storageAccounts': {
    label: 'Storage Accounts',
    schema: 'policies/azure_storage_schema.json',
  },
  'Microsoft.Sql/servers': {
    label: 'SQL Servers',
    schema: 'policies/azure_sql_schema.json',
  },
  'Microsoft.KeyVault/vaults': {
    label: 'Key Vaults',
    schema: 'policies/azure_keyvault_schema.json',
  },
};

// Pre-canned Azure Policy aliases (fetched lazily)
let cpAliasesCache = null;
let cpResourceSchemaCache = {};
async function cpGetAliases() {
  if (cpAliasesCache) return cpAliasesCache;
  try {
    const text = await fetchText('policies/azure_policy_aliases.json');
    cpAliasesCache = text;
    return text;
  } catch {
    return null;
  }
}

const CP_GENERATE_SYSTEM_REGO = `\
You are a Rego policy generator.
The user describes a policy in natural language. You generate TWO variants of the policy
AND a shared JSON Schema describing the expected input structure.

Variant A — "Basic": a straightforward, minimal policy that covers the core intent.
Variant B — "Strict": a more comprehensive policy that adds extra conditions, edge-case
handling, or tighter constraints beyond the basic requirement.

Briefly explain (1-2 sentences each) what distinguishes the two variants.

Rego v1 syntax rules (MANDATORY for BOTH variants):
- Use package name "policy"
- Define a boolean rule: default allow := false  (use := not =)
- Rule syntax: allow if { ... }  (NOT "allow { ... }")
- Iteration: some item in input.collection  (NOT some i; item := ...)
- Partial sets: violation contains x if { ... }  (NOT violation[x] { ... })
- Use idiomatic Rego v1: not, some, in, contains, if, every
- Access input fields via "input." prefix

Output format — return EXACTLY three fenced code blocks in this order:
1. Variant A (Basic):
\`\`\`rego
package policy
...
\`\`\`
2. Variant B (Strict):
\`\`\`rego
package policy
...
\`\`\`
3. Shared input JSON Schema:
\`\`\`json
{"type":"object", ...}
\`\`\`

JSON Schema conventions:
- Top-level "type": "object" with "required" and "properties"
- Use "enum" arrays to constrain string fields to a finite set of representative values
- For integers use "minimum" and "maximum"
- For arrays use "minItems", "maxItems", and "items" with a nested schema
- Add "x-unique": ["fieldname"] on array schemas when elements should have unique keys
- Include ALL fields used by EITHER variant

Do NOT include explanations outside the code blocks (except the brief variant descriptions).`;

const CP_GENERATE_SYSTEM_AZURE = `\
You are an Azure Policy definition generator.
The user describes a policy in natural language. You generate a valid Azure Policy definition
in JSON format.

The user will provide a JSON Schema describing the resource properties available via Azure
Policy aliases. Use ONLY the field names and enum values from this schema when writing
conditions in the policyRule. Do NOT invent field names.

CRITICAL — field names in policyRule MUST use fully-qualified Azure Policy alias names
with FORWARD SLASHES only as separators (never dots between the resource type and the property).
Correct:   "Microsoft.Storage/storageAccounts/minimumTlsVersion"
WRONG:     "Microsoft.Storage/storageAccounts.minimumTlsVersion"  (dot before property)
WRONG:     "minimumTlsVersion"  (missing resource type prefix)
The only exception is the "type" field which stays as "type".

TAGS: To check resource tags, use the built-in tag field syntax:
  "field": "tags['tagName']"   — references a specific tag by name
  "field": "tags"              — references the tags object itself
Tag fields do NOT need the resource type prefix. Examples:
  { "field": "tags['costCenter']", "exists": false }
  { "field": "tags['environment']", "in": ["prod", "staging"] }

MANDATORY: The effect MUST be parameterized. Define an "effect" parameter with
allowedValues ["deny", "audit", "disabled"] (all lowercase) and defaultValue "deny".
In policyRule.then.effect use "[parameters('effect')]".

Example for a Storage Account policy:
{
  "properties": {
    "displayName": "Storage accounts should enforce HTTPS",
    "policyType": "Custom",
    "mode": "Indexed",
    "parameters": {
      "effect": {
        "type": "String",
        "allowedValues": ["deny", "audit", "disabled"],
        "defaultValue": "deny"
      }
    },
    "policyRule": {
      "if": {
        "allOf": [
          { "field": "type", "equals": "Microsoft.Storage/storageAccounts" },
          { "field": "Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly", "equals": false }
        ]
      },
      "then": { "effect": "[parameters('effect')]" }
    }
  }
}

You MUST generate TWO variants:
Variant A — "Basic": a straightforward policy covering the core requirement.
Variant B — "Strict": a more comprehensive policy with additional conditions or tighter constraints.

Briefly explain (1-2 sentences each) what distinguishes the two variants.

Output format — return EXACTLY two fenced code blocks in this order:
1. Variant A (Basic):
\`\`\`json
// Variant A: Basic
{ "properties": { ... } }
\`\`\`
2. Variant B (Strict):
\`\`\`json
// Variant B: Strict
{ "properties": { ... } }
\`\`\`

Do NOT return a JSON Schema block — the schema is pre-built.
Do NOT include explanations outside the code blocks (except the brief variant descriptions).`;

const CP_REFINE_SYSTEM = `\
You are a policy expert helping refine a policy.
The user has a generated policy (Rego or Azure Policy), an input JSON Schema,
and Z3 analysis results.

For Rego — mandatory v1 syntax:
- default allow := false  (use := not =)
- Rule syntax: allow if { ... }  (NOT "allow { ... }")
- Iteration: some item in input.collection  (NOT some i; item := ...)
- Partial sets: violation contains x if { ... }  (NOT violation[x] { ... })

For Azure Policy — standard ARM policy definition format.

When the user asks you to fix or adjust:
- Return the COMPLETE updated policy in the appropriate fenced code block
  (\`\`\`rego or \`\`\`json with a comment on the first line inside)
- If the schema also needs updating, also return the COMPLETE updated JSON Schema
  in a separate fenced code block
- Briefly explain what you changed (1-2 sentences)

If only the policy changes and the schema is still correct, you may omit the schema block.`;

const CP_EXPLAIN_SYSTEM = `\
You are a policy analysis expert. The user will provide:
1. One or two policy definitions (Rego or Azure Policy JSON)
2. Z3 analysis results (synthesized inputs that trigger or satisfy the policy)

Explain the Z3 results in plain English:
- What each synthesized input means in business terms
- Whether the results match the likely policy intent
- Any potential issues, edge cases, or surprises
- If two variants are provided, explain how they differ in coverage or strictness
- Be concise but specific. Reference concrete field values from the results.`;

const CP_QUERY_SYSTEM = `\
You are a policy analysis assistant. The user has an existing policy (Rego or Azure Policy JSON) \
and wants to ask natural-language questions about it — e.g. "Can a storage account without HTTPS pass?" \
or "What inputs trigger the deny effect?"

Your job: translate the user's question into a Z3-solvable constraint specification.

You will receive:
- The current policy source code
- The JSON Schema describing valid inputs
- The user's natural-language question

Respond with EXACTLY one fenced JSON block (\`\`\`json ... \`\`\`) containing:
{
  "goal": "expected" | "non-default",
  "desired": "<value>" | null,
  "schema_overrides": { "<field>": <value_or_constraint>, ... } | null,
  "explanation": "Brief explanation of how you translated the question"
}

Rules:
- "goal": "non-default" for Azure Policy (finds inputs that trigger the effect). \
  "expected" for Rego (finds inputs producing a specific output).
- "desired": for Rego "expected" goals, the string value to target (e.g. "true" or "false"). \
  null for "non-default" goals.
- "schema_overrides": an object of field-name → value pairs to pin specific fields. \
  For example, if the user asks "can a resource without HTTPS pass?", you would set \
  {"supportsHttpsTrafficOnly": false}. Use null if no overrides are needed. \
  Field names must match the JSON Schema property names.
- "explanation": a short sentence explaining the translation.

Only output the JSON block. No other text.`;

function cpRenderSuggestions() {
  const suggestions = cpGetMode() === 'query' ? CP_QUERY_SUGGESTIONS : CP_SUGGESTIONS;
  return suggestions.map((s, i) =>
    `<button class="cp-suggestion" onclick="cpUseSuggestion(${i})">${s.substring(0, 65)}…</button>`
  ).join('');
}

function cpGetMode() {
  return document.getElementById('cp-mode')?.value || 'author';
}

let cpSessionId = null;
let cpInitialized = false;
let cpLastZ3Results = null;  // store for explain flow

// Variant state: stores policy text for each variant
let cpVariants = { a: '', b: '' };
let cpActiveVariant = 'a';

function cpSwitchVariant(v) {
  // Save current editor content to active variant
  const editor = document.getElementById('cp-policy-editor');
  if (editor) cpVariants[cpActiveVariant] = editor.value;
  // Switch
  cpActiveVariant = v;
  if (editor) editor.value = cpVariants[v] || '';
  syncCpPolicyHighlight();
  // Update tab styling
  document.querySelectorAll('.cp-variant-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.variant === v);
  });
}

function cpGetActivePolicy() {
  const editor = document.getElementById('cp-policy-editor');
  if (editor) cpVariants[cpActiveVariant] = editor.value;
  return cpVariants[cpActiveVariant]?.trim() || '';
}

function cpHasBothVariants() {
  const editor = document.getElementById('cp-policy-editor');
  if (editor) cpVariants[cpActiveVariant] = editor.value;
  return !!(cpVariants.a?.trim() && cpVariants.b?.trim());
}

function buildCopilotPanel() {
  return `<div class="act-header">
    <h2>🤖 Copilot — LLM + Policy Intelligence</h2>
    <div class="subtitle">
      Describe a policy in natural language. The LLM generates code + schema,
      Z3 validates with concrete inputs, the LLM explains. Iterate until correct.
    </div>
  </div>

  <div class="cp-toolbar">
    <div class="cp-workflow" id="cp-workflow">
      <div class="cp-wf-step active" id="cp-wf-1">① Describe</div>
      <div class="cp-wf-step" id="cp-wf-2">② Generate</div>
      <div class="cp-wf-step" id="cp-wf-3">③ Validate</div>
      <div class="cp-wf-step" id="cp-wf-4">④ Explain</div>
      <div class="cp-wf-step" id="cp-wf-5">⑤ Refine</div>
    </div>
    <div class="cp-mode-select">
      <label for="cp-mode">Mode</label>
      <select id="cp-mode" onchange="cpModeChanged()">
        <option value="author" selected>✍️ Author</option>
        <option value="query">🔍 Query</option>
      </select>
    </div>
    <div class="cp-lang-select">
      <label for="cp-lang">Language</label>
      <select id="cp-lang" onchange="cpLangChanged()">
        <option value="rego" selected>Rego</option>
        <option value="azure">Azure Policy</option>
      </select>
    </div>
    <div class="cp-resource-select" id="cp-resource-group" style="display:none">
      <label for="cp-resource">Resource</label>
      <select id="cp-resource" onchange="cpResourceChanged()">
        ${Object.entries(CP_AZURE_RESOURCES).map(([k, v]) => `<option value="${k}">${v.label}</option>`).join('')}
      </select>
    </div>
    <button class="btn-sm cp-new-btn" onclick="cpNewSession()">New session</button>
  </div>

  <!-- ROW 1: Chat + Policy editor side by side -->
  <div class="cp-row cp-row-top" id="cp-row-top">
    <div class="cp-panel cp-panel-chat">
      <div class="cp-panel-header">Chat</div>
      <div class="cp-chat" id="cp-chat">
        <div class="cp-msg cp-msg-system">Describe the policy you want to create…</div>
      </div>
      <div class="cp-suggestions" id="cp-suggestions">
        ${cpRenderSuggestions()}
      </div>
      <div class="cp-prompt-row">
        <textarea id="cp-prompt" class="cp-prompt"
          placeholder="Describe your policy in plain English…"
          onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();cpSend()}"></textarea>
        <button class="cp-send-btn" id="cp-send-btn" onclick="cpSend()">Send</button>
      </div>
    </div>

    <div class="cp-panel cp-panel-policy">
      <div class="cp-panel-header">
        <span id="cp-policy-header">Generated Policy</span>
        <span class="cp-status" id="cp-status"></span>
      </div>
      <div class="cp-variant-tabs">
        <button class="cp-variant-tab active" data-variant="a" onclick="cpSwitchVariant('a')">Variant A — Basic</button>
        <button class="cp-variant-tab" data-variant="b" onclick="cpSwitchVariant('b')">Variant B — Strict</button>
      </div>
      <div class="cp-editor-wrap">
        <pre class="cp-editor-highlight" id="cp-policy-highlight"></pre>
        <textarea id="cp-policy-editor" class="cp-policy-editor" spellcheck="false"
          placeholder="Policy variants will appear here after LLM generates them…"></textarea>
      </div>
    </div>
  </div>

  <!-- ROW 2: Schema + Z3 Results side by side -->
  <div class="cp-row cp-row-bottom">
    <div class="cp-panel cp-panel-schema">
      <div class="cp-panel-header">
        <span>Input Schema</span>
        <button class="btn-sm" style="font-size:0.7rem" onclick="document.getElementById('cp-schema-editor').value='';syncCpSchemaHighlight()">Clear</button>
      </div>
      <div class="cp-editor-wrap cp-schema-wrap">
        <pre class="cp-editor-highlight" id="cp-schema-highlight"></pre>
        <textarea id="cp-schema-editor" class="cp-policy-editor cp-schema-editor" spellcheck="false"
          placeholder="JSON Schema will appear here…"></textarea>
      </div>
    </div>

    <div class="cp-panel cp-panel-z3">
      <div class="cp-panel-header">
        <span>Z3 Analysis</span>
        <div class="cp-action-bar">
          <div class="cp-config-row">
            <label>Entry:</label>
            <input type="text" id="cp-entrypoint" value="data.policy.allow" spellcheck="false">
            <label>Loops:</label>
            <input type="text" id="cp-max-loops" value="3" style="width:3rem">
          </div>
          <button class="cp-validate-btn" id="cp-validate-btn" onclick="cpValidate()">⚡ Validate</button>
          <button class="cp-compare-btn" id="cp-compare-btn" onclick="cpCompare()" disabled>🔀 Compare</button>
          <button class="cp-explain-btn" id="cp-explain-btn" onclick="cpExplain()" disabled>💬 Explain</button>
        </div>
      </div>
      <div class="cp-z3-body" id="cp-z3-body">
        <div class="cp-z3-placeholder">
          Click <strong>Validate</strong> to analyze the active variant, or
          <strong>Compare</strong> to find where A and B disagree.
        </div>
      </div>
    </div>
  </div>`;
}

function ensureCopilotInit() {
  if (cpInitialized) return;
  if (!document.getElementById('cp-chat')) return;
  cpInitialized = true;

  // Wire up syntax highlighting overlays
  const policyTa = document.getElementById('cp-policy-editor');
  const policyPre = document.getElementById('cp-policy-highlight');
  if (policyTa && policyPre) {
    policyTa.addEventListener('input', syncCpPolicyHighlight);
    policyTa.addEventListener('scroll', () => {
      policyPre.scrollTop = policyTa.scrollTop;
      policyPre.scrollLeft = policyTa.scrollLeft;
    });
  }
  const schemaTa = document.getElementById('cp-schema-editor');
  const schemaPre = document.getElementById('cp-schema-highlight');
  if (schemaTa && schemaPre) {
    schemaTa.addEventListener('input', syncCpSchemaHighlight);
    schemaTa.addEventListener('scroll', () => {
      schemaPre.scrollTop = schemaTa.scrollTop;
      schemaPre.scrollLeft = schemaTa.scrollLeft;
    });
  }
}

function syncCpPolicyHighlight() {
  const ta = document.getElementById('cp-policy-editor');
  const pre = document.getElementById('cp-policy-highlight');
  if (!ta || !pre) return;
  const text = ta.value;
  if (!text) { pre.innerHTML = ''; return; }
  const lang = cpGetLang();
  pre.innerHTML = lang === 'azure' ? highlightJsonFull(text) : highlightRegoFull(text);
}

function syncCpSchemaHighlight() {
  const ta = document.getElementById('cp-schema-editor');
  const pre = document.getElementById('cp-schema-highlight');
  if (!ta || !pre) return;
  const text = ta.value;
  if (!text) { pre.innerHTML = ''; return; }
  pre.innerHTML = highlightJsonFull(text);
}

function cpGetLang() {
  return document.getElementById('cp-lang')?.value || 'rego';
}

function cpGetLangDefaults() {
  const lang = cpGetLang();
  if (lang === 'azure') {
    return { entryPoint: 'main', placeholder: 'Azure Policy definition JSON…' };
  }
  return { entryPoint: 'data.policy.allow', placeholder: 'Rego policy…' };
}

function cpLangChanged() {
  const defaults = cpGetLangDefaults();
  const ep = document.getElementById('cp-entrypoint');
  if (ep) ep.value = defaults.entryPoint;
  const editor = document.getElementById('cp-policy-editor');
  if (editor) editor.placeholder = `Policy variants will appear here after LLM generates them…`;

  const lang = cpGetLang();
  const resGroup = document.getElementById('cp-resource-group');
  const schemaEditor = document.getElementById('cp-schema-editor');
  if (resGroup) resGroup.style.display = lang === 'azure' ? '' : 'none';
  if (schemaEditor) {
    schemaEditor.readOnly = (lang === 'azure');
    schemaEditor.classList.toggle('cp-readonly', lang === 'azure');
    const schemaWrap = schemaEditor.closest('.cp-schema-wrap');
    if (schemaWrap) schemaWrap.classList.toggle('cp-readonly-wrap', lang === 'azure');
    // Clear schema when switching to Rego (LLM will generate it)
    if (lang === 'rego') { schemaEditor.value = ''; syncCpSchemaHighlight(); }
  }
  // Auto-load the schema for the selected resource type
  if (lang === 'azure') cpResourceChanged();
  // Re-highlight policy with appropriate language
  syncCpPolicyHighlight();
}

async function cpResourceChanged() {
  const sel = document.getElementById('cp-resource');
  if (!sel) return;
  const resType = sel.value;
  const entry = CP_AZURE_RESOURCES[resType];
  if (!entry) return;

  const schemaEditor = document.getElementById('cp-schema-editor');
  if (!schemaEditor) return;

  // Use cache if available
  if (cpResourceSchemaCache[resType]) {
    schemaEditor.value = cpResourceSchemaCache[resType];
    syncCpSchemaHighlight();
    return;
  }

  schemaEditor.value = 'Loading schema…';
  syncCpSchemaHighlight();
  try {
    const text = await fetchText(entry.schema);
    cpResourceSchemaCache[resType] = text;
    schemaEditor.value = text;
    syncCpSchemaHighlight();
  } catch (err) {
    schemaEditor.value = `Error loading schema: ${err.message}`;
    syncCpSchemaHighlight();
  }
}

function cpSetWorkflowStep(step) {
  for (let i = 1; i <= 5; i++) {
    const el = document.getElementById(`cp-wf-${i}`);
    if (!el) continue;
    el.classList.remove('active', 'done');
    if (i < step) el.classList.add('done');
    else if (i === step) el.classList.add('active');
  }
}

function cpRenderMarkdown(text) {
  // Lightweight markdown → HTML for chat messages.
  // Handles: fenced code, inline code, bold, italic, headers, bullets, line breaks.
  let html = '';
  const lines = text.split('\n');
  let inCode = false;
  let codeLang = '';
  let codeLines = [];
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Fenced code blocks
    if (line.trimStart().startsWith('```')) {
      if (!inCode) {
        if (inList) { html += '</ul>'; inList = false; }
        inCode = true;
        codeLang = line.trim().slice(3).trim();
        codeLines = [];
      } else {
        const langLabel = codeLang ? `<span class="cp-code-lang">${escapeHtml(codeLang)}</span>` : '';
        html += `<div class="cp-code-block">${langLabel}<pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre></div>`;
        inCode = false;
        codeLang = '';
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }

    // Blank line — end list, add spacing
    if (line.trim() === '') {
      if (inList) { html += '</ul>'; inList = false; }
      html += '<div class="cp-md-gap"></div>';
      continue;
    }

    // Headings
    const hMatch = line.match(/^(#{1,4})\s+(.+)/);
    if (hMatch) {
      if (inList) { html += '</ul>'; inList = false; }
      const level = Math.min(hMatch[1].length, 4);
      html += `<div class="cp-md-h cp-md-h${level}">${cpInlineMarkdown(hMatch[2])}</div>`;
      continue;
    }

    // Bullet lists (-, *, or numbered)
    const bulletMatch = line.match(/^\s*[-*]\s+(.+)/);
    const numMatch = line.match(/^\s*\d+[.)\s]\s*(.+)/);
    if (bulletMatch || numMatch) {
      if (!inList) { html += '<ul class="cp-md-list">'; inList = true; }
      const content = bulletMatch ? bulletMatch[1] : numMatch[1];
      html += `<li>${cpInlineMarkdown(content)}</li>`;
      continue;
    }

    // Regular paragraph line
    if (inList) { html += '</ul>'; inList = false; }
    html += `<div class="cp-md-p">${cpInlineMarkdown(line)}</div>`;
  }

  if (inCode) {
    // Unclosed code block
    html += `<div class="cp-code-block"><pre><code>${escapeHtml(codeLines.join('\n'))}</code></pre></div>`;
  }
  if (inList) html += '</ul>';
  return html;
}

function cpInlineMarkdown(text) {
  // Escape HTML first, then apply inline formatting
  let s = escapeHtml(text);
  // Bold: **text** or __text__
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__(.+?)__/g, '<strong>$1</strong>');
  // Italic: *text* or _text_ (but not inside words with underscores)
  s = s.replace(/(?<![\w*])\*([^*]+?)\*(?![\w*])/g, '<em>$1</em>');
  // Inline code: `text`
  s = s.replace(/`([^`]+?)`/g, '<code class="cp-md-inline-code">$1</code>');
  return s;
}

function cpFinalizeMessage(msgDiv, fullText) {
  // Replace the streaming span with rendered markdown
  const contentEl = msgDiv.querySelector('#cp-stream-content');
  if (contentEl) {
    contentEl.classList.remove('cp-streaming');
    contentEl.removeAttribute('id');
  }
  // Re-render the whole assistant message with markdown
  const label = msgDiv.querySelector('.cp-msg-label');
  const labelHtml = label ? label.outerHTML : '';
  msgDiv.innerHTML = labelHtml + '<div class="cp-md-content">' + cpRenderMarkdown(fullText) + '</div>';
}

function cpAddMessage(role, text) {
  const chat = document.getElementById('cp-chat');
  if (!chat) return null;
  const div = document.createElement('div');
  const icon = role === 'user' ? '👤' : role === 'assistant' ? '🤖' : 'ℹ️';
  const labelText = role === 'user' ? 'You' : role === 'assistant' ? 'Copilot' : '';
  div.className = `cp-msg cp-msg-${role}`;
  if (role === 'system') {
    div.innerHTML = escapeHtml(text);
  } else {
    const content = role === 'assistant'
      ? '<div class="cp-md-content">' + cpRenderMarkdown(text) + '</div>'
      : escapeHtml(text);
    div.innerHTML = `<div class="cp-msg-avatar">${icon}</div><div class="cp-msg-body"><div class="cp-msg-label">${labelText}</div>${content}</div>`;
  }
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return div;
}

function cpAddStreamingMessage() {
  const chat = document.getElementById('cp-chat');
  if (!chat) return null;
  const div = document.createElement('div');
  div.className = 'cp-msg cp-msg-assistant';
  div.innerHTML = '<div class="cp-msg-avatar">🤖</div><div class="cp-msg-body"><div class="cp-msg-label">Copilot</div><span class="cp-streaming" id="cp-stream-content"></span></div>';
  chat.appendChild(div);
  chat.scrollTop = chat.scrollHeight;
  return div;
}

function cpExtractRego(text) {
  // Extract rego code from fenced code block (first match)
  const match = text.match(/```rego\s*\n([\s\S]*?)```/);
  return match ? match[1].trim() : null;
}

function cpExtractAllRego(text) {
  // Extract ALL rego code blocks (for variants)
  const matches = [...text.matchAll(/```rego\s*\n([\s\S]*?)```/g)];
  return matches.map(m => m[1].trim()).filter(s => s.length > 0);
}

function cpExtractAzureDefinition(text) {
  // Extract Azure Policy definition from fenced JSON block (first match)
  const blocks = [...text.matchAll(/```json\s*\n([\s\S]*?)```/g)];
  for (const m of blocks) {
    const content = m[1].trim();
    const cleaned = content.replace(/^\/\/.*\n/, '').trim();
    try {
      const parsed = JSON.parse(cleaned);
      if (parsed.properties?.policyRule || parsed.policyRule) {
        return JSON.stringify(parsed, null, 2);
      }
    } catch { /* not valid JSON, skip */ }
  }
  return null;
}

function cpExtractAllAzureDefinitions(text) {
  // Extract ALL Azure Policy definitions from fenced JSON blocks (for variants)
  const blocks = [...text.matchAll(/```json\s*\n([\s\S]*?)```/g)];
  const defs = [];
  for (const m of blocks) {
    const content = m[1].trim();
    const cleaned = content.replace(/^\/\/.*\n/, '').trim();
    try {
      const parsed = JSON.parse(cleaned);
      if (parsed.properties?.policyRule || parsed.policyRule) {
        defs.push(JSON.stringify(parsed, null, 2));
      }
    } catch { /* skip */ }
  }
  return defs;
}

function cpExtractJsonSchema(text) {
  // Extract JSON Schema from fenced code block (```json ... ```)
  // Pick the JSON block that looks like a schema (has "type":"object", no policyRule)
  const blocks = [...text.matchAll(/```json\s*\n([\s\S]*?)```/g)];
  for (const m of blocks) {
    const content = m[1].trim();
    const cleaned = content.replace(/^\/\/.*\n/, '').trim();
    try {
      const parsed = JSON.parse(cleaned);
      if (parsed.type === 'object' && !parsed.properties?.policyRule && !parsed.policyRule) {
        return JSON.stringify(parsed, null, 2);
      }
    } catch { /* skip */ }
  }
  return null;
}

async function cpLlmChat(message, systemOverride, context) {
  const body = {
    message,
    session_id: cpSessionId || undefined,
    context: context || undefined,
  };

  // For generate/refine, we use a fresh session with the specific system prompt
  if (systemOverride) {
    body.session_id = undefined;
  }

  const resp = await fetch(`${CP_LLM_BASE}/api/chat/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    throw new Error(`LLM server error: ${resp.status} ${resp.statusText}`);
  }

  return resp.body;
}

async function cpStreamResponse(readableStream, targetEl) {
  const reader = readableStream.getReader();
  const decoder = new TextDecoder();
  let fullText = '';
  let newSessionId = null;
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const jsonStr = line.slice(6).trim();
      if (!jsonStr) continue;
      try {
        const data = JSON.parse(jsonStr);
        if (data.chunk) {
          fullText += data.chunk;
          if (targetEl) {
            targetEl.textContent = fullText;
            const chat = document.getElementById('cp-chat');
            if (chat) chat.scrollTop = chat.scrollHeight;
          }
        }
        if (data.done && data.session_id) {
          newSessionId = data.session_id;
        }
      } catch { /* ignore parse errors in SSE */ }
    }
  }

  if (newSessionId) cpSessionId = newSessionId;
  return fullText;
}

async function cpSend() {
  const promptEl = document.getElementById('cp-prompt');
  const message = promptEl.value.trim();
  if (!message) return;

  // Route to query mode if active
  if (cpGetMode() === 'query') {
    return cpQuery(message);
  }

  const sendBtn = document.getElementById('cp-send-btn');
  sendBtn.disabled = true;
  promptEl.value = '';

  // Hide suggestions after first message
  const sugEl = document.getElementById('cp-suggestions');
  if (sugEl) sugEl.style.display = 'none';

  cpAddMessage('user', message);

  const policyEditor = document.getElementById('cp-policy-editor');
  const existingPolicy = cpGetActivePolicy();

  try {
    // Determine if this is a generate or refine request
    let systemPrompt;
    let fullMessage;
    const context = {};
    const lang = cpGetLang();

    if (!existingPolicy) {
      // Fresh generation
      cpSetWorkflowStep(2);
      systemPrompt = lang === 'azure' ? CP_GENERATE_SYSTEM_AZURE : CP_GENERATE_SYSTEM_REGO;

      // For Azure, prefix with the pre-built JSON schema so the LLM knows available fields
      let schemaPrefix = '';
      if (lang === 'azure') {
        const schemaText = (document.getElementById('cp-schema-editor')?.value || '').trim();
        if (schemaText && schemaText !== 'Loading schema…') {
          const resType = document.getElementById('cp-resource')?.value || '';
          schemaPrefix = `Resource type: ${resType}\nResource JSON Schema (properties under "resource" are aliases — use fully-qualified names like "${resType}/<propertyName>" in policyRule field references):\n${schemaText}\n\n`;
        }
      }
      fullMessage = `Language: ${lang.toUpperCase()}\n\n${schemaPrefix}${message}`;
    } else {
      // Refinement — include current policy and Z3 results
      cpSetWorkflowStep(5);
      systemPrompt = CP_REFINE_SYSTEM;
      context.policy = existingPolicy;
      // Include both variants so LLM can differentiate
      if (cpVariants.a?.trim()) context.variant_a = cpVariants.a;
      if (cpVariants.b?.trim()) context.variant_b = cpVariants.b;
      const existingSchema = (document.getElementById('cp-schema-editor')?.value || '').trim();
      if (existingSchema) context.schema = existingSchema;
      if (cpLastZ3Results) {
        context.analysis_result = cpLastZ3Results;
      }
      fullMessage = `Language: ${lang.toUpperCase()}\n\n${message}`;
    }

    // We send to the streaming endpoint
    // First inject system prompt via a fresh session
    const initBody = {
      message: `[System] ${systemPrompt}\n\n---\n\nUser request: ${fullMessage}`,
      context: Object.keys(context).length > 0 ? context : undefined,
    };

    const resp = await fetch(`${CP_LLM_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(initBody),
    });

    if (!resp.ok) throw new Error(`LLM server error: ${resp.status}`);

    const msgDiv = cpAddStreamingMessage();
    const contentEl = msgDiv.querySelector('#cp-stream-content');
    const fullText = await cpStreamResponse(resp.body, contentEl);

    // Finalize: render markdown in the message
    cpFinalizeMessage(msgDiv, fullText);

    // Extract policy variants and populate editor
    let variants = [];
    if (lang === 'rego') {
      variants = cpExtractAllRego(fullText);
    } else {
      variants = cpExtractAllAzureDefinitions(fullText);
    }

    // Detect if user's message targets a specific variant for refinement.
    // This prevents the 2-variant path from triggering when the LLM echoes
    // the existing variant for reference alongside the new one.
    const wantsSpecificVariant = /variant\s*[ab]\b/i.test(message);
    const isFreshGeneration = !existingPolicy;

    if (variants.length >= 2 && (isFreshGeneration || !wantsSpecificVariant)) {
      // Two variants — populate both tabs (fresh generation or general refinement)
      cpVariants.a = variants[0];
      cpVariants.b = variants[1];
      cpActiveVariant = 'a';
      policyEditor.value = variants[0];
      syncCpPolicyHighlight();
      // Update tab styling
      document.querySelectorAll('.cp-variant-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.variant === 'a');
      });
      // Enable compare button, invalidate stale Z3 results
      const compareBtn = document.getElementById('cp-compare-btn');
      if (compareBtn) compareBtn.disabled = false;
      cpLastZ3Results = null;
      const explainBtnA = document.getElementById('cp-explain-btn');
      if (explainBtnA) explainBtnA.disabled = true;
    } else if (variants.length >= 1) {
      // Single-variant update: pick the last extracted variant (most likely the new one)
      const newVariant = variants[variants.length - 1];
      // Determine target variant: if user mentioned "variant B" / "variant A", honor that
      let targetVariant = cpActiveVariant;
      if (/variant\s*b\b/i.test(message)) targetVariant = 'b';
      else if (/variant\s*a\b/i.test(message)) targetVariant = 'a';
      cpVariants[targetVariant] = newVariant;
      // Switch to the target variant so user sees the result
      cpActiveVariant = targetVariant;
      policyEditor.value = newVariant;
      syncCpPolicyHighlight();
      document.querySelectorAll('.cp-variant-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.variant === targetVariant);
      });
      // Enable compare if both variants now have content
      if (cpHasBothVariants()) {
        const compareBtn = document.getElementById('cp-compare-btn');
        if (compareBtn) compareBtn.disabled = false;
      }
      // Invalidate stale Z3 results since variants changed
      cpLastZ3Results = null;
      const explainBtnB = document.getElementById('cp-explain-btn');
      if (explainBtnB) explainBtnB.disabled = true;
    }

    // Extract JSON Schema and populate schema editor (Rego only — Azure uses pre-built)
    const schema = (lang === 'rego') ? cpExtractJsonSchema(fullText) : null;
    const schemaEditor = document.getElementById('cp-schema-editor');
    if (schema && schemaEditor) {
      schemaEditor.value = schema;
      syncCpSchemaHighlight();
    }

    const hasPolicy = variants.length > 0;
    if (hasPolicy) {
      cpSetWorkflowStep(3);
      const status = document.getElementById('cp-status');
      if (status) {
        const variantMsg = variants.length >= 2 ? '2 variants' : 'Policy updated';
        status.textContent = `✓ ${variantMsg}${schema ? ' + schema' : ''} generated — re-run Validate or Compare`;
        status.className = 'cp-status success';
      }
      // Clear stale Z3 display
      const z3Body = document.getElementById('cp-z3-body');
      if (z3Body && cpLastZ3Results === null) {
        z3Body.innerHTML = '<div class="cp-z3-placeholder">Policy changed — click <strong>Validate</strong> or <strong>Compare</strong> to re-analyze.</div>';
      }
    }
  } catch (err) {
    cpAddMessage('system', `Error: ${err.message}`);
    console.error('Copilot send error:', err);
  }

  sendBtn.disabled = false;
}

// ── Query Mode ─────────────────────────────────────────────
async function cpQuery(message) {
  const promptEl = document.getElementById('cp-prompt');
  const sendBtn = document.getElementById('cp-send-btn');
  const z3Body = document.getElementById('cp-z3-body');
  const status = document.getElementById('cp-status');

  sendBtn.disabled = true;
  promptEl.value = '';

  // Hide suggestions after first query
  const sugEl = document.getElementById('cp-suggestions');
  if (sugEl) sugEl.style.display = 'none';

  cpAddMessage('user', message);

  const policyText = cpGetActivePolicy();
  if (!policyText) {
    cpAddMessage('system', 'Please paste or load a policy first, then ask your question.');
    sendBtn.disabled = false;
    return;
  }

  if (!wasm) {
    cpAddMessage('system', 'WASM engine not loaded yet. Please wait and try again.');
    sendBtn.disabled = false;
    return;
  }

  const lang = cpGetLang();
  const schemaText = (document.getElementById('cp-schema-editor')?.value || '').trim();
  const entryPoint = document.getElementById('cp-entrypoint')?.value?.trim() || cpGetLangDefaults().entryPoint;
  const maxLoops = parseInt(document.getElementById('cp-max-loops')?.value) || 3;

  cpSetWorkflowStep(2); // Ask

  try {
    // ── Step 1: Ask LLM to translate question → constraint spec ──
    const systemPrompt = CP_QUERY_SYSTEM;
    const contextObj = { policy: policyText };
    if (schemaText) contextObj.schema = schemaText;

    const initBody = {
      message: `[System] ${systemPrompt}\n\n---\n\nLanguage: ${lang.toUpperCase()}\n\nUser question: ${message}`,
      context: contextObj,
    };

    const resp = await fetch(`${CP_LLM_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(initBody),
    });

    if (!resp.ok) throw new Error(`LLM server error: ${resp.status}`);

    const msgDiv = cpAddStreamingMessage();
    const contentEl = msgDiv.querySelector('#cp-stream-content');
    const fullText = await cpStreamResponse(resp.body, contentEl);
    cpFinalizeMessage(msgDiv, fullText);

    // ── Step 2: Parse the constraint JSON from LLM response ──
    const jsonMatch = fullText.match(/```json\s*([\s\S]*?)```/);
    if (!jsonMatch) {
      cpAddMessage('system', 'Could not extract constraint specification from LLM response. Try rephrasing your question.');
      sendBtn.disabled = false;
      return;
    }

    let constraints;
    try {
      constraints = JSON.parse(jsonMatch[1]);
    } catch (e) {
      cpAddMessage('system', `Failed to parse constraint JSON: ${e.message}`);
      sendBtn.disabled = false;
      return;
    }

    console.log('[cpQuery] constraints:', constraints);

    // ── Step 3: Build overridden schema with pinned fields ──
    const cfg = { max_loop_depth: maxLoops };
    if (schemaText) {
      try {
        const baseSchema = JSON.parse(schemaText);
        if (constraints.schema_overrides && typeof constraints.schema_overrides === 'object') {
          // Pin each override field to an enum with one value
          for (const [field, val] of Object.entries(constraints.schema_overrides)) {
            if (baseSchema.properties && field in baseSchema.properties) {
              baseSchema.properties[field] = { const: val };
            }
          }
        }
        cfg.input_schema = baseSchema;
      } catch (e) {
        cpAddMessage('system', `Schema parse error: ${e.message}`);
        sendBtn.disabled = false;
        return;
      }
    }
    const configJson = JSON.stringify(cfg);

    // ── Step 4: Compile policy + Z3 solve ──
    cpSetWorkflowStep(3); // Z3 Solve
    z3Body.innerHTML = '<div class="cp-z3-placeholder">Running Z3 analysis for your question…</div>';
    if (status) { status.textContent = ''; status.className = 'cp-status'; }

    const t0 = performance.now();
    let program;
    if (lang === 'rego') {
      const modules = [{ id: 'query.rego', content: policyText }];
      program = wasm.Program.compileFromModules('{}', JSON.stringify(modules), JSON.stringify([entryPoint]));
    } else {
      const aliases = await cpGetAliases();
      program = wasm.Program.compileAzurePolicyDefinition(policyText, aliases);
    }

    const goal = constraints.goal || (lang === 'azure' ? 'non-default' : 'expected');
    const desired = constraints.desired || null;

    const problem = wasm.prepareForGoal(program, '{}', entryPoint, goal, desired, configJson);
    const smtText = problem.smtLib2();
    const warnings = problem.warnings();
    const numExtractions = countExtractions(smtText);
    const solutionJson = await solveSmtLib2(smtText, numExtractions, { timeoutMs: 30000 });
    const resultJson = problem.interpretSolution(solutionJson);
    const result = JSON.parse(resultJson);

    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);

    // ── Step 5: Display Z3 result ──
    let z3Html = `<div style="margin-bottom:0.5rem"><strong style="color:var(--accent)">Query: ${escapeHtml(message)}</strong></div>`;
    if (constraints.explanation) {
      z3Html += `<div style="margin-bottom:0.5rem;color:var(--text-dim)"><em>Translation: ${escapeHtml(constraints.explanation)}</em></div>`;
    }
    if (constraints.schema_overrides && Object.keys(constraints.schema_overrides).length > 0) {
      z3Html += `<div style="margin-bottom:0.5rem;color:var(--text-dim)">Pinned: ${escapeHtml(JSON.stringify(constraints.schema_overrides))}</div>`;
    }

    if (result.satisfiable === true) {
      z3Html += `<span style="color:var(--accent2)">YES — found a matching input:</span>\n\n`;
      try {
        const parsed = JSON.parse(result.input);
        z3Html += `<code style="white-space:pre-wrap">${escapeHtml(JSON.stringify(parsed, null, 2))}</code>`;
      } catch {
        z3Html += `<code>${escapeHtml(result.input)}</code>`;
      }
    } else if (result.satisfiable === false) {
      z3Html += `<span style="color:var(--warn)">NO — no input can satisfy this query.</span>`;
    } else {
      z3Html += `<span style="color:var(--text-dim)">UNKNOWN — solver timed out.</span>`;
    }

    z3Body.innerHTML = z3Html;
    if (status) {
      status.textContent = `✓ Query answered in ${elapsed}s`;
      status.className = 'cp-status success';
    }
    if (warnings) console.log('[cpQuery] Z3 warnings:', warnings);

    // Store for explain context
    cpLastZ3Results = [{
      goal: `Query: ${message}`,
      satisfiable: result.satisfiable,
      input: result.input ? JSON.parse(result.input) : null,
      error: null,
    }];
    const explainBtn = document.getElementById('cp-explain-btn');
    if (explainBtn) explainBtn.disabled = false;

    // ── Step 6: Ask LLM to explain the Z3 answer ──
    cpSetWorkflowStep(4); // Answer
    const answerContext = {
      policy: policyText,
      user_question: message,
      z3_result: cpLastZ3Results[0],
      constraints_used: constraints,
    };

    const answerBody = {
      message: `[System] You are a policy analysis expert. The user asked a question about \
their policy, and Z3 has produced a result. Explain the answer in plain English. \
Be direct — answer the user's original question first ("Yes, because…" or "No, because…"), \
then explain the Z3 result details. Be concise.\n\n---\n\nUser question: ${message}`,
      context: answerContext,
    };

    const answerResp = await fetch(`${CP_LLM_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(answerBody),
    });

    if (answerResp.ok) {
      const answerDiv = cpAddStreamingMessage();
      const answerContentEl = answerDiv.querySelector('#cp-stream-content');
      const answerText = await cpStreamResponse(answerResp.body, answerContentEl);
      cpFinalizeMessage(answerDiv, answerText);
    }

  } catch (err) {
    const errMsg = err?.message || String(err);
    cpAddMessage('system', `Query error: ${errMsg}`);
    if (z3Body) z3Body.innerHTML = `<span style="color:var(--danger)">Error: ${escapeHtml(errMsg)}</span>`;
    if (status) { status.textContent = '✗ Query failed'; status.className = 'cp-status error'; }
    console.error('Copilot query error:', err);
  }

  sendBtn.disabled = false;
}

async function cpValidate() {
  const policyText = cpGetActivePolicy();
  if (!policyText) {
    const status = document.getElementById('cp-status');
    status.textContent = '✗ No policy to validate';
    status.className = 'cp-status error';
    return;
  }

  if (!wasm) {
    const status = document.getElementById('cp-status');
    status.textContent = '✗ WASM not loaded yet';
    status.className = 'cp-status error';
    return;
  }

  const validateBtn = document.getElementById('cp-validate-btn');
  const explainBtn = document.getElementById('cp-explain-btn');
  const status = document.getElementById('cp-status');
  const z3Body = document.getElementById('cp-z3-body');

  validateBtn.disabled = true;
  validateBtn.innerHTML = '<span class="spinner"></span> Validating…';
  status.textContent = '';
  status.className = 'cp-status';
  z3Body.innerHTML = '<div class="cp-z3-placeholder">Running Z3 analysis…</div>';

  cpSetWorkflowStep(3);
  const t0 = performance.now();

  const entryPoint = document.getElementById('cp-entrypoint').value.trim() || cpGetLangDefaults().entryPoint;
  const maxLoops = parseInt(document.getElementById('cp-max-loops').value) || 3;
  const lang = cpGetLang();

  try {
    // Compile the policy based on language
    let program;
    if (lang === 'rego') {
      const modules = [{ id: 'copilot.rego', content: policyText }];
      program = wasm.Program.compileFromModules(
        '{}',
        JSON.stringify(modules),
        JSON.stringify([entryPoint]),
      );
    } else {
      // Azure Policy — compile definition JSON with pre-canned aliases
      const aliases = await cpGetAliases();
      program = wasm.Program.compileAzurePolicyDefinition(policyText, aliases);
    }

    // Build config with optional schema
    const cfg = { max_loop_depth: maxLoops };
    const schemaText = (document.getElementById('cp-schema-editor')?.value || '').trim();
    if (schemaText) {
      try {
        cfg.input_schema = JSON.parse(schemaText);
      } catch (e) {
        z3Body.innerHTML = `<span style="color:var(--danger)">Schema parse error: ${escapeHtml(e.message)}</span>`;
        status.textContent = '✗ Invalid schema JSON';
        status.className = 'cp-status error';
        validateBtn.disabled = false;
        validateBtn.innerHTML = '⚡ Validate';
        return;
      }
    }
    const configJson = JSON.stringify(cfg);
    const results = [];

    // Determine goals based on language
    // Azure Policy: main returns the effect string (e.g. "deny") when violated, undefined when compliant.
    //   Use "non-default" goal to find a violating input.
    // Rego: allow is a boolean with default false.
    //   Use "expected" goal to find inputs producing allow=false and allow=true.
    const goals = lang === 'azure'
      ? [{ goal: 'non-default', desired: null, label: 'Violating input (triggers effect)' }]
      : [{ goal: 'expected', desired: 'false', label: 'allow = false' },
         { goal: 'expected', desired: 'true', label: 'allow = true' }];

    for (const { goal, desired, label } of goals) {
      try {
        const problem = wasm.prepareForGoal(program, '{}', entryPoint, goal, desired, configJson);
        const smtText = problem.smtLib2();
        const warnings = problem.warnings();
        const numExtractions = countExtractions(smtText);
        const solutionJson = await solveSmtLib2(smtText, numExtractions, { timeoutMs: 30000 });
        const resultJson = problem.interpretSolution(solutionJson);
        const result = JSON.parse(resultJson);
        results.push({ desired: desired || 'non-default', label, result, warnings });
      } catch (err) {
        results.push({ desired, label, error: err.message });
      }
    }

    // Format results
    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);
    let html = '';
    for (const r of results) {
      html += `<div style="margin-bottom:1rem"><strong style="color:var(--accent)">Goal: ${escapeHtml(r.label)}</strong>\n`;

      if (r.error) {
        html += `<span style="color:var(--danger)">Error: ${escapeHtml(r.error)}</span>`;
      } else if (r.result.satisfiable === true) {
        html += `<span style="color:var(--accent2)">SATISFIABLE</span> — found an input:\n\n`;
        try {
          const parsed = JSON.parse(r.result.input);
          html += `<code style="white-space:pre-wrap">${escapeHtml(JSON.stringify(parsed, null, 2))}</code>`;
        } catch {
          html += `<code>${escapeHtml(r.result.input)}</code>`;
        }
      } else if (r.result.satisfiable === false) {
        html += `<span style="color:var(--warn)">UNSATISFIABLE</span> — no input can produce this output.`;
      } else {
        html += `<span style="color:var(--text-dim)">UNKNOWN</span> — solver timed out or could not determine satisfiability.`;
      }
      html += '</div>';
    }

    z3Body.innerHTML = html;
    status.textContent = `✓ Validated in ${elapsed}s`;
    status.className = 'cp-status success';

    // Store results for explanation
    cpLastZ3Results = results.map(r => ({
      goal: r.label,
      satisfiable: r.result?.satisfiable,
      input: r.result?.input ? JSON.parse(r.result.input) : null,
      error: r.error || null,
    }));

    explainBtn.disabled = false;
    cpSetWorkflowStep(4);

  } catch (err) {
    z3Body.innerHTML = `<span style="color:var(--danger)">Compilation error: ${escapeHtml(err.message)}</span>`;
    status.textContent = '✗ Failed';
    status.className = 'cp-status error';
    console.error('Copilot validate error:', err);
  }

  validateBtn.disabled = false;
  validateBtn.innerHTML = '⚡ Validate';
}

async function cpCompare() {
  if (!cpHasBothVariants()) {
    const status = document.getElementById('cp-status');
    status.textContent = '✗ Need both variants to compare';
    status.className = 'cp-status error';
    return;
  }

  if (!wasm) {
    const status = document.getElementById('cp-status');
    status.textContent = '✗ WASM not loaded yet';
    status.className = 'cp-status error';
    return;
  }

  const compareBtn = document.getElementById('cp-compare-btn');
  const explainBtn = document.getElementById('cp-explain-btn');
  const status = document.getElementById('cp-status');
  const z3Body = document.getElementById('cp-z3-body');

  compareBtn.disabled = true;
  compareBtn.innerHTML = '<span class="spinner"></span> Comparing…';
  status.textContent = '';
  status.className = 'cp-status';
  z3Body.innerHTML = '<div class="cp-z3-placeholder">Running Z3 diff analysis…</div>';

  cpSetWorkflowStep(3);
  const t0 = performance.now();

  const entryPoint = document.getElementById('cp-entrypoint').value.trim() || cpGetLangDefaults().entryPoint;
  const maxLoops = parseInt(document.getElementById('cp-max-loops').value) || 3;
  const lang = cpGetLang();

  // Sync editor to cpVariants before reading
  const editorSync = document.getElementById('cp-policy-editor');
  if (editorSync) cpVariants[cpActiveVariant] = editorSync.value;

  console.log('[cpCompare] active:', cpActiveVariant, 'a.len:', cpVariants.a?.length, 'b.len:', cpVariants.b?.length, 'same:', cpVariants.a === cpVariants.b);

  try {
    // Compile both variants
    let program1, program2;
    if (lang === 'rego') {
      const mod1 = [{ id: 'variant_a.rego', content: cpVariants.a }];
      const mod2 = [{ id: 'variant_b.rego', content: cpVariants.b }];
      program1 = wasm.Program.compileFromModules('{}', JSON.stringify(mod1), JSON.stringify([entryPoint]));
      program2 = wasm.Program.compileFromModules('{}', JSON.stringify(mod2), JSON.stringify([entryPoint]));
    } else {
      const aliases = await cpGetAliases();
      program1 = wasm.Program.compileAzurePolicyDefinition(cpVariants.a, aliases);
      program2 = wasm.Program.compileAzurePolicyDefinition(cpVariants.b, aliases);
    }

    // Build config with optional schema
    const cfg = { max_loop_depth: maxLoops };
    const schemaText = (document.getElementById('cp-schema-editor')?.value || '').trim();
    if (schemaText) {
      try {
        cfg.input_schema = JSON.parse(schemaText);
      } catch (e) {
        z3Body.innerHTML = `<span style="color:var(--danger)">Schema parse error: ${escapeHtml(e.message)}</span>`;
        status.textContent = '✗ Invalid schema JSON';
        status.className = 'cp-status error';
        compareBtn.disabled = false;
        compareBtn.innerHTML = '🔀 Compare';
        return;
      }
    }
    const configJson = JSON.stringify(cfg);

    // Determine desired output for the diff
    // For Rego: default is true (find input where one allows and the other denies)
    // For Azure: use "deny" (find input where one denies and the other doesn't)
    const desiredOutput = lang === 'azure' ? '"deny"' : null;

    const problem = wasm.preparePolicyDiff(program1, program2, '{}', entryPoint, desiredOutput, configJson);
    const smtText = problem.smtLib2();
    const warnings = problem.warnings();
    const numExtractions = countExtractions(smtText);
    const solutionJson = await solveSmtLib2(smtText, numExtractions, { timeoutMs: 30000 });
    const resultJson = problem.interpretSolution(solutionJson);
    const result = JSON.parse(resultJson);

    const elapsed = ((performance.now() - t0) / 1000).toFixed(1);
    let html = '<div style="margin-bottom:1rem"><strong style="color:var(--accent)">Variant A vs Variant B</strong></div>';
    let variantADenies = null;
    let variantBDenies = null;

    if (result.satisfiable === true) {
      // Determine which variant denies and which allows the counterexample
      try {
        const inputStr = result.input;
        if (lang === 'rego') {
          const evalA = program1.evaluate(inputStr, '{}', entryPoint);
          const evalB = program2.evaluate(inputStr, '{}', entryPoint);
          variantADenies = evalA !== undefined && evalA !== 'undefined';
          variantBDenies = evalB !== undefined && evalB !== 'undefined';
        } else {
          // Azure Policy: evaluate both programs against the counterexample.
          // main returns the effect string (e.g. "deny") when violated, undefined when compliant.
          try {
            const evalA = program1.evaluate(inputStr, '{}', entryPoint);
            variantADenies = evalA !== undefined && evalA !== 'undefined' && evalA !== '';
          } catch { variantADenies = false; }
          try {
            const evalB = program2.evaluate(inputStr, '{}', entryPoint);
            variantBDenies = evalB !== undefined && evalB !== 'undefined' && evalB !== '';
          } catch { variantBDenies = false; }
        }
      } catch (e) {
        console.warn('Could not evaluate variants against counterexample:', e);
      }

      let whoLabel = '';
      if (variantADenies === true && variantBDenies === false) {
        whoLabel = '<div style="margin-top:0.5rem;color:var(--warn)">⚠ <strong>Variant A (Basic)</strong> triggers the effect; <strong>Variant B (Strict)</strong> does not.</div>';
      } else if (variantADenies === false && variantBDenies === true) {
        whoLabel = '<div style="margin-top:0.5rem;color:var(--warn)">⚠ <strong>Variant B (Strict)</strong> triggers the effect; <strong>Variant A (Basic)</strong> does not.</div>';
      }

      html += `<span style="color:var(--warn)">NOT EQUIVALENT</span> — the variants disagree on this input:\n\n`;
      try {
        const parsed = JSON.parse(result.input);
        html += `<code style="white-space:pre-wrap">${escapeHtml(JSON.stringify(parsed, null, 2))}</code>`;
      } catch {
        html += `<code>${escapeHtml(result.input)}</code>`;
      }
      html += `\n<div style="margin-top:0.8rem;color:var(--text-dim);font-size:0.85rem">One variant triggers the desired output for this input while the other does not.</div>`;
      html += whoLabel;
    } else if (result.satisfiable === false) {
      html += `<span style="color:var(--accent2)">EQUIVALENT</span> — both variants produce the same output for all possible inputs.`;
    } else {
      html += `<span style="color:var(--text-dim)">UNKNOWN</span> — solver timed out or could not determine equivalence.`;
    }

    z3Body.innerHTML = html;
    status.textContent = `✓ Compared in ${elapsed}s`;
    status.className = 'cp-status success';

    // Store results for explanation
    cpLastZ3Results = [{
      goal: 'Variant A vs B diff',
      satisfiable: result.satisfiable,
      equivalent: result.satisfiable === false,
      input: result.input ? JSON.parse(result.input) : null,
      variant_a_triggers_effect: variantADenies,
      variant_b_triggers_effect: variantBDenies,
    }];

    explainBtn.disabled = false;
    cpSetWorkflowStep(4);

  } catch (err) {
    z3Body.innerHTML = `<span style="color:var(--danger)">Compilation error: ${escapeHtml(err.message)}</span>`;
    status.textContent = '✗ Failed';
    status.className = 'cp-status error';
    console.error('Copilot compare error:', err);
  }

  compareBtn.disabled = false;
  compareBtn.innerHTML = '🔀 Compare';
}

// Extract field conditions from an Azure Policy policyRule for diffing
function cpExtractFieldConditions(policyJson) {
  try {
    const parsed = typeof policyJson === 'string' ? JSON.parse(policyJson) : policyJson;
    const rule = parsed.properties?.policyRule || parsed.policyRule;
    if (!rule?.if) return [];
    const conditions = [];
    function walk(node, parentOp, depth) {
      if (!node || typeof node !== 'object') return;
      if (node.allOf) {
        for (const child of node.allOf) walk(child, 'allOf', depth + 1);
      } else if (node.anyOf) {
        for (const child of node.anyOf) walk(child, 'anyOf', depth + 1);
      } else if (node.not) {
        walk(node.not, 'not', depth + 1);
      } else if (node.field) {
        const cond = { field: node.field, parentOp, depth };
        for (const op of ['equals','notEquals','like','notLike','in','notIn','exists',
                          'greater','less','greaterOrEquals','lessOrEquals','contains',
                          'notContains','match','notMatch']) {
          if (op in node) { cond.operator = op; cond.value = node[op]; break; }
        }
        conditions.push(cond);
      }
    }
    walk(rule.if, 'root', 0);
    return conditions;
  } catch { return []; }
}

function cpExtractTopOp(policyJson) {
  try {
    const parsed = typeof policyJson === 'string' ? JSON.parse(policyJson) : policyJson;
    const rule = parsed.properties?.policyRule || parsed.policyRule;
    if (!rule?.if) return null;
    if (rule.if.allOf) return 'allOf';
    if (rule.if.anyOf) return 'anyOf';
    if (rule.if.not) return 'not';
    return 'single';
  } catch { return null; }
}

function cpBuildConditionDiff(variantA, variantB) {
  const condsA = cpExtractFieldConditions(variantA);
  const condsB = cpExtractFieldConditions(variantB);
  const topA = cpExtractTopOp(variantA);
  const topB = cpExtractTopOp(variantB);

  // Group conditions by field name
  const allFields = new Set([...condsA.map(c => c.field), ...condsB.map(c => c.field)]);
  const fmt = c => `${c.operator} ${JSON.stringify(c.value)} (inside ${c.parentOp})`;

  let diff = `Structure: Variant A uses "${topA || 'single'}" at top level, Variant B uses "${topB || 'single'}" at top level.\n`;
  if (topA !== topB) {
    diff += `⚠ Different top-level operators! This changes which conditions must ALL match vs ANY match.\n`;
  }
  diff += '\nPer-field comparison:\n';

  for (const field of allFields) {
    if (field === 'type') continue; // skip resource type check — always shared
    const inA = condsA.filter(c => c.field === field);
    const inB = condsB.filter(c => c.field === field);
    if (inA.length > 0 && inB.length > 0) {
      const sameCheck = inA.length === inB.length &&
        inA.every((a, i) => a.operator === inB[i].operator && JSON.stringify(a.value) === JSON.stringify(inB[i].value));
      if (sameCheck) {
        diff += `  "${field}": SAME in both — ${inA.map(fmt).join(', ')}\n`;
      } else {
        diff += `  "${field}": DIFFERS\n`;
        diff += `    Variant A: ${inA.map(fmt).join(', ')}\n`;
        diff += `    Variant B: ${inB.map(fmt).join(', ')}\n`;
      }
    } else if (inA.length > 0) {
      diff += `  "${field}": ONLY in Variant A — ${inA.map(fmt).join(', ')}\n`;
    } else {
      diff += `  "${field}": ONLY in Variant B — ${inB.map(fmt).join(', ')}\n`;
    }
  }

  return diff;
}

async function cpExplain() {
  if (!cpLastZ3Results) return;

  const explainBtn = document.getElementById('cp-explain-btn');
  explainBtn.disabled = true;

  cpSetWorkflowStep(4);

  try {
    const schemaText = (document.getElementById('cp-schema-editor')?.value || '').trim();
    const isDiff = cpLastZ3Results[0]?.goal === 'Variant A vs B diff';
    const context = {
      analysis_result: JSON.stringify(cpLastZ3Results, null, 2),
    };
    // Always include both variants when available so the LLM has full context
    if (cpVariants.a) context.variant_a = cpVariants.a;
    if (cpVariants.b) context.variant_b = cpVariants.b;
    // Also include the active policy for single-variant validate
    if (!isDiff) context.active_variant = cpActiveVariant;
    if (schemaText) context.schema = schemaText;

    const explainPrompt = isDiff
      ? (() => {
        const r = cpLastZ3Results[0];
        const lang = cpGetLang();
        let evalFact = '';
        if (r.variant_a_triggers_effect === true && r.variant_b_triggers_effect === false) {
          evalFact = `VERIFIED EVALUATION RESULT:
→ Variant A (Basic) TRIGGERS the effect for this counterexample.
→ Variant B (Strict) DOES NOT trigger the effect for this counterexample.`;
        } else if (r.variant_a_triggers_effect === false && r.variant_b_triggers_effect === true) {
          evalFact = `VERIFIED EVALUATION RESULT:
→ Variant B (Strict) TRIGGERS the effect for this counterexample.
→ Variant A (Basic) DOES NOT trigger the effect for this counterexample.`;
        }

        if (lang === 'azure') {
          // Azure Policy: pre-compute structured condition diff
          const condDiff = cpBuildConditionDiff(cpVariants.a, cpVariants.b);
          return `Here is a STRUCTURED DIFF of the Azure Policy conditions (pre-computed — these are facts):

${condDiff}
${evalFact}

The counterexample input is in the analysis_result context.

Your job: explain in 3-5 sentences WHY the counterexample triggers one variant but not the other,
using the structured diff above. Reference the specific field differences and the counterexample
values that exploit them. Do NOT re-analyze the JSON — use the diff provided.
One-sentence conclusion: which variant is stricter (denies more inputs) and why.`;
        } else {
          // Rego: policies are arbitrary code; pass them directly with the verified result
          return `You have two Rego policy variants (Variant A and Variant B) in the context.
Z3 found a counterexample input where they DISAGREE.

${evalFact}

The counterexample input is in the analysis_result context. Both full policy source codes are
in variant_a and variant_b context fields.

Your job: read both Rego policies and explain in 3-5 sentences WHY the counterexample triggers
one variant but not the other. Focus on the specific rule logic, conditions, or functions that
differ between the two. Reference concrete field values from the counterexample.
One-sentence conclusion: which variant is stricter (denies/blocks more inputs) and why.`;
        }
      })()
      : CP_EXPLAIN_SYSTEM;

    const message = `[System] ${explainPrompt}\n\n---\n\nPlease explain the Z3 analysis results.`;

    const resp = await fetch(`${CP_LLM_BASE}/api/chat/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, context }),
    });

    if (!resp.ok) throw new Error(`LLM server error: ${resp.status}`);

    const msgDiv = cpAddStreamingMessage();
    const contentEl = msgDiv.querySelector('#cp-stream-content');
    const fullText = await cpStreamResponse(resp.body, contentEl);

    cpFinalizeMessage(msgDiv, fullText);

    cpSetWorkflowStep(5);
  } catch (err) {
    cpAddMessage('system', `Error: ${err.message}`);
    console.error('Copilot explain error:', err);
  }

  explainBtn.disabled = false;
}

function cpUseSuggestion(idx) {
  const promptEl = document.getElementById('cp-prompt');
  const suggestions = cpGetMode() === 'query' ? CP_QUERY_SUGGESTIONS : CP_SUGGESTIONS;
  if (promptEl && suggestions[idx]) {
    promptEl.value = suggestions[idx];
    promptEl.focus();
  }
}

function cpModeChanged() {
  const mode = cpGetMode();
  const isQuery = mode === 'query';
  const promptEl = document.getElementById('cp-prompt');
  const sugEl = document.getElementById('cp-suggestions');
  const chat = document.getElementById('cp-chat');
  const policyEditor = document.getElementById('cp-policy-editor');
  const variantTabs = document.querySelector('.cp-variant-tabs');
  const workflow = document.getElementById('cp-workflow');

  // Swap placeholder & suggestions
  if (promptEl) promptEl.placeholder = isQuery
    ? 'Ask a question about the loaded policy…'
    : 'Describe your policy in plain English…';
  if (sugEl) {
    sugEl.innerHTML = cpRenderSuggestions();
    sugEl.style.display = 'flex';
  }

  // Chat welcome message
  if (chat) {
    const sysMsg = chat.querySelector('.cp-msg-system');
    if (sysMsg) sysMsg.textContent = isQuery
      ? 'Load a policy, then ask questions about it…'
      : 'Describe the policy you want to create…';
  }

  // Policy editor: editable in both modes (user pastes policy to query against)
  if (policyEditor) {
    policyEditor.readOnly = false;
    policyEditor.classList.remove('cp-readonly');
    const wrap = policyEditor.closest('.cp-editor-wrap');
    if (wrap) wrap.classList.remove('cp-readonly-wrap');
    if (isQuery) policyEditor.placeholder = 'Paste or load a policy here, then ask questions…';
    else policyEditor.placeholder = 'Policy variants will appear here after LLM generates them…';
  }

  // Hide variant tabs in query mode (single policy)
  if (variantTabs) variantTabs.style.display = isQuery ? 'none' : '';

  // Update policy panel header
  const policyHeader = document.getElementById('cp-policy-header');
  if (policyHeader) policyHeader.textContent = isQuery ? 'Policy' : 'Generated Policy';

  // Workflow steps: different labels for query mode
  if (workflow) {
    const steps = workflow.querySelectorAll('.cp-wf-step');
    if (isQuery) {
      if (steps[0]) steps[0].textContent = '① Load';
      if (steps[1]) steps[1].textContent = '② Ask';
      if (steps[2]) steps[2].textContent = '③ Z3 Solve';
      if (steps[3]) steps[3].textContent = '④ Answer';
      if (steps[4]) steps[4].style.display = 'none';
    } else {
      if (steps[0]) steps[0].textContent = '① Describe';
      if (steps[1]) steps[1].textContent = '② Generate';
      if (steps[2]) steps[2].textContent = '③ Validate';
      if (steps[3]) steps[3].textContent = '④ Explain';
      if (steps[4]) { steps[4].textContent = '⑤ Refine'; steps[4].style.display = ''; }
    }
  }

  // Swap panel order: policy first in query mode
  const topRow = document.getElementById('cp-row-top');
  if (topRow) topRow.classList.toggle('cp-query-layout', isQuery);

  // In query mode, hide Compare but keep Validate (re-labeled "Query" via button text)
  const validateBtn = document.getElementById('cp-validate-btn');
  const compareBtn = document.getElementById('cp-compare-btn');
  if (validateBtn) validateBtn.style.display = isQuery ? 'none' : '';
  if (compareBtn) compareBtn.style.display = isQuery ? 'none' : '';

  cpSetWorkflowStep(1);
}

function cpNewSession() {
  cpSessionId = null;
  cpLastZ3Results = null;
  cpVariants = { a: '', b: '' };
  cpActiveVariant = 'a';

  const chat = document.getElementById('cp-chat');
  if (chat) chat.innerHTML = '<div class="cp-msg cp-msg-system">Describe the policy you want to create…</div>';

  const editor = document.getElementById('cp-policy-editor');
  if (editor) editor.value = '';
  syncCpPolicyHighlight();

  // Reset variant tabs
  document.querySelectorAll('.cp-variant-tab').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.variant === 'a');
  });

  const schemaEditor = document.getElementById('cp-schema-editor');
  if (schemaEditor) schemaEditor.value = '';
  syncCpSchemaHighlight();

  const z3Body = document.getElementById('cp-z3-body');
  if (z3Body) z3Body.innerHTML = '<div class="cp-z3-placeholder">Click <strong>Validate</strong> to analyze the active variant, or <strong>Compare</strong> to find where A and B disagree.</div>';

  const status = document.getElementById('cp-status');
  if (status) { status.textContent = ''; status.className = 'cp-status'; }

  const explainBtn = document.getElementById('cp-explain-btn');
  if (explainBtn) explainBtn.disabled = true;

  const compareBtn = document.getElementById('cp-compare-btn');
  if (compareBtn) compareBtn.disabled = true;

  const sugEl = document.getElementById('cp-suggestions');
  if (sugEl) sugEl.style.display = 'flex';

  // Reset entry point to match current language
  cpLangChanged();
  cpSetWorkflowStep(1);
}
