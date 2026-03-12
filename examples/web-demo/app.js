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
    if (di > 0) {
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
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tabId}`));
}

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
