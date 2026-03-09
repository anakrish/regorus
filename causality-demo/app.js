import { evaluateScenario, formatJson, renderConditionCards, initRuntime } from "./demo-core.js";
import { createCodeEditor } from "./code-editor.js";
import { scenarios } from "./scenarios.js";

const state = {
  activeExampleId: scenarios[0]?.id ?? null,
  activeOutputTab: "result",
  activeRequestTab: "input",
  lastRun: null,
  scenarioDrafts: {}
};

const nav = document.querySelector("#example-nav");
const heroTitle = document.querySelector("#hero-title");
const heroSummary = document.querySelector("#hero-summary");
const heroResult = document.querySelector("#hero-result");
const heroEngine = document.querySelector("#hero-engine");
const heroFocus = document.querySelector("#hero-focus");
const featureStrip = document.querySelector("#feature-strip");
const conditionList = document.querySelector("#condition-list");
const tabs = document.querySelector("#tabs");
const tabContent = document.querySelector("#tab-content");
const serverStatus = document.querySelector("#server-status");
const exampleRuntime = document.querySelector("#example-runtime");
const runAnalysis = document.querySelector("#run-analysis");
const analysisStatus = document.querySelector("#analysis-status");
const analysisPanel = document.querySelector("#analysis-panel");
const policyContent = document.querySelector("#policy-content");
const policyLabel = document.querySelector("#policy-label");
const requestTabs = document.querySelector("#request-tabs");
const requestContent = document.querySelector("#request-content");
const requestHeading = document.querySelector("#request-heading");
const entryPoint = document.querySelector("#entry-point");
const engineSelect = document.querySelector("#engine-select");
const valueMode = document.querySelector("#value-mode");
const conditionMode = document.querySelector("#condition-mode");
const policyEditor = createCodeEditor(policyContent, { language: "rego" });
const requestEditor = createCodeEditor(requestContent, { language: "json" });

function focusAnalysis() {
  analysisPanel?.scrollIntoView({
    behavior: "smooth",
    block: "start"
  });
}

function currentScenario() {
  return scenarios.find((scenario) => scenario.id === state.activeExampleId) ?? scenarios[0];
}

function ensureScenarioDraft(scenario) {
  if (!state.scenarioDrafts[scenario.id]) {
    state.scenarioDrafts[scenario.id] = {
      engine: scenario.engine,
      policy: scenario.policy,
      input: scenario.input,
      data: scenario.data
    };
  }

  return state.scenarioDrafts[scenario.id];
}

function renderNav() {
  nav.innerHTML = "";
  scenarios.forEach((scenario) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `nav-button${scenario.id === state.activeExampleId ? " active" : ""}`;
    button.innerHTML = `<strong>${scenario.navTitle}</strong><span>${scenario.navSubtitle}</span>`;
    button.addEventListener("click", () => {
      state.activeExampleId = scenario.id;
      state.activeOutputTab = "result";
      state.activeRequestTab = "input";
      state.lastRun = null;
      renderScenario();
    });
    nav.appendChild(button);
  });
}

function renderFeatures(features) {
  featureStrip.innerHTML = "";
  features.forEach((feature) => {
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.textContent = feature;
    featureStrip.appendChild(pill);
  });
}

function requestTabMap(scenario) {
  const draft = ensureScenarioDraft(scenario);
  return {
    input: draft.input,
    data: draft.data
  };
}

function syncPolicyDraft() {
  const scenario = currentScenario();
  const draft = ensureScenarioDraft(scenario);
  draft.policy = policyContent.value;
}

function syncEngineDraft() {
  const scenario = currentScenario();
  const draft = ensureScenarioDraft(scenario);
  draft.engine = engineSelect.value;
  heroEngine.textContent = draft.engine;
  policyLabel.textContent = draft.engine;
}

function syncRequestDraft() {
  const scenario = currentScenario();
  const draft = ensureScenarioDraft(scenario);
  draft[state.activeRequestTab] = requestContent.value;
}

function renderRequestTabs(scenario) {
  const tabMap = requestTabMap(scenario);
  requestTabs.innerHTML = "";
  Object.entries(tabMap).forEach(([key, value]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `tab-button${key === state.activeRequestTab ? " active" : ""}`;
    button.textContent = key;
    button.addEventListener("click", () => {
      state.activeRequestTab = key;
      renderRequestTabs(scenario);
    });
    requestTabs.appendChild(button);
    if (!value?.trim()) {
      button.disabled = true;
    }
  });

  requestHeading.textContent = state.activeRequestTab === "data" ? "Data" : "Input";
  requestEditor.setValue(tabMap[state.activeRequestTab] || "{}");
}

function outputTabPayload() {
  if (!state.lastRun) {
    return {
      result: "Run the analysis to populate the result payload.",
      why: "Run the analysis to populate the explanation payload."
    };
  }

  return {
    result: formatJson(state.lastRun.result),
    why: formatJson(state.lastRun.why)
  };
}

function renderOutputTabs() {
  const payload = outputTabPayload();
  tabs.innerHTML = "";
  Object.keys(payload).forEach((key) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `tab-button${key === state.activeOutputTab ? " active" : ""}`;
    button.textContent = key;
    button.addEventListener("click", () => {
      state.activeOutputTab = key;
      renderOutputTabs();
    });
    tabs.appendChild(button);
  });
  tabContent.textContent = payload[state.activeOutputTab] || "";
}

function renderScenario() {
  const scenario = currentScenario();
  const draft = ensureScenarioDraft(scenario);
  renderNav();
  renderFeatures(scenario.features);
  heroTitle.textContent = scenario.title;
  heroSummary.textContent = scenario.summary;
  heroResult.textContent = state.lastRun?.resultSummary || "pending";
  heroEngine.textContent = draft.engine;
  heroFocus.textContent = scenario.focus;
  policyEditor.setValue(draft.policy);
  policyLabel.textContent = draft.engine;
  entryPoint.textContent = scenario.query;
  engineSelect.value = draft.engine;
  valueMode.textContent = scenario.whyFullValues ? "full" : "redacted";
  conditionMode.textContent = scenario.whyAllConditions ? "all contributing" : "primary only";
  analysisStatus.textContent = state.lastRun ? "completed" : "ready";
  exampleRuntime.textContent = state.lastRun?.runtimeMs ? `${state.lastRun.runtimeMs} ms` : "";
  renderRequestTabs(scenario);
  renderOutputTabs();

  if (state.lastRun) {
    renderConditionCards(conditionList, state.lastRun.why.reasons || []);
  } else {
    conditionList.innerHTML = '<div class="loading-card">Policy and request are shown first. Run the analysis to inspect the decision and explanation chain.</div>';
  }
}

async function runCurrentScenario() {
  const scenario = currentScenario();
  const draft = ensureScenarioDraft(scenario);
  runAnalysis.disabled = true;
  analysisStatus.textContent = "running";
  exampleRuntime.textContent = "";
  conditionList.innerHTML = '<div class="loading-card">Evaluating scenario in wasm…</div>';
  requestAnimationFrame(focusAnalysis);

  try {
    state.lastRun = await evaluateScenario({
      ...scenario,
      engine: draft.engine,
      policy: draft.policy,
      input: draft.input,
      data: draft.data
    });
    analysisStatus.textContent = "completed";
    renderScenario();
    requestAnimationFrame(focusAnalysis);
  } catch (error) {
    state.lastRun = null;
    heroResult.textContent = "error";
    analysisStatus.textContent = "error";
    tabContent.textContent = error.message;
    conditionList.innerHTML = `<div class="error-banner">${error.message}</div>`;
    requestAnimationFrame(focusAnalysis);
  } finally {
    runAnalysis.disabled = false;
  }
}

policyContent.addEventListener("input", syncPolicyDraft);
requestContent.addEventListener("input", syncRequestDraft);
engineSelect.addEventListener("change", syncEngineDraft);
runAnalysis.addEventListener("click", runCurrentScenario);

async function bootstrap() {
  renderScenario();
  try {
    await initRuntime();
    serverStatus.textContent = "Wasm runtime ready. Scenarios execute entirely in the browser.";
  } catch (error) {
    serverStatus.textContent = "Failed to initialize the wasm runtime.";
    conditionList.innerHTML = `<div class="error-banner">${error.message}</div>`;
    runAnalysis.disabled = true;
  }
}

bootstrap();