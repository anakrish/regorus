import init, { Engine, Rvm } from "./pkg/regorusjs.js";

let runtimePromise;

export function initRuntime() {
  if (!runtimePromise) {
    runtimePromise = init();
  }
  return runtimePromise;
}

export function formatJson(value) {
  return JSON.stringify(value, null, 2);
}

function parseJsonText(label, text) {
  try {
    return JSON.stringify(JSON.parse(text || "{}"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function explanationMode(options) {
  return {
    enabled: true,
    valueMode: options.whyFullValues ? "full" : "redacted",
    conditionMode: options.whyAllConditions ? "all_contributing" : "primary_only"
  };
}

function summarizeEvaluation(evaluation) {
  if (!evaluation) {
    return { meta: [], checks: [] };
  }

  const meta = [];
  const checks = [];
  if (evaluation.operator) {
    meta.push(`operator: ${evaluation.operator}`);
  }
  if (Object.prototype.hasOwnProperty.call(evaluation, "actual_value")) {
    meta.push(`actual: ${JSON.stringify(evaluation.actual_value)}`);
  }
  if (Object.prototype.hasOwnProperty.call(evaluation, "expected_value")) {
    meta.push(`expected: ${JSON.stringify(evaluation.expected_value)}`);
  }
  if (evaluation.witness?.iteration_count != null) {
    meta.push(`${evaluation.witness.iteration_count} iterations`);
  }
  if (evaluation.witness?.success_count != null) {
    meta.push(`${evaluation.witness.success_count} successes`);
  }
  if (evaluation.witness?.yield_count != null) {
    meta.push(`${evaluation.witness.yield_count} yielded values`);
  }
  if (evaluation.witness?.condition_texts?.length) {
    checks.push(...evaluation.witness.condition_texts);
  }
  return { meta, checks };
}

function summarizeWitness(witness) {
  if (!witness) {
    return [];
  }

  const details = [];
  if (witness.passing_iteration?.sample_value !== undefined) {
    details.push(`passing sample: ${JSON.stringify(witness.passing_iteration.sample_value)}`);
  }
  if (witness.failing_iteration?.sample_value !== undefined) {
    details.push(`failing sample: ${JSON.stringify(witness.failing_iteration.sample_value)}`);
  }
  if (witness.sample_value !== undefined && !details.length) {
    details.push(`sample: ${JSON.stringify(witness.sample_value)}`);
  }
  return details;
}

export function renderConditionCards(container, reasons) {
  container.innerHTML = "";

  if (!reasons.length) {
    container.innerHTML = '<div class="loading-card">No conditions were returned for this evaluation.</div>';
    return;
  }

  reasons.forEach((reason) => {
    const group = document.createElement("article");
    group.className = "reason-group";

    const header = document.createElement("div");
    header.className = "reason-header";
    header.innerHTML = `
      <div>
        <p class="reason-label">Observed result</p>
        <h4 class="reason-result">${JSON.stringify(reason.result)}</h4>
      </div>
      <span class="result-count">${reason.conditions.length} condition${reason.conditions.length === 1 ? "" : "s"}</span>
    `;

    const list = document.createElement("div");
    list.className = "reason-condition-list";

    reason.conditions.forEach((condition, index) => {
      const item = document.createElement("section");
      item.className = "condition-card nested-condition-card";

      const top = document.createElement("div");
      top.className = "condition-topline";
      top.innerHTML = `
        <div class="condition-heading">
          <span class="condition-index">${index + 1}</span>
          <span class="badge ${condition.outcome}">${condition.outcome}</span>
          <span class="condition-kind">${condition.evaluation?.kind || "condition"}</span>
        </div>
        <span class="condition-location">${condition.location?.row ? `L${condition.location.row}` : ""}</span>
      `;

      const text = document.createElement("p");
      text.className = "condition-text";
      text.textContent = condition.text;

      const evaluationSummary = summarizeEvaluation(condition.evaluation);
      const meta = document.createElement("div");
      meta.className = "condition-meta";
      [...evaluationSummary.meta, ...summarizeWitness(condition.evaluation?.witness)].forEach((entry) => {
        const chip = document.createElement("span");
        chip.className = "meta-chip";
        chip.textContent = entry;
        meta.appendChild(chip);
      });

      let checks = null;
      if (evaluationSummary.checks.length) {
        checks = document.createElement("div");
        checks.className = "condition-detail-group";

        const label = document.createElement("p");
        label.className = "condition-detail-label";
        label.textContent = "Checks";

        const list = document.createElement("ul");
        list.className = "condition-detail-list";
        evaluationSummary.checks.forEach((entry) => {
          const item = document.createElement("li");
          item.className = "condition-detail-item";
          item.textContent = entry;
          list.appendChild(item);
        });

        checks.appendChild(label);
        checks.appendChild(list);
      }

      let bindings = null;
      if (condition.bindings?.length) {
        bindings = document.createElement("div");
        bindings.className = "condition-detail-group condition-bindings";
        const label = document.createElement("p");
        label.className = "condition-detail-label";
        label.textContent = "Bindings";

        const list = document.createElement("ul");
        list.className = "condition-detail-list";
        condition.bindings.forEach((binding) => {
          const item = document.createElement("li");
          item.className = "condition-detail-item binding-item";
          item.textContent = `${binding.name} = ${JSON.stringify(binding.value)}`;
          list.appendChild(item);
        });
        bindings.appendChild(label);
        bindings.appendChild(list);
      }

      item.appendChild(top);
      item.appendChild(text);
      if (meta.childElementCount) {
        item.appendChild(meta);
      }
      if (checks) {
        item.appendChild(checks);
      }
      if (bindings) {
        item.appendChild(bindings);
      }
      list.appendChild(item);
    });

    group.appendChild(header);
    group.appendChild(list);
    container.appendChild(group);
  });
}

function summarizeQueryResults(result) {
  const expressions = result?.result?.[0]?.expressions ?? [];
  if (!expressions.length) {
    return "undefined";
  }
  return summarizeValue(expressions[0].value);
}

function summarizeValue(value) {
  if (typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    return `${value.length} result(s)`;
  }
  if (value && typeof value === "object") {
    return `object with ${Object.keys(value).length} field(s)`;
  }
  return JSON.stringify(value);
}

async function evaluateInterpreter(options) {
  const engine = new Engine();
  engine.addPolicy("demo.rego", options.policy);
  engine.addDataJson(parseJsonText("Data", options.data));
  engine.setInputJson(parseJsonText("Input", options.input));

  const mode = explanationMode(options);
  engine.setExplanationOptions(mode.enabled, mode.valueMode, mode.conditionMode);

  const result = JSON.parse(engine.evalQuery(options.query));
  const why = JSON.parse(engine.takeExplanations());
  return {
    result,
    why,
    resultSummary: summarizeQueryResults(result)
  };
}

async function evaluateRvm(options) {
  const vm = new Rvm();
  const mode = explanationMode(options);
  vm.setExplanationOptions(mode.enabled, mode.valueMode, mode.conditionMode);
  vm.loadModules(
    parseJsonText("Data", options.data),
    JSON.stringify([{ id: "demo.rego", content: options.policy }]),
    JSON.stringify([options.query])
  );
  vm.setInputJson(parseJsonText("Input", options.input));

  const result = JSON.parse(vm.executeEntryPoint(options.query));
  const why = JSON.parse(vm.takeExplanations());
  return {
    result,
    why,
    resultSummary: summarizeValue(result)
  };
}

export async function evaluatePolicy(options) {
  await initRuntime();
  const started = performance.now();
  const payload = options.engine === "rvm"
    ? await evaluateRvm(options)
    : await evaluateInterpreter(options);

  return {
    ...payload,
    runtimeMs: Math.round(performance.now() - started)
  };
}

export async function evaluateScenario(scenario) {
  return evaluatePolicy(scenario);
}

export async function evaluateCustom(request) {
  if (!request.policy?.trim()) {
    throw new Error("Policy must not be empty.");
  }
  if (!request.query?.trim()) {
    throw new Error("Entry point must not be empty.");
  }
  return evaluatePolicy(request);
}