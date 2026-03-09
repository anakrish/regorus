# Reason examples

This folder contains small Rego policies and matching inputs that are useful when experimenting with reason capture.

Suggested commands:

- Query evaluation with reasons:
  - `cargo run --features reasons --example regorus -- eval -d examples/explanations/basic_violations.rego -i examples/explanations/basic_violations_input.json data.demo.violations --why`
- Complete-rule helper chain with loop summaries:
  - `cargo run --features reasons --example regorus -- eval --engine rvm -d examples/explanations/release_gate.rego -i examples/explanations/release_gate_input.json data.demo.ship --why --why-all-conditions`
- Multiple contributing builtin-style fraud signals:
  - `cargo run --features reasons --example regorus -- eval --engine rvm -d examples/explanations/fraud_signals.rego -i examples/explanations/fraud_signals_input.json data.demo.alerts --why --why-all-conditions`
- Comprehension summary with yielded values:
  - `cargo run --features reasons --example regorus -- eval --engine rvm -d examples/explanations/comprehension_summary.rego -i examples/explanations/comprehension_summary_input.json data.demo.violations --why`
- Inline assignment then predicate check:
  - `cargo run --features reasons --example regorus -- eval --engine interp -d examples/explanations/timezone_inline.rego -d examples/explanations/timezone_inline_data.json data.demo.violations --why`
- Helper rule reused from the violation rule:
  - `cargo run --features reasons --example regorus -- eval --engine interp -d examples/explanations/timezone_helper_positive.rego -d examples/explanations/timezone_helper_positive_data.json data.demo.violations --why`
- Negated helper rule:
  - `cargo run --features reasons --example regorus -- eval --engine interp -d examples/explanations/timezone_helper_negated.rego -d examples/explanations/timezone_helper_negated_data.json data.demo.violations --why`
- Derived tuple then indexed predicate:
  - `cargo run --features reasons --example regorus -- eval --engine interp -d examples/explanations/tuple_index.rego -i examples/explanations/tuple_index_input.json data.demo.violations --why`
- Full values instead of redaction:
  - `cargo run --features reasons --example regorus -- eval -d examples/explanations/secret_redaction.rego -i examples/explanations/secret_redaction_input.json data.demo.violations --why --why-full-values`

Files:

- `basic_violations.rego` / `basic_violations_input.json`
  - partial set violations with direct local bindings
- `allow_from_violations.rego` / `allow_from_violations_input.json`
  - complete boolean rule derived from partial-set violations
- `loop_witnesses.rego` / `loop_witnesses_input.json`
  - loops, iteration variables, and helper rules
- `release_gate.rego` / `release_gate_input.json`
  - complete decision with helper rules, `every`, and supporting findings merged into one why chain
- `fraud_signals.rego` / `fraud_signals_input.json`
  - partial-set alerts that show multiple contributing builtin/comparison conditions
- `comprehension_summary.rego` / `comprehension_summary_input.json`
  - comprehensions whose yielded values show up in structured why output
- `partial_object.rego` / `partial_object_input.json`
  - partial object findings keyed by an id
- `secret_redaction.rego` / `secret_redaction_input.json`
  - bindings that should demonstrate redaction behavior
- `timezone_inline.rego` / `timezone_inline_data.json`
  - direct local assignment followed by a field comparison against data
- `timezone_helper_positive.rego` / `timezone_helper_positive_data.json`
  - helper rule whose success is reused by the violation rule
- `timezone_helper_negated.rego` / `timezone_helper_negated_data.json`
  - helper rule wrapped in `not` to show negated-rule explanations
- `tuple_index.rego` / `tuple_index_input.json`
  - local tuple construction followed by an indexed comparison
