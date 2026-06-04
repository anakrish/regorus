# RVM Diagrams

Mermaid diagram sources illustrating the Regorus Virtual Machine architecture,
value proposition, and strategic vision.

## Technical Diagrams (Engineering)

| # | Diagram | Description |
|---|---------|-------------|
| 01 | [Universal Policy VM](01-universal-policy-vm.mmd) | Multi-language compilation pipeline into unified bytecode |
| 02 | [Register-Based Architecture](02-register-based-architecture.mmd) | VM internals: registers, stacks, caching |
| 03 | [Execution State Machine](03-execution-state-machine.mmd) | Run-to-completion and suspendable modes |
| 04 | [Short-Circuit Optimization](04-short-circuit-optimization.mmd) | Eager vs lazy allOf/anyOf with PolicyOp guards |
| 05 | [Polyglot Reach](05-polyglot-reach.mmd) | One Rust core, 8 language bindings, every platform |
| 06 | [Portable Bytecode](06-portable-bytecode.mmd) | Binary artifact format with forward compatibility |

## Presentation Diagrams (Program Managers)

| # | Diagram | Description |
|---|---------|-------------|
| 07 | [Problem & Solution](07-problem-and-solution.mmd) | Policy fragmentation problem → unified RVM solution |
| 08 | [Policy Lifecycle](08-policy-lifecycle.mmd) | Author → Compile → Ship → Evaluate → Observe |
| 09 | [Strategic Ecosystem](09-strategic-ecosystem.mmd) | RVM at the center: Azure + industry + deployment + languages |
| 10 | [JVM Analogy](10-jvm-analogy.mmd) | "What Java did for apps, RVM does for policy" |
| 11 | [Performance Impact](11-performance-impact.mmd) | Before/after: interpreted vs compiled evaluation |
| 12 | [Azure Policy Flow](12-azure-policy-flow.mmd) | Sequence diagram: real-world Azure evaluation flow |
| 13 | [Safety & Compliance](13-safety-compliance.mmd) | Memory safety, execution safety, auditability |
| 14 | [Playground Experience](14-playground-experience.mmd) | Interactive browser-based policy development |
| 15 | [Competitive Landscape](15-competitive-landscape.mmd) | RVM vs OPA, Cedar SDK, and custom engines |
| 16 | [Vision Timeline](16-vision-timeline.mmd) | Evolution from Regorus → RVM → multi-language → future |
| 17 | [Developer Tooling Platform](17-developer-tooling-platform.mmd) | LSP, IntelliSense, linters, formatters — build once for all languages |

## Rendering

These `.mmd` files can be rendered with any Mermaid-compatible tool:

- **VS Code**: Install the "Mermaid Markdown" extension
- **GitHub**: Mermaid is natively supported in `.md` fenced code blocks
- **CLI**: `npx @mermaid-js/mermaid-cli -i diagram.mmd -o diagram.svg`
- **Online**: Paste into [mermaid.live](https://mermaid.live)

### Suggested presentation order for PM audiences

1. **07** — Start with the problem (fragmentation is expensive)
2. **10** — The JVM analogy (instant understanding)
3. **09** — Strategic ecosystem (where RVM sits)
4. **08** — The lifecycle (how teams use it)
5. **12** — Azure flow (concrete scenario)
6. **11** — Performance impact (the numbers)
7. **13** — Safety & compliance (risk mitigation)
8. **14** — Playground (live demo hook)
9. **15** — Competitive landscape (why us)
10. **17** — Developer tooling platform (LSP, IntelliSense, linters — built once for all)
11. **16** — Vision timeline (where we're going)
