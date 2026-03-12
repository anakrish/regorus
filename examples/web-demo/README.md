# Regorus Policy Analysis — Web Demo

A fully client-side web demo that runs Rego policy analysis entirely in the
browser using WASM:

- **regorus** (compiled to WASM) translates policies into SMT constraints
- **z3-solver** (Z3 compiled to WASM) solves the constraints
- No server needed — everything runs in your browser

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

## Building

```bash
# 1. Build the regorus WASM module with policy-analysis support
cd ../../bindings/wasm
wasm-pack build --target web --release -- --features policy-analysis
cd ../../examples/web-demo

# 2. Install npm dependencies (z3-solver)
npm install

# 3. Start the dev server (with required COOP/COEP headers for SharedArrayBuffer)
npm start
```

Then open http://localhost:8080 in your browser.

## How It Works

1. You enter a Rego policy + desired output in the browser
2. **regorus WASM** compiles the policy and translates it to SMT constraints
3. The SMT-LIB2 text is sent to **Z3 WASM** (running in a Web Worker)
4. Z3 solves the constraints and returns a model
5. The model is parsed and sent back to **regorus WASM** for interpretation
6. The synthesized input is displayed

## Architecture

```
Browser
┌─────────────────────────────────────────────────────┐
│                                                     │
│  ┌──────────┐   SMT-LIB2    ┌──────────────────┐   │
│  │ regorus  │ ──────────────>│  Z3 WASM Worker  │   │
│  │  WASM    │                │  (z3-solver npm)  │   │
│  │          │ <──────────────│                    │   │
│  │          │  SmtCheckResult│                    │   │
│  └──────────┘   (JSON)       └──────────────────┘   │
│       │                                             │
│       v                                             │
│  AnalysisResult (synthesized input)                 │
│                                                     │
└─────────────────────────────────────────────────────┘
```
