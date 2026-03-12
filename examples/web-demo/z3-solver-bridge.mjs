// z3-solver-bridge.mjs
//
// Bridge between regorus SMT-LIB2 output and the z3-solver npm package.
// Designed to run in a browser with <script> tag loading z3-built.js first.
//
// Usage:
//   <script src="/z3-solver/build/z3-built.js"></script>
//   <script type="module">
//     import { initZ3, solveSmtLib2 } from './z3-solver-bridge.mjs';
//     await initZ3();
//     const result = await solveSmtLib2(smtLib2Text, numExtractions);
//   </script>

let Z3 = null;
let emModule = null;

/**
 * Initialize the Z3 WASM solver.
 * Must be called once before solveSmtLib2().
 * Requires z3-built.js to have been loaded via <script> tag.
 *
 * @returns {Promise<void>}
 */
export async function initZ3() {
  if (Z3) return; // already initialized

  if (typeof window.initZ3 === 'undefined') {
    throw new Error(
      'z3-built.js must be loaded via <script> tag before calling initZ3(). ' +
      'Expected window.initZ3 to be defined.'
    );
  }

  // Initialize the low-level wrapper using the Emscripten module.
  const Mod = await window.initZ3();
  emModule = Mod;

  // Build a minimal Z3 API object with the functions we need.
  Z3 = {
    mk_config: Mod._Z3_mk_config,
    del_config: Mod._Z3_del_config,
    mk_context: (cfg) => {
      const ctx = Mod._Z3_mk_context(cfg);
      Mod._set_noop_error_handler(ctx);
      return ctx;
    },
    del_context: Mod._Z3_del_context,
    eval_smtlib2_string: async (ctx, str) => {
      // async_call resolves with the string result directly (not a pointer)
      const result = await Mod.async_call(() =>
        Mod.ccall('async_Z3_eval_smtlib2_string', 'void', ['number', 'string'], [ctx, str])
      );
      return result || '';
    },
    get_error_code: Mod._Z3_get_error_code,
    get_error_msg: (ctx) => {
      return Mod.ccall('Z3_get_error_msg', 'string', ['number', 'number'],
        [ctx, Mod._Z3_get_error_code(ctx)]) || '';
    },
  };
}

/**
 * Solve an SMT-LIB2 script and return an SmtCheckResult JSON string.
 *
 * The SMT-LIB2 script is expected to be produced by regorus's
 * `PreparedProblem::render_smt_lib2()`.  It contains:
 *   - (set-logic ALL)
 *   - declarations
 *   - assertions
 *   - (check-sat)
 *   - (get-value (...))  -- optional
 *   - (exit)
 *
 * @param {string} smtLib2 -- The SMT-LIB2 script text.
 * @param {number} numExtractions -- Number of extractions expected.
 * @returns {Promise<string>} -- JSON string of SmtCheckResult.
 */
export async function solveSmtLib2(smtLib2, numExtractions) {
  if (!Z3) throw new Error('Z3 not initialized. Call initZ3() first.');

  // Create a fresh context.
  const cfg = Z3.mk_config();
  const ctx = Z3.mk_context(cfg);
  Z3.del_config(cfg);

  try {
    // Strip (exit)
    let script = smtLib2.replace(/\(exit\)\s*$/m, '');

    // Split: everything before (check-sat), then (check-sat), then after
    const checkSatIdx = script.lastIndexOf('(check-sat)');
    if (checkSatIdx === -1) {
      return JSON.stringify({
        status: 'Unknown',
        values: [],
        unsat_core: [],
        reason_unknown: 'No (check-sat) found in SMT-LIB2 script',
        stats: null,
      });
    }

    // Run the prelude (declarations + assertions)
    const prelude = script.substring(0, checkSatIdx).trim();
    if (prelude) {
      const preludeResult = await Z3.eval_smtlib2_string(ctx, prelude);
      if (preludeResult && preludeResult.trim()) {
        const lines = preludeResult.trim().split('\n').filter(l => l.trim() !== '' && l.trim() !== 'success');
        if (lines.length > 0) {
          console.warn('Z3 prelude output:', preludeResult);
        }
      }
    }

    // Check satisfiability
    const checkResult = await Z3.eval_smtlib2_string(ctx, '(check-sat)');
    const status = checkResult.trim();

    if (status === 'sat') {
      // Extract values
      const afterCheckSat = script.substring(checkSatIdx + '(check-sat)'.length).trim();
      let values = [];

      if (afterCheckSat && afterCheckSat.includes('(get-value')) {
        const getValueResult = await Z3.eval_smtlib2_string(ctx, afterCheckSat);
        const errCode = Z3.get_error_code(ctx);
        if (errCode !== 0) {
          console.error('[z3-bridge] Z3 error after get-value:', errCode, Z3.get_error_msg(ctx));
        }
        values = parseGetValueOutput(getValueResult, numExtractions);
      }

      return JSON.stringify({
        status: 'Sat',
        values,
        unsat_core: [],
        reason_unknown: null,
        stats: null,
      });
    } else if (status === 'unsat') {
      return JSON.stringify({
        status: 'Unsat',
        values: [],
        unsat_core: [],
        reason_unknown: null,
        stats: null,
      });
    } else {
      return JSON.stringify({
        status: 'Unknown',
        values: [],
        unsat_core: [],
        reason_unknown: status || 'solver returned unknown',
        stats: null,
      });
    }
  } finally {
    Z3.del_context(ctx);
  }
}

// ---------------------------------------------------------------------------
// S-expression parser for Z3 (get-value ...) output
// ---------------------------------------------------------------------------

/**
 * Parse Z3's (get-value ...) output into an array of SmtValue objects.
 *
 * Z3 output format:
 *   ((expr1 val1)\n (expr2 val2)\n ...)
 */
function parseGetValueOutput(output, numExtractions) {
  const values = [];
  if (!output || !output.trim()) {
    for (let i = 0; i < numExtractions; i++) values.push('Undefined');
    return values;
  }

  const pairs = parseSexprPairs(output.trim());
  for (const [, valStr] of pairs) {
    values.push(parseSmtValue(valStr));
  }

  // Pad with Undefined if fewer values than expected
  while (values.length < numExtractions) {
    values.push('Undefined');
  }

  return values;
}

/**
 * Parse an S-expression of the form ((a b) (c d) ...) into pairs.
 */
function parseSexprPairs(input) {
  const pairs = [];
  let i = 0;
  const s = input.trim();

  if (s[i] !== '(') return pairs;
  i++;

  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (s[i] === ')') break;
    if (s[i] !== '(') break;
    i++;

    const exprStart = i;
    i = skipSexpr(s, i);
    const exprStr = s.substring(exprStart, i).trim();

    while (i < s.length && /\s/.test(s[i])) i++;

    const valStart = i;
    i = skipSexpr(s, i);
    const valStr = s.substring(valStart, i).trim();

    while (i < s.length && /\s/.test(s[i])) i++;
    if (s[i] === ')') i++;

    pairs.push([exprStr, valStr]);
  }

  return pairs;
}

/**
 * Skip one S-expression starting at position i.
 */
function skipSexpr(s, i) {
  if (i >= s.length) return i;

  if (s[i] === '(') {
    let depth = 1;
    i++;
    while (i < s.length && depth > 0) {
      if (s[i] === '"') {
        i++;
        while (i < s.length && s[i] !== '"') {
          if (s[i] === '\\') i++;
          i++;
        }
        i++;
      } else if (s[i] === '(') { depth++; i++; }
      else if (s[i] === ')') { depth--; i++; }
      else i++;
    }
    return i;
  } else if (s[i] === '"') {
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\') i++;
      i++;
    }
    i++;
    return i;
  } else {
    while (i < s.length && !/[\s()]/.test(s[i])) i++;
    return i;
  }
}

/**
 * Parse a Z3 value string into an SmtValue object (regorus-smt schema).
 */
function parseSmtValue(valStr) {
  const v = valStr.trim();

  if (v === 'true') return { Bool: true };
  if (v === 'false') return { Bool: false };

  if (v.startsWith('"') && v.endsWith('"')) {
    return { String: v.slice(1, -1).replace(/\\\\/g, '\\').replace(/\\"/g, '"') };
  }

  // Integer
  if (/^-?\d+$/.test(v)) return { Int: parseInt(v, 10) };

  // Negative integer: (- N)
  const negMatch = v.match(/^\(-\s+(\d+)\)$/);
  if (negMatch) return { Int: -parseInt(negMatch[1], 10) };

  // Rational: (/ N D)
  const ratMatch = v.match(/^\(\/\s+(-?\d+)\s+(\d+)\)$/);
  if (ratMatch) return { Real: [parseInt(ratMatch[1], 10), parseInt(ratMatch[2], 10)] };

  // Negative rational: (- (/ N D))
  const negRatMatch = v.match(/^\(-\s+\(\/\s+(\d+)\s+(\d+)\)\)$/);
  if (negRatMatch) return { Real: [-parseInt(negRatMatch[1], 10), parseInt(negRatMatch[2], 10)] };

  // Decimal: N.D
  if (/^-?\d+\.\d+$/.test(v)) {
    const parts = v.split('.');
    const denom = Math.pow(10, parts[1].length);
    const numer = parseInt(parts[0] + parts[1], 10);
    return { Real: [numer, denom] };
  }

  // Fallback
  return { String: v };
}
