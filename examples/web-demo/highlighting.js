// highlighting.js — Syntax highlighting for Rego, Cedar, JSON/Azure Policy, SMT-LIB

export function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ═══════════════════════════════════════════════════════════
//  OUTPUT HIGHLIGHTING (JSON)
// ═══════════════════════════════════════════════════════════
export function highlightOutput(text) {
  let isJson = false;
  try { JSON.parse(text); isJson = true; } catch {}
  if (!isJson) return escapeHtml(text);

  const result = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') { if (text[j] === '\\') j++; j++; }
      j = Math.min(j + 1, text.length);
      const raw = text.substring(i, j);
      let k = j;
      while (k < text.length && (text[k] === ' ' || text[k] === '\t')) k++;
      if (text[k] === ':') {
        result.push(`<span class="j-k">${escapeHtml(raw)}</span>`);
      } else {
        result.push(`<span class="j-s">${escapeHtml(raw)}</span>`);
      }
      i = j;
    } else if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let j = i;
      if (text[j] === '-') j++;
      while (j < text.length && ((text[j] >= '0' && text[j] <= '9') || text[j] === '.' || text[j] === 'e' || text[j] === 'E' || text[j] === '+' || text[j] === '-')) j++;
      result.push(`<span class="j-n">${escapeHtml(text.substring(i, j))}</span>`);
      i = j;
    } else if (text.startsWith("true", i) || text.startsWith("false", i)) {
      const w = text.startsWith("true", i) ? 4 : 5;
      result.push(`<span class="j-b">${text.substring(i, i + w)}</span>`);
      i += w;
    } else if (text.startsWith("null", i)) {
      result.push(`<span class="j-l">null</span>`);
      i += 4;
    } else {
      result.push(escapeHtml(ch));
      i++;
    }
  }
  return result.join("");
}

// ═══════════════════════════════════════════════════════════
//  KEYWORD HIGHLIGHTING (post-pass over already-highlighted HTML)
// ═══════════════════════════════════════════════════════════
export function applyKeywordHighlights(html, keywords) {
  if (!keywords || keywords.length === 0) return html;
  const sorted = [...keywords].sort((a, b) => b.length - a.length);
  const escaped = sorted.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
  const kwRegex = new RegExp(`(${escaped.join('|')})`, 'gi');
  const parts = html.split(/(<[^>]*>)/);
  for (let i = 0; i < parts.length; i++) {
    if (i % 2 === 0 && parts[i]) {
      parts[i] = parts[i].replace(kwRegex, '<span class="hl-kw">$1</span>');
    }
  }
  return parts.join('');
}

// ═══════════════════════════════════════════════════════════
//  SMT-LIB HIGHLIGHTING
// ═══════════════════════════════════════════════════════════
const SMT_DECLS = new Set(['declare-fun','declare-const','define-fun','define-sort','assert','check-sat','check-sat-assuming','get-model','get-value','push','pop','set-logic','set-option','set-info']);
const SMT_TYPES = new Set(['Bool','Int','String','Real','Array','BitVec','RegLan']);
const SMT_LOGIC = new Set(['and','or','not','ite','xor','implies','forall','exists','let','match','as']);
const SMT_FUNCS = new Set(['str.++','str.len','str.contains','str.prefixof','str.suffixof','str.indexof','str.substr','str.replace','str.replace_all','str.at','str.from_int','str.to_int','str.in_re','str.to_re','int.to.str','re.++','re.union','re.inter','re.range','re.all','re.allchar','re.*','re.+','re.opt','re.comp','re.none','bvadd','bvsub','bvmul','bvand','bvor','bvnot','bvshl','bvlshr','bvashr','select','store','concat','extract','fp.add','fp.mul','fp.div','fp.lt','fp.leq']);

export function highlightSMT(text) {
  const lines = text.split('\n');
  return lines.map(line => {
    const trimmed = line.trimStart();
    if (trimmed.startsWith(';')) return `<span class="smt-cmt">${escapeHtml(line)}</span>`;

    let result = [], i = 0;
    while (i < line.length) {
      const ch = line[i];
      if (ch === '"') {
        let j = i + 1;
        while (j < line.length && line[j] !== '"') { if (line[j] === '\\') j++; j++; }
        j = Math.min(j + 1, line.length);
        result.push(`<span class="smt-str">${escapeHtml(line.substring(i, j))}</span>`);
        i = j;
      } else if (ch === '(' || ch === ')') {
        result.push(`<span class="smt-paren">${ch}</span>`);
        i++;
      } else if (ch === ';') {
        result.push(`<span class="smt-cmt">${escapeHtml(line.substring(i))}</span>`);
        break;
      } else if (/[a-zA-Z_!+\-*\/<>=.?@$%^&#]/.test(ch)) {
        let j = i;
        while (j < line.length && /[a-zA-Z0-9_!+\-*\/<>=.?@$%^&#:]/.test(line[j])) j++;
        const word = line.substring(i, j);
        if (SMT_DECLS.has(word)) result.push(`<span class="smt-decl">${escapeHtml(word)}</span>`);
        else if (SMT_TYPES.has(word)) result.push(`<span class="smt-type">${escapeHtml(word)}</span>`);
        else if (SMT_LOGIC.has(word) || word === '=>') result.push(`<span class="smt-logic">${escapeHtml(word)}</span>`);
        else if (SMT_FUNCS.has(word)) result.push(`<span class="smt-func">${escapeHtml(word)}</span>`);
        else if (word === 'true' || word === 'false') result.push(`<span class="smt-bool">${word}</span>`);
        else result.push(`<span class="smt-var">${escapeHtml(word)}</span>`);
        i = j;
      } else if (ch >= '0' && ch <= '9') {
        let j = i;
        while (j < line.length && /[0-9.]/.test(line[j])) j++;
        result.push(`<span class="smt-num">${line.substring(i, j)}</span>`);
        i = j;
      } else {
        result.push(escapeHtml(ch));
        i++;
      }
    }
    return result.join('');
  }).join('\n');
}

// ═══════════════════════════════════════════════════════════
//  SYNTAX HIGHLIGHTING — Rego
// ═══════════════════════════════════════════════════════════
const REGO_KEYWORDS = new Set(['package','import','default','not','as','with','if','else','some','every','in','contains']);
const REGO_BUILTINS = new Set([
  'count','sum','product','max','min','sort','all','any','concat','contains',
  'endswith','format_int','indexof','lower','replace','split','sprintf',
  'startswith','substring','trim','trim_left','trim_prefix','trim_right',
  'trim_suffix','trim_space','upper','to_number','abs','round','ceil','floor',
  'is_number','is_string','is_boolean','is_array','is_set','is_object','is_null',
  'type_name','json','yaml','base64','urlquery','regex','glob','bits','object',
  'array','set','strings','numbers','print','trace','time','io','opa','http',
  'net','uuid','crypto','fetch',
]);

export function highlightRego(line) {
  const stripped = line.trimStart();
  if (stripped.startsWith('#')) return `<span class="sy-cmt">${escapeHtml(line)}</span>`;

  let code = line, comment = '';
  const ci = findCommentStart(line);
  if (ci >= 0) { code = line.substring(0, ci); comment = line.substring(ci); }

  let result = '', i = 0;
  while (i < code.length) {
    if (code[i] === '"') {
      let j = i + 1;
      while (j < code.length && code[j] !== '"') { if (code[j] === '\\') j++; j++; }
      j = Math.min(j + 1, code.length);
      result += `<span class="sy-str">${escapeHtml(code.substring(i, j))}</span>`;
      i = j;
    } else if (code[i] === '`') {
      let j = code.indexOf('`', i + 1);
      if (j < 0) j = code.length - 1;
      j++;
      result += `<span class="sy-str">${escapeHtml(code.substring(i, j))}</span>`;
      i = j;
    } else if (':=!<>&|'.includes(code[i])) {
      let op = code[i];
      if (i + 1 < code.length && '='.includes(code[i + 1])) op += code[++i];
      result += `<span class="sy-op">${escapeHtml(op)}</span>`;
      i++;
    } else if (/[a-zA-Z_]/.test(code[i])) {
      let j = i;
      while (j < code.length && /[a-zA-Z0-9_]/.test(code[j])) j++;
      const word = code.substring(i, j);
      if (REGO_KEYWORDS.has(word)) result += `<span class="sy-kw">${word}</span>`;
      else if (word === 'true' || word === 'false') result += `<span class="sy-bool">${word}</span>`;
      else if (REGO_BUILTINS.has(word) && j < code.length && code[j] === '(') result += `<span class="sy-bi">${word}</span>`;
      else result += escapeHtml(word);
      i = j;
    } else if (/[0-9]/.test(code[i])) {
      let j = i;
      while (j < code.length && /[0-9.]/.test(code[j])) j++;
      result += `<span class="sy-num">${escapeHtml(code.substring(i, j))}</span>`;
      i = j;
    } else {
      result += escapeHtml(code[i]);
      i++;
    }
  }
  if (comment) result += `<span class="sy-cmt">${escapeHtml(comment)}</span>`;
  return result;
}

function findCommentStart(line) {
  let inStr = false, sCh = '';
  for (let i = 0; i < line.length; i++) {
    if (inStr) { if (line[i] === '\\') { i++; continue; } if (line[i] === sCh) inStr = false; }
    else { if (line[i] === '"' || line[i] === '`') { inStr = true; sCh = line[i]; } if (line[i] === '#') return i; }
  }
  return -1;
}

// ═══════════════════════════════════════════════════════════
//  SYNTAX HIGHLIGHTING — Cedar
// ═══════════════════════════════════════════════════════════
const CEDAR_EFFECTS = new Set(['permit', 'forbid']);
const CEDAR_KW = new Set(['when', 'unless', 'if', 'then', 'else', 'in', 'like', 'has', 'is']);
const CEDAR_ACTORS = new Set(['principal', 'action', 'resource', 'context']);

export function highlightCedar(line) {
  const stripped = line.trimStart();
  if (stripped.startsWith('//')) return `<span class="sy-cmt">${escapeHtml(line)}</span>`;

  let code = line, comment = '';
  const ci = line.indexOf('//');
  if (ci >= 0) {
    let inStr = false;
    for (let k = 0; k < line.length; k++) {
      if (line[k] === '"') inStr = !inStr;
      if (!inStr && line[k] === '/' && line[k+1] === '/') {
        code = line.substring(0, k);
        comment = line.substring(k);
        break;
      }
    }
  }

  let result = '', i = 0;
  while (i < code.length) {
    if (code[i] === '"') {
      let j = i + 1;
      while (j < code.length && code[j] !== '"') { if (code[j] === '\\') j++; j++; }
      j = Math.min(j + 1, code.length);
      result += `<span class="sy-str">${escapeHtml(code.substring(i, j))}</span>`;
      i = j;
    } else if (/[a-zA-Z_]/.test(code[i])) {
      let j = i;
      while (j < code.length && /[a-zA-Z0-9_]/.test(code[j])) j++;
      const word = code.substring(i, j);
      if (code[j] === ':' && code[j+1] === ':') {
        result += `<span class="sy-type">${escapeHtml(word)}</span>`;
      } else if (CEDAR_EFFECTS.has(word)) {
        result += `<span class="sy-eff">${word}</span>`;
      } else if (CEDAR_KW.has(word)) {
        result += `<span class="sy-kw">${word}</span>`;
      } else if (CEDAR_ACTORS.has(word)) {
        result += `<span class="sy-act">${word}</span>`;
      } else if (word === 'true' || word === 'false') {
        result += `<span class="sy-bool">${word}</span>`;
      } else {
        result += escapeHtml(word);
      }
      i = j;
    } else if (/[0-9]/.test(code[i])) {
      let j = i;
      while (j < code.length && /[0-9.]/.test(code[j])) j++;
      result += `<span class="sy-num">${escapeHtml(code.substring(i, j))}</span>`;
      i = j;
    } else if ('=<>!&|'.includes(code[i])) {
      let op = code[i];
      if (i + 1 < code.length && '='.includes(code[i+1])) op += code[++i];
      result += `<span class="sy-op">${escapeHtml(op)}</span>`;
      i++;
    } else {
      result += escapeHtml(code[i]);
      i++;
    }
  }
  if (comment) result += `<span class="sy-cmt">${escapeHtml(comment)}</span>`;
  return result;
}

// ═══════════════════════════════════════════════════════════
//  SYNTAX HIGHLIGHTING — JSON (line-by-line, Azure Policy aware)
// ═══════════════════════════════════════════════════════════
const AZ_LOGIC_KEYS = new Set(['"allOf"','"anyOf"','"not"','"if"','"then"','"policyRule"']);
const AZ_OP_KEYS = new Set(['"equals"','"notEquals"','"contains"','"notContains"','"in"','"notIn"','"like"','"notLike"','"exists"','"greater"','"greaterOrEquals"','"less"','"lessOrEquals"','"match"','"notMatch"','"matchInsensitively"','"notMatchInsensitively"','"containsKey"','"notContainsKey"']);
const AZ_FIELD_KEYS = new Set(['"field"','"count"','"value"','"source"']);
const AZ_EFFECT_KEYS = new Set(['"effect"']);
const AZ_EFFECT_VALUES = new Set(['"deny"','"audit"','"disabled"','"Deny"','"Audit"','"Disabled"']);

export function highlightJsonLine(line) {
  let result = [], i = 0;
  while (i < line.length) {
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length && line[j] !== '"') { if (line[j] === '\\') j++; j++; }
      j = Math.min(j + 1, line.length);
      const raw = line.substring(i, j);
      let k = j;
      while (k < line.length && (line[k] === ' ' || line[k] === '\t')) k++;
      if (line[k] === ':') {
        if (AZ_LOGIC_KEYS.has(raw)) result.push(`<span class="j-az-logic">${escapeHtml(raw)}</span>`);
        else if (AZ_OP_KEYS.has(raw)) result.push(`<span class="j-az-op">${escapeHtml(raw)}</span>`);
        else if (AZ_FIELD_KEYS.has(raw)) result.push(`<span class="j-az-field">${escapeHtml(raw)}</span>`);
        else if (AZ_EFFECT_KEYS.has(raw)) result.push(`<span class="j-az-eff">${escapeHtml(raw)}</span>`);
        else result.push(`<span class="j-k">${escapeHtml(raw)}</span>`);
      } else {
        if (AZ_EFFECT_VALUES.has(raw)) result.push(`<span class="j-az-eff">${escapeHtml(raw)}</span>`);
        else result.push(`<span class="j-s">${escapeHtml(raw)}</span>`);
      }
      i = j;
    } else if (line[i] === '-' || (line[i] >= '0' && line[i] <= '9')) {
      let j = i;
      if (line[j] === '-') j++;
      while (j < line.length && ((line[j] >= '0' && line[j] <= '9') || line[j] === '.')) j++;
      result.push(`<span class="j-n">${escapeHtml(line.substring(i, j))}</span>`);
      i = j;
    } else if (line.startsWith("true", i) || line.startsWith("false", i)) {
      const w = line.startsWith("true", i) ? 4 : 5;
      result.push(`<span class="j-b">${line.substring(i, i + w)}</span>`);
      i += w;
    } else if (line.startsWith("null", i)) {
      result.push(`<span class="j-l">null</span>`);
      i += 4;
    } else {
      result.push(escapeHtml(line[i]));
      i++;
    }
  }
  return result.join("");
}
