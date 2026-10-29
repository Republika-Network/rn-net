// A small tokenizer for the ECMAScript module source used in packages/**. It exists so the
// dependency-boundary guard reads imports as tokens, with comments, strings, template literals and
// regular expressions already separated out, instead of matching raw text.
//
// It supports a deliberately narrow language: anything it does not recognize (unterminated
// literals, escaped identifiers, legacy octal escapes, unknown characters) throws
// UnsupportedSyntax, and the guard reports the file instead of guessing.
//
// Whether a `/` starts a regular expression depends on the grammar. Without a full parser, the
// tokenizer decides from the previous token and from what the enclosing brackets were: a `)`
// that closes an `if`, `for`, `while` or `with` condition, and a `}` that closes a block, are
// followed by a regular expression; other `)` by a division. Where the answer would need a full
// parser, the tokenizer fails closed instead: a `/` after a `}` it did not classify as a block
// (an object literal, but also a labelled block or a `case` block), or after `of`, is
// UnsupportedSyntax. The remaining known misreading is a function or class expression body
// followed by a division, which is read as a regular expression; the raw pattern checks in the
// guard apply to every file as a second layer.

export class UnsupportedSyntax extends Error {}

// Keywords after which `/` starts a regular expression rather than a division.
const REGEX_AFTER_KEYWORD = new Set([
  'return', 'typeof', 'instanceof', 'in', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await',
]);
// Keywords after which `{` starts an object literal rather than a block.
const EXPRESSION_KEYWORDS = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'yield', 'await',
]);
// Statements whose parenthesized condition is followed by a statement, which may begin with a
// regular expression.
const CONDITION_KEYWORDS = new Set(['if', 'for', 'while', 'with']);

const PUNCTUATORS = [
  '>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '&&=', '||=', '??=',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '**', '<<', '>>',
  '{', '}', '(', ')', '[', ']', ';', ',', '<', '>', '+', '-', '*', '/', '%', '&', '|', '^', '!', '~', '?', ':', '=', '.', '@',
];

const WHITESPACE = /[\s\uFEFF]/u; // includes line terminators, U+2028 and U+2029
const LINE_TERMINATOR = /[\n\r\u2028\u2029]/u;
const IDENTIFIER_START = /[\p{ID_Start}$_]/u;
const IDENTIFIER_PART = /[\p{ID_Continue}$\u200C\u200D]/u;
const NUMBER = /0[xXoObB][\da-fA-F_]+n?|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?n?/y;
// A name after `.` or `?.` is a property name, not a keyword (`x.if(...)`).
const isMemberName = (token) => token?.type === 'punctuator' && (token.value === '.' || token.value === '?.');
const SINGLE_ESCAPES = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', 0: '\0' };

/**
 * Tokens of a module: { type, value, start }, where type is 'identifier', 'private', 'string',
 * 'template' (one per literal chunk), 'number', 'regex' or 'punctuator'. String and template
 * values are cooked (escapes decoded). Comments and whitespace are dropped.
 */
export function tokenize(source) {
  const tokens = [];
  const braces = []; // { block } for `{`, or '${' for a template substitution
  const parens = []; // for each open `(`: whether it holds a statement condition
  let i = 0;

  const fail = (what) => {
    throw new UnsupportedSyntax(`${what} at offset ${i}`);
  };
  const codePointAt = (index) => (index < source.length ? String.fromCodePoint(source.codePointAt(index)) : '');

  if (source.startsWith('#!')) while (i < source.length && !LINE_TERMINATOR.test(source[i])) i++;

  // Whether a `{` here opens a block (rather than an object literal).
  const opensBlock = () => {
    const prev = tokens.at(-1);
    if (prev === undefined) return true;
    if (prev.type === 'punctuator') return [';', '{', '}', ')', '=>'].includes(prev.value);
    if (prev.type === 'identifier') return !EXPRESSION_KEYWORDS.has(prev.value);
    return false;
  };

  const regexAllowed = () => {
    const prev = tokens.at(-1);
    if (prev === undefined) return true;
    if (prev.type === 'punctuator') {
      if (prev.value === '}' && !prev.regexAfter) fail('`/` after an object literal or labelled block is ambiguous');
      if (prev.value === ')' || prev.value === '}') return prev.regexAfter;
      return prev.value !== ']';
    }
    if (prev.type === 'identifier' && !isMemberName(tokens.at(-2))) {
      // `of` is a keyword only in for-of; as a variable name it is followed by a division.
      if (prev.value === 'of') fail('`/` after `of` is ambiguous');
      return REGEX_AFTER_KEYWORD.has(prev.value);
    }
    return false;
  };

  // Reads an escape sequence starting after the backslash; returns the cooked text.
  const readEscape = (inTemplate) => {
    const c = source[i++];
    if (c === undefined) fail('unterminated escape');
    if (c === '\r' && source[i] === '\n') i++;
    if (LINE_TERMINATOR.test(c)) return ''; // line continuation
    if (c === 'x') {
      const hex = source.slice(i, i + 2);
      if (!/^[\da-fA-F]{2}$/.test(hex)) fail('malformed \\x escape');
      i += 2;
      return String.fromCharCode(parseInt(hex, 16));
    }
    if (c === 'u') return String.fromCodePoint(readUnicodeEscape());
    if (c === '0' && !/\d/.test(source[i] ?? '')) return '\0';
    if (/\d/.test(c)) fail(inTemplate ? 'numeric escape in template' : 'legacy octal escape');
    return SINGLE_ESCAPES[c] ?? c;
  };

  const readUnicodeEscape = () => {
    let hex;
    if (source[i] === '{') {
      const end = source.indexOf('}', i);
      hex = end === -1 ? '' : source.slice(i + 1, end);
      if (!/^[\da-fA-F]{1,6}$/.test(hex)) fail('malformed \\u{} escape');
      i = end + 1;
    } else {
      hex = source.slice(i, i + 4);
      if (!/^[\da-fA-F]{4}$/.test(hex)) fail('malformed \\u escape');
      i += 4;
    }
    const codePoint = parseInt(hex, 16);
    if (codePoint > 0x10ffff) fail('escape outside Unicode');
    return codePoint;
  };

  // Reads template characters up to the closing backtick or a `${`.
  const readTemplateChunk = (start) => {
    let value = '';
    for (;;) {
      const c = source[i];
      if (c === undefined) fail('unterminated template literal');
      if (c === '`') {
        i++;
        break;
      }
      if (c === '$' && source[i + 1] === '{') {
        i += 2;
        braces.push('${');
        break;
      }
      i++;
      if (c !== '\\') {
        value += c;
        continue;
      }
      // A tagged template (String.raw`\d`) may contain escapes that have no cooked value; keep
      // their raw text.
      const escapeStart = i;
      try {
        value += readEscape(true);
      } catch {
        i = escapeStart;
        value += `\\${source[i++] ?? ''}`;
      }
    }
    tokens.push({ type: 'template', value, start });
  };

  while (i < source.length) {
    const start = i;
    const c = source[i];

    if (WHITESPACE.test(c)) {
      i++;
      continue;
    }
    if (c === '/' && source[i + 1] === '/') {
      while (i < source.length && !LINE_TERMINATOR.test(source[i])) i++;
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end === -1) fail('unterminated comment');
      i = end + 2;
      continue;
    }
    if (c === '"' || c === "'") {
      i++;
      let value = '';
      for (;;) {
        const d = source[i];
        if (d === undefined || d === '\n' || d === '\r') fail('unterminated string');
        i++;
        if (d === c) break;
        value += d === '\\' ? readEscape(false) : d;
      }
      tokens.push({ type: 'string', value, start });
      continue;
    }
    if (c === '`') {
      i++;
      readTemplateChunk(start);
      continue;
    }
    if (c === '}' && braces.at(-1) === '${') {
      braces.pop();
      i++;
      readTemplateChunk(start);
      continue;
    }
    if (c === '/' && regexAllowed()) {
      i++;
      let inClass = false;
      for (;;) {
        const d = source[i];
        if (d === undefined || LINE_TERMINATOR.test(d)) fail('unterminated regular expression');
        i++;
        if (d === '\\') {
          if (source[i] === undefined || LINE_TERMINATOR.test(source[i])) fail('unterminated regular expression');
          i++;
        } else if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) break;
      }
      while (i < source.length && IDENTIFIER_PART.test(codePointAt(i))) i += codePointAt(i).length;
      tokens.push({ type: 'regex', value: source.slice(start, i), start });
      continue;
    }
    if (c === '\\') fail('escaped identifier');
    const first = codePointAt(i);
    if (IDENTIFIER_START.test(first) || (c === '#' && IDENTIFIER_START.test(codePointAt(i + 1)))) {
      i += c === '#' ? 1 : 0;
      while (i < source.length && IDENTIFIER_PART.test(codePointAt(i))) i += codePointAt(i).length;
      if (source[i] === '\\') fail('escaped identifier');
      const name = source.slice(start, i);
      tokens.push({ type: c === '#' ? 'private' : 'identifier', value: name, start });
      continue;
    }
    NUMBER.lastIndex = i;
    const number = /\d/.test(c) || (c === '.' && /\d/.test(source[i + 1] ?? '')) ? NUMBER.exec(source) : null;
    if (number) {
      i = NUMBER.lastIndex;
      if (IDENTIFIER_PART.test(source[i] ?? '')) fail('malformed number');
      tokens.push({ type: 'number', value: number[0], start });
      continue;
    }
    const punctuator = PUNCTUATORS.find((p) => source.startsWith(p, i) && !(p === '?.' && /\d/.test(source[i + 2] ?? '')));
    if (punctuator === undefined) fail(`unsupported character ${JSON.stringify(c)}`);
    const token = { type: 'punctuator', value: punctuator, start };
    if (punctuator === '{') braces.push({ block: opensBlock() });
    if (punctuator === '(') {
      const prev = tokens.at(-1);
      parens.push(prev?.type === 'identifier' && CONDITION_KEYWORDS.has(prev.value) && !isMemberName(tokens.at(-2)));
    }
    if (punctuator === '}') {
      const open = braces.pop();
      if (open === undefined) fail('unbalanced }');
      token.regexAfter = open.block;
    }
    if (punctuator === ')') {
      if (parens.length === 0) fail('unbalanced )');
      token.regexAfter = parens.pop();
    }
    i += punctuator.length;
    tokens.push(token);
  }
  if (braces.length > 0) fail(braces.at(-1) === '${' ? 'unterminated template literal' : 'unbalanced {');
  if (parens.length > 0) fail('unbalanced (');
  return tokens;
}
