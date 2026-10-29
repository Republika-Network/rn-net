// Strict parser for rnnet.canonical-json.v1 (spec §3). It accepts a subset of RFC 8259 JSON
// and rejects every input whose meaning could be read in more than one way.
import { CanonicalError, CanonicalErrorCode as E } from './errors.mjs';
import { LIMITS, MAX_INTEGER, MIN_INTEGER } from './limits.mjs';

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/**
 * Parses JSON text into plain values: null, booleans, safe integers, strings, arrays and
 * null-prototype objects.
 * @param {Uint8Array | string} input UTF-8 bytes (normative), or a string (a convenience: it is
 *   treated as the UTF-8 encoding of that string, so it cannot detect bytes that were already
 *   replaced by U+FFFD when the string was decoded)
 */
export function parse(input) {
  return new Parser(decodeInput(input)).parseDocument();
}

function decodeInput(input) {
  if (typeof input === 'string') {
    // Same order as for bytes (spec §3.1): size, byte order mark, then encodability. A string's
    // UTF-8 length is never smaller than its UTF-16 length, so the first test is a cheap bound.
    if (input.length > LIMITS.maxBytes || utf8Length(input) > LIMITS.maxBytes) throw sizeError();
    if (input.charCodeAt(0) === 0xfeff) throw new CanonicalError(E.BOM, 'Input starts with a byte order mark.', { offset: 0 });
    if (!input.isWellFormed()) throw new CanonicalError(E.LONE_SURROGATE, 'Input string contains an unpaired surrogate.');
    return input;
  }
  if (!(input instanceof Uint8Array)) {
    throw new CanonicalError(E.UNSUPPORTED_VALUE, 'Input must be a Uint8Array or a string.');
  }
  if (input.length > LIMITS.maxBytes) throw sizeError();
  if (input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) {
    throw new CanonicalError(E.BOM, 'Input starts with a byte order mark.', { offset: 0 });
  }
  try {
    return decoder.decode(input);
  } catch {
    throw new CanonicalError(E.INVALID_UTF8, 'Input is not well-formed UTF-8.');
  }
}

const sizeError = () => new CanonicalError(E.SIZE_EXCEEDED, `Input exceeds ${LIMITS.maxBytes} bytes.`);

const isDigit = (c) => c >= 0x30 && c <= 0x39;
const isHighSurrogate = (u) => u >= 0xd800 && u <= 0xdbff;
const isLowSurrogate = (u) => u >= 0xdc00 && u <= 0xdfff;

/** UTF-8 length of a string without allocating; an unpaired surrogate counts as 3 bytes. */
function utf8Length(string) {
  let bytes = 0;
  for (let i = 0; i < string.length; i++) {
    const c = string.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (isHighSurrogate(c) && isLowSurrogate(string.charCodeAt(i + 1))) {
      bytes += 4;
      i++;
    } else bytes += 3;
  }
  return bytes;
}

class Parser {
  constructor(text) {
    this.text = text;
    this.pos = 0;
  }

  fail(code, message, offset = this.pos) {
    throw new CanonicalError(code, message, { offset });
  }

  parseDocument() {
    this.skipWhitespace();
    if (this.pos >= this.text.length) this.fail(E.SYNTAX, 'Empty input.');
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.pos < this.text.length) this.fail(E.TRAILING_CONTENT, 'Unexpected content after the JSON value.');
    return value;
  }

  skipWhitespace() {
    const { text } = this;
    while (this.pos < text.length) {
      const c = text.charCodeAt(this.pos);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) break;
      this.pos++;
    }
  }

  parseValue(depth) {
    const c = this.text.charCodeAt(this.pos);
    switch (c) {
      case 0x7b: return this.parseObject(depth + 1); // {
      case 0x5b: return this.parseArray(depth + 1); // [
      case 0x22: return this.parseString(); // "
      case 0x74: return this.parseLiteral('true', true);
      case 0x66: return this.parseLiteral('false', false);
      case 0x6e: return this.parseLiteral('null', null);
      default:
        if (c === 0x2d || isDigit(c)) return this.parseNumber();
        return this.fail(E.SYNTAX, 'Expected a JSON value.');
    }
  }

  checkDepth(depth) {
    if (depth > LIMITS.maxDepth) this.fail(E.DEPTH_EXCEEDED, `Nesting exceeds depth ${LIMITS.maxDepth}.`);
  }

  parseObject(depth) {
    this.checkDepth(depth);
    this.pos++;
    const object = Object.create(null);
    this.skipWhitespace();
    if (this.text.charCodeAt(this.pos) === 0x7d) {
      this.pos++;
      return object;
    }
    for (;;) {
      this.skipWhitespace();
      const keyOffset = this.pos;
      if (this.text.charCodeAt(this.pos) !== 0x22) this.fail(E.SYNTAX, 'Expected a string key.');
      const key = this.parseString();
      // Duplicates are detected after unescaping, so "a" and "a" are the same key.
      if (Object.hasOwn(object, key)) this.fail(E.DUPLICATE_KEY, 'Duplicate object key.', keyOffset);
      this.skipWhitespace();
      if (this.text.charCodeAt(this.pos) !== 0x3a) this.fail(E.SYNTAX, 'Expected ":".');
      this.pos++;
      this.skipWhitespace();
      object[key] = this.parseValue(depth);
      this.skipWhitespace();
      const c = this.text.charCodeAt(this.pos);
      this.pos++;
      if (c === 0x7d) return object;
      if (c !== 0x2c) this.fail(E.SYNTAX, 'Expected "," or "}".', this.pos - 1);
    }
  }

  parseArray(depth) {
    this.checkDepth(depth);
    this.pos++;
    const array = [];
    this.skipWhitespace();
    if (this.text.charCodeAt(this.pos) === 0x5d) {
      this.pos++;
      return array;
    }
    for (;;) {
      this.skipWhitespace();
      array.push(this.parseValue(depth));
      this.skipWhitespace();
      const c = this.text.charCodeAt(this.pos);
      this.pos++;
      if (c === 0x5d) return array;
      if (c !== 0x2c) this.fail(E.SYNTAX, 'Expected "," or "]".', this.pos - 1);
    }
  }

  parseLiteral(word, value) {
    if (!this.text.startsWith(word, this.pos)) this.fail(E.SYNTAX, 'Invalid literal.');
    this.pos += word.length;
    return value;
  }

  parseString() {
    const { text } = this;
    this.pos++; // opening quote
    let out = '';
    let runStart = this.pos;
    for (;;) {
      if (this.pos >= text.length) this.fail(E.SYNTAX, 'Unterminated string.');
      const c = text.charCodeAt(this.pos);
      if (c === 0x22) {
        out += text.slice(runStart, this.pos);
        this.pos++;
        return out;
      }
      if (c < 0x20) this.fail(E.SYNTAX, 'Unescaped control character in string.');
      if (c !== 0x5c) {
        this.pos++;
        continue;
      }
      out += text.slice(runStart, this.pos);
      out += this.parseEscape();
      runStart = this.pos;
    }
  }

  parseEscape() {
    const escapeOffset = this.pos;
    const c = this.text[this.pos + 1];
    this.pos += 2;
    switch (c) {
      case '"': return '"';
      case '\\': return '\\';
      case '/': return '/';
      case 'b': return '\b';
      case 'f': return '\f';
      case 'n': return '\n';
      case 'r': return '\r';
      case 't': return '\t';
      case 'u': break;
      default: return this.fail(E.SYNTAX, 'Invalid escape sequence.', escapeOffset);
    }
    const unit = this.readHex4(escapeOffset);
    if (isLowSurrogate(unit)) this.fail(E.LONE_SURROGATE, 'Unpaired low surrogate escape.', escapeOffset);
    if (!isHighSurrogate(unit)) return String.fromCharCode(unit);
    // A high surrogate must be followed immediately by an escaped low surrogate.
    if (this.text[this.pos] !== '\\' || this.text[this.pos + 1] !== 'u') {
      this.fail(E.LONE_SURROGATE, 'Unpaired high surrogate escape.', escapeOffset);
    }
    this.pos += 2;
    const low = this.readHex4(escapeOffset);
    if (!isLowSurrogate(low)) this.fail(E.LONE_SURROGATE, 'Unpaired high surrogate escape.', escapeOffset);
    return String.fromCharCode(unit, low);
  }

  readHex4(escapeOffset) {
    const hex = this.text.slice(this.pos, this.pos + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(hex)) this.fail(E.SYNTAX, 'Invalid \\u escape.', escapeOffset);
    this.pos += 4;
    return Number.parseInt(hex, 16);
  }

  parseNumber() {
    const { text } = this;
    const start = this.pos;
    if (text.charCodeAt(this.pos) === 0x2d) this.pos++;
    const intStart = this.pos;
    if (text.charCodeAt(this.pos) === 0x30) {
      this.pos++;
      if (isDigit(text.charCodeAt(this.pos))) this.fail(E.SYNTAX, 'Leading zeros are not allowed.', start);
    } else if (isDigit(text.charCodeAt(this.pos))) {
      while (isDigit(text.charCodeAt(this.pos))) this.pos++;
    } else {
      this.fail(E.SYNTAX, 'Invalid number.', start);
    }
    const intEnd = this.pos;
    let integer = true;
    if (text.charCodeAt(this.pos) === 0x2e) {
      integer = false;
      this.pos++;
      if (!isDigit(text.charCodeAt(this.pos))) this.fail(E.SYNTAX, 'Invalid fraction.', start);
      while (isDigit(text.charCodeAt(this.pos))) this.pos++;
    }
    const e = text.charCodeAt(this.pos);
    if (e === 0x65 || e === 0x45) {
      integer = false;
      this.pos++;
      const sign = text.charCodeAt(this.pos);
      if (sign === 0x2b || sign === 0x2d) this.pos++;
      if (!isDigit(text.charCodeAt(this.pos))) this.fail(E.SYNTAX, 'Invalid exponent.', start);
      while (isDigit(text.charCodeAt(this.pos))) this.pos++;
    }
    // The full JSON number grammar is consumed first so that errors are classified by meaning.
    if (!integer) this.fail(E.NUMBER_NOT_INTEGER, 'Only integers are allowed (no fraction or exponent).', start);
    const lexeme = text.slice(start, intEnd);
    if (lexeme === '-0') this.fail(E.NEGATIVE_ZERO, 'Negative zero is not allowed.', start);
    if (intEnd - intStart > 16) this.fail(E.NUMBER_OUT_OF_RANGE, 'Integer outside the safe range.', start);
    const value = Number(lexeme);
    if (value > MAX_INTEGER || value < MIN_INTEGER) this.fail(E.NUMBER_OUT_OF_RANGE, 'Integer outside the safe range.', start);
    return value;
  }
}
