// Strict JSON for untrusted RPC responses (spec/rnnet.live-observation-report.v1.md §4).
//
// RPC responses are not canonical JSON (server_info, for example, carries fractions), so the
// canonical parser cannot be used. This parser accepts RFC 8259 JSON with these limits:
// at most `maxBytes` of UTF-8, nesting depth 64, duplicate keys refused, objects with a null
// prototype. Integers in the safe range become numbers; any other number is kept as a RawNumber
// with its exact text, which canonical serialization refuses, so it can never reach an
// observation silently.
export class RawNumber {
  constructor(text) {
    this.text = text;
    Object.freeze(this);
  }
}

export class JsonError extends Error {
  constructor(reason, offset) {
    super(`${reason} at offset ${offset}`);
    this.name = 'JsonError';
    this.code = 'RNLO_INVALID_JSON';
    this.reason = reason;
  }
}

const MAX_DEPTH = 64;
const NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const INTEGER = /^-?(?:0|[1-9]\d*)$/;

/** Parses UTF-8 JSON bytes; throws JsonError. */
export function parseRpcJson(bytes, maxBytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes must be a Uint8Array.');
  if (bytes.length > maxBytes) throw new JsonError('response too large', maxBytes);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new JsonError('invalid UTF-8', 0);
  }
  let i = 0;
  const fail = (reason) => {
    throw new JsonError(reason, i);
  };
  const space = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i++;
  };
  const string = () => {
    const start = i;
    i++;
    for (;;) {
      const c = text[i];
      if (c === undefined) fail('unterminated string');
      if (c === '"') break;
      if (c === '\\') i += 2;
      else {
        if (c < ' ') fail('control character in string');
        i++;
      }
    }
    i++;
    try {
      return JSON.parse(text.slice(start, i));
    } catch {
      return fail('invalid string escape');
    }
  };
  const value = (depth) => {
    if (depth > MAX_DEPTH) fail('nesting too deep');
    space();
    const c = text[i];
    if (c === '{') {
      i++;
      const object = Object.create(null);
      space();
      if (text[i] === '}') {
        i++;
        return object;
      }
      for (;;) {
        space();
        if (text[i] !== '"') fail('expected a key');
        const key = string();
        if (Object.hasOwn(object, key)) fail('duplicate key');
        space();
        if (text[i++] !== ':') fail('expected ":"');
        object[key] = value(depth + 1);
        space();
        if (text[i] === ',') i++;
        else if (text[i] === '}') {
          i++;
          return object;
        } else fail('expected "," or "}"');
      }
    }
    if (c === '[') {
      i++;
      const array = [];
      space();
      if (text[i] === ']') {
        i++;
        return array;
      }
      for (;;) {
        array.push(value(depth + 1));
        space();
        if (text[i] === ',') i++;
        else if (text[i] === ']') {
          i++;
          return array;
        } else fail('expected "," or "]"');
      }
    }
    if (c === '"') return string();
    for (const [literal, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, i)) {
        i += literal.length;
        return result;
      }
    }
    NUMBER.lastIndex = i;
    const match = NUMBER.exec(text);
    if (!match) fail('unexpected character');
    i = NUMBER.lastIndex;
    const raw = match[0];
    if (INTEGER.test(raw) && Number.isSafeInteger(Number(raw)) && raw !== '-0') return Number(raw);
    return new RawNumber(raw);
  };
  if (text.charCodeAt(0) === 0xfeff) fail('byte order mark');
  const result = value(1);
  space();
  if (i !== text.length) fail('trailing content');
  return result;
}
