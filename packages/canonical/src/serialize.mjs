// Canonical serializer for rnnet.canonical-json.v1 (spec §4). The same rules apply whether the
// value came from parse() or was built in code, so both paths fail on the same inputs.
import { CanonicalError, CanonicalErrorCode as E } from './errors.mjs';
import { LIMITS } from './limits.mjs';

const encoder = new TextEncoder();

/** Canonical JSON text for a value. */
export function canonicalize(value) {
  return serialize(value, 0, '$');
}

/** Canonical JSON as UTF-8 bytes. */
export function canonicalBytes(value) {
  return encoder.encode(canonicalize(value));
}

const fail = (code, message, path) => {
  throw new CanonicalError(code, message, { path });
};

function serialize(value, depth, path) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      if (!value.isWellFormed()) fail(E.LONE_SURROGATE, 'String contains an unpaired surrogate.', path);
      return quote(value);
    case 'number':
      return serializeNumber(value, path);
    case 'object':
      break;
    default:
      return fail(E.UNSUPPORTED_VALUE, `Unsupported value of type ${typeof value}.`, path);
  }
  if (depth + 1 > LIMITS.maxDepth) fail(E.DEPTH_EXCEEDED, `Nesting exceeds depth ${LIMITS.maxDepth}.`, path);
  if (Array.isArray(value)) return serializeArray(value, depth + 1, path);
  return serializeObject(value, depth + 1, path);
}

function serializeNumber(value, path) {
  if (!Number.isFinite(value)) fail(E.UNSUPPORTED_VALUE, 'Non-finite numbers are not allowed.', path);
  if (!Number.isInteger(value)) fail(E.NUMBER_NOT_INTEGER, 'Only integers are allowed.', path);
  if (Object.is(value, -0)) fail(E.NEGATIVE_ZERO, 'Negative zero is not allowed.', path);
  if (!Number.isSafeInteger(value)) fail(E.NUMBER_OUT_OF_RANGE, 'Integer outside the safe range.', path);
  return String(value);
}

function serializeArray(array, depth, path) {
  if (Object.getPrototypeOf(array) !== Array.prototype) fail(E.UNSUPPORTED_VALUE, 'Unsupported array type.', path);
  const parts = [];
  for (let i = 0; i < array.length; i++) {
    if (!Object.hasOwn(array, i)) fail(E.UNSUPPORTED_VALUE, 'Sparse arrays are not allowed.', `${path}[${i}]`);
    parts.push(serialize(array[i], depth, `${path}[${i}]`));
  }
  return `[${parts.join(',')}]`;
}

function serializeObject(object, depth, path) {
  const proto = Object.getPrototypeOf(object);
  if (proto !== Object.prototype && proto !== null) fail(E.UNSUPPORTED_VALUE, 'Only plain objects are allowed.', path);
  if (Object.getOwnPropertySymbols(object).length > 0) fail(E.UNSUPPORTED_VALUE, 'Symbol keys are not allowed.', path);
  const descriptors = Object.getOwnPropertyDescriptors(object);
  // UTF-16 code unit order: the default string comparison of ECMAScript.
  const keys = Object.keys(descriptors).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const parts = [];
  for (const key of keys) {
    const descriptor = descriptors[key];
    const childPath = `${path}[${JSON.stringify(key)}]`;
    if (!('value' in descriptor)) fail(E.UNSUPPORTED_VALUE, 'Accessor properties are not allowed.', childPath);
    if (!descriptor.enumerable) fail(E.UNSUPPORTED_VALUE, 'Non-enumerable properties are not allowed.', childPath);
    if (!key.isWellFormed()) fail(E.LONE_SURROGATE, 'Key contains an unpaired surrogate.', childPath);
    parts.push(`${quote(key)}:${serialize(descriptor.value, depth, childPath)}`);
  }
  return `{${parts.join(',')}}`;
}

const SHORT_ESCAPES = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\' };

/** Spec §4.3: escape only '"', '\', and U+0000..U+001F; everything else is emitted as is. */
function quote(string) {
  let out = '"';
  let runStart = 0;
  for (let i = 0; i < string.length; i++) {
    const c = string.charCodeAt(i);
    if (c >= 0x20 && c !== 0x22 && c !== 0x5c) continue;
    out += string.slice(runStart, i) + (SHORT_ESCAPES[c] ?? `\\u00${c.toString(16).padStart(2, '0')}`);
    runStart = i + 1;
  }
  return `${out}${string.slice(runStart)}"`;
}
