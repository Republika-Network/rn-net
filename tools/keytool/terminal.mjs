// The controlling terminal (ADR-RN-017 Amendment C1, K3): the only place a passphrase or an
// approval is read from. The only file in the repository that opens /dev/tty or changes terminal
// modes (the guard pins this).
//
// Refused (RNKEY_NOT_INTERACTIVE) unless standard input and output are terminals and /dev/tty
// opens as a terminal. Input is read in raw mode, so nothing is echoed unless asked for, and the
// line editing is this module's own: Enter ends the line, Backspace removes one character,
// Ctrl-C or Ctrl-D aborts (RNKEY_ABORTED), any other control character is refused.
import { Buffer } from 'node:buffer';
import { closeSync, openSync, writeSync } from 'node:fs';
import { isatty, ReadStream } from 'node:tty';
import { KeyToolCode, KeyToolError } from './errors.mjs';

const MAX_LINE_BYTES = 1024;

/**
 * The line editing of raw-mode input, without the terminal (tested directly). `push(bytes)`
 * returns null while the line goes on, { value: Buffer } at Enter, or { error } on Ctrl-C, Ctrl-D,
 * a control character or an over-long line. The editor overwrites its own buffer when done.
 */
export function lineEditor({ echo, write }) {
  const line = Buffer.alloc(MAX_LINE_BYTES);
  let length = 0;
  let finished = false;
  const end = (result) => {
    finished = true;
    line.fill(0);
    return result;
  };
  const push = (chunk) => {
    if (finished) return { error: new KeyToolError(KeyToolCode.INPUT_INVALID, 'the line is already finished') };
    for (const byte of chunk) {
      if (byte === 0x0d || byte === 0x0a) return end({ value: Buffer.from(line.subarray(0, length)) });
      if (byte === 0x03 || byte === 0x04) return end({ error: new KeyToolError(KeyToolCode.ABORTED, 'aborted at the terminal') });
      if (byte === 0x7f || byte === 0x08) {
        // One character back: UTF-8 continuation bytes, then the lead byte.
        while (length > 0 && (line[length - 1] & 0xc0) === 0x80) length -= 1;
        if (length > 0) length -= 1;
        if (echo) write(Buffer.from('\b \b'));
        continue;
      }
      if (byte < 0x20 || byte === 0x1b) return end({ error: new KeyToolError(KeyToolCode.INPUT_INVALID, 'a control character was typed') });
      if (length >= MAX_LINE_BYTES) return end({ error: new KeyToolError(KeyToolCode.INPUT_INVALID, 'the line is too long') });
      line[length] = byte;
      length += 1;
      if (echo) write(Buffer.of(byte));
    }
    return null;
  };
  return Object.freeze({ push });
}

/**
 * Opens the terminal. Returns { write(text), readLine({ echo }) -> Promise<Buffer>, close() }.
 * The caller owns the returned Buffer and should overwrite it when done.
 */
export function openTerminal({ stdin = process.stdin, stdout = process.stdout } = {}) {
  if (!stdin.isTTY || !stdout.isTTY) throw new KeyToolError(KeyToolCode.NOT_INTERACTIVE, 'standard input and output must be a terminal');
  let fd;
  try {
    fd = openSync('/dev/tty', 'r+');
  } catch {
    throw new KeyToolError(KeyToolCode.NOT_INTERACTIVE, 'no controlling terminal');
  }
  if (!isatty(fd)) {
    closeSync(fd);
    throw new KeyToolError(KeyToolCode.NOT_INTERACTIVE, '/dev/tty is not a terminal');
  }
  const input = new ReadStream(fd);
  input.pause();
  const restore = () => {
    try {
      input.setRawMode(false);
    } catch {
      // already closed
    }
  };
  process.once('exit', restore);
  const write = (text) => {
    writeSync(fd, Buffer.from(text, 'utf8'));
  };

  const readLine = ({ echo }) =>
    new Promise((resolve, reject) => {
      const editor = lineEditor({ echo, write: (bytes) => writeSync(fd, bytes) });
      const onData = (chunk) => {
        let result;
        try {
          result = editor.push(chunk);
        } finally {
          chunk.fill(0);
        }
        if (result === null) return;
        input.removeListener('data', onData);
        input.pause();
        restore();
        write('\n');
        if (result.error) reject(result.error);
        else resolve(result.value);
      };
      input.setRawMode(true);
      input.on('data', onData);
      input.resume();
    });

  const close = () => {
    restore();
    process.removeListener('exit', restore);
    input.destroy();
  };
  return Object.freeze({ write, readLine, close });
}
