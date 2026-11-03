// The founder's typed approval of one C6 run (RN-NET-03B2-C6-LIVE-ENABLE, H3): the prompt is
// written to, and the answer read from, the controlling terminal (/dev/tty) only. Standard input is
// never read, so a pipe, a here-document, a file or another program cannot answer for the founder;
// without a terminal there is no approval. There is no flag, variable or file that approves.
// The answer is one line of at most 64 bytes; the entry point compares it with
// `c6 <last 16 hex digits of the authorization digest>` (entry.mjs, requireApproval).
import { Buffer } from 'node:buffer';
import { closeSync, constants, openSync, readSync, writeSync } from 'node:fs';
import { isatty } from 'node:tty';

export const TTY_PATH = '/dev/tty';
export const MAX_ANSWER_BYTES = 64;

/** The terminal calls the approval uses; tests replace them (there is no terminal in CI). */
export const TTY_IO = Object.freeze({ openSync, readSync, writeSync, closeSync, isatty });

/**
 * Returns approve(prompt) => Promise<string>: shows `prompt` on the terminal and returns the line
 * typed there. Throws if there is no terminal, or the line is longer than MAX_ANSWER_BYTES.
 */
export function createTtyApproval(io = TTY_IO) {
  return async (prompt) => {
    const fd = io.openSync(TTY_PATH, constants.O_RDWR | constants.O_NOCTTY);
    try {
      if (!io.isatty(fd)) throw new Error('not a terminal');
      const out = Buffer.from(`${prompt}\n> `, 'utf8');
      let written = 0;
      while (written < out.length) written += io.writeSync(fd, out, written, out.length - written);
      const answer = Buffer.alloc(MAX_ANSWER_BYTES + 1);
      let length = 0;
      for (;;) {
        const n = io.readSync(fd, answer, length, answer.length - length, null);
        if (n <= 0) throw new Error('no answer');
        length += n;
        const newline = answer.subarray(0, length).indexOf(0x0a);
        if (newline >= 0) return answer.subarray(0, newline).toString('utf8').replace(/\r$/, '');
        if (length > MAX_ANSWER_BYTES) throw new Error('answer too long');
      }
    } finally {
      io.closeSync(fd);
    }
  };
}
