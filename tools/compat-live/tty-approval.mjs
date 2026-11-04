// The founder's typed approval of one C6 run (RN-NET-03B2-C6-LIVE-ENABLE, H3): the prompt is
// written to, and the answer read from, the controlling terminal (/dev/tty) only. Standard input is
// never read, so a pipe, a here-document, a file or another program cannot answer for the founder;
// without a terminal there is no approval. There is no flag, variable or file that approves.
// Anything typed before the prompt is discarded first, and the input pending on the terminal when the
// answer line has been read (the rest of an over-long line, further pasted lines, a partial line
// without Enter) is discarded before returning, so the shell does not receive it. The answer is one line of at most 64 bytes; the entry point compares it with
// `c6 <last 16 hex digits of the authorization digest>` (entry.mjs, requireApproval).
import { Buffer } from 'node:buffer';
import { closeSync, constants, openSync, readSync, writeSync } from 'node:fs';
import { isatty, ReadStream } from 'node:tty';

export const TTY_PATH = '/dev/tty';
export const MAX_ANSWER_BYTES = 64;

/**
 * Makes a partial line (typed without Enter) readable (review R2). In canonical mode such bytes sit
 * in the kernel's line buffer, invisible to any read, and would reach the shell after this program
 * exits (with the next Enter, or at once when its line editor turns canonical mode off). Turning
 * canonical mode off and back on makes the kernel end them as a line (Linux n_tty: on the switch
 * to canonical with input pending, the pending bytes become a line), so the non-blocking discard
 * can then read them. The terminal's own settings are restored exactly (libuv saves them first).
 * Throws if the terminal cannot be switched: the approval is then refused.
 */
function releasePartialLine() {
  const fd = openSync(TTY_PATH, constants.O_RDWR | constants.O_NOCTTY);
  let stream;
  try {
    stream = new ReadStream(fd);
  } catch (error) {
    closeSync(fd);
    throw error;
  }
  try {
    stream.setRawMode(true);
  } finally {
    try {
      stream.setRawMode(false);
    } finally {
      stream.destroy();
    }
  }
}

/** The terminal calls the approval uses; tests replace them (there is no terminal in CI). */
export const TTY_IO = Object.freeze({ openSync, readSync, writeSync, closeSync, isatty, releasePartialLine });

/**
 * Returns approve(prompt) => Promise<string>: shows `prompt` on the terminal and returns the line
 * typed there. Throws if there is no terminal, or the line is longer than MAX_ANSWER_BYTES (in which
 * case the whole line is discarded, never returned and never left for the shell).
 */
export function createTtyApproval(io = TTY_IO) {
  return async (prompt) => {
    discardTypeAhead(io);
    const fd = io.openSync(TTY_PATH, constants.O_RDWR | constants.O_NOCTTY);
    try {
      if (!io.isatty(fd)) throw new Error('not a terminal');
      const out = Buffer.from(`${prompt}\n(press Ctrl-U first to clear anything typed before this prompt)\n> `, 'utf8');
      let written = 0;
      while (written < out.length) written += io.writeSync(fd, out, written, out.length - written);
      const answer = Buffer.alloc(MAX_ANSWER_BYTES + 1);
      let length = 0;
      try {
        for (;;) {
          const n = io.readSync(fd, answer, length, answer.length - length, null);
          if (n <= 0) throw new Error('no answer');
          length += n;
          const newline = answer.subarray(0, length).indexOf(0x0a);
          if (newline >= 0) return answer.subarray(0, newline).toString('utf8').replace(/\r$/, '');
          if (length > MAX_ANSWER_BYTES) throw new Error('answer too long');
        }
      } finally {
        // Whatever the outcome, what was typed for this prompt is not left on the terminal: the
        // rest of a line longer than MAX_ANSWER_BYTES (and its Enter), further pasted lines, and a
        // partial line without Enter (review R2) would otherwise be read by the shell as a command
        // once this program exits (C6-H3, TTY review). Input typed after this point is not covered.
        try {
          io.releasePartialLine();
        } finally {
          discardTypeAhead(io); // also when the release fails, which then refuses the approval
        }
      }
    } finally {
      io.closeSync(fd);
    }
  };
}

/** At most this much input typed before the prompt is discarded. */
export const MAX_TYPE_AHEAD_BYTES = 65_536;

/**
 * Discards the complete lines pending on the terminal, before the prompt (C6-LIVE-ENABLE review)
 * and again after the answer line has been read (C6-H3 TTY review): the
 * terminal is read without blocking until it has nothing more. Refuses (throws) if it does not run
 * dry. A line typed but not yet ended with Enter stays in the terminal's own line buffer (canonical
 * mode) and is not discarded; the prompt therefore asks for Ctrl-U first, which clears it. Typing
 * the right answer ahead needs the digest the prompt shows (round-2 review F1, accepted residual).
 */
function discardTypeAhead(io) {
  const fd = io.openSync(TTY_PATH, constants.O_RDONLY | constants.O_NOCTTY | constants.O_NONBLOCK);
  try {
    if (!io.isatty(fd)) throw new Error('not a terminal');
    const scratch = Buffer.alloc(4096);
    let discarded = 0;
    for (;;) {
      let n;
      try {
        n = io.readSync(fd, scratch, 0, scratch.length, null);
      } catch (error) {
        if (error?.code === 'EAGAIN' || error?.code === 'EWOULDBLOCK') return;
        throw error;
      }
      if (n <= 0) return;
      discarded += n;
      if (discarded > MAX_TYPE_AHEAD_BYTES) throw new Error('the terminal does not stop sending input');
    }
  } finally {
    io.closeSync(fd);
  }
}
