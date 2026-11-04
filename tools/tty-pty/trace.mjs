// A byte trace of the C6 typed approval on the founder's own terminal (RN-NET-03B2-C6-H3, TTY
// approval review). A DIAGNOSTIC, run by hand only:
//   stty -a </dev/tty; node tools/tty-pty/trace.mjs
// It runs the unchanged production createTtyApproval() with its terminal calls wrapped so that
// every open, read and close of /dev/tty is printed (flags, byte counts, the bytes in hex, errors,
// milliseconds since start). It asks for the word PRUEBA, never for a C6 answer: it uses no digest,
// starts no C6 command, reads no authorization, endpoints file or evidence directory, and imports no
// network module. Its output contains only what was typed at its own prompt.
import { constants } from 'node:fs';
import { createTtyApproval, TTY_IO } from '../compat-live/tty-approval.mjs';

const t0 = process.hrtime.bigint();
const ms = () => (Number(process.hrtime.bigint() - t0) / 1e6).toFixed(1).padStart(8);
const log = [];
const note = (text) => log.push(`${ms()} ms  ${text}`);
const hex = (buffer, offset, n) => Buffer.from(buffer.subarray(offset, offset + n)).toString('hex').replace(/(..)/g, '$1 ').trim();
const flagNames = (flags) => ['O_RDWR', 'O_WRONLY', 'O_NOCTTY', 'O_NONBLOCK'].filter((name) => constants[name] !== 0 && (flags & constants[name]) === constants[name]).join('|') || 'O_RDONLY';

const io = Object.freeze({
  openSync(path, flags) {
    try {
      const fd = TTY_IO.openSync(path, flags);
      note(`open ${path} ${flagNames(flags)} -> fd ${fd}`);
      return fd;
    } catch (error) {
      note(`open ${path} ${flagNames(flags)} -> ${error.code ?? error.message}`);
      throw error;
    }
  },
  readSync(fd, buffer, offset, length, position) {
    try {
      const n = TTY_IO.readSync(fd, buffer, offset, length, position);
      note(`read fd ${fd} (up to ${length}) -> ${n} byte(s)${n > 0 ? `: ${hex(buffer, offset, n)}` : ''}`);
      return n;
    } catch (error) {
      note(`read fd ${fd} (up to ${length}) -> ${error.code ?? error.message}`);
      throw error;
    }
  },
  writeSync(fd, buffer, offset, length) {
    const n = TTY_IO.writeSync(fd, buffer, offset, length);
    note(`write fd ${fd} -> ${n} byte(s)`);
    return n;
  },
  closeSync(fd) {
    note(`close fd ${fd}`);
    return TTY_IO.closeSync(fd);
  },
  isatty(fd) {
    const yes = TTY_IO.isatty(fd);
    note(`isatty fd ${fd} -> ${yes}`);
    return yes;
  },
});

let outcome;
try {
  const answer = await createTtyApproval(io)('RN-NET TTY TRACE (diagnostic; not a C6 approval). Type the word PRUEBA and press Enter.');
  outcome = `answer ${JSON.stringify(answer)} (${Buffer.byteLength(answer)} bytes; ${answer === 'PRUEBA' ? 'matches PRUEBA' : 'does NOT match PRUEBA'})`;
} catch (error) {
  outcome = `error: ${error.message}`;
}
process.stderr.write(`--- RN-NET TTY TRACE (node ${process.version}, stdin isatty ${process.stdin.isTTY === true}, TERM ${process.env.TERM ?? '(unset)'}) ---\n${log.join('\n')}\n${ms()} ms  ${outcome}\n--- end ---\n`);
