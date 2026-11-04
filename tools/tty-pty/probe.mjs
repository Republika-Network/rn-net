// The approval alone, on a real terminal (RN-NET-03B2-C6-H3, TTY approval review). Started only by
// tools/tty-pty/driver.py inside a pseudo-terminal it controls. It runs the production
// createTtyApproval() and requireApproval() with a SYNTHETIC digest that is not, and cannot become,
// an authorization: it never starts the C6 command (compat-live.mjs), never reads an authorization,
// an endpoints file or an evidence directory, and imports no network module. It prints one record:
//   RNNET-PTY-RESULT {"answer": string | null, "approved": bool, "code": string | null, "error": string | null}
import { requireApproval } from '../compat-live/entry.mjs';
import { createTtyApproval } from '../compat-live/tty-approval.mjs';

export const SYNTHETIC_DIGEST = `sha256:${'0'.repeat(48)}0123456789abcdef`;

const say = (text) => process.stdout.write(text);
say('RNNET-PTY-READY\n');
// The driver types any type-ahead now, while the probe has started but not yet shown the prompt.
await new Promise((resolve) => setTimeout(resolve, 400));
const tty = createTtyApproval();
let answer = null;
let error = null;
const approve = async (prompt) => {
  try {
    answer = await tty(prompt);
    return answer;
  } catch (failure) {
    error = failure.message;
    throw failure;
  }
};
const record = { answer: null, approved: false, code: null, error: null };
try {
  await requireApproval(approve, { digest: SYNTHETIC_DIGEST, lines: ['RN-NET TTY PTY CHECK (synthetic digest; not an authorization)'] });
  record.approved = true;
} catch (refusal) {
  record.code = refusal.code ?? null;
}
record.answer = answer;
record.error = error;
say(`\nRNNET-PTY-RESULT ${JSON.stringify(record)}\n`);
