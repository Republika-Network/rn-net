# A real pseudo-terminal for the C6 typed approval (RN-NET-03B2-C6-H3, TTY approval review).
#
# Started only by tools/tty-pty/pty.check.mjs (offline-checks.sh, inside the network namespace),
# as `python3 -I -B driver.py <node> <probe> <scenario JSON>`. Python standard library only.
#
# It starts the probe (tools/tty-pty/probe.mjs, which runs only the approval: never the C6 command,
# never an authorization, never a network module) in a new session whose controlling terminal is a
# new pseudo-terminal, so /dev/tty in the probe is that terminal. The driver is the "keyboard": it
# writes bytes to the terminal's master side exactly as a terminal emulator does (Enter is "\r",
# Ctrl-U is "\x15"), and the kernel's line discipline does the rest.
#
# Scenario: {"mode": "cooked" | "raw" | "none", "ahead": str, "steps": [[op, value], ...], "timeout": s}
#   cooked  the normal interactive terminal (canonical, echo, ICRNL);
#   raw     a terminal left in raw mode (-icanon -echo -icrnl -isig), as full-screen programs set it;
#   none    no controlling terminal at all (new session, no terminal opened).
#   ahead   bytes typed after the probe has started but BEFORE it shows the prompt (type-ahead).
#   steps   after the prompt: ["send", str] types bytes, ["sleep", s] waits.
# Output (stdout, one JSON line): {"result": <the probe's record or null>, "blocked": bool, "transcript": str}
import json
import os
import pty
import select
import signal
import sys
import termios
import time

MARKER = b'RNNET-PTY-RESULT '
READY = b'RNNET-PTY-READY'
PROMPT_END = b'\n> '


def main():
    node, probe, scenario = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    mode = scenario['mode']
    timeout = float(scenario.get('timeout', 8))
    if mode == 'none':
        return no_terminal(node, probe, timeout)
    pid, master = pty.fork()
    if pid == 0:
        try:
            if mode == 'raw':
                attrs = termios.tcgetattr(0)
                attrs[0] &= ~(termios.ICRNL | termios.IXON)
                attrs[3] &= ~(termios.ICANON | termios.ECHO | termios.ISIG | termios.IEXTEN)
                attrs[6][termios.VMIN] = 1
                attrs[6][termios.VTIME] = 0
                termios.tcsetattr(0, termios.TCSANOW, attrs)
            os.execve(node, [node, probe], {})
        finally:
            os._exit(127)
    out = bytearray()
    deadline = time.monotonic() + timeout
    alive = True

    def pump(until=None, seconds=None):
        nonlocal alive
        stop = time.monotonic() + seconds if seconds is not None else deadline
        while alive and time.monotonic() < min(stop, deadline):
            if until is not None and until(out):
                return True
            ready, _, _ = select.select([master], [], [], 0.02)
            if ready:
                try:
                    data = os.read(master, 4096)
                except OSError:
                    data = b''
                if not data:
                    alive = False
                    break
                out.extend(data)
        return until(out) if until is not None else True

    def send(text):
        os.write(master, text.encode('latin-1'))

    if pump(until=lambda b: READY in b):
        if scenario.get('ahead'):
            send(scenario['ahead'])
        if pump(until=lambda b: PROMPT_END in b):
            for op, value in scenario.get('steps', []):
                if op == 'send':
                    send(value)
                elif op == 'sleep':
                    pump(seconds=float(value))
    pump(until=lambda b: MARKER in b and b.rstrip().endswith(b'}'))
    pump(seconds=0.2)
    blocked = MARKER not in out
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    report(out, blocked)


def no_terminal(node, probe, timeout):
    read_end, write_end = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()  # a new session has no controlling terminal: /dev/tty cannot be opened
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(write_end, 1)
            os.dup2(write_end, 2)
            os.execve(node, [node, probe], {})
        finally:
            os._exit(127)
    os.close(write_end)
    out = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([read_end], [], [], 0.05)
        if ready:
            data = os.read(read_end, 4096)
            if not data:
                break
            out.extend(data)
    blocked = MARKER not in out
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    report(out, blocked)


def report(out, blocked):
    result = None
    at = out.rfind(MARKER)
    if at >= 0:
        line = out[at + len(MARKER):].split(b'\n', 1)[0].strip()
        result = json.loads(line.decode('utf-8'))
    print(json.dumps({'result': result, 'blocked': blocked, 'transcript': out.decode('utf-8', 'replace')}))


if __name__ == '__main__':
    main()
