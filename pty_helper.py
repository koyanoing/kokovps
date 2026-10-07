#!/usr/bin/env python3
"""Run a command inside a real PTY. stdin/stdout carry terminal data;
fd 3 carries resize requests as lines of "cols rows"."""
import os, pty, sys, select, fcntl, termios, struct, signal, time

def set_size(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))

def write_all(fd, data):
    while data:
        n = os.write(fd, data)
        data = data[n:]

if len(sys.argv) < 2:
    sys.exit(2)

pid, master = pty.fork()
if pid == 0:
    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    except Exception as e:
        sys.stderr.write('cannot start %s: %s\n' % (sys.argv[1], e))
        os._exit(127)

set_size(master, 24, 80)
ctl_open = True
buf = b''
try:
    while True:
        fds = [master, 0] + ([3] if ctl_open else [])
        ready, _, _ = select.select(fds, [], [])
        if master in ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            write_all(1, data)
        if 0 in ready:
            data = os.read(0, 65536)
            if not data:
                break
            write_all(master, data)
        if ctl_open and 3 in ready:
            data = os.read(3, 1024)
            if not data:
                ctl_open = False
            else:
                buf += data
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    try:
                        cols, rows = line.split()
                        set_size(master, int(rows), int(cols))
                    except Exception:
                        pass
finally:
    try:
        os.kill(pid, signal.SIGHUP)
    except Exception:
        pass
    for _ in range(20):
        try:
            done, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if done:
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except Exception:
            pass
