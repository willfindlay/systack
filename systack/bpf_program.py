from time import sleep
import signal
import os
import sys
import subprocess

from bcc import BPF
from bcc.syscall import syscall_name

from systack import defs


def drop_privileges(function):
    """
    Decorator to drop root privileges.
    """

    def inner(*args, **kwargs):
        # Get sudoer's UID
        try:
            sudo_uid = int(os.environ['SUDO_UID'])
        except (KeyError, ValueError):
            print("Could not get UID for sudoer", file=sys.stderr)
            return
        # Get sudoer's GID
        try:
            sudo_gid = int(os.environ['SUDO_GID'])
        except (KeyError, ValueError):
            print("Could not get GID for sudoer", file=sys.stderr)
            return
        # Make sure groups are reset
        try:
            os.setgroups([])
        except PermissionError:
            pass
        # Drop root
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        # Execute function
        ret = function(*args, **kwargs)
        # Get root back
        os.setresgid(0, 0, -1)
        os.setresuid(0, 0, -1)
        return ret

    return inner


def which(binary):
    """
    Find a binary if it exists.
    """
    try:
        w = subprocess.Popen(
            ["which", binary], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        res = w.stdout.readlines()
        if len(res) == 0:
            raise Exception(f"{binary} not found")
        return os.path.realpath(res[0].strip())
    except Exception:
        if os.path.isfile(binary):
            return os.path.realpath(binary)
        else:
            raise Exception(f"{binary} not found")


@drop_privileges
def run_binary(args_str, discard_output=False):
    """
    Drop privileges and run a binary if it exists.
    """
    # Wake up and do nothing on SIGCLHD
    signal.signal(signal.SIGUSR1, lambda x, y: None)
    # Reap zombies
    signal.signal(signal.SIGCHLD, lambda x, y: os.wait())
    args = args_str.split()
    try:
        binary = which(args[0])
    except Exception:
        return -1
    pid = os.fork()
    # Setup traced process
    if pid == 0:
        if discard_output:
            with open('/dev/null', 'w') as f:
                os.dup2(f.fileno(), sys.stdout.fileno(), inheritable=True)
                os.dup2(f.fileno(), sys.stderr.fileno(), inheritable=True)
        signal.pause()
        os.execvp(binary, args)
    # Return pid of traced process
    return pid


class BPFProgram:
    """BPFProgram.
    """

    def __init__(self, pid: int = None, run: str = None):
        """__init__.

        Parameters
        ----------
        pid : int
            pid
        pid : str
            pid
        """
        self.bpf = None
        self.pid = pid
        self.run = run

        self.should_exit = 0

        self.load_bpf()

    def register_perf_buffers(self) -> None:
        assert self.bpf is not None

        def on_syscall(cpu, data, size):
            event = self.bpf['on_syscall'].event(data)
            addrs = self.bpf['user_stack'].walk(event.trace_id)
            addrs = list(addrs)
            name = syscall_name(event.syscall).decode('utf-8')
            # print(f'Syscall {name:<16} blamed on 0x{addrs[-1]:016x}')
            print(f'Syscall {name:<16}')
            for addr in addrs:
                print(
                    f'    0x{addr:016x} -> {self.bpf.sym(addr, self.pid, show_offset=True, demangle=False)}'
                )
            print()

        self.bpf['on_syscall'].open_perf_buffer(on_syscall)

    def load_bpf(self) -> None:
        """load_bpf.

        Parameters
        ----------

        Returns
        -------
        None

        """
        assert self.bpf is None

        flags = []
        if self.run:
            self.pid = run_binary(self.run, discard_output=True)

            def set_exit(x, y):
                self.should_exit = 1

            signal.signal(signal.SIGCHLD, set_exit)
        if self.pid:
            flags.append(f'-DPID={self.pid}')

        with open(defs.BPF_PATH, 'r') as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)

        self.register_perf_buffers()
        if self.run:
            os.kill(self.pid, signal.SIGUSR1)

    def event_loop(self) -> None:
        while 1:
            self.bpf.perf_buffer_poll(30)
            if self.should_exit:
                sys.exit()
            sleep(0.1)
