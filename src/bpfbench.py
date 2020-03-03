import os, sys
import atexit
import time
import datetime
import threading
import signal

from bcc import BPF

from src import defs
from src.utils import syscall_name, parse_args

signal.signal(signal.SIGINT, lambda x, y: sys.exit())
signal.signal(signal.SIGTERM, lambda x, y: sys.exit())

class BPFBench:
    """
    Uses a BPF program to benchmark system state.
    """
    def __init__(self, args):
        self.args = args
        self.bpf = None
        self.should_exit = 0
        self.timer_thread = threading.Thread(target=self.timer)
        self.timer_thread.setDaemon(1)

    def load_bpf(self):
        """
        Load BPF program.
        """
        assert self.bpf is None

        flags = []
        # Add BPF_PATH for header includes
        flags.append(f'-I{defs.BPF_PATH}')

        # Load BPF program
        self.bpf = BPF(src_file=f'{defs.BPF_PATH}/bpf_program.c', cflags=flags)

        # Register exit hook
        atexit.register(self.save_results)

    def timer(self):
        """
        Timer for controlling duration and checkpoint.
        """
        seconds = 0
        while 1:
            seconds += 1
            if seconds % self.args.checkpoint.total_seconds() == 0:
                self.save_results()
            if seconds >= self.args.duration.total_seconds():
                self.should_exit = 1
            time.sleep(1)

    def save_results(self):
        """
        Save benchmark results.
        """
        # Drop privileges
        try:
            os.setegid(int(os.getenv('SUDO_GID')))
            os.seteuid(int(os.getenv('SUDO_UID')))
        except TypeError:
            print("Error: Unable to drop privileges before saving!", file=sys.stderr)
        with open(self.args.outfile, 'w') as f:
            f.write('test')
        # Get privileges back
        os.seteuid(0)
        os.setegid(0)

    def bench(self):
        """
        Run benchmarking.
        """
        # Load BPF program
        self.load_bpf()

        # Start the timer
        self.timer_thread.start()
        while 1:
            if self.should_exit:
                sys.exit()
            time.sleep(1)

def main():
    """
    Parse arguments and run the benchmark.
    """
    args = parse_args()
    bpf_bench = BPFBench(args)
    bpf_bench.bench()
