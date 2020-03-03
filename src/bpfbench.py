import os, sys
import atexit

from bcc import BPF

from src import defs
from src.utils import syscall_name, parse_args

class BPFBench:
    """
    Uses a BPF program to benchmark system state.
    """
    def __init__(self, args):
        self.args = args
        self.bpf = None

    def load_bpf(self):
        """
        Load BPF program.
        """
        assert self.bpf is None

        flags = []
        # Add BPF_PATH for header includes
        flags.append(f'-I{defs.BPF_PATH}')

        self.bpf = BPF(src_file=f'{defs.BPF_PATH}/bpf_program.c', cflags=flags)

    def bench(self):
        """
        Run benchmarking.
        """
        self.load_bpf()

def main():
    args = parse_args()
    bpf_bench = BPFBench(args)
    bpf_bench.bench()
