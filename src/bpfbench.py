# bpfbench  A better benchmarking tool written in eBPF.
# Copyright (C) 2020  William Findlay
#
# Heavily inspired by syscount from bcc-tools:
# https://github.com/iovisor/bcc/blob/master/tools/syscount.py
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os, sys
import atexit
import time
import datetime
import threading
import signal

from bcc import BPF, syscall

from src import defs
from src.utils import syscall_name, parse_args, drop_privileges, which

signal.signal(signal.SIGINT, lambda x, y: sys.exit())
signal.signal(signal.SIGTERM, lambda x, y: sys.exit())

class BPFBench:
    """
    Uses a BPF program to benchmark system state.
    """
    def __init__(self, args):
        self.args = args
        self.bpf = None
        self.start_time = None
        self.should_exit = 0
        self.trace_pid = 0
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
        flags.append(f'-DNUM_SYSCALLS={len(syscall.syscalls)}')
        if self.trace_pid > 0:
            flags.append(f'-DTRACE_PID={self.trace_pid}')

        # Load BPF program
        self.bpf = BPF(src_file=f'{defs.BPF_PATH}/bpf_program.c', cflags=flags)

        # Register exit hook
        atexit.register(self.save_results)

    def timer(self):
        """
        Timer for controlling duration and checkpoint.
        """
        seconds = 0
        self.start_time = datetime.datetime.now()
        while 1:
            seconds += 1
            if seconds % self.args.checkpoint.total_seconds() == 0:
                self.save_results()
            if seconds >= self.args.duration.total_seconds():
                self.should_exit = 1
            time.sleep(1)

    def get_results(self):
        """
        Get benchmark results.
        """
        results = {}
        for key, percpu_syscall in self.bpf['syscalls'].iteritems():
            count = 0
            overhead = 0.0
            for syscall in percpu_syscall:
                count += syscall.count
                overhead += syscall.overhead
            if not count:
                continue
            if self.args.average:
                overhead = overhead / (count if count else 1)
            results[syscall_name(key.value)] = {'sysnum': key.value, 'count': count, 'overhead': overhead / 1e3}
        return results

    @drop_privileges
    def save_results(self):
        """
        Save benchmark results.
        """
        results = self.get_results()
        with open(self.args.outfile, 'w') as f:
            results_str = ''
            # Add timestamp
            curr_time = datetime.datetime.now()
            # String += is O(n^2) in Python, don't try this at home, kids
            results_str += f'Experiment start: {self.start_time}\n'
            results_str += f'Current time:     {curr_time}\n'
            results_str += f'Seconds elapsed:  {(curr_time - self.start_time).total_seconds()}\n\n'
            # Add header
            results_str += f'{"SYSCALL":<22s} {"COUNT":>8s} {"AVG. OVERHEAD(us)" if self.args.average else "OVERHEAD(us)":>22s}\n'
            # Add results
            for k, v in sorted(results.items(), key=lambda v: v[1]['sysnum'] if self.args.sort == 'sys' else
                    v[1]['count'] if self.args.sort == 'count' else v[1]['overhead'] if self.args.sort == 'overhead' else v[1], reverse=1):
                results_str += f'{k:<22s} {v["count"]:>8d} {v["overhead"] :>22.3f}\n'
            f.write(results_str + '\n')

    def handle_sigchld(self, x, y):
        """
        Handle SIGCHLD.
        """
        os.wait()
        sys.exit(0)

    @drop_privileges
    def run_binary(self, binary, args):
        binary = which(binary)
        # Wake up and do nothing on SIGUSR1
        signal.signal(signal.SIGUSR1, lambda x,y: None)
        # Reap zombies
        signal.signal(signal.SIGCHLD, self.handle_sigchld)
        pid = os.fork()
        # Setup traced process
        if pid == 0:
            signal.pause()
            os.execvp(binary, args)
        # Return pid of traced process
        return pid

    def bench(self):
        """
        Run benchmarking.
        """
        # Maybe run a program
        if self.args.run:
            self.trace_pid = self.run_binary(self.args.run, self.args.runargs)

        # Load BPF program
        self.load_bpf()

        if self.args.run and self.trace_pid:
            os.kill(self.trace_pid, signal.SIGUSR1)

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
