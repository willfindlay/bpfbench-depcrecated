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
import functools

from bcc import BPF, syscall

from src import defs
from src.parse_args import parse_args
from src.utils import syscall_name, drop_privileges, which

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
        self.last_checkpoint = None
        self.checknum = 0
        # Maybe get duration
        try:
            self.duration   = functools.reduce(lambda a,b: a + b, self.args.duration)
        except TypeError:
            self.duration = None
        # Get checkpoint
        self.checkpoint = functools.reduce(lambda a,b: a + b, self.args.checkpoint)
        # Set should_exit to 0
        self.should_exit = 0
        # Set trace_pid to 0 for now
        self.trace_pid = 0
        # Should sort be reversed?
        if self.args.sort in ['count', 'overhead', 'avg_overhead']:
            self.reverse_sort = 1
        else:
            self.reverse_sort = 0
        # Timer thread stuff
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
        flags.append(f'-DBPFBENCH_PID={os.getpid()}')
        if self.trace_pid > 0:
            flags.append(f'-DTRACE_PID={self.trace_pid}')
            if self.args.follow:
                flags.append(f'-DFOLLOW')

        # Load BPF program
        self.bpf = BPF(src_file=f'{defs.BPF_PATH}/bpf_program.c', cflags=flags)

        # Register exit hook
        atexit.unregister(self.bpf.cleanup)
        atexit.register(self.on_exit)

    def on_exit(self):
        print(file=sys.stderr)
        self.save_results()
        print('All done!', file=sys.stderr)

    def timer(self):
        """
        Timer for controlling duration and checkpoint.
        """
        while 1:
            curr_time = datetime.datetime.now()
            if curr_time >= (self.last_checkpoint + self.checkpoint):
                self.last_checkpoint = curr_time
                self.save_results()
            if self.duration and curr_time >= self.duration + self.start_time:
                self.should_exit = 1
            time.sleep(1)

    def sort_func(self, v):
        """
        Return correct dict value based on sort argument.
        """
        if self.args.sort == 'sysname':
            return v[0]
        try:
            return v[1][self.args.sort]
        except:
            raise TypeError(f"Unable to sort based on {self.args.sort}")

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
            # Convert to us from ns
            overhead = overhead / 1e3
            results[syscall_name(key.value)] = {'sysnum': key.value, 'count': count, 'overhead': overhead}
            # Get average
            average_overhead = overhead / (count if count else 1)
            results[syscall_name(key.value)]['avg_overhead'] = average_overhead
        return results

    @drop_privileges
    def save_results(self):
        """
        Save benchmark results.
        """
        results = self.get_results()
        results_str = ''
        # Maybe open file for writing
        f = open(os.path.join(self.args.outdir, f'{defs.PREFIX}.{self.checknum}'), 'w') if self.args.outdir else sys.stderr
        self.checknum += 1
        # Add timestamp
        curr_time = datetime.datetime.now()
        # String += is O(n^2) in Python, don't try this at home, kids
        results_str += f'Start time:   {self.start_time}\n'
        results_str += f'Current time: {curr_time}\n'
        results_str += f'Time elapsed: {(curr_time - self.start_time)}\n\n'
        # Add header
        if self.args.sysnum:
            results_str += f'{"NUM":<3s} '
        results_str += f'{"SYSCALL":<22s} {"COUNT":>8s} {"OVERHEAD(us)":>22s} {"AVG_OVERHEAD(us/call)":>22s}'
        results_str += '\n'
        # Add results
        for k, v in sorted(results.items(), key=self.sort_func, reverse=self.reverse_sort):
            if self.args.sysnum:
                results_str += f'{v["sysnum"]:<3d} '
            results_str += f'{k:<22s} {v["count"]:>8d} {v["overhead"] :>22.3f}{v["avg_overhead"] :>22.3f}'
            results_str += '\n'
        f.write(results_str + '\n')
        # Maybe duplicate output
        if self.args.tee:
            sys.stderr.write(results_str + '\n')
        # Maybe close file
        if self.args.outdir:
            f.close()

    def handle_sigchld(self, x, y):
        """
        Handle SIGCHLD.
        """
        os.wait()
        self.should_exit = 1

    @drop_privileges
    def run_binary(self, binary, args):
        try:
            binary = which(binary)
        except:
            print(f'Unable to find {binary}... Exiting...')
            sys.exit(-1)
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
        self.start_time = datetime.datetime.now()
        self.last_checkpoint = datetime.datetime.now()

        print(f'Duration:   {self.duration if self.duration else "Forever"}', file=sys.stderr)
        print(f'Checkpoint: {self.checkpoint}', file=sys.stderr)
        print(f'Start time: {self.start_time}', file=sys.stderr)

        # Maybe run a program
        if self.args.run:
            print(f'Tracing \"{" ".join(self.args.runargs)}\" for {self.duration if self.duration else "Forever"}...', file=sys.stderr)
            self.trace_pid = self.run_binary(self.args.run, self.args.runargs)
        # Maybe trace a pid
        elif self.args.pid:
            print(f'Tracing pid {self.args.pid} for {self.duration if self.duration else "Forever"}...', file=sys.stderr)
            self.trace_pid = int(self.args.pid)
        else:
            print(f'Tracing system for {self.duration if self.duration else "Forever"}...', file=sys.stderr)

        # Load BPF program
        self.load_bpf()

        if self.args.run and self.trace_pid:
            os.kill(self.trace_pid, signal.SIGUSR1)

        # Start the timer
        self.timer_thread.start()
        while 1:
            time.sleep(1)
            if self.should_exit:
                sys.exit()

def main():
    """
    Parse arguments and run the benchmark.
    """
    args = parse_args()
    bpf_bench = BPFBench(args)
    bpf_bench.bench()
