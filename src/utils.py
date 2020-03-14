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
import argparse
import re
import datetime
import subprocess

from bcc import syscall

DESCRIPTION = """
System benchmarking with eBPF.
Right now, supports benchmarking system calls.
"""

EPILOG = """
"""

class ParserTimeDeltaType():
    """
    Arguments of type timedelta.
    Works like the arguments to timeout(1).
    """

    formats = {
            'seconds': re.compile(r'^(\d+)[sS]?$'),
            'minutes': re.compile(r'^(\d+)[mM]$'),
            'hours': re.compile(r'^(\d+)[hH]$'),
            'days': re.compile(r'^(\d+)[dD]$'),
            'weeks': re.compile(r'^(\d+)[wW]$'),
            }

    def construct_time(self, unit, value):
        value = int(value)
        if unit == 'seconds':
            return datetime.timedelta(seconds=value)
        if unit == 'minutes':
            return datetime.timedelta(minutes=value)
        if unit == 'hours':
            return datetime.timedelta(hours=value)
        if unit == 'days':
            return datetime.timedelta(days=value)
        if unit == 'weeks':
            return datetime.timedelta(weeks=value)
        raise argparse.ArgumentTypeError(f'Unable to construct {unit} with {value}.')

    def __call__(self, value):
        for k, v in self.formats.items():
            match = v.match(value)
            if match:
                return self.construct_time(k, match[1])
        raise argparse.ArgumentTypeError(f'Invalid specification for time "{value}".')

class ParserNewFileType():
    """
    Arguments of type new file.
    Intelligently prevents user from specifying an invalid path.
    """

    def __call__(self, path):
        d, f = os.path.split(path)
        # Make things absolute
        try:
            d = os.path.realpath(d)
        except:
            # Parent dir doesn't exist
            raise argparse.ArgumentTypeError(f'Parent directory {d} does not exist.')
        # Check if parent dir is a dir
        if d and not os.path.isdir(d):
            raise argparse.ArgumentTypeError(f'{d} is a file.')
        # Make sure f is not a dir
        if os.path.isdir(f):
            raise argparse.ArgumentTypeError(f'{f} is a directory.')
        # Join f with new d
        return os.path.join(d, f)

def parse_args(sysargs=sys.argv[1:]):
    """
    Argument parsing logic.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    timings = parser.add_argument_group('TIMING OPTIONS')
    timings.add_argument('-d', '--duration', type=ParserTimeDeltaType(), nargs='+',
            help="Duration to run benchmark. Durations can be combined. Defaults to forever. Supports values like: #[s] #m #h #d #w")
    timings.add_argument('-c', '--checkpoint', type=ParserTimeDeltaType(), default=[ParserTimeDeltaType()('30m')], nargs='+',
            help="Interval to checkpoint results. Durations can be combined. Defaults to 30m. Supports values like: #[s] #m #h #d #w")

    output = parser.add_argument_group('OUTPUT OPTIONS')
    output.add_argument('-o', '--outfile', type=ParserNewFileType(),
            help="Location to save benchmark data.")
    output.add_argument('--overwrite', action='store_true',
            help='Allow overwriting an existing outfile.')
    output.add_argument('--sort', type=str, choices=['sys', 'count', 'overhead'], default='overhead',
            help='Sort by system call number, count, or overhead. Defaults to overhead.')
    output.add_argument('--average', action='store_true',
            help='Average overhead per syscall count instead printing total overhead.')

    _micro = parser.add_argument_group('MICRO-BENCHMARK OPTIONS')
    micro = _micro.add_mutually_exclusive_group()
    micro.add_argument('-r', '--run', metavar='prog', type=str,
            help='Run program <prog> instead of benchmarking entire system. Provides microbenchmark functionality.')
    micro.add_argument('-p', '--pid', metavar='pid', type=int,
            help='Attach to program with userspace pid <pid> instead of benchmarking entire system. Provides microbenchmark functionality.')
    _micro.add_argument('-f', '--follow', action='store_true',
            help='Follow child processes. Only makes sense when used with -p or -r.')

    # Hack to allow arguments to be passed to the analyzed program
    try:
        index_of_run = sysargs.index('--run')
    except ValueError:
        try:
            index_of_run = sysargs.index('-r')
            args = parser.parse_args(sysargs[:index_of_run + 2])
            vars(args)['runargs'] = sysargs[index_of_run + 1:]
        except ValueError:
            args = parser.parse_args(sysargs)
            vars(args)['runargs'] = []

    # Check for whether follow makes sense
    if args.follow and not (args.run or args.pid):
        parser.error(f"Setting follow mode only makes sense when running with --pid or --run.")

    # Check for overwrite
    if not args.overwrite and args.outfile and os.path.exists(args.outfile):
        parser.error(f"Cannot overwrite {args.outfile} without --overwrite.")

    # Check for root
    if os.geteuid() != 0:
        parser.error("This script must be run with root privileges.")

    # Check for sudo_uid
    if not os.getenv('SUDO_UID'):
        print('Warning: You should probably run this script with sudo, not via a root shell.', file=sys.stderr)

    return args

def syscall_name(num):
    """
    Return uppercase system call name.
    """
    return syscall.syscall_name(num).decode('utf-8')

def drop_privileges(function):
    """
    Decorator to drop root
    """
    def inner(*args, **kwargs):
        # Get proper UID
        try:
            sudo_uid = int(os.environ['SUDO_UID'])
        except (KeyError, ValueError):
            print("Could not get UID for sudoer", file=sys.stderr)
            return
        # Get proper GID
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
    Locate a binary on the system, use relative paths as a fallback.
    """
    try:
        w = subprocess.Popen(["which", binary],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        res = w.stdout.readlines()
        if len(res) == 0:
            raise FileNotFoundError(f"{binary} not found")
        return os.path.realpath(res[0].strip())
    except FileNotFoundError:
        if os.path.isfile(binary):
            return os.path.realpath(binary)
        else:
            raise FileNotFoundError(f"{binary} not found")
