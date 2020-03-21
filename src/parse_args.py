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
import datetime
import re

from src.utils import drop_privileges

DESCRIPTION = """
bpfbench
    System benchmarking with eBPF.
    Right now, supports benchmarking system calls.
"""

EPILOG = """
    Copyright (C) 2020  William Findlay
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
    @drop_privileges
    def check_access(self, path):
        """
        Check whether we would have access to the file.
        NOTE: This is for error prevention, NOT for security.
        We will ALWAYS drop privileges before writing to a file.
        """
        if os.path.exists(path):
            return os.access(path, os.W_OK)
        d, f = os.path.split(path)
        try:
            d = os.path.realpath(d)
        except:
            # Parent dir doesn't exist
            return False
        return os.access(d, os.W_OK)

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
        if not self.check_access(path):
            raise argparse.ArgumentTypeError(f'No permissions to write to location {d}/{f}.')
        # Join f with new d
        return os.path.join(d, f)

def parse_args(sysargs=sys.argv[1:]):
    """
    Argument parsing logic.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawTextHelpFormatter)

    timings = parser.add_argument_group('timing options')
    timings.add_argument('-d', '--duration', type=ParserTimeDeltaType(), nargs='+',
            help='Duration to run benchmark. Defaults to forever.\n'
            'Supports values like: #[s] #m #h #d #w.\n'
            'Durations can be combined like: 1m 30s.')
    timings.add_argument('-c', '--checkpoint', type=ParserTimeDeltaType(), default=[ParserTimeDeltaType()('30m')], nargs='+',
            help='Interval to checkpoint results. Defaults to 30m.\n'
            'Supports values like: #[s] #m #h #d #w.\n'
            'Durations can be combined like: 1m 30s.')

    output = parser.add_argument_group('output options')
    output.add_argument('-o', '--outfile', type=ParserNewFileType(),
            help="Location to save benchmark data. Overwriting existing files is disabled by default.")
    output.add_argument('--overwrite', action='store_true',
            help='Allow overwriting an existing outfile.')
    output.add_argument('--tee', action='store_true',
            help='Print to stderr in addition to outfile.')
    output.add_argument('--sort', type=str, choices=['sys', 'count', 'overhead'], default='overhead',
            help='Sort by system call number, count, or overhead. Defaults to overhead.')
    output.add_argument('--noaverage', '--noavg', dest='average', action='store_false',
            help='Do not print average overhead.')

    _micro = parser.add_argument_group('micro-benchmark options')
    micro = _micro.add_mutually_exclusive_group()
    micro.add_argument('-r', '--run', metavar='prog', type=str,
            help='Run program <prog> instead of benchmarking entire system.')
    micro.add_argument('-p', '--pid', metavar='pid', type=int,
            help='Attach to program with userspace pid <pid> instead of benchmarking entire system.')
    _micro.add_argument('-f', '--follow', action='store_true',
            help='Follow child processes. Only makes sense when used with -p or -r.')

    parser.add_argument('--debug', action='store_true',
            help=argparse.SUPPRESS)

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

    # Check whether overwrite makes sense
    if args.overwrite and not args.outfile:
        parser.error(f"--overwrite does not make sense without --outfile.")

    # Check whether tee makes sense
    if args.tee and not args.outfile:
        parser.error(f"--tee does not make sense without --outfile.")

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
