import os, sys
import argparse
import re
import datetime

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
    Intelligently prevents user from specifying and invalid path.
    """

    def __call__(self, path):
        d, f = os.path.split(path)
        try:
            d = os.path.realpath(d)
        except:
            pass
        if d and not os.path.exists(d):
            raise argparse.ArgumentTypeError(f'Parent directory {d} does not exist.')
        if d and not os.path.isdir(d):
            raise argparse.ArgumentTypeError(f'{d} is a file.')
        if os.path.isdir(f):
            raise argparse.ArgumentTypeError(f'{f} is a directory.')
        return os.path.join(d, f)
        #raise argparse.ArgumentTypeError(f'Invalid specification for time "{path}".')

def parse_args(args=sys.argv[1:]):
    """
    Argument parsing logic.
    """
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('duration', type=ParserTimeDeltaType(),
            help="Duration to run benchmark. Supports values like: #[s] #m #h #d #w")
    parser.add_argument('-c', '--checkpoint', type=ParserTimeDeltaType(), default='30m',
            help="Interval to checkpoint results. Defaults to 30m. Supports values like: #[s] #m #h #d #w")
    parser.add_argument('outfile', type=ParserNewFileType(),
            help="Location to save benchmark data.")

    args = parser.parse_args()

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
    return syscall.syscall_name(num).upper()
