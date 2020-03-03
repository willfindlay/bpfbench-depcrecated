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

class ParserTimeType():
    """
    Arguments of type time w.r.t. now.
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
        now = datetime.datetime.now()
        if unit == 'seconds':
            return now + datetime.timedelta(seconds=value)
        if unit == 'minutes':
            return now + datetime.timedelta(minutes=value)
        if unit == 'hours':
            return now + datetime.timedelta(hours=value)
        if unit == 'days':
            return now + datetime.timedelta(days=value)
        if unit == 'weeks':
            return now + datetime.timedelta(weeks=value)
        raise argparse.ArgumentTypeError(f'Unable to construct {unit} with {value}.')

    def __call__(self, value):
        for k, v in self.formats.items():
            match = v.match(value)
            if match:
                return self.construct_time(k, match[1])
        raise argparse.ArgumentTypeError(f'Invalid specification for time "{value}".')

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('duration', type=ParserTimeType(),
            help="Duration to run benchmark. Supports values like: #s #m #h #d #w")
    parser.add_argument('-c', '--checkpoint', type=ParserTimeType(), default='30m',
            help="Interval to checkpoint results. Defaults to 30m. Supports values like: #s #m #h #d #w")

    args = parser.parse_args()

    # Check for root
    if os.geteuid() != 0:
        parser.error("This script must be run with root privileges.")

    return args


def syscall_name(num):
    return syscall.syscall_name(num).upper()
