import os, sys
import argparse

from bcc import syscall

DESCRIPTION = """
System benchmarking with eBPF.
Right now, supports benchmarking system calls.
"""

EPILOG = """
"""

def parse_args(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    #parser.add_argument()

    args = parser.parse_args()

    # Check for root
    if os.geteuid() != 0:
        parser.error("This script must be run with root privileges.")

    return args


def syscall_name(num):
    return syscall.syscall_name(num).upper()
