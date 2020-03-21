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
import subprocess

from bcc import syscall

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
