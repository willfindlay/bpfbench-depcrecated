/* bpfbench  A better benchmarking tool written in eBPF.
 * Copyright (C) 2020  William Findlay
 *
 * Heavily inspired by syscount from bcc-tools:
 * https://github.com/iovisor/bcc/blob/master/tools/syscount.py
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>. */

#include <uapi/asm/unistd_64.h>

struct intermediate_t
{
    u64 pid_tgid;
    u64 start_time;
};

struct data_t
{
    u64 count;
    u64 overhead;
};

BPF_PERCPU_ARRAY(intermediate, struct intermediate_t, 1);
BPF_PERCPU_ARRAY(syscalls, struct data_t, NUM_SYSCALLS);

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    int zero = 0;
    struct intermediate_t start = {};

    start.pid_tgid = bpf_get_current_pid_tgid();
    start.start_time = bpf_ktime_get_ns();

    intermediate.update(&zero, &start);

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    int zero = 0;
    int syscall = args->id;
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Discard restarted syscalls due to system suspend */
    if (args->id == __NR_restart_syscall)
        return 0;

    struct data_t *data = syscalls.lookup(&syscall);
    struct intermediate_t *start = intermediate.lookup(&zero);
    if (start && data)
    {
        /* We don't want to count twice for calls that return in two places */
        if (pid_tgid != start->pid_tgid)
            return 0;
        data->count++;
        data->overhead += bpf_ktime_get_ns() - start->start_time;
    }

    return 0;
}
