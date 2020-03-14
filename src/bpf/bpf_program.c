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
#include <linux/sched.h>

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

#ifdef FOLLOW
BPF_HASH(children, u32, u8);

RAW_TRACEPOINT_PROBE(sched_process_fork)
{
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    struct task_struct *c = (struct task_struct *)ctx->args[1];

    u32 ppid = p->tgid;

    /* Filter ppid */
    if (ppid != TRACE_PID && !children.lookup(&ppid))
    {
        return 0;
    }

    u32 cpid = c->tgid;

    u8 zero = 0;

    children.update(&cpid, &zero);

    return 0;
}

RAW_TRACEPOINT_PROBE(sched_process_exit)
{
    u32 pid = (bpf_get_current_pid_tgid() >> 32);

    /* Filter ppid */
    if (pid != TRACE_PID && !children.lookup(&pid))
    {
        return 0;
    }

    children.delete(&pid);

    return 0;
}
#endif

TRACEPOINT_PROBE(raw_syscalls, sys_enter)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Maybe filter by PID */
    #if defined(TRACE_PID) && defined(FOLLOW)
    u32 pid = (pid_tgid >> 32);
    if (pid != TRACE_PID && !children.lookup(&pid))
    {
        return 0;
    }
    #elif defined(TRACE_PID)
    if (pid_tgid >> 32 != TRACE_PID)
    {
        return 0;
    }
    #endif

    /* Don't trace self */
    if (pid_tgid >> 32 == BPFBENCH_PID)
    {
        return 0;
    }

    int zero = 0;
    struct intermediate_t *start = intermediate.lookup(&zero);
    if (!start)
    {
        return 0;
    }

    /* Record pit_tgid of initiating process */
    start->pid_tgid = pid_tgid;
    /* Record start time */
    start->start_time = bpf_ktime_get_ns();

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_exit)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Maybe filter by PID */
    #if defined(TRACE_PID) && defined(FOLLOW)
    u32 pid = (pid_tgid >> 32);
    if (pid != TRACE_PID && !children.lookup(&pid))
    {
        return 0;
    }
    #elif defined(TRACE_PID)
    if (pid_tgid >> 32 != TRACE_PID)
    {
        return 0;
    }
    #endif

    /* Don't trace self */
    if (pid_tgid >> 32 == BPFBENCH_PID)
    {
        return 0;
    }

    int zero = 0;
    int syscall = args->id;

    /* Discard restarted syscalls due to system suspend */
    if (args->id == __NR_restart_syscall)
    {
        return 0;
    }

    struct data_t *data = syscalls.lookup(&syscall);
    struct intermediate_t *start = intermediate.lookup(&zero);
    if (start && data)
    {
        /* We don't want to count twice for calls that return in two places */
        if (pid_tgid != start->pid_tgid)
        {
            bpf_trace_printk("syscall %ld: return pid: %lu start pid: %lu\n", args->id, pid_tgid >> 32, start->pid_tgid >> 32);
            return 0;
        }
        data->count++;
        data->overhead += bpf_ktime_get_ns() - start->start_time;
    }

    return 0;
}
