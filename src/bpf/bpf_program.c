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
