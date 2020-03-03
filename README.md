# bpfbench

Benchmarking done right in BPF.

## Features

- Summarize system call count and latency, **free of race conditions** that plague competitors like syscount
- Options to customize benchmark duration and checkpoint intervals (to ensure no loss of data)
- Disregards spurious system calls (e.g., `restart_syscall` after a system suspend)

## Installing

- Clone this repo
- Run `sudo make install`
- ???
- Profit
