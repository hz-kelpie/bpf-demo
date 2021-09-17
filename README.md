# 说明

Support kernel > 3.15 in the abstract, but only pass test on 4.19/5.11

# Examples

- [kprobe](kprobe/) - Attach a program to the entry or exit of an arbitrary kernel symbol (function).
- [tracepoint-openat](tracepoint-openat/) - HOOK file event by tracepoint. It assumes the BPF FS is mounted at `/sys/fs/bpf`.
- [tracepoint-execve](tracepoint-execve/) - HOOK execve event by tracepoint.
- [uretprobe-bashline](uretprobe-bashline/) - HOOK user bash line by ureprobe.


# How to run

```bash
go run -exec sudo [./tracepoint-execve, ./uretprobe-bashline, ./tracepoint-openat, ...]
```
