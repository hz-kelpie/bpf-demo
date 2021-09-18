#include "common.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define FNAME_LEN 32
#define ARGSIZE 128
#define DEFAULT_MAXARGS 20

struct execve_entry_args_t {
        u64 _unused; //8 bytes
        u64 _unused1; //8 bytes
        const char* filename; //offset:16;	size:8;
        // u64 _unused2;
        const char* const* argv; //offset:24;	size:8;
        const char* const* envp; //offset:32;   size:8;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *ctx)
{
	bpf_printk("execve syscall traced!");
    // 参数地址
	const char* argp = NULL;
    char fname[FNAME_LEN];
	char comm[TASK_COMM_LEN];
    char args[ARGSIZE];
	bpf_probe_read_str(fname, sizeof(fname), ctx->filename);
    
	// https://stackoverflow.com/questions/67188440/ebpf-cannot-read-argv-and-envp-from-tracepoint-sys-enter-execve
    // bpf_probe_read(&argp, sizeof(argp), &ctx->argv[0]);
	// bpf_probe_read_user_str(exec_data.args, ARGSIZE, argp);
    // bpf_perf_event_output(ctx, &execve_perf_map, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
	#pragma unroll
    for (__s32 i = 0; i < DEFAULT_MAXARGS; i++)
    {
		bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]);
		if (!argp) {
			return 0;;
		}
        int size = bpf_probe_read_str(args, ARGSIZE, argp);
        if (size  < 0) {
            bpf_printk("[ERROR] bpf_probe_read failed, [size]:%d [tgid]:%d",size,bpf_get_current_pid_tgid() >> 32);
        } else {
            bpf_printk("[INFO] [tgid]:%d [arg]:%s",bpf_get_current_pid_tgid() >> 32, args);
        }
    }
    bpf_printk("[WARN] more than 20 args! [tgid]:%d",bpf_get_current_pid_tgid() >> 32);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
