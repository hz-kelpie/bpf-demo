#include "common.h"
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define FNAME_LEN 32
#define ARGSIZE 128
#define DEFAULT_MAXARGS 20


struct exec_data_t {
    u32 type;
	u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    u32 ppid;
	char fname[FNAME_LEN];
	char comm[TASK_COMM_LEN];
    char args[ARGSIZE];
    u32 arg_size;
};

// For Rust libbpf-rs only
struct exec_data_t _edt = {0};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} execve_perf_map SEC(".maps");

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
	// bpf_printk("execve syscall traced!");
	struct exec_data_t exec_data = {};
    // 参数地址
	const char* argp = NULL;
	exec_data.pid = bpf_get_current_pid_tgid();

    // 命令行参数都是用户空间分配的，所以用***_user_str
	// https://stackoverflow.com/questions/67188440/ebpf-cannot-read-argv-and-envp-from-tracepoint-sys-enter-execve
    // 先读取第一个参数地址，在读取第一个参数内容
    int err = bpf_probe_read(&argp, sizeof(argp), &ctx->argv[0]);
	int result = bpf_probe_read_str(exec_data.args, ARGSIZE, argp);
    
    char msg[] = "reading arg string %d %d %d\n";
    bpf_trace_printk(msg, sizeof(msg), result, err, argp);
    if (result < 0) {
        return 0;
    }
    exec_data.arg_size = result;
    bpf_perf_event_output(ctx, &execve_perf_map, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
    // 从第二个参数开始处理
    // 告诉编译器，不做循环展开
    // #pragma unroll
    // for (__s32 i = 0; i < DEFAULT_MAXARGS; i++)
    // {
    //     // 读取后续参数地址
	// 	bpf_probe_read(&argp, sizeof(argp), &ctx->argv[i]);
	// 	if (!argp) {
	// 		goto finish;
	// 	}
    //     // 地址为空，说明没有参数
    //     exec_data.arg_size = bpf_probe_read_str(exec_data.args, ARGSIZE, argp);
    //     bpf_perf_event_output(ctx, &execve_perf_map, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
    // }
    // // 参数超出上限，不继续处理 TODO
	// finish:

    exec_data.type = 1;
    exec_data.tgid = bpf_get_current_pid_tgid() >> 32;
    exec_data.uid = bpf_get_current_uid_gid();
    exec_data.gid = bpf_get_current_uid_gid() >> 32;
	bpf_probe_read_str(exec_data.fname, sizeof(exec_data.fname), ctx->filename);

	bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));
    bpf_perf_event_output(ctx, &execve_perf_map, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
