#include "common.h"
#include "bpf_helpers.h"


#define FNAME_LEN 64 
struct exec_data_t {
	u32 pid;
	u8 fname[FNAME_LEN];
	u8 comm[FNAME_LEN];
};

// For Rust libbpf-rs only
struct exec_data_t _edt = {0};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct openat_entry_args_t {
        u16 _unused; //2 bytes
		const char* common_flags; //1 byte
		u8 _unused2; //1 byte
		u32 _unused3; //4 bytes
        u64 _unused4; //8 bytes
        u64 _unused5; //8 bytes

        const char* filename;
        u64 _unused6; //8 bytes
        u64 _unused7; //8 bytes
};

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32

SEC("tracepoint/syscalls/sys_enter_openat")
int enter_open(struct openat_entry_args_t *args)
{
	bpf_printk("Open syscall traced!");
	u64 uid_gid;
	u32 uid;
	uid_gid = bpf_get_current_uid_gid();
	uid = LAST_32_BITS(uid_gid); 
	if (uid == 1000) {
	
	struct exec_data_t exec_data = {};
	u64 pid_tgid;

	pid_tgid = bpf_get_current_pid_tgid();
	exec_data.pid = LAST_32_BITS(pid_tgid);
	
	bpf_probe_read_user_str(exec_data.fname,
		sizeof(exec_data.fname), args->filename);

	bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));

	bpf_perf_event_output(args, &events,
		BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));

	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";