//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 sysExecve ./bpf/sys_execve.c -- -nostdinc -I../headers

type exec_data_t struct {
	Type     uint32
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Ppid     uint32
	F_name   [32]byte
	Comm     [16]byte
	Args     [128]byte
	Arg_size uint32
}

func setlimit() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK,
		&unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}
}

func main() {
	args := make(map[uint32][]string)

	setlimit()

	objs := sysExecveObjects{}

	loadSysExecveObjects(&objs, nil)
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)

	rd, err := perf.NewReader(objs.ExecvePerfMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}

	for {
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		if data.Type == 0 {
			// args
			e, ok := args[data.Pid]
			if !ok {
				e = make([]string, 0)
			}
			if data.Arg_size > 127 {
				// abnormal
				if bs, err := json.Marshal(data); err == nil {
					log.Printf("[err]abnormal data: %s", string(bs))
				}
			} else {
				e = append(e, string(data.Args[:data.Arg_size]))
				args[data.Pid] = e
			}

		} else {
			argv, ok := args[data.Pid]
			if !ok {
				continue
			}
			// fmt.Printf("<type> %d <cpu> %02d <Common> %s <Pid> %d <Tgid> %d <Uid> %d <Gid> %d <FileNamme> %s <Args> %s <Size> %d\n",
			// 	data.Type, ev.CPU, data.Comm, data.Pid, data.Tgid, data.Uid, data.Gid, data.F_name, data.Args, data.Arg_size)
			fmt.Printf("<Pid> %d <Common> %s <Exe> %s <Cmdline> %s\n",
				data.Pid, data.Comm, data.F_name, strings.TrimSpace(strings.Replace(strings.Join(argv, " "), "\n", "\\n", -1)))
			delete(args, data.Pid)
			// fmt.Println(len(args))
		}
	}
}
