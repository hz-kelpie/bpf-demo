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
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 sysOpenat ./bpf/sys_openat.c -- -nostdinc -I../headers

type exec_data_t struct {
	Pid      uint32
	FileName [64]byte
	Command  [64]byte
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
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	setlimit()
	//after go generate we can load our objects
	objs := sysOpenatObjects{}
	err := loadSysOpenatObjects(&objs, nil)
	if err != nil {
		panic(err)
	}
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.EnterOpen)
	if err != nil {
		panic(err)
	}
	defer tp.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper
		rd.Close()
	}()

	for {
		//https://pkg.go.dev/github.com/cilium/ebpf/perf#Reader.Read
		ev, err := rd.Read()
		if err != nil {
			panic(err)
		}
		if ev.LostSamples != 0 {
			log.Printf("Ring buffer is full, dropped messages %v\n", ev.LostSamples)
		}
		rawData := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(rawData, binary.LittleEndian, &data); err != nil {
			log.Printf("Error while parsing perf event: %v\n", err)
			continue
		}

		//fmt.Printf("On cpu %02d %s ran : %d %s\n", ev.CPU, data.Command, data.Pid, data.FileName)
		fmt.Printf("FileName: %s\n", data.FileName)
	}
}
