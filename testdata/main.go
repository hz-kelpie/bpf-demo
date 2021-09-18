//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 sysExecve ./bpf/sys_execve.c -- -nostdinc -I../headers

func main() {
	objs := sysExecveObjects{}

	loadSysExecveObjects(&objs, nil)
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)

	c := make(chan os.Signal)
	//监听所有信号
	signal.Notify(c)
	//阻塞直到有信号传入
	fmt.Println("start")
	s := <-c
	fmt.Println("exit", s)
}
