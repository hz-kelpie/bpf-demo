// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSysExecve returns the embedded CollectionSpec for sysExecve.
func loadSysExecve() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SysExecveBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load sysExecve: %w", err)
	}

	return spec, err
}

// loadSysExecveObjects loads sysExecve and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *sysExecveObjects
//     *sysExecvePrograms
//     *sysExecveMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSysExecveObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSysExecve()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// sysExecveSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sysExecveSpecs struct {
	sysExecveProgramSpecs
	sysExecveMapSpecs
}

// sysExecveSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sysExecveProgramSpecs struct {
	EnterExecve *ebpf.ProgramSpec `ebpf:"enter_execve"`
}

// sysExecveMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sysExecveMapSpecs struct {
	ExecvePerfMap *ebpf.MapSpec `ebpf:"execve_perf_map"`
}

// sysExecveObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSysExecveObjects or ebpf.CollectionSpec.LoadAndAssign.
type sysExecveObjects struct {
	sysExecvePrograms
	sysExecveMaps
}

func (o *sysExecveObjects) Close() error {
	return _SysExecveClose(
		&o.sysExecvePrograms,
		&o.sysExecveMaps,
	)
}

// sysExecveMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSysExecveObjects or ebpf.CollectionSpec.LoadAndAssign.
type sysExecveMaps struct {
	ExecvePerfMap *ebpf.Map `ebpf:"execve_perf_map"`
}

func (m *sysExecveMaps) Close() error {
	return _SysExecveClose(
		m.ExecvePerfMap,
	)
}

// sysExecvePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSysExecveObjects or ebpf.CollectionSpec.LoadAndAssign.
type sysExecvePrograms struct {
	EnterExecve *ebpf.Program `ebpf:"enter_execve"`
}

func (p *sysExecvePrograms) Close() error {
	return _SysExecveClose(
		p.EnterExecve,
	)
}

func _SysExecveClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed sysexecve_bpfeb.o
var _SysExecveBytes []byte
