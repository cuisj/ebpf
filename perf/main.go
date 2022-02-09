package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	prog, amap, err := newMonitor()
	if err != nil {
		log.Fatal(err)
	}
	defer prog.Close()
	defer amap.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	showMessage(amap)
}

func newMonitor() (*ebpf.Program, *ebpf.Map, error) {
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "comm_map",
	})
	if err != nil {
		return nil, nil, err
	}

	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),

		// long bpf_get_current_comm(void *buf, u32 size_of_buf)
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),

		// long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, mp.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -16),
		asm.Mov.Imm(asm.R5, 16),
		asm.FnPerfEventOutput.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "map_oper",
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: ins,
	})
	if err != nil {
		mp.Close()
		return nil, nil, err
	}

	return prog, mp, nil
}

func showMessage(mp *ebpf.Map) {
	rd, err := perf.NewReader(mp, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("%s\n", string(record.RawSample))
	}
}
