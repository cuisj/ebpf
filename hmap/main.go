package main

import (
	"time"
	"log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	prog, hmap, err := newMonitor()
	if err != nil {
		log.Fatal(err)
	}
	defer prog.Close()
	defer hmap.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	for {
		showMessage(hmap)
		time.Sleep(time.Second)
	}
}

func newMonitor() (*ebpf.Program, *ebpf.Map, error) {
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash,
		KeySize: 4,
		ValueSize: 8,
		MaxEntries: 4,
	})
	if err != nil {
		return nil, nil, err
	}

	ins := asm.Instructions{
		// r1: map ptr
		asm.LoadMapPtr(asm.R1, mp.FD()),

		// r2: key
		asm.StoreImm(asm.RFP, -4, 1, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),

		// r3: value
		asm.StoreImm(asm.RFP, -16, 3, asm.DWord),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),

		// r4: flags, 0
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "map_oper",
		Type: ebpf.TracePoint,
		License: "GPL",
		Instructions: ins,
	})
	if err != nil {
		mp.Close()
		return nil, nil, err
	}

	return prog, mp, nil
}

func showMessage(mp *ebpf.Map) {
	var (
		iter = mp.Iterate()
		key uint32
		val uint64
	)

	for iter.Next(&key, &val) {
		log.Printf("%d : %d\n", key, val)
	}

	if err := iter.Err(); err != nil {
		log.Fatal(err)
	}
}
