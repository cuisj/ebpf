package main

import (
	"bufio"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"io"
	"log"
	"os"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	ins := asm.Instructions{
		// char comm[16]
		asm.Mov.Reg(asm.R6, asm.RFP),
		asm.Add.Imm(asm.R6, -16),

		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),

		// "%s"
		asm.StoreImm(asm.RFP, -18, 0, asm.Half),
		asm.StoreImm(asm.RFP, -20, 29477, asm.Half),

		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -20),
		asm.Mov.Imm(asm.R2, 3),
		asm.Mov.Reg(asm.R3, asm.R6),
		asm.FnTracePrintk.Call(),

		asm.Return(),
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         "comm",
		Type:         ebpf.TracePoint,
		Instructions: ins,
		License:      "GPL",
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}
	defer prog.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	trace_output()
}

func trace_output() {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Fatalf("open file: %s", err)
	}
	defer f.Close()

	br := bufio.NewReader(f)

	for {
		l, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}

		log.Printf("%s", string(l))
	}
}
