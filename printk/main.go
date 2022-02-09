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
		// 把字符串"hello!"放到栈上
		asm.StoreImm(asm.RFP, -8, 0x6C6C6568, asm.Word), // lleh
		asm.StoreImm(asm.RFP, -4, 0x216F, asm.Word),     // 00!o

		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8), // 字符串超始处(在栈上)

		asm.Mov.Imm(asm.R2, 7), // 字符串长度(包含结尾的null)

		asm.FnTracePrintk.Call(), // 调用函数

		asm.Mov.Imm(asm.R0, 0), // 返回值
		asm.Return(),
	}

	progSpec := &ebpf.ProgramSpec{
		Name:         "hello",
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

/*
	0: (62) *(u32 *)(r10 -8) = 1819043176
	1: (62) *(u32 *)(r10 -4) = 8559
	2: (bf) r1 = r10
	3: (07) r1 += -8
	4: (b7) r2 = 7
	5: (85) call bpf_trace_printk#6
	6: (b7) r0 = 0
	7: (95) exit
*/
