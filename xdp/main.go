package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"flag"
	"net"
	"log"
	"os"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	nifName := flag.String("interface", "lo", "network device interface name")
	flag.Parse()

	nif, err := net.InterfaceByName(*nifName)
	if err != nil {
		log.Fatal(err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	prog, amap, err := newMonitor()
	if err != nil {
		log.Fatal(err)
	}
	defer prog.Close()
	defer amap.Close()

	lnk, err := link.AttachXDP(link.XDPOptions{
			Program: prog,
			Interface: nif.Index,
		})
	if err != nil {
		log.Fatal(err)
	}
	defer lnk.Close()

	showMessage(amap)
}

func newMonitor() (*ebpf.Program, *ebpf.Map, error) {
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "xdp",
	})
	if err != nil {
		return nil, nil, err
	}

	ins := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),			// R6: R1, ctx
		asm.Mov.Imm(asm.R0, 1),				// XDP_DROP

		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),	// R1: ctx->data, ethhdr
		asm.Mov.Reg(asm.R2, asm.R1),			// R2: ctx->data + 14(ethhdr length)
		asm.Add.Imm(asm.R2, 14),
		asm.LoadMem(asm.R3, asm.R6, 4, asm.Word),	// R3: ctx->data_end

		// 必须检查长度，否则为越界访问
		asm.JGT.Reg(asm.R2, asm.R3, "exit"),		// 超长则退出

		// 获取数据链路层协议号
		asm.LoadMem(asm.R2, asm.R1, 12, asm.Half),	// R2: ethhdr->h_proto
		asm.StoreMem(asm.RFP, -2, asm.R2, asm.Half),	// 保存协议号

		// 输出
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, mp.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -2),
		asm.Mov.Imm(asm.R5, 2),
		asm.FnPerfEventOutput.Call(),

		asm.Mov.Imm(asm.R0, 2),				// XDP_PASS
		asm.Return().Sym("exit"),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "netcap",
		Type:         ebpf.XDP,
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

		log.Printf("0x%04X", binary.BigEndian.Uint16(record.RawSample[0:2]))
	}
}
