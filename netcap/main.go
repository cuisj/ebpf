package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"syscall"
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

	// ETH_P_ALL 网络序: 0x0300
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0x0300)
	if err != nil {
		log.Fatal(err)
	}
	defer syscall.Close(sock)

	err = syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
	if err != nil {
		log.Fatal(err)
	}

	showMessage(amap)
}

func newMonitor() (*ebpf.Program, *ebpf.Map, error) {
	mp, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "netcap",
	})
	if err != nil {
		return nil, nil, err
	}

	ins := asm.Instructions{
		// 获取数据链路层协议
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadAbs(12, asm.Half), // r0 = ntoh(*(size *)(((sk_buff *)R6)->data + offset))
		asm.StoreMem(asm.RFP, -2, asm.R0, asm.Half),

		// 输出协议
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.LoadMapPtr(asm.R2, mp.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -2),
		asm.Mov.Imm(asm.R5, 2),
		asm.FnPerfEventOutput.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "netcap",
		Type:         ebpf.SocketFilter,
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

		log.Printf("ETH_P: 0x%04X\n", binary.LittleEndian.Uint16(record.RawSample[0:2]))
	}
}
