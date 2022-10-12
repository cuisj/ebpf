package main

import (
	"bytes"
	"os/signal"
	"syscall"
	"os"
	"encoding/binary"
	"log"
	"flag"
	"errors"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $CFLAGS -target native bpf probe.c -- -Iheaders

type bpf_event struct {
	Pid uint32
};

func main() {
	binPath := flag.String("binpath", "hello-bpf", "executable programm")
	symbol := flag.String("symbol", "main.main", "symbol to trace")
	flag.Parse()
	
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 加载程序和映射到内核
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// 基于maps打开perf event文件
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	// 收到中止信号
	go func() {
		<-stopper
		log.Println("Received signal, exiting program...")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	// 打开ELF文件读取符号
	ex, err := link.OpenExecutable(*binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	// 关联程序到符号执行点事件上
	up, err := ex.Uprobe(*symbol, objs.TraceMain, nil)
	if err != nil {
		log.Fatalf("creating uprobe: %s", err)
	}
	defer up.Close()

	// 监听并输出事件
	var ev bpf_event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		rbuf := bytes.NewBuffer(record.RawSample)
		if err := binary.Read(rbuf, binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		log.Printf("%s:%s pid: %d", *binPath, *symbol, ev.Pid)
	}
}
