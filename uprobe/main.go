package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $CFLAGS -target native bpf probe.c -- -Iheaders

type bpf_event struct {
	Pid uint32
}

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

	// 打开Ringbuf文件
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %s", err)
	}
	defer rd.Close()

	// 收到中止信号
	go func() {
		<-stopper
		log.Println("Received signal, exiting program...")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	// 监听并输出事件
	var ev bpf_event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading from ringbuf reader: %s", err)
			continue
		}

		rbuf := bytes.NewBuffer(record.RawSample)
		if err := binary.Read(rbuf, binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing event: %s", err)
			continue
		}

		log.Printf("%s:%s pid: %d", *binPath, *symbol, ev.Pid)
	}
}
