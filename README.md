# ebpf
eBPF 程序

## 汇编说明

- r0 保存辅助函数的返回值，通用寄存器
- r1 一般保存上下文
- r1 - r5 传递辅助函数参数，暂存，调用结束后，值被清除
- r6 - r9 跨辅助函数保存值，保持，调用结束后，值被保留
- r10 保存栈指针，只读

## 生成eBPF汇编代码

- 创建容器

  ```
  docker create -it --name zta -h zta -v /Volumes/VD/work/zt:/root/work -w /root/work \
  --privileged fedora bash
  ```

  ```
  yum install -y python3-bcc kernel-devel kernel-modules
  ln -s /lib/modules/5.16.5-200.fc35.x86_64 /lib/modules/5.10.76-linuxkit
  ```

- 生成代码

  ```
  #!/usr/bin/python3
  
  from bcc import BPF
  
  bpf_source = """
  void show(void *ctx) {
  	char comm[16];
  	bpf_get_current_comm(&comm, sizeof(comm));
  	bpf_trace_printk("%s", comm);
  }
  """
  
  bpf = BPF(text = bpf_source)
  print(bpf.disassemble_func(func_name="show"))
  ```

- XDP

  ```
  #!/usr/bin/python3
  
  from bcc import BPF
  
  bpf_source = """
  #include <linux/bpf.h>
  #include <linux/in.h>
  #include <linux/ip.h>
  #include <linux/tcp.h>
  
  int show(struct xdp_md *ctx) {
  	void *data = (void *)(long)ctx->data;
  	void *data_end = (void *)(long)ctx->data_end;
  	struct ethhdr *eth = data;
  
  	// 必须检查长度，否则视为越界访问
  	if (data + 14 > data_end) {
  		return XDP_DROP;
  	}
  
  	bpf_trace_printk("%d", eth->h_proto);
  
  	return XDP_PASS;
  }
  """
  
  bpf = BPF(text = bpf_source)
  print(bpf.disassemble_func(func_name="show"))
  ```

## TracePoint

- 需挂载debugfs文件系统

```
mount -t debugfs debugfs /sys/kernel/debug
```

## 内核符号表

```
cat /proc/kallsyms
```

## 程序符号表

```
readelf -s /usr/bin/bash
```

## TracePoint事件

```
tree /sys/kernel/debug/tracing/events
```

## USDT

- 程序中添加探测点

  ```
  #include <sys/sdt.h>

  int main(int argc, char *argv[]) {
		DTRACE_PROBE(hello, main);
		return 0;
  }
  ```

- 列出探测点

  ```
  [cgo@localhost ~]$ readelf -n hello
  
  Displaying notes found at file offset 0x00000254 with length 0x00000020:
    Owner                 Data size	Description
    GNU                  0x00000010	NT_GNU_ABI_TAG (ABI version tag)
      OS: Linux, ABI: 2.6.32
  
  Displaying notes found at file offset 0x00000274 with length 0x00000024:
    Owner                 Data size	Description
    GNU                  0x00000014	NT_GNU_BUILD_ID (unique build ID bitstring)
      Build ID: 47142f92fcbd08030218e1c441ed2596afa051e9
  
  Displaying notes found at file offset 0x0000105c with length 0x00000038:
    Owner                 Data size	Description
    stapsdt              0x00000024	NT_STAPSDT (SystemTap probe descriptors)
      Provider: hello
      Name: main
      Location: 0x00000000004004f8, Base: 0x0000000000400590, Semaphore: 0x0000000000000000
      Arguments: 
  ```

- 查看内核配置

  ```
  zcat /proc/config.gz
  ```

## 由C生成bpf代码

- 创建容器

  ```
  docker create -it --name bpf -h bpf -v /Volumes/VD/work/pf:/root/work \
  -v /Volumes/VD/work/os/go:/usr/local/go -v /Volumes/VD/work/os/pg:/root/go \
  -w /root/work --cap-add SYS_RESOURCE --cap-add SYS_ADMIN centos bash
  ```

- 替换安装源

  ```
  sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
  sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
  ```

- 安装编译工具

  ```
  /usr/bin/cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
  echo -e 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' > /etc/profile.d/golang.sh
  echo -e 'export BPF_CLANG=clang\nexport BPF_CFLAGS="-O2 -g -Wall -Werror"' > /etc/profile.d/ebpf.sh
  go env -w GOPROXY=https://goproxy.cn
  
  yum install -y clang llvm
  ```

- 反汇编

  ```
  llvm-objdump -d bpf_bpfel_x86.o
  ```

  
