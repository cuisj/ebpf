# ebpf
eBPF 程序

- 生成eBPF汇编代码

  - 创建容器

    ```
    docker run -it --name zta -h zta -v /Volumes/VD/work/zt:/root/work -w /root/work \
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

- TracePoint需挂载debugfs文件系统

  ```
  mount -t debugfs debugfs /sys/kernel/debug
  ```
