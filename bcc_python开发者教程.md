# bcc Python 开发者教程

这个教程是关于使用Python接口开发 [bcc](https://github.com/iovisor/bcc) 工具集和程序。有两个部分：可观察性与网络。代码片段都是来自bcc里的各种程序：查看它们的文件以获取许可证。

也可以查看bcc开发者的参考指南 [reference_guide.md](reference_guide.md)和面向最终用户的工具教程 [tutorial.md](tutorial.md)。bcc也有lua接口。

## 可观察性

这个可观察性教程包含17个课程和46个列举出来的需要学习的地方。


### 课程 1. Hello World

开始运行 [examples/hello_world.py](../examples/hello_world.py)同时在另一个会话中运行相同的命令（例如，"ls"）。对于新的进程它应该打印出"Hello, World!"。如果没有，请先修复bcc：查看 [INSTALL.md](../INSTALL.md)。

```
# ./examples/hello_world.py
            bash-13364 [002] d... 24573433.052937: : Hello, World!
            bash-13364 [003] d... 24573436.642808: : Hello, World!
[...]
```

这里是有关hello_world.py的代码：

```Python
from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

这里有6个地方需要学习：

1. ```text='...'```: 这是定义BPF内联程序的地方。这个程序是由C语言编写的。

2. ```kprobe__sys_clone()```: 这是一个通过探针进行内核动态跟踪的捷径。如果C函数是以``kprobe__``开头，则其余部分被命名为要检测的内核函数，在这个例子中是```sys_clone()```。

3. ```void *ctx```: ctx有参数，但是由于我们这里没有使用它们，所以只需将其转换为```void *```。

4. ```bpf_trace_printk()```:  一个简单的内核工具用于printf()到公共的trace_pipe(/sys/kernel/debug/tracing/trace_pipe)。对于一些快速的例子这是ok的，但是有局限性：最大3个参数，只有一个%s，并且trace_pipe是全局共享的，所以并发程序会有冲突的输出。一个更好的接口是通过BPF_PERF_OUTPUT()，稍后介绍。

5. ```return 0;```: 必要的形式（如果你想知道为什么，看看 [#139](https://github.com/iovisor/bcc/issues/139)）。

6. ```.trace_print()```: 一个读取trace_pipe并且打印其输出的惯例。



### 课程 2. sys_sync()

编写一个追踪sys_sync()内核函数的程序。当它开始运行时打印"sys_sync() called"。通过在另外一个会话中运行```sync```进行测试同时追踪。hello_world.py程序有你所需的一切。

当第一次启动这个程序时，通过打印"Tracing sys_sync()... Ctrl-C to end."来改进它。提示：它只是一个Python程序。

### 课程 3. hello_fields.py

这个程序在 [examples/tracing/hello_fields.py](../examples/tracing/hello_fields.py)中。样本输出（在另外一个会话运行命令）：


```
# ./examples/tracing/hello_fields.py
TIME(s)            COMM             PID    MESSAGE
24585001.174885999 sshd             1432   Hello, World!
24585001.195710000 sshd             15780  Hello, World!
24585001.991976000 systemd-udevd    484    Hello, World!
24585002.276147000 bash             15787  Hello, World!
```

代码:

```Python
from bcc import BPF

# define BPF program
prog = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\\n");
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
```

这与hello_world.py类似，并且再次通过sys_clone()追踪新的进程，但是有几个地方需要学习：

1. ```prog =```: 这次我们把C程序声明为变量，并且在稍后引用它。如果你想根据命令行参数添加一些字符串替换这会很有用。

1. ```hello()```: 现在我们只是声明了一个C函数，用来代替那个```kprobe__```捷径。我们稍后会引用它。所有在BPF程序中声明的C函数都应该工作在探针上，因此它们都需要把```pt_reg* ctx```作为第一个参数。如果你需要定义一些不在探针上工作的帮助函数，它们需要被定义为```static inline```以便编译器内联。有时候你也需要为它添加```_always_inline```函数属性。

1. ```b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")```: 为内核克隆系统调用函数创建一个探针，这个探针将会执行我们定义的hello()函数。你可以不止一次调用attach_kprobe()，并且将你的C函数连接到多个内核函数。

1. ```b.trace_fields()```: 从trace_pipe返回一组固定的字段。类似于trace_print()，这有利于黑客攻击，因此在实际的工具中我们应该切换成BPF_PERF_OUTPUT()。


### Lesson 4. sync_timing.py

Remember the days of sysadmins typing ```sync``` three times on a slow console before ```reboot```, to give the first asynchronous sync time to complete? Then someone thought ```sync;sync;sync``` was clever, to run them all on one line, which became industry practice despite defeating the original purpose! And then sync became synchronous, so more reasons it was silly. Anyway.

The following example times how quickly the ```do_sync``` function is called, and prints output if it has been called more recently than one second ago. A ```sync;sync;sync``` will print output for the 2nd and 3rd sync's:

```
# ./examples/tracing/sync_timing.py
Tracing for quick sync's... Ctrl-C to end
At time 0.00 s: multiple syncs detected, last 95 ms ago
At time 0.10 s: multiple syncs detected, last 96 ms ago
```

This program is [examples/tracing/sync_timing.py](../examples/tracing/sync_timing.py):

```Python
from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    (task, pid, cpu, flags, ts, ms) = b.trace_fields()
    if start == 0:
        start = ts
    ts = ts - start
    print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
```

Things to learn:

1. ```bpf_ktime_get_ns()```: Returns the time as nanoseconds.
1. ```BPF_HASH(last)```: Creates a BPF map object that is a hash (associative array), called "last". We didn't specify any further arguments, so it defaults to key and value types of u64.
1. ```key = 0```: We'll only store one key/value pair in this hash, where the key is hardwired to zero.
1. ```last.lookup(&key)```: Lookup the key in the hash, and return a pointer to its value if it exists, else NULL. We pass the key in as an address to a pointer.
1. ```if (tsp != NULL) {```: The verifier requires that pointer values derived from a map lookup must be checked for a null value before they can be dereferenced and used.
1. ```last.delete(&key)```: Delete the key from the hash. This is currently required because of [a kernel bug in `.update()`](https://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=a6ed3ea65d9868fdf9eff84e6fe4f666b8d14b02) (fixed in 4.8.10).
1. ```last.update(&key, &ts)```: Associate the value in the 2nd argument to the key, overwriting any previous value. This records the timestamp.

### Lesson 5. sync_count.py

Modify the sync_timing.py program (prior lesson) to store the count of all kernel sync system calls (both fast and slow), and print it with the output. This count can be recorded in the BPF program by adding a new key index to the existing hash.

### Lesson 6. disksnoop.py

Browse the [examples/tracing/disksnoop.py](../examples/tracing/disksnoop.py) program to see what is new. Here is some sample output:

```
# ./disksnoop.py
TIME(s)            T  BYTES    LAT(ms)
16458043.436012    W  4096        3.13
16458043.437326    W  4096        4.44
16458044.126545    R  4096       42.82
16458044.129872    R  4096        3.24
[...]
```

And a code snippet:

```Python
[...]
REQ_WRITE = 1		# from include/linux/blk_types.h

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, struct request *);

void trace_start(struct pt_regs *ctx, struct request *req) {
	// stash start timestamp by request ptr
	u64 ts = bpf_ktime_get_ns();

	start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
	u64 *tsp, delta;

	tsp = start.lookup(&req);
	if (tsp != 0) {
		delta = bpf_ktime_get_ns() - *tsp;
		bpf_trace_printk("%d %x %d\\n", req->__data_len,
		    req->cmd_flags, delta / 1000);
		start.delete(&req);
	}
}
""")

b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")
[...]
```

Things to learn:

1. ```REQ_WRITE```: We're defining a kernel constant in the Python program because we'll use it there later. If we were using REQ_WRITE in the BPF program, it should just work (without needing to be defined) with the appropriate #includes.
1. ```trace_start(struct pt_regs *ctx, struct request *req)```: This function will later be attached to kprobes. The arguments to kprobe functions are ```struct pt_regs *ctx```, for registers and BPF context, and then the actual arguments to the function. We'll attach this to blk_start_request(), where the first argument is ```struct request *```.
1. ```start.update(&req, &ts)```: We're using the pointer to the request struct as a key in our hash. What? This is commonplace in tracing. Pointers to structs turn out to be great keys, as they are unique: two structs can't have the same pointer address. (Just be careful about when it gets free'd and reused.) So what we're really doing is tagging the request struct, which describes the disk I/O, with our own timestamp, so that we can time it. There's two common keys used for storing timestamps: pointers to structs, and, thread IDs (for timing function entry to return).
1. ```req->__data_len```: We're dereferencing members of ```struct request```. See its definition in the kernel source for what members are there. bcc actually rewrites these expressions to be a series of ```bpf_probe_read_kernel()``` calls. Sometimes bcc can't handle a complex dereference, and you need to call ```bpf_probe_read_kernel()``` directly.

This is a pretty interesting program, and if you can understand all the code, you'll understand many important basics. We're still using the bpf_trace_printk() hack, so let's fix that next.

### Lesson 7. hello_perf_output.py

Let's finally stop using bpf_trace_printk() and use the proper BPF_PERF_OUTPUT() interface. This will also mean we stop getting the free trace_field() members like PID and timestamp, and will need to fetch them directly. Sample output while commands are run in another session:

```
# ./hello_perf_output.py
TIME(s)            COMM             PID    MESSAGE
0.000000000        bash             22986  Hello, perf_output!
0.021080275        systemd-udevd    484    Hello, perf_output!
0.021359520        systemd-udevd    484    Hello, perf_output!
0.021590610        systemd-udevd    484    Hello, perf_output!
[...]
```

Code is [examples/tracing/hello_perf_output.py](../examples/tracing/hello_perf_output.py):

```Python
from bcc import BPF

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        "Hello, perf_output!"))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
```

Things to learn:

1. ```struct data_t```: This defines the C struct we'll use to pass data from kernel to user space.
1. ```BPF_PERF_OUTPUT(events)```: This names our output channel "events".
1. ```struct data_t data = {};```: Create an empty data_t struct that we'll then populate.
1. ```bpf_get_current_pid_tgid()```: Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID), and the thread group ID in the upper 32 bits (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits. Should you be presenting the PID or the TGID? For a multi-threaded app, the TGID will be the same, so you need the PID to differentiate them, if that's what you want. It's also a question of expectations for the end user.
1. ```bpf_get_current_comm()```: Populates the first argument address with the current process name.
1. ```events.perf_submit()```: Submit the event for user space to read via a perf ring buffer.
1. ```def print_event()```: Define a Python function that will handle reading events from the ```events``` stream.
1. ```b["events"].event(data)```: Now get the event as a Python object, auto-generated from the C declaration.
1. ```b["events"].open_perf_buffer(print_event)```: Associate the Python ```print_event``` function with the ```events``` stream.
1. ```while 1: b.perf_buffer_poll()```: Block waiting for events.

### Lesson 8. sync_perf_output.py

Rewrite sync_timing.py, from a prior lesson, to use ```BPF_PERF_OUTPUT```.

### Lesson 9. bitehist.py

The following tool records a histogram of disk I/O sizes. Sample output:

```
# ./bitehist.py
Tracing... Hit Ctrl-C to end.
^C
     kbytes          : count     distribution
       0 -> 1        : 3        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 211      |**********                            |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 800      |**************************************|
```

Code is [examples/tracing/bitehist.py](../examples/tracing/bitehist.py):

```Python
from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req)
{
	dist.increment(bpf_log2l(req->__data_len / 1024));
	return 0;
}
""")

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
b["dist"].print_log2_hist("kbytes")
```

A recap from earlier lessons:

- ```kprobe__```: This prefix means the rest will be treated as a kernel function name that will be instrumented using kprobe.
- ```struct pt_regs *ctx, struct request *req```: Arguments to kprobe. The ```ctx``` is registers and BPF context, the ```req``` is the first argument to the instrumented function: ```blk_account_io_done()```.
- ```req->__data_len```: Dereferencing that member.

New things to learn:

1. ```BPF_HISTOGRAM(dist)```: Defines a BPF map object that is a histogram, and names it "dist".
1. ```dist.increment()```: Increments the histogram bucket index provided as first argument by one by default. Optionally, custom increments can be passed as the second argument.
1. ```bpf_log2l()```: Returns the log-2 of the provided value. This becomes the index of our histogram, so that we're constructing a power-of-2 histogram.
1. ```b["dist"].print_log2_hist("kbytes")```: Prints the "dist" histogram as power-of-2, with a column header of "kbytes". The only data transferred from kernel to user space is the bucket counts, making this efficient.

### Lesson 10. disklatency.py

Write a program that times disk I/O, and prints a histogram of their latency. Disk I/O instrumentation and timing can be found in the disksnoop.py program from a prior lesson, and histogram code can be found in bitehist.py from a prior lesson.

### Lesson 11. vfsreadlat.py

This example is split into separate Python and C files. Example output:

```
# ./vfsreadlat.py 1
Tracing... Hit Ctrl-C to end.
     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 2        |***********                             |
         4 -> 7          : 7        |****************************************|
         8 -> 15         : 4        |**********************                  |

     usecs               : count     distribution
         0 -> 1          : 29       |****************************************|
         2 -> 3          : 28       |**************************************  |
         4 -> 7          : 4        |*****                                   |
         8 -> 15         : 8        |***********                             |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 0        |                                        |
       128 -> 255        : 0        |                                        |
       256 -> 511        : 2        |**                                      |
       512 -> 1023       : 0        |                                        |
      1024 -> 2047       : 0        |                                        |
      2048 -> 4095       : 0        |                                        |
      4096 -> 8191       : 4        |*****                                   |
      8192 -> 16383      : 6        |********                                |
     16384 -> 32767      : 9        |************                            |
     32768 -> 65535      : 6        |********                                |
     65536 -> 131071     : 2        |**                                      |

     usecs               : count     distribution
         0 -> 1          : 11       |****************************************|
         2 -> 3          : 2        |*******                                 |
         4 -> 7          : 10       |************************************    |
         8 -> 15         : 8        |*****************************           |
        16 -> 31         : 1        |***                                     |
        32 -> 63         : 2        |*******                                 |
[...]
```

Browse the code in [examples/tracing/vfsreadlat.py](../examples/tracing/vfsreadlat.py) and [examples/tracing/vfsreadlat.c](../examples/tracing/vfsreadlat.c). Things to learn:

1. ```b = BPF(src_file = "vfsreadlat.c")```: Read the BPF C program from a separate source file.
1. ```b.attach_kretprobe(event="vfs_read", fn_name="do_return")```: Attaches the BPF C function ```do_return()``` to the return of the kernel function ```vfs_read()```. This is a kretprobe: instrumenting the return from a function, rather than its entry.
1. ```b["dist"].clear()```: Clears the histogram.

### Lesson 12. urandomread.py

Tracing while a ```dd if=/dev/urandom of=/dev/null bs=8k count=5``` is run:

```
# ./urandomread.py
TIME(s)            COMM             PID    GOTBITS
24652832.956994001 smtp             24690  384
24652837.726500999 dd               24692  65536
24652837.727111001 dd               24692  65536
24652837.727703001 dd               24692  65536
24652837.728294998 dd               24692  65536
24652837.728888001 dd               24692  65536
```

Hah! I caught smtp by accident. Code is [examples/tracing/urandomread.py](../examples/tracing/urandomread.py):

```Python
from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
""")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "GOTBITS"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
```

Things to learn:

1. ```TRACEPOINT_PROBE(random, urandom_read)```: Instrument the kernel tracepoint ```random:urandom_read```. These have a stable API, and thus are recommend to use instead of kprobes, wherever possible. You can run ```perf list``` for a list of tracepoints. Linux >= 4.7 is required to attach BPF programs to tracepoints.
1. ```args->got_bits```: ```args``` is auto-populated to be a structure of the tracepoint arguments. The comment above says where you can see that structure. Eg:

```
# cat /sys/kernel/debug/tracing/events/random/urandom_read/format
name: urandom_read
ID: 972
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int got_bits;	offset:8;	size:4;	signed:1;
	field:int pool_left;	offset:12;	size:4;	signed:1;
	field:int input_left;	offset:16;	size:4;	signed:1;

print fmt: "got_bits %d nonblocking_pool_entropy_left %d input_entropy_left %d", REC->got_bits, REC->pool_left, REC->input_left
```

In this case, we were printing the ```got_bits``` member.

### Lesson 13. disksnoop.py fixed

Convert disksnoop.py from a previous lesson to use the ```block:block_rq_issue``` and ```block:block_rq_complete``` tracepoints.

### Lesson 14. strlen_count.py

This program instruments a user-level function, the ```strlen()``` library function, and frequency counts its string argument. Example output:

```
# ./strlen_count.py
Tracing strlen()... Hit Ctrl-C to end.
^C     COUNT STRING
         1 " "
         1 "/bin/ls"
         1 "."
         1 "cpudist.py.1"
         1 ".bashrc"
         1 "ls --color=auto"
         1 "key_t"
[...]
        10 "a7:~# "
        10 "/root"
        12 "LC_ALL"
        12 "en_US.UTF-8"
        13 "en_US.UTF-8"
        20 "~"
        70 "#%^,~:-=?+/}"
       340 "\x01\x1b]0;root@bgregg-test: ~\x07\x02root@bgregg-test:~# "
```

These are various strings that are being processed by this library function while tracing, along with their frequency counts. ```strlen()``` was called on "LC_ALL" 12 times, for example.

Code is [examples/tracing/strlen_count.py](../examples/tracing/strlen_count.py):

```Python
from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    char c[80];
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    bpf_probe_read_user(&key.c, sizeof(key.c), (void *)PT_REGS_PARM1(ctx));
    // could also use `counts.increment(key)`
    val = counts.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
};
""")
b.attach_uprobe(name="c", sym="strlen", fn_name="count")

# header
print("Tracing strlen()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# print output
print("%10s %s" % ("COUNT", "STRING"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    print("%10d \"%s\"" % (v.value, k.c.encode('string-escape')))
```

Things to learn:

1. ```PT_REGS_PARM1(ctx)```: This fetches the first argument to ```strlen()```, which is the string.
1. ```b.attach_uprobe(name="c", sym="strlen", fn_name="count")```: Attach to library "c" (if this is the main program, use its pathname), instrument the user-level function ```strlen()```, and on execution call our C function ```count()```.

### Lesson 15. nodejs_http_server.py

This program instruments a user statically-defined tracing (USDT) probe, which is the user-level version of a kernel tracepoint. Sample output:

```
# ./nodejs_http_server.py 24728
TIME(s)            COMM             PID    ARGS
24653324.561322998 node             24728  path:/index.html
24653335.343401998 node             24728  path:/images/welcome.png
24653340.510164998 node             24728  path:/images/favicon.png
```

Relevant code from [examples/tracing/nodejs_http_server.py](../examples/tracing/nodejs_http_server.py):

```Python
from __future__ import print_function
from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("USAGE: nodejs_http_server PID")
    exit()
pid = sys.argv[1]
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
int do_trace(struct pt_regs *ctx) {
    uint64_t addr;
    char path[128]={0};
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path), (void *)addr);
    bpf_trace_printk("path:%s\\n", path);
    return 0;
};
"""

# enable USDT probe from given PID
u = USDT(pid=int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")
if debug:
    print(u.get_text())
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text, usdt_contexts=[u])
```

Things to learn:

1. ```bpf_usdt_readarg(6, ctx, &addr)```: Read the address of argument 6 from the USDT probe into ```addr```.
1. ```bpf_probe_read_user(&path, sizeof(path), (void *)addr)```: Now the string ```addr``` points to into our ```path``` variable.
1. ```u = USDT(pid=int(pid))```: Initialize USDT tracing for the given PID.
1. ```u.enable_probe(probe="http__server__request", fn_name="do_trace")```: Attach our ```do_trace()``` BPF C function to the Node.js ```http__server__request``` USDT probe.
1. ```b = BPF(text=bpf_text, usdt_contexts=[u])```: Need to pass in our USDT object, ```u```, to BPF object creation.

### Lesson 16. task_switch.c

This is an older tutorial included as a bonus lesson. Use this for recap and to reinforce what you've already learned.

This is a slightly more complex tracing example than Hello World. This program
will be invoked for every task change in the kernel, and record in a BPF map
the new and old pids.

The C program below introduces a new concept: the prev argument. This
argument is treated specially by the BCC frontend, such that accesses
to this variable are read from the saved context that is passed by the
kprobe infrastructure. The prototype of the args starting from
position 1 should match the prototype of the kernel function being
kprobed. If done so, the program will have seamless access to the
function parameters.

```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct key_t {
    u32 prev_pid;
    u32 curr_pid;
};

BPF_HASH(stats, struct key_t, u64, 1024);
int count_sched(struct pt_regs *ctx, struct task_struct *prev) {
    struct key_t key = {};
    u64 zero = 0, *val;

    key.curr_pid = bpf_get_current_pid_tgid();
    key.prev_pid = prev->pid;

    // could also use `stats.increment(key);`
    val = stats.lookup_or_try_init(&key, &zero);
    if (val) {
      (*val)++;
    }
    return 0;
}
```

The userspace component loads the file shown above, and attaches it to the
`finish_task_switch` kernel function.
The `[]` operator of the BPF object gives access to each BPF_HASH in the
program, allowing pass-through access to the values residing in the kernel. Use
the object as you would any other python dict object: read, update, and deletes
are all allowed.
```python
from bcc import BPF
from time import sleep

b = BPF(src_file="task_switch.c")
b.attach_kprobe(event="finish_task_switch", fn_name="count_sched")

# generate many schedule events
for i in range(0, 100): sleep(0.01)

for k, v in b["stats"].items():
    print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))
```

These programs can be found in the files [examples/tracing/task_switch.c](../examples/tracing/task_switch.c) and [examples/tracing/task_switch.py](../examples/tracing/task_switch.py) respectively.

### Lesson 17. Further Study

For further study, see Sasha Goldshtein's [linux-tracing-workshop](https://github.com/goldshtn/linux-tracing-workshop), which contains additional labs. There are also many tools in bcc /tools to study.

Please read [CONTRIBUTING-SCRIPTS.md](../CONTRIBUTING-SCRIPTS.md) if you wish to contribute tools to bcc. At the bottom of the main [README.md](../README.md), you'll also find methods for contacting us. Good luck, and happy tracing!

## Networking

To do.