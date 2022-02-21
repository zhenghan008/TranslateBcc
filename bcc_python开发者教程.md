# bcc Python 开发者教程

这个教程是关于使用Python接口开发 [bcc](https://github.com/iovisor/bcc) 工具集和程序。有两个部分：可观察性追踪与网络追踪。代码片段都是来自bcc里的各种程序：查看它们的文件以获取许可证。

也可以查看bcc开发者的参考指南 [reference_guide.md](reference_guide.md)和面向最终用户的工具教程 [tutorial.md](tutorial.md)。bcc也有lua接口。

## 可观察性追踪

这个可观察性追踪教程包含17个课程和46个列举出来的知识点。


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

这里有6个知识点：

1. ```text='...'```: 这是定义BPF内联程序的地方。这个程序是由C语言编写的。

2. ```kprobe__sys_clone()```: 这是一个通过kprobes探针进行内核动态跟踪的捷径。如果C函数是以``kprobe__``开头，则其余部分被命名为要检测的内核函数，在这个例子中是```sys_clone()```。

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

这与hello_world.py类似，并且再次通过sys_clone()追踪新的进程，但是有几个知识点：

1. ```prog =```: 这次我们把C程序声明为变量，并且在稍后引用它。如果你想根据命令行参数添加一些字符串替换这会很有用。

1. ```hello()```: 现在我们只是声明了一个C函数，用来代替那个```kprobe__```捷径。我们稍后会引用它。所有在BPF程序中声明的C函数都应该工作在探针上，因此它们都需要把```pt_reg* ctx```作为第一个参数。如果你需要定义一些不在探针上工作的帮助函数，它们需要被定义为```static inline```以便编译器内联。有时候你也需要为它添加```_always_inline```函数属性。

1. ```b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")```: 为内核克隆系统调用函数创建一个kprobe探针，这个探针将会执行我们定义的hello()函数。你可以不止一次调用attach_kprobe()，并且将你的C函数附加到多个内核函数。

1. ```b.trace_fields()```: 从trace_pipe返回一组固定的字段。类似于trace_print()，这有利于黑客攻击，因此在实际的工具中我们应该切换成BPF_PERF_OUTPUT()。


### 课程 4. sync_timing.py

还记得系统管理员在```reboot```前在一个慢速的控制台上连续键入3次```sync```的日子，以给第一个异步同步时间来完成吗？然后有些人认为```sync;sync;sync```是聪明的，把它们绑在一起去运行，尽管这不符合最初的目的，但已成为行业惯例！然后sync又变成同步的，所以更多的理由是这是愚蠢的。Anyway。

下面的例子计算```do_sync```函数调用的速度，并打印输出如果它在一秒前被调用过。```sync;sync;sync```将打印第二和第三个sync的输出：


```
# ./examples/tracing/sync_timing.py
Tracing for quick sync's... Ctrl-C to end
At time 0.00 s: multiple syncs detected, last 95 ms ago
At time 0.10 s: multiple syncs detected, last 96 ms ago
```

代码在 [examples/tracing/sync_timing.py](../examples/tracing/sync_timing.py):

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

知识点:

1. ```bpf_ktime_get_ns()```: 返回以纳秒为单位的时间。

2. ```BPF_HASH(last)```: 创建一个哈希表（关联数组）的BPF映射对象，叫做"last"。我们没有进一步指定任何其它的参数，所以它默认是u64类型的键值对。

3. ```key = 0```: 我们只是在这个哈希表存储一对键值对，其中键被固定为0。

4. ```last.lookup(&key)```: 在哈希表中查找key，并且返回一个指向key的值的指针如果key的值是存在的，如果不存在就返回NULL。我们把key的地址传递给指针。

5. ```if (tsp != NULL) {```: 验证器要求必须检查从映射查找派生的指针值是否为空值，然后才能取消引用和使用它们。

6. ```last.delete(&key)```: 从哈希表删除key。这是当前必须的由于 [a kernel bug in `.update()`](https://git.kernel.org/cgit/linux/kernel/git/davem/net.git/commit/?id=a6ed3ea65d9868fdf9eff84e6fe4f666b8d14b02) (在4.8.10修复。)。

7. ```last.update(&key, &ts)```:  将第二个参数中的值与key关联起来，覆盖之前的值。这个有记录时间戳。


### 课程 5. sync_count.py

修改sync_timing.py（前一课）的程序以存储所有内核同步系统调用（快的和慢的）的计数，并且把输出都打印出来。这个计数可以通过在现有的哈希表中添加新的键索引来记录到BPF程序中。


### 课程 6. disksnoop.py

浏览 [examples/tracing/disksnoop.py](../examples/tracing/disksnoop.py) 程序以看看有什么新的变化。 这是一些样本输出:

```
# ./disksnoop.py
TIME(s)            T  BYTES    LAT(ms)
16458043.436012    W  4096        3.13
16458043.437326    W  4096        4.44
16458044.126545    R  4096       42.82
16458044.129872    R  4096        3.24
[...]
```

代码片段:

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

知识点:

1. ```REQ_WRITE```: 我们要在Python程序中定义一个内核常量因为稍后要使用它。如果我们已经在BPF程序中使用REQ_WRITE，那它应该在适当的#includes下工作（无需定义）。
1. ```trace_start(struct pt_regs *ctx, struct request *req)```: 这个函数稍后会附加到kprobes探针。kprobe函数的参数是```struct pt_regs *ctx```，用于寄存器和BPF上下文，然后是函数的实际参数。我们将会把它附加于blk_start_request()，其中第一个参数是```struct request *```。
1. ```start.update(&req, &ts)```: 我们将会使用一个指向请求体的指针作为我们哈希表中的一个键。什么？这在追踪中很常见。指向结构体的指针可以作为很好的键，因为它们是唯一的：两个结构体不能拥有相同的指针地址。（只是要小心当它可以自由的获取和重复使用。）所以我们真正要做的是用自己的时间戳来标记描述磁盘I/O的请求体，以便我们对它计时。有两个常见的键用于存储时间戳：一个是指向结构体的指针一个是线程的ID（用于返回计时函数条目）。
1. ```req->__data_len```: 我们将会解引用```struct request```的成员。在内核源代码中看看它们的定义以了解其中的成员。bcc实际上把这些表达式重写为一系列```bpf_probe_read_kernel()```调用。有时候bcc无法处理复杂的解引用，需要直接调用```bpf_probe_read_kernel()```。

这是一个优雅有趣的程序，如果你明白所有的代码，你将会了解许多重要的基础知识。我们仍是使用bpf_trace_printk()来hack，所以让我们接下来修复它。

### 课程 7. hello_perf_output.py

让我们最终停止使用bpf_trace_printk()并且使用更加恰当的BPF_PERF_OUTPUT()接口。这也意味着我们将停止自由地获取trace_field()的成员如PID和时间戳，并且需要直接获取它们。当在另一个会话中运行命令时的输出示例：

```
# ./hello_perf_output.py
TIME(s)            COMM             PID    MESSAGE
0.000000000        bash             22986  Hello, perf_output!
0.021080275        systemd-udevd    484    Hello, perf_output!
0.021359520        systemd-udevd    484    Hello, perf_output!
0.021590610        systemd-udevd    484    Hello, perf_output!
[...]
```

代码在 [examples/tracing/hello_perf_output.py](../examples/tracing/hello_perf_output.py):

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

知识点:

1. ```struct data_t```: 这定义了一个C结构体用于从内核空间传递数据到用户空间。
1. ```BPF_PERF_OUTPUT(events)```: 这将我们的输出通道命名为"events"。
1. ```struct data_t data = {};```: 创建一个空的data_t结构体，然后我们将会填充它。
1. ```bpf_get_current_pid_tgid()```: 返回低32位的进程ID（PID的内核视图，其在用户空间中通常呈现为线程ID），并且线程组ID在高32位中（用户空间通常认为的PID）。通过直接将其设置为u32，我们丢弃了高32位。你应该提供PID或者TGID？对于多线程app来说，那个TGID是一样的，因此你需要PID来区分它们，如果那是你想要的。它对于最终用户来说也是一样的问题。
1. ```bpf_get_current_comm()```: 使用当前的进程名填充第一个参数地址。
1. ```events.perf_submit()```: 提交用户空间通过perf环形缓冲区读取的事件。
1. ```def print_event()```: 定义一个Python函数，这个函数将处理从```events```流中读取事件。
1. ```b["events"].event(data)```: 现在获取事件作为一个Python对象，从C声明中自动生成。
1. ```b["events"].open_perf_buffer(print_event)```: 把```print_event```Python函数与```events```流关联起来。
1. ```while 1: b.perf_buffer_poll()```: 阻塞等待事件。


### 课程 8. sync_perf_output.py

使用```BPF_PERF_OUTPUT```重写前一课的sync_timing.py。


### 课程 9. bitehist.py

下面的工具记录了磁盘I/O大小的直方图。示例输出：


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

代码在 [examples/tracing/bitehist.py](../examples/tracing/bitehist.py):

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

回顾早先的课程：

- ```kprobe__```: 这个前缀意味着剩余的部分是被视为使用kprobe探针检测的内核函数名称。
- ```struct pt_regs *ctx, struct request *req```: kprobe探针的参数。```ctx```是寄存器和BPF上下文，```req```是检测函数```blk_account_io_done()```的第一个参数。
- ```req->__data_len```: 解引用成员.

新的知识点:
1. ```BPF_HISTOGRAM(dist)```: 定义一个BPF映射对象，这个对象是一个直方图，命名为"dist"。
1. ```dist.increment()```: 默认情况下，将作为第一个参数提供的直方图存储桶索引递增一个。或者，自定义增量可以作为第二个参数传递。
1. ```bpf_log2l()```: 返回提供的值的log-2。这变成我们直方图的索引，以便我们构造一个power-of-2直方图。
1. ```b["dist"].print_log2_hist("kbytes")```: 打印出"dist"的power-of-2直方图，以"kbytes"为列标题。从内核空间传输到用户空间的唯一数据是桶计数，这很高效。


### 课程 10. disklatency.py

编写一个计时磁盘I/O的程序，并打印出其延迟的直方图。磁盘I/O的检测和计时代码可以在上一课的disksnoop.py程序中找到，直方图代码可以在上一课的bitehist.py程序中找到。


### 课程 11. vfsreadlat.py

此示例是把Python文件和C文件分割开来的。示例输出：

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
在 [examples/tracing/vfsreadlat.py](../examples/tracing/vfsreadlat.py)和[examples/tracing/vfsreadlat.c](../examples/tracing/vfsreadlat.c)中浏览代码。
 知识点:

1. ```b = BPF(src_file = "vfsreadlat.c")```: 从单独的源代码文件中读取BPF C 程序。
1. ```b.attach_kretprobe(event="vfs_read", fn_name="do_return")```: 把BPF C 函数```do_return()```附加到内核函数```vfs_read()```的返回中。这是一个kretprobe探针：从一个函数检测其返回，而不是它们的入口。
1. ```b["dist"].clear()```: 清除直方图。


### 课程 12. urandomread.py

追踪```dd if=/dev/urandom of=/dev/null bs=8k count=5```的运行：

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

哈！我意外地捕抓到了smtp。代码在 [examples/tracing/urandomread.py](../examples/tracing/urandomread.py):


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

知识点:

1. ```TRACEPOINT_PROBE(random, urandom_read)```: 检测内核追踪点```random:urandom_read```。这是一个稳定的API，因此建议尽可能使用它代替kprobes探针。你可以运行```perf list```以获取追踪点列表。Linux >= 4.7需要将BPF程序附加到追踪点。
1. ```args->got_bits```:  ```args```被自动填充为一个追踪点参数的结构体。上面那个注释是说你可以在哪里看到这个结构体。例如：

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

在这个例子中，我们是打印出```got_bits```成员。


### 课程 13. disksnoop.py fixed

使用```block:block_rq_issue``` 和 ```block:block_rq_complete``` 跟踪点改造上一课的disksnoop.py程序。

### 课程 14. strlen_count.py

这个程序检测一个用户级函数```strlen()``` 库函数，并且计算它的字符串参数的频率。示例输出：

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

这些是通过追踪此库函数时正在处理的各种字符串以及它们的频率计数。举例，```strlen()```在 "LC_ALL" 上被调用了12次。

代码在 [examples/tracing/strlen_count.py](../examples/tracing/strlen_count.py):

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

知识点:

1. ```PT_REGS_PARM1(ctx)```: 这会获取```strlen()```的第一个参数，它是字符串。
1. ```b.attach_uprobe(name="c", sym="strlen", fn_name="count")```: 附加到"c"库中（如果这是主程序，使用它的路径名），检测用户级别的函数```strlen()```，并且在执行时调用我们的C函数```count()```。


### 课程 15. nodejs_http_server.py

这个程序检测一个用户静态定义的追踪(USDT)探针，它是内核追踪点的用户级版本。示例输出：

```
# ./nodejs_http_server.py 24728
TIME(s)            COMM             PID    ARGS
24653324.561322998 node             24728  path:/index.html
24653335.343401998 node             24728  path:/images/welcome.png
24653340.510164998 node             24728  path:/images/favicon.png
```

相关代码在 [examples/tracing/nodejs_http_server.py](../examples/tracing/nodejs_http_server.py):

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

知识点:

1. ```bpf_usdt_readarg(6, ctx, &addr)```: 将USDT探针参数6的地址读入到```addr```中。
1. ```bpf_probe_read_user(&path, sizeof(path), (void *)addr)```: 现在将字符串```addr```指向我们的```path```变量。
1. ```u = USDT(pid=int(pid))```: 为给定的PID初始化USDT追踪。
1. ```u.enable_probe(probe="http__server__request", fn_name="do_trace")```: 将我们的```do_trace()```BPF C 函数附加到Node.js ```http__server__request``` USDT 探针中。
1. ```b = BPF(text=bpf_text, usdt_contexts=[u])```: 需要传入我们的USDT对象```u```来创建BPF对象。


### 课程 16. task_switch.c

这是作为一个奖励的课程包含了一个较旧的教程。使用这个课程去回顾和加强你已经学到的。

这是一个比Hello World稍微复杂一点的追踪例子。这个程序在每个内核任务改变时将被调用，并且把新旧pids记录到BPF映射中。

下面的C程序引入了一个新概念：prev参数。这是通过BCC前端特殊处理过的参数，以便从 kprobe 基础结构传递的已保存上下文中读取对该变量的访问。从位置 1 开始的 args 原型应该与被 kprobed 的内核函数的原型相匹配。如果已经这样做，程序将会无缝访问函数参数。

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

用户空间组件加载上面显示的文件，并将它附加到`finish_task_switch`内核函数中。
BPF对象的`[]`操作符允许访问程序中每个BPF_HASH，允许通过访问驻留在内核中的值。 像你使用其它任何python dict对象一样使用它：read, update, 和 deletes都是被允许的。

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

这些程序可以分别在[examples/tracing/task_switch.c](../examples/tracing/task_switch.c) 和 [examples/tracing/task_switch.py](../examples/tracing/task_switch.py) 中找到。


### 课程 17. 更进一步的研究

对于更进一步的研究，可以看看Sasha Goldshtein的 [linux-tracing-workshop](https://github.com/goldshtn/linux-tracing-workshop)，其中包含了额外的试验。在bcc的 /tools里面的很多工具也可以用于学习。

请阅读[CONTRIBUTING-SCRIPTS.md](../CONTRIBUTING-SCRIPTS.md)如果你希望为bcc贡献工具集。在主[README.md](../README.md)底部，你还可以找到联系我们的方法。祝你好运，tracing愉快！

## 网络追踪

待续.