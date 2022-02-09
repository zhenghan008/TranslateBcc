# bcc 教程

此教程涵盖了如何快速使用[bcc](https://github.com/iovisor/bcc) 工具集解决性能，故障排除和网络问题。 如果你想开发新的bcc工具, 可以查看 [tutorial_bcc_python_developer.md](tutorial_bcc_python_developer.md) 这个教程.

此教程假定你已经安装好bcc, 并且已成功运行如execsnoop这样的工具。 可以查看 [INSTALL.md](../INSTALL.md)。 这使用添加到Linux 4.x系列版本的增强功能.

### 0. 使用bcc之前

在使用bcc之前， 你应该从linux基础开始。一个参考是[Linux Performance Analysis in 60,000 Milliseconds](https://netflixtechblog.com/linux-performance-analysis-in-60-000-milliseconds-accc10403c55)， 涵盖了以下这些命令:

1. uptime
1. dmesg | tail
1. vmstat 1
1. mpstat -P ALL 1
1. pidstat 1
1. iostat -xz 1
1. free -m
1. sar -n DEV 1
1. sar -n TCP,ETCP 1
1. top

### 1. 通用性能检查

这是使用bcc进行性能检查的通用命令清单， 先列出来， 然后再来详述:

1. execsnoop
1. opensnoop
1. ext4slower (or btrfs\*, xfs\*, zfs\*)
1. biolatency
1. biosnoop
1. cachestat
1. tcpconnect
1. tcpaccept
1. tcpretrans
1. runqlat
1. profile

这些命令可能安装在你的系统 /usr/share/bcc/tools 路径下，或者你可以在具有 .py 扩展名的工具集下从 bcc github 存储库运行它们。浏览 50 多种可用工具以获取更多分析选项。

#### 1.1 execsnoop

```
# ./execsnoop
PCOMM            PID    RET ARGS
supervise        9660     0 ./run
supervise        9661     0 ./run
mkdir            9662     0 /bin/mkdir -p ./main
run              9663     0 ./run
[...]
```

execsnoop 为每个新进程打印一行输出。 检查 short-lived 进程。 这些进程可能会消耗cpu资源， 但不会出现在大多数定期拍摄正在运行的进程快照的监控工具中。

它通过跟踪 exec() 而不是 fork() 工作，因此它会捕获许多类型的新进程，但不是全部（例如，它不会看到应用程序启动的工作进程，不会 exec() 其他任何东西）。

更多例子请看 [examples](../tools/execsnoop_example.txt).

#### 1.2. opensnoop

```
# ./opensnoop
PID    COMM               FD ERR PATH
1565   redis-server        5   0 /proc/1565/stat
1565   redis-server        5   0 /proc/1565/stat
1565   redis-server        5   0 /proc/1565/stat
1603   snmpd               9   0 /proc/net/dev
1603   snmpd              11   0 /proc/net/if_inet6
1603   snmpd              -1   2 /sys/class/net/eth0/device/vendor
1603   snmpd              11   0 /proc/sys/net/ipv4/neigh/eth0/retrans_time_ms
1603   snmpd              11   0 /proc/sys/net/ipv6/neigh/eth0/retrans_time_ms
1603   snmpd              11   0 /proc/sys/net/ipv6/conf/eth0/forwarding
[...]
```

opensnoop 为每一个open()的系统调用打印一行输出， 包括详情。

打开的文件可以告诉你很多关于应用程序如何工作的信息: 定位出它们的数据文件，配置文件和日志文件。 有时候应用程序可能出现行为异常， 并且性能不佳， 当它们不断的尝试读取不存在的文件时， opensnoop 可以给你一个快速的浏览。

更多例子请看 [examples](../tools/opensnoop_example.txt).

#### 1.3. ext4slower (or btrfs\*, xfs\*, zfs\*)

```
# ./ext4slower
Tracing ext4 operations slower than 10 ms
TIME     COMM           PID    T BYTES   OFF_KB   LAT(ms) FILENAME
06:35:01 cron           16464  R 1249    0          16.05 common-auth
06:35:01 cron           16463  R 1249    0          16.04 common-auth
06:35:01 cron           16465  R 1249    0          16.03 common-auth
06:35:01 cron           16465  R 4096    0          10.62 login.defs
06:35:01 cron           16464  R 4096    0          10.61 login.defs
```

ext4slower 跟踪ext4文件系统并计时常用的操作， 并且只打印那些超过阈值的操作。


这对于定位或者排除一种性能问题非常有用: 通过文件系统逐个展示慢速磁盘i/O。很难将异步磁盘I/O的延迟与应用程序层面的延迟关联起来。在内核堆栈中向上跟踪，在文件系统接口处（VFS）跟踪，将更能接近匹配应用程序所遇到的问题。如果文件系统延迟超过给定的阈值那就用这个工具去定位吧。

对于其它的文件系统在bcc中有相似的工具集：btrfsslower, xfsslower, 和 zfsslower。还有fileslower，它工作在VFS层并且追踪所有内容（虽然有更高的开销）。


更多例子请看 [examples](../tools/ext4slower_example.txt).

#### 1.4. biolatency

```
# ./biolatency
Tracing block device I/O... Hit Ctrl-C to end.
^C
     usecs           : count     distribution
       0 -> 1        : 0        |                                      |
       2 -> 3        : 0        |                                      |
       4 -> 7        : 0        |                                      |
       8 -> 15       : 0        |                                      |
      16 -> 31       : 0        |                                      |
      32 -> 63       : 0        |                                      |
      64 -> 127      : 1        |                                      |
     128 -> 255      : 12       |********                              |
     256 -> 511      : 15       |**********                            |
     512 -> 1023     : 43       |*******************************       |
    1024 -> 2047     : 52       |**************************************|
    2048 -> 4095     : 47       |**********************************    |
    4096 -> 8191     : 52       |**************************************|
    8192 -> 16383    : 36       |**************************            |
   16384 -> 32767    : 15       |**********                            |
   32768 -> 65535    : 2        |*                                     |
   65536 -> 131071   : 2        |*                                     |
```

biolatency 跟踪磁盘I/O延迟（从设备发出到完成的时间），并且当工具执行完成时（Ctrl-C，或者给定的时间间隔），它会打印延迟的直方图摘要。

这对于了解磁盘I/O延迟是非常有用的，超过了像iostat等工具给出的平均时间。IO延迟异常值将在分布以及多模式分布结束时可见。

更多例子请看 [examples](../tools/biolatency_example.txt).

#### 1.5. biosnoop

```
# ./biosnoop
TIME(s)        COMM           PID    DISK    T  SECTOR    BYTES   LAT(ms)
0.000004001    supervise      1950   xvda1   W  13092560  4096       0.74
0.000178002    supervise      1950   xvda1   W  13092432  4096       0.61
0.001469001    supervise      1956   xvda1   W  13092440  4096       1.24
0.001588002    supervise      1956   xvda1   W  13115128  4096       1.09
1.022346001    supervise      1950   xvda1   W  13115272  4096       0.98
1.022568002    supervise      1950   xvda1   W  13188496  4096       0.93
[...]
```

biosnoop 为每一个磁盘I/O打印一行输出，详情包括延迟（从设备发出到完成的时间）。

这个工具允许你详细检查磁盘I/O，并且可以据此发现按时间排序的模式（例如，读取是在写入后面）。注意如果你的系统正在高速运行磁盘I/O那输出将会变得冗长。

更多例子请看 [examples](../tools/biosnoop_example.txt).

#### 1.6. cachestat

```
# ./cachestat
    HITS   MISSES  DIRTIES  READ_HIT% WRITE_HIT%   BUFFERS_MB  CACHED_MB
    1074       44       13      94.9%       2.9%            1        223
    2195      170        8      92.5%       6.8%            1        143
     182       53       56      53.6%       1.3%            1        143
   62480    40960    20480      40.6%      19.8%            1        223
       7        2        5      22.2%      22.2%            1        223
     348        0        0     100.0%       0.0%            1        223
[...]
```
cachestat 每秒打印一行输出摘要（或者每个自定义时间间隔），显示来自文件系统缓存的统计信息。

使用这个工具来识别低缓存命中率和高未命中率：这为性能调优提供了一条线索。


更多例子请看 [examples](../tools/cachestat_example.txt).

#### 1.7. tcpconnect

```
# ./tcpconnect
PID    COMM         IP SADDR            DADDR            DPORT
1479   telnet       4  127.0.0.1        127.0.0.1        23
1469   curl         4  10.201.219.236   54.245.105.25    80
1469   curl         4  10.201.219.236   54.67.101.145    80
1991   telnet       6  ::1              ::1              23
2015   ssh          6  fe80::2000:bff:fe82:3ac fe80::2000:bff:fe82:3ac 22
[...]
```
tcpconnect 为每个活跃的TCP连接（例如， 通过connect()调用）打印一行输出，详情包括源地址和目标地址。

可以据此发现那些可能指向应用程序配置效率低下或入侵者的异常连接。

更多例子请看 [examples](../tools/tcpconnect_example.txt).

#### 1.8. tcpaccept

```
# ./tcpaccept
PID    COMM         IP RADDR            LADDR            LPORT
907    sshd         4  192.168.56.1     192.168.56.102   22
907    sshd         4  127.0.0.1        127.0.0.1        22
5389   perl         6  1234:ab12:2040:5020:2299:0:5:0 1234:ab12:2040:5020:2299:0:5:0 7001
[...]
```
tcpaccept 为每个被动的TCP连接（例如， 通过accept()调用）打印一行输出，详情包括源地址和目标地址。

可以据此发现那些可能指向应用程序配置效率低下或入侵者的异常连接。

更多例子请看 [examples](../tools/tcpaccept_example.txt).

#### 1.9. tcpretrans

```
# ./tcpretrans
TIME     PID    IP LADDR:LPORT          T> RADDR:RPORT          STATE
01:55:05 0      4  10.153.223.157:22    R> 69.53.245.40:34619   ESTABLISHED
01:55:05 0      4  10.153.223.157:22    R> 69.53.245.40:34619   ESTABLISHED
01:55:17 0      4  10.153.223.157:22    R> 69.53.245.40:22957   ESTABLISHED
[...]
```

tcprerans 为每个 TCP 重传数据包打印一行输出，详情包括源地址和目标地址，并且包括该TCP连接的内核状态。

TCP的重传会导致网络延迟和吞吐量的问题。对于ESTABLISHED的重传，可以据此发现网络模式。对于SYN_SENT的重传，这可能指向目标内核CPU的饱和度和发现内核数据包丢失的情况。


更多例子请看 [examples](../tools/tcpretrans_example.txt).

#### 1.10. runqlat

```
# ./runqlat
Tracing run queue latency... Hit Ctrl-C to end.
^C
     usecs               : count     distribution
         0 -> 1          : 233      |***********                             |
         2 -> 3          : 742      |************************************    |
         4 -> 7          : 203      |**********                              |
         8 -> 15         : 173      |********                                |
        16 -> 31         : 24       |*                                       |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 30       |*                                       |
       128 -> 255        : 6        |                                        |
       256 -> 511        : 3        |                                        |
       512 -> 1023       : 5        |                                        |
      1024 -> 2047       : 27       |*                                       |
      2048 -> 4095       : 30       |*                                       |
      4096 -> 8191       : 20       |                                        |
      8192 -> 16383      : 29       |*                                       |
     16384 -> 32767      : 809      |****************************************|
     32768 -> 65535      : 64       |***                                     |
```
runqlat 计时线程在CPU运行队列中等待多长时间，并将其打印为直方图。

这可以帮助量化在CPU饱和期等待开启CPU所损失的时间。


更多例子请看 [examples](../tools/runqlat_example.txt).

#### 1.11. profile

```
# ./profile
Sampling at 49 Hertz of all threads by user + kernel stack... Hit Ctrl-C to end.
^C
    00007f31d76c3251 [unknown]
    47a2c1e752bf47f7 [unknown]
    -                sign-file (8877)
        1

    ffffffff813d0af8 __clear_user
    ffffffff813d5277 iov_iter_zero
    ffffffff814ec5f2 read_iter_zero
    ffffffff8120be9d __vfs_read
    ffffffff8120c385 vfs_read
    ffffffff8120d786 sys_read
    ffffffff817cc076 entry_SYSCALL_64_fastpath
    00007fc5652ad9b0 read
    -                dd (25036)
        4

    0000000000400542 func_a
    0000000000400598 main
    00007f12a133e830 __libc_start_main
    083e258d4c544155 [unknown]
    -                func_ab (13549)
        5

[...]

    ffffffff8105eb66 native_safe_halt
    ffffffff8103659e default_idle
    ffffffff81036d1f arch_cpu_idle
    ffffffff810bba5a default_idle_call
    ffffffff810bbd07 cpu_startup_entry
    ffffffff8104df55 start_secondary
    -                swapper/1 (0)
        75
```
profile是一个CPU分析器，它以定时间隔对堆栈跟踪进行采样，并打印唯一堆栈跟踪的摘要及其发生的次数。

使用这个工具可以了解那些消耗CPU资源的代码路径。

更多例子请看 [examples](../tools/profile_example.txt).

### 2. 通用工具的可见性

除了以上工具用于性能调优之外，下面是一个bcc通用工具的清单，先列出来，再来详述：
1. trace
1. argdist
1. funccount

这些通用工具可能有助于提供可见性以解决你特定的问题。

#### 2.1. trace

##### Example 1

假设你想跟踪文件所有权的更改。有3个系统调用工具可用，`chown`, `fchown` 和 `lchown`这3个工具可以让用户用于更改文件的所有权。这些相应的系统调用入口是`SyS_[f|l]chown`。以下的命令可用于打印出系统调用的参数和正在调用的进程用户id。你可以使用 `id` 命令查找特定用户的 uid。

```
$ trace.py \
  'p::SyS_chown "file = %s, to_uid = %d, to_gid = %d, from_uid = %d", arg1, arg2, arg3, $uid' \
  'p::SyS_fchown "fd = %d, to_uid = %d, to_gid = %d, from_uid = %d", arg1, arg2, arg3, $uid' \
  'p::SyS_lchown "file = %s, to_uid = %d, to_gid = %d, from_uid = %d", arg1, arg2, arg3, $uid'
PID    TID    COMM         FUNC             -
1269255 1269255 python3.6    SyS_lchown       file = /tmp/dotsync-usisgezu/tmp, to_uid = 128203, to_gid = 100, from_uid = 128203
1269441 1269441 zstd         SyS_chown        file = /tmp/dotsync-vic7ygj0/dotsync-package.zst, to_uid = 128203, to_gid = 100, from_uid = 128203
1269255 1269255 python3.6    SyS_lchown       file = /tmp/dotsync-a40zd7ev/tmp, to_uid = 128203, to_gid = 100, from_uid = 128203
1269442 1269442 zstd         SyS_chown        file = /tmp/dotsync-gzp413o_/dotsync-package.zst, to_uid = 128203, to_gid = 100, from_uid = 128203
1269255 1269255 python3.6    SyS_lchown       file = /tmp/dotsync-whx4fivm/tmp/.bash_profile, to_uid = 128203, to_gid = 100, from_uid = 128203
```

##### Example 2

假设你想要基于bpf性能监控工具去计算非自愿上下文切换(`nvcsw`)而又不知道适当的方法是什么。`/proc/<pid>/status`已经告诉你pid的编号(`nonvoluntary_ctxt_switches`)并且你可以使用`trace.py` 做一个快速的实验来验证你的方法。对于内核源代码，`nvcsw`在`linux/kernel/sched/core.c`文件中的`__schedule`函数和在```!(!preempt && prev->state) // i.e., preempt || !prev->state```条件下计算。`__schedule`函数被标记为 `notrace`，并且评估上述条件的最佳位置似乎是在函数`__schedule`的内部调用并在`linux/include/trace/events/sched.h`中定义的`sched/sched_switch`跟踪点。`trace.py`已经有`args`作为一个指向跟踪点`TP_STRUCT__entry`的指针。函数`__schedule`中的上述条件可以表示为```args->prev_state == TASK_STATE_MAX || args->prev_state == 0```。下面的命令可以用于计算非自愿上下文切换（每个进程或者每个pid）并且比较`/proc/<pid>/status` 或者 `/proc/<pid>/task/<task_id>/status`的正确性，在通常情况下，非自愿上下文切换并不常见。

```
$ trace.py -p 1134138 't:sched:sched_switch (args->prev_state == TASK_STATE_MAX || args->prev_state == 0)'
PID    TID    COMM         FUNC
1134138 1134140 contention_test sched_switch
1134138 1134142 contention_test sched_switch
...
$ trace.py -L 1134140 't:sched:sched_switch (args->prev_state == TASK_STATE_MAX || args->prev_state == 0)'
PID    TID    COMM         FUNC
1134138 1134140 contention_test sched_switch
1134138 1134140 contention_test sched_switch
...
```

##### Example 3

此示例与 uprobe 的问题 [1231](https://github.com/iovisor/bcc/issues/1231) 和 [1516](https://github.com/iovisor/bcc/issues/1516) 相关在某些情况下根本不起作用。首先，你可以做一个 `strace` 如下

```
$ strace trace.py 'r:bash:readline "%s", retval'
...
perf_event_open(0x7ffd968212f0, -1, 0, -1, 0x8 /* PERF_FLAG_??? */) = -1 EIO (Input/output error)
...
```

`perf_event_open`系统调用返回`-EIO`。在 `/kernel/trace` 和 `/kernel/events`中挖掘内核 uprobe 相关代码以搜索 `EIO`，函数`uprobe_register`是最可疑的。让我们看看这个函数是否被调用并且如果被调用返回值是什么。在一个终端使用以下命令打印出uprobe_register的返回值，```$ trace.py 'r::uprobe_register "ret = %d", retval'```。在另一个终端运行相同的 bash uretprobe 跟踪示例，你应该得到
```
$ trace.py 'r::uprobe_register "ret = %d", retval'
PID    TID    COMM         FUNC             -
1041401 1041401 python2.7    uprobe_register  ret = -5
```

那个`-5`的错误代码是EIO。这证实了函数 `uprobe_register` 中的以下代码是最可疑的罪魁祸首
```
 if (!inode->i_mapping->a_ops->readpage && !shmem_mapping(inode->i_mapping))
        return -EIO;
```
函数`shmem_mapping`定义为
```
bool shmem_mapping(struct address_space *mapping)
{
        return mapping->a_ops == &shmem_aops;
}
```
为了确认这个理论，用下面的命令来查找`inode->i_mapping->a_ops`是什么
```
$ trace.py -I 'linux/fs.h' 'p::uprobe_register(struct inode *inode) "a_ops = %llx", inode->i_mapping->a_ops'
PID    TID    COMM         FUNC             -
814288 814288 python2.7    uprobe_register  a_ops = ffffffff81a2adc0
^C$ grep ffffffff81a2adc0 /proc/kallsyms
ffffffff81a2adc0 R empty_aops
```

内核符号`empty_aops`没有定义`readpage`因此上述可疑情况为真。进一步检查内核源代码表明，`overlayfs` 不提供自己的`a_ops`，而其他一些文件系统（例如，ext4）定义了自己的`a_ops`（例如，`ext4_da_aops`），而`ext4_da_aops`定义了`readpage `。因此，uprobe在ext4文件系统上可以工作而不能在overlayfs上工作。

更多例子请看 [examples](../tools/trace_example.txt). 

#### 2.2. argdist

更多例子请看 [examples](../tools/argdist_example.txt).

#### 2.3. funccount

更多例子请看 [examples](../tools/funccount_example.txt).

## Networking

To do.