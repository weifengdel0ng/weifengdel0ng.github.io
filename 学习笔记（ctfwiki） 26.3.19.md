# ptmalloc2
## 序言
`Linux 中早期的堆分配与回收由 Doug Lea 实现，但它在并行处理多个线程时，会共享进程的堆内存空间。因此，为了安全性，一个线程使用堆时，会进行加锁。然而，与此同时，加锁会导致其它线程无法使用堆，降低了内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能影响内存分配和回收的正确性。Wolfram Gloger 在 Doug Lea 的基础上进行改进使其可以支持多线程，这个堆分配器就是 ptmalloc 。在 glibc-2.3.x. 之后，glibc 中集成了 ptmalloc2。`

`目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通过 malloc/free 函数来分配和释放内存块。`

`需要注意的是，在内存分配与使用的过程中，Linux 有这样的一个基本内存管理思想，**只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系**。 所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页面给用户使用。`
## 一、malloc：
/* 官方 
	malloc(size_t n)  
	返回一个指向新分配的、至少包含 n 字节内存块的指针；如果无法分配空间，则返回空指针（NULL）。此外，在 ANSI C 系统上，失败时会将 errno 设置为 ENOMEM。
	如果 n 为零，malloc 会返回一个最小尺寸的内存块（在大多数 32 位系统上，最小尺寸为 16 字节；在 64 位系统上通常为 24 或 32 字节）。
	在大多数系统中，size_t 是无符号类型，因此传入负数参数会被解释为请求极大数量的内存空间，这类请求通常会失败。
	n 的最大支持值因系统而异，但在所有情况下都小于 size_t 类型所能表示的最大值。  
### （一）是什么：C 标准库中最基础的内存分配接口
其内部机制常被视为`黑盒`，实现由 `brk` 与 `mmap`分工。
现代 libc（如 glibc）采用 ptmalloc2 作为默认分配器
![[pwn/笔记/附件/Pasted image 20260316111655.png]]
阈值可以调节：
```c
mallopt(M_MMAP_THRESHOLD, 256 * 1024);
```
### （二）运作机制：
#### （1）brk/sbrk
进程启动时，内核在数据段（.bss）之后预留一小段连续内存作为初始堆。brk 系统调用通过移动 program break 指针扩展堆顶：
```c
// 简化版 brk 工作流程
void *current_brk = sbrk(0);          // 获取当前堆顶
void *new_brk = sbrk(4096);           // 向上扩展 4KB
// 内核将 [current_brk, new_brk) 映射为可读写匿名页
```
##### 1.malloc 的堆管理
	ptmalloc2 在 brk 提供的连续空间上构建空闲链表（free list）：
	将大块堆内存切分为不同大小的“bins”（如 fastbins、smallbins）
	分配时从合适 bin 中取出 chunk；释放时将 chunk 归还至 bin
	仅当堆顶存在连续空闲区域且超过阈值时，才调用 brk 向下收缩堆
	关键点：free() 通常不立即归还内存给内核，而是保留在分配器的空闲池中。这是用户态内存管理与内核内存管理的分界。
在brk中free()仅将内存标记为空闲，仍占据虚拟地址空间。
#### (2)mmap :匿名映射与独立内存区域
mmap并非堆的一部分，和堆不连续
##### 1.创建：
```c
void *ptr = mmap(NULL, size, 
                 PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
```
`MAP_ANONYMOUS：不关联文件，内容初始化为零. MAP_PRIVATE：写时复制（COW）,修改不影响其他进程返回的地址独立于堆，形成新的 VMA`
##### 2.释放：
```c
free(ptr);// 若为 mmap 分配，内部直接调用 munmap()
```
在mmap中，调用free()会直接再调用munmap().
`munmap() 会：  从进程页表中移除该 VMA 的映射  释放对应的物理页（若为私有匿名页）  地址空间立即回收，无残留  这与 brk 分配的内存形成鲜明对比：后者释放后仍占据虚拟地址空间，仅标记为空闲。`
[[pwn/笔记/堆/笔记附件/malloc释放机制|malloc释放机制]]
####  （3）进程虚拟地址空间布局
```c
高位地址 (0x7fffffffffff)
+------------------------+
|      栈 (Stack)        | ← 向下增长，主线程栈约 8MB
|      [vvar]            |   内核变量只读映射
|      [vdso]            |   虚拟动态共享对象
+------------------------+
|   内存映射区 (mmap)    | ← 新映射通常从此向下分配
|   • 匿名 mmap          |
|   • 共享库 (.so)       |
|   • 线程栈             |
+------------------------+
|      （空洞）          |   隔离堆与映射区，缓解碎片
+------------------------+
|      堆 (Heap)         | ← 向上增长，由 brk 管理
+------------------------+
|   BSS / Data 段        |
|   代码段 (.text)       |
+------------------------+
低位地址 (0x0000000000400000)
```

#### （4） /proc/pid/maps：内存布局的实时快照
	该文件以文本形式暴露进程的完整 VMA 列表，是分析内存行为的基石。

![[pwn/笔记/附件/Pasted image 20260316192047.png]]

#### （5） /proc/pid/mem：进程内存的原始接口
`该文件允许按虚拟地址直接读写目标进程的内存，是调试器与内存工具的底层基石。`
```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
void read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t len) {
    // 1. 附加进程
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    // 2. 打开 mem 文件
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    // 3. 按虚拟地址读取（必须用 pread）
    pread(fd, buf, len, addr);
    // 4. 清理
    close(fd);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
```






## 二、free：  
	free(void* p)  
	释放由指针 p 所指向的内存块，该内存块必须是之前通过 malloc 或相关函数（如 realloc）分配的。
	如果 p 为 NULL，free 不会产生任何效果。
	如果 p 指向的内存已经被释放过，则调用 free 可能导致未定义行为（即可能产生任意的、糟糕的后果！）。
	除非通过 mallopt 禁用了相关功能，否则在可能的情况下，释放非常大的内存块会自动触发将未使用的内存归还给操作系统的操作，从而减少程序的内存占用（footprint）。

## 三、堆基本操作：
### （一）内存分配背后的系统调用：
![[pwn/笔记/附件/Pasted image 20260318084236.png|841]]
![[pwn/笔记/附件/Pasted image 20260318084116.png|835]]
malloc和free不和系统直接交互，系统调用一般采用 `(s)brk`函数以及 `mmap, munmap`函数。
#### （1）brk/sbrk：
操作系统提供了 brk 函数，glibc 库提供了 sbrk 函数。
初始时，堆的起始地址 `start_brk` 以及堆的当前末尾 `brk`指向同一地址。
- 不开启 ASLR 保护时，start_brk 以及 brk 会指向 data/bss 段的结尾。
- 开启 ASLR 保护时，start_brk 以及 brk 也会指向同一位置，只是这个位置是在 data/bss 段结尾后的随机偏移处。
![[pwn/笔记/附件/Pasted image 20260318085150.png|922]]
sbrk（）的作用：[[pwn/笔记/堆/笔记附件/sbrk|sbrk]]
brk（）的作用：申请一个堆空间，在第一个brk运行之前，是不会出现堆空间的。[[pwn/笔记/堆/笔记附件/brk|brk]]


#### （2）mmap：[[pwn/笔记/堆/笔记附件/mmap|mmap]]
	malloc 会使用 [mmap](http://lxr.free-electrons.com/source/mm/mmap.c?v=3.8#L1285) 来创建独立的匿名映射段。匿名映射的目的主要是可以申请以 0 填充的内存，并且这块内存仅被调用进程所使用。
#### （3）多线程支持：
	在原来的 dlmalloc 实现中，当两个线程同时要申请内存时，只有一个线程可以进入临界区申请内存，而另外一个线程则必须等待直到临界区中不再有线程。这是因为所有的线程共享一个堆。在 glibc 的 ptmalloc 实现中，比较好的一点就是支持了多线程的快速访问。在新的实现中，所有的线程共享多个堆。
[[pwn/笔记/堆/笔记附件/pthread_create|pthread_create]]
```c
	pthread_create(&t1, NULL, threadFunc, NULL);
```

##### ctfwiki摘录：[[pwn/笔记/堆/笔记附件/摘录1|摘录1]]

## 四、堆相关数据结构
### 与堆相应的数据结构主要分为：
- 宏观结构，包含堆的宏观信息，可以通过这些数据结构索引堆的基本信息。
	**宏**是由 **预处理器（preprocessor）** 处理的一种文本替换机制。它不是变量，也不是函数，而是在编译前由 `#define` 指令定义的一段文本，在源代码中所有出现该宏的地方都会被替换成其定义的内容。
- 微观结构，用于具体处理堆的分配与回收中的内存块。
### （1） malloc_chunk：
由 malloc 申请的内存为 `chunk`
这块内存在 ptmalloc 内部用 malloc_chunk 结构体来表示。当程序申请的 `chunk` 被 free 后，会被加入到相应的空闲管理列表中。
**无论一个 `chunk` 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构**。虽然它们使用了同一个数据结构，但是根据是否被释放，它们的表现形式会有所不同。
```c#
/* This struct declaration is misleading (but accurate and necessary). 
  It declares a "view" into memory allowing access to necessary fields at known offsets from a given base. 
  See explanation below. */ 
  struct malloc_chunk { INTERNAL_SIZE_T prev_size; /* Size of previous chunk (if free). */ 
  INTERNAL_SIZE_T size; /* Size in bytes, including overhead. */ 
  struct malloc_chunk* fd; /* double links -- used only if free. */ 
  struct malloc_chunk* bk; /* Only used for large blocks: pointer to next larger size. */ 
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */ 
  struct malloc_chunk* bk_nextsize; 
  };
```
##### `chunk` 结构体参数：
下面我们来看 `chunk` 结构体，各个字段的具体的解释如下：

- **prev_size**, 如果该 `chunk` 的 **物理相邻的前一地址 chunk（两个指针的地址差值为前一 chunk 大小）** 是空闲的话，那该字段记录的是前一个 `chunk` 的大小 (包括 `chunk` 头)。否则，该字段可以用来存储物理相邻的前一个 chunk 的数据。**这里的前一 `chunk` 指的是较低地址的 `chunk`** 。
- **size** ，该 `chunk` 的大小，大小必须是 `MALLOC_ALIGNMENT` 的整数倍。如果申请的内存大小不是 `MALLOC_ALIGNMENT` 的整数倍，会被转换满足大小的最小的 `MALLOC_ALIGNMENT` 的倍数，这通过 `request2size()` 宏完成。32 位系统中， `MALLOC_ALIGNMENT` 可能是 `4` 或 `8` ；64 位系统中，`MALLOC_ALIGNMENT` 是 `8`。 该字段的低三个比特位对 `chunk` 的大小没有影响，它们从高到低分别表示
    - NON_MAIN_ARENA，记录当前 `chunk` 是否不属于主线程，1 表示不属于，0 表示属于。
    - IS_MAPPED，记录当前 `chunk` 是否是由 mmap 分配的。
    - PREV_INUSE，记录前一个 `chunk` 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的 P 位都会被设置为 1，以便于防止访问前面的非法内存。当一个 `chunk` 的 size 的 P 位为 0 时，我们能通过 `prev_size` 字段来获取上一个 `chunk` 的大小以及地址。这也方便进行空闲 `chunk` 之间的合并。
- **fd，bk**。 `chunk` 处于分配状态时，从 fd 字段开始是用户的数据。 `chunk` 空闲时，会被添加到对应的空闲管理链表中，其字段的含义如下
    - ==fd 指向下一个（非物理相邻）空闲的 `chunk` 。==
    - ==bk 指向上一个（非物理相邻）空闲的 `chunk` 。==
    - 通过 fd 和 bk 可以将空闲的 `chunk` 块加入到空闲的 `chunk` 块链表进行统一管理。
- **fd_nextsize， bk_nextsize**，也是只有 `chunk` 空闲的时候才使用，不过其用于较大的 chunk（large chunk）。
    - fd_nextsize 指向前一个与当前 `chunk` 大小不同的第一个空闲块，不包含 bin 的头指针。
    - bk_nextsize 指向后一个与当前 `chunk` 大小不同的第一个空闲块，不包含 bin 的头指针。
    - 一般空闲的 large `chunk` 在 fd 的遍历顺序中，按照由大到小的顺序排列。**这样做可以避免在寻找合适 chunk 时挨个遍历。**
##### chunk格式：
一个已经分配的 `chunk` 的样子如下。**我们称前两个字段称为 `chunk` header，后面的部分称为 user data。每次 malloc 申请得到的内存指针，其实指向 user data 的起始处。**
当一个 `chunk` 处于使用状态时，它的下一个 `chunk` 的 prev_size 域无效，所以下一个 `chunk` 的该部分也可以被当前 chunk 使用。**这就是 chunk 中的空间复用。**
```plantext
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- 
		| Size of previous chunk, if unallocated (P clear) | 
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		|          Size of chunk, in bytes           |A|M|P|
mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		|            User data starts here...              . 
		.                                                  .
		.       (malloc_usable_size() bytes)               .       
		.                  next                            | 
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		| (size of chunk, but used for application data)   | 
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
		|          Size of next chunk, in bytes      |A|0|1| 
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
```
被释放的 `chunk` 被记录在链表中（可能是循环双向链表，也可能是单向链表）。具体结构如下
![[pwn/笔记/附件/Pasted image 20260318191935.png]]
内存结构：
![[pwn/笔记/附件/Pasted image 20260318200752.png]]
最小的 `chunk` 至少要包含 bk 指针。
用户最小申请的内存大小必须是 2 * SIZE_SZ 的最小整数倍。
==chunk 相关宏==:[[pwn/笔记/堆/笔记附件/chunk 相关宏1|chunk 相关宏1]][[pwn/笔记/堆/笔记附件/chunk 相关宏2|chunk 相关宏2]]
### (2)bin:
ptmalloc会根据空闲的 `chunk` 的大小以及使用状态将 `chunk` 初步分为 4 类：fast bins，small bins，large bins，unsorted bin。
相似大小的 `chunk` 会用双向链表链接起来。
每类 bin 的内部仍然会有多个互不相关的链表来保存不同大小的 chunk。
#### small bins，large bins，unsorted bin
small bins，large bins，unsorted bin在同一个数组中。对应的数据结构在 malloc_state 中
```c#
#define NBINS 128 
/* Normal bins packed as described above */ 
mchunkptr bins[ NBINS * 2 - 2 ];
```
`bins` 主要用于索引不同 bin 的 fd 和 bk。
以 32 位系统为例，bins 前 4 项的含义如下：

| 含义     | bin1 的 fd/bin2 的 prev_size | bin1 的 bk/bin2 的 size | bin2 的 fd/bin3 的 prev_size | bin2 的 bk/bin3 的 size |
| ------ | -------------------------- | --------------------- | -------------------------- | --------------------- |
| bin 下标 | 0                          | 1                     | 2                          | 3                     |
数组中的 bin 依次如下

1. 第一个为 unsorted bin，字如其面，这里面的 `chunk` 没有进行排序，存储的 `chunk` 比较杂。
2. 索引从 2 到 63 的 bin 称为 small bin，同一个 small bin 链表中的 `chunk` 的大小相同。两个相邻索引的 small bin 链表中的 `chunk` 大小相差的字节数为 **2 个机器字长**，即 32 位相差 8 字节，64 位相差 16 字节。
3. small bins 后面的 bin 被称作 large bins。large bins 中的每一个 bin 都包含一定范围内的 chunk，其中的 chunk 按 fd 指针的顺序从大到小排列。相同大小的 chunk 同样按照最近使用顺序排列。

此外，上述这些 bin 的排布都会遵循一个原则：**任意两个物理相邻的空闲 chunk 不能在一起**。

需要注意的是，并不是所有的 `chunk` 被释放后就立即被放到 bin 中。ptmalloc 为了提高分配的速度，会把一些小的 `chunk` **先**放到 ==fast bins== 的容器内。**而且，==fastbin ==容器中的 `chunk` 的使用标记总是被置位的，所以不满足上面的原则。**
bin 通用的宏如下

```c#
typedef struct malloc_chunk *mbinptr;
/* addressing -- note that bin_at(0) does not exist */ 
#define bin_at(m, i) 
	(mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) -                        \               
	offsetof(struct malloc_chunk, fd))                                         \
	/* analog of ++bin */ 
	//获取下一个bin的地址 
#define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))  
/* Reminders about list directionality within bins */ 
// 这两个宏可以用来遍历bin 
// 获取 bin 的位于链表头的 chunk 
#define first(b) ((b)->fd) 
// 获取 bin 的位于链表尾的 chunk 
#define last(b) ((b)->bk)
```
#### fast bin
大多数程序经常会申请以及释放一些比较小的内存块。如果将一些较小的 `chunk` 释放之后发现存在与之相邻的空闲的 `chunk` 并将它们进行合并，那么当下一次再次申请相应大小的 `chunk` 时，就需要对 `chunk` 进行分割，这样就大大降低了堆的利用效率。**因为我们把大部分时间花在了合并、分割以及中间检查的过程中。**因此，ptmalloc 中专门设计了 fast bin，对应的变量就是 malloc state 中的 fastbinsY
为了更加高效地利用 fast bin，glibc 采用单向链表对其中的每个 bin 进行组织，并且**每个 bin 采取 LIFO 策略**，最近释放的 `chunk` 会更早地被分配，所以会更加适合于局部性。也就是说，当用户需要的 `chunk` 的大小小于 fastbin 的最大大小时， ptmalloc 会首先判断 fastbin 中相应的 bin 中是否有对应大小的空闲块，如果有的话，就会直接从这个 bin 中获取 chunk。如果没有的话，ptmalloc 才会做接下来的一系列操作。
默认情况下（**32 位系统为例**）， fastbin 中默认支持最大的 `chunk` 的数据空间大小为 64 字节。但是其可以支持的 chunk 的数据空间最大为 80 字节。除此之外， fastbin 最多可以支持的 bin 的个数为 10 个，从数据空间为 8 字节开始一直到 80 字节（注意这里说的是数据空间大小，也即除去 prev_size 和 size 字段部分的大小）
ptmalloc 默认情况下会调用 set_max_fast(s) 将全局变量 global_max_fast 设置为 DEFAULT_MXFAST，也就是设置 fast bins 中 `chunk` 的最大值。当 MAX_FAST_SIZE 被设置为 0 时，系统就不会支持 fastbin 。
**fastbin 的索引**：
```c#
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[ idx ]) 
/* offset 2 to use otherwise unindexable first 2 bins */ 
// chunk size=2*size_sz*(2+idx) 
// 这里要减2，否则的话，前两个bin没有办法索引到。 
#define fastbin_index(sz)          \ 
	((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```
**需要特别注意的是，fastbin 范围的 `chunk` 的 inuse 始终被置为 1。因此它们不会和其它被释放的 `chunk` 合并。**

但是当释放的 `chunk` 与该 `chunk` 相邻的空闲 `chunk` 合并后的大小大于 FASTBIN_CONSOLIDATION_THRESHOLD 时，内存碎片可能比较多了，我们就需要把 fast bins 中的 chunk 都进行合并，以减少内存碎片对系统的影响。
**malloc_consolidate 函数可以将 fastbin 中所有能和其它 `chunk` 合并的 `chunk` 合并在一起。具体地参见后续的详细函数的分析。**
fast bin 中的 `chunk` 是有可能被放到 small bin 中去

##### fastbinsY[NFASTBINS]
存放每个 fast `chunk` 链表头部的指针
#### Small Bin：
small bins 中每个 `chunk` 的大小与其所在的 bin 的 index 的关系为：chunk_size = 2 * SIZE_SZ *index，具体如下

|下标|SIZE_SZ=4（32 位）|SIZE_SZ=8（64 位）|
|---|---|---|
|2|16|32|
|3|24|48|
|4|32|64|
|5|40|80|
|x|2*4*x|2*8*x|
|63|504|1008|
small bins 中一共有 62 个循环双向链表，每个链表中存储的 `chunk` 大小都一致。比如对于 32 位系统来说，下标 2 对应的双向链表中存储的 `chunk` 大小为均为 16 字节。每个链表都有链表头结点，这样可以方便对于链表内部结点的管理。此外，**small bins 中每个 bin 对应的链表采用 FIFO 的规则**，所以同一个链表中先被释放的 `chunk` 会先被分配出去。

#### Large Bin
large bins 中一共包括 63 个 bin，每个 bin 中的 `chunk` 的大小不一致，而是处于一定区间范围内。此外，这 63 个 bin 被分成了 6 组，每组 bin 中的 `chunk` 大小之间的公差一致，具体如下：

|组|数量|公差|
|---|---|---|
|1|32|64B|
|2|16|512B|
|3|8|4096B|
|4|4|32768B|
|5|2|262144B|
|6|1|不限制|
这里我们以 32 位平台的 large bin 为例，第一个 large bin 的起始 `chunk` 大小为 512 字节，位于第一组，所以该 bin 可以存储的 `chunk` 的大小范围为 `[512,512+64)` 。
#### Unsorted Bin
unsorted bin 可以视为空闲 `chunk` 回归其所属 bin 之前的缓冲区。
unsorted bin 处于我们之前所说的 bin 数组下标 1 处。故而 unsorted bin 只有一个链表。unsorted bin 中的空闲 `chunk` 处于乱序状态，主要有两个来源

- 当一个较大的 `chunk` 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
- 释放一个不属于 fast bin 的 chunk，并且该 `chunk` 不和 top `chunk` 紧邻时，该 `chunk` 会被首先放到 unsorted bin 中。
此外，Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO 。

**根据 chunk 的大小统一地获得 chunk 所在的索引**
```c#
#define bin_index(sz)              
((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz))
```

### Top Chunk：

程序第一次进行 malloc 的时候，heap 会被分为两块，一块给用户，剩下的那块就是 top chunk。其实，所谓的 top `chunk` 就是处于当前堆的物理地址最高的 chunk。这个 `chunk` 不属于任何一个 bin，它的作用在于当所有的 bin 都无法满足用户请求的大小时，如果其大小不小于指定的大小，就进行分配，并将剩下的部分作为新的 top chunk。否则，就对 heap 进行扩展后再进行分配。在 main arena 中通过 sbrk 扩展 heap，而在 thread arena 中通过 mmap 分配新的 heap。

需要注意的是，top `chunk` 的 prev_inuse 比特位始终为 1，否则其前面的 chunk 就会被合并到 top chunk 中。

**初始情况下，我们可以将 unsorted `chunk` 作为 top chunk。**
### last remainder[¶](https://ctf-wiki.isisy.com/pwn/linux/user-mode/heap/ptmalloc2/heap-structure/#last-remainder "Permanent link")

在用户使用 malloc 请求分配内存时，ptmalloc2 找到的 `chunk` 可能并不和申请的内存大小一致，这时候就将分割之后的剩余部分称之为 last remainder `chunk` ，unsort bin 也会存这一块。top `chunk` 分割剩下的部分不会作为 last remainder.


# 堆溢出：
## 介绍：
堆溢出是指程序向某个堆块中写入的字节数超过了堆块本身可使用的字节数（**之所以是可使用而不是用户申请的字节数，是因为堆管理器会对用户所申请的字节数进行调整，这也导致可利用的字节数都不小于用户申请的字节数**），因而导致了数据溢出，并覆盖到**物理相邻的高地址**的下一个堆块。


## 基本利用：
与栈溢出所不同的是，堆上并不存在返回地址等可以让攻击者直接控制执行流程的数据，因此我们一般无法直接通过堆溢出来控制 EIP 。一般来说，我们利用堆溢出的策略是

1. 覆盖与其**物理相邻的下一个 chunk** 的内容。
    - prev_size
    - size，主要有三个比特位，以及该堆块真正的大小。
        - NON_MAIN_ARENA
        - IS_MAPPED
        - PREV_INUSE
        - the True chunk size
    - chunk content，从而改变程序固有的执行流。
2. 利用堆中的机制（如 unlink 等 ）来实现任意地址写入（ Write-Anything-Anywhere）或控制堆块中的内容等效果，从而来控制程序的执行流。
## 利用步骤：
### （1）寻找堆分配函数：
通常来说堆是通过调用 glibc 函数 ==malloc== 进行分配的，在某些情况下会使用 ==calloc== 分配。calloc 与 malloc 的区别是 **calloc 在分配后会自动进行清空，这对于某些信息泄露漏洞的利用来说是致命的**。
```c
calloc(0x20); 
//等同于 
ptr=malloc(0x20); 
memset(ptr,0,0x20);
```
- memset是什么：[[pwn/笔记/堆/笔记附件/memset|memset]]

除此之外，还有一种分配是经由 ==realloc== 进行的，realloc 函数可以身兼 malloc 和 free 两个函数的功能。
#### realloc
realloc 的操作并不是像字面意义上那么简单，其内部会根据不同的情况进行不同操作
- 当 realloc(ptr,size) 的 size 不等于 ptr 的 size 时
    - 如果申请 size > 原来 size
        - 如果 chunk 与 top chunk 相邻，直接扩展这个 chunk 到新 size 大小
        - 如果 chunk 与 top chunk 不相邻，相当于 free(ptr),malloc(new_size)
    - 如果申请 size < 原来 size
        - 如果相差不足以容得下一个最小 chunk(64 位下 32 个字节，32 位下 16 个字节)，则保持不变
        - 如果相差可以容得下一个最小 chunk，则切割原 chunk 为两部分，free 掉后一部分
- 当 realloc(ptr,size) 的 size 等于 0 时，相当于 free(ptr)
- 当 realloc(ptr,size) 的 size 等于 ptr 的 size，不进行任何操作

### (2)寻找危险函数:
通过寻找危险函数，我们快速确定程序是否可能有堆溢出，以及有的话，堆溢出的位置在哪里。

常见的危险函数如下

- 输入
    - gets，直接读取一行，忽略 `'\x00'`
    - scanf
    - vscanf:[[pwn/笔记/堆/笔记附件/vscanf|vscanf]]
- 输出
    - sprintf:[[pwn/笔记/堆/笔记附件/sprintf|sprintf]]
- 字符串
    - strcpy，字符串复制，遇到 `'\x00'` 停止
    - strcat，字符串拼接，遇到 `'\x00'` 停止
    - bcopy:[[pwn/笔记/堆/笔记附件/bcopy|bcopy]]

### (3)确定填充长度：
**开始写入的地址与我们所要覆盖的地址之间的距离**
一个常见的误区是 malloc 的参数等于实际分配堆块的大小，但是事实上 ptmalloc 分配出来的大小是对齐的。这个长度一般是字长的 2 倍，比如 32 位系统是 8 个字节，64 位系统是 16 个字节。但是对于不大于 2 倍字长的请求，malloc 会直接返回 2 倍字长的块也就是最小 chunk，比如 64 位系统执行`malloc(0)`会返回用户区域为 16 字节的块。
```c
#include <stdio.h> 
int main(void) 
{ 
	char *chunk; 
	chunk=malloc(0); 
	puts("Get input:"); 
	gets(chunk); 
	return 0; 
}
```
```bash
//根据系统的位数，malloc会分配8或16字节的用户空间 
0x602000: 0x0000000000000000 0x0000000000000021 
0x602010: 0x0000000000000000 0x0000000000000000 
0x602020: 0x0000000000000000 0x0000000000020fe1 
0x602030: 0x0000000000000000 0x0000000000000000
```
注意用户区域的大小不等于chunk_head.size（即chunk的大小），chunk_head.size = 用户区域大小 + 2 * 字长
用户申请的内存大小会被修改，其有可能会使用与其物理相邻的下一个 chunk 的 prev_size 字段储存内容。
```c
#include <stdio.h> 
int main(void) 
{ 
	char *chunk; 
	chunk=malloc(24); 
	puts("Get input:"); 
	gets(chunk); 
	return 0; 
}
```
观察如上代码，我们申请的 chunk 大小是 24 个字节。但是我们将其编译为 64 位可执行程序时，实际上分配的内存会是 16 个字节而不是 24 个。
```bash
0x602000: 0x0000000000000000 0x0000000000000021 
0x602010: 0x0000000000000000 0x0000000000000000 
0x602020: 0x0000000000000000 0x0000000000020fe1
```
16 个字节的空间是如何装得下 24 个字节的内容呢？答案是借用了下一个块的 pre_size 域。我们可来看一下用户申请的内存大小与 glibc 中实际分配的内存大小之间的转换。
当 req=24 时，request2size(24)=32。而除去 chunk 头部的 16 个字节。实际上用户可用 chunk 的字节数为 16。而根据我们前面学到的知识可以知道 chunk 的 pre_size 仅当它的前一块处于释放状态时才起作用。所以用户这时候其实还可以使用下一个 chunk 的 prev_size 字段，正好 24 个字节。**实际上 ptmalloc 分配内存是以双字为基本单位，以 64 位系统为例，分配出来的空间是 16 的整数倍，即用户申请的 chunk 都是 16 字节对齐的。**
[[pwn/笔记/堆/笔记附件/request2size|request2size]]
溢出长度计算：[[pwn/笔记/堆/笔记附件/溢出长度计算|溢出长度计算]]












